// SPDX-License-Identifier: BSD-3-Clause
//
//! DERO peer protocol (P2P) — clean-room port of the reference's wire
//! protocol (p2p/wire_structs.go + p2p/rpc_cbor_codec.go):
//!   framing: 4-byte little-endian length + CBOR frame
//!   header:  {M: method, S: seq, E: error}
//!   payload: CBOR map with the tagged struct fields (COMMON, BLIST, ...)
//! Methods: Peer.Chain (block list sync), Peer.GetObject (block bodies),
//!          Peer.Handshake (the initial hello).
//!
//! This is the real DERO P2P wire format (rpc2 over CBOR), used by the
//! reference daemon on port 11010. spore-peer implements the client + server
//! side of the sync subset so Rust nodes can exchange stored bodies directly;
//! the live sync loop in spore_peer.rs drives it.

use std::io::{Read, Write};
use std::net::TcpStream;

/// Send a CBOR frame: 4-byte LE length + payload.
pub fn write_frame(w: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = (payload.len() as u32).to_le_bytes();
    w.write_all(&len)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a CBOR frame: 4-byte LE length + payload.
pub fn read_frame(r: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad frame length",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// A decoded rpc2 message: the header map plus the (optional) payload item.
#[derive(Debug, Clone)]
pub struct Rpc2Message {
    pub method: String, // "Peer.Chain" etc (empty for responses)
    pub seq: u64,
    pub error: String,
    pub payload: serde_json::Value, // the CBOR-decoded payload as JSON
}

/// Minimal CBOR map encoder for the tagged structs we send
/// (fxamacker-compatible: keys are text strings).
pub mod cbor {
    /// CBOR major-type head
    pub fn head(major: u8, n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        if n < 24 {
            out.push((major << 5) | n as u8);
        } else if n <= 0xff {
            out.push((major << 5) | 24);
            out.push(n as u8);
        } else if n <= 0xffff {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= 0xffff_ffff {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            out.push((major << 5) | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
        out
    }

    pub fn text(s: &str) -> Vec<u8> {
        let mut out = head(3, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
        out
    }

    pub fn uint(v: u64) -> Vec<u8> {
        head(0, v)
    }

    pub fn bytes(b: &[u8]) -> Vec<u8> {
        let mut out = head(2, b.len() as u64);
        out.extend_from_slice(b);
        out
    }

    pub fn array(n: usize) -> Vec<u8> {
        head(4, n as u64)
    }

    pub fn map(n: usize) -> Vec<u8> {
        head(5, n as u64)
    }

    /// Encode a key:value pair.
    pub fn kv(key: &str, val: &[u8]) -> Vec<u8> {
        let mut out = text(key);
        out.extend_from_slice(val);
        out
    }

    /// A 32-byte hash as a byte-string (BLID/CID entries).
    pub fn hash32(h: &[u8; 32]) -> Vec<u8> {
        bytes(h)
    }

    /// Encode a full frame payload: header + body (the rpc2 codec sends the
    /// header map then the payload object as separate CBOR items — the
    /// reference's WriteRequest writes TWO frames: header then object).
    pub fn header(method: &str, seq: u64, err: &str) -> Vec<u8> {
        // the reference ALWAYS emits M, S and E (fxamacker marshals the struct
        // with all fields, even when M or E is empty) — the map count must
        // match the pairs actually written or the decoder will swallow the
        // payload item as a phantom pair.
        let mut out = map(3);
        out.extend_from_slice(&kv("M", &text(method)));
        out.extend_from_slice(&kv("S", &uint(seq)));
        out.extend_from_slice(&kv("E", &text(err)));
        out
    }

    pub fn message(method: &str, seq: u64, err: &str, body: Vec<u8>) -> Vec<u8> {
        // NOTE: legacy merged-map form; the reference uses TWO frames.
        // Kept for compatibility with our own tests; use header() + body.
        let mut out = header(method, seq, err);
        out.extend_from_slice(&body);
        out
    }
}

/// Send a request and read the response (sync subset). Returns the decoded
/// response header (M/S/E) and payload; a non-empty E is the caller's error.
pub fn rpc2_call(
    stream: &mut TcpStream,
    method: &str,
    seq: u64,
    body: Vec<u8>,
) -> std::io::Result<Rpc2Message> {
    let frame = cbor::message(method, seq, "", body);
    write_frame(stream, &frame)?;
    let resp = read_frame(stream)?;
    match decode_message(&resp) {
        Some(m) => Ok(m),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "undecodable rpc2 response",
        )),
    }
}

/// Decode an rpc2 frame: a CBOR header map {M, S, E} followed (optionally) by
/// one more CBOR item as the payload. Returns None on malformed input.
pub fn decode_message(buf: &[u8]) -> Option<Rpc2Message> {
    let head_v = decode_value(buf)?;
    let obj = head_v.as_object()?;
    let method = obj
        .get("M")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let seq = obj.get("S").and_then(|v| v.as_u64()).unwrap_or(0);
    let error = obj
        .get("E")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let used = advance(buf, &head_v);
    let payload = if buf.len() > used {
        decode_value(&buf[used..])?
    } else {
        serde_json::Value::Null
    };
    Some(Rpc2Message {
        method,
        seq,
        error,
        payload,
    })
}

fn decode_value(buf: &[u8]) -> Option<serde_json::Value> {
    if buf.is_empty() {
        // None, not Null: a decode that runs past the end of the buffer must
        // terminate the caller's element loop, never feed it an infinite
        // stream of empty values.
        return None;
    }
    let ib = buf[0];
    let major = ib >> 5;
    let info = ib & 0x1f;
    let (n, mut pos) = match info {
        0..=23 => (info as u64, 1usize),
        24 => (*buf.get(1)? as u64, 2),
        25 => (
            u16::from_be_bytes(buf.get(1..3)?.try_into().ok()?) as u64,
            3,
        ),
        26 => (
            u32::from_be_bytes(buf.get(1..5)?.try_into().ok()?) as u64,
            5,
        ),
        27 => (u64::from_be_bytes(buf.get(1..9)?.try_into().ok()?), 9),
        _ => return None,
    };
    match major {
        0 => Some(serde_json::json!(n)),
        1 => Some(serde_json::json!(-1 - n as i128)),
        2 => {
            let b = buf.get(pos..pos + n as usize)?;
            Some(serde_json::json!(hex::encode(b)))
        }
        3 => {
            let s = std::str::from_utf8(buf.get(pos..pos + n as usize)?).ok()?;
            Some(serde_json::json!(s))
        }
        4 => {
            let mut arr = Vec::new();
            for _ in 0..n {
                let v = decode_value(&buf[pos..])?;
                pos += advance(&buf[pos..], &v);
                arr.push(v);
            }
            Some(serde_json::Value::Array(arr))
        }
        5 => {
            let mut m = serde_json::Map::new();
            for _ in 0..n {
                let k = decode_value(&buf[pos..])?;
                pos += advance(&buf[pos..], &k);
                let v = decode_value(&buf[pos..])?;
                pos += advance(&buf[pos..], &v);
                if let Some(ks) = k.as_str() {
                    m.insert(ks.to_string(), v);
                }
            }
            Some(serde_json::Value::Object(m))
        }
        6 | 7 => {
            // tags / simple: skip the extra byte
            if major == 7 && info == 20 {
                return Some(serde_json::Value::Bool(false));
            }
            if major == 7 && info == 21 {
                return Some(serde_json::Value::Bool(true));
            }
            if major == 7 && info == 22 {
                return Some(serde_json::Value::Null);
            }
            Some(serde_json::Value::Null)
        }
        _ => None,
    }
}

fn advance(buf: &[u8], _v: &serde_json::Value) -> usize {
    // estimate the byte length of the encoded value by re-decoding —
    // simplest correct approach: use the raw byte length from the head.
    if buf.is_empty() {
        return 0;
    }
    let ib = buf[0];
    let info = ib & 0x1f;
    let header = match info {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => 1,
    };
    let major = ib >> 5;
    let n = match info {
        0..=23 => info as u64,
        24 => buf.get(1).copied().unwrap_or(0) as u64,
        25 => u16::from_be_bytes([buf[1], buf[2]]) as u64,
        26 => u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64,
        27 => u64::from_be_bytes(buf[1..9].try_into().unwrap_or([0; 8])),
        _ => 0,
    };
    match major {
        2 | 3 => header + n as usize,
        4 => {
            // sum of children
            let mut pos = header;
            let mut total = header;
            for _ in 0..n {
                let step = advance(&buf[pos..], &serde_json::Value::Null);
                pos += step;
                total += step;
            }
            total
        }
        5 => {
            let mut pos = header;
            let mut total = header;
            for _ in 0..n {
                let sk = advance(&buf[pos..], &serde_json::Value::Null);
                pos += sk;
                total += sk;
                let sv = advance(&buf[pos..], &serde_json::Value::Null);
                pos += sv;
                total += sv;
            }
            total
        }
        _ => header,
    }
}

// --- rpc2 payload builders (the sync subset spore-peer actually speaks) ---

/// Peer.Handshake request payload: {"N": network/version id}.
pub fn handshake_request(version: u64) -> Vec<u8> {
    let mut out = cbor::map(1);
    out.extend_from_slice(&cbor::kv("N", &cbor::uint(version)));
    out
}

/// Peer.Handshake response payload: {"H": chain height, "N": version}.
pub fn handshake_response(height: u64, version: u64) -> Vec<u8> {
    let mut out = cbor::map(2);
    out.extend_from_slice(&cbor::kv("H", &cbor::uint(height)));
    out.extend_from_slice(&cbor::kv("N", &cbor::uint(version)));
    out
}

/// Peer.Chain request payload: {"TOP": topoheight to start at (0 = peer's tip),
/// "N": max entries}.
pub fn chain_request(top: u64, n: u64) -> Vec<u8> {
    let mut out = cbor::map(2);
    out.extend_from_slice(&cbor::kv("TOP", &cbor::uint(top)));
    out.extend_from_slice(&cbor::kv("N", &cbor::uint(n)));
    out
}

/// Peer.Chain response payload: array of [topoheight, blid(32B)] pairs,
/// newest first.
pub fn chain_response(pairs: &[(u64, [u8; 32])]) -> Vec<u8> {
    let mut out = cbor::array(pairs.len());
    for (h, blid) in pairs {
        out.extend_from_slice(&cbor::array(2));
        out.extend_from_slice(&cbor::uint(*h));
        out.extend_from_slice(&cbor::hash32(blid));
    }
    out
}

/// Peer.GetObject request payload: {"BLID": 32-byte hash}.
pub fn getobject_request(blid: &[u8; 32]) -> Vec<u8> {
    let mut out = cbor::map(1);
    out.extend_from_slice(&cbor::kv("BLID", &cbor::hash32(blid)));
    out
}

/// Peer.GetObject response payload: the raw object bytes.
pub fn getobject_response(body: &[u8]) -> Vec<u8> {
    cbor::bytes(body)
}

/// An rpc2 error response: empty method, echoed seq, E = message.
pub fn error_response(seq: u64, msg: &str) -> Vec<u8> {
    cbor::message("", seq, msg, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_message_roundtrips_header_and_payload() {
        let body = chain_response(&[(7, [9u8; 32]), (6, [3u8; 32])]);
        let frame = cbor::message("Peer.Chain", 42, "", body);
        let m = decode_message(&frame).expect("decode");
        assert_eq!(m.method, "Peer.Chain");
        assert_eq!(m.seq, 42);
        assert_eq!(m.error, "");
        let pairs = m.payload.as_array().expect("payload array");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0][0].as_u64(), Some(7));
        let blid = hex::encode([9u8; 32]);
        assert_eq!(pairs[0][1].as_str(), Some(blid.as_str()));
    }

    #[test]
    fn decode_message_handles_error_response() {
        let frame = cbor::message("", 5, "404 not found", Vec::new());
        let m = decode_message(&frame).expect("decode");
        assert_eq!(m.method, "");
        assert_eq!(m.error, "404 not found");
        assert_eq!(m.seq, 5);
    }

    #[test]
    fn decode_message_without_payload_is_null() {
        let frame = cbor::header("Peer.Handshake", 1, "");
        let m = decode_message(&frame).expect("decode");
        assert_eq!(m.method, "Peer.Handshake");
        assert!(m.payload.is_null());
    }

    #[test]
    fn getobject_payload_is_hex_body() {
        let frame = cbor::message("", 3, "", getobject_response(b"BINARY\x00DATA"));
        let m = decode_message(&frame).expect("decode");
        let want = hex::encode(b"BINARY\x00DATA");
        assert_eq!(m.payload.as_str(), Some(want.as_str()));
    }

    #[test]
    fn decode_message_rejects_garbage() {
        assert!(decode_message(&[0xff, 0xff, 0xff]).is_none());
        assert!(decode_message(&[]).is_none());
    }
}
