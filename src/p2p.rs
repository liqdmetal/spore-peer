// SPDX-License-Identifier: BSD-3-Clause
//
//! DERO peer protocol (P2P) — clean-room port of the reference's wire
//! protocol (p2p/wire_structs.go + p2p/rpc_cbor_codec.go):
//!   framing: 4-byte little-endian length + CBOR frame
//!   header:  {M: method, S: seq, E: error}
//!   payload: CBOR map with the tagged struct fields (COMMON, BLIST, ...)
//! Methods: Peer.Chain (block list sync), Peer.GetObject (block bodies),
//!          Peer.PutObject (push a stored body), Peer.Handshake (the hello).
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
    // 64 MiB payload cap... adjusted to 192 MiB: a Peer.PutObject carries
    // BODY hex-encoded, so a max-size (32 MiB) body needs a 2*MAX_BODY_BYTES
    // frame. The cap must exceed the wire size of any body the protocol
    // permits, or legal pushes get misread as hostile lengths.
    if len == 0 || len > 192 * 1024 * 1024 {
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
///
/// Hardened against hostile frames: depth-capped, no panics on truncated
/// input, length arithmetic checked, and every decode consumes a measured
/// byte count (no heuristics).
pub fn decode_message(buf: &[u8]) -> Option<Rpc2Message> {
    let (head_v, used) = decode_value(buf, 0)?;
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
    let payload = if buf.len() > used {
        let (v, used2) = decode_value(&buf[used..], 0)?;
        if used2 == 0 {
            return None; // a zero-consumption decode is malformed by definition
        }
        v
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

/// Maximum container nesting the decoder will follow. Real rpc2 traffic
/// nests at most a handful of levels (header map -> chain array -> pair
/// array = 3); anything deeper is rejected as hostile.
const MAX_DEPTH: usize = 64;

/// Decode one CBOR item at `buf[0..]` at nesting depth `depth`. Returns the
/// JSON value and the number of bytes consumed. `None` on truncation,
/// overflow, or depth exhaustion; a returned count of 0 is malformed.
fn decode_value(buf: &[u8], depth: usize) -> Option<(serde_json::Value, usize)> {
    if depth > MAX_DEPTH {
        return None; // hostile nesting
    }
    let (&ib, rest) = buf.split_first()?;
    let major = ib >> 5;
    let info = ib & 0x1f;
    let (n, pos) = match info {
        0..=23 => (info as u64, 1usize),
        24 => (*rest.first()? as u64, 2),
        25 => (
            u16::from_be_bytes(rest.get(0..2)?.try_into().ok()?) as u64,
            3,
        ),
        26 => (
            u32::from_be_bytes(rest.get(0..4)?.try_into().ok()?) as u64,
            5,
        ),
        27 => (u64::from_be_bytes(rest.get(0..8)?.try_into().ok()?), 9),
        _ => return None, // indefinite length (info 31) and reserved infos
    };
    match major {
        0 => Some((serde_json::json!(n), pos)),
        1 => {
            // CBOR negint = -1 - n. Magnitudes below i64::MIN would panic
            // serde_json's number conversion (found by the fuzz corpus):
            // reject instead — the rpc2 subset never sends negints anyway.
            let neg: i128 = -1 - n as i128;
            if neg < i64::MIN as i128 {
                return None;
            }
            Some((serde_json::json!(neg as i64), pos))
        }
        2 | 3 => {
            // checked_add + get: a length past the buffer end is truncation.
            // `pos` is buf-space (bytes consumed by the head).
            let end = pos.checked_add(n as usize)?;
            let b = buf.get(pos..end)?;
            if major == 3 {
                let s = std::str::from_utf8(b).ok()?;
                Some((serde_json::json!(s), end))
            } else {
                Some((serde_json::json!(hex::encode(b)), end))
            }
        }
        4 => {
            // Children start at buf[pos]; every returned count is in the
            // callee's own buffer space, so `at += used` stays buf-space.
            let mut out = Vec::new();
            let mut at = pos;
            for _ in 0..n {
                let (v, used) = decode_value(&buf[at..], depth + 1)?;
                if used == 0 {
                    return None;
                }
                at = at.checked_add(used)?;
                out.push(v);
            }
            Some((serde_json::Value::Array(out), at))
        }
        5 => {
            let mut m = serde_json::Map::new();
            let mut at = pos;
            for _ in 0..n {
                let (k, used) = decode_value(&buf[at..], depth + 1)?;
                if used == 0 {
                    return None;
                }
                at = at.checked_add(used)?;
                let (v, used) = decode_value(&buf[at..], depth + 1)?;
                if used == 0 {
                    return None;
                }
                at = at.checked_add(used)?;
                if let Some(ks) = k.as_str() {
                    m.insert(ks.to_string(), v);
                }
            }
            Some((serde_json::Value::Object(m), at))
        }
        6 | 7 => {
            // tags / simple values / bools / null
            if major == 7 && info == 20 {
                Some((serde_json::Value::Bool(false), pos))
            } else if major == 7 && info == 21 {
                Some((serde_json::Value::Bool(true), pos))
            } else {
                Some((serde_json::Value::Null, pos))
            }
        }
        _ => None,
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

/// Peer.PutObject request payload: {"BLID": 32-byte hash, "BODY": raw bytes}.
/// The server recomputes sha256(BODY) and stores under the hash it COMPUTED,
/// rejecting the object outright if it does not match BLID.
pub fn putobject_request(blid: &[u8; 32], body: &[u8], token: &str) -> Vec<u8> {
    let mut n = 2;
    if !token.is_empty() {
        n += 1;
    }
    let mut out = cbor::map(n);
    out.extend_from_slice(&cbor::kv("BLID", &cbor::hash32(blid)));
    out.extend_from_slice(&cbor::kv("BODY", &cbor::bytes(body)));
    if !token.is_empty() {
        out.extend_from_slice(&cbor::kv("TOKEN", &cbor::text(token)));
    }
    out
}

/// Peer.PutObject response payload: {"BLID": the hash actually stored}.
pub fn putobject_response(blid: &[u8; 32]) -> Vec<u8> {
    let mut out = cbor::map(1);
    out.extend_from_slice(&cbor::kv("BLID", &cbor::hash32(blid)));
    out
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

    #[test]
    fn putobject_roundtrips_blid_and_body() {
        let blid = [7u8; 32];
        let body = b"pushed body bytes";
        let frame = cbor::message("Peer.PutObject", 11, "", putobject_request(&blid, body, ""));
        let m = decode_message(&frame).expect("decode");
        assert_eq!(m.method, "Peer.PutObject");
        assert_eq!(
            m.payload.get("BLID").and_then(|v| v.as_str()),
            Some(hex::encode(blid).as_str())
        );
        let body_hex = m.payload.get("BODY").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(hex::decode(body_hex).unwrap(), body);

        let resp = cbor::message("", 11, "", putobject_response(&blid));
        let m = decode_message(&resp).expect("decode");
        assert_eq!(
            m.payload.get("BLID").and_then(|v| v.as_str()),
            Some(hex::encode(blid).as_str())
        );
    }
}
