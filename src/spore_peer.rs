// SPDX-License-Identifier: BSD-3-Clause
//
//! spore-peer — the long-body P2P transport for Spore (m³).
//!
//! A long message never rides a DERO block. The sender holds the ECDH-encrypted
//! body on their own node and advertises only a pointer (whisper). The recipient
//! fetches the body peer-to-peer over this transport when both are online, then
//! keys rotate + erase. Nobody but sender and receiver ever holds the bytes.
//!
//! The body is already XChaCha20-encrypted to the recipient's key, so this
//! transport needs no additional secrecy: even the serving node's operator or an
//! on-path observer sees only ciphertext they cannot decrypt. The transport only
//! has to move bytes and let the recipient verify integrity (sha256(ciphertext)
//! == CID).
//!
//! Framing reuses the byte-verified dero-crypto p2p layer (4-byte LE length +
//! CBOR-ish payload), BSD-3 and clean-room.
//!
//! Response protocol (v2, audit H4 fix): the response frame is
//!
//!     [status:1][payload...]
//!
//!   - status 0x00: payload is the body bytes (sha256(body) MUST equal the CID)
//!   - status 0x01: payload is an ASCII error message
//!
//! The old protocol sniffed the first BODY byte for ASCII '4'/'5' to detect
//! error strings — which misclassified ~1.6% of valid ciphertexts (any body
//! starting 0x34/0x35) as failures. v2 sends an explicit status byte; the
//! client still accepts frame-less legacy bodies as a fallback, decided by
//! the sha256 check rather than content sniffing.
//!
//! Usage:
//!   spore-peer serve --listen 0.0.0.0:8099 --dir <body-store-dir>   (sender)
//!   spore-peer fetch --addr host:8099 --cid <64-hex> [--out file]   (recipient)
//!   spore-peer sync  --addr host:8099 --dir <body-store-dir>        (rpc2 sync subset)
//!
//! Request (over the frame): JSON {"cid": "<64-hex>"}, or an rpc2/CBOR map
//! (Peer.Handshake / Peer.Chain / Peer.GetObject) on the same port.
use std::fs;
use std::net::{TcpListener, TcpStream};

mod p2p;
use p2p::{
    chain_request, chain_response, decode_message, error_response, getobject_request,
    getobject_response, handshake_request, handshake_response, read_frame, rpc2_call,
    write_frame, Rpc2Message,
};

/// Response status bytes (first byte of every response frame).
const STATUS_OK: u8 = 0x00;
const STATUS_ERR: u8 = 0x01;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// serve_body looks up, hashes, and returns the body for `cid_hex` from `dir`.
/// Pure aside from the filesystem read, so the integrity rules are testable
/// without sockets. Returns Err(ascii message) for 400/404/500 conditions.
fn serve_body(dir: &str, cid_hex: &str) -> Result<Vec<u8>, String> {
    let raw = match hex_decode(cid_hex) {
        Some(r) if r.len() == 32 => r,
        _ => return Err("400 bad cid".to_string()),
    };
    // The cid hex is length-checked 64 hex chars above, so the path can only
    // be <dir>/<64 hex>.body — no traversal is possible.
    let path = format!("{dir}/{cid_hex}.body");
    let data = fs::read(&path).map_err(|_| "404 not found".to_string())?;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&data);
    let digest = h.finalize();
    if digest[..] != raw[..] {
        // Never serve bytes that do not hash to the requested CID: a
        // corrupted or planted file must not become "the message".
        return Err("500 cid mismatch".to_string());
    }
    Ok(data)
}

/// frame_ok / frame_err build a v2 response frame from a status + payload.
fn frame_ok(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(STATUS_OK);
    out.extend_from_slice(body);
    out
}

fn frame_err(msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 1);
    out.push(STATUS_ERR);
    out.extend_from_slice(msg.as_bytes());
    out
}

/// The body store doubles as the ledger for the rpc2 sync subset: chain
/// entries are the stored bodies' CIDs ordered oldest->newest by file mtime
/// (topoheight = position in that order).
fn chain_view(dir: &str) -> Vec<(u64, [u8; 32])> {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut entries: Vec<(std::time::SystemTime, [u8; 32])> = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        // <64 hex>.body only — the length gate makes the [..64] slice safe.
        if name.len() != 64 + 5 || !name.ends_with(".body") {
            continue;
        }
        let cid = match hex_decode(&name[..64]) {
            Some(c) if c.len() == 32 => c,
            _ => continue,
        };
        let mt = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if let Ok(cid) = <[u8; 32]>::try_from(cid) {
            entries.push((mt, cid));
        }
    }
    entries.sort_by_key(|(t, _)| *t);
    entries
        .into_iter()
        .enumerate()
        .map(|(i, (_, c))| (i as u64, c))
        .collect()
}

/// handle_rpc2 answers one rpc2 request (the DERO peer sync subset) using the
/// body store as its ledger. Single request/response per connection, matching
/// the cid-fetch protocol's shape.
fn handle_rpc2(s: &mut TcpStream, msg: &Rpc2Message, dir: &str) {
    match msg.method.as_str() {
        "Peer.Handshake" => {
            let height = chain_view(dir).len() as u64;
            let resp = handshake_response(height, 1);
            let _ = write_frame(s, &p2p::cbor::message("", msg.seq, "", resp));
        }
        "Peer.Chain" => {
            let top = msg.payload.get("TOP").and_then(|v| v.as_u64()).unwrap_or(0);
            let n = msg
                .payload
                .get("N")
                .and_then(|v| v.as_u64())
                .unwrap_or(128)
                .min(5000) as usize;
            let chain = chain_view(dir);
            // TOP=0 means "from the tip"; otherwise walk down from topoheight
            // <= TOP, newest first, at most n entries.
            let mut selected: Vec<(u64, [u8; 32])> = Vec::new();
            for (h, c) in chain.iter().rev() {
                if top != 0 && *h > top {
                    continue;
                }
                selected.push((*h, *c));
                if selected.len() == n {
                    break;
                }
            }
            let resp = chain_response(&selected);
            let _ = write_frame(s, &p2p::cbor::message("", msg.seq, "", resp));
        }
        "Peer.GetObject" => {
            let blid_hex = msg
                .payload
                .get("BLID")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // serve_body already enforces 64-hex + sha256(cipher) == BLID —
            // the same integrity rule the cid-fetch path applies.
            match serve_body(dir, blid_hex) {
                Ok(body) => {
                    let resp = getobject_response(&body);
                    let _ = write_frame(s, &p2p::cbor::message("", msg.seq, "", resp));
                }
                Err(e) => {
                    let _ = write_frame(s, &error_response(msg.seq, &e));
                }
            }
        }
        _unknown => {
            let _ = write_frame(s, &error_response(msg.seq, "501 unknown method"));
        }
    }
}

fn handle_client(s: &mut TcpStream, dir: &str) {
    // One connection, many requests: the rpc2 sync subset is persistent (the
    // reference keeps peer connections open), so a syncing client does
    // Handshake -> Chain -> GetObject... over a single socket. Legacy
    // cid-fetch clients send one request and close; the read then errors and
    // the loop exits. The two protocols can even interleave on one socket —
    // dispatch is per-frame.
    loop {
        let body = match read_frame(s) {
            Ok(b) => b,
            Err(_) => return,
        };
        // Dispatch: rpc2/CBOR (DERO peer sync) vs the legacy JSON cid-fetch.
        // A CBOR map starts 0xa0..=0xbf; JSON always starts with '{' (0x7b),
        // whose first 8 bytes decode as an absurd CBOR length — so a JSON
        // frame never decodes as an rpc2 message and misdispatch is impossible.
        if let Some(msg) = decode_message(&body) {
            if !msg.method.is_empty() {
                handle_rpc2(s, &msg, dir);
                continue;
            }
        }
        // Request is a small JSON object: {"cid":"<hex>"}.
        let req: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                let _ = write_frame(s, &frame_err("400 bad request"));
                continue;
            }
        };
        let cid = req.get("cid").and_then(|c| c.as_str()).unwrap_or("");
        match serve_body(dir, cid) {
            Ok(data) => {
                let _ = write_frame(s, &frame_ok(&data));
            }
            Err(e) => {
                let _ = write_frame(s, &frame_err(&e));
            }
        }
    }
}

/// parse_fetch_response turns a response frame into the verified body bytes.
///
/// v2: [0x00]+body (sha256 verified) or [0x01]+ascii error.
/// Legacy fallback: any other first byte is treated as a raw body from an old
/// server and accepted ONLY if sha256(frame) == cid — integrity decides, never
/// content sniffing (the old client's bug: it treated bodies starting with
/// ASCII '4'/'5' as errors, rejecting ~1.6% of valid ciphertexts).
fn parse_fetch_response(resp: &[u8], cid: &str) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};

    let expected = hex_decode(cid).ok_or("bad cid hex")?;
    if expected.len() != 32 {
        return Err("bad cid hex".to_string());
    }

    match resp.first() {
        Some(&STATUS_OK) => {
            let body = &resp[1..];
            let mut h = Sha256::new();
            h.update(body);
            let digest = h.finalize();
            if digest[..] != expected[..] {
                return Err("body sha256 does not match cid (tampered)".to_string());
            }
            Ok(body.to_vec())
        }
        Some(&STATUS_ERR) => Err(String::from_utf8_lossy(&resp[1..]).to_string()),
        _ => {
            // Legacy server: the whole frame is the raw body; verify by hash.
            let mut h = Sha256::new();
            h.update(resp);
            let digest = h.finalize();
            if digest[..] != expected[..] {
                return Err("body sha256 does not match cid (tampered)".to_string());
            }
            Ok(resp.to_vec())
        }
    }
}

/// fetch_stream runs the fetch protocol over an already-connected stream.
fn fetch_stream(s: &mut TcpStream, cid: &str, out: Option<&str>) -> Result<(), String> {
    let req = serde_json::json!({ "cid": cid });
    write_frame(s, req.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let resp = read_frame(s).map_err(|e| e.to_string())?;
    let body = parse_fetch_response(&resp, cid)?;
    if let Some(path) = out {
        fs::write(path, &body).map_err(|e| format!("write {path}: {e}"))?;
    }
    Ok(())
}

fn fetch(addr: &str, cid: &str, out: Option<&str>) -> Result<(), String> {
    let mut s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let r = fetch_stream(&mut s, cid, out);
    if let Ok(()) = r {
        // Success report goes to stderr like the rest of the CLI chatter.
        eprintln!("fetched and integrity-verified cid {cid}");
    }
    r
}

/// sync_stream runs the rpc2 sync subset against a peer: handshake (learn
/// the peer's height), chain (what it has), then Peer.GetObject for every
/// CID the local store is missing. Every body is sha256-verified against
/// its blid before it touches disk — the same integrity rule as fetch.
fn sync_stream(s: &mut TcpStream, dir: &str) -> Result<(u64, usize, usize), String> {
    use sha2::{Digest, Sha256};

    // 1. handshake: learn the peer's height.
    let hs = rpc2_call(s, "Peer.Handshake", 1, handshake_request(1))
        .map_err(|e| e.to_string())?;
    if !hs.error.is_empty() {
        return Err(format!("handshake: {}", hs.error));
    }
    let peer_height = hs.payload.get("H").and_then(|v| v.as_u64()).unwrap_or(0);

    // 2. chain: newest-first list of [topoheight, blid].
    let chain = rpc2_call(s, "Peer.Chain", 2, chain_request(0, 5000))
        .map_err(|e| e.to_string())?;
    if !chain.error.is_empty() {
        return Err(format!("chain: {}", chain.error));
    }
    let empty = Vec::new();
    let entries = chain.payload.as_array().unwrap_or(&empty);
    let mut fetched = 0usize;
    let mut have = 0usize;
    for (i, entry) in entries.iter().enumerate() {
        let pair = entry.as_array().ok_or("chain entry not an array")?;
        if pair.len() != 2 {
            return Err("chain entry must be [topoheight, blid]".to_string());
        }
        let top = pair[0].as_u64().unwrap_or(0);
        let blid_hex = pair[1].as_str().unwrap_or("");
        let expected = hex_decode(blid_hex).ok_or("bad blid hex in chain")?;
        let path = format!("{dir}/{blid_hex}.body");
        if fs::metadata(&path).is_ok() {
            have += 1;
            continue; // already stored
        }
        if i >= 2000 {
            break; // hard per-sync cap on object fetches
        }
        // 3. get-object: fetch and verify sha256(cipher) == blid.
        let mut blid = [0u8; 32];
        blid.copy_from_slice(&expected);
        let obj = rpc2_call(s, "Peer.GetObject", 100 + i as u64, getobject_request(&blid))
            .map_err(|e| e.to_string())?;
        if !obj.error.is_empty() {
            eprintln!("sync: topo {top}: {}", obj.error);
            continue;
        }
        let body_hex = obj.payload.as_str().ok_or("object payload not bytes")?;
        let body = hex::decode(body_hex).map_err(|e| e.to_string())?;
        let mut h = Sha256::new();
        h.update(&body);
        if h.finalize()[..] != expected[..] {
            return Err(format!("topo {top}: body sha256 != blid (tampered)"));
        }
        fs::write(&path, &body).map_err(|e| format!("write {path}: {e}"))?;
        fetched += 1;
    }
    Ok((peer_height, fetched, have))
}

fn sync(addr: &str, dir: &str) -> Result<(), String> {
    // First sync into a fresh store must not die on a missing directory.
    fs::create_dir_all(dir).map_err(|e| format!("dir {dir}: {e}"))?;
    let mut s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let (height, fetched, have) = sync_stream(&mut s, dir)?;
    eprintln!(
        "synced from {addr}: peer height {height}, fetched {fetched}, already had {have}"
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: spore-peer <serve|fetch|sync> ...");
        std::process::exit(2);
    }
    let code = match args[1].as_str() {
        "serve" => {
            let mut addr = "0.0.0.0:8099".to_string();
            let mut dir = ".".to_string();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--listen" => {
                        addr = args.get(i + 1).cloned().unwrap_or(addr);
                        i += 2;
                    }
                    "--dir" => {
                        dir = args.get(i + 1).cloned().unwrap_or(dir);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            match serve(&addr, &dir) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("serve error: {e}");
                    1
                }
            }
        }
        "fetch" => {
            let mut addr = String::new();
            let mut cid = String::new();
            let mut out = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--addr" => {
                        addr = args.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                    }
                    "--cid" => {
                        cid = args.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                    }
                    "--out" => {
                        out = args.get(i + 1).cloned();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            if addr.is_empty() || cid.is_empty() {
                eprintln!("fetch needs --addr and --cid");
                2
            } else {
                match fetch(&addr, &cid, out.as_deref()) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("fetch failed: {e}");
                        1
                    }
                }
            }
        }
        "sync" => {
            let mut addr = String::new();
            let mut dir = ".".to_string();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--addr" => {
                        addr = args.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                    }
                    "--dir" => {
                        dir = args.get(i + 1).cloned().unwrap_or(dir);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            if addr.is_empty() {
                eprintln!("sync needs --addr");
                2
            } else {
                match sync(&addr, &dir) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("sync failed: {e}");
                        1
                    }
                }
            }
        }
        _ => {
            eprintln!("unknown subcommand");
            2
        }
    };
    std::process::exit(code);
}

fn serve(addr: &str, dir: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("spore-peer serve: listening on {addr}, bodies in {dir}");
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let d = dir.to_string();
                std::thread::spawn(move || handle_client(&mut s, &d));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Unique temp dir per call (no external test deps). Cleaned up on process
    /// exit by the OS; tests only ever write a few small files.
    fn mk_temp_dir(tag: &str) -> std::path::PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "spore-peer-test-{}-{}-{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    /// A temp dir with one body file whose content STARTS with ASCII '4' —
    /// the exact case the old client misclassified as an error (audit H4).
    fn fixture_dir(body: &[u8]) -> (std::path::PathBuf, String) {
        let dir = mk_temp_dir("fixture");
        let cid = sha256_hex(body);
        let path = dir.join(format!("{cid}.body"));
        fs::write(path, body).expect("write body");
        (dir, cid)
    }

    // --- wire-spec conformance (docs/WIRE_SPEC.md in the spore repo;
    // vectors generated by internal/secure TestGenerateWireSpecVectors) ---

    /// Frame = LE32(len) + payload; ok = 0x00 + body; err = 0x01 + ascii.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() as u32).to_le_bytes();
        let mut out = len.to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn spec_frame_vectors_match() {
        // Golden vectors from spore/docs/interop-vectors.json. The body starts
        // with ASCII '4' on purpose (audit H4: only the status byte and the
        // sha256-vs-CID check may decide anything).
        let body: [u8; 6] = [0x34, 0x34, 0x34, 0x34, 0xAB, 0xCD];
        let mut ok_payload = Vec::with_capacity(1 + body.len());
        ok_payload.push(0x00u8);
        ok_payload.extend_from_slice(&body);
        let ok_frame = frame(&ok_payload);
        assert_eq!(
            hex::encode(&ok_frame),
            "070000000034343434abcd",
            "ok frame must match the wire spec vector"
        );
        let mut err_payload = Vec::with_capacity(1 + 13);
        err_payload.push(0x01u8);
        err_payload.extend_from_slice(b"404 not found");
        let err_frame = frame(&err_payload);
        assert_eq!(
            hex::encode(&err_frame),
            "0e00000001343034206e6f7420666f756e64",
            "err frame must match the wire spec vector"
        );
    }

    #[test]
    fn spec_parse_fetch_response_vectors() {
        // The client parser must accept the spec's ok frame (status 0x00) and
        // verify sha256(body) against the CID, and surface the err text.
        let body = [0x34u8, 0x34, 0x34, 0x34, 0xAB, 0xCD];
        let cid = sha256_hex(&body);
        let mut ok_payload = Vec::with_capacity(1 + body.len());
        ok_payload.push(0x00u8);
        ok_payload.extend_from_slice(&body);
        let ok = frame(&ok_payload);
        // parse_fetch_response sees the payload AFTER read_frame strips the
        // 4-byte LE length prefix.
        let got = parse_fetch_response(&ok[4..], &cid).expect("spec ok frame must parse");
        assert_eq!(got, body);

        let mut err_payload = Vec::with_capacity(1 + 13);
        err_payload.push(0x01u8);
        err_payload.extend_from_slice(b"404 not found");
        let err = frame(&err_payload);
        let e = parse_fetch_response(&err[4..], &"0".repeat(64)).unwrap_err();
        assert_eq!(e, "404 not found");
    }

    // --- server side (serve_body + framing) ---

    #[test]
    fn serve_body_serves_body_starting_with_4() {
        // Regression H4 (server side): a body starting with '4' is a perfectly
        // valid ciphertext — it must be served, not rejected.
        let body = b"4444 this body starts with the ASCII byte that broke the old client";
        let (_dir, cid) = fixture_dir(body);
        let got = serve_body(_dir.clone().to_str().unwrap(), &cid).expect("must serve");
        assert_eq!(got, body);
    }

    #[test]
    fn serve_body_not_found() {
        let dir = mk_temp_dir("notfound");
        let cid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = serve_body(dir.clone().to_str().unwrap(), cid).unwrap_err();
        assert_eq!(err, "404 not found");
    }

    #[test]
    fn serve_body_bad_cid() {
        let dir = mk_temp_dir("badcid");
        let d = dir.to_string_lossy().into_owned();
        assert_eq!(serve_body(&d, "nothex").unwrap_err(), "400 bad cid");
        assert_eq!(serve_body(&d, "abcd").unwrap_err(), "400 bad cid");
        // 63 hex chars (31.5 bytes) is one short.
        assert_eq!(
            serve_body(&d, &"a".repeat(63)).unwrap_err(),
            "400 bad cid"
        );
        // Path traversal must be impossible: a ".." payload can't pass the hex gate.
        assert_eq!(serve_body(&d, "../../etc/passwd").unwrap_err(), "400 bad cid");
    }

    #[test]
    fn serve_body_rejects_cid_mismatch() {
        // File exists but its sha256 != requested cid (corrupted or planted).
        let dir = mk_temp_dir("mismatch");
        let bogus_cid = "1111111111111111111111111111111111111111111111111111111111111111";
        fs::write(dir.join(format!("{bogus_cid}.body")), b"actual bytes")
            .unwrap();
        let err =
            serve_body(dir.clone().to_str().unwrap(), bogus_cid).unwrap_err();
        assert_eq!(err, "500 cid mismatch");
    }

    #[test]
    fn frame_ok_err_prefixes() {
        let f = frame_ok(b"BODY");
        assert_eq!(f[0], STATUS_OK);
        assert_eq!(&f[1..], b"BODY");
        let e = frame_err("404 not found");
        assert_eq!(e[0], STATUS_ERR);
        assert_eq!(&e[1..], b"404 not found");
    }

    // --- client side (parse_fetch_response) ---

    #[test]
    fn client_accepts_v2_body_starting_with_4() {
        // Regression H4 (client side): the old client sniffed the first body
        // byte for ASCII '4'/'5' and failed ~1.6% of valid ciphertexts.
        let body = b"5555 body starting with the byte that used to look like an error";
        let cid = sha256_hex(body);
        let resp = frame_ok(body);
        let got = parse_fetch_response(&resp, &cid).expect("must parse");
        assert_eq!(got, body);
    }

    #[test]
    fn client_rejects_v2_tampered_body() {
        let body = b"legit body";
        let cid = sha256_hex(body);
        let mut resp = frame_ok(body);
        // Tamper AFTER the status byte.
        let last = resp.len() - 1;
        resp[last] ^= 0xff;
        assert!(parse_fetch_response(&resp, &cid).is_err());
    }

    #[test]
    fn client_reports_v2_error_string() {
        let resp = frame_err("404 not found");
        let err = parse_fetch_response(&resp, &"0".repeat(64)).unwrap_err();
        assert_eq!(err, "404 not found");
    }

    #[test]
    fn client_legacy_fallback_hash_decides() {
        // An OLD server sends a raw body with no status prefix — including one
        // starting with '4'. The hash check must decide, not the first byte.
        let body = b"4444 legacy raw body starting with the trouble byte";
        let cid = sha256_hex(body);
        let got = parse_fetch_response(body, &cid).expect("legacy body must verify");
        assert_eq!(got, body);
        // A legacy raw 404 TEXT (no hash match) must NOT be accepted as a body.
        assert!(parse_fetch_response(b"404 not found", &"0".repeat(64)).is_err());
    }

    // --- end-to-end over real sockets ---

    #[test]
    fn roundtrip_over_socket_body_starting_with_4() {
        let body = b"4x4x full roundtrip with a body that used to be misclassified";
        let (dir, cid) = fixture_dir(body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        fetch_stream(&mut client, &cid, None).expect("fetch must succeed");
        drop(client); // handle_client is now persistent: close to release it
        server.join().unwrap();
    }

    #[test]
    fn roundtrip_reports_missing_cid_as_error() {
        let dir = mk_temp_dir("missing");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let cid = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        let err = fetch_stream(&mut client, cid, None).unwrap_err();
        assert!(err.contains("404"), "got: {err}");
        drop(client); // handle_client is now persistent: close to release it
        server.join().unwrap();
    }

    // --- rpc2 sync subset (Peer.Handshake / Peer.Chain / Peer.GetObject) ---

    #[test]
    fn rpc2_chain_response_matches_dero_wire_shape() {
        // Conformance: Peer.Chain's payload must be a CBOR array of
        // [topoheight(uint), blid(32-byte bstr)] pairs, newest first.
        let pairs = [
            (2u64, [0xAAu8; 32]),
            (1u64, [0x11u8; 32]),
        ];
        let payload = chain_response(&pairs);
        let frame = p2p::cbor::message("", 9, "", payload);
        let m = p2p::decode_message(&frame).expect("decode");
        let arr = m.payload.as_array().expect("array payload");
        assert_eq!(arr.len(), 2);
        // newest first
        assert_eq!(arr[0][0].as_u64(), Some(2));
        assert_eq!(arr[0][1].as_str(), Some(hex::encode([0xAAu8; 32]).as_str()));
        assert_eq!(arr[1][0].as_u64(), Some(1));
    }

    #[test]
    fn rpc2_request_dispatch_and_getobject_roundtrip() {
        let (dir, cid) = fixture_dir(b"rpc2 body for Peer.GetObject");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        // A real Peer.Chain request frame: header map with M/S/E + payload map.
        let req = p2p::cbor::message("Peer.Chain", 7, "", chain_request(0, 100));
        p2p::write_frame(&mut client, &req).unwrap();
        let resp = p2p::read_frame(&mut client).unwrap();
        let m = p2p::decode_message(&resp).expect("response decodes");
        assert_eq!(m.error, "");
        assert_eq!(m.seq, 7);
        let entries = m.payload.as_array().expect("chain array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0][1].as_str(), Some(cid.as_str()));

        // Peer.GetObject for that blid on the SAME connection (persistent rpc2).
        let mut blid = [0u8; 32];
        blid.copy_from_slice(&hex_decode(&cid).unwrap());
        let req = p2p::cbor::message("Peer.GetObject", 8, "", getobject_request(&blid));
        p2p::write_frame(&mut client, &req).unwrap();
        let resp = p2p::read_frame(&mut client).unwrap();
        let m = p2p::decode_message(&resp).expect("object response decodes");
        assert_eq!(m.error, "");
        let body_hex = m.payload.as_str().expect("hex body");
        assert_eq!(hex::decode(body_hex).unwrap(), b"rpc2 body for Peer.GetObject");

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn rpc2_error_for_unknown_method_and_missing_object() {
        let dir = mk_temp_dir("rpc2-errors");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        // Unknown method -> E is set.
        let req = p2p::cbor::message("Peer.Nope", 1, "", Vec::new());
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert!(m.error.contains("501"), "got: {}", m.error);

        // Missing object -> E carries the 404.
        let req = p2p::cbor::message(
            "Peer.GetObject",
            2,
            "",
            getobject_request(&[0xEE; 32]),
        );
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert!(m.error.contains("404"), "got: {}", m.error);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn sync_stream_end_to_end_fills_missing_bodies() {
        // Server has three bodies; client starts empty; sync must fetch all
        // three, verify sha256==blid, store them, and skip nothing.
        let server_dir = mk_temp_dir("sync-server");
        let bodies: Vec<Vec<u8>> = vec![
            b"body one".to_vec(),
            b"body two".to_vec(),
            b"body three".to_vec(),
        ];
        let mut cids = Vec::new();
        for b in &bodies {
            let cid = sha256_hex(b);
            fs::write(server_dir.join(format!("{cid}.body")), b).unwrap();
            cids.push(cid);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = server_dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let client_dir = mk_temp_dir("sync-client");
        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        let (height, fetched, _have) =
            sync_stream(&mut client, client_dir.to_str().unwrap()).expect("sync");
        assert_eq!(height, 3);
        assert_eq!(fetched, 3);
        drop(client);
        server.join().unwrap();

        // All three bodies landed, integrity-verified, in the client store.
        for (cid, body) in cids.iter().zip(bodies.iter()) {
            let stored = fs::read(client_dir.join(format!("{cid}.body"))).expect("stored");
            assert_eq!(&stored, body);
        }
    }

    #[test]
    fn sync_stream_idempotent_second_run_fetches_nothing() {
        let server_dir = mk_temp_dir("sync-server2");
        let body = b"only one body here";
        fs::write(
            server_dir.join(format!("{}.body", sha256_hex(body))),
            body,
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let client_dir = mk_temp_dir("sync-client2");
        let dirpath = server_dir.clone();
        // One server thread serving TWO sequential connections (first sync,
        // then the idempotent re-sync).
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut s = stream;
                handle_client(&mut s, dirpath.to_str().unwrap());
            }
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        let (height, fetched, _have) =
            sync_stream(&mut client, client_dir.to_str().unwrap()).expect("first sync");
        assert_eq!((height, fetched), (1, 1));
        drop(client);

        // Second run over a fresh socket: nothing new to fetch.
        let mut client2 = std::net::TcpStream::connect(&addr).unwrap();
        let (height, fetched, have) =
            sync_stream(&mut client2, client_dir.to_str().unwrap()).expect("second sync");
        assert_eq!((height, fetched, have), (1, 0, 1));
        drop(client2);
        server.join().unwrap();
    }

    #[test]
    fn legacy_json_and_rpc2_interleave_on_one_socket() {
        // Protocol independence: the same connection serves a JSON cid-fetch
        // AND an rpc2 request, per-frame.
        let (dir, cid) = fixture_dir(b"shared socket body");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(&mut s, dirpath.to_str().unwrap());
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        fetch_stream(&mut client, &cid, None).expect("json fetch");
        let req = p2p::cbor::message("Peer.Chain", 5, "", chain_request(0, 10));
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(m.error, "");
        assert_eq!(m.payload.as_array().unwrap().len(), 1);
        drop(client);
        server.join().unwrap();
    }

    // Guard the fixture helper itself.
    #[test]
    fn fixture_writes_body_file() {
        let (dir, cid) = fixture_dir(b"probe");
        assert!(dir.join(format!("{cid}.body")).exists());
        assert_eq!(cid.len(), 64);
        let _ = std::fs::File::create(dir.join("x")); // touch
        let mut f = std::fs::File::open(dir.join(format!("{cid}.body"))).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"probe");
        let _ = std::io::stdout().flush();
    }
}
