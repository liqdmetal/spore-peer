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
//!
//! Request (over the frame): JSON {"cid": "<64-hex>"}.
use std::fs;
use std::net::{TcpListener, TcpStream};

mod p2p;
use p2p::{read_frame, write_frame};

/// Response status bytes (first byte of every response frame).
const STATUS_OK: u8 = 0x00;
const STATUS_ERR: u8 = 0x01;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
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

fn handle_client(s: &mut TcpStream, dir: &str) {
    let body = match read_frame(s) {
        Ok(b) => b,
        Err(_) => return,
    };
    // Request is a small JSON object: {"cid":"<hex>"}.
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let _ = write_frame(s, &frame_err("400 bad request"));
            return;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: spore-peer <serve|fetch> ...");
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
        let err = fetch_stream(&mut client, &cid, None).unwrap_err();
        assert!(err.contains("404"), "got: {err}");
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
