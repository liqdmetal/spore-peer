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
//! Usage:
//!   spore-peer serve --listen 0.0.0.0:8099 --dir <body-store-dir>   (sender)
//!   spore-peer fetch --addr host:8099 --cid <64-hex> [--out file]   (recipient)
//!
//! Protocol (JSON over the frame):
//!   request : {"cid": "<64-hex>"}
//!   response: 200 + raw body bytes          (body sha256 must == cid)
//!             404 "not found"               (sender no longer holds it)
use std::fs;
use std::net::{TcpListener, TcpStream};

mod p2p;
use p2p::{read_frame, write_frame};

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
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

fn handle_client(s: &mut TcpStream, dir: &str) {
    let body = match read_frame(s) {
        Ok(b) => b,
        Err(_) => return,
    };
    // Request is a small JSON object: {"cid":"<hex>"}.
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let _ = write_frame(s, b"400 bad request");
            return;
        }
    };
    let cid = req.get("cid").and_then(|c| c.as_str()).unwrap_or("");
    let raw = match hex_decode(cid) {
        Some(r) if r.len() == 32 => r,
        _ => {
            let _ = write_frame(s, b"400 bad cid");
            return;
        }
    };
    let path = format!("{dir}/{cid}.body");
    match fs::read(&path) {
        Ok(data) => {
            // Verify sha256(body) == cid before serving.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&data);
            let digest = h.finalize();
            if digest[..] == raw[..] {
                let _ = write_frame(s, &data);
            } else {
                let _ = write_frame(s, b"500 cid mismatch");
            }
        }
        Err(_) => {
            let _ = write_frame(s, b"404 not found");
        }
    }
}

fn fetch(addr: &str, cid: &str, out: Option<&str>) -> std::io::Result<()> {
    let mut s = TcpStream::connect(addr)?;
    let req = serde_json::json!({ "cid": cid });
    write_frame(&mut s, req.to_string().as_bytes())?;
    let resp = read_frame(&mut s)?;
    // Distinguish errors (ASCII text) from a body (arbitrary bytes).
    if resp.starts_with(b"4") || resp.starts_with(b"5") {
        eprintln!("fetch failed: {}", String::from_utf8_lossy(&resp));
        std::process::exit(1);
    }
    // Integrity: sha256(resp) must equal cid.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&resp);
    let digest = h.finalize();
    let expected = hex_decode(cid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad cid hex"))?;
    if digest[..] != expected[..] {
        eprintln!("fetch failed: body sha256 does not match cid (tampered)");
        std::process::exit(1);
    }
    eprintln!("fetched {} bytes, integrity OK", resp.len());
    if let Some(path) = out {
        fs::write(path, &resp)?;
        eprintln!("wrote {path}");
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: spore-peer <serve|fetch> ...");
        std::process::exit(2);
    }
    match args[1].as_str() {
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
            let _ = serve(&addr, &dir);
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
                std::process::exit(2);
            }
            let _ = fetch(&addr, &cid, out.as_deref());
        }
        _ => {
            eprintln!("unknown subcommand");
            std::process::exit(2);
        }
    }
}
