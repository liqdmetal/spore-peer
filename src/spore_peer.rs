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
//!   spore-peer sync  --addr host:8099 --dir <body-store-dir>        (rpc2 pull subset)
//!   spore-peer push  --addr host:8099 --dir <body-store-dir>        (rpc2 push subset)
//!   spore-peer peers --dir <store> add|remove <host:port> | list    (peer list)
//!   spore-peer sync-loop --dir <store> [--interval 30] [--once]     (bidirectional convergence)
//!
//! Request (over the frame): JSON {"cid": "<64-hex>"}, or an rpc2/CBOR map
//! (Peer.Handshake / Peer.Chain / Peer.GetObject / Peer.PutObject) on the
//! same port.
use std::collections::HashMap;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

// The wire codec lives in the library crate (src/p2p.rs) so benchmarks and
// hostile-frame tests can exercise it without spawning the binary.
use spore_peer::p2p;
use spore_peer::p2p::{
    chain_request, chain_response, decode_message, error_response, getobject_request,
    getobject_response, handshake_request, handshake_response, putobject_request,
    putobject_response, read_frame, rpc2_call, write_frame, Rpc2Message,
};

/// Largest body a peer may push into the local store (also the frame cap's
/// practical limit: a push request carries BLID + BODY in one CBOR frame).
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Write-path policy for a serve node. Read paths (cid-fetch, GetObject,
/// Chain) stay open; writes (PutObject) are gated here so a public node is
/// not a disk-fill target for strangers.
#[derive(Default, Clone)]
struct ServeConfig {
    /// Total bytes across *.body files; a PutObject that would exceed this
    /// is refused (507). 0 = unlimited.
    max_store_bytes: u64,
    /// Max PutObject pushes per client IP per minute. 0 = unlimited.
    put_rate: u32,
    /// If set, every PutObject must carry TOKEN == this secret. Read paths
    /// never need it. 0/None = no auth (content-addressed writes are safe
    /// from poisoning, but not from disk fill).
    token: Option<String>,
}

/// Fixed-window per-IP push counter. Bounded memory: stale windows are
/// overwritten on the next hit from that IP, never accumulated.
struct RateLimiter {
    max: u32,
    wins: std::sync::Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
    fn new(max: u32) -> Self {
        RateLimiter {
            max,
            wins: std::sync::Mutex::new(HashMap::new()),
        }
    }
    fn allow(&self, ip: &str, now_sec: u64) -> bool {
        if self.max == 0 {
            return true;
        }
        let mut w = self.wins.lock().unwrap();
        let e = w.entry(ip.to_string()).or_insert((now_sec, 0));
        if e.0 != now_sec {
            *e = (now_sec, 1);
            return true;
        }
        if e.1 >= self.max {
            return false;
        }
        e.1 += 1;
        true
    }
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time-ish equality for the optional write token. Length is not
/// secret, bytes are compared without early exit.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        d |= x ^ y;
    }
    d == 0
}

/// Sum of *.body file bytes in the store (the quota baseline). O(n) per
/// check; peer stores are small and pushes are rare — a full walk is fine.
fn store_bytes(dir: &str) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) == Some("body") {
                if let Ok(md) = fs::metadata(&p) {
                    total = total.saturating_add(md.len());
                }
            }
        }
    }
    total
}

/// Gate a PutObject against the serve policy: rate limit, store quota, and
/// (optionally) the write token carried in the request payload.
fn enforce_write_policy(
    cfg: &ServeConfig,
    ip: &str,
    dir: &str,
    body_len: usize,
    limiter: &RateLimiter,
    payload: &serde_json::Value,
) -> Result<(), String> {
    if !limiter.allow(ip, now_sec()) {
        return Err("429 put rate limit exceeded".to_string());
    }
    if let Some(tok) = &cfg.token {
        let given = payload.get("TOKEN").and_then(|v| v.as_str()).unwrap_or("");
        if !ct_eq(given, tok) {
            return Err("401 bad write token".to_string());
        }
    }
    if cfg.max_store_bytes > 0 {
        let used = store_bytes(dir);
        if used.saturating_add(body_len as u64) > cfg.max_store_bytes {
            return Err("507 store full".to_string());
        }
    }
    Ok(())
}

/// store_body writes `body` into the store under the hash it COMPUTES, never
/// under a caller-supplied name: the only way a file lands in the store is
/// with sha256(body) == its filename. Returns the 64-hex CID. Integrity rule
/// is identical for locally-stored and peer-pushed bodies.
fn store_body(dir: &str, body: &[u8]) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    if body.is_empty() {
        return Err("400 empty body".to_string());
    }
    if body.len() > MAX_BODY_BYTES {
        return Err("413 body too large".to_string());
    }
    let mut h = Sha256::new();
    h.update(body);
    let cid = h.finalize();
    let cid_hex = hex::encode(cid);
    let final_path = format!("{dir}/{cid_hex}.body");
    if fs::metadata(&final_path).is_ok() {
        return Ok(cid_hex); // already stored — a push of a known body is a no-op
    }
    fs::create_dir_all(dir).map_err(|e| format!("dir {dir}: {e}"))?;
    // Write to a temp name in the same directory, then rename: a concurrent
    // reader can never observe a half-written body (rename is atomic on the
    // platforms spore-peer targets).
    let tmp_path = format!("{dir}/.incoming-{cid_hex}.part");
    fs::write(&tmp_path, body).map_err(|e| format!("write {tmp_path}: {e}"))?;
    if let Err(e) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("rename {tmp_path}: {e}"));
    }
    Ok(cid_hex)
}

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
/// body store as its ledger. The caller loops per frame, so one connection
/// serves many requests.
fn handle_rpc2(
    s: &mut TcpStream,
    msg: &Rpc2Message,
    dir: &str,
    ip: &str,
    cfg: &ServeConfig,
    limiter: &RateLimiter,
) {
    use sha2::{Digest, Sha256};
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
        "Peer.PutObject" => {
            // Push direction: a peer hands us a body it believes we lack. The
            // server is the judge — sha256(BODY) is recomputed here and must
            // equal BLID, and the file is stored under the hash WE computed
            // (store_body). A lying or corrupting peer gets a 400 and writes
            // nothing; a valid body of any claimed name lands under its true
            // hash. Size cap and empty-body rejection live in store_body.
            let body_hex = msg
                .payload
                .get("BODY")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body = match hex::decode(body_hex) {
                Ok(b) => b,
                Err(_) => {
                    let _ = write_frame(s, &error_response(msg.seq, "400 body not valid hex"));
                    return;
                }
            };
            let blid_hex = msg
                .payload
                .get("BLID")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Write-policy gate: per-IP rate limit, optional write token, and
            // the total-store quota. Read paths never pass through here.
            if let Err(e) = enforce_write_policy(cfg, ip, dir, body.len(), limiter, &msg.payload) {
                let _ = write_frame(s, &error_response(msg.seq, &e));
                return;
            }
            let mut h = Sha256::new();
            h.update(&body);
            let digest = h.finalize();
            let blid_ok =
                hex_decode(blid_hex).is_some_and(|b| b.len() == 32 && b[..] == digest[..]);
            if !blid_ok {
                let _ = write_frame(s, &error_response(msg.seq, "400 body sha256 != BLID"));
                return;
            }
            match store_body(dir, &body) {
                Ok(cid_hex) => {
                    let mut blid = [0u8; 32];
                    if let Some(b) = hex_decode(&cid_hex) {
                        blid.copy_from_slice(&b);
                    }
                    let resp = putobject_response(&blid);
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

fn handle_client(
    s: &mut TcpStream,
    dir: &str,
    ip: String,
    cfg: &ServeConfig,
    limiter: &RateLimiter,
) {
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
                handle_rpc2(s, &msg, dir, &ip, cfg, limiter);
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
    let hs = rpc2_call(s, "Peer.Handshake", 1, handshake_request(1)).map_err(|e| e.to_string())?;
    if !hs.error.is_empty() {
        return Err(format!("handshake: {}", hs.error));
    }
    let peer_height = hs.payload.get("H").and_then(|v| v.as_u64()).unwrap_or(0);

    // 2. chain: newest-first list of [topoheight, blid].
    let chain = rpc2_call(s, "Peer.Chain", 2, chain_request(0, 5000)).map_err(|e| e.to_string())?;
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
        let obj = rpc2_call(
            s,
            "Peer.GetObject",
            100 + i as u64,
            getobject_request(&blid),
        )
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
    eprintln!("synced from {addr}: peer height {height}, fetched {fetched}, already had {have}");
    Ok(())
}

/// push_stream is the inverse of sync_stream: after the handshake, pull the
/// peer's chain and Peer.PutObject every LOCAL body the peer is missing,
/// sha256-verified locally before sending (the server re-verifies anyway —
/// we just refuse to ship garbage). Returns (peer_height, pushed, peer_had).
fn push_stream(s: &mut TcpStream, dir: &str, token: &str) -> Result<(u64, usize, usize), String> {
    // 1. handshake: learn the peer's height (also proves it speaks rpc2).
    let hs = rpc2_call(s, "Peer.Handshake", 1, handshake_request(1)).map_err(|e| e.to_string())?;
    if !hs.error.is_empty() {
        return Err(format!("handshake: {}", hs.error));
    }
    let peer_height = hs.payload.get("H").and_then(|v| v.as_u64()).unwrap_or(0);

    // 2. chain: everything the peer already has, newest-first.
    let chain = rpc2_call(s, "Peer.Chain", 2, chain_request(0, 5000)).map_err(|e| e.to_string())?;
    if !chain.error.is_empty() {
        return Err(format!("chain: {}", chain.error));
    }
    let empty = Vec::new();
    let entries = chain.payload.as_array().unwrap_or(&empty);
    let mut peer_has: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in entries {
        let pair = entry.as_array().ok_or("chain entry not an array")?;
        if pair.len() != 2 {
            return Err("chain entry must be [topoheight, blid]".to_string());
        }
        peer_has.insert(pair[1].as_str().unwrap_or("").to_string());
    }

    // 3. push every local body the peer lacks (mtime order = topo order).
    let mut pushed = 0usize;
    let mut attempted = 0usize;
    for (topo, cid) in chain_view(dir) {
        if peer_has.contains(&hex::encode(cid)) {
            continue; // peer already has it
        }
        if attempted >= 2000 {
            break; // same per-pass cap as the pull direction
        }
        attempted += 1;
        let path = format!("{dir}/{}.body", hex::encode(cid));
        let body = fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
        // Never ship bytes that do not hash to the CID we advertise.
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&body);
            if h.finalize()[..] != cid[..] {
                eprintln!("push: skipping corrupt store file for topo {topo}");
                continue;
            }
        }
        let resp = rpc2_call(
            s,
            "Peer.PutObject",
            200 + attempted as u64,
            putobject_request(&cid, &body, token),
        )
        .map_err(|e| e.to_string())?;
        if !resp.error.is_empty() {
            if resp.error.contains("401") {
                return Err(format!(
                    "push: write token rejected by peer: {}",
                    resp.error
                ));
            }
            eprintln!("push: topo {topo}: {}", resp.error);
            continue;
        }
        // The server answers with the hash it actually stored; a mismatch
        // means we and the peer disagree about the object — fail loudly.
        let stored = resp
            .payload
            .get("BLID")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if stored != hex::encode(cid) {
            return Err(format!(
                "topo {topo}: peer stored different hash ({stored})"
            ));
        }
        pushed += 1;
    }
    Ok((peer_height, pushed, peer_has.len()))
}

/// push runs one push pass against a single peer.
fn push(addr: &str, dir: &str, token: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("dir {dir}: {e}"))?;
    let mut s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let (height, pushed, peer_had) = push_stream(&mut s, dir, token)?;
    eprintln!(
        "pushed to {addr}: peer height {height}, pushed {pushed}, peer already had {peer_had}"
    );
    Ok(())
}

// --- multi-peer convergence (peers list + periodic sync loop) ---

/// The peers list lives in the store dir as `peers.txt`: one `host:port` per
/// line, `#` comments and blank lines ignored, deduplicated on write.
fn peers_path(dir: &str) -> String {
    format!("{dir}/peers.txt")
}

fn peers_list(dir: &str) -> Vec<String> {
    let text = match fs::read_to_string(peers_path(dir)) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !out.iter().any(|p| p == line) {
            out.push(line.to_string());
        }
    }
    out
}

/// `host:port` shape check: non-empty host, numeric port 1..=65535, no
/// whitespace or path characters. rsplit_once keeps raw IPv6 literals
/// (`::1:8099`) and bracketed forms (`[::1]:8099`) working.
fn validate_peer_addr(addr: &str) -> Result<(), String> {
    if addr
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\')
    {
        return Err(format!(
            "peer '{addr}': whitespace and path characters are not allowed"
        ));
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err(format!("peer '{addr}': need host:port"));
    };
    if host.is_empty() {
        return Err(format!("peer '{addr}': empty host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("peer '{addr}': port must be numeric (1-65535)"))?;
    if port == 0 {
        return Err(format!("peer '{addr}': port 0 is not connectable"));
    }
    Ok(())
}

fn peers_write(dir: &str, list: &[String]) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("dir {dir}: {e}"))?;
    let mut body = String::from("# spore-peer peers list: one host:port per line\n");
    for p in list {
        body.push_str(p);
        body.push('\n');
    }
    fs::write(peers_path(dir), body).map_err(|e| e.to_string())
}

/// Returns Ok(true) if the peer was newly added, Ok(false) if already known.
fn peers_add(dir: &str, addr: &str) -> Result<bool, String> {
    validate_peer_addr(addr)?;
    let mut list = peers_list(dir);
    if list.iter().any(|p| p == addr) {
        return Ok(false);
    }
    list.push(addr.to_string());
    peers_write(dir, &list)?;
    Ok(true)
}

/// Returns Ok(true) if the peer was removed, Ok(false) if it was not listed.
fn peers_remove(dir: &str, addr: &str) -> Result<bool, String> {
    let list = peers_list(dir);
    let kept: Vec<String> = list
        .iter()
        .filter(|p| p.as_str() != addr)
        .cloned()
        .collect();
    if kept.len() == list.len() {
        return Ok(false);
    }
    peers_write(dir, &kept)?;
    Ok(true)
}

/// One convergence pass, bidirectional: for every peer in the list, PULL
/// what it has and PUSH what it lacks, over one socket each (the rpc2
/// connection is persistent). A dead or unreachable peer is logged and
/// skipped, never fatal — convergence must not depend on every peer being
/// online. Returns (ok, failed, transferred = bodies fetched + pushed).
fn sync_pass(dir: &str) -> (usize, usize, u64) {
    let peers = peers_list(dir);
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut transferred = 0u64;
    for addr in &peers {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                let pull = sync_stream(&mut s, dir);
                let push = if pull.is_ok() {
                    push_stream(&mut s, dir, "")
                } else {
                    Err("skipped (pull failed)".to_string())
                };
                match (pull, push) {
                    (Ok((_, f, _)), Ok((_, p, _))) => {
                        ok += 1;
                        transferred += (f + p) as u64;
                    }
                    (Err(e), _) => {
                        eprintln!("sync-loop: {addr}: {e}");
                        failed += 1;
                    }
                    (_, Err(e)) => {
                        eprintln!("sync-loop: {addr}: push: {e}");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("sync-loop: {addr}: unreachable ({e})");
                failed += 1;
            }
        }
    }
    (ok, failed, transferred)
}

/// Periodic convergence loop: one sync_pass every `interval` seconds, forever
/// (or once, with `once`). Returns the last pass summary when running --once.
fn sync_loop(dir: &str, interval: u64, once: bool) -> Result<(usize, usize, u64), String> {
    fs::create_dir_all(dir).map_err(|e| format!("dir {dir}: {e}"))?;
    loop {
        let (ok, failed, transferred) = sync_pass(dir);
        eprintln!(
            "sync-loop: pass done: {ok} peer(s) synced, {failed} failed, {transferred} body(ies) transferred"
        );
        if once {
            return Ok((ok, failed, transferred));
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: spore-peer <serve|fetch|sync|push|peers|sync-loop> ...");
        std::process::exit(2);
    }
    let code = match args[1].as_str() {
        "serve" => {
            let mut addr = "0.0.0.0:8099".to_string();
            let mut dir = ".".to_string();
            let mut cfg = ServeConfig::default();
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
                    "--max-store-bytes" => {
                        if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                            cfg.max_store_bytes = v;
                        }
                        i += 2;
                    }
                    "--put-rate" => {
                        if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) {
                            cfg.put_rate = v;
                        }
                        i += 2;
                    }
                    "--token" => {
                        cfg.token = args.get(i + 1).cloned();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            match serve(&addr, &dir, cfg) {
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
        "push" => {
            let mut addr = String::new();
            let mut dir = ".".to_string();
            let mut token = String::new();
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
                    "--token" => {
                        token = args.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            if addr.is_empty() {
                eprintln!("push needs --addr");
                2
            } else {
                match push(&addr, &dir, &token) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("push failed: {e}");
                        1
                    }
                }
            }
        }
        "peers" => {
            // peers --dir <store> add|remove <host:port> | list
            let mut dir = ".".to_string();
            let mut op = String::new();
            let mut addr = String::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--dir" => {
                        dir = args.get(i + 1).cloned().unwrap_or(dir);
                        i += 2;
                    }
                    "add" | "remove" => {
                        op = args[i].clone();
                        addr = args.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                    }
                    "list" => {
                        op = "list".to_string();
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            match op.as_str() {
                "add" if !addr.is_empty() => match peers_add(&dir, &addr) {
                    Ok(true) => {
                        eprintln!("peer added: {addr}");
                        0
                    }
                    Ok(false) => {
                        eprintln!("peer already listed: {addr}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                },
                "remove" if !addr.is_empty() => match peers_remove(&dir, &addr) {
                    Ok(true) => {
                        eprintln!("peer removed: {addr}");
                        0
                    }
                    Ok(false) => {
                        eprintln!("peer not listed: {addr}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                },
                "list" => {
                    let peers = peers_list(&dir);
                    for p in &peers {
                        println!("{p}");
                    }
                    eprintln!("{} peer(s) in {}", peers.len(), peers_path(&dir));
                    0
                }
                _ => {
                    eprintln!("peers needs: add <host:port> | remove <host:port> | list");
                    2
                }
            }
        }
        "sync-loop" => {
            let mut dir = ".".to_string();
            let mut interval = 30u64;
            let mut once = false;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--dir" => {
                        dir = args.get(i + 1).cloned().unwrap_or(dir);
                        i += 2;
                    }
                    "--interval" => {
                        interval = args
                            .get(i + 1)
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(interval);
                        i += 2;
                    }
                    "--once" => {
                        once = true;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            match sync_loop(&dir, interval, once) {
                Ok((_ok, failed, _)) => {
                    if once && failed > 0 {
                        1 // --once is scriptable: nonzero when any peer failed
                    } else {
                        0
                    }
                }
                Err(e) => {
                    eprintln!("sync-loop failed: {e}");
                    1
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

fn serve(addr: &str, dir: &str, cfg: ServeConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let limiter = Arc::new(RateLimiter::new(cfg.put_rate));
    eprintln!("spore-peer serve: listening on {addr}, bodies in {dir} (max_store_bytes={} put_rate={}/min write_token={})",
        cfg.max_store_bytes, cfg.put_rate, if cfg.token.is_some() { "set" } else { "off" });
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let d = dir.to_string();
                let ip = s
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                let c = cfg.clone();
                let l = Arc::clone(&limiter);
                std::thread::spawn(move || handle_client(&mut s, &d, ip, &c, &l));
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
        assert_eq!(serve_body(&d, &"a".repeat(63)).unwrap_err(), "400 bad cid");
        // Path traversal must be impossible: a ".." payload can't pass the hex gate.
        assert_eq!(
            serve_body(&d, "../../etc/passwd").unwrap_err(),
            "400 bad cid"
        );
    }

    #[test]
    fn serve_body_rejects_cid_mismatch() {
        // File exists but its sha256 != requested cid (corrupted or planted).
        let dir = mk_temp_dir("mismatch");
        let bogus_cid = "1111111111111111111111111111111111111111111111111111111111111111";
        fs::write(dir.join(format!("{bogus_cid}.body")), b"actual bytes").unwrap();
        let err = serve_body(dir.clone().to_str().unwrap(), bogus_cid).unwrap_err();
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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
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
        let pairs = [(2u64, [0xAAu8; 32]), (1u64, [0x11u8; 32])];
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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
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
        assert_eq!(
            hex::decode(body_hex).unwrap(),
            b"rpc2 body for Peer.GetObject"
        );

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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        // Unknown method -> E is set.
        let req = p2p::cbor::message("Peer.Nope", 1, "", Vec::new());
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert!(m.error.contains("501"), "got: {}", m.error);

        // Missing object -> E carries the 404.
        let req = p2p::cbor::message("Peer.GetObject", 2, "", getobject_request(&[0xEE; 32]));
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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
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
        fs::write(server_dir.join(format!("{}.body", sha256_hex(body))), body).unwrap();
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
                handle_client(
                    &mut s,
                    dirpath.to_str().unwrap(),
                    "127.0.0.1".to_string(),
                    &ServeConfig::default(),
                    &RateLimiter::new(0),
                );
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
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
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

    // --- multi-peer convergence (peers list + sync-loop) ---

    #[test]
    fn peers_add_list_remove_dedupe_and_persist() {
        let dir = mk_temp_dir("peers");
        let d = dir.to_str().unwrap();
        assert!(peers_list(d).is_empty(), "fresh store has no peers");

        assert!(peers_add(d, "10.0.0.1:8099").unwrap());
        assert!(
            !peers_add(d, "10.0.0.1:8099").unwrap(),
            "duplicate add is a no-op"
        );
        assert!(peers_add(d, "10.0.0.2:8099").unwrap());
        assert_eq!(peers_list(d), vec!["10.0.0.1:8099", "10.0.0.2:8099"]);

        // The list survives a fresh read (persistence via peers.txt).
        let reread = peers_list(d);
        assert_eq!(reread.len(), 2);

        // Comments and blanks in a hand-edited file are ignored.
        fs::write(
            peers_path(d),
            "# comment\n\n10.0.0.3:8099\n  10.0.0.4:8099  \n",
        )
        .unwrap();
        assert_eq!(
            peers_list(d),
            vec!["10.0.0.3:8099", "10.0.0.4:8099"],
            "trim + comment skip"
        );

        assert!(peers_remove(d, "10.0.0.3:8099").unwrap());
        assert!(
            !peers_remove(d, "10.0.0.3:8099").unwrap(),
            "removing twice is a no-op"
        );
        assert_eq!(peers_list(d), vec!["10.0.0.4:8099"]);
    }

    #[test]
    fn peers_reject_bad_addrs() {
        let dir = mk_temp_dir("peers-bad");
        let d = dir.to_str().unwrap();
        assert!(peers_add(d, "no-port").is_err());
        assert!(peers_add(d, "host:0").is_err(), "port 0 is not connectable");
        assert!(peers_add(d, "host:99999").is_err());
        assert!(peers_add(d, ":8099").is_err());
        assert!(peers_add(d, "bad host:8099").is_err(), "no whitespace");
        assert!(
            peers_add(d, "../../etc:8099").is_err(),
            "no path characters"
        );
        // These are VALID and must be accepted:
        assert!(peers_add(d, "localhost:8099").unwrap());
        assert!(peers_add(d, "::1:8099").unwrap(), "raw IPv6 literal");
        assert!(peers_add(d, "[::1]:8099").unwrap(), "bracketed IPv6");
    }

    #[test]
    fn sync_loop_once_converges_two_peers() {
        // Two servers, one empty client. peers.txt lists both; a single
        // --once pass must converge the client from both. Server A holds
        // "from alpha", server B holds "from beta".
        let dir_a = mk_temp_dir("conv-a");
        let dir_b = mk_temp_dir("conv-b");
        let client = mk_temp_dir("conv-client");

        let body_a = b"from alpha";
        let body_b = b"from beta";
        fs::write(dir_a.join(format!("{}.body", sha256_hex(body_a))), body_a).unwrap();
        fs::write(dir_b.join(format!("{}.body", sha256_hex(body_b))), body_b).unwrap();

        let lsn_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_a = lsn_a.local_addr().unwrap().to_string();
        let lsn_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_b = lsn_b.local_addr().unwrap().to_string();

        // Each server serves two sequential connections: this pass and the
        // post-add re-check later in the test.
        for (lsn, d) in [(&lsn_a, &dir_a), (&lsn_b, &dir_b)] {
            let lsn = lsn.try_clone().unwrap();
            let d = d.clone();
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let (stream, _) = lsn.accept().unwrap();
                    let mut s = stream;
                    handle_client(
                        &mut s,
                        d.to_str().unwrap(),
                        "127.0.0.1".to_string(),
                        &ServeConfig::default(),
                        &RateLimiter::new(0),
                    );
                }
            });
        }

        // List both peers, then converge in one pass.
        peers_add(client.to_str().unwrap(), &addr_a).unwrap();
        peers_add(client.to_str().unwrap(), &addr_b).unwrap();
        let (ok, failed, transferred) =
            sync_loop(client.to_str().unwrap(), 30, true).expect("pass");
        assert_eq!((ok, failed), (2, 0));
        // Pull a from A, pull b from B, then push a to B (it lacks it — the
        // pass is bidirectional now). Transferred = 3.
        assert_eq!(transferred, 3);

        // Both bodies landed locally.
        assert!(client.join(format!("{}.body", sha256_hex(body_a))).exists());
        assert!(client.join(format!("{}.body", sha256_hex(body_b))).exists());

        // After adding a third peer, a pass fails exactly once (dead peer is
        // skipped, live peers still converge).
        peers_add(client.to_str().unwrap(), "127.0.0.1:1").unwrap();
        let (ok, failed, _fetched) = sync_loop(client.to_str().unwrap(), 30, true).expect("pass 2");
        assert_eq!((ok, failed), (2, 1), "dead peer must not break the pass");
    }

    #[test]
    fn sync_pass_empty_list_is_a_clean_noop() {
        let dir = mk_temp_dir("conv-none");
        let (ok, failed, transferred) = sync_pass(dir.to_str().unwrap());
        assert_eq!((ok, failed, transferred), (0, 0, 0));
    }

    // --- push direction (Peer.PutObject) ---

    #[test]
    fn store_body_names_files_by_computed_hash() {
        let dir = mk_temp_dir("store");
        let d = dir.to_str().unwrap();
        let cid = store_body(d, b"hash-named body").unwrap();
        assert_eq!(cid, sha256_hex(b"hash-named body"));
        assert_eq!(
            fs::read(dir.join(format!("{cid}.body"))).unwrap(),
            b"hash-named body"
        );

        // Re-storing the same bytes is a no-op (already present).
        assert_eq!(store_body(d, b"hash-named body").unwrap(), cid);

        // Empty bodies are rejected outright.
        assert!(store_body(d, b"").is_err());

        // Oversized bodies are rejected without touching the store.
        let before = fs::read_dir(&dir).unwrap().count();
        let big = vec![0u8; MAX_BODY_BYTES + 1];
        assert!(store_body(d, &big).is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), before);

        // No temp files left behind.
        assert!(!fs::read_dir(&dir).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".incoming-")));
    }

    #[test]
    fn server_accepts_push_and_rejects_tampered_frames() {
        // A push of a body whose sha256 != BLID must be rejected with a 400
        // and must store NOTHING; a valid push stores under the true hash.
        let (dir, cid) = fixture_dir(b"server-push body");
        let blid = hex::decode(&cid).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        let mut fake_blid = [0u8; 32];
        fake_blid.copy_from_slice(&blid);

        // 1. tampered: BLID does not match the body's real hash.
        let req = p2p::cbor::message(
            "Peer.PutObject",
            1,
            "",
            putobject_request(&fake_blid, b"totally different bytes", ""),
        );
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert!(
            m.error.contains("400"),
            "tampered push must be rejected, got: {}",
            m.error
        );

        // 2. non-hex BODY (a CBOR text string, as a hostile peer would send).
        let bogus = p2p::cbor::message("Peer.PutObject", 2, "", {
            let mut out = p2p::cbor::map(2);
            out.extend_from_slice(&p2p::cbor::kv("BLID", &p2p::cbor::hash32(&fake_blid)));
            out.extend_from_slice(&p2p::cbor::kv("BODY", &p2p::cbor::text("not-hex-zz")));
            out
        });
        p2p::write_frame(&mut client, &bogus).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert!(m.error.contains("400"), "non-hex BODY must be rejected");

        // 3. valid push of a NEW body lands under its computed hash.
        let fresh = b"a brand new pushed body";
        let fresh_cid = sha256_hex(fresh);
        let mut fresh_blid = [0u8; 32];
        fresh_blid.copy_from_slice(&hex::decode(&fresh_cid).unwrap());
        let req = p2p::cbor::message(
            "Peer.PutObject",
            3,
            "",
            putobject_request(&fresh_blid, fresh, ""),
        );
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(m.error, "");
        assert_eq!(
            m.payload.get("BLID").and_then(|v| v.as_str()),
            Some(fresh_cid.as_str())
        );
        assert_eq!(
            fs::read(dir.join(format!("{fresh_cid}.body"))).unwrap(),
            fresh
        );

        // 4. re-pushing the same body is a clean no-op success.
        let req = p2p::cbor::message(
            "Peer.PutObject",
            4,
            "",
            putobject_request(&fresh_blid, fresh, ""),
        );
        p2p::write_frame(&mut client, &req).unwrap();
        let m = p2p::decode_message(&p2p::read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(m.error, "");

        // The tampered/garbage attempts stored nothing beyond the two valid bodies.
        let bodies = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".body"))
            .count();
        assert_eq!(bodies, 2, "rejected pushes must not leave files");
        drop(client);
        server.join().unwrap();
        let _ = cid;
    }

    #[test]
    fn push_stream_ships_only_missing_bodies() {
        // Server store starts with body A; client store holds A and B. The
        // push must send only B, skip A (peer already has it), and the server
        // store must end with both.
        let body_a = b"push-already-there";
        let body_b = b"push-the-missing-one";
        let server_dir = mk_temp_dir("push-server");
        let client_dir = mk_temp_dir("push-client");
        fs::write(
            server_dir.join(format!("{}.body", sha256_hex(body_a))),
            body_a,
        )
        .unwrap();
        for b in [body_a.as_slice(), body_b.as_slice()] {
            fs::write(client_dir.join(format!("{}.body", sha256_hex(b))), b).unwrap();
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dirpath = server_dir.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            handle_client(
                &mut s,
                dirpath.to_str().unwrap(),
                "127.0.0.1".to_string(),
                &ServeConfig::default(),
                &RateLimiter::new(0),
            );
        });

        let mut client = std::net::TcpStream::connect(&addr).unwrap();
        let (height, pushed, peer_had) =
            push_stream(&mut client, client_dir.to_str().unwrap(), "").expect("push");
        assert_eq!((height, pushed, peer_had), (1, 1, 1));
        drop(client);
        server.join().unwrap();

        let stored = fs::read(server_dir.join(format!("{}.body", sha256_hex(body_b))));
        assert_eq!(
            stored.unwrap(),
            body_b,
            "missing body must land on the peer"
        );
    }

    #[test]
    fn bidirectional_pass_converges_two_stores() {
        // The core guarantee: one pull+push pass over one socket per peer
        // makes BOTH stores converge to the union, regardless of who starts
        // with what.
        let dir_a = mk_temp_dir("bidi-a");
        let dir_b = mk_temp_dir("bidi-b");
        let body_a = b"only a starts with this";
        let body_b = b"only b starts with this";
        fs::write(dir_a.join(format!("{}.body", sha256_hex(body_a))), body_a).unwrap();
        fs::write(dir_b.join(format!("{}.body", sha256_hex(body_b))), body_b).unwrap();

        let lsn_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_a = lsn_a.local_addr().unwrap().to_string();
        let lsn_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_b = lsn_b.local_addr().unwrap().to_string();

        // Server A pulls from B first (gets body_b), then B pulls from A —
        // but by then B already pushed... this test just runs a full
        // bidirectional pass from ONE side and verifies union convergence.
        let dpa = dir_a.clone();
        let dpb = dir_b.clone();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = lsn_b.accept() {
                handle_client(
                    &mut s,
                    dpb.to_str().unwrap(),
                    "127.0.0.1".to_string(),
                    &ServeConfig::default(),
                    &RateLimiter::new(0),
                );
            }
        });

        // Client-side: store A syncs with B over one connection.
        let mut s = std::net::TcpStream::connect(&addr_b).unwrap();
        let (_, fetched, _) = sync_stream(&mut s, dir_a.to_str().unwrap()).expect("pull");
        let (_, pushed, _) = push_stream(&mut s, dir_a.to_str().unwrap(), "").expect("push");
        assert_eq!(fetched, 1, "A pulls B's body");
        assert_eq!(pushed, 1, "A pushes its body to B");
        drop(s);

        // Both stores now hold the union.
        for d in [&dir_a, &dir_b] {
            assert!(
                d.join(format!("{}.body", sha256_hex(body_a))).exists(),
                "a in {d:?}"
            );
            assert!(
                d.join(format!("{}.body", sha256_hex(body_b))).exists(),
                "b in {d:?}"
            );
        }
        let _ = (dpa, addr_a, lsn_a); // symmetric direction covered by sync-loop tests
    }

    #[test]
    fn sync_loop_pass_is_bidirectional() {
        // Two servers each holding one distinct body; the client store
        // starts with a THIRD body. One --once pass must: pull both remote
        // bodies into the client AND push the client's body out to BOTH
        // servers. Final state: all three stores hold all three bodies.
        let dir_a = mk_temp_dir("loop-a");
        let dir_b = mk_temp_dir("loop-b");
        let dir_c = mk_temp_dir("loop-c");
        let body_a = b"lives on a";
        let body_b = b"lives on b";
        let body_c = b"lives on client";
        fs::write(dir_a.join(format!("{}.body", sha256_hex(body_a))), body_a).unwrap();
        fs::write(dir_b.join(format!("{}.body", sha256_hex(body_b))), body_b).unwrap();
        fs::write(dir_c.join(format!("{}.body", sha256_hex(body_c))), body_c).unwrap();

        let lsn_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_a = lsn_a.local_addr().unwrap().to_string();
        let lsn_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_b = lsn_b.local_addr().unwrap().to_string();

        // Each server serves TWO sequential connections (the pass pulls and
        // pushes over ONE socket per peer, so why two? — the pull pass and
        // push pass both run inside sync_pass on the same socket; two
        // connections are only needed because the test re-checks after the
        // pass via a second sync). Serve generously: 4 connections each.
        for (lsn, d) in [(&lsn_a, &dir_a), (&lsn_b, &dir_b)] {
            let lsn = lsn.try_clone().unwrap();
            let d = d.clone();
            std::thread::spawn(move || {
                for _ in 0..4 {
                    let (stream, _) = lsn.accept().unwrap();
                    let mut s = stream;
                    handle_client(
                        &mut s,
                        d.to_str().unwrap(),
                        "127.0.0.1".to_string(),
                        &ServeConfig::default(),
                        &RateLimiter::new(0),
                    );
                }
            });
        }

        peers_add(dir_c.to_str().unwrap(), &addr_a).unwrap();
        peers_add(dir_c.to_str().unwrap(), &addr_b).unwrap();
        let (ok, failed, transferred) = sync_loop(dir_c.to_str().unwrap(), 30, true).expect("pass");
        assert_eq!((ok, failed), (2, 0));
        // Peer A: pull a (1) + push c (1). Peer B: pull b (1) + push a AND c
        // (2) — B lacked both, including the body the client just pulled from
        // A: one pass gives a transitive hop. Total transferred = 5.
        assert_eq!(transferred, 5);

        // One pass leaves A without b (nothing carried b to A yet — gossip is
        // not transitive within a single pass in every topology). The loop is
        // periodic precisely for this: pass two carries b to A.
        let (ok, failed, transferred2) =
            sync_loop(dir_c.to_str().unwrap(), 30, true).expect("pass 2");
        assert_eq!((ok, failed), (2, 0));
        assert_eq!(
            transferred2, 1,
            "second pass moves exactly one body: b to A"
        );

        // Union everywhere after two passes.
        for d in [&dir_a, &dir_b, &dir_c] {
            for b in [body_a.as_slice(), body_b.as_slice(), body_c.as_slice()] {
                assert!(d.join(format!("{}.body", sha256_hex(b))).exists());
            }
        }
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

    // ---- write-path hardening (ServeConfig / RateLimiter / store_bytes) ----

    #[test]
    fn store_bytes_counts_only_body_files() {
        let (dir, _cid) = fixture_dir(b"quota-probe");
        let _ = std::fs::File::create(dir.join("noise.bin")).unwrap();
        let used = store_bytes(dir.to_str().unwrap());
        assert_eq!(used, 11, "only the .body file counts (probe = 11 bytes)");
    }

    #[test]
    fn rate_limiter_blocks_after_max_per_window() {
        let l = RateLimiter::new(2);
        let now = 1000u64;
        assert!(l.allow("1.2.3.4", now));
        assert!(l.allow("1.2.3.4", now));
        assert!(
            !l.allow("1.2.3.4", now),
            "third push in the same window must be refused"
        );
        // different IP is unaffected
        assert!(l.allow("5.6.7.8", now));
        // a new window resets the counter
        assert!(l.allow("1.2.3.4", now + 61));
    }

    #[test]
    fn enforce_write_policy_token_gate() {
        let cfg = ServeConfig {
            token: Some("s3cret".to_string()),
            ..Default::default()
        };
        let lim = RateLimiter::new(0);
        let (dir, _) = fixture_dir(b"tok");
        let ok = serde_json::json!({"TOKEN": "s3cret"});
        let bad = serde_json::json!({"TOKEN": "wrong"});
        let none = serde_json::json!({"BLID": "aa"});
        assert!(enforce_write_policy(&cfg, "ip", dir.to_str().unwrap(), 10, &lim, &ok).is_ok());
        assert!(enforce_write_policy(&cfg, "ip", dir.to_str().unwrap(), 10, &lim, &bad).is_err());
        assert!(enforce_write_policy(&cfg, "ip", dir.to_str().unwrap(), 10, &lim, &none).is_err());
        // no token configured -> everything writes
        let open = ServeConfig::default();
        assert!(enforce_write_policy(&open, "ip", dir.to_str().unwrap(), 10, &lim, &none).is_ok());
    }

    #[test]
    fn enforce_write_policy_store_quota() {
        let cfg = ServeConfig {
            max_store_bytes: 11,
            ..Default::default()
        }; // exactly the probe body
        let lim = RateLimiter::new(0);
        let (dir, _) = fixture_dir(b"quota-one");
        let payload = serde_json::json!({});
        assert!(enforce_write_policy(&cfg, "ip", dir.to_str().unwrap(), 0, &lim, &payload).is_ok());
        // "quota-one" is 9 bytes on disk; a 3-byte push exceeds the 11-byte quota
        assert!(
            enforce_write_policy(&cfg, "ip", dir.to_str().unwrap(), 3, &lim, &payload).is_err()
        );
    }

    #[test]
    fn ct_eq_rejects_differing_lengths_and_bytes() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "x"));
    }
}
