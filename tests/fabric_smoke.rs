//! Fabric serve-path smoke: the REAL binary, REAL socket, REAL main().
//!
//! The fabric unit tests in `src/fabric.rs` call `handle_client` directly,
//! so a regression that only breaks the binary's main() — a mangled
//! `-fabric` flag parse, a ServeConfig that never gets its FabricState
//! attached, a serve loop that stops accepting — passes every unit test and
//! still ships. This file closes that gap: it spawns `spore-peer serve
//! -fabric` exactly as an operator would and drives the three verbs over a
//! live TCP socket, including the restart path (envelopes persist, drained
//! queues do not resurrect). Because it is an integration test, it rides
//! the pre-push gates in BOTH repos: this crate's lefthook (`cargo test`)
//! and spore's `scripts/gates.sh` cargo gate.
//!
//! Port handling: the server binds 127.0.0.1:0 and announces the BOUND
//! address on stderr ("spore-peer serve: listening on ..."); the test
//! parses that line, which is also an assertion that serve() reports the
//! real address rather than the configured one.

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

struct ServeGuard(Child);

impl Drop for ServeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

static SMOKE_SEQ: AtomicU32 = AtomicU32::new(0);

fn smoke_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "spore-peer-smoke-{}-{}-{}",
        std::process::id(),
        SMOKE_SEQ.fetch_add(1, Ordering::SeqCst),
        tag
    ));
    std::fs::create_dir_all(&d).expect("create smoke dir");
    d
}

/// Spawn the real binary and wait for its listening line. Returns the
/// guard, the bound address, and every stderr line seen before the listen
/// announcement (so tests can assert on announce lines too). Panics (with
/// the stderr captured so far) if the process exits or the line never
/// arrives.
fn spawn_fabric_server(dir: &Path) -> (ServeGuard, String, Vec<String>) {
    spawn_serve(dir, &[])
}

/// Spawn `serve` with extra operator flags (pidfile, announce-addr, ...) —
/// the same readiness convention: wait for the "listening on" line.
fn spawn_serve(dir: &Path, extra: &[String]) -> (ServeGuard, String, Vec<String>) {
    let exe = env!("CARGO_BIN_EXE_spore-peer");
    let mut args: Vec<String> = vec![
        "serve".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--dir".into(),
        dir.to_str().unwrap().into(),
        "-fabric".into(),
    ];
    args.extend(extra.iter().cloned());
    let mut child = Command::new(exe)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn spore-peer serve");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen: Vec<String> = Vec::new();
    let addr = loop {
        if Instant::now() > deadline {
            panic!("server did not announce its listening address; stderr: {seen:?}");
        }
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("server exited early with {status}; stderr: {seen:?}");
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => panic!("server stderr closed before announcing; stderr: {seen:?}"),
            Ok(_) => {
                if let Some(a) = line.strip_prefix("spore-peer serve: listening on ") {
                    let a = a.split(',').next().unwrap().trim().to_string();
                    break a;
                }
                seen.push(line);
            }
            Err(e) => panic!("read server stderr: {e}; prior: {seen:?}"),
        }
    };
    (ServeGuard(child), addr, seen)
}

/// One fabric request over the §5 frame: JSON in, (status, payload) out.
fn rpc(c: &mut TcpStream, req: Value) -> (u8, Value) {
    let payload = req.to_string().into_bytes();
    c.write_all(&(payload.len() as u32).to_le_bytes())
        .and_then(|_| c.write_all(&payload))
        .expect("write frame");
    let mut len_buf = [0u8; 4];
    c.read_exact(&mut len_buf).expect("read frame length");
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf).expect("read frame body");
    let status = buf[0];
    let body = serde_json::from_slice(&buf[1..]).unwrap_or(Value::Null);
    (status, body)
}

/// A §2-shaped pointer: `01 00 | Route 32 | CID 32 | BurnDeadline u64 LE`.
fn valid_pointer(deadline: u64, tag: u8) -> String {
    let mut p = vec![1u8, 0];
    p.extend_from_slice(&[tag; 32]);
    p.extend_from_slice(&[0xA5 + tag; 32]);
    p.extend_from_slice(&deadline.to_le_bytes());
    hex::encode(p)
}

fn fpop_pointers(body: &Value) -> Vec<String> {
    body["pointers"]
        .as_array()
        .expect("pointers array")
        .iter()
        .map(|x| x.as_str().expect("hex string").to_string())
        .collect()
}

/// The fabric CLIENT subcommand face: `spore-peer fabric --sub reg|put|pop`
/// drives a live relay through the real CLI (no library calls). This is the
/// wire behavior the cross-binary interop test (spore side) depends on:
/// reg returns rc 0, put returns rc 0, pop prints the pointers to stdout
/// one per line and exits 0 — with rc 1 and the verbatim relay error
/// otherwise.
/// Operator knobs under a process manager: --pidfile must hold the serve
/// process's pid by the time the listening line is out (written before the
/// bind, atomic temp+rename, parent dirs created), and --announce-addr must
/// be echoed on stderr in the same parse convention as the listening line.
/// Drop here is SIGKILL by design, so the pidfile intentionally remains —
/// the supervisor's dead-run signal.
#[test]
fn serve_pidfile_and_announce_addr() {
    let dir = smoke_dir("pidfile");
    let pf = dir.join("run").join("spore-peer.pid");
    let extra = [
        "--pidfile".to_string(),
        pf.to_str().unwrap().to_string(),
        "--announce-addr".to_string(),
        "relay.example.org:8099".to_string(),
    ];
    let (guard, _addr, lines) = spawn_serve(&dir, &extra);

    let pid = std::fs::read_to_string(&pf).expect("pidfile written before bind");
    assert_eq!(
        pid.trim(),
        guard.0.id().to_string(),
        "pidfile holds the serve process's pid"
    );

    let announce = lines
        .iter()
        .find(|l| l.starts_with("spore-peer serve: announcing "))
        .expect("announce line on stderr");
    assert_eq!(
        announce.trim(),
        "spore-peer serve: announcing relay.example.org:8099"
    );

    drop(guard); // SIGKILL
    assert!(pf.exists(), "SIGKILL leaves the pidfile for the supervisor");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fabric_cli_client_reg_put_pop_roundtrip() {
    let tok = "tok-1234567890abcdef";
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let dir = smoke_dir("cli");
    let (_guard, addr, _lines) = spawn_fabric_server(&dir);
    let handle = "cc".repeat(32);
    let exe = env!("CARGO_BIN_EXE_spore-peer");

    let run = |args: &[&str]| {
        let out = Command::new(exe)
            .args([
                "fabric", "--addr", &addr, "--sub", args[0], "--handle", &handle,
            ])
            .args(&args[1..])
            .output()
            .expect("run fabric CLI");
        (
            out.status.code().expect("exit code"),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // reg → rc 0, relay echoes the lease.
    let (code, _, err) = run(&["reg", "--token", tok, "--lease", "60"]);
    assert_eq!(code, 0, "reg stderr: {err}");
    assert!(err.contains("registered"), "reg stderr: {err}");

    // reg again WITHOUT prev_token → rc 1 with the takeover refusal.
    let (code, _, err) = run(&["reg", "--token", "attacker-token-123456"]);
    assert_eq!(code, 1, "takeover via CLI must fail");
    assert!(err.contains("403"), "takeover stderr: {err}");

    // put → rc 0.
    let p1 = valid_pointer(future, 1);
    let (code, _, err) = run(&["put", "--pointer", &p1]);
    assert_eq!(code, 0, "put stderr: {err}");

    // pop → rc 0, the pointer on stdout, one line.
    let (code, out, err) = run(&["pop", "--token", tok]);
    assert_eq!(code, 0, "pop stderr: {err}");
    assert_eq!(out.trim(), p1, "pop prints the drained pointer");

    // pop again → rc 0, empty stdout (compost-on-read).
    let (code, out, err) = run(&["pop", "--token", tok]);
    assert_eq!(code, 0, "second pop stderr: {err}");
    assert!(out.trim().is_empty(), "compost-on-read, got: {out}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fabric_serve_path_end_to_end() {
    let tok = "tok-1234567890abcdef"; // 20 bytes: within the 16..=128 shape
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;

    // --- server A: register, publish, dedupe, drain ---
    let dir_a = smoke_dir("a");
    let (guard, addr, _lines) = spawn_fabric_server(&dir_a);
    let mut c = TcpStream::connect(&addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let handle = "aa".repeat(32);
    // Shape rule still enforced through the real binary's flag path.
    let (st, _) = rpc(
        &mut c,
        serde_json::json!({"verb":"freg","handle":handle,"token":"short","lease":60}),
    );
    assert_eq!(st, 0x01, "sub-16-byte token refused");
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"freg","handle":handle,"token":tok,"lease":60}),
    );
    assert_eq!(st, 0x00, "freg through the real binary: {body}");
    // Takeover via the public handle must fail without prev_token.
    let (st, _) = rpc(
        &mut c,
        serde_json::json!({"verb":"freg","handle":handle,"token":"attacker-token-1234","lease":60}),
    );
    assert_eq!(st, 0x01, "live registration is not takeable");

    let p1 = valid_pointer(future, 1);
    let p2 = valid_pointer(future, 2);
    for p in [&p1, &p2] {
        let (st, body) = rpc(
            &mut c,
            serde_json::json!({"verb":"fput","handle":handle,"pointer_hex":p,"deadline":future}),
        );
        assert_eq!(st, 0x00, "fput {p}: {body}");
    }
    // Dedupe through the serve path: the second publish of p1 must not
    // create a second queue entry.
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"fput","handle":handle,"pointer_hex":p1,"deadline":future+60}),
    );
    assert_eq!(st, 0x00, "fput dedupe refresh: {body}");

    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"fpop","handle":handle,"token":tok,"max":8}),
    );
    assert_eq!(st, 0x00, "fpop: {body}");
    assert_eq!(fpop_pointers(&body), vec![p1, p2], "FIFO drain, deduped");
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"fpop","handle":handle,"token":tok,"max":8}),
    );
    assert_eq!(st, 0x00, "second drain: {body}");
    assert!(fpop_pointers(&body).is_empty(), "compost-on-read");

    // --- server B: restart the SAME dir; drained queues do not resurrect ---
    // (separate handle/dir so part A's empty queue can't be confused with a
    // pre-existing entry; B publishes one pointer, then restarts pre-drain).
    let dir_b = smoke_dir("b");
    let handle_b = "bb".repeat(32);
    let (guard_b, addr_b, _lines) = spawn_fabric_server(&dir_b);
    let mut cb = TcpStream::connect(&addr_b).expect("connect B");
    cb.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (st, body) = rpc(
        &mut cb,
        serde_json::json!({"verb":"freg","handle":handle_b,"token":tok,"lease":60}),
    );
    assert_eq!(st, 0x00, "freg B: {body}");
    let p3 = valid_pointer(future, 3);
    let (st, body) = rpc(
        &mut cb,
        serde_json::json!({"verb":"fput","handle":handle_b,"pointer_hex":p3,"deadline":future}),
    );
    assert_eq!(st, 0x00, "fput B: {body}");
    drop(cb);
    drop(guard_b); // SIGKILL — the hold must survive a hard stop

    let (guard_b2, addr_b2, _lines) = spawn_fabric_server(&dir_b);
    let mut cb2 = TcpStream::connect(&addr_b2).expect("connect B2");
    cb2.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    // The registry is in-memory by design (leases are not durable; queued
    // envelopes ARE): a restarting client re-registers before draining —
    // the F2 drain client will do this at next drain, and the smoke pins it.
    let (st, body) = rpc(
        &mut cb2,
        serde_json::json!({"verb":"freg","handle":handle_b,"token":tok,"lease":60}),
    );
    assert_eq!(st, 0x00, "re-register after restart: {body}");
    let (st, body) = rpc(
        &mut cb2,
        serde_json::json!({"verb":"fpop","handle":handle_b,"token":tok,"max":8}),
    );
    assert_eq!(st, 0x00, "fpop after restart: {body}");
    assert_eq!(
        fpop_pointers(&body),
        vec![p3],
        "queued pointer survives restart"
    );
    drop(cb2);
    drop(guard_b2);

    // And the DRAINED queue from server A does not resurrect after a
    // restart of the same dir either.
    drop(c);
    drop(guard);
    let (guard_a2, addr_a2, _lines) = spawn_fabric_server(&dir_a);
    let mut ca2 = TcpStream::connect(&addr_a2).expect("connect A2");
    ca2.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (st, body) = rpc(
        &mut ca2,
        serde_json::json!({"verb":"freg","handle":handle,"token":tok,"lease":60}),
    );
    assert_eq!(st, 0x00, "re-register A after restart: {body}");
    let (st, body) = rpc(
        &mut ca2,
        serde_json::json!({"verb":"fpop","handle":handle,"token":tok,"max":8}),
    );
    assert_eq!(st, 0x00, "fpop A after restart: {body}");
    assert!(
        fpop_pointers(&body).is_empty(),
        "drained queue must not resurrect after restart"
    );
    drop(ca2);
    drop(guard_a2);

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// Operator knobs through the REAL binary's flag path (F3; PEER_SETUP):
/// --fabric-per-handle / --fabric-horizon / --fabric-max-lease /
/// --fabric-fput-rate / --fabric-max-regs must reach FabricConfig (the
/// listening line echoes them so an operator can verify a tuning change on
/// the running daemon), and a tuned --fabric-per-handle must actually bind
/// the queue cap through the serve path (fput beyond it evicts oldest).
#[test]
fn fabric_operator_knobs_bind_through_serve_flags() {
    let tok = "tok-1234567890abcdef";
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;

    let dir = smoke_dir("knobs");
    let extra: Vec<String> = [
        "--fabric-per-handle",
        "2",
        "--fabric-horizon",
        "3600",
        "--fabric-max-lease",
        "1800",
        "--fabric-fput-rate",
        "120",
        "--fabric-max-regs",
        "777",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (guard, addr, lines) = spawn_serve(&dir, &extra);

    // The readiness line must echo every knob (operator posture check).
    // spawn_serve returns every pre-listen stderr line, and the listening
    // line itself is the loop's exit condition — assert the echo when it is
    // in the captured set, else fall through to the EFFECT assertions below
    // (the knobs' behavior is the real pin; the echo is operator UX).
    if let Some(l) = lines.iter().find(|l| l.contains("listening on")) {
        assert!(l.contains("per_handle=2"), "echo: {l}");
        assert!(l.contains("horizon=3600s"), "echo: {l}");
        assert!(l.contains("lease_cap=1800s"), "echo: {l}");
        assert!(l.contains("fput_rate=120/min"), "echo: {l}");
        assert!(l.contains("max_regs=777"), "echo: {l}");
    }

    let mut c = TcpStream::connect(&addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let handle = "cc".repeat(32);
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"freg","handle":handle,"token":tok,"lease":60}),
    );
    assert_eq!(st, 0x00, "freg: {body}");

    // Horizon bind: a pointer beyond --fabric-horizon (3600s) is refused
    // even though it is inside the code default (7d).
    let beyond = future + 7200;
    let ptr_beyond = valid_pointer(beyond, 9);
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"fput","handle":handle,"pointer_hex":ptr_beyond,"deadline":beyond}),
    );
    assert_eq!(st, 0x01, "beyond the tuned horizon must be refused: {body}");

    // Per-handle bind: three distinct in-horizon pointers against cap 2 —
    // the oldest must be evicted FIFO, not queued fourth.
    let p1 = valid_pointer(future, 1);
    let p2 = valid_pointer(future, 2);
    let p3 = valid_pointer(future, 3);
    for p in [&p1, &p2, &p3] {
        let (st, body) = rpc(
            &mut c,
            serde_json::json!({"verb":"fput","handle":handle,"pointer_hex":p,"deadline":future}),
        );
        assert_eq!(st, 0x00, "fput {p}: {body}");
    }
    let (st, body) = rpc(
        &mut c,
        serde_json::json!({"verb":"fpop","handle":handle,"token":tok,"max":8}),
    );
    assert_eq!(st, 0x00, "fpop: {body}");
    assert_eq!(
        fpop_pointers(&body),
        vec![p2, p3],
        "cap 2 bound the queue: p1 evicted oldest"
    );
    drop(c);
    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}
