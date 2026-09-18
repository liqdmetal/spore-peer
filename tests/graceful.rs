// SPDX-License-Identifier: BSD-3-Clause

//! Graceful-shutdown integration tests (tests/graceful.rs).
//!
//! The contract under test (src/spore_peer.rs, "graceful shutdown" block):
//!   * SIGTERM (unix) / Ctrl+C or Ctrl+Break (Windows) => serve() RETURNS,
//!     main() removes the pidfile, exit code 0, "graceful exit" on stderr.
//!   * SIGKILL (unix) / taskkill /F (Windows) => no cleanup, pidfile STAYS,
//!     nonzero exit — the dead-run signal a supervisor keys on.
//!
//! Delivery mechanics:
//!   * unix: plain `kill -TERM/-9` to the child pid.
//!   * windows: the daemon is created with CREATE_NEW_PROCESS_GROUP, which
//!     makes its pid a console process-group id; the test then fires
//!     GenerateConsoleCtrlEvent(CTRL_BREAK, <pid>) directly. The event is
//!     scoped to that group — the test harness itself (in the console's
//!     default group) never receives it, so no console detaching or helper
//!     process is needed. CTRL_BREAK is chosen over CTRL_C because group
//!     creation disables CTRL_C delivery for the group (documented Win32
//!     behavior) while CTRL_BREAK always arrives.
//!
//! Everything is bounded by explicit timeouts — a regression must fail,
//! never hang the gate.

use std::io::{BufRead, BufReader};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "spore-peer-graceful-{}-{}",
        std::process::id(),
        tag
    ));
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Spawn the real serve binary with a pidfile and wait for the readiness
/// line. Returns (guard, bound addr).
fn spawn_serve(
    dir: &Path,
    pidfile: &Path,
) -> (Guard, String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spore-peer"));
    cmd.args([
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--dir",
        dir.to_str().unwrap(),
        "-fabric",
        "--pidfile",
        pidfile.to_str().unwrap(),
    ])
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        // Own process group => the pid doubles as a console process-group
        // id the test can target with GenerateConsoleCtrlEvent. Shares the
        // test's console (needed for the event to reach it) but sits in a
        // group of its own, so the event cannot hit the harness.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = cmd.spawn().expect("spawn serve");
    let stderr = child.stderr.take().expect("stderr piped");
    let log: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let mut addr = None;
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut lines = BufReader::new(stderr).lines();
    while Instant::now() < deadline {
        let line = match lines.next() {
            Some(Ok(l)) => l,
            _ => break,
        };
        if let Some(rest) = line.strip_prefix("spore-peer serve: listening on ") {
            addr = Some(rest.split(',').next().unwrap_or("").to_string());
            // Keep reading after readiness on a background thread so the
            // daemon never blocks on a full stderr pipe.
            let log2 = std::sync::Arc::clone(&log);
            std::thread::spawn(move || {
                for l in lines {
                    if let Ok(l) = l {
                        log2.lock().unwrap().push(l);
                    } else {
                        break;
                    }
                }
            });
            break;
        }
        log.lock().unwrap().push(line);
    }
    let addr = addr.unwrap_or_else(|| panic!("no listening line in {}s", READY_TIMEOUT.as_secs()));
    (Guard(child), addr, log)
}

fn wait_exit(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(st)) => return st.code(),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
    None
}

#[cfg(unix)]
fn signal_graceful_unix(pid: u32, sig: &str) {
    let st = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .expect("kill available on unix");
    assert!(st.success(), "kill {sig} failed");
}

#[cfg(windows)]
fn signal_graceful_windows(pid: u32) {
    use windows_sys::Win32::System::Console::GenerateConsoleCtrlEvent;
    // 1 == CTRL_BREAK_EVENT; target group == the daemon's own group (its
    // pid, by CREATE_NEW_PROCESS_GROUP). The harness is in the console's
    // default group and is intentionally NOT addressed.
    unsafe {
        if GenerateConsoleCtrlEvent(1, pid) == 0 {
            panic!(
                "GenerateConsoleCtrlEvent failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn assert_serving(addr: &str) {
    // Liveness check: the accept loop must still accept while we decide to
    // shut down. A full fetch roundtrip is covered by the other smokes.
    assert!(
        std::net::TcpStream::connect(addr).is_ok(),
        "daemon not accepting on {addr} before the signal"
    );
}

#[test]
fn graceful_shutdown_roundtrip() {
    let dir = unique_dir("rt");
    let pidfile = dir.join("sp.pid");
    let (mut guard, addr, log) = spawn_serve(&dir, &pidfile);
    assert_serving(&addr);
    let pid = guard.0.id();
    let pf = pidfile.clone();

    #[cfg(windows)]
    signal_graceful_windows(pid);
    #[cfg(unix)]
    signal_graceful_unix(pid, "-TERM");

    let code = match wait_exit(&mut guard.0, EXIT_TIMEOUT) {
        Some(c) => c,
        None => panic!(
            "daemon did not exit in {}s; stderr: {:?}",
            EXIT_TIMEOUT.as_secs(),
            log.lock().unwrap()
        ),
    };
    if code != 0 {
        panic!(
            "graceful stop must exit 0, got {code}; stderr: {:?}",
            log.lock().unwrap()
        );
    }
    assert!(
        !pf.exists(),
        "pidfile must be removed after a graceful stop"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hard_kill_leaves_pidfile() {
    let dir = unique_dir("kill");
    let pidfile = dir.join("sp.pid");
    let (mut guard, addr, _log) = spawn_serve(&dir, &pidfile);
    assert_serving(&addr);
    let pid = guard.0.id();
    let pf = pidfile.clone();

    #[cfg(windows)]
    {
        let st = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
            .expect("taskkill");
        assert!(st.success());
    }
    #[cfg(unix)]
    signal_graceful_unix(pid, "-9");

    let code = wait_exit(&mut guard.0, EXIT_TIMEOUT);
    assert_ne!(code, Some(0), "a hard kill must not exit 0");
    assert!(
        pf.exists(),
        "pidfile must SURVIVE a hard kill (dead-run signal)"
    );
    std::fs::remove_dir_all(&dir).ok();
}
