# Service wrappers for `spore-peer serve -fabric`

Process-manager integration for the fabric relay daemon, using the two
operator flags `serve` ships:

- `--pidfile <path>` — written **atomically before the bind** (parent dirs
  auto-created). A graceful stop removes it; a hard kill leaves it behind,
  which is the dead-run signal a supervisor (or the checks below) can act
  on. The file contains one line: the daemon's pid.
- `--announce-addr host:port` — the operator-facing address echoed on
  stderr (same parse convention as the `listening on` line): set it to what
  peers and fabric clients must actually dial when the daemon sits behind
  NAT or a container boundary. The readiness line remains
  `spore-peer serve: listening on <bound addr>`.

Files here:

| File | For |
|---|---|
| `spore-peer-fabric.service` | systemd (Linux) — the reference setup |
| `spore-peer-fabric.ps1` | Windows — supervise/probe/stop wrapper (Task Scheduler or manual) |

## Linux — systemd

```sh
sudo useradd --system --home /var/lib/spore-peer --shell /usr/sbin/nologin spore-peer
sudo install -d -o spore-peer -g spore-peer /var/lib/spore-peer/hold /run/spore-peer
sudo install -m 0755 target/release/spore-peer /usr/local/bin/spore-peer
# Edit the unit: set --announce-addr to YOUR public host:port.
sudo install -m 0644 deploy/spore-peer-fabric.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now spore-peer-fabric
systemctl status spore-peer-fabric        # ExecStartPost already asserted the pidfile
```

Stop semantics: `systemctl stop` sends SIGTERM; the daemon's graceful-exit
path removes the pidfile. A crash or SIGKILL leaves it — the unit's
`ExecStopPost` prints a warning in that case instead of failing the stop.

## Windows

Windows has no POSIX signals: an SCM stop (or `Stop-Process`) becomes
`TerminateProcess`, which cannot run cleanup — so **the pidfile surviving a
service stop is expected**, and the wrapper removes it after a deliberate
stop and clears a crashed run's leftover at the next start (after checking
the pid it names is really dead). A console-hosted daemon (Task Scheduler
console host, NSSM, or a plain terminal) gets the graceful path instead:
serve installs a console control handler, so Ctrl+C / Ctrl+Break exit 0 and
remove the pidfile — the same contract as SIGTERM on Linux.

### Option A — Task Scheduler + the wrapper script (no extra tools)

```powershell
# from an ELEVATED PowerShell, at the repo root:
install-Dir C:\ProgramData\spore-peer\hold
.\deploy\spore-peer-fabric.ps1 run `
    -AnnounceAddr relay.example.org:8099     # foreground trial first
schtasks /Create /TN spore-peer-fabric /SC ONSTART /RU SYSTEM `
    /TR "powershell -ExecutionPolicy Bypass -File C:\path\to\deploy\spore-peer-fabric.ps1 run -AnnounceAddr relay.example.org:8099"
schtasks /Run   /TN spore-peer-fabric       # start now, no reboot needed
```

The script self-watches (restart budget: 5 failures per 60s with backoff;
a graceful daemon exit -- Ctrl+C/Ctrl+Break, now exit 0 with the pidfile
removed -- ends the watcher instead of triggering a restart), writes its
log where the announce/listening lines are greppable, and supports
`stop` / `status` verbs.

### Option B — NSSM (a real Windows service)

```powershell
choco install nssm   # or scoop install nssm
nssm install spore-peer-fabric C:\path\to\spore-peer.exe `
  "serve --dir C:\ProgramData\spore-peer\hold --listen 0.0.0.0:8099 -fabric --pidfile C:\ProgramData\spore-peer\spore-peer.pid --announce-addr relay.example.org:8099"
nssm set spore-peer-fabric AppStderr C:\ProgramData\spore-peer\spore-peer.log
nssm set spore-peer-fabric AppRotateFiles 1
nssm set spore-peer-fabric AppExit Default Exit
nssm start spore-peer-fabric
```

NSSM drives SCM recovery (restart on failure), log rotation, and a real
`sc stop`. Because NSSM's default stop includes a console-event attempt
before terminating, the pidfile *may* be removed or may survive — either
way the next start reconciles it, which is the whole point of
write-before-bind.

## Both platforms — the checks that matter

1. **Readiness**: watch the log for `listening on <bound>` (the announce
   line, when set, appears immediately *before* it — announced config
   first, then the ready signal).
2. **Liveness**: `kill -0 $(cat /run/spore-peer/spore-peer.pid)` on Linux,
   `Get-Process -Id (Get-Content C:\ProgramData\spore-peer\spore-peer.pid)`
   on Windows. A pidfile naming a dead pid = dead run, restart it.
3. **Reachability**: dial `--announce-addr` from OUTSIDE the host — that is
   the address every `sporepeer://` body URL and every fabric
   `freg/fput/fpop` client will use.
