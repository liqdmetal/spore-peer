#requires -Version 5.1
# deploy/spore-peer-fabric.ps1 — Windows wrapper for `spore-peer serve -fabric`.
#
# Windows console processes have no POSIX signals: an SCM/scheduler stop is
# TerminateProcess (Rust's default console handler terminates without running
# cleanup), so the pidfile SURVIVING a Windows stop is expected — exactly the
# hard-kill contract the --pidfile flag documents. This script treats a stale
# pidfile as the dead-run signal it is:
#   * stop  : terminate, then remove the pidfile (a deliberate stop = no pidfile)
#   * run   : if a pidfile exists, check the pid it names — dead means stale:
#             remove it and start fresh; ALIVE means another daemon still owns
#             it: refuse to start (fail closed, never steal a live identity)
#
# Verbs:
#   run    [-Dir H] [-Listen A] [-AnnounceAddr A] [-NoFabric] [-Pidfile P] [-Watch]
#   stop   [-Pidfile P]
#   status [-Pidfile P]
#
# Typical use:
#   .\deploy\spore-peer-fabric.ps1 run -AnnounceAddr relay.example.org:8099 -Watch
#   .\deploy\spore-peer-fabric.ps1 status
#   .\deploy\spore-peer-fabric.ps1 stop
#
# Under Task Scheduler or NSSM, `run -Watch` supervises: the daemon is
# restarted on exit with a linear backoff, up to a budget of 5 failures per
# rolling 60 s window (then the wrapper exits nonzero so the scheduler's own
# recovery can take over). Without -Watch the daemon runs in the foreground
# and the caller supervises.

[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateSet('run','stop','status')][string]$Verb = 'run',
    [string]$Dir        = 'C:\ProgramData\spore-peer\hold',
    [string]$Listen     = '0.0.0.0:8099',
    [string]$AnnounceAddr,
    [switch]$NoFabric,
    [string]$Pidfile    = 'C:\ProgramData\spore-peer\spore-peer.pid',
    [switch]$Watch
)

$ErrorActionPreference = 'Stop'

# Restart budget (used only by -Watch): 5 failures per rolling 60 s.
$script:BudgetMax     = 5
$script:BudgetWindowS = 60
$script:BackoffBaseS  = 2

## helpers ----------------------------------------------------------------

function Test-PidAlive {
    param([int]$ProcId)
    try { $null = Get-Process -Id $ProcId -ErrorAction Stop; return $true }
    catch { return $false }
}

function Read-Pid {
    param([string]$File)
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    try { return [int]((Get-Content -LiteralPath $File -TotalCount 1) -as [int]) } catch { return $null }
    # -as [int] returns $null for garbage; Get-Content on a file removed
    # between Test-Path and here throws, caught above.
}

function Remove-Pidfile {
    param([string]$File)
    try { Remove-Item -LiteralPath $File -Force -ErrorAction Stop } catch {}
}

function Find-Binary {
    # The release binary next to the repo's deploy\ dir, else PATH.
    $here = Split-Path -Parent $PSScriptRoot
    $cand = Join-Path $here 'target\release\spore-peer.exe'
    if (Test-Path -LiteralPath $cand) { return $cand }
    $cmd = Get-Command spore-peer.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "spore-peer.exe not found (looked in $cand and PATH)"
}

function Test-Announce {
    param([string]$Addr)
    # `host:port` — same parse convention the daemon documents for
    # --announce-addr (LastIndexOf(':'), so IPv6 literals with a trailing
    # :port parse the port correctly).
    if (-not $Addr) { return $true }
    $i = $Addr.LastIndexOf(':')
    if ($i -le 0) { return $false }
    $port = 0
    if (-not [int]::TryParse($Addr.Substring($i + 1), [ref]$port)) { return $false }
    return ($port -gt 0 -and $port -le 65535)
}

function Wait-Listening {
    param([System.Diagnostics.Process]$Proc, [int]$TimeoutS = 15)
    # The daemon writes its announce line, then `spore-peer serve: listening
    # on <addr>` to stderr. Wait for that readiness line (or exit).
    $deadline = (Get-Date).AddSeconds($TimeoutS)
    while ((Get-Date) -lt $deadline) {
        if ($Proc.HasExited) { return $false }
        if ($Proc.StandardError -and $Proc.StandardError.Peek() -ge 0) {
            $line = $Proc.StandardError.ReadLine()
            Write-Host "[spore-peer] $line"
            if ($line -match 'listening on') { return $true }
            continue
        }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Invoke-RunOnce {
    # Start the daemon, assert readiness, return the process (or $null).
    $bin = Find-Binary
    $args = @('serve', '--dir', $Dir, '--listen', $Listen, '-fabric', '--pidfile', $Pidfile)
    if ($AnnounceAddr) { $args += @('--announce-addr', $AnnounceAddr) }
    if ($NoFabric)     { $args = $args | Where-Object { $_ -ne '-fabric' } }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Pidfile) | Out-Null
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null

    # Reconcile any leftover pidfile BEFORE the daemon's write-before-bind:
    #   * no file / dead pid  -> stale (hard kill or crashed run): clear it
    #   * alive pid           -> a live daemon owns this identity: refuse
    $stale = Read-Pid $Pidfile
    if ($null -ne $stale) {
        if (Test-PidAlive $stale) {
            Write-Warning "refusing to start: pidfile names LIVE pid $stale (is another spore-peer serve already running?)"
            return $null
        }
        Write-Host "clearing stale pidfile (pid $stale is dead)"
        Remove-Pidfile $Pidfile
    }

    Write-Host "starting: $bin $($args -join ' ')"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo.FileName               = $bin
    $p.StartInfo.Arguments              = ($args -join ' ')
    $p.StartInfo.UseShellExecute        = $false
    $p.StartInfo.RedirectStandardError  = $true
    $p.StartInfo.RedirectStandardOutput = $true
    $null = $p.Start()
    if (-not (Wait-Listening $p)) {
        if (-not $p.HasExited) { Write-Warning "no 'listening on' line within 15 s (continuing; check the announce line above)" }
        else { Write-Warning "daemon exited during startup (code $($p.ExitCode))" }
    }
    return $p
}

## verbs ------------------------------------------------------------------

if ($Verb -eq 'status') {
    $pid0 = Read-Pid $Pidfile
    if ($null -eq $pid0)      { "status: no pidfile at $Pidfile"; exit 1 }
    elseif (Test-PidAlive $pid0) { "status: RUNNING (pid $pid0)"; exit 0 }
    else                        { "status: STALE (pidfile names dead pid $pid0)"; exit 2 }
}

if ($Verb -eq 'stop') {
    $pid0 = Read-Pid $Pidfile
    if ($null -eq $pid0) { "stop: no pidfile at $Pidfile (nothing to stop)"; exit 0 }
    if (Test-PidAlive $pid0) {
        Write-Host "stopping pid $pid0 (TerminateProcess -- the documented Windows hard-kill path)"
        try { Stop-Process -Id $pid0 -Force -ErrorAction Stop } catch { Write-Warning "Stop-Process: $_" }
        # Wait briefly for the OS to reap it so status right after is honest.
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline -and (Test-PidAlive $pid0)) { Start-Sleep -Milliseconds 100 }
    } else {
        Write-Host "pidfile named dead pid $pid0 (stale -- clearing)"
    }
    Remove-Pidfile $Pidfile
    "stop: done"
    exit 0
}

# Verb 'run' -- with -Watch: supervise with the restart budget; else foreground.
if ($Watch) {
    $failures = New-Object System.Collections.Generic.List[datetime]
    while ($true) {
        $now = Get-Date
        while ($failures.Count -gt 0 -and ($now - $failures[0]).TotalSeconds -gt $script:BudgetWindowS) { $failures.RemoveAt(0) }
        if ($failures.Count -ge $script:BudgetMax) {
            Write-Error "restart budget exhausted ($($script:BudgetMax) failures in ${script:BudgetWindowS}s) -- giving up"
            exit 3
        }
        $p = Invoke-RunOnce
        if ($null -eq $p) { exit 4 }        # refused: live daemon owns the pidfile
        $p.WaitForExit()
        Write-Warning "daemon exited (code $($p.ExitCode)) -- restarting after backoff"
        $failures.Add((Get-Date))
        $backoff = [Math]::Min($script:BackoffBaseS * $failures.Count, 30)
        Start-Sleep -Seconds $backoff
    }
} else {
    $p = Invoke-RunOnce
    if ($null -eq $p) { exit 4 }
    $p.WaitForExit()
    exit $p.ExitCode
}
