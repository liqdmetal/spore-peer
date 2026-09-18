#!/bin/sh
# unix-branch-check.sh — typecheck the cfg(unix) branch from any dev machine.
#
# Platform-gated code never compiles on a Windows/macOS dev machine, so a
# unix-only defect is invisible to every local gate until a Linux runner
# builds it (the first release-gate dry-run failed on an undeclared
# signal() FFI for exactly this reason). This check typechecks the linux
# target locally; the pre-push hook runs it on every push.
#
# Exit codes: 0 = typecheck passed OR target not installed (skip, loudly);
# nonzero = the unix branch does not typecheck — the push is blocked.
if rustup target list --installed | grep -q x86_64-unknown-linux-gnu; then
    exec cargo check --locked --target x86_64-unknown-linux-gnu --all-targets
fi
echo "unix-branch-typecheck: SKIPPED (x86_64-unknown-linux-gnu not installed; rustup target add x86_64-unknown-linux-gnu)"
exit 0
