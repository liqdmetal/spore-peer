# Contributing to spore-peer

BSD-3-Clause, clean-room. Small, focused patches welcome.

## Setup

- Stable Rust. `cargo build --locked` must be clean with zero warnings from
  this crate.
- A checkout of the `spore` repo next to this one (sibling `../spore`, or
  `_review_tmp/spore` — the known layouts) provides
  `docs/interop-vectors.json` for the conformance tests. Optional for a
  build, expected for full verification.

## Gates (every patch)

    cargo build --locked
    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    # cross-target typecheck of the cfg(unix) branch (skips with a note if
    # the target is not installed — `rustup target add x86_64-unknown-linux-gnu`)
    cargo check --locked --target x86_64-unknown-linux-gnu --all-targets

rustfmt and clippy (`-D warnings`) are blocking gates: a patch that fails
either does not land, whatever it does for `cargo test`.

The cross-target check is blocking too where it runs: `cfg(unix)` code is
not compiled by any of the gates above on a Windows or macOS dev machine,
so a unix-only defect (an undeclared FFI, a platform API misuse) is
invisible until a Linux runner builds it. The typecheck for the linux
target rides the pre-push hook for exactly that reason — it caught a
never-compiled unix signal branch on its first release-gate dry-run.

The `cargo test` gate also runs `tests/fabric_smoke.rs`, which spawns the
real `spore-peer serve -fabric` binary and drives freg/fput/fpop over a
live socket (including a hard kill and restart of the hold). The in-process
fabric unit tests call `handle_client` directly, so only this smoke catches
a regression in main()'s `-fabric` flag wiring or the serve loop itself —
and since the pre-push hook runs `cargo test`, such a break fails the push
before it can ship.

## The default `go test` run: -race + cross-binary interop

The spore-side tests in `internal/peerstore` exercise BOTH wire directions
against the real binaries, and running them that way is the default
expectation, not an optional extra:

- Go client -> real Rust `spore-peer serve` (holds written by Go `Put`,
  served by the Rust binary)
- real Rust `spore-peer fetch` -> Go-served hold (`SporePeerStore`
  listener), including the verbatim `404 not found` / `410 gone` error
  strings crossing the binary boundary

Run it exactly as CI does:

    cargo build --locked                 # produces target/debug/spore-peer
    cd ../spore
    SPORE_PEER_BIN="$PWD/../spore-peer/target/debug/spore-peer" \
      go test -race -count=1 ./internal/peerstore ./internal/store

(The `SPORE_PEER_BIN` path assumes the sibling layout; adjust it if your
spore-peer checkout lives elsewhere, e.g. `../_review_tmp/spore-peer`.)

(`-race` needs cgo enabled — the toolchain default on most dev boxes; on
Windows that means a gcc for mingw-w64 must be on PATH.)

From the spore checkout, `scripts/gates.sh` does all of it in one command:
builds this crate, exports `SPORE_PEER_BIN` to the freshly built binary,
runs the `-race` suite with both interop directions live, and finishes
with the doc-refs pin check.

Without `SPORE_PEER_BIN` set, the interop tests skip (loudly) and the
suite stays hermetic — fine for a quick inner-loop check, but a patch that
touches the wire protocol, the store, or the serve path is not verified
until it has passed with the real binary in the loop.

## Conformance vectors

`spec_frame_vectors_match` and `spec_parse_fetch_response_vectors` consume
spore's committed `docs/interop-vectors.json`. Wherever that file exists,
failing a vector is a hard failure; when no spore checkout is present the
tests skip rather than panic — a missing file is a layout fact, not a
conformance failure. If you extend the protocol: add vectors to spore's
`docs/interop-vectors.json` first, then make both implementations agree.

## Commits

Conventional subjects (`feat:`, `fix:`, `test:`, `docs:`, `ci:`). rustfmt
and clippy cleanliness are part of the change, never a follow-up commit.
