#!/bin/bash -eu
# Copyright (c) 2026 the spore-peer authors
#
# Build the Rust p2p rpc2/CBOR decoder fuzz target as a libFuzzer binary —
# the Rust half of the cross-binary decoder pair (the Go half lives in
# spore's internal/wirefuzz + .clusterfuzzlite). Mirrors the canonical
# OSS-Fuzz Rust recipe (projects/serde_json): `cargo fuzz build -O` with the
# image's nightly toolchain, then copy the linked binary to $OUT.
#
# The harness is fuzz/fuzz_targets/fuzz_p2p_decode.rs (libfuzzer-sys 0.4,
# oracles: panic-free decode + payload-boundary content stability); its seed
# corpus is generated reproducibly by fuzz/gen_corpus.py and committed under
# fuzz/corpus/fuzz_p2p_decode/ — zipped here per target, exactly as the Go
# side zips internal/wirefuzz's seedcorpus.

cd $SRC/spore-peer

# Deterministic corpus regeneration is unnecessary in CI (seeds are
# committed); gen_corpus.py remains the documented way to refresh them.
if [ ! -d fuzz/corpus/fuzz_p2p_decode ] || [ -z "$(ls -A fuzz/corpus/fuzz_p2p_decode 2>/dev/null)" ]; then
  python3 fuzz/gen_corpus.py fuzz/corpus/fuzz_p2p_decode
fi

mkdir -p $OUT
zip -q -j $OUT/fuzz_p2p_decode_fuzzer_seed_corpus.zip fuzz/corpus/fuzz_p2p_decode/*

# -O: the libfuzzer-sys build applies -Cpanic=abort + sanitizer+coverage
# instrumentation against the image's pinned nightly; release profile keeps
# exec throughput sane. Only the target binary is needed in $OUT — cargo
# emits the harness under fuzz/target/<triple>/release/.
cargo fuzz build -O

cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_p2p_decode $OUT/
