// SPDX-License-Identifier: BSD-3-Clause
//
//! fuzz_lite — the stable-toolchain mirror of the libFuzzer target
//! (fuzz/fuzz_targets/fuzz_p2p_decode.rs).
//!
//! Why this exists: rustc sanitizers (ASan/libFuzzer) are unsupported on
//! windows-gnu hosts, so `cargo fuzz run` cannot hunt here — the real
//! libFuzzer treatment lives in CI (the `fuzz` job runs nightly + cargo-fuzz
//! on ubuntu). This test keeps the same invariants exercised on EVERY
//! `cargo test` run, on every machine, in the standard gate:
//!
//!   1. Every regression seed in fuzz/corpus/fuzz_p2p_decode/ decodes
//!      panic-free (Some or None — never a panic, never a hang).
//!   2. Content-drift oracle: whenever a seed decodes to Some, appending
//!      structurally hostile bytes must yield either None (the decoder's
//!      strict-tail policy: the tail is tried as the payload item and
//!      rejected) or the identical result — never Some with different
//!      content, which would mean the payload boundary drifted.
//!   3. Structured mutation (deterministic, seeded LCG): bitflips, byte
//!      substitution, truncation, splicing, and length-field corruption over
//!      the seed set — the deterministic stand-in for libFuzzer's coverage
//!      guidance. Any panic fails the suite.
//!
//! The corpus is the shared source of truth: the libFuzzer target's regression
//! seeds and this test's inputs are the same files (fuzz/corpus/), so a
//! CI-caught crasher lands here too the moment its seed is committed.

use std::path::PathBuf;

use spore_peer::p2p::decode_message;

const CORPUS_DIR: &str = "fuzz/corpus/fuzz_p2p_decode";

/// The hostile tail the libFuzzer target appends (invariant 2). Keep the two
/// definitions in sync.
const PROBE_TAIL: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, // indefinite-length head cluster
    0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // near-2^64 map len
    b't', b'a', b'i', b'l',
];

fn corpus_files() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    // Locate the corpus from the crate root (integration tests run there).
    let dir = PathBuf::from(CORPUS_DIR);
    let mut entries: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(e) => panic!(
            "fuzz corpus missing at {} — run `python fuzz/gen_corpus.py` ({e})",
            dir.display()
        ),
    };
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_file() {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let data = std::fs::read(&p)
                .unwrap_or_else(|e| panic!("unreadable corpus seed {}: {e}", p.display()));
            out.push((name, data));
        }
    }
    assert!(
        !out.is_empty(),
        "fuzz corpus is empty — run fuzz/gen_corpus.py"
    );
    out
}

/// Invariants 1+2 over one input. Panics (i.e. fails the suite) on a decoder
/// panic — caught here so the report names the seed instead of unwinding
/// into an opaque worker failure.
fn check_panic_free(name: &str, data: &[u8]) {
    let r = std::panic::catch_unwind(|| decode_message(data));
    let msg = match r {
        Ok(m) => m,
        Err(_) => panic!("decoder PANICKED on seed {name} ({} bytes)", data.len()),
    };
    if let Some(m) = msg {
        // Invariant 2: appended garbage may be rejected (strict tail) but
        // must never change the decoded content.
        let mut probed = Vec::with_capacity(data.len() + PROBE_TAIL.len());
        probed.extend_from_slice(data);
        probed.extend_from_slice(PROBE_TAIL);
        if let Some(again) = decode_message(&probed) {
            assert_eq!(
                again.method, m.method,
                "seed {name}: method drifted under tail"
            );
            assert_eq!(again.seq, m.seq, "seed {name}: seq drifted under tail");
            assert_eq!(
                again.error, m.error,
                "seed {name}: error drifted under tail"
            );
            assert_eq!(
                again.payload, m.payload,
                "seed {name}: payload drifted under tail"
            );
        }
    }
}

#[test]
fn every_corpus_seed_is_panic_free_and_tail_sound() {
    for (name, data) in corpus_files() {
        check_panic_free(&name, &data);
    }
}

/// Deterministic LCG so a failure is reproducible from the printed case id.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        // Numerical Recipes constants.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 33) as usize % n.max(1)
    }
}

#[test]
fn structured_mutations_of_corpus_survive() {
    let corpus = corpus_files();
    let mut rng = Lcg(0x5eed_c0de_b055_face);
    // 20 rounds x per-seed mutation keeps this under a second while giving
    // libFuzzer's coverage-guided hunt a deterministic daily floor.
    for round in 0..20u32 {
        for (name, data) in &corpus {
            let mut m = data.clone();
            match rng.below(6) {
                0 => {
                    // bitflip: 1-8 random bits
                    for _ in 0..(rng.below(8) + 1) {
                        if !m.is_empty() {
                            let i = rng.below(m.len());
                            m[i] ^= 1u8 << rng.below(8);
                        }
                    }
                }
                1 => {
                    // byte substitution with structurally interesting bytes
                    if !m.is_empty() {
                        let i = rng.below(m.len());
                        m[i] = [0xff, 0x81, 0x9f, 0x5b, 0x7b, 0x00, 0x1b, 0xf9][rng.below(8)];
                    }
                }
                2 => {
                    // truncation
                    let cut = rng.below(m.len() + 1);
                    m.truncate(cut);
                }
                3 => {
                    // splice: append a random chunk of another seed
                    let (oname, other) = &corpus[rng.below(corpus.len())];
                    let start = rng.below(other.len() + 1);
                    let end = rng.below(other.len() + 1);
                    let (a, b) = (start.min(end), start.max(end));
                    m.extend_from_slice(&other[a..b]);
                    let _ = oname;
                }
                4 => {
                    // length-field corruption: overwrite any 8-byte window
                    // with a huge declared length (the wrap class)
                    if m.len() >= 8 {
                        let i = rng.below(m.len() - 7);
                        m[i..i + 8].copy_from_slice(&[0xff; 8]);
                    }
                }
                _ => {
                    // duplicate a chunk (round-trip weirdness)
                    if !m.is_empty() {
                        let start = rng.below(m.len());
                        let end = (start + rng.below(m.len() - start) + 1).min(m.len());
                        let chunk: Vec<u8> = m[start..end].to_vec();
                        let at = rng.below(m.len() + 1);
                        m.splice(at..at, chunk);
                    }
                }
            }
            let case = format!("r{round}:{name}");
            check_panic_free(&case, &m);
        }
    }
}

#[test]
fn corpus_grows_with_vectors_guard() {
    // The golden seeds come from the generated vectors; if the generator
    // stops finding them (checkout moved, key renamed) the corpus silently
    // shrinks to only the hand-minted shapes. Fail loudly instead.
    let names: Vec<String> = corpus_files().into_iter().map(|(n, _)| n).collect();
    let golden = names.iter().any(|n| n.starts_with("rpc2_"));
    assert!(
        golden,
        "no rpc2_* golden seeds in the corpus — gen_corpus.py lost \
         spore/docs/interop-vectors.json"
    );
}
