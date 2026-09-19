// SPDX-License-Identifier: BSD-3-Clause
//
//! fuzz_p2p_decode — libFuzzer target for the rpc2/CBOR wire decoder
//! (src/p2p.rs `decode_message`/`decode_value`).
//!
//! Surface: the full-frame entry `p2p::decode_message` — exactly what an
//! untrusted peer's bytes hit (LE32 length + CBOR header map {M,S,E} + one
//! payload item; the length prefix is checked by `read_frame` before this
//! decoder ever sees the buffer, so the fuzz input is the post-frame bytes).
//!
//! Invariants (a failure is a remote-code-path defect, not a style issue):
//!   1. Never panic, never hang on arbitrary input. Truncation, absurd
//!      declared lengths, indefinite/reserved heads, depth bombs, hostile
//!      UTF-8 — all must return None. libFuzzer treats a panic/timeout as a
//!      crash and files it in artifacts/.
//!   2. Content-drift oracle: `decode_message` reads a header map then, if
//!      bytes remain, ONE payload item. Appending garbage after a frame that
//!      decodes must either (a) yield None — the tail is tried as the payload
//!      item and rejected, the decoder's strict-tail policy — or (b) yield
//!      the identical result. What it must NEVER do is return Some with
//!      different content: that means the consumption count drifted (an
//!      off-by-one or unchecked length moving the payload boundary), the
//!      exact bug class behind the Go decoder's length-wrap crasher. The
//!      Rust decoder's checked_add + get() posture should hold — this
//!      target exists to keep it honest.
//!   3. Regression seeds in fuzz/corpus/ carry the known-bad shapes: the
//!      negint magnitude past i64::MIN (the panic "found by the fuzz corpus"
//!      in p2p.rs's comment), the near-2^64 declared-length heads (the Go
//!      wrap class), depth bombs past MAX_DEPTH, and byte-exact golden
//!      frames from spore/docs/interop-vectors.json (fabric_v1.rpc2_* — the
//!      same {M,S,E}+payload CBOR family).

#![no_main]

use libfuzzer_sys::fuzz_target;
use spore_peer::p2p::decode_message;

fuzz_target!(|data: &[u8]| {
    let msg = decode_message(data);

    // Invariant 2: appended garbage may be rejected (strict tail) but must
    // never change the decoded content.
    if let Some(m) = msg {
        // 16 bytes of structurally-hostile tail: an indefinite-length head,
        // a near-2^64 declared length, and filler. None of it may change
        // what the prefix decodes to.
        let mut probed = Vec::with_capacity(data.len() + 16);
        probed.extend_from_slice(data);
        probed.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        probed.extend_from_slice(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        probed.extend_from_slice(b"tail");
        // None is a sound outcome (tail tried as payload item, rejected);
        // Some must carry the identical message.
        if let Some(again) = decode_message(&probed) {
            assert_eq!(
                again.method, m.method,
                "method changed under appended garbage"
            );
            assert_eq!(again.seq, m.seq, "seq changed under appended garbage");
            assert_eq!(again.error, m.error, "error changed under appended garbage");
            assert_eq!(
                again.payload, m.payload,
                "payload changed under appended garbage"
            );
        }
    }
});
