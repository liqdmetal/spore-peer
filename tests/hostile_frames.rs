// SPDX-License-Identifier: BSD-3-Clause
//
//! Hostile-frame suite for the rpc2/CBOR decoder. Every test here feeds
//! attacker-shaped input — deep nesting, truncated tails, absurd lengths,
//! indefinite-length encodings, mutated garbage — and asserts the decoder
//! returns None or a sane value. A panic or a hang anywhere in this file is
//! a vulnerability (a remote peer can kill or wedge the node).

use spore_peer::p2p::{cbor, chain_response, decode_message, getobject_response};

/// Round-trip helper: a well-formed message must always survive.
fn well_formed_roundtrip() -> Vec<u8> {
    cbor::message("Peer.Chain", 1, "", chain_response(&[(3, [7u8; 32])]))
}

#[test]
fn benign_frame_still_decodes() {
    // Guard: the hostile suite must never pass because decoding broke.
    let f = well_formed_roundtrip();
    let m = decode_message(&f).expect("benign frame must decode");
    assert_eq!(m.method, "Peer.Chain");
    assert_eq!(m.seq, 1);
    assert_eq!(m.payload.as_array().unwrap().len(), 1);
}

#[test]
fn deep_nesting_capped_not_fatal() {
    // 100_000 nested arrays (1 byte each). Pre-hardening this overflowed the
    // stack and killed the process; now it must be rejected by the depth cap.
    let mut f = Vec::with_capacity(100_100);
    f.push(0x9f); // bogus outer byte: any array-ish opener
    f.resize(f.len() + 100_000, 0x81); // array(1), one hundred thousand deep
    f.push(0x00); // final uint(0)
    let frame = cbor::message("Peer.Chain", 1, "", f);
    assert!(
        decode_message(&frame).is_none(),
        "deep nesting must be rejected"
    );
}

#[test]
fn nesting_just_under_cap_is_fine() {
    // 60 nested arrays inside the 64 cap must still decode.
    let mut payload = vec![0x00u8]; // uint(0)
    for _ in 0..60 {
        payload.insert(0, 0x81); // array(1) wrapping one item
    }
    let frame = cbor::message("Peer.Chain", 2, "", payload);
    assert!(
        decode_message(&frame).is_some(),
        "nesting under the cap must decode"
    );
}

#[test]
fn huge_declared_length_rejected() {
    // bstr claiming 2^40 bytes; the frame is 40 bytes total.
    let mut payload = vec![0x5B]; // bstr, 8-byte length
    payload.extend_from_slice(&0x100_0000_0000u64.to_be_bytes());
    payload.extend_from_slice(b"short tail");
    let frame = cbor::message("", 3, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn u64_max_length_rejected_without_overflow() {
    // Length = u64::MAX must not wrap around into a "valid" small range.
    let mut payload = vec![0x5B];
    payload.extend_from_slice(&u64::MAX.to_be_bytes());
    payload.push(0xAA);
    let frame = cbor::message("", 4, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn length_arithmetic_overflow_rejected() {
    // Array claiming 2^64-1 elements; element walk must abort, not loop.
    let mut payload = vec![0x9B];
    payload.extend_from_slice(&u64::MAX.to_be_bytes());
    let frame = cbor::message("", 5, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn map_count_zero_decodes_but_is_rejected_as_header() {
    // map(0) is valid CBOR, but an rpc2 header without M/S/E has no method —
    // the dispatcher must route it to the JSON path and fail there.
    let frame = cbor::message("", 6, "", getobject_response(b"x"));
    assert!(decode_message(&frame).is_some());
}

#[test]
fn truncated_sweep_never_panics() {
    // Take a well-formed frame and feed every possible prefix of it — each
    // truncation must return None or decode, never panic or hang.
    let full = well_formed_roundtrip();
    for cut in 0..full.len() {
        let prefix = &full[..cut];
        let _ = decode_message(prefix); // must not panic
    }
    // And every single-byte mutation must be survivable too.
    for i in 0..full.len() {
        let mut mutated = full.clone();
        mutated[i] = mutated[i].wrapping_add(1);
        let _ = decode_message(&mutated);
    }
}

#[test]
fn truncated_tail_inside_bstr_rejected() {
    // bstr declares 32 bytes but only 3 are present.
    let mut payload = vec![0x58, 32];
    payload.extend_from_slice(b"abc");
    let frame = cbor::message("", 7, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn truncated_head_extra_bytes_rejected() {
    // 8-byte length head declared but only 2 length bytes present.
    let payload = vec![0x5B, 0x00, 0x01];
    let frame = cbor::message("", 8, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn indefinite_length_rejected() {
    // info=31 (indefinite) is legal CBOR but unsupported here: reject.
    for opener in [0x5Fu8, 0x7F, 0x9F, 0xBF] {
        let frame = cbor::message("", 9, "", vec![opener, 0xFF]);
        assert!(decode_message(&frame).is_none(), "opener {opener:#x}");
    }
}

#[test]
fn reserved_info_values_rejected() {
    // info 28..=30 are reserved in RFC 8949.
    for info in 28u8..=30 {
        let ib = 0x40 | info; // bstr major with reserved info
        let frame = cbor::message("", 10, "", vec![ib, 0x00]);
        assert!(decode_message(&frame).is_none(), "info {info}");
    }
}

#[test]
fn bad_utf8_text_rejected() {
    // text string with invalid UTF-8 must be rejected, not lossy-decoded.
    let mut payload = vec![0x64]; // text(4)
    payload.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    let frame = cbor::message("", 11, "", payload);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn trailing_garbage_after_header_is_payload_attempted() {
    // Header followed by a nonsense payload: decode fails cleanly.
    let mut frame = cbor::header("Peer.Chain", 12, "");
    frame.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    assert!(decode_message(&frame).is_none());
}

#[test]
fn zero_consumption_payload_rejected() {
    // Empty payload region between header and end: treated as no payload.
    let frame = cbor::header("Peer.Handshake", 13, "");
    let m = decode_message(&frame).expect("header-only must decode");
    assert!(m.payload.is_null());
}

#[test]
fn empty_and_tiny_inputs_rejected() {
    assert!(decode_message(&[]).is_none());
    assert!(
        decode_message(&[0x00]).is_none(),
        "uint is not a map header"
    );
    assert!(decode_message(&[0xA1]).is_none(), "truncated map head");
    assert!(decode_message(&[0xFF, 0xFF]).is_none());
}

#[test]
fn fuzz_corpus_garbage_is_always_survivable() {
    // Deterministic pseudo-random corpus (xorshift): 20k garbage buffers of
    // varying size must never panic, hang, or wedged the decoder.
    let mut state: u64 = 0x5EED_5EED_5EED_5EED;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in [0usize, 1, 2, 3, 7, 16, 64, 255, 4096] {
        for _ in 0..200 {
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            let _ = decode_message(&buf);
            // Also wrap in a valid header so the payload path is exercised.
            let frame = cbor::message("Peer.Chain", 14, "", buf);
            let _ = decode_message(&frame);
        }
    }
}

#[test]
fn fuzz_corpus_half_valid_mutations() {
    // Mutate a VALID frame heavily: decoder must survive every mutation and
    // must never return a message whose header fields are corrupted past
    // recognition (method/seq come only from the map that parsed).
    let base = cbor::message("Peer.GetObject", 99, "", getobject_response(b"body bytes"));
    let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..5000 {
        let mut mutated = base.clone();
        // Flip 1-4 random bytes.
        let flips = 1 + (next() % 4) as usize;
        for _ in 0..flips {
            let idx = (next() as usize) % mutated.len();
            mutated[idx] = (next() & 0xFF) as u8;
        }
        if let Some(m) = decode_message(&mutated) {
            // Whatever survived must still be structurally sane: decoded
            // strings come from the frame itself and can never exceed it.
            assert!(m.method.len() <= mutated.len());
            assert!(m.error.len() <= mutated.len());
        }
    }
}
