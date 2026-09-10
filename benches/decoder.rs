// SPDX-License-Identifier: BSD-3-Clause
//
//! Throughput benchmarks for the rpc2/CBOR decode path: the frames a real
//! sync pass moves (Peer.Chain lists at two sizes, a 64 KiB Peer.GetObject
//! body) plus reject-throughput on garbage.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spore_peer::p2p::{cbor, chain_response, decode_message, getobject_response};

fn bench_decode(c: &mut Criterion) {
    for n in [100usize, 1000] {
        let pairs: Vec<(u64, [u8; 32])> =
            (0..n as u64).map(|i| (i, [(i % 256) as u8; 32])).collect();
        let frame = cbor::message("Peer.Chain", 1, "", chain_response(&pairs));
        c.bench_function(
            &format!("decode chain({n} pairs, {} B)", frame.len()),
            |b| b.iter(|| decode_message(black_box(&frame)).expect("decode")),
        );
    }

    let body = vec![0xABu8; 64 * 1024];
    let frame = cbor::message("", 2, "", getobject_response(&body));
    c.bench_function("decode getobject(64KiB body)", |b| {
        b.iter(|| decode_message(black_box(&frame)).expect("decode"))
    });

    // Hostile-ish: how fast garbage is rejected matters as much as how fast
    // valid input decodes.
    let junk: Vec<u8> = (0..16 * 1024).map(|i| ((i * 31) % 251) as u8).collect();
    c.bench_function("reject 16KiB garbage", |b| {
        b.iter(|| {
            let _ = decode_message(black_box(&junk));
        })
    });
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
