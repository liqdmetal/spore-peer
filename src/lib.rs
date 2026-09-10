// SPDX-License-Identifier: BSD-3-Clause
//
//! spore-peer library surface: the rpc2/CBOR wire codec used by the
//! spore-peer binary. Kept as a library so the decoder can be exercised by
//! benchmarks (`benches/`), hostile-frame tests (`tests/hostile_frames.rs`)
//! and fuzz targets without spawning the binary.

pub mod p2p;
