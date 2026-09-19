# ClusterFuzzLite build environment for spore-peer — the Rust side of the
# cross-binary decoder pair, mirrored from spore's .clusterfuzzlite/ (the Go
# half). Same CFL contract, Rust toolchain:
#
# Same recipe as the spore CFL integration, with the one difference CFL
# mandates: the source is COPYed in during docker build rather than
# git-cloned (https://google.github.io/clusterfuzzlite/build-integration/).
FROM gcr.io/oss-fuzz-base/base-builder-rust

# The fuzz crate is its own workspace root (fuzz/Cargo.toml) and pins
# libfuzzer-sys 0.4. cargo-fuzz is preinstalled in base-builder-rust; the
# pinned nightly toolchain for `-Zsanitizer` builds comes with the image
# (rustup default lives in /usr/local/rustup). No extra apt deps: the
# p2p decoder is std-only.

COPY . $SRC/spore-peer
WORKDIR $SRC/spore-peer
COPY ./.clusterfuzzlite/build.sh $SRC/
