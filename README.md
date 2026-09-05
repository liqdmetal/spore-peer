# compost-peer

P2P long-body transport for **compost** (the no-relay DERO messenger).

Clean-room, BSD-3. Standalone — no derohe dependency. Serves and fetches
ECDH-encrypted bodies by CID with sha256 integrity on both sides.

## Build
    cargo build --release

## Usage
Sender holds an encrypted body by CID (from `compost whisper send-long`):
    compost-peer serve --dir <outbox-dir>
Recipient fetches it peer-to-peer:
    compost-peer fetch --addr <sender-host:port> --cid <64hex>

Integrity is enforced both directions: a body whose sha256 != requested CID
is rejected (`500 cid mismatch`), so a tampered or hostile peer can never
hand you bytes you did not ask for.

## License
BSD-3-Clause. Reuses the byte-verified p2p frame primitives from derohe-rs.
