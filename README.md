# spore-peer (m³)

P2P long-body transport for **Spore** (the no-relay multi-chain messenger, part of the Mycelium stack) (the no-relay multi-chain
messenger). Clean-room, BSD-3. Standalone — no derohe dependency.

Long bodies never ride a chain block. The sender holds the ECDH-encrypted
body on their own node and advertises only a pointer (whisper); the
recipient fetches the body peer-to-peer over this transport when both are
online, then keys rotate + erase. Nobody but sender and receiver ever holds
the bytes.

Serves and fetches ECDH-encrypted bodies by CID with sha256 integrity on
both sides.

## Build
    cargo build --release

## Usage
Sender holds an encrypted body by CID (from `spore whisper send-long`):
    spore-peer serve --dir <outbox-dir>
Recipient fetches it peer-to-peer:
    spore-peer fetch --addr <sender-host:port> --cid <64hex>

Integrity is enforced both directions: a body whose sha256 != requested CID
is rejected (`500 cid mismatch`), so a tampered or hostile peer can never
hand you bytes you did not ask for.

## License
BSD-3-Clause. Standalone clean-room — the framing primitives are vendored in
`src/p2p.rs`.
