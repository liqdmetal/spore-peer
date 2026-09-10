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

Peers can also run the DERO rpc2 sync subset on the same port — one node
exchanges its whole store with another in a single pass:
    spore-peer sync --addr <peer-host:port> --dir <store-dir>

Integrity is enforced both directions: a body whose sha256 != requested CID
is rejected (`500 cid mismatch`), so a tampered or hostile peer can never
hand you bytes you did not ask for.

The rpc2 subset speaks the reference DERO wire protocol (clean-room): a CBOR
header map `{M: method, S: seq, E: error}` followed by a CBOR payload item,
with `Peer.Handshake`, `Peer.Chain` (topoheight/blid list — the body store is
the ledger, ordered by mtime) and `Peer.GetObject` (sha256-verified body
fetch). It coexists with the legacy JSON cid-fetch protocol per-frame on the
same connection.

## License
BSD-3-Clause. Standalone clean-room — the framing primitives are vendored in
`src/p2p.rs`.
