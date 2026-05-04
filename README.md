# FHE Relayer over Nym

## Objectives

This project has two concurrent goals:

**1. Test the new Nym SDK transport primitives in a real-world scenario.**
The recently released `smolmix` layer exposes standard `TcpStream` and `UdpSocket`
types that route all traffic through the Nym mixnet transparently. This project
uses that layer as the body transport between clients and the relayer, exercising
the SDK under realistic conditions — variable payload sizes, concurrent connections,
reconnection behavior — rather than in a toy demo.

**2. Build a theoretically sound private message relay using FHE primitives.**
Fully Homomorphic Encryption ensures message content remains opaque to every
party except the intended recipient. On-chain commitments provide censorship-resistant
ordering and proof of relay. Together they implement a public/private register:
the chain is fully public (anyone can observe that the system is being used) but
completely opaque (no observer can learn who is communicating with whom or what
is being exchanged).

---

## Threat Model

The system protects the **communication graph**. An adversary watching both chains
and the Nym network simultaneously should learn nothing about which sender is
communicating with which recipient — only that the system is being used.

| Adversary | Capability | Protected property |
|---|---|---|
| Chain observer | Sees all on-chain data and timestamps | Sender/recipient identity, communication graph |
| Network observer | Sees IP traffic and timing | Handled by Nym mixnet |
| Relayer | Sees Nym packets and both chains | Cannot link a src event to a dst event |
| Anyone | Full access to dst chain | Cannot recognize a message without the shared secret |

**Out of scope:** shared secret establishment between A and B. This is assumed
to happen out of band (a private rendezvous protocol is a separate project).

---

## Architecture

### Primitives

```
Client A          Src Chain          Relayer           Dst Chain         Client B
   |                  |                 |                  |                 |
   |-- stealth tag -->|                 |                  |                 |
   |                  |<--- watching ---|                  |                 |
   |                  |--- tag event -->|                  |                 |
   |                  |                 |                  |                 |
   |-------- Nym: (ciphertext, nonce, ZK proof) -------->|                  |
   |                  |                 |-- verify --------|                 |
   |                  |                 |-- post anon ---->|                 |
   |                  |                 |                  |<---- scanning --|
   |                  |                 |                  |---- recognize --|
```

### Components

**Client A**
- Derives a stealth tag from the shared secret and a nonce via HKDF
- Posts the tag (opaque bytes, no identity) on the src chain
- Sends `(FHE ciphertext, nonce, ZK binding proof)` over the Nym tunnel to the relayer

**Relayer**
- Watches src chain for any tag matching the expected format (pattern match, not identity)
- Receives Nym packets from senders
- Verifies the ZK proof links the body to an existing on-chain tag
- Posts anonymously to the dst chain
- Stateless — no logging of sender identity or src/dst correlation

**Client B**
- Watches dst chain passively
- Trial-decrypts each tag event using the shared secret
- Recovers the FHE ciphertext when a match is found

### On-chain data structure

Both chains only ever hold:

```
{ tag: bytes32, payload: bytes }
```

No sender address. No recipient address. No metadata. The tag is a MAC over a
nonce — meaningless without the shared secret.

### Nym transport stack (smolmix)

```
User code (RelayEnvelope send/recv)
        ↓
tokio-smoltcp::Net
        ↓
NymAsyncDevice  (raw IP packet adapter)
        ↓
NymIprBridge    (mixnet ↔ channel shuttle)
        ↓
IpMixStream → MixnetClient → Nym mixnet → IPR exit node
```

---

## Crate Layout

```
fhe-relayer/
├── crates/
│   ├── primitives/     # Crypto: HKDF, stealth tags, ZK binding proof
│   ├── chain/          # ChainWatcher and ChainPoster traits + implementations
│   ├── transport/      # Nym tunnel setup, RelayEnvelope wire format
│   ├── relayer/        # Core relay logic: tag matching, verify, post
│   └── client/         # Client A (send) and Client B (scan + recognize)
└── tests/
    └── e2e/            # Full integration tests against local chain (Anvil)
```

---

## Implementation Plan

Each step is independently testable. No step depends on an untested previous step.

---

### Step 1 — Cryptographic primitives (`crates/primitives`)

Everything else derives from these. Establish and test in complete isolation.

- HKDF derivation: `shared_secret → tag_key + binding_key`
- Tag generation: `HMAC(tag_key, nonce) → [u8; 32]`
- Tag recognition: given shared secret + nonce, B can verify a tag
- Nonce scheme: generation and uniqueness guarantees

**Tests**
- Unit: `derive → tag → recognize` round trips correctly
- Property: a wrong secret never recognizes a valid tag
- Property: two different nonces never produce the same tag

---

### Step 2 — Chain interface (`crates/chain`)

Define the chain boundary as a trait before touching any real node.

```rust
trait ChainWatcher {
    async fn watch(&self) -> impl Stream<Item = TagEvent>;
}

trait ChainPoster {
    async fn post(&self, tag: [u8; 32], payload: Vec<u8>) -> TxHash;
}
```

Implement with an in-memory mock first. Then implement against Anvil (local EVM node).

**Tests**
- Unit: mock watcher emits events, mock poster records calls, trait contract holds
- Integration: post a tag on Anvil, assert watcher picks it up within N blocks
- Integration: assert no sender address appears in the on-chain event

---

### Step 3 — Nym transport layer (`crates/transport`)

Integrate smolmix. Build the simplest possible thing: relayer opens a Nym
listener, client connects and sends raw bytes, relayer receives them. No crypto,
no chain — just reliable byte transport through the mixnet.

**Tests**
- Loopback: send 1000 random payloads of varying size, assert all arrive intact
- Stress: concurrent senders, assert no cross-contamination
- Reconnection: drop and re-establish tunnel, assert delivery resumes

---

### Step 4 — Message envelope (`crates/transport`)

Define and test the wire format for what A sends over Nym.

```rust
struct RelayEnvelope {
    nonce:           [u8; 32],
    tag:             [u8; 32],   // must match the on-chain commitment
    fhe_ciphertext:  Vec<u8>,
    binding_proof:   Vec<u8>,    // stubbed as empty bytes for now
}
```

Serialize with `postcard`. The binding proof field is a stub — it carries bytes
but is not yet verified.

**Tests**
- Round trip: serialize → deserialize produces identical struct
- Transport: send envelope over Nym tunnel from step 3, assert relayer receives
  and deserializes correctly
- Rejection: malformed bytes are rejected cleanly, no panic

---

### Step 5 — Relayer core logic without ZK (`crates/relayer`)

Wire chain watcher + Nym receiver together. The relayer maintains a pending set
of tags seen on the src chain. When an envelope arrives, it checks the tag is in
the pending set, posts to dst chain, and removes the tag. Unmatched tags are
dropped silently.

**Tests**
- Integration (mock chains): A posts tag, sends envelope, assert relayer posts
  correct payload on dst chain
- Drop: envelope with unknown tag is dropped, nothing posted on dst chain
- Replay: same tag used twice, second envelope dropped after first succeeds
- Ordering: multiple in-flight messages, assert all arrive on dst chain

---

### Step 6 — ZK binding proof (`crates/primitives`)

Add the actual proof. The ZK statement:

> I know a nonce such that `HMAC(tag_key, nonce) == tag`, where `tag_key` is
> derived from a secret I know, without revealing the secret or the nonce.

Circuit: Groth16 with arkworks (small proof size, fast verify) or Bulletproofs
(no trusted setup). Choose based on proof size budget for the on-chain payload.

Integrate into the relayer: envelopes with invalid proofs are rejected before
tag lookup. Add a nullifier to prevent proof replay.

**Tests**
- Unit: valid proof verifies, tampered proof fails, wrong key fails
- Unit: replayed proof (same nullifier) rejected
- Integration: plug into relayer from step 5, assert end-to-end still passes
- Negative: envelope with stubbed empty proof now rejected

---

### Step 7 — Client B recognition (`crates/client`)

B scans dst chain events and trial-decrypts each tag using the shared secret.
On a match, recovers the FHE ciphertext.

**Tests**
- Post N dummy tag events + 1 real event on mock dst chain
- Assert B finds exactly one match
- Assert B recovers the correct ciphertext
- Assert B ignores all dummy events without error

---

### Step 8 — End to end (`tests/e2e`)

Full flow with all real components. Chain layer uses Anvil. Nym layer uses
smolmix against a local mixnet node or the Nym testnet.

```
A → src chain (Anvil) + Nym tunnel → Relayer → dst chain (Anvil) → B
```

**Tests**
- Full scenario: A sends, B receives correct ciphertext
- Unlinkability audit: capture everything the relayer logs, verify it cannot
  reconstruct the A↔B pair from its own data
- Noise: inject dummy traffic on both chains, assert B still finds its message
- Latency: measure and document mixnet overhead as a baseline for the Nym SDK

---

## Dependencies

| Crate | Purpose |
|---|---|
| `nym-sdk` / `smolmix` | Mixnet transport |
| `arkworks` | ZK proof system (Groth16) |
| `tfhe-rs` | FHE primitives |
| `alloy` | EVM chain interaction |
| `tokio` | Async runtime |
| `postcard` | Wire format serialization |
| `hkdf` + `hmac` | Key derivation and tag MAC |
| `anvil` (dev) | Local EVM node for integration tests |

---

## Status

- [ ] Step 1 — Cryptographic primitives
- [ ] Step 2 — Chain interface
- [ ] Step 3 — Nym transport layer
- [ ] Step 4 — Message envelope
- [ ] Step 5 — Relayer core logic
- [ ] Step 6 — ZK binding proof
- [ ] Step 7 — Client B recognition
- [ ] Step 8 — End to end
