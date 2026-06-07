# FHE Relayer over Nym

## Objectives

This project has two concurrent goals:

**1. Test the new Nym SDK transport primitives in a real-world scenario.**
The recently released `smolmix` layer exposes standard `TcpStream` types that
route all traffic through the Nym mixnet transparently. This project exercises
both the `smolmix` TCP path and the native Nym SURB path under realistic
conditions — variable payload sizes, concurrent connections, anonymous reply
channels — rather than in a toy demo.

**2. Build a theoretically sound private message relay using FHE primitives.**
Fully Homomorphic Encryption ensures message content remains opaque to every
party except the intended recipient. On-chain commitments provide
censorship-resistant ordering and proof of relay. Together they implement a
public/private register: the chain is fully public (anyone can observe that the
system is being used) but completely opaque (no observer can learn who is
communicating with whom or what is being exchanged).

---

## Threat Model

The system protects the **communication graph**. An adversary watching both
chains and the Nym network simultaneously should learn nothing about which
sender is communicating with which recipient — only that the system is being
used.

| Adversary | Capability | Protected property |
|---|---|---|
| Chain observer | Sees all on-chain data and timestamps | Sender/recipient identity, communication graph |
| Network observer | Sees IP traffic and timing | Handled by Nym mixnet |
| Relayer | Sees Nym packets and both chains | Cannot link a src event to a dst event |
| Anyone | Full access to dst chain | Cannot recognize a message without the shared secret |

**Out of scope:** shared secret and static keypair establishment between A and B.
This is assumed to happen out of band.

---

## Architecture

### Key Setup (out of band)

```
B generates static X25519 keypair (sk_b, pk_b)
B generates FHE keypair (fhe_sk, fhe_pk, fhe_server_key)

B ──► A:         shared_secret, pk_b, fhe_pk
B ──► RELAYER:   fhe_server_key  (enables homomorphic evaluation)
```

### Per-Message Key Derivation

```
A generates ephemeral keypair (ek_secret, ek_pub)

stealth_input = X25519(ek_secret, pk_b)   ← B verifies with X25519(sk_b, ek_pub)

IKM = shared_secret || stealth_input

HKDF-SHA256(IKM, salt=nonce)
    ├── info="fhe-relay-tag-v1"     → tag_key
    └── info="fhe-relay-binding-v1" → binding_key

tag      = HMAC-SHA256(tag_key, nonce)       ← posted on src chain
nullifier = HMAC-SHA256(binding_key, tag)    ← replay protection at relayer
```

### Protocol Flow

```
Client A           Src Chain         Relayer          Dst Chain        Client B
   |                   |                |                  |                |
   |-- submit(tag) --->|                |                  |                |
   |                   |<-- watching ---|                  |                |
   |                   |--- Submitted ->|                  |                |
   |                                   |                  |                |
   |-------- Nym SURB: ClientEnvelope(nonce, ek, tag, ct, proof) -------->|mailbox
   |                               mailbox                |                |
   |                               |-- RelayerEnvelope -->|                |
   |                               |         |-- verify nullifier          |
   |                               |         |-- check src chain           |
   |                               |         |-- verify(tag) ------------>|
   |                               |         |                  Verified   |
   |                               |<-- VerifiedNotification --------------|
   |                               |-- DispatchEnvelope --> dispatcher     |
   |                               |                          |            |
   |                               |                          |-- Nym SURB: DeliveryEnvelope -->|
   |                               |                          |                        B decrypts
   |                               |                          |<-- ReceivedNotification --------|
   |                               |<-- ReceivedNotification -|            |                |
   |                               |                          |-- received(tag) ----------->|
```

### Envelope Types

All messages share a single `Envelope` tagged union serialized with `postcard`:

| Variant | Direction | Key fields |
|---|---|---|
| `ClientEnvelope` | A → mailbox | `nonce, ek, tag, fhe_ciphertext, binding_proof, nullifier, fhe_pk` |
| `RelayerEnvelope` | mailbox → relayer | `tag, binding_proof, nullifier, fhe_pk, fhe_ciphertext` |
| `DispatchEnvelope` | mailbox → dispatcher | `nonce, ek, tag, fhe_ciphertext` |
| `VerifiedNotification` | relayer → mailbox | `tag` |
| `ReceivedNotification` | dispatcher → mailbox | `tag` |
| `DeliveryEnvelope` | dispatcher → B | `nonce, ek, tag, fhe_ciphertext` |

### Transport Layer

Two Nym transport mechanisms are provided:

**`SurbTransport`** — wraps `nym-sdk::MixnetClient`, uses SURBs for anonymous
reply channels. Used on edge legs: A → mailbox, dispatcher → B. The receiver
never learns the sender's Nym address.

**`SmolmixTransport`** — routes standard TCP through the mixnet via `smolmix`.
Returns a `TcpStream` compatible with tokio-rustls, hyper, etc. Used on
server-side legs: mailbox ↔ relayer, mailbox ↔ dispatcher.

```
SmolmixTransport Nym stack:

User code (Envelope over TcpStream)
        ↓
tokio-smoltcp::Net
        ↓
NymAsyncDevice   (raw IP packet adapter)
        ↓
NymIprBridge     (mixnet ↔ channel shuttle)
        ↓
IpMixStream → MixnetClient → Nym mixnet → IPR exit node
```

---

## Crate Layout

```
fhe-over-nym/
├── crypto-primitives/
│   └── src/
│       ├── ecdh.rs      # X25519 keypair gen, stealth_input derivation
│       ├── kdf.rs       # HKDF: derive_sender_keys / derive_recipient_keys
│       ├── tag.rs       # generate_tag / recognize_tag (HMAC-SHA256)
│       ├── nonce.rs     # NonceGenerator (OsRng, zeroized on drop)
│       ├── proof.rs     # generate_proof / verify_proof (HMAC-based, nullifier set)
│       ├── fhe.rs       # encrypt_compact / expand / decrypt / evaluate / FHEKeys
│       ├── types.rs     # all key, bundle, and proof types
│       └── error.rs     # NonceError, KdfError, TagError, ProofError
└── transport/
    └── src/
        ├── envelopes.rs          # Envelope tagged union, EnvelopeCodec, WireEnvelope trait
        ├── surb_transport.rs     # SurbTransport (send, receive_anon, reply_to_anon)
        ├── smolmix_transport.rs  # SmolmixTransport (tcp_connect, shutdown)
        └── error.rs              # EnvelopeError, TransportError
```

Planned crates (not yet implemented):

```
├── chain/       # ChainWatcher / ChainPoster traits, Anvil integration
├── mailbox/     # receives from A, stores, replicates to dispatcher
├── relayer/     # proof verify, nullifier set, posts Verified
├── dispatcher/  # entitlement registry, delivers to B
├── client/      # client A (send) and client B (receive + decrypt)
└── tests/e2e/   # full flow against local L2 node
```

---

## Implementation Plan

### Step 1 — Cryptographic primitives (`crypto-primitives`) ✓

- [x] ECDH: `generate_ephemeral_keypair`, `generate_static_keypair`, `compute_stealth_input`
- [x] KDF: `derive_sender_keys(shared_secret, stealth_input, nonce)` → `tag_key + binding_key`
      `derive_recipient_keys(...)` → `tag_key` only
- [x] Tag: `generate_tag(tag_key, nonce)`, `recognize_tag`
- [x] Nonce: `NonceGenerator` (OsRng, zeroized on drop)
- [x] Proof: `generate_proof` (64-byte HMAC blob), `verify_proof` (nullifier set check)
- [x] FHE: `encrypt_compact`, `expand`, `decrypt`, `evaluate`, `FHEKeys`

**Remaining**: replace HMAC-based binding proof with a real ZK proof (Groth16).

---

### Step 2 — Chain interface (`chain`) — not started

Define the chain boundary as a trait before touching any real node.

```rust
trait ChainWatcher {
    async fn watch(&self) -> impl Stream<Item = TagEvent>;
}

trait ChainPoster {
    async fn post(&self, tag: [u8; 32]) -> TxHash;
}
```

Implement with an in-memory mock first. Then implement against Anvil.

---

### Step 3 — Nym transport layer (`transport`) ✓

- [x] `SurbTransport`: send with SURB, `receive_anon`, `reply_to_anon`
- [x] `SmolmixTransport`: TCP-over-Nym tunnel, `tcp_connect`
- [x] IP masking verified: Cloudflare reports a different IP when routed through smolmix

---

### Step 4 — Message envelope (`transport`) ✓

- [x] `Envelope` tagged union with 6 variants
- [x] `EnvelopeCodec`: postcard encode/decode through the tagged union
- [x] `WireEnvelope` trait: `into_envelope` / `from_envelope` with `KindMismatch` on wrong variant
- [x] Round-trip and variant-distinguishability tests

---

### Step 5 — Relayer core logic (`relayer`) — not started

Wire chain watcher + Nym receiver. Maintain pending tag set, verify nullifier,
post Verified on dst chain, send `VerifiedNotification` to mailbox.

---

### Step 6 — ZK binding proof (`crypto-primitives`) — not started

Replace HMAC-based proof with Groth16 (arkworks) or Bulletproofs. Statement:

> I know a nonce such that `HMAC(tag_key, nonce) == tag`, where `tag_key` is
> derived from a secret I know, without revealing the secret or the nonce.

---

### Step 7 — Client B recognition (`client`) — not started

B receives `DeliveryEnvelope`, re-derives `stealth_input` from `sk_b` and `ek`,
re-derives `tag_key`, verifies tag, decrypts ciphertext with `fhe_sk`.

---

### Step 8 — End to end (`tests/e2e`) — not started

Full flow with Anvil chains and local Nym mixnet or testnet.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `nym-sdk` | Native Nym mixnet client (SurbTransport) |
| `smolmix` | TCP-over-Nym transport (SmolmixTransport) |
| `tfhe` | FHE: CompactPublicKey, ServerKey, ClientKey, FheUint8, integer feature |
| `x25519-dalek` | X25519 ECDH (stealth input derivation) |
| `hkdf` + `hmac` + `sha2` | Key derivation and tag/proof MAC |
| `zeroize` | Nonce zeroization on drop |
| `postcard` | Wire format serialization |
| `alloy` (planned) | EVM chain interaction, event watching |
| `tokio` | Async runtime |
| `anvil` (dev, planned) | Local EVM node for integration tests |

---

## Status

- [x] Step 1 — Cryptographic primitives (ECDH, KDF, tag, nonce, HMAC proof, FHE)
- [ ] Step 2 — Chain interface
- [x] Step 3 — Nym transport layer (SurbTransport + SmolmixTransport)
- [x] Step 4 — Message envelope (Envelope tagged union, EnvelopeCodec)
- [ ] Step 5 — Relayer core logic
- [ ] Step 6 — ZK binding proof (currently HMAC-based placeholder)
- [ ] Step 7 — Client B recognition
- [ ] Step 8 — End to end
