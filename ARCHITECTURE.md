# Architecture

## Overview

A private document relay system. The chain is a public state register — anyone
can observe that documents are moving through the system, no one can observe who
is communicating with whom or what is being exchanged.

Four infrastructure components handle the relay. Two clients sit at the edges.
All internal communication travels over the Nym mixnet. No HTTP, no TCP, no
correlatable IP traffic between components.

---

## Entities and Knowledge Boundaries

```
ENTITY        KNOWS                                    DOES NOT KNOW
─────────────────────────────────────────────────────────────────────────────
Client A      shared_secret, pk_b, ek (per-message)   B's Nym address
              fhe_pk, stealth_input (per-message)
Mailbox       A's Nym address, ciphertext              B, shared_secret, plaintext
Relayer       tag, nullifier, proof, fhe_server_key    A, B, shared_secret, plaintext
Dispatcher    B's Nym address, entitlement             A, shared_secret, plaintext
Client B      shared_secret, sk_b, fhe_sk              A's Nym address
Chain         tag, state transitions                   everything else
```

The tag is the only artifact that crosses all components. It is an HMAC over a
nonce using a key derived from the ECDH stealth input — opaque without `sk_b`
and the shared secret.

---

## Out of Band Setup

Before any document is sent, two registrations happen outside the system:

```
B generates static X25519 keypair (sk_b, pk_b)
B generates FHE keypair (fhe_sk, fhe_pk, fhe_server_key)

B ──► A  (private rendezvous, separate protocol)
        shares: shared_secret, pk_b, fhe_pk

B ──► RELAYER  (out of scope registration)
        shares: fhe_server_key
        (relayer can perform homomorphic evaluation on ciphertexts)

A ──► MAILBOX
        registers Nym address
        "I am an authorized sender"

B ──► DISPATCHER
        registers Nym address + entitlement proof
        ZK("I know the shared_secret that produces tags of this form")
        dispatcher cannot link this to A
        mailbox never learns B exists
```

---

## On-Chain State Machine

Two separate Solidity contracts, each deployed on an EVM-compatible L2
(Base or Optimism). `SubmitRegister` lives on the src chain and is written to
by client A. `DeliveryRegister` lives on the dst chain and is written to by the
relayer and client B. They share no on-chain link — the tag is the only
correlation and it is opaque without the shared secret.

```solidity
// src chain — written by client A
contract SubmitRegister {
    mapping(bytes32 => bool) public submitted;

    event Submitted(bytes32 indexed tag);

    function submit(bytes32 tag) external {
        require(!submitted[tag]);
        submitted[tag] = true;
        emit Submitted(tag);
    }
}
```

```solidity
// dst chain — written by relayer (verify) and client B (received)
contract DeliveryRegister {
    enum State { Unknown, Verified, Received }

    mapping(bytes32 => State) public tags;

    event Verified(bytes32 indexed tag);
    event Received(bytes32 indexed tag);

    function verify(bytes32 tag) external {
        require(tags[tag] == State.Unknown);
        tags[tag] = State.Verified;
        emit Verified(tag);
    }

    function received(bytes32 tag) external {
        require(tags[tag] == State.Verified);
        tags[tag] = State.Received;
        emit Received(tag);
    }
}
```

No sender address. No recipient address. No payload. No metadata.
State transitions are the only public information.

---

## Envelope Wire Format

All messages are serialized with `postcard` through a tagged union. The variant
discriminant is on the wire so receivers can route without inspecting the payload.

```rust
enum Envelope {
    Client(ClientEnvelope),       // A → mailbox
    Relayer(RelayerEnvelope),     // mailbox → relayer
    Dispatch(DispatchEnvelope),   // mailbox → dispatcher (after Verified)
    Verified(VerifiedNotification), // relayer → mailbox
    Received(ReceivedNotification), // dispatcher → mailbox
    Delivery(DeliveryEnvelope),   // dispatcher → B
}
```

### Field breakdown

```rust
// A → mailbox
struct ClientEnvelope {
    nonce:          [u8; 32], // per-message random nonce
    ek:             [u8; 32], // ephemeral public key (X25519 KEM encapsulation)
    tag:            [u8; 32], // HMAC(tag_key, nonce), matches src chain
    fhe_ciphertext: Vec<u8>,  // FHE-encrypted payload
    binding_proof:  Vec<u8>,  // HMAC-based proof: nullifier || commitment (64 bytes)
    nullifier:      [u8; 32], // HMAC(binding_key, tag), replay protection
    fhe_pk:         Vec<u8>,  // sender's FHE public key (for relayer evaluation)
}

// mailbox → relayer (no nonce/ek — relayer does not decrypt)
struct RelayerEnvelope {
    tag:            [u8; 32],
    binding_proof:  Vec<u8>,
    nullifier:      [u8; 32],
    fhe_pk:         Vec<u8>,
    fhe_ciphertext: Vec<u8>,
}

// mailbox → dispatcher (after Verified; nonce+ek needed for B to decrypt)
struct DispatchEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}

// relayer → mailbox
struct VerifiedNotification { tag: [u8; 32] }

// dispatcher → mailbox
struct ReceivedNotification { tag: [u8; 32] }

// dispatcher → B (same fields as DispatchEnvelope, distinct wire variant)
struct DeliveryEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}
```

The FHE ciphertext is large (tens of KB to MB depending on operation). It
travels only over Nym tunnels and is held in memory by mailbox and dispatcher.
It never appears on chain.

---

## Full Message Flow

```
t=0s

  CLIENT A
    generates ephemeral keypair (ek_secret, ek_pub)
    computes stealth_input = X25519(ek_secret, pk_b)
    derives tag_key, binding_key via HKDF(shared_secret || stealth_input, nonce)
    derives tag = HMAC(tag_key, nonce)
    derives nullifier = HMAC(binding_key, tag)
    derives binding_proof = nullifier || HMAC(binding_key, nonce||shared_secret||stealth_input)
    encrypts payload: compact_ct = FHE_encrypt(plaintext, fhe_pk)
    posts src chain: Submitted(tag)
    sends ClientEnvelope(nonce, ek, tag, compact_ct, proof, nullifier, fhe_pk)
          to MAILBOX over Nym (SurbTransport)

  MAILBOX
    stores ClientEnvelope locally
    forwards RelayerEnvelope(tag, proof, nullifier, fhe_pk, ciphertext)
             to RELAYER over Nym

  RELAYER
    receives RelayerEnvelope
    checks nullifier not previously seen (replay protection)
    verifies binding_proof structure: proof[0..32] == nullifier
    checks src chain: tag == Submitted?

t=~2s   (L2 block confirmation)

  RELAYER
    sees Submitted confirmed on L2
    (optionally: expands CompactCiphertextList and performs homomorphic evaluation
     using fhe_server_key — relayer learns nothing about plaintext)
    posts dst chain: Verified(tag)
    sends VerifiedNotification(tag) to MAILBOX over Nym

  MAILBOX
    receives VerifiedNotification
    sends DispatchEnvelope(nonce, ek, tag, ciphertext) to DISPATCHER over Nym
    holds data locally until Received

  DISPATCHER
    receives DispatchEnvelope
    matches tag against B's registered entitlement
    sends DeliveryEnvelope(nonce, ek, tag, ciphertext) to CLIENT B over Nym

  CLIENT B
    receives DeliveryEnvelope
    computes stealth_input = X25519(sk_b, ek)
    derives tag_key via HKDF(shared_secret || stealth_input, nonce)
    verifies tag = HMAC(tag_key, nonce)
    decrypts ciphertext using fhe_sk
    posts dst chain: Received(tag)
    notifies DISPATCHER: "tag received"

  DISPATCHER
    receives Received notification
    notifies MAILBOX: "tag received"
    deletes data from local store

  MAILBOX
    receives Received notification
    deletes data from local store   ← safe to delete only here
```

---

## Storage State vs Chain State

```
CHAIN STATE     MAILBOX HOLDS     DISPATCHER HOLDS
────────────────────────────────────────────────────
Submitted       yes               no
Verified        yes               yes
Received        no                no
```

Mailbox holds until Received as a backup. If the dispatcher crashes after
replication but before delivery, the mailbox can re-replicate. No data is
deleted until the chain confirms Received.

---

## Nym Transport Topology

All internal links are Nym tunnels. Components have Nym addresses, not IP
addresses. No component exposes an IP-reachable interface.

```
CLIENT A  ──Nym──►  MAILBOX  ──Nym──►  RELAYER  ──Nym──►  DISPATCHER  ──Nym──►  CLIENT B
                       │                                        ▲
                       └────────────── Nym (replication) ──────┘
```

Two transport implementations are available, used on different protocol legs:

### SurbTransport (native Nym SURB)

Used for: A → mailbox, dispatcher → B, and notification replies.

Wraps `nym-sdk::MixnetClient` directly. The sender includes one SURB so the
receiver can reply without learning the sender's Nym address. The reply channel
is anonymous in both directions.

```
send(recipient, Envelope)   →  wraps in SURB, blocks until reply arrives
receive_anon()              →  returns (Envelope, AnonymousSenderTag)
reply_to_anon(tag, Envelope)→  reply via SURB tag, no address disclosed
```

### SmolmixTransport (TCP-over-Nym)

Used for: server-side component links (mailbox ↔ relayer, mailbox ↔ dispatcher).

Routes standard TCP through the mixnet. Returned `TcpStream` is compatible with
tokio-rustls, hyper, and the full async ecosystem.

```
Nym transport stack (smolmix):

User code (Envelope send/recv over TcpStream)
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

## Cryptographic Primitives

### Key hierarchy

```
B's static keypair: (sk_b, pk_b)  — generated once, pk_b shared out of band
A's ephemeral keypair: (ek_secret, ek_pub)  — generated fresh per message

                                        ek_pub travels in envelope as `ek`
X25519(ek_secret, pk_b)  =  X25519(sk_b, ek_pub)  =  stealth_input

IKM = shared_secret || stealth_input    [64 bytes, stack-allocated]

HKDF-SHA256(IKM, salt=nonce)
    ├── info="fhe-relay-tag-v1"     → tag_key     [32 bytes]
    └── info="fhe-relay-binding-v1" → binding_key [32 bytes]
```

### Tag

```
tag = HMAC-SHA256(key=tag_key, msg=nonce)    → [u8; 32]
```

The tag is the on-chain identifier. It is computed by A and can be independently
re-derived by B (who holds `sk_b` and the shared secret).

### Binding proof

The binding proof is a 64-byte HMAC-based blob, not a zero-knowledge proof.
Full ZK (Groth16 / Bulletproofs) is a TODO.

```
nullifier  = HMAC-SHA256(binding_key, tag)                              [32 bytes]
commitment = HMAC-SHA256(binding_key, nonce || shared_secret || stealth_input) [32 bytes]
proof      = nullifier || commitment                                     [64 bytes]
```

The nullifier uniquely identifies the spend. The relayer maintains a
spent-nullifier set (`NullifierProof`) and rejects replays. The relayer cannot
re-derive `commitment` (it does not hold `binding_key`), so full binding
verification requires the ZK layer.

### FHE key distribution

Three TFHE keys are produced at setup time:

```
fhe_pk  (CompactPublicKey)  → sender A     compact batch encryption
fhe_sk  (ClientKey)         → recipient B  decryption
fhe_server_key (ServerKey)  → relayer      expand compact ct + homomorphic evaluation
```

The relayer receives `fhe_pk` and `fhe_ciphertext` in `RelayerEnvelope`. It can
expand the compact ciphertext and perform homomorphic operations (e.g. `ct + 1`)
without ever accessing the plaintext.

---

## Collusion Analysis

```
MAILBOX + RELAYER      learn A sent something       cannot find B
RELAYER + DISPATCHER   learn something went to B    cannot find A
MAILBOX + DISPATCHER   learn A sent, B received     cannot link them
                       (no shared tag knowledge between the two
                        without also having the relayer's data)

ALL THREE colluding    can link A sent → B received via tag
                       still cannot read the ciphertext
                       FHE holds regardless of collusion
```

The three-entity collusion is the residual trust assumption. Content is
protected unconditionally by FHE. The communication graph requires full
three-way collusion to expose.

---

## Latency Budget

```
Nym packet latency          ~1–5s    (cover traffic, mixing delays)
L2 block confirmation       ~2s      (Base / Optimism)
Ciphertext replication      ~1–5s    (Nym tunnel, mailbox → dispatcher)
Delivery to B               ~1–5s    (Nym tunnel, dispatcher → B)

Total expected latency      ~5–15s   happy path
Bottleneck                  L2 confirmation + Nym mixing
```

---

## Known Gaps (POC Scope)

```
// TODO(poc): binding proof is HMAC-based, not a real ZK proof
// proof.rs produces a 64-byte nullifier||commitment blob; the relayer cannot
// re-derive the commitment and therefore cannot fully verify binding
// for production: replace with Groth16 (arkworks) or Bulletproofs

// TODO(poc): single message, single recipient only
// this POC covers exactly one A → one B, one message
// for production: multiple senders, multiple recipients, multiple
// concurrent in-flight messages, per-recipient entitlement isolation

// TODO(poc): no retry logic on Nym tunnel drop during replication
// happy path only — assumes stable tunnels between all components
// for production: mailbox needs retry queue, dispatcher needs
// deduplication on tag before storing ciphertext

// TODO(poc): nonce coordination between A and B not specified
// B needs to know which nonce to use during tag verification
// for production: define nonce window protocol as part of
// out-of-band secret sharing

// TODO(poc): entitlement proof scheme not fully specified
// B's ZK registration with dispatcher is described but not implemented
// for production: define the exact ZK statement and circuit
```

---

## Crate Layout

```
fhe-over-nym/
├── crypto-primitives/
│   └── src/
│       ├── ecdh.rs     # X25519 keypair generation, stealth_input derivation
│       ├── kdf.rs      # HKDF: derive_sender_keys, derive_recipient_keys
│       ├── tag.rs      # generate_tag, recognize_tag (HMAC-SHA256)
│       ├── nonce.rs    # NonceGenerator (OsRng, zeroized on drop)
│       ├── proof.rs    # generate_proof, verify_proof (HMAC-based, nullifier set)
│       ├── fhe.rs      # encrypt_compact, expand, decrypt, evaluate, FHEKeys
│       ├── types.rs    # Tag, Nullifier, TagKey, BindingKey, StealthInput,
│       │               # EphemeralKeyPair, StaticKeyPair,
│       │               # SenderBundle, RecipientBundle, RelayerBundle,
│       │               # SenderKeys, RecipientKeys,
│       │               # BindingProof, NullifierProof, FheEvalResult
│       └── error.rs    # NonceError, KdfError, TagError, ProofError
└── transport/
    └── src/
        ├── envelopes.rs         # Envelope tagged union (6 variants), EnvelopeCodec,
        │                        # WireEnvelope trait, all concrete envelope structs
        ├── surb_transport.rs    # SurbTransport (nym-sdk MixnetClient + SURB)
        ├── smolmix_transport.rs # SmolmixTransport (TCP-over-Nym via smolmix)
        └── error.rs             # EnvelopeError, TransportError
```

---

## Dependencies

| Crate | Purpose |
|---|---|
| `nym-sdk` | Native Nym mixnet client (SurbTransport) |
| `smolmix` | TCP-over-Nym transport (SmolmixTransport) |
| `tfhe` | FHE primitives: CompactPublicKey, ServerKey, ClientKey, FheUint8 |
| `x25519-dalek` | X25519 ECDH (stealth input derivation) |
| `hkdf` + `hmac` + `sha2` | Key derivation and tag/proof MAC |
| `zeroize` | Nonce zeroization on drop |
| `postcard` | Envelope wire format serialization |
| `alloy` (planned) | EVM chain interaction, event watching |
| `tokio` | Async runtime |
| `anvil` (dev, planned) | Local EVM node for integration tests |
