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
ENTITY        KNOWS                          DOES NOT KNOW
──────────────────────────────────────────────────────────────────
Client A      shared_secret, B exists        B's Nym address
Mailbox       A's Nym address, ciphertext    B, shared_secret, plaintext
Relayer       tag, proof validity            A, B, ciphertext, plaintext
Dispatcher    B's Nym address, entitlement   A, shared_secret, plaintext
Client B      shared_secret, A exists        A's Nym address
Chain         tag, state transitions         everything else
```

The tag is the only artifact that crosses all components. It is an HMAC over a
nonce — opaque without the shared secret.

---

## Out of Band Setup

Before any document is sent, two registrations happen outside the system:

```
A ←──── shared_secret ────► B       (private rendezvous, separate protocol)

A ──► MAILBOX
        registers Nym address
        "I am an authorized sender"

B ──► DISPATCHER
        registers Nym address + entitlement proof
        ZK("I know the shared_secret that produces tags of this form")
        dispatcher cannot link this to A
        mailbox never learns B exists
```

Entitlement is proven at registration time. The dispatcher authenticates B once,
not per message.

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

## Message Envelope

What A sends to the mailbox over Nym:

```rust
struct Envelope {
    nonce:          [u8; 32],
    tag:            [u8; 32],    // HMAC(tag_key, nonce), matches src chain
    fhe_ciphertext: Vec<u8>,     // encrypted document, never touches chain
    binding_proof:  Vec<u8>,     // ZK proof linking nonce+binding_key → tag
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
    derives tag = HMAC(tag_key, nonce)
    posts src chain: Submitted(tag)
    sends Envelope(nonce, tag, ciphertext, proof) to MAILBOX over Nym

  MAILBOX
    stores ciphertext locally
    forwards (tag, proof) to RELAYER over Nym

  RELAYER
    receives (tag, proof)
    verifies ZK proof: proof binds (nonce, binding_key) → tag
    checks src chain: tag == Submitted?

t=~2s   (L2 block confirmation)

  RELAYER
    sees Submitted confirmed on L2
    posts dst chain: Verified(tag)
    notifies MAILBOX: "tag verified"

  MAILBOX
    receives verified notification
    pushes ciphertext to DISPATCHER over Nym   ← replication starts here
    holds ciphertext locally until Received

  DISPATCHER
    receives ciphertext
    matches tag against B's registered entitlement
    delivers ciphertext to CLIENT B over Nym

  CLIENT B
    receives ciphertext
    trial-decrypts tag using shared_secret to confirm match
    posts dst chain: Received(tag)
    notifies DISPATCHER: "tag received"

  DISPATCHER
    receives Received notification
    notifies MAILBOX: "tag received"
    deletes ciphertext from local store

  MAILBOX
    receives Received notification
    deletes ciphertext from local store   ← safe to delete only here
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

```
Nym transport stack (smolmix):

User code (Envelope send/recv)
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

```
shared_secret
    │
    └─► HKDF
            ├─► tag_key      used by A to generate tags
            │                used by B to trial-decrypt tags
            └─► binding_key  used by A to generate ZK binding proof
```

**Tag generation**
```
tag = HMAC(tag_key, nonce)    → [u8; 32]
```

**ZK binding proof statement**
```
I know a nonce and a binding_key such that:
    HMAC(tag_key, nonce) == tag
where tag_key is derived from a secret I know,
without revealing the secret, the nonce, or the binding_key.
```

Circuit: Groth16 via arkworks (small proof, fast verify, trusted setup required)
or Bulletproofs (larger proof, no trusted setup). Choice depends on proof size
budget and setup trust acceptability.

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

The ciphertext replication and delivery happen after chain confirmation.
The chain is the ordering bottleneck, not the transport.

---

## Known Gaps (POC Scope)

```
// TODO(poc): single message, single recipient only
// this POC covers exactly one A → one B, one message
// for production: multiple senders, multiple recipients, multiple
// concurrent in-flight messages, per-recipient entitlement isolation

// TODO(poc): no retry logic on Nym tunnel drop during replication
// happy path only — assumes stable tunnels between all components
// for production: mailbox needs retry queue, dispatcher needs
// deduplication on tag before storing ciphertext

// TODO(poc): nonce coordination between A and B not specified
// B needs to know which nonce range to scan during trial decryption
// for production: define nonce window protocol as part of
// out-of-band secret sharing

// TODO(poc): entitlement proof scheme not fully specified
// B's ZK registration with dispatcher is described but not implemented
// for production: define the exact ZK statement and circuit
```

---

## Crate Layout

```
fhe-relayer/
├── contracts/
│   ├── SubmitRegister.sol      # src chain: Submitted state, written by A
│   └── DeliveryRegister.sol    # dst chain: Verified → Received, written by relayer and B
├── crates/
│   ├── primitives/             # HKDF, tag generation, ZK binding proof
│   ├── chain/                  # contract interfaces, event watcher, chain poster
│   ├── transport/              # Nym tunnel setup, Envelope wire format
│   ├── mailbox/                # receives from A, stores, replicates to dispatcher
│   ├── relayer/                # pure proof verifier, posts Verified on dst chain
│   ├── dispatcher/             # entitlement registry, delivers to B
│   └── client/                 # client A (send) and client B (receive)
└── tests/
    └── e2e/                    # full flow against local L2 node
```

---

## Dependencies

| Crate | Purpose |
|---|---|
| `nym-sdk` / `smolmix` | Mixnet transport, all internal tunnels |
| `arkworks` | ZK proof system (Groth16) |
| `tfhe-rs` | FHE primitives, ciphertext format |
| `alloy` | EVM chain interaction, event watching |
| `tokio` | Async runtime |
| `postcard` | Envelope wire format serialization |
| `hkdf` + `hmac` | Key derivation and tag MAC |
| `anvil` (dev) | Local EVM node for integration tests |
