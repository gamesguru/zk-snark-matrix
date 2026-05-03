# Security Model

## What the ZK proof guarantees

The STARK proof provides **computational soundness** at the 2⁻¹²⁸ level:

1. **Correct execution** — the topological sort and tie-breaking logic were
   applied faithfully to the input DAG.
2. **Routing integrity** — every data dependency was routed through the Beneš
   network without collisions (Theorem 4.1).
3. **Tamper detection** — any single-bit falsification in the trace cascades to
   ≥10% corruption in the LTC-stretched grid, caught by 843 random column
   queries (Theorem 4.3).

## What the ZK proof replaces

### The federated room join bottleneck

Today's `/v2/send_join` endpoint returns two payloads:

1. **State events** — the current room state (e.g., 43k events / 15MB for
   `#community:matrix.org`).
2. **Auth chain** — the chain of events proving each state event is valid.
   Typically 3–10× larger than the state itself (50–100MB for large rooms).

The joining server must then: verify every signature in the auth chain, re-run
state resolution to confirm the state is correct, and store everything in its
database. For large rooms this takes **minutes**.

### What the proof replaces

The proof **replaces the auth chain, not the state**. The joining server still
receives the current state events (it needs to know who's in the room), but
instead of the massive auth chain it receives a compact proof:

| Component          | Today (no proof)    | With ZK proof         |
| ------------------ | ------------------- | --------------------- |
| State events       | [x] 15MB (same)     | [x] 15MB (same)       |
| Auth chain         | [x] 50-100MB        | [ ] Replaced by proof |
| Proof              | --                  | ~KB                   |
| Signature re-check | All events          | Only state events     |
| State resolution   | Full O(N^2) re-exec | O(log N) proof verify |

### Benchmark: `#community:matrix.org` (43,543 events)

```
Events loaded: 43543
Padded width:  65536 (2^16)
Waksman routing: 9.9ms (31 layers × 32,768 switches)
Trace build:    3.7ms (1,015,808 constraints)
✓ All routing constraints satisfied
```

Total witness generation: **13.6ms** (release build, single-threaded).

## What the ZK proof does NOT guarantee

These are **protocol-level concerns** that must be addressed outside the
zero-knowledge system:

### Data availability

A valid proof attests that the prover executed state resolution correctly on
_some_ set of events, but it does not prove that the prover is not withholding
events. A malicious server could omit inconvenient events from the input DAG
and produce a valid proof over the incomplete set.

**Mitigation:** The verifier must independently confirm that the
`merge_base` and `tips` hashes in the public journal match events it can
retrieve over federation. If any referenced event is unavailable, the proof
should be rejected regardless of its cryptographic validity.

### Circuit identity (verification key pinning)

A malicious server could substitute a trivial "always accept" circuit that
proves nothing. Without verification key pinning, the verifier has no way to
distinguish a legitimate proof from a vacuous one.

**Mitigation:** Each Matrix room version must bind to a canonical verification
key hash (`VK_HASH`). The verifier rejects any proof whose verification key
does not match the expected hash for the room version. This hash must be
distributed via a trusted channel (e.g., hardcoded in the client, or published
in the room version specification).

## Ed25519 split-verification architecture

### Why signatures stay native

Ed25519 relies on elliptic curve arithmetic over a large prime field
(p = 2²⁵⁵ - 19). The STARK trace operates entirely in GF(2) — binary
field arithmetic via XOR/AND. Arithmetizing prime-field elliptic curve
operations inside a strict F₂ circuit would cause catastrophic non-native
arithmetic blowup, entirely wiping out the O(N log N) performance gains of the
Beneš network.

Therefore, Ed25519 verification is **delegated to the native host OS**, which
uses optimized CPU instructions for scalar multiplication. This is the only
mathematically viable architecture for a binary-field STARK.

### The boundary seal: Fiat-Shamir `h_auth` binding

The attack vector in any split-verification design is the boundary between
the native layer and the circuit. A malicious prover could verify signatures
for one set of events but generate a STARK proof for a different, manipulated
DAG.

The boundary is sealed by `h_auth`:

1. The prover verifies Ed25519 signatures natively over **all** events in
   the auth chain (the full historical DAG).
2. The prover computes `h_auth` = Keccak-256 over the concatenated
   (event_id, signature) pairs of all verified events.
3. `h_auth` is committed as a **public input** in the STARK proof's
   Fiat-Shamir transcript.
4. The STARK proof mathematically guarantees: "state resolution was
   executed correctly on a DAG of events that had valid signatures,
   producing this resolved state."

### Verifier-side flow

The verifier (the joining guest server) receives **only the state events**
(the final resolved outputs) and the proof. It does **not** receive the
auth chain -- that is the entire value proposition.

1. Receive state events + proof from resident server.
2. **Verify Ed25519 signatures** on ALL received state events (native,
   O(N)). Reject immediately if any single signature fails. This is a
   cheap DoS short-circuit that prevents the verifier from wasting time
   on STARK verification for obviously fabricated events.
3. Check `da_root` in the proof's public journal against the federation.
   Query multiple resident servers: "does this `da_root` match your view
   of the room?" If the honest majority agrees, the hidden auth chain
   is confirmed complete.
4. Verify the STARK proof (O(log N)).

If step 2 fails, the verifier never reaches step 4. If step 3 fails
(da_root divergence), the verifier rejects the proof and requests a
new ZK proof from a trusted peer whose `da_root` matches the federation
consensus. Traditional `/send_join` is used only as a last resort when
no ZK-capable peer is available.

### The blind spot: auth chain opacity

The verifier is **entirely blind** to the historical auth chain. It cannot
natively verify the signatures of intermediate events because it does not
have them. The STARK proof attests that the prover did verify them, but
the verifier has no independent way to confirm this from the proof alone.

This is inherent to any architecture where the proof replaces the auth
chain. The proof exists precisely so the verifier can safely **ignore**
the auth chain. If the verifier had to download the auth chain to verify
`h_auth`, the proof would achieve nothing.

### Bridging the blind spot: `da_root` attestation

The `da_root` in the public journal is the Merkle root over the
canonically sorted event set used by the prover. Instead of downloading
the auth chain, the verifier relies on **multi-server attestation**:

- The verifier extracts `da_root` from the STARK's public journal.
- The verifier asks N federation peers: "what is your `da_root` for
  this room?"
- If the honest minority agrees on the same root, the event set is
  confirmed complete and the proof is accepted.
- If roots diverge, the verifier queries `/get_missing_events` to
  identify what was omitted before accepting any proof.

This reduces the trust assumption from "trust one server's auth chain"
to "at least one federation peer is honest" -- a strictly weaker
assumption that holds under the same Byzantine model Matrix already
assumes for federation.

## Recursive proof provenance

### The proof genealogy ledger

When proofs are generated via Recursive MapReduce (see paper §4), the
framework must maintain a complete, unforgeable audit trail of which
homeserver generated each sub-proof, when, and from what base state.

Every STARK proof's **public journal** is extended with provenance fields:

```
{
  // Existing fields
  "da_root":     "0xc29ab9db...",
  "state_root":  "0x259df515...",
  "n_events":    43543,

  // Provenance ledger
  "prover_id":      "0x...",     // Keccak-256(server_name), e.g. "matrix.org"
  "proof_timestamp": 1746230400, // Unix epoch when proof was generated
  "epoch_range":    [0, 43543],  // Event index range this proof covers
  "merge_base":     "0x...",     // state_root of the previous epoch (IVC parent)
  "parent_proofs":  ["0x...", "0x..."]  // Hashes of sub-proofs folded into this one
}
```

**Cost: zero additional constraints.** Public journal entries are inputs to
the Fiat-Shamir hash sponge. They do not add gates to the arithmetic circuit.

### Recursive hash binding

In the recursive aggregator circuit, provenance is structurally enforced:

```
For each parent proof πᵢ being recursively verified:
  assert keccak256(πᵢ.public_journal) == parent_proofs[i]
```

This adds only a Keccak hash per parent (~20,000 F₂ constraints each) —
negligible compared to the routing network. A malicious aggregator cannot
claim a different server generated a sub-proof or backdate a timestamp
without invalidating the recursive verification.

### The proof genealogy DAG

Because each recursive fold carries its parents' journal hashes, the
complete history of proof generation forms a **proof DAG** mirroring the
event DAG:

```
Identity Proof π₁ (Chunk 1)
  prover_id:     matrix.org
  timestamp:     2026-05-02T12:00:00Z
  epoch_range:   [0, 1000)
  parent_proofs: []

Identity Proof π₂ (Chunk 2)
  prover_id:     envs.net
  timestamp:     2026-05-02T12:00:12Z
  epoch_range:   [1000, 2000)
  parent_proofs: []

Aggregated Proof π_agg
  prover_id:     t2l.io
  timestamp:     2026-05-02T12:01:40Z
  epoch_range:   [0, 43543)
  merge_base:    0x... (previous epoch's state_root)
  parent_proofs: [hash(π₁), hash(π₂), ...]
```

Any server joining later can trace the final `π_agg` back to every leaf
identity proof, seeing exactly who proved what, when, and what they were
building on. If a sub-proof is later found to have been generated from
manipulated events, the provenance chain pinpoints the exact server
responsible.

### Matrix integration

Proofs are published as Matrix events:

| Event Type              | Scope           | Purpose                                                      |
| ----------------------- | --------------- | ------------------------------------------------------------ |
| `m.room.identity_proof` | EDU (ephemeral) | Broadcast a chunk's identity proof to the gossip pool        |
| `m.room.epoch_proof`    | State event     | Publish the final aggregated proof + full provenance journal |

The room's event history **becomes** the proof ledger. Walking the
`m.room.epoch_proof` chain backwards gives the complete history of
distributed proof generation for the room, from genesis.

## Proof signing requirement

### Servers MUST sign all proofs

All proofs broadcast over federation — both identity chunk proofs (EDUs) and
aggregated epoch proofs (state events) — **MUST** carry a standard Matrix
signature from the generating homeserver using its Ed25519 signing key (or
its Falcon/FN-DSA key post-PQC migration).

The signature covers the serialized public journal:

```
signature = sign(
  server_signing_key,
  canonical_json(proof.public_journal)
)
```

This signature is transmitted **alongside** the proof, not inside the
arithmetic circuit. It adds zero constraints.

### Why sign proofs if the STARK already guarantees correctness?

The STARK guarantees **computational integrity** — the state was resolved
correctly. But it does not, by itself, prevent two distinct attack vectors
that require identity-level accountability:

1. **DoS via garbage proofs:** Without signatures, any anonymous node
   could flood the federation with syntactically valid but semantically
   useless proofs (e.g., proofs over empty or stale epoch ranges). The
   receiving server would waste CPU on STARK verification before
   discovering the proof is irrelevant. A signature allows the receiver to
   reject proofs from untrusted or unknown servers **before** running the
   verifier.

2. **Accountability for malicious data selection:** A valid proof can be
   generated over a biased event set (data availability attack). The
   `da_root` attestation detects the divergence, but without a signed
   `prover_id`, the federation cannot identify which server produced the
   biased proof. Signatures make data-selection attacks attributable.

3. **Replay prevention:** The signature binds the proof to a specific
   `proof_timestamp` and `epoch_range`. A server cannot replay a stale
   proof from a previous epoch without the signature revealing the
   mismatch against the current federation state.

### Verification flow (updated)

The verifier-side flow from the previous section is extended:

1. Receive proof + signature from federation peer.
2. **Verify the server signature** on the public journal (native Ed25519
   or Falcon, ~1μs). Reject unknown/untrusted servers immediately.
3. Verify Ed25519/Falcon signatures on all received state events (DoS
   short-circuit).
4. Check `da_root` against federation peers.
5. Verify the STARK proof (O(log N)).

Step 2 is the cheapest possible filter — microseconds to reject garbage
before committing to any cryptographic verification.

## Summary

| Property               | Guaranteed by          | Level         |
| ---------------------- | ---------------------- | ------------- |
| Execution correctness  | STARK proof            | 2^-128        |
| Routing completeness   | Beneš theorem          | Deterministic |
| Tamper detection       | LTC + 843 queries      | 2^-128        |
| Auth chain elision     | Proof replaces chain   | Cryptographic |
| Data availability      | da_root + federation   | Protocol      |
| Circuit identity       | VK_HASH pinning        | Protocol      |
| Signature authenticity | Prover OS + h_auth     | Cryptographic |
| State completeness     | da_root + multi-attest | Byzantine     |
| Proof provenance       | Public journal + IVC   | Cryptographic |
| Prover accountability  | Server signature       | Cryptographic |
