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

### Identity-logic trust boundary

Ed25519 signature verification is delegated to the native Host OS, not
performed inside the STARK trace. The proof assumes the OS-verified event IDs
are authentic. The Fiat-Shamir sponge binds the OS-computed authentication
digest (`h_auth`) to the trace commitment root, but if the prover's OS is
compromised, `h_auth` could be fabricated.

**Mitigation:** This is inherent to any architecture that offloads signature
verification for performance. The verifier should independently verify
signatures on any events it fetches over federation, rather than trusting the
prover's `h_auth` blindly.

## Summary

| Property               | Guaranteed by        | Level         |
| ---------------------- | -------------------- | ------------- |
| Execution correctness  | STARK proof          | 2⁻¹²⁸         |
| Routing completeness   | Beneš theorem        | Deterministic |
| Tamper detection       | LTC + 843 queries    | 2⁻¹²⁸         |
| Data availability      | Federation protocol  | Protocol      |
| Circuit identity       | VK_HASH pinning      | Protocol      |
| Signature authenticity | Host OS + federation | Protocol      |
