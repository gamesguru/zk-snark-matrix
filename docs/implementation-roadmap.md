# Implementation Roadmap: Waksman Router + Binius Migration

## Current State

The codebase uses **Plonky3/BabyBear** (`p = 2³¹ - 1`) with a **Star Graph**
scaffold. The AIR constraint body is empty (`fn eval` is a no-op). The prover
walks a Star Graph `S_n` over factoriadic permutations — this is placeholder
scaffolding, not a real Beneš network.

---

## Phase 1: Waksman Router (pure algorithmic, no crypto dependency)

**Goal:** Given any permutation `π: [N] → [N]`, compute the boolean switch
settings for a Beneš network of depth `2⌈log₂ N⌉ - 1`.

### 1.1 Data structures

```rust
// ruma-zk-prover/src/waksman.rs

/// A Beneš network for N inputs (padded to 2^d).
pub struct BenesNetwork {
    pub depth: usize,       // 2*d - 1
    pub width: usize,       // 2^d (padded)
    /// Switch settings: switches[layer][switch_index] ∈ {false, true}
    /// false = straight-through, true = cross
    pub switches: Vec<Vec<bool>>,
}

impl BenesNetwork {
    /// Compute switch settings for a given permutation using Waksman's
    /// recursive algorithm (1968).
    pub fn from_permutation(perm: &[usize]) -> Self { ... }

    /// Given inputs, apply the network to produce outputs.
    /// Used for testing: assert output == perm(input).
    pub fn route<T: Copy>(&self, inputs: &[T]) -> Vec<T> { ... }
}
```

### 1.2 Algorithm (Waksman 1968)

The recursive decomposition:

1. Pad `N` to `2^d`.
2. Split the network into upper and lower halves.
3. Use a greedy coloring on a bipartite constraint graph to assign the
   outermost layer switches.
4. Recurse on the two sub-permutations induced by the split.

**Complexity:** O(N log N) time, O(N log N) space.

### 1.3 Tests

- Round-trip: `route(from_permutation(π), input) == π(input)` for random
  permutations at N = 2, 4, 8, 16, 64, 1024, 32768.
- Edge cases: identity permutation, reversal, single swap.

---

## Phase 2: Trace Builder

**Goal:** Build the 2D execution trace as a `W × D` binary matrix.

### 2.1 Trace layout

```
Layer 0:        Input layer (N events, padded to W = 2^d)
Layers 1..D-1:  Beneš routing layers (switch + route constraints)
Layer D:        Logic layer (tie-breaking, power-level checks)
```

Each cell is a fixed-width bitstring (e.g., 256 bits for a hash).

### 2.2 Implementation

```rust
// ruma-zk-prover/src/trace.rs

pub struct ExecutionTrace {
    pub width: usize,   // W = 2^d
    pub depth: usize,   // D = 2*d - 1 + 1 (routing + logic)
    /// Row-major: data[layer][column][bit]
    pub data: Vec<Vec<Vec<u8>>>,
    /// Switch hints from Waksman (private witness)
    pub switches: BenesNetwork,
}

impl ExecutionTrace {
    pub fn build(events: &[MatrixEvent], perm: &[usize]) -> Self { ... }
}
```

### 2.3 Constraint gates (from paper §4)

Three constraint families, each evaluating to zero on a valid trace:

1. **Switch validity:** `s * (s ⊕ 1) = 0` (s is binary)
2. **Routing correctness:** `y ⊕ a ⊕ s·(a ⊕ b) = 0` (Lemma 4.2)
3. **Logic layer:** Application-specific tie-breaking (Matrix case study)

---

## Phase 3: Binary STARK Prover (hand-rolled, no external dependency)

**Goal:** Implement the Prover-Verifier Protocol from paper §6 as a
self-contained binary STARK over the existing GF(2) trace.

**Decision:** We are **not** using Binius. The architecture is simple enough
(3 gate types, Expander LTC commitment, no FFTs) that a hand-rolled prover
is smaller, faster to ship, and avoids coupling to a pre-1.0 external API.

### 3.1 Expander Matrix

```rust
// ruma-zk-prover/src/expander.rs

/// A sparse, constant-degree Expander matrix G for LTC stretch.
/// G ∈ F₂^{n × m} with m = ρ·n (stretch factor ρ ≥ 2).
/// Each column has exactly d_G = 8 nonzero entries (XOR neighbors).
pub struct ExpanderMatrix {
    pub n: usize,        // original columns
    pub m: usize,        // stretched columns (ρ·n)
    pub degree: usize,   // d_G = 8
    /// neighbors[col] = [row indices of nonzero entries]
    pub neighbors: Vec<Vec<usize>>,
}

impl ExpanderMatrix {
    /// Deterministic construction from a seed (public parameter).
    pub fn from_seed(n: usize, stretch: usize, seed: [u8; 32]) -> Self { ... }

    /// Stretch the trace: T_ext = T · G (all XOR, O(d_G · |T|))
    pub fn stretch(&self, trace: &[Vec<u8>]) -> Vec<Vec<u8>> { ... }
}
```

### 3.2 Fiat-Shamir Transcript

```rust
// ruma-zk-prover/src/transcript.rs

/// Keccak-256 sponge transcript for Fiat-Shamir compilation.
/// Initialized with the public journal J = (da_root, state_root, h_auth, n_events).
pub struct Transcript {
    state: Keccak,
}

impl Transcript {
    pub fn new(journal: &PublicJournal) -> Self { ... }
    pub fn absorb(&mut self, data: &[u8]) { ... }
    pub fn squeeze_indices(&mut self, count: usize, modulus: usize) -> Vec<usize> { ... }
}
```

### 3.3 Proof Generation

The prover pipeline (called after `ExecutionTrace::build()`):

1. Stretch trace via Expander: `T_ext = T · G`
2. Merkle-commit the stretched columns → root `r`
3. Absorb `r` into transcript, squeeze k=843 column indices
4. For each challenged column: collect column data + Merkle path + pre-image neighbors
5. Serialize as `RawProof`

### 3.4 Verification

The verifier checks (per opened column):

1. Merkle path authenticity against root `r`
2. Stretch consistency: `T_ext[·, c_i] == XOR of T[·, j] for j ∈ N_G(c_i)`
3. Constraint satisfaction: `C_switch = 0`, `C_route = 0`, `C_logic = 0`

### 3.5 Proof Size Estimate

| Parameter             | Value       |
| --------------------- | ----------- |
| k (queries)           | 843         |
| d_G (Expander degree) | 8           |
| W (network width)     | 2^16        |
| Columns per query     | d_G + 1 = 9 |
| Merkle path depth     | ~17 hashes  |
| **Total proof size**  | **~150 KB** |

---

## Execution Order

```
Phase 1 (Waksman)  ─── no crypto dependency, pure algorithms  ✅ DONE
     │
     ▼
Phase 2 (Trace)    ─── builds on Waksman, field-agnostic       ✅ DONE
     │
     ▼
Phase 3 (Prover)   ─── hand-rolled binary STARK over the trace
```

Phases 1-2 are complete. Phase 3 has no external dependency blockers.

## Resolved Questions

1. **Binius vs roll-our-own?** → Roll our own. The circuit has 3 gate types,
   the commitment is sparse XOR matrix multiply + Merkle, and Fiat-Shamir is
   a Keccak sponge. Total new code: ~500-800 lines of Rust.
2. **Packed representation?** → Use `u64` or `u128` bitwise packing for SIMD
   throughput on the Expander stretch. No external packed-field type needed.
3. **LTC commitment:** → Our own Expander LTC, not FRI-Binius. The paper's §6
   formalizes this protocol completely.
