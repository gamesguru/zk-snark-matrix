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

## Phase 3: Binius Migration

**Goal:** Replace Plonky3/BabyBear with Binius binary tower fields.

### 3.1 Dependency swap

```toml
# Remove from Cargo.toml:
# p3-baby-bear, p3-air, p3-field, p3-matrix

# Add:
binius_field = "latest"
binius_core = "latest"
binius_circuits = "latest"  # if using their constraint framework
```

### 3.2 Field migration

| Component       | BabyBear (current)        | F₂ (target)                                 |
| --------------- | ------------------------- | ------------------------------------------- |
| Trace cells     | `BabyBear` (32-bit prime) | `BinaryField1b` or packed `BinaryField128b` |
| Addition        | Modular add               | XOR                                         |
| Multiplication  | Modular mul               | AND                                         |
| Extension field | `BabyBear4`               | `BinaryField128b` (for Fiat-Shamir)         |
| Commitment      | FRI over BabyBear         | Binius binary PCS (FRI-Binius)              |

### 3.3 AIR → Binius constraints

Binius uses a different constraint model than Plonky3's `Air` trait. Instead of
`AirBuilder`, Binius uses `ConstraintComposition` over multilinear polynomials.
The three constraint gates (switch validity, routing, logic) must be re-expressed
as Binius constraint compositions.

### 3.4 Risk: Binius maturity

Binius is under active development with breaking API changes. The alternative
is to implement our own minimal binary STARK:

- Merkle commit (Keccak-256) over trace columns
- Sparse Expander matrix multiply (LTC stretch) — just XORs
- Sum-check protocol over binary multilinear extensions
- Fiat-Shamir via `F_{2^128}` with CLMUL

This is feasible because our architecture is far simpler than a general zkVM.

---

## Execution Order

```
Phase 1 (Waksman)  ─── no crypto dependency, pure algorithms
     │
     ▼
Phase 2 (Trace)    ─── builds on Waksman, still field-agnostic
     │
     ▼
Phase 3 (Binius)   ─── swap the field backend under the trace
```

Phase 1 can start immediately. Phases 2-3 depend on stable Binius APIs.

## Open Questions

1. **Binius vs roll-our-own?** Binius is the only binary STARK lib but is
   pre-1.0. Our architecture is simple enough to hand-roll the binary prover
   if needed.
2. **Packed representation?** Binius supports 128-bit packed binary fields
   for SIMD. Do we pack trace cells into `BinaryField128b` for throughput?
3. **LTC commitment:** Does Binius's native PCS (FRI-Binius) replace our
   Expander LTC, or do we layer our Expander on top of Binius field ops?
