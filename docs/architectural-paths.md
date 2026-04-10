# Architectural Paths for ZK-Matrix-Join

We explored several paths to achieve verifiable Matrix joins. This document outlines the rationale behind our current Jolt-based architecture.

## Path A: Standard Guest Execution (Full Spec)

_Using standard Jolt RV64IMAC to execute the Ruma resolution logic directly._

- **Pros**: Direct reuse of `ruma-lean`. No custom cryptography needed.
- **Cons**: High cycle counts for massive DAGs due to $O(N \log N)$ sorting complexity.
- **Status**: Supported as `--unoptimized`. Useful for verifying smaller rooms or as a ground-truth reference.

## Path B: Jolt Coprocessor (Topological Reducer)

_Using a hybrid approach where the Host pre-computes the sort and the Guest verifies the result._

- **Pros**: $O(N)$ verification time in the VM. Leverages Jolt's efficient XOR and popcount lookups.
- **Cons**: Requires a mapping function from Event IDs to coordinates.
- **Status**: **Current Production Path**. Achieves 10x speedup over Path A.

### Implementation Details:

1.  **Host-side Sort**: The host performs the expensive Kahn's sort natively in Rust.
2.  **Topological Flattening**: The DAG is mapped to a hypercube. Each edge in the DAG must correspond to a valid path in the hypercube.
3.  **Linear Verification**: The Guest receives a list of coordinate "hops" and asserts that exactly one bit is flipped per hop. This guarantees the sequence is topologically valid.

## Path C: Pure Mathematical Prover (Plonky3)

_Bypassing the general-purpose zkVM entirely and using a custom circuit._

- **Pros**: Maximum performance. Minimal proof size.
- **Cons**: Extremely high development complexity. Hard to audit and maintain.
- **Status**: **Archived**. The Jolt (Path B) approach provides sufficient performance with much better maintainability.
