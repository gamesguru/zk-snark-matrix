# ruma-zk-prover

High-level SDK and CLI for generating trustless proofs of Matrix State Resolution.

## Architecture

The prover implements a **Graph-Native STARK** operating over binary fields (GF(2)):

```
Events (DAG) → Topological Sort → Beneš Routing Network → Execution Trace → STARK Proof
                                                                ↑
                                                    Auth Witnesses (§11 power levels)
                                                    Recursive Sub-Proofs (Keccak circuit)
```

### Modules

| Module              | Purpose                                                                    |
| ------------------- | -------------------------------------------------------------------------- |
| `stark.rs`          | Core prover/verifier: `prove()`, `prove_recursive()`, `verify()`           |
| `recursive.rs`      | Recursive STARK-in-STARK composition via Keccak-f[1600] circuit            |
| `keccak_circuit.rs` | Keccak-256 with packed u64 lanes (25 ops/round) and χ constraint witnesses |
| `trace.rs`          | Execution trace builder from Beneš switch settings                         |
| `expander.rs`       | XOR-stretch expander graph for proximity amplification                     |
| `merkle.rs`         | Keccak-256 Merkle tree for column commitment                               |
| `transcript.rs`     | Fiat-Shamir transcript (Keccak sponge)                                     |
| `transport.rs`      | Federation JSON serialization / base64 proof encoding                      |
| `auth.rs`           | §11 Matrix auth constraint witnesses (power levels, membership)            |
| `waksman.rs`        | Waksman/Beneš permutation network                                          |
| `pdu.rs`            | Matrix PDU → auth witness extraction                                       |

## Usage

```bash
cargo run -p ruma-zk-prover -- demo --limit 1000
```

## Test Coverage

- **69 unit tests** covering all modules
- **12 end-to-end tests** including recursive proof composition
- **0 clippy warnings**

```bash
make test           # full suite: 176 tests (~30s debug)
cargo test --release  # optimized (~5s)
```

## Key Design Decisions

- **Keccak-256** for all hashing: native GF(2) sponge construction, ~25 u64 ops per round
- **Packed u64 lanes**: Keccak state = 25 × u64 (200 bytes), not 1600 × u8
- **Compact recursive witnesses**: all Keccak round witnesses hashed into 2 × 32-byte commitments per sub-proof (not ~100K individual columns)
- **Framework-portable**: public journal format is hash-function-agnostic; any STARK/SNARK backend (Binius, Plonky3, etc.) can verify the same proofs
