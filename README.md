# ZK-Matrix-Join: Trustless Matrix Light Clients

[![CI](https://github.com/gamesguru/ruma-zk/actions/workflows/ci.yml/badge.svg)](https://github.com/gamesguru/ruma-zk/actions/workflows/ci.yml) [![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](#) [![Jolt zkVM](https://img.shields.io/badge/jolt-zkVM-purple.svg)](#) [![Status](https://img.shields.io/badge/status-experimental_AF-red.svg)](#)

A Layer-2 Zero-Knowledge scaling solution for the Matrix protocol powered by **a16z's Jolt VM**.

We're replacing slow **Full Joins** and insecure **Partial Joins** with instant, cryptographically secure **ZK-Joins**.

## The Problem

Joining a massive Matrix room (like `#matrix:matrix.org`) sucks. You either:

1. **Download the universe (Full Join):** Crunch hundreds of thousands of events from genesis. Kills your RAM, CPU, and takes forever.
2. **YOLO it (MSC3902):** Blindly trust the remote server's state so you can chat now, verifying gigabytes in the background. A huge compromise on decentralization.

## The Solution: Math > Computation

`zk-matrix-join` moves Matrix state resolution into a Zero-Knowledge architecture.

A beefy prover node crunches the heavy State Res v2 logic inside the **Jolt zkVM**. Jolt utilizes the **Lasso** lookup argument and **Sumcheck protocol** to generate proofs that are significantly faster and "leaner" than traditional arithmetization-based zkVMs.

Instead of downloading 50MB of Auth Chain and verifying 500k signatures, servers (and browser light clients) just download the 2MB state and a tiny STARK proof. They verify it in **milliseconds**.

## Architecture

```mermaid
graph TD
    subgraph Epoch Rollup Phase
        Events[(Raw DAG Events)] --> |Sent periodically| Prover[ZK Prover Node<br/>GPU Cluster]
        Prover --> |"Lasso + Sumcheck<br/>Generates STARK"| Jolt((Jolt zkVM))
        Jolt --> |Returns Receipt| Res[Resident Matrix Server]
    end

    subgraph Case 1: Server Joining Room
        Join[Joining Homeserver] --> |"GET /zk_state_proof"| Res
        Res --> |"1. Checkpoint Proof<br/>2. Unproven Event Delta"| Join
        Join -.-> |"Verifies Proof in 10ms<br/>Resolves Delta Natively"| State1((Trustless<br/>Room State))
    end

    subgraph Case 2: Client Edge-Verification
        Client[Mobile/Web Client<br/>Element] --> |"GET /zk_state_proof"| Res
        Res --> |"Passes Proof Down"| Client
        Client -.-> |"WASM Verifies Proof<br/>No Server Trust Needed!"| State2((Trustless<br/>Room State))
    end

    classDef server fill:#4183C4,stroke:#333,stroke-width:2px,color:#fff;
    classDef prover fill:#800080,stroke:#333,stroke-width:2px,color:#fff;
    classDef client fill:#E24329,stroke:#333,stroke-width:2px,color:#fff;
    classDef state fill:#4CAF50,stroke:#333,stroke-width:2px,color:#fff;

    class Res,Join server;
    class Prover,Jolt prover;
    class Client client;
    class State1,State2 state;
```

Built on **Jolt RV64IMAC**, allowing formally verified Rust libraries (`ruma-lean`) to run in ZK.

- **`ruma-zk` (The Prover):** Root-level facade that orchestrates state res and parallelizes the Jolt Prover.
- **`ruma_zk_guest/` (The zkVM):** Formally verified logic that runs inside Jolt, proving topological compliance and state transitions.
- **`ruma-zk-wasm/` (The Verifier):** Exposes proof verification to WebAssembly.

## CLI Usage

The primary interface is the `ruma-zk` binary.

```bash
cargo run --release --bin ruma-zk -- [COMMAND]
```

### Commands:

- **`demo`**: Run a fast end-to-end simulation.
  ```bash
  ruma-zk demo -i res/benchmark_1k.json
  ```
- **`prove`**: Generate a full cryptographic proof.
  ```bash
  ruma-zk prove -i res/benchmark_1k.json --compression groth16
  ```
- **`verify`**: Verify an existing STARK/SNARK proof.
  ```bash
  ruma-zk verify --proof-path proof.bin
  ```

### Options:

- `-i, --input <PATH>`: Path to the Matrix state JSON fixture.
- `-l, --limit <N>`: Limit the number of events processed (default: 1000, max: 2^24).
- `-u, --unoptimized`: Run the full Matrix Spec State Res v2 instead of the Optimized Topological Reducer.
- `-c, --compression <LEVEL>`: Proof compression (uncompressed, intermediate, groth16).
- `--trace`: Enable cycle-accurate trace analysis during simulation (Warning: High CPU/RAM).

## Security & Memory Safety

To cryptographically neutralize VM-level exploits, **the entire workspace (Guest, Host, and WASM Verifier)** strictly bans `unsafe` Rust via the `#![forbid(unsafe_code)]` compiler directive. All resolution logic is offloaded to `ruma-lean`, a zero-dependency crate designed for formal verification.

## Development

### Code Coverage

To generate a code coverage report:

```bash
make coverage
```

### Parity Testing

To run the Jolt parity simulation (comparing native Rust vs. proven Guest):

```bash
make test-zk
```

## License

Dual-licensed under MIT or Apache 2.0.
