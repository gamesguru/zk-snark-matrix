# ZK-Matrix-Join: Trustless Matrix Light Clients

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](#) [![SP1 zkVM](https://img.shields.io/badge/sp1-zkVM-blue.svg)](#) [![Status](https://img.shields.io/badge/status-experimental_AF-red.svg)](#)

A Layer-2 Zero-Knowledge scaling solution for the Matrix protocol.

We're replacing slow **Full Joins** and insecure **Partial Joins** with instant, cryptographically secure **ZK-Joins**.

## The Problem

Joining a massive Matrix room (like `#matrix:matrix.org`) sucks. You either:

1. **Download the universe (Full Join):** Crunch hundreds of thousands of events from genesis. Kills your RAM, CPU, and takes forever.
2. **YOLO it (MSC3902):** Blindly trust the remote server's state so you can chat now, verifying gigabytes in the background. A huge compromise on decentralization.

## The Solution: Math > Computation

`zk-matrix-join` moves Matrix state resolution into a Zero-Knowledge architecture.

A beefy prover node crunches the heavy State Res v2 logic inside a Gen-Purpose **zkVM** (SP1). It generates a succinct STARK proof proving the state conforms perfectly to protocol rules.

Instead of downloading 50MB of Auth Chain and verifying 500k signatures, servers (and browser light clients) just download the 2MB state and a tiny 250KB proof. They verify it in **milliseconds**.

Instant, 100% trustless joins.

## Architecture

Built on the **SP1 RISC-V zkVM**, allowing native Rust libraries (`ruma-state-res`) to run in ZK.

- **`src/host/` (The Prover):** Orchestrates state res, pre-sorts DAG branches, and builds linear "Hints" for the guest. Compresses the SP1 STARK into a tiny Groth16 SNARK.
- **`src/guest/` (The zkVM):** Linearly verifies the Host's Hints in $O(N)$ time (avoiding expensive $O(N \log N)$ sorting in the VM) using optimized memory hashing.
- **`src/wasm-client/` (The Verifier):** Exposes SNARK verification to pure JavaScript via WebAssembly, clocking <15ms verification times in the browser.

## Get Started

Highly experimental. We're using the SP1 Prover paired with Verifiable Computation to scale Matrix topology resolution to 1,000,000+ events.

To run the simulated validations natively in Rust (without burning CPU on full SNARK generation):

```bash
cargo test
```

## License

Dual-licensed under MIT or Apache 2.0.
