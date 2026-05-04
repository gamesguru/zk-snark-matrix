# ruma-zk-verifier

Universal, lightweight verifier for Matrix State Resolution proofs.

## Features

- **Dual-Build**: Compiles to standard Rust (for servers/nodes) and WebAssembly (for browsers).
- **Lightweight**: Stripped of heavy prover logic; only ~25KB when compiled to WASM.
- **Fast**: Typical verification takes <20ms on modern hardware.

## WASM Support

```bash
make wasm
```

Exposes `verify_matrix_proof` and `timed_verify` to JavaScript via `wasm-bindgen`.
