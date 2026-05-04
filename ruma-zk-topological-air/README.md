# ruma-zk-topological-air

The "Coprocessor" chip for the Matrix State Resolution ZK-SNARK.

## Overview

This crate implements the **Star Graph ($S_n$)** topology and the factoradic indexing required for $O(N)$ trace compilation. It transforms a set of Matrix events into a verified topological trace that can then be proven.

## Key Components

- **StarGraph**: Optimized permutation graph for transition verification.
- **Factoradic Indexing**: Zero-allocation state mapping.
- **Topological Constraint**: The specific AIR logic for Matrix State Res v2.1.
