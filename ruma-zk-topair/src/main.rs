use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use ruma_zk_topair::{StarGraph, STATE_WIDTH};
use std::collections::HashSet;
use std::time::Instant;

fn main() {
    #[cfg(debug_assertions)]
    println!("!!! WARNING: Running in DEBUG mode. Benchmarks will be 100x slower. Use 'make bench' or '--release' !!!");

    println!("--- CTopology: Benchmark & Proof Generation (Parallel Optimized) ---");

    // Benchmark Target: n=10 (3,628,800 nodes)
    let n = 10;
    let mut g = StarGraph::new(n);
    let total_nodes = g.nodes.len();
    println!(
        "Initialized S_{} with {} nodes (~{} MB RAM)",
        n,
        total_nodes,
        (total_nodes * STATE_WIDTH * 4) / 1024 / 1024
    );

    let matrix_constraint = |state: [BabyBear; STATE_WIDTH],
                             neighbors: &[[BabyBear; STATE_WIDTH]]| {
        if state[0] == BabyBear::new(0) {
            return BabyBear::new(0);
        }
        if state[1] == BabyBear::new(0) {
            return state[3] - BabyBear::new(100);
        }
        let p1_idx = state[1].as_canonical_u32() as usize;
        let p1_val = neighbors[p1_idx - 1][3];
        state[3] - p1_val // Honest PL carry-over
    };

    // 1. Prover: Compile Trace
    println!("Compiling Trace...");
    let start_comp = Instant::now();
    let mut current_idx = 0;
    let mut visited = HashSet::new();
    visited.insert(current_idx);
    g.nodes[current_idx] = [
        BabyBear::new(1),
        BabyBear::new(0),
        BabyBear::new(0),
        BabyBear::new(100),
        BabyBear::new(0),
    ];

    let mut steps = 1;
    for _ in 1..total_nodes {
        let mut moved = false;
        for edge_idx in 1..n {
            let next_idx = g.get_neighbor_index(current_idx, edge_idx);
            if !visited.contains(&next_idx) {
                g.nodes[next_idx] = [
                    BabyBear::new(1),
                    BabyBear::new(edge_idx as u32),
                    BabyBear::new(0),
                    BabyBear::new(100),
                    BabyBear::new(1),
                ];
                visited.insert(next_idx);
                current_idx = next_idx;
                steps += 1;
                moved = true;
                break;
            }
        }
        if !moved {
            break;
        }
    }
    println!("  - Compiled {} steps in {:?}", steps, start_comp.elapsed());

    // 2. Global Parallel Verification
    println!("Verifying Entire Topology (Parallel)...");
    let start_verify = Instant::now();
    let all_consistent = g.verify_entire_topology(matrix_constraint);
    println!(
        "  - Verified in {:?} (Result: {})",
        start_verify.elapsed(),
        all_consistent
    );

    // 3. Raw Proof Generation (k=1730)
    let k = 1730;
    println!(
        "Generating Raw Proof (k={} random queries, Parallel Optimized)...",
        k
    );
    let start_proof = Instant::now();
    let proof = g.prove(k);
    let proof_time = start_proof.elapsed();

    // Estimate size
    let proof_bytes = bincode::serialize(&proof).unwrap_or_default().len();
    println!("  - Proof Generated in {:?}", proof_time);
    println!(
        "  - Proof Size: {:.2} MB",
        proof_bytes as f64 / 1024.0 / 1024.0
    );
    println!("  - Merkle Root: {}", hex::encode(proof.root));

    // 4. Verifier
    println!("Verifier: Checking k openings...");
    let start_verif_proof = Instant::now();
    let mut success = true;
    for opening in &proof.openings {
        if !proof.verify_opening(opening) {
            success = false;
            break;
        }
    }
    println!(
        "  - Verifier completed in {:?} (Result: {})",
        start_verif_proof.elapsed(),
        success
    );

    if all_consistent && success {
        println!("FINAL STATUS: O(N) Benchmark Successful. Proof Valid.");
    }
}
