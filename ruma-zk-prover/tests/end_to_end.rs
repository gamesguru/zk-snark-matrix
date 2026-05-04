//! End-to-end integration test: Matrix events → witness generation → constraint verification.

use ruma_zk_prover::field::GF2;
use ruma_zk_prover::trace::ExecutionTrace;
use ruma_zk_prover::waksman::BenesNetwork;

/// Simulate a DAG dependency permutation for N events.
/// In production, Kahn's topological sort produces this permutation.
/// Here we use a fixed permutation representing a plausible re-ordering.
fn mock_topological_permutation(n: usize) -> Vec<usize> {
    assert!(n.is_power_of_two());
    // Reverse order: simulates a DAG where later events depend on earlier ones
    (0..n).rev().collect()
}

#[test]
fn end_to_end_small() {
    // 4 Matrix events
    let n = 4;
    let perm = mock_topological_permutation(n);

    // Waksman: compute Beneš switch settings
    let network = BenesNetwork::from_permutation(&perm);
    assert_eq!(network.n, 4);
    assert_eq!(network.switches.len(), 3); // 2*2 - 1

    // Trace: embed switch hints into GF(2) grid
    // Each event is represented as a 1-bit "active" flag
    let inputs: Vec<GF2> = vec![GF2::ONE; n];
    let trace = ExecutionTrace::build(&inputs, &network);

    // Verify all constraints
    assert_eq!(
        trace.verify_constraints(),
        0,
        "routing constraints violated"
    );

    // Verify routing correctness: route the indices through the network
    let indices: Vec<usize> = (0..n).collect();
    let routed = network.route(&indices);
    for (i, &p) in perm.iter().enumerate() {
        assert_eq!(routed[p], i, "routing mismatch at position {p}");
    }
}

#[test]
fn end_to_end_with_padding() {
    // 5 real events → padded to 8
    let n_real: usize = 5;
    let n_padded = n_real.next_power_of_two(); // 8

    // Permutation: cycle the first 5, identity on padding
    let mut perm: Vec<usize> = (0..n_padded).collect();
    // Rotate first 5: [1, 2, 3, 4, 0, 5, 6, 7]
    for (i, val) in perm.iter_mut().enumerate().take(n_real) {
        *val = (i + 1) % n_real;
    }

    let network = BenesNetwork::from_permutation(&perm);

    // Active bits for real events, zero for padding
    let inputs: Vec<GF2> = (0..n_padded)
        .map(|i| if i < n_real { GF2::ONE } else { GF2::ZERO })
        .collect();

    let trace = ExecutionTrace::build(&inputs, &network);
    assert_eq!(trace.verify_constraints(), 0);
    assert_eq!(trace.routing_depth, 5); // 2*3 - 1
    assert_eq!(trace.num_constraints(), 4 * 5); // 4 switches × 5 layers
}

#[test]
fn end_to_end_n1024() {
    // Stress test: 1024 events with a deterministic pseudo-random permutation
    let n = 1024;
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (i * 37 + 7) % (i + 1);
        perm.swap(i, j);
    }

    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    assert_eq!(trace.verify_constraints(), 0);
    assert_eq!(trace.width, 1024);
    assert_eq!(trace.routing_depth, 19); // 2*10 - 1

    // Verify routing
    let indices: Vec<usize> = (0..n).collect();
    let routed = network.route(&indices);
    for (i, &p) in perm.iter().enumerate() {
        assert_eq!(routed[p], i);
    }
}

// ── Full STARK pipeline tests (prove → serialize → verify) ──

use ruma_zk_prover::stark::{prove, verify, PublicJournal, SOUNDNESS_QUERIES};

fn make_journal(n: u64) -> PublicJournal {
    use ruma_zk_prover::merkle::keccak256;
    PublicJournal {
        da_root: keccak256(b"test-da-root"),
        state_root: keccak256(b"test-state-root"),
        h_auth: keccak256(b"test-h-auth"),
        n_events: n,
    }
}

#[test]
fn end_to_end_stark_small() {
    // 8 events, reversal permutation → full proof pipeline
    let n = 8;
    let perm: Vec<usize> = (0..n).rev().collect();
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    assert_eq!(trace.verify_constraints(), 0);

    let journal = make_journal(n as u64);
    let proof = prove(&trace, journal);

    // Verify
    assert!(verify(&proof).is_ok(), "proof should verify");

    // Serialize → deserialize roundtrip
    let bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!("  [e2e] proof serialized: {} bytes", bytes.len());
    let deserialized: ruma_zk_prover::stark::StarkProof =
        bincode::deserialize(&bytes).expect("deserialize");
    assert!(
        verify(&deserialized).is_ok(),
        "deserialized proof should verify"
    );
}

#[test]
fn end_to_end_stark_n64() {
    // 64 events, pseudo-random permutation
    let n = 64;
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (i * 37 + 7) % (i + 1);
        perm.swap(i, j);
    }

    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    assert_eq!(trace.verify_constraints(), 0);

    let journal = make_journal(n as u64);
    let proof = prove(&trace, journal);

    assert_eq!(proof.stretched_openings.len(), SOUNDNESS_QUERIES);
    assert!(verify(&proof).is_ok(), "n=64 proof should verify");

    // Serialized proof size
    let bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!(
        "  [e2e] n={}: proof {} bytes (~{} KB), degree={}",
        n,
        bytes.len(),
        bytes.len() / 1024,
        proof.expander_degree
    );
}

#[test]
fn end_to_end_stark_tamper_detection() {
    let n = 8;
    let perm: Vec<usize> = (0..n).rev().collect();
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    let journal = make_journal(n as u64);
    let proof = prove(&trace, journal);

    // Serialize, tamper, deserialize, verify should fail
    let mut bytes = bincode::serialize(&proof).expect("serialize");
    // Flip a byte deep in the proof data
    if bytes.len() > 200 {
        bytes[200] ^= 0xFF;
    }
    let tampered: Result<ruma_zk_prover::stark::StarkProof, _> = bincode::deserialize(&bytes);
    if let Ok(p) = tampered {
        // If deserialization still succeeds, verification should catch it
        assert!(
            verify(&p).is_err(),
            "tampered proof should fail verification"
        );
    }
    // If deserialization fails, that's also fine — the tamper was caught
}
