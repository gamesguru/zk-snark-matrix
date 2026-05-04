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
        ..Default::default()
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

// ── Auth-integrated STARK pipeline tests ──

use ruma_zk_prover::auth::{compute_auth, MEMBERSHIP_BAN, MEMBERSHIP_JOIN, MEMBERSHIP_NONE};
use ruma_zk_prover::stark::prove_with_auth;

#[test]
fn end_to_end_stark_with_auth() {
    // 8 events with auth witnesses: mix of authorized and unauthorized
    let n = 8;
    let perm: Vec<usize> = (0..n).rev().collect();
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    // Create auth witnesses: events 0-5 authorized, 6 insufficient PL, 7 banned
    let auth_witnesses: Vec<_> = (0..n)
        .map(|i| match i {
            6 => compute_auth(10, 50, MEMBERSHIP_JOIN), // insufficient PL
            7 => compute_auth(100, 0, MEMBERSHIP_BAN),  // banned
            _ => compute_auth(100, 0, MEMBERSHIP_JOIN), // authorized
        })
        .collect();

    // Verify auth witnesses are correct
    assert_eq!(auth_witnesses[0].authorized, GF2::ONE);
    assert_eq!(auth_witnesses[6].authorized, GF2::ZERO);
    assert_eq!(auth_witnesses[7].authorized, GF2::ZERO);

    let journal = make_journal(n as u64);
    let proof = prove_with_auth(&trace, journal, &auth_witnesses);

    // Proof should include auth columns
    assert_eq!(proof.auth_column_count, n);
    assert!(
        verify(&proof).is_ok(),
        "auth-integrated proof should verify"
    );

    // Serialize → deserialize → verify
    let bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!(
        "  [e2e] auth proof: {} bytes (~{} KB), {} auth columns",
        bytes.len(),
        bytes.len() / 1024,
        proof.auth_column_count
    );
    let deserialized: ruma_zk_prover::stark::StarkProof =
        bincode::deserialize(&bytes).expect("deserialize");
    assert!(
        verify(&deserialized).is_ok(),
        "deserialized auth proof should verify"
    );
    assert_eq!(deserialized.auth_column_count, n);
}

#[test]
fn end_to_end_stark_auth_all_membership_states() {
    let n = 4;
    let perm: Vec<usize> = (0..n).collect(); // identity
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = vec![GF2::ONE; n];
    let trace = ExecutionTrace::build(&inputs, &network);

    // One event per membership state
    let auth_witnesses = vec![
        compute_auth(50, 0, MEMBERSHIP_NONE), // not joined
        compute_auth(50, 0, MEMBERSHIP_JOIN), // authorized
        compute_auth(50, 0, 0b10),            // invited
        compute_auth(50, 0, MEMBERSHIP_BAN),  // banned
    ];

    assert_eq!(auth_witnesses[0].authorized, GF2::ZERO);
    assert_eq!(auth_witnesses[1].authorized, GF2::ONE);
    assert_eq!(auth_witnesses[2].authorized, GF2::ZERO);
    assert_eq!(auth_witnesses[3].authorized, GF2::ZERO);

    let journal = make_journal(n as u64);
    let proof = prove_with_auth(&trace, journal, &auth_witnesses);
    assert!(verify(&proof).is_ok());
}

#[test]
fn end_to_end_stark_auth_n64() {
    // Stress test: 64 events with auth
    let n = 64;
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (i * 37 + 7) % (i + 1);
        perm.swap(i, j);
    }

    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    let auth_witnesses: Vec<_> = (0..n)
        .map(|i| {
            if i % 10 == 0 {
                compute_auth(10, 50, MEMBERSHIP_JOIN) // every 10th event fails PL
            } else {
                compute_auth(100, 0, MEMBERSHIP_JOIN) // rest authorized
            }
        })
        .collect();

    let journal = make_journal(n as u64);
    let proof = prove_with_auth(&trace, journal, &auth_witnesses);
    assert_eq!(proof.auth_column_count, n);
    assert!(verify(&proof).is_ok(), "n=64 auth proof should verify");
}

// ── Federation transport tests ──

use ruma_zk_prover::transport::{build_response, decode_proof_bytes, encode_proof_bytes};

#[test]
fn end_to_end_federation_transport() {
    // Full pipeline: prove → transport encode → JSON → transport decode → verify
    let n = 8;
    let perm: Vec<usize> = (0..n).rev().collect();
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    let journal = make_journal(n as u64);
    let proof = prove(&trace, journal);

    // Build MSC-compliant response
    let response = build_response(
        &proof,
        "12",
        "sha256:test_vk_hash",
        "$cutoff:example.com",
        "example.com",
    )
    .expect("build response");

    // Serialize to JSON
    let json = serde_json::to_string(&response).expect("json serialize");
    eprintln!("  [e2e] transport JSON: {} bytes", json.len());

    // Deserialize from JSON
    let parsed: ruma_zk_prover::transport::ZkStateProofResponse =
        serde_json::from_str(&json).expect("json deserialize");
    assert_eq!(parsed.room_version, "12");
    assert_eq!(parsed.checkpoint.public_journal.n_events, n as u64);

    // Decode proof and verify
    let decoded = decode_proof_bytes(&parsed.checkpoint.zk_proof_bytes).expect("decode proof");
    assert!(verify(&decoded).is_ok(), "decoded proof should verify");
}

#[test]
fn end_to_end_proof_bytes_roundtrip() {
    let n = 8;
    let perm: Vec<usize> = (0..n).rev().collect();
    let network = BenesNetwork::from_permutation(&perm);
    let inputs: Vec<GF2> = (0..n).map(|i| GF2::new(i as u8 & 1)).collect();
    let trace = ExecutionTrace::build(&inputs, &network);

    let journal = make_journal(n as u64);
    let proof = prove(&trace, journal);

    let encoded = encode_proof_bytes(&proof).expect("encode");
    let decoded = decode_proof_bytes(&encoded).expect("decode");

    // The decoded proof should produce the same commitment root
    assert_eq!(decoded.commitment_root, proof.commitment_root);
    assert_eq!(decoded.journal.n_events, proof.journal.n_events);
    assert!(verify(&decoded).is_ok());
}

#[test]
fn end_to_end_recursive_proof() {
    use ruma_zk_prover::stark::{prove_recursive, PublicJournal};

    // Create two independent sub-proofs (simulating MapReduce shards)
    let make_sub_proof = |n: usize, seed: u8| {
        let perm: Vec<usize> = (0..n).rev().collect();
        let network = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<GF2> = (0..n).map(|i| GF2::new((i as u8 + seed) & 1)).collect();
        let trace = ExecutionTrace::build(&inputs, &network);

        let journal = PublicJournal {
            da_root: [seed; 32],
            state_root: [seed + 1; 32],
            h_auth: [seed + 2; 32],
            n_events: n as u64,
            ..Default::default()
        };

        prove(&trace, journal)
    };

    let sub_proof_1 = make_sub_proof(8, 0xAA);
    let sub_proof_2 = make_sub_proof(8, 0xBB);

    // Verify sub-proofs individually
    assert!(verify(&sub_proof_1).is_ok(), "sub-proof 1 should verify");
    assert!(verify(&sub_proof_2).is_ok(), "sub-proof 2 should verify");

    // Create the parent trace (aggregator's own routing)
    let parent_perm: Vec<usize> = (0..8).rev().collect();
    let parent_network = BenesNetwork::from_permutation(&parent_perm);
    let parent_inputs: Vec<GF2> = (0..8).map(|i| GF2::new(i as u8 & 1)).collect();
    let parent_trace = ExecutionTrace::build(&parent_inputs, &parent_network);

    let parent_journal = PublicJournal {
        da_root: [0xCC; 32],
        state_root: [0xDD; 32],
        h_auth: [0xEE; 32],
        n_events: 16, // 8 + 8 events aggregated
        ..Default::default()
    };

    // Generate recursive proof
    let (recursive_proof, parent_hashes) = prove_recursive(
        &parent_trace,
        parent_journal,
        &[], // no auth witnesses for this test
        &[sub_proof_1.clone(), sub_proof_2.clone()],
    );

    // Verify the recursive proof passes standard verification
    assert!(
        verify(&recursive_proof).is_ok(),
        "recursive proof should verify"
    );

    // Verify parent_hashes were correctly derived
    assert_eq!(parent_hashes.len(), 2, "should have 2 parent proof hashes");
    assert_ne!(
        parent_hashes[0], parent_hashes[1],
        "different sub-proofs should produce different hashes"
    );

    // Verify the recursive proof has more columns than a non-recursive one
    let non_recursive = prove(
        &parent_trace,
        PublicJournal {
            da_root: [0xCC; 32],
            state_root: [0xDD; 32],
            h_auth: [0xEE; 32],
            n_events: 16,
            ..Default::default()
        },
    );
    assert!(
        recursive_proof.original_columns > non_recursive.original_columns,
        "recursive proof should have more columns ({} vs {})",
        recursive_proof.original_columns,
        non_recursive.original_columns
    );

    eprintln!(
        "  [e2e] recursive: {} columns (vs {} non-recursive), {} parent_hashes",
        recursive_proof.original_columns,
        non_recursive.original_columns,
        parent_hashes.len()
    );
}
