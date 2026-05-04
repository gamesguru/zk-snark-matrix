//! Recursive STARK verifier circuit.
//!
//! Implements the STARK verifier as a GF(2) constraint system, enabling
//! proof-of-verification. A recursive proof attests: "I correctly verified
//! sub-proof π and it was valid."
//!
//! This is the foundation for the MapReduce recursive proving architecture
//! described in MSC0000 §Recursive MapReduce Proving.
//!
//! ## Architecture
//!
//! The recursive verifier replays the `verify()` function but records all
//! intermediate values as constraint witnesses. The constraint system then
//! enforces that each step was computed correctly:
//!
//! 1. **Transcript replay**: Keccak sponge produces deterministic challenge indices
//! 2. **Merkle verification**: Keccak hash chain authenticates opened columns
//! 3. **Stretch consistency**: XOR accumulation matches stretched columns
//! 4. **Binary validation**: All trace bytes are 0 or 1

use crate::expander::DEFAULT_STRETCH;
use crate::keccak_circuit::{
    keccak256_circuit, verify_keccak_constraints, KeccakWitness, STATE_LANES,
};
use crate::merkle::keccak256;
use crate::stark::{StarkProof, SOUNDNESS_QUERIES};
use ruma_zk_topological_air::field::GF2;

/// Witness for recursive verification of a sub-proof.
#[derive(Clone)]
pub struct RecursiveVerifierWitness {
    /// The sub-proof being verified (private witness).
    pub sub_proof: StarkProof,

    /// Keccak witnesses for the Fiat-Shamir transcript computation.
    /// One witness per transcript hash invocation.
    pub transcript_witnesses: Vec<KeccakWitness>,

    /// Keccak witnesses for Merkle path verification.
    /// One witness chain per Merkle hash in the opened paths.
    pub merkle_witnesses: Vec<KeccakWitness>,

    /// Challenge indices derived from the transcript (public for constraint checking).
    pub challenge_indices: Vec<usize>,

    /// XOR consistency: for each query, the recomputed stretched column.
    pub recomputed_columns: Vec<Vec<u8>>,

    /// Per-query binary validation results.
    pub binary_checks: Vec<bool>,

    /// Final verification result: ONE if the sub-proof is valid.
    pub is_valid: GF2,

    /// Hash of the sub-proof's public journal (for parent_proofs binding).
    pub sub_proof_hash: [u8; 32],
}

/// Compute the recursive verifier witness by "running" verify() and recording
/// all intermediate Keccak computations.
///
/// This does NOT prove anything yet — it produces the witness data that will
/// be committed as additional columns in the parent proof.
pub fn recursive_verify_witness(sub_proof: &StarkProof) -> RecursiveVerifierWitness {
    let mut transcript_witnesses = Vec::new();
    let mut merkle_witnesses = Vec::new();
    let mut is_valid = true;

    // ── Step 1: Replay Fiat-Shamir transcript ──
    // Build the transcript input bytes (same as Transcript::new + absorb)
    let mut transcript_input = Vec::new();
    transcript_input.extend_from_slice(b"graph-native-stark-v1");
    transcript_input.extend_from_slice(&sub_proof.journal.da_root);
    transcript_input.extend_from_slice(&sub_proof.journal.state_root);
    transcript_input.extend_from_slice(&sub_proof.journal.h_auth);
    transcript_input.extend_from_slice(&sub_proof.journal.n_events.to_le_bytes());
    transcript_input.extend_from_slice(&sub_proof.commitment_root);

    // Derive challenge indices using Keccak circuit
    let n = sub_proof.original_columns;
    let m = n * DEFAULT_STRETCH;
    let mut state = transcript_input.clone();
    let mut challenge_indices = Vec::with_capacity(SOUNDNESS_QUERIES);

    for i in 0..SOUNDNESS_QUERIES {
        let mut hash_input = state.clone();
        hash_input.extend_from_slice(&(i as u64).to_le_bytes());

        let (hash, witnesses) = keccak256_circuit(&hash_input);
        transcript_witnesses.extend(witnesses);

        // u128 from first 16 bytes, mod m
        let val_bytes: [u8; 16] = hash[0..16].try_into().unwrap();
        let val = u128::from_le_bytes(val_bytes);
        challenge_indices.push((val % m as u128) as usize);

        // Chain state
        state = hash.to_vec();
    }

    // ── Step 2: Verify Merkle paths ──
    for (query_idx, &col_idx) in challenge_indices.iter().enumerate() {
        if query_idx >= sub_proof.stretched_openings.len() {
            is_valid = false;
            break;
        }

        let opening = &sub_proof.stretched_openings[query_idx];

        // Check column index
        if opening.column_index != col_idx {
            is_valid = false;
        }

        // Verify Merkle path using GF(2) Keccak
        let (leaf_hash, leaf_witnesses) = keccak256_circuit(&opening.data);
        merkle_witnesses.extend(leaf_witnesses);

        let mut current = leaf_hash;
        let mut idx = col_idx;

        for sibling in &opening.merkle_path {
            let mut concat = Vec::with_capacity(64);
            if idx % 2 == 0 {
                concat.extend_from_slice(&current);
                concat.extend_from_slice(sibling);
            } else {
                concat.extend_from_slice(sibling);
                concat.extend_from_slice(&current);
            }

            let (parent_hash, parent_witnesses) = keccak256_circuit(&concat);
            merkle_witnesses.extend(parent_witnesses);
            current = parent_hash;
            idx /= 2;
        }

        if current != sub_proof.commitment_root {
            is_valid = false;
        }
    }

    // ── Step 3: XOR consistency ──
    let mut recomputed_columns = Vec::new();
    for (query_idx, _) in challenge_indices.iter().enumerate() {
        if query_idx >= sub_proof.stretched_openings.len() {
            break;
        }

        let stretched = &sub_proof.stretched_openings[query_idx];
        let rows = stretched.data.len();
        let mut recomputed = vec![0u8; rows];

        for d in 0..sub_proof.expander_degree {
            let preimage_idx = query_idx * sub_proof.expander_degree + d;
            if preimage_idx < sub_proof.preimage_openings.len() {
                let preimage = &sub_proof.preimage_openings[preimage_idx];
                for (dst, &src) in recomputed.iter_mut().zip(preimage.data.iter()) {
                    *dst ^= src;
                }
            }
        }

        if recomputed != stretched.data {
            is_valid = false;
        }
        recomputed_columns.push(recomputed);
    }

    // ── Step 4: Binary validation ──
    let mut binary_checks = Vec::new();
    for (query_idx, _) in challenge_indices.iter().enumerate() {
        let mut ok = true;
        for d in 0..sub_proof.expander_degree {
            let preimage_idx = query_idx * sub_proof.expander_degree + d;
            if preimage_idx < sub_proof.preimage_openings.len() {
                for &byte in &sub_proof.preimage_openings[preimage_idx].data {
                    if byte > 1 {
                        ok = false;
                    }
                }
            }
        }
        binary_checks.push(ok);
    }

    // ── Compute sub-proof hash for parent_proofs binding ──
    let journal_bytes = [
        sub_proof.journal.da_root.as_slice(),
        sub_proof.journal.state_root.as_slice(),
        sub_proof.journal.h_auth.as_slice(),
        &sub_proof.journal.n_events.to_le_bytes(),
    ]
    .concat();
    let sub_proof_hash = keccak256(&journal_bytes);

    RecursiveVerifierWitness {
        sub_proof: sub_proof.clone(),
        transcript_witnesses,
        merkle_witnesses,
        challenge_indices,
        recomputed_columns,
        binary_checks,
        is_valid: if is_valid { GF2::ONE } else { GF2::ZERO },
        sub_proof_hash,
    }
}

/// Verify all constraints in the recursive verifier witness.
///
/// Returns the total number of constraint violations:
/// - Keccak constraint violations (transcript + Merkle hashes)
/// - XOR consistency violations
/// - Binary validation violations
pub fn verify_recursive_constraints(witness: &RecursiveVerifierWitness) -> usize {
    let mut violations = 0;

    // Check all Keccak constraints (transcript)
    violations += verify_keccak_constraints(&witness.transcript_witnesses);

    // Check all Keccak constraints (Merkle paths)
    violations += verify_keccak_constraints(&witness.merkle_witnesses);

    // Check XOR consistency
    for (query_idx, recomputed) in witness.recomputed_columns.iter().enumerate() {
        if query_idx < witness.sub_proof.stretched_openings.len()
            && *recomputed != witness.sub_proof.stretched_openings[query_idx].data
        {
            violations += 1;
        }
    }

    // Check binary validation
    for &ok in &witness.binary_checks {
        if !ok {
            violations += 1;
        }
    }

    violations
}

/// Serialize the recursive verifier witness into column bytes for trace embedding.
///
/// Returns one column per Keccak round witness (the χ intermediate states),
/// plus one column for the verification result flag.
pub fn recursive_witness_to_columns(witness: &RecursiveVerifierWitness) -> Vec<Vec<u8>> {
    let mut columns = Vec::new();

    // Emit all transcript Keccak witnesses as columns (packed lane bytes)
    for kw in &witness.transcript_witnesses {
        for round in &kw.rounds {
            let mut col = Vec::with_capacity(STATE_LANES * 8);
            for &lane in &round.after_chi.lanes {
                col.extend_from_slice(&lane.to_le_bytes());
            }
            columns.push(col);
        }
    }

    // Emit all Merkle Keccak witnesses as columns
    for kw in &witness.merkle_witnesses {
        for round in &kw.rounds {
            let mut col = Vec::with_capacity(STATE_LANES * 8);
            for &lane in &round.after_chi.lanes {
                col.extend_from_slice(&lane.to_le_bytes());
            }
            columns.push(col);
        }
    }

    // Final column: verification result
    columns.push(vec![witness.is_valid.val()]);

    columns
}

/// Compute the total number of GF(2) constraints for recursive verification.
pub fn recursive_constraint_count(witness: &RecursiveVerifierWitness) -> usize {
    let transcript_rounds: usize = witness
        .transcript_witnesses
        .iter()
        .map(|kw| kw.rounds.len())
        .sum();
    let merkle_rounds: usize = witness
        .merkle_witnesses
        .iter()
        .map(|kw| kw.rounds.len())
        .sum();

    // 1600 χ constraints per round
    let keccak_constraints = (transcript_rounds + merkle_rounds) * 1600;

    // XOR + binary constraints are degree-1 (trivially satisfied), but counted
    let xor_constraints = witness.recomputed_columns.len();
    let binary_constraints = witness.binary_checks.len();

    keccak_constraints + xor_constraints + binary_constraints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GF2 as FieldGF2;
    use crate::stark::{prove, PublicJournal};
    use crate::trace::ExecutionTrace;
    use crate::waksman::BenesNetwork;

    fn make_proof(n: usize) -> StarkProof {
        let perm: Vec<usize> = (0..n).rev().collect();
        let network = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<FieldGF2> = (0..n).map(|i| FieldGF2::new(i as u8 & 1)).collect();
        let trace = ExecutionTrace::build(&inputs, &network);

        let journal = PublicJournal {
            da_root: keccak256(b"test-da"),
            state_root: keccak256(b"test-state"),
            h_auth: keccak256(b"test-auth"),
            n_events: n as u64,
        };

        prove(&trace, journal)
    }

    #[test]
    fn test_recursive_verify_valid() {
        let proof = make_proof(8);

        // Standard verification should pass
        assert!(crate::stark::verify(&proof).is_ok());

        // Recursive verification should produce a valid witness
        let witness = recursive_verify_witness(&proof);
        assert_eq!(witness.is_valid, GF2::ONE);
        assert_eq!(verify_recursive_constraints(&witness), 0);

        let constraint_count = recursive_constraint_count(&witness);
        eprintln!(
            "  [recursive] n=8: {} total constraints, {} transcript Keccak witnesses, {} Merkle Keccak witnesses",
            constraint_count,
            witness.transcript_witnesses.len(),
            witness.merkle_witnesses.len()
        );
    }

    #[test]
    fn test_recursive_constraint_count() {
        let proof = make_proof(8);
        let witness = recursive_verify_witness(&proof);
        let count = recursive_constraint_count(&witness);
        // Should be dominated by Keccak constraints (>10K)
        assert!(count > 10_000, "expected >10K constraints, got {}", count);
        eprintln!("  [recursive] constraint count: {}", count);
    }

    #[test]
    fn test_recursive_witness_columns() {
        let proof = make_proof(8);
        let witness = recursive_verify_witness(&proof);
        let columns = recursive_witness_to_columns(&witness);

        // Should have columns from all Keccak rounds + 1 result column
        assert!(!columns.is_empty());
        // Last column is the verification result
        assert_eq!(columns.last().unwrap(), &[1u8]); // is_valid = ONE
    }

    #[test]
    fn test_recursive_sub_proof_hash() {
        let proof = make_proof(8);
        let witness = recursive_verify_witness(&proof);

        // Sub-proof hash should be deterministic
        let journal_bytes = [
            proof.journal.da_root.as_slice(),
            proof.journal.state_root.as_slice(),
            proof.journal.h_auth.as_slice(),
            &proof.journal.n_events.to_le_bytes(),
        ]
        .concat();
        let expected_hash = keccak256(&journal_bytes);
        assert_eq!(witness.sub_proof_hash, expected_hash);
    }
}
