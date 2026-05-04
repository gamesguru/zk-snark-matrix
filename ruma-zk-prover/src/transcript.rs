//! Fiat-Shamir transcript for non-interactive proof compilation.
//!
//! The transcript is a Keccak-256 sponge that absorbs commitments
//! and squeezes pseudorandom challenges.  It is initialized with
//! the public journal to bind the proof to a specific computation.

use tiny_keccak::{Hasher, Keccak};

/// A Keccak-256 sponge transcript for Fiat-Shamir compilation.
///
/// Usage:
/// 1. Initialize with the public journal (binds proof to instance)
/// 2. Absorb the Merkle commitment root
/// 3. Squeeze k challenge indices
#[derive(Clone)]
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript initialized with the public journal.
    ///
    /// All journal fields (core + provenance) are absorbed in canonical
    /// order to produce a deterministic initial state.
    pub fn new(journal: &crate::stark::PublicJournal) -> Self {
        let mut state = Vec::with_capacity(256);
        // Domain separator
        state.extend_from_slice(b"graph-native-stark-v1");
        // Core fields
        state.extend_from_slice(&journal.da_root);
        state.extend_from_slice(&journal.state_root);
        state.extend_from_slice(&journal.h_auth);
        state.extend_from_slice(&journal.n_events.to_le_bytes());
        // Provenance fields
        state.extend_from_slice(&journal.prover_id);
        state.extend_from_slice(&journal.proof_timestamp.to_le_bytes());
        state.extend_from_slice(&journal.epoch_range[0].to_le_bytes());
        state.extend_from_slice(&journal.epoch_range[1].to_le_bytes());
        state.extend_from_slice(&journal.merge_base);
        // Parent proofs: length-prefixed for unambiguous parsing
        state.extend_from_slice(&(journal.parent_proofs.len() as u64).to_le_bytes());
        for pp in &journal.parent_proofs {
            state.extend_from_slice(pp);
        }
        Transcript { state }
    }

    /// Absorb arbitrary data into the transcript.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }

    /// Squeeze `count` pseudorandom indices in [0, modulus).
    ///
    /// Each index is derived from 16 bytes of Keccak output,
    /// interpreted as a u128 and reduced modulo `modulus`.
    /// The squeeze is sequential: each hash includes the
    /// previous state to maintain a chain.
    pub fn squeeze_indices(&mut self, count: usize, modulus: usize) -> Vec<usize> {
        assert!(modulus > 0, "modulus must be positive");
        let mut indices = Vec::with_capacity(count);

        for i in 0..count {
            let mut hasher = Keccak::v256();
            let mut hash = [0u8; 32];
            hasher.update(&self.state);
            hasher.update(&(i as u64).to_le_bytes());
            hasher.finalize(&mut hash);

            // Use first 16 bytes as u128 for modular reduction
            let val_bytes: [u8; 16] = hash[0..16].try_into().unwrap();
            let val = u128::from_le_bytes(val_bytes);
            indices.push((val % modulus as u128) as usize);

            // Chain: absorb the hash back for next squeeze
            self.state.clear();
            self.state.extend_from_slice(&hash);
        }

        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark::PublicJournal;

    fn make_journal(da: [u8; 32], sr: [u8; 32], ha: [u8; 32], n: u64) -> PublicJournal {
        PublicJournal {
            da_root: da,
            state_root: sr,
            h_auth: ha,
            n_events: n,
            prover_id: [0; 32],
            proof_timestamp: 0,
            epoch_range: [0, n],
            merge_base: [0; 32],
            parent_proofs: vec![],
        }
    }

    #[test]
    fn test_transcript_deterministic() {
        let j = make_journal([0xAA; 32], [0xBB; 32], [0xCC; 32], 1000);

        let mut t1 = Transcript::new(&j);
        let mut t2 = Transcript::new(&j);

        t1.absorb(b"merkle_root_abc");
        t2.absorb(b"merkle_root_abc");

        let indices1 = t1.squeeze_indices(10, 100);
        let indices2 = t2.squeeze_indices(10, 100);
        assert_eq!(indices1, indices2);
    }

    #[test]
    fn test_different_journals_different_indices() {
        let j1 = make_journal([0xAA; 32], [0xBB; 32], [0xCC; 32], 1000);
        let j2 = make_journal([0xAA; 32], [0xBB; 32], [0xCC; 32], 1001);

        let mut t1 = Transcript::new(&j1);
        let mut t2 = Transcript::new(&j2);

        t1.absorb(b"root");
        t2.absorb(b"root");

        let indices1 = t1.squeeze_indices(10, 100);
        let indices2 = t2.squeeze_indices(10, 100);
        assert_ne!(indices1, indices2);
    }

    #[test]
    fn test_indices_in_range() {
        let j = make_journal([0; 32], [0; 32], [0; 32], 0);
        let mut t = Transcript::new(&j);
        t.absorb(b"test");
        let indices = t.squeeze_indices(843, 1000);
        assert_eq!(indices.len(), 843);
        for &idx in &indices {
            assert!(idx < 1000);
        }
    }
}
