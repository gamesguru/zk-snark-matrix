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
    /// The journal fields (da_root, state_root, h_auth, n_events)
    /// are absorbed in canonical order to produce a deterministic
    /// initial state.
    pub fn new(
        da_root: &[u8; 32],
        state_root: &[u8; 32],
        h_auth: &[u8; 32],
        n_events: u64,
    ) -> Self {
        let mut state = Vec::with_capacity(128);
        // Domain separator
        state.extend_from_slice(b"graph-native-stark-v1");
        // Public journal fields in canonical order
        state.extend_from_slice(da_root);
        state.extend_from_slice(state_root);
        state.extend_from_slice(h_auth);
        state.extend_from_slice(&n_events.to_le_bytes());
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

    #[test]
    fn test_transcript_deterministic() {
        let da = [0xAA; 32];
        let sr = [0xBB; 32];
        let ha = [0xCC; 32];

        let mut t1 = Transcript::new(&da, &sr, &ha, 1000);
        let mut t2 = Transcript::new(&da, &sr, &ha, 1000);

        t1.absorb(b"merkle_root_abc");
        t2.absorb(b"merkle_root_abc");

        let indices1 = t1.squeeze_indices(10, 100);
        let indices2 = t2.squeeze_indices(10, 100);
        assert_eq!(indices1, indices2);
    }

    #[test]
    fn test_different_journals_different_indices() {
        let da = [0xAA; 32];
        let sr = [0xBB; 32];
        let ha = [0xCC; 32];

        let mut t1 = Transcript::new(&da, &sr, &ha, 1000);
        let mut t2 = Transcript::new(&da, &sr, &ha, 1001); // different n_events

        t1.absorb(b"root");
        t2.absorb(b"root");

        let indices1 = t1.squeeze_indices(10, 100);
        let indices2 = t2.squeeze_indices(10, 100);
        assert_ne!(indices1, indices2);
    }

    #[test]
    fn test_indices_in_range() {
        let mut t = Transcript::new(&[0; 32], &[0; 32], &[0; 32], 0);
        t.absorb(b"test");
        let indices = t.squeeze_indices(843, 1000);
        assert_eq!(indices.len(), 843);
        for &idx in &indices {
            assert!(idx < 1000);
        }
    }
}
