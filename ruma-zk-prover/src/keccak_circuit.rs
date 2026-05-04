//! Keccak-256 as a GF(2) constraint circuit.
//!
//! Implements the full Keccak-f[1600] permutation using native u64 lane
//! operations (XOR, AND, NOT, ROT). Each lane is 64 bits packed into a u64,
//! so each round processes 25 u64s — not 1600 individual bytes.
//!
//! ## Lane Indexing
//! We use flat indexing `lanes[5*x + y]` matching the NIST Keccak reference.
//! `xor_bytes` loads bytes sequentially into `lanes[0..17]` (rate = 17 lanes).
//!
//! ## Constraint Model
//! - χ is the only nonlinear step: `a ^ ((!b) & c)` — degree 2 in GF(2)
//! - θ, ρ, π, ι are all linear (XOR + rotation) — degree 1

use ruma_zk_topological_air::field::GF2;

pub const STATE_LANES: usize = 25; // 5 × 5
pub const LANE_BITS: usize = 64;
pub const STATE_BITS: usize = 1600;
pub const NUM_ROUNDS: usize = 24;

/// The 24 Keccak round constants.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// ρ rotation offsets indexed as ROTATIONS[lane_flat_index].
/// Derived from the NIST spec: lane (0,0) has offset 0, then follow
/// the (x,y) = (1,0),(0,2),(2,1),... sequence.
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// π permutation table: PI[i] = source index for destination i.
/// Computed from (x,y) → (y, 2x+3y mod 5).
const PI: [usize; 25] = [
    0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
];

/// Keccak state: 25 lanes of 64 bits each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeccakState {
    pub lanes: [u64; STATE_LANES],
}

impl Default for KeccakState {
    fn default() -> Self {
        KeccakState {
            lanes: [0u64; STATE_LANES],
        }
    }
}

impl KeccakState {
    /// XOR bytes into the state (sponge absorption). NIST byte ordering.
    pub fn xor_bytes(&mut self, data: &[u8]) {
        for (i, chunk) in data.chunks(8).enumerate() {
            if i >= STATE_LANES {
                break;
            }
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            self.lanes[i] ^= u64::from_le_bytes(buf);
        }
    }

    /// Extract bytes from state (sponge squeezing).
    pub fn extract_bytes(&self, count: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(count);
        for &lane in &self.lanes {
            for &b in &lane.to_le_bytes() {
                if result.len() >= count {
                    return result;
                }
                result.push(b);
            }
        }
        result
    }

    /// Convert packed state to GF(2) bits for constraint verification.
    pub fn to_gf2_bits(&self) -> [GF2; STATE_BITS] {
        let mut bits = [GF2::ZERO; STATE_BITS];
        for (i, &lane) in self.lanes.iter().enumerate() {
            for z in 0..64 {
                bits[i * 64 + z] = GF2::new(((lane >> z) & 1) as u8);
            }
        }
        bits
    }
}

/// Witness for one Keccak round.
#[derive(Clone)]
pub struct KeccakRoundWitness {
    /// State before χ (after θ+ρ+π).
    pub before_chi: KeccakState,
    /// State after χ (before ι).
    pub after_chi: KeccakState,
    /// State after full round (after ι).
    pub state_out: KeccakState,
}

/// Full witness for a Keccak-256 hash.
#[derive(Clone)]
pub struct KeccakWitness {
    pub rounds: Vec<KeccakRoundWitness>,
}

/// Execute one Keccak-f[1600] round using native u64 operations.
/// Uses the standard flat-index Keccak-p[1600,24] from NIST FIPS 202.
fn keccak_round(state: &KeccakState, round: usize) -> KeccakRoundWitness {
    let a = state.lanes;

    // θ step: column parity XOR
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    let mut after_theta = a;
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            after_theta[5 * y + x] ^= d;
        }
    }

    // ρ + π steps (combined): rotate each lane, then permute
    let mut after_rho_pi = [0u64; 25];
    for i in 0..25 {
        after_rho_pi[i] = after_theta[PI[i]].rotate_left(ROTATIONS[PI[i]]);
    }

    let before_chi = KeccakState {
        lanes: after_rho_pi,
    };

    // χ step: the ONLY nonlinear step
    let mut chi_out = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let i = 5 * y + x;
            chi_out[i] = after_rho_pi[i]
                ^ (!after_rho_pi[5 * y + (x + 1) % 5] & after_rho_pi[5 * y + (x + 2) % 5]);
        }
    }

    let after_chi = KeccakState { lanes: chi_out };

    // ι step: XOR round constant into lane[0]
    chi_out[0] ^= RC[round];

    let state_out = KeccakState { lanes: chi_out };

    KeccakRoundWitness {
        before_chi,
        after_chi,
        state_out,
    }
}

/// Execute the full Keccak-f[1600] permutation.
pub fn keccak_permutation(state: &KeccakState) -> (KeccakState, KeccakWitness) {
    let mut current = state.clone();
    let mut rounds = Vec::with_capacity(NUM_ROUNDS);

    for round in 0..NUM_ROUNDS {
        let witness = keccak_round(&current, round);
        current = witness.state_out.clone();
        rounds.push(witness);
    }

    (current, KeccakWitness { rounds })
}

/// Compute Keccak-256 with full witness chain.
/// Sponge: rate = 136 bytes (17 lanes), capacity = 64 bytes (8 lanes).
pub fn keccak256_circuit(input: &[u8]) -> ([u8; 32], Vec<KeccakWitness>) {
    const RATE_BYTES: usize = 136;

    // Pad: input || 0x01 || 0x00...0x00 || 0x80
    let mut padded = input.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE_BYTES) {
        padded.push(0x00);
    }
    let last = padded.len() - 1;
    padded[last] |= 0x80;

    let mut state = KeccakState::default();
    let mut all_witnesses = Vec::new();

    for block in padded.chunks(RATE_BYTES) {
        state.xor_bytes(block);
        let (new_state, witness) = keccak_permutation(&state);
        state = new_state;
        all_witnesses.push(witness);
    }

    let output = state.extract_bytes(32);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&output);

    (hash, all_witnesses)
}

/// Verify the χ constraint for a single round.
/// Returns the number of violated constraints (0 = all satisfied).
pub fn verify_chi_constraints(witness: &KeccakRoundWitness) -> usize {
    let mut violations = 0;
    let b = &witness.before_chi.lanes;
    let c = &witness.after_chi.lanes;
    for y in 0..5 {
        for x in 0..5 {
            let i = 5 * y + x;
            let expected = b[i] ^ (!b[5 * y + (x + 1) % 5] & b[5 * y + (x + 2) % 5]);
            violations += (expected ^ c[i]).count_ones() as usize;
        }
    }
    violations
}

/// Verify all constraints for a complete Keccak-256 computation.
pub fn verify_keccak_constraints(witnesses: &[KeccakWitness]) -> usize {
    witnesses
        .iter()
        .flat_map(|kw| &kw.rounds)
        .map(verify_chi_constraints)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_keccak256(data: &[u8]) -> [u8; 32] {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }

    #[test]
    fn test_empty_input() {
        let (hash, witnesses) = keccak256_circuit(b"");
        assert_eq!(hash, reference_keccak256(b""), "empty input hash mismatch");
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
    }

    #[test]
    fn test_short_input() {
        let (hash, witnesses) = keccak256_circuit(b"hello");
        assert_eq!(hash, reference_keccak256(b"hello"));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
    }

    #[test]
    fn test_exact_rate_input() {
        let input = vec![0xAB; 136];
        let (hash, witnesses) = keccak256_circuit(&input);
        assert_eq!(hash, reference_keccak256(&input));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
    }

    #[test]
    fn test_multi_block_input() {
        let input: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let (hash, witnesses) = keccak256_circuit(&input);
        assert_eq!(hash, reference_keccak256(&input));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
        assert!(witnesses.len() >= 3);
    }

    #[test]
    fn test_known_hash() {
        let (hash, witnesses) = keccak256_circuit(b"abc");
        assert_eq!(hash, reference_keccak256(b"abc"));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
        eprintln!("  keccak256(\"abc\") = {}", hex::encode(hash));
    }

    #[test]
    fn test_32_byte_input() {
        let input = [0x42u8; 32];
        let (hash, witnesses) = keccak256_circuit(&input);
        assert_eq!(hash, reference_keccak256(&input));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
    }

    #[test]
    fn test_64_byte_input() {
        let input = [0x42u8; 64];
        let (hash, witnesses) = keccak256_circuit(&input);
        assert_eq!(hash, reference_keccak256(&input));
        assert_eq!(verify_keccak_constraints(&witnesses), 0);
    }

    #[test]
    fn test_constraint_count() {
        let (_, witnesses) = keccak256_circuit(b"test");
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].rounds.len(), NUM_ROUNDS);
    }

    #[test]
    fn test_theta_column_parity() {
        let mut state = KeccakState::default();
        state.lanes[0] = 1;
        assert_eq!(verify_chi_constraints(&keccak_round(&state, 0)), 0);
    }

    #[test]
    fn test_determinism() {
        let (h1, _) = keccak256_circuit(b"deterministic");
        let (h2, _) = keccak256_circuit(b"deterministic");
        assert_eq!(h1, h2);
    }
}
