#![forbid(unsafe_code)]

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixEvent {
    pub event_id: String,
    pub event_type: String,
    pub state_key: String,
    pub prev_events: Vec<String>,
    pub power_level: u64,
}

/// The number of field elements stored in each node (columns).
/// [0] -> is_active (1 or 0)
/// [1] -> parent_1_edge_idx (1 to n-1, 0 for genesis)
/// [2] -> parent_2_edge_idx (1 to n-1, 0 if single parent)
/// [3] -> current_pl (Matrix Power Level)
/// [4] -> event_type_hash (Reduced identifier for the event type)
pub const STATE_WIDTH: usize = 5;

/// The canonical Topological Constraint for Matrix State Resolution v2.
pub fn matrix_topological_constraint(
    state: [BabyBear; STATE_WIDTH],
    neighbors: &[[BabyBear; STATE_WIDTH]],
) -> BabyBear {
    let is_active = state[0];
    let p1_idx = state[1].as_canonical_u32() as usize;
    let current_pl = state[3];

    if is_active == BabyBear::new(0) {
        return is_active + state[1] + state[2] + current_pl + state[4];
    }

    if p1_idx == 0 {
        return current_pl - BabyBear::new(100);
    }

    let p1_state = neighbors[p1_idx - 1];
    let p1_pl = p1_state[3];

    // Simple case: Power level compliance check
    current_pl - p1_pl
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawProof {
    pub root: [u8; 32],
    pub openings: Vec<Opening>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Opening {
    pub index: usize,
    pub state: [u32; STATE_WIDTH],
    pub path: Vec<[u8; 32]>,
}

impl RawProof {
    pub fn verify_all(&self) -> bool {
        for opening in &self.openings {
            if !self.verify_opening(opening) {
                return false;
            }
        }
        true
    }

    pub fn verify_opening(&self, opening: &Opening) -> bool {
        use tiny_keccak::{Hasher, Keccak};
        let mut current_hash = [0u8; 32];
        let mut k = Keccak::v256();
        for e in &opening.state {
            k.update(&e.to_le_bytes());
        }
        k.finalize(&mut current_hash);

        let mut idx = opening.index;
        for sibling in &opening.path {
            let mut k = Keccak::v256();
            if idx.is_multiple_of(2) {
                k.update(&current_hash);
                k.update(sibling);
            } else {
                k.update(sibling);
                k.update(&current_hash);
            }
            k.finalize(&mut current_hash);
            idx /= 2;
        }
        current_hash == self.root
    }
}

// --- WASM Bindings ---

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_matrix_proof(proof_bytes: &[u8]) -> bool {
    let proof: Result<RawProof, _> = bincode::deserialize(proof_bytes);
    match proof {
        Ok(p) => p.verify_all(),
        Err(_) => false,
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn timed_verify(proof_bytes: &[u8]) -> String {
    let start = web_time::Instant::now();
    let success = verify_matrix_proof(proof_bytes);
    let duration = start.elapsed();

    format!(
        "Verification Result: {} (Completed in {:?})",
        if success { "SUCCESS" } else { "FAILURE" },
        duration
    )
}
