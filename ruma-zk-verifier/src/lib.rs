#![forbid(unsafe_code)]

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};

pub use ruma_zk_topological_air::MatrixEvent;

/// Width of a Merkle-committed state column (legacy scaffold).
/// This will be replaced by the Binius trace commitment scheme.
pub const STATE_WIDTH: usize = 5;

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
            if idx % 2 == 0 {
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

// -------------------------------------------------
// --- WASM Bindings ---
// -------------------------------------------------

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

// -------------------------------------------------
// --- Mobile (UniFFI) Bindings ---
// -------------------------------------------------

uniffi::setup_scaffolding!();

#[uniffi::export]
pub fn verify_matrix_proof_mobile(proof_bytes: Vec<u8>) -> bool {
    let proof: Result<RawProof, _> = bincode::deserialize(&proof_bytes);
    match proof {
        Ok(p) => p.verify_all(),
        Err(_) => false,
    }
}

#[uniffi::export]
pub fn timed_verify_mobile(proof_bytes: Vec<u8>) -> String {
    let start = std::time::Instant::now();
    let success = verify_matrix_proof_mobile(proof_bytes);
    let duration = start.elapsed();

    format!(
        "Verification Result: {} (Completed in {:?})",
        if success { "SUCCESS" } else { "FAILURE" },
        duration
    )
}
