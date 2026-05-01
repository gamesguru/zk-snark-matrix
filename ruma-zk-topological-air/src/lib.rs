//! Topological AIR constraint definitions for the graph-native STARK framework.
//!
//! All arithmetic operates over GF(2) — addition is XOR, multiplication is AND.
//!
//! ## Constraint layers
//!
//! 1. **Routing layer** (Beneš network): `y ⊕ a ⊕ s·(a ⊕ b) = 0` (Lemma 4.2)
//! 2. **Logic layer** (application-specific): power-level, tie-breaking, etc.

#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub mod field;

pub use field::GF2;

/// Canonical verification key hash for circuit identity pinning.
pub const VK_HASH: &str = "0x8f2a1b9c7d4e5f6a7b8c9d0e1f2a3b4c";

/// A Matrix protocol event (case study from §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixEvent {
    pub event_id: String,
    pub event_type: String,
    pub state_key: String,
    pub prev_events: Vec<String>,
    pub power_level: u64,
}
