//! Matrix protocol constraint logic.
//!
//! This module implements the application-specific auth rules from the
//! Matrix specification (§11.20.2 State Resolution v2) as GF(2) constraints
//! built on top of the general-purpose gadgets.
//!
//! The key rules enforced:
//!   1. Power-level precedence: higher power level wins a state conflict.
//!   2. Origin server timestamp: ties broken by `origin_server_ts`.
//!   3. Lexicographic event ID: final tiebreak by `event_id` byte order.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::field::GF2;
use crate::gadgets::{compare_less_than, mux_wide, CompareWitness};

/// A Matrix protocol event (case study from §5).
///
/// This is the application-level data type. The framework itself is
/// agnostic to this structure — it operates on arbitrary DAG nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixEvent {
    pub event_id: String,
    pub event_type: String,
    pub state_key: String,
    pub prev_events: Vec<String>,
    pub power_level: u64,
}

/// Binary decomposition of a Matrix event's comparison key.
///
/// Each field is represented as a vector of GF(2) bits (LSB-first).
/// The prover decomposes the u64/byte values into individual bits
/// and commits them as trace columns.
#[derive(Debug, Clone)]
pub struct EventKey {
    /// Power level (64 bits, LSB-first).
    pub power_level: Vec<GF2>,
    /// Origin server timestamp (64 bits, LSB-first).
    pub origin_server_ts: Vec<GF2>,
    /// Event ID hash (256 bits, LSB-first) — Keccak-256 of the event_id string.
    pub event_id_hash: Vec<GF2>,
}

impl EventKey {
    /// Create an event key from raw u64 values and a 32-byte event ID hash.
    pub fn new(power_level: u64, origin_server_ts: u64, event_id_hash: &[u8; 32]) -> Self {
        let pl_bits = (0..64)
            .map(|i| GF2::new(((power_level >> i) & 1) as u8))
            .collect();
        let ts_bits = (0..64)
            .map(|i| GF2::new(((origin_server_ts >> i) & 1) as u8))
            .collect();
        let id_bits = event_id_hash
            .iter()
            .flat_map(|byte| (0..8).map(move |i| GF2::new((byte >> i) & 1)))
            .collect();

        EventKey {
            power_level: pl_bits,
            origin_server_ts: ts_bits,
            event_id_hash: id_bits,
        }
    }
}

/// Witness for the three-stage comparison between two events.
#[derive(Debug, Clone)]
pub struct TieBreakWitness {
    /// Power level comparison: is A's power level < B's?
    pub pl_cmp: CompareWitness,
    /// Timestamp comparison: is A's timestamp < B's?
    pub ts_cmp: CompareWitness,
    /// Event ID comparison: is A's event_id < B's?
    pub id_cmp: CompareWitness,
    /// Are power levels equal?
    pub pl_equal: GF2,
    /// Are timestamps equal?
    pub ts_equal: GF2,
    /// Final winner selector: ONE if B wins, ZERO if A wins.
    pub b_wins: GF2,
}

/// Compute the three-stage tiebreak comparison per §11.20.2:
///   1. Higher power level wins.
///   2. If equal, lower origin_server_ts wins.
///   3. If still equal, lower event_id (lexicographic) wins.
///
/// Returns the witness and a selector bit indicating whether B wins.
pub fn tiebreak_compare(a: &EventKey, b: &EventKey) -> TieBreakWitness {
    // Stage 1: power level (higher wins → B wins if A.pl < B.pl)
    let pl_cmp = compare_less_than(&a.power_level, &b.power_level);
    let pl_equal = crate::gadgets::equal_wide(&a.power_level, &b.power_level);

    // Stage 2: timestamp (lower wins → B wins if B.ts < A.ts, i.e., A.ts > B.ts)
    // So we check: is B.ts < A.ts?
    let ts_cmp = compare_less_than(&b.origin_server_ts, &a.origin_server_ts);
    let ts_equal = crate::gadgets::equal_wide(&a.origin_server_ts, &b.origin_server_ts);

    // Stage 3: event ID (lower wins → B wins if B.id < A.id)
    let id_cmp = compare_less_than(&b.event_id_hash, &a.event_id_hash);

    // Combine: B wins if:
    //   (A.pl < B.pl) OR
    //   (pl_equal AND B.ts < A.ts) OR
    //   (pl_equal AND ts_equal AND B.id < A.id)
    //
    // In GF(2): b_wins = pl_cmp.result + pl_equal * (ts_cmp.result + ts_equal * id_cmp.result)
    // But we need OR, not XOR. In GF(2), OR(a,b) = a + b + a*b.
    //
    // Since the three conditions are mutually exclusive (if pl differs, we don't
    // check ts; if ts differs, we don't check id), XOR = OR here.
    let stage2 = pl_equal * ts_cmp.result;
    let stage3 = pl_equal * ts_equal * id_cmp.result;
    let b_wins = pl_cmp.result + stage2 + stage3;

    TieBreakWitness {
        pl_cmp,
        ts_cmp,
        id_cmp,
        pl_equal,
        ts_equal,
        b_wins,
    }
}

/// Given two event keys and the tiebreak result, select the winner's key.
pub fn select_winner<'a>(a: &'a EventKey, b: &'a EventKey, b_wins: GF2) -> Vec<GF2> {
    mux_wide(b_wins, &a.power_level, &b.power_level)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash() -> [u8; 32] {
        [0u8; 32]
    }

    fn hash_from_byte(b: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    #[test]
    fn test_higher_power_wins() {
        let a = EventKey::new(50, 1000, &zero_hash());
        let b = EventKey::new(100, 1000, &zero_hash());
        let w = tiebreak_compare(&a, &b);
        assert_eq!(w.b_wins, GF2::ONE, "B (pl=100) should beat A (pl=50)");
    }

    #[test]
    fn test_lower_power_loses() {
        let a = EventKey::new(100, 1000, &zero_hash());
        let b = EventKey::new(50, 1000, &zero_hash());
        let w = tiebreak_compare(&a, &b);
        assert_eq!(w.b_wins, GF2::ZERO, "A (pl=100) should beat B (pl=50)");
    }

    #[test]
    fn test_equal_power_lower_ts_wins() {
        let a = EventKey::new(100, 2000, &zero_hash());
        let b = EventKey::new(100, 1000, &zero_hash());
        let w = tiebreak_compare(&a, &b);
        assert_eq!(
            w.b_wins,
            GF2::ONE,
            "B (ts=1000) should beat A (ts=2000) at equal power"
        );
    }

    #[test]
    fn test_equal_power_higher_ts_loses() {
        let a = EventKey::new(100, 1000, &zero_hash());
        let b = EventKey::new(100, 2000, &zero_hash());
        let w = tiebreak_compare(&a, &b);
        assert_eq!(w.b_wins, GF2::ZERO, "A (ts=1000) should beat B (ts=2000)");
    }

    #[test]
    fn test_full_tiebreak_to_event_id() {
        let a = EventKey::new(100, 1000, &hash_from_byte(0xFF));
        let b = EventKey::new(100, 1000, &hash_from_byte(0x01));
        let w = tiebreak_compare(&a, &b);
        assert_eq!(
            w.b_wins,
            GF2::ONE,
            "B (lower event_id) should win full tiebreak"
        );
    }

    #[test]
    fn test_identical_events() {
        let a = EventKey::new(100, 1000, &hash_from_byte(0x42));
        let b = EventKey::new(100, 1000, &hash_from_byte(0x42));
        let w = tiebreak_compare(&a, &b);
        assert_eq!(
            w.b_wins,
            GF2::ZERO,
            "identical events: A wins by convention"
        );
    }
}
