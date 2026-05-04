//! Binary constraint gadgets for the graph-native STARK framework.
//!
//! These are general-purpose building blocks for enforcing integer arithmetic
//! and conditional logic inside a GF(2) trace. They are protocol-agnostic —
//! the Matrix-specific auth rules are built on top of these in `matrix.rs`.

use crate::field::GF2;
use alloc::vec::Vec;

// ── Ripple-carry comparator ─────────────────────────────────────────

/// Result of comparing two W-bit integers A > B inside a GF(2) trace.
///
/// Each bit position produces a `carry` flag that propagates through the
/// ripple chain. The final carry is the comparison result.
#[derive(Debug, Clone)]
pub struct CompareWitness {
    /// Borrow/carry bits, one per bit position (LSB first).
    pub borrows: Vec<GF2>,
    /// Final result: ONE if A > B, ZERO otherwise.
    pub result: GF2,
}

/// Compute a ripple-carry less-than comparison: is A < B?
///
/// Both `a_bits` and `b_bits` are LSB-first binary representations.
/// Returns the witness (borrow chain) and the final comparison bit.
///
/// The constraint per bit position i is:
///   borrow[i+1] = (NOT a[i]) AND b[i]  OR  (NOT (a[i] XOR b[i])) AND borrow[i]
///
/// In GF(2) arithmetic (where NOT x = x + 1):
///   borrow[i+1] = (a[i] + 1) * b[i] + (a[i] + b[i] + 1) * borrow[i]
pub fn compare_less_than(a_bits: &[GF2], b_bits: &[GF2]) -> CompareWitness {
    assert_eq!(a_bits.len(), b_bits.len(), "bit widths must match");
    let w = a_bits.len();

    let mut borrows = Vec::with_capacity(w + 1);
    borrows.push(GF2::ZERO); // initial borrow = 0

    for i in 0..w {
        let a = a_bits[i];
        let b = b_bits[i];
        let prev = borrows[i];

        // borrow[i+1] = (a+1)*b + (a+b+1)*prev
        let not_a = a + GF2::ONE;
        let eq_bit = a + b + GF2::ONE; // 1 if a==b, 0 if a!=b
        let next = not_a * b + eq_bit * prev;
        borrows.push(next);
    }

    let result = borrows[w];
    CompareWitness { borrows, result }
}

/// Verify the ripple-carry constraint at bit position `i`.
/// Returns ZERO if the constraint is satisfied.
#[inline]
pub fn compare_constraint(a: GF2, b: GF2, borrow_in: GF2, borrow_out: GF2) -> GF2 {
    let not_a = a + GF2::ONE;
    let eq_bit = a + b + GF2::ONE;
    let expected = not_a * b + eq_bit * borrow_in;
    borrow_out + expected
}

// ── Multiplexer ─────────────────────────────────────────────────────

/// Binary multiplexer: select = 0 → output a; select = 1 → output b.
///
/// Constraint: output = a + select * (b + a)
///   (same algebraic form as the routing constraint from Lemma 4.2)
#[inline(always)]
pub fn mux(select: GF2, a: GF2, b: GF2) -> GF2 {
    a + select * (b + a)
}

/// Verify the multiplexer constraint. Returns ZERO if satisfied.
#[inline(always)]
pub fn mux_constraint(select: GF2, a: GF2, b: GF2, output: GF2) -> GF2 {
    output + a + select * (b + a)
}

// ── Multi-bit multiplexer ───────────────────────────────────────────

/// Select between two W-bit values based on a single selector bit.
pub fn mux_wide(select: GF2, a_bits: &[GF2], b_bits: &[GF2]) -> Vec<GF2> {
    assert_eq!(a_bits.len(), b_bits.len());
    a_bits
        .iter()
        .zip(b_bits.iter())
        .map(|(&a, &b)| mux(select, a, b))
        .collect()
}

// ── Equality check ──────────────────────────────────────────────────

/// Check if two W-bit values are equal.
/// Returns ONE if equal, ZERO otherwise.
///
/// This uses the algebraic identity: equal = PRODUCT(1 + a[i] + b[i]) for all i.
/// If any bit differs, the product is zero.
pub fn equal_wide(a_bits: &[GF2], b_bits: &[GF2]) -> GF2 {
    assert_eq!(a_bits.len(), b_bits.len());
    let mut result = GF2::ONE;
    for (&a, &b) in a_bits.iter().zip(b_bits.iter()) {
        result *= a + b + GF2::ONE;
    }

    result
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert a u64 to LSB-first GF2 bits.
    fn to_bits(val: u64, width: usize) -> Vec<GF2> {
        (0..width)
            .map(|i| GF2::new(((val >> i) & 1) as u8))
            .collect()
    }

    #[test]
    fn test_compare_basic() {
        let a = to_bits(5, 8); // 00000101
        let b = to_bits(10, 8); // 00001010
        let w = compare_less_than(&a, &b);
        assert_eq!(w.result, GF2::ONE, "5 < 10 should be true");

        let w2 = compare_less_than(&b, &a);
        assert_eq!(w2.result, GF2::ZERO, "10 < 5 should be false");
    }

    #[test]
    fn test_compare_equal() {
        let a = to_bits(42, 8);
        let b = to_bits(42, 8);
        let w = compare_less_than(&a, &b);
        assert_eq!(w.result, GF2::ZERO, "42 < 42 should be false");
    }

    #[test]
    fn test_compare_edge_cases() {
        let a = to_bits(0, 8);
        let b = to_bits(255, 8);
        let w = compare_less_than(&a, &b);
        assert_eq!(w.result, GF2::ONE, "0 < 255 should be true");

        let w2 = compare_less_than(&b, &a);
        assert_eq!(w2.result, GF2::ZERO, "255 < 0 should be false");
    }

    #[test]
    fn test_compare_constraint_valid() {
        let a = to_bits(100, 64);
        let b = to_bits(50, 64);
        let w = compare_less_than(&a, &b);

        for i in 0..64 {
            let c = compare_constraint(a[i], b[i], w.borrows[i], w.borrows[i + 1]);
            assert_eq!(c, GF2::ZERO, "constraint violated at bit {i}");
        }
        assert_eq!(w.result, GF2::ZERO, "100 < 50 should be false");
    }

    #[test]
    fn test_compare_64bit() {
        let a = to_bits(u64::MAX - 1, 64);
        let b = to_bits(u64::MAX, 64);
        let w = compare_less_than(&a, &b);
        assert_eq!(w.result, GF2::ONE, "MAX-1 < MAX should be true");
    }

    #[test]
    fn test_mux() {
        assert_eq!(mux(GF2::ZERO, GF2::ONE, GF2::ZERO), GF2::ONE);
        assert_eq!(mux(GF2::ONE, GF2::ONE, GF2::ZERO), GF2::ZERO);
        assert_eq!(mux(GF2::ZERO, GF2::ZERO, GF2::ONE), GF2::ZERO);
        assert_eq!(mux(GF2::ONE, GF2::ZERO, GF2::ONE), GF2::ONE);
    }

    #[test]
    fn test_mux_constraint_valid() {
        for s in [GF2::ZERO, GF2::ONE] {
            for a in [GF2::ZERO, GF2::ONE] {
                for b in [GF2::ZERO, GF2::ONE] {
                    let out = mux(s, a, b);
                    assert_eq!(mux_constraint(s, a, b, out), GF2::ZERO);
                }
            }
        }
    }

    #[test]
    fn test_mux_wide() {
        let a = to_bits(0xDEAD, 16);
        let b = to_bits(0xBEEF, 16);

        let out0 = mux_wide(GF2::ZERO, &a, &b);
        assert_eq!(out0, a, "select=0 should return a");

        let out1 = mux_wide(GF2::ONE, &a, &b);
        assert_eq!(out1, b, "select=1 should return b");
    }

    #[test]
    fn test_equal_wide() {
        let a = to_bits(42, 8);
        let b = to_bits(42, 8);
        let c = to_bits(43, 8);

        assert_eq!(equal_wide(&a, &b), GF2::ONE, "42 == 42");
        assert_eq!(equal_wide(&a, &c), GF2::ZERO, "42 != 43");
    }
}
