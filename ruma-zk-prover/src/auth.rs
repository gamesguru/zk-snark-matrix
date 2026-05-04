//! Matrix authorization rule constraints for the STARK trace.
//!
//! This module enforces Matrix Spec §11 authorization rules as GF(2)
//! constraints embedded directly in the execution trace. Rather than
//! emulating auth checks through a general-purpose VM, we express
//! each rule as a binary circuit over the trace columns.
//!
//! Authorization rules verified:
//!   1. Power-level sufficiency: `sender_pl >= required_pl`
//!   2. Membership validity: sender is `join`ed to the room
//!   3. Ban enforcement: sender is not banned
//!   4. Event-type permissions: sender has rights for the event type
//!
//! These constraints augment the routing trace (Phases 1-2) with
//! additional columns that the verifier checks alongside the
//! Beneš switch constraints.

use ruma_zk_topological_air::field::GF2;
use ruma_zk_topological_air::gadgets::{compare_less_than, CompareWitness};

/// Bit width for power levels (64-bit integers).
const PL_WIDTH: usize = 64;

/// Membership state encoded as 2-bit value:
///   00 = leave/none, 01 = join, 10 = invite, 11 = ban
const MEMBERSHIP_WIDTH: usize = 2;

/// Membership constants (2-bit encoding).
pub const MEMBERSHIP_NONE: u8 = 0b00;
pub const MEMBERSHIP_JOIN: u8 = 0b01;
pub const MEMBERSHIP_INVITE: u8 = 0b10;
pub const MEMBERSHIP_BAN: u8 = 0b11;

/// Convert a u64 to LSB-first GF2 bit vector.
fn to_bits(val: u64, width: usize) -> Vec<GF2> {
    (0..width)
        .map(|i| GF2::new(((val >> i) & 1) as u8))
        .collect()
}

/// An authorization witness for a single event.
///
/// The prover decomposes each event's auth context into binary
/// columns and computes the comparison witnesses. The verifier
/// checks that all constraints evaluate to zero.
#[derive(Debug, Clone)]
pub struct AuthWitness {
    /// Sender's power level (64 bits, LSB-first).
    pub sender_pl: Vec<GF2>,
    /// Required power level for this event type (64 bits, LSB-first).
    pub required_pl: Vec<GF2>,
    /// Comparison witness: is `required_pl <= sender_pl`?
    /// (i.e., `required_pl < sender_pl + 1`, equivalently NOT(sender_pl < required_pl))
    pub pl_cmp: CompareWitness,
    /// Power level check passes: ONE if sender_pl >= required_pl.
    pub pl_sufficient: GF2,
    /// Sender's membership state (2 bits).
    pub membership: Vec<GF2>,
    /// Is sender joined? (derived from membership == 01).
    pub is_joined: GF2,
    /// Is sender banned? (derived from membership == 11).
    pub is_banned: GF2,
    /// Overall authorization result: ONE if event is authorized.
    pub authorized: GF2,
}

/// Number of bytes per auth witness column.
/// 64 (sender_pl) + 64 (required_pl) + 65 (borrow chain) + 2 (membership) + 3 (flags) = 198.
pub const AUTH_COLUMN_BYTES: usize = PL_WIDTH + PL_WIDTH + (PL_WIDTH + 1) + MEMBERSHIP_WIDTH + 3;

impl AuthWitness {
    /// Serialize the auth witness into a flat byte vector for trace embedding.
    ///
    /// Layout (198 bytes):
    ///   [0..64)    sender_pl bits
    ///   [64..128)  required_pl bits
    ///   [128..193) borrow chain (PL_WIDTH + 1 entries)
    ///   [193..195) membership bits
    ///   [195]      pl_sufficient
    ///   [196]      is_joined
    ///   [197]      authorized
    pub fn to_column_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AUTH_COLUMN_BYTES);

        // Power level bits
        for &bit in &self.sender_pl {
            bytes.push(bit.val());
        }
        for &bit in &self.required_pl {
            bytes.push(bit.val());
        }

        // Borrow chain (PL_WIDTH + 1 entries)
        for &borrow in &self.pl_cmp.borrows {
            bytes.push(borrow.val());
        }

        // Membership
        for &bit in &self.membership {
            bytes.push(bit.val());
        }

        // Derived flags
        bytes.push(self.pl_sufficient.val());
        bytes.push(self.is_joined.val());
        bytes.push(self.authorized.val());

        debug_assert_eq!(bytes.len(), AUTH_COLUMN_BYTES);
        bytes
    }
}

/// Compute the authorization witness for a single event.
///
/// Arguments:
///   - `sender_power_level`: the sender's power level in the current state
///   - `required_power_level`: minimum power level for this event type
///   - `membership`: sender's membership state (use MEMBERSHIP_* constants)
///
/// Returns an `AuthWitness` with all comparison witnesses and the
/// final authorization bit.
pub fn compute_auth(
    sender_power_level: u64,
    required_power_level: u64,
    membership: u8,
) -> AuthWitness {
    let sender_pl = to_bits(sender_power_level, PL_WIDTH);
    let required_pl = to_bits(required_power_level, PL_WIDTH);

    // Check: sender_pl >= required_pl ⟺ NOT(sender_pl < required_pl)
    let pl_cmp = compare_less_than(&sender_pl, &required_pl);
    let pl_sufficient = pl_cmp.result + GF2::ONE; // NOT(sender < required)

    // Membership encoding
    let membership_bits = to_bits(membership as u64, MEMBERSHIP_WIDTH);

    // is_joined: membership == 01 ⟺ membership[0]=1 AND membership[1]=0
    let is_joined = membership_bits[0] * (membership_bits[1] + GF2::ONE);

    // is_banned: membership == 11 ⟺ membership[0]=1 AND membership[1]=1
    let is_banned = membership_bits[0] * membership_bits[1];

    // Authorization: pl_sufficient AND is_joined AND NOT(is_banned)
    // In GF(2): authorized = pl_sufficient * is_joined * (is_banned + 1)
    let authorized = pl_sufficient * is_joined * (is_banned + GF2::ONE);

    AuthWitness {
        sender_pl,
        required_pl,
        pl_cmp,
        pl_sufficient,
        membership: membership_bits,
        is_joined,
        is_banned,
        authorized,
    }
}

/// Verify the power level constraint at bit position `i`.
/// Returns ZERO if satisfied.
#[inline]
pub fn pl_constraint(sender_bit: GF2, required_bit: GF2, borrow_in: GF2, borrow_out: GF2) -> GF2 {
    ruma_zk_topological_air::gadgets::compare_constraint(
        sender_bit,
        required_bit,
        borrow_in,
        borrow_out,
    )
}

/// Verify the membership constraint.
/// Returns ZERO if the membership encoding is valid (one of 00, 01, 10, 11)
/// AND the is_joined and is_banned flags are correctly derived.
pub fn membership_constraint(membership: &[GF2], is_joined: GF2, is_banned: GF2) -> GF2 {
    assert_eq!(membership.len(), MEMBERSHIP_WIDTH);

    // is_joined should be membership[0] * (membership[1] + 1)
    let expected_joined = membership[0] * (membership[1] + GF2::ONE);
    let joined_ok = is_joined + expected_joined;

    // is_banned should be membership[0] * membership[1]
    let expected_banned = membership[0] * membership[1];
    let banned_ok = is_banned + expected_banned;

    // Both must be zero
    joined_ok + banned_ok
}

/// Verify the overall authorization constraint.
/// Returns ZERO if authorized == pl_sufficient * is_joined * (is_banned + 1).
pub fn auth_constraint(pl_sufficient: GF2, is_joined: GF2, is_banned: GF2, authorized: GF2) -> GF2 {
    let expected = pl_sufficient * is_joined * (is_banned + GF2::ONE);
    authorized + expected
}

/// Verify all constraints in an auth witness. Returns the number of violations.
pub fn verify_auth_constraints(witness: &AuthWitness) -> usize {
    let mut violations = 0;

    // Power level comparison chain
    for i in 0..PL_WIDTH {
        let c = pl_constraint(
            witness.sender_pl[i],
            witness.required_pl[i],
            witness.pl_cmp.borrows[i],
            witness.pl_cmp.borrows[i + 1],
        );
        if c != GF2::ZERO {
            violations += 1;
        }
    }

    // pl_sufficient = NOT(result of comparison)
    if witness.pl_sufficient != witness.pl_cmp.result + GF2::ONE {
        violations += 1;
    }

    // Membership
    if membership_constraint(&witness.membership, witness.is_joined, witness.is_banned) != GF2::ZERO
    {
        violations += 1;
    }

    // Overall auth
    if auth_constraint(
        witness.pl_sufficient,
        witness.is_joined,
        witness.is_banned,
        witness.authorized,
    ) != GF2::ZERO
    {
        violations += 1;
    }

    violations
}

/// Count the total number of auth constraints for `n` events.
///
/// Per event:
///   - 64 power-level comparison constraints
///   - 1 pl_sufficient derivation
///   - 1 membership derivation (joined + banned flags)
///   - 1 overall authorization
///
/// Total: 67 constraints per event.
pub const AUTH_CONSTRAINTS_PER_EVENT: usize = PL_WIDTH + 3;

pub fn total_auth_constraints(n_events: usize) -> usize {
    n_events * AUTH_CONSTRAINTS_PER_EVENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorized_event() {
        // Sender has PL 50, needs PL 0, is joined
        let w = compute_auth(50, 0, MEMBERSHIP_JOIN);
        assert_eq!(w.pl_sufficient, GF2::ONE);
        assert_eq!(w.is_joined, GF2::ONE);
        assert_eq!(w.is_banned, GF2::ZERO);
        assert_eq!(w.authorized, GF2::ONE);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_insufficient_power_level() {
        // Sender has PL 10, needs PL 50, is joined
        let w = compute_auth(10, 50, MEMBERSHIP_JOIN);
        assert_eq!(w.pl_sufficient, GF2::ZERO, "10 < 50");
        assert_eq!(w.is_joined, GF2::ONE);
        assert_eq!(w.authorized, GF2::ZERO);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_exact_power_level() {
        // Sender has PL 50, needs exactly PL 50
        let w = compute_auth(50, 50, MEMBERSHIP_JOIN);
        assert_eq!(w.pl_sufficient, GF2::ONE, "50 >= 50");
        assert_eq!(w.authorized, GF2::ONE);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_not_joined() {
        // Sender has sufficient PL but is not joined (leave state)
        let w = compute_auth(100, 0, MEMBERSHIP_NONE);
        assert_eq!(w.pl_sufficient, GF2::ONE);
        assert_eq!(w.is_joined, GF2::ZERO);
        assert_eq!(w.authorized, GF2::ZERO);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_banned_user() {
        // Sender is banned — should fail even with sufficient PL
        let w = compute_auth(100, 0, MEMBERSHIP_BAN);
        assert_eq!(w.pl_sufficient, GF2::ONE);
        assert_eq!(w.is_joined, GF2::ZERO); // ban != join
        assert_eq!(w.is_banned, GF2::ONE);
        assert_eq!(w.authorized, GF2::ZERO);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_invited_user() {
        // Invited users cannot send state events
        let w = compute_auth(100, 0, MEMBERSHIP_INVITE);
        assert_eq!(w.is_joined, GF2::ZERO);
        assert_eq!(w.is_banned, GF2::ZERO);
        assert_eq!(w.authorized, GF2::ZERO);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_admin_override() {
        // Max power level, joined
        let w = compute_auth(u64::MAX, 100, MEMBERSHIP_JOIN);
        assert_eq!(w.authorized, GF2::ONE);
        assert_eq!(verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_constraint_count() {
        assert_eq!(AUTH_CONSTRAINTS_PER_EVENT, 67);
        assert_eq!(total_auth_constraints(100), 6700);
        assert_eq!(total_auth_constraints(43_543), 43_543 * 67);
    }

    #[test]
    fn test_all_membership_states() {
        for &(membership, expect_auth) in &[
            (MEMBERSHIP_NONE, false),
            (MEMBERSHIP_JOIN, true),
            (MEMBERSHIP_INVITE, false),
            (MEMBERSHIP_BAN, false),
        ] {
            let w = compute_auth(100, 0, membership);
            assert_eq!(
                w.authorized,
                if expect_auth { GF2::ONE } else { GF2::ZERO },
                "membership={membership:#04b}"
            );
            assert_eq!(verify_auth_constraints(&w), 0);
        }
    }
}
