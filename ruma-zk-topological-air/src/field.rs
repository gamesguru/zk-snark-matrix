//! Binary field arithmetic for the graph-native STARK framework.
//!
//! `GF2` is the Galois field with two elements {0, 1}.
//! Addition = XOR, Multiplication = AND, Negation = identity.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// An element of GF(2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct GF2(u8);

impl GF2 {
    pub const ZERO: Self = GF2(0);
    pub const ONE: Self = GF2(1);

    #[inline(always)]
    pub const fn new(val: u8) -> Self {
        GF2(val & 1)
    }

    #[inline(always)]
    pub const fn val(self) -> u8 {
        self.0
    }

    #[inline(always)]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for GF2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for GF2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for GF2 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        GF2(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF2 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for GF2 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        GF2(self.0 ^ rhs.0)
    }
}

impl SubAssign for GF2 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Mul for GF2 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        GF2(self.0 & rhs.0)
    }
}

impl MulAssign for GF2 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl From<bool> for GF2 {
    #[inline(always)]
    fn from(b: bool) -> Self {
        GF2(b as u8)
    }
}

impl From<GF2> for bool {
    #[inline(always)]
    fn from(f: GF2) -> bool {
        f.0 != 0
    }
}

// ── Constraint gates (Lemma 4.2) ───────────────────────────────────

/// Routing constraint: `y ⊕ a ⊕ s·(a ⊕ b) = 0`
/// Returns ZERO iff y = a when s=0, y = b when s=1.
#[inline(always)]
pub fn routing_constraint(s: GF2, a: GF2, b: GF2, y: GF2) -> GF2 {
    y + a + s * (a + b)
}

/// Switch validity: `s · (s ⊕ 1) = 0` (s is binary).
#[inline(always)]
pub fn switch_validity(s: GF2) -> GF2 {
    s * (s + GF2::ONE)
}
