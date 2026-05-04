//! Topological AIR constraint definitions for the graph-native STARK framework.
//!
//! All arithmetic operates over GF(2) — addition is XOR, multiplication is AND.
//!
//! ## Crate structure
//!
//! - `field` — GF(2) binary field arithmetic (general)
//! - `gadgets` — binary constraint gadgets: comparator, multiplexer (general)
//! - `matrix` — Matrix protocol auth rules: tiebreak logic (application-specific)

#![no_std]
extern crate alloc;

pub mod field;
pub mod gadgets;
pub mod matrix;

pub use field::GF2;
pub use matrix::MatrixEvent;
