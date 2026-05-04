//! Sparse Expander matrix for LTC (Locally Testable Code) commitment.
//!
//! The Expander matrix G ∈ F₂^{n × m} with m = ρ·n maps the original
//! trace columns to stretched columns via XOR accumulation.  Because G
//! has constant degree d_G, the stretch operation is O(d_G · |T|).
//!
//! The construction is deterministic from a public seed, ensuring
//! that prover and verifier agree on the same matrix.

use crate::merkle::keccak256;

/// A sparse, constant-degree Expander matrix for LTC stretch.
///
/// Each of the `m` stretched columns is computed as the XOR of
/// exactly `degree` columns from the original trace.
#[derive(Debug, Clone)]
pub struct ExpanderMatrix {
    /// Number of original columns.
    pub n: usize,
    /// Number of stretched columns (n * stretch_factor).
    pub m: usize,
    /// Constant degree: each stretched column XORs this many originals.
    pub degree: usize,
    /// For each stretched column j ∈ [0, m), the indices of the
    /// original columns that contribute to it.
    /// `neighbors[j].len() == degree` for all j.
    pub neighbors: Vec<Vec<usize>>,
}

impl ExpanderMatrix {
    /// Construct a deterministic Expander matrix from a public seed.
    ///
    /// The neighbor lists are derived by iteratively hashing the seed
    /// with the column index, then reducing modulo `n`.  This produces
    /// a pseudorandom constant-degree bipartite graph.
    ///
    /// # Parameters
    /// - `n`: number of original columns
    /// - `stretch_factor`: ratio m/n (typically 2)
    /// - `degree`: number of XOR neighbors per stretched column (typically 8)
    /// - `seed`: 32-byte public parameter
    pub fn from_seed(n: usize, stretch_factor: usize, degree: usize, seed: [u8; 32]) -> Self {
        assert!(n > 0, "need at least 1 column");
        assert!(stretch_factor >= 2, "stretch factor must be >= 2");
        assert!(degree >= 2, "degree must be >= 2");

        // Cap effective degree at n (can't have more distinct neighbors than columns)
        let effective_degree = degree.min(n);

        let m = n * stretch_factor;
        let mut neighbors = Vec::with_capacity(m);

        for col in 0..m {
            let mut col_neighbors = Vec::with_capacity(effective_degree);
            // Derive d_G distinct neighbors by hashing (seed || col || i)
            let mut attempt = 0u64;
            while col_neighbors.len() < effective_degree {
                let mut preimage = Vec::with_capacity(32 + 8 + 8);
                preimage.extend_from_slice(&seed);
                preimage.extend_from_slice(&(col as u64).to_le_bytes());
                preimage.extend_from_slice(&attempt.to_le_bytes());
                let hash = keccak256(&preimage);

                // Extract neighbor index from first 8 bytes
                let idx_bytes: [u8; 8] = hash[0..8].try_into().unwrap();
                let neighbor = (u64::from_le_bytes(idx_bytes) as usize) % n;

                // Ensure distinct neighbors within this column
                if !col_neighbors.contains(&neighbor) {
                    col_neighbors.push(neighbor);
                }
                attempt += 1;
            }
            neighbors.push(col_neighbors);
        }

        ExpanderMatrix {
            n,
            m,
            degree: effective_degree,
            neighbors,
        }
    }

    /// Stretch the trace columns: T_ext[col] = XOR of T[neighbors[col]].
    ///
    /// Each column is a byte vector of length `rows` (the trace height W).
    /// The stretch is computed entirely via XOR — no multiplication needed.
    ///
    /// # Parameters
    /// - `trace_columns`: the original n columns, each of length `rows`
    ///
    /// # Returns
    /// The stretched m columns, each of length `rows`.
    pub fn stretch(&self, trace_columns: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(
            trace_columns.len(),
            self.n,
            "expected {} columns, got {}",
            self.n,
            trace_columns.len()
        );
        let rows = trace_columns[0].len();

        let mut stretched = Vec::with_capacity(self.m);
        for col_neighbors in &self.neighbors {
            let mut col = vec![0u8; rows];
            for &neighbor_idx in col_neighbors {
                let src = &trace_columns[neighbor_idx];
                for (dst, &src_byte) in col.iter_mut().zip(src.iter()) {
                    *dst ^= src_byte;
                }
            }
            stretched.push(col);
        }
        stretched
    }
}

/// Default public seed for the Expander matrix.
/// In production, this would be derived from the VK_HASH or room version.
pub const DEFAULT_SEED: [u8; 32] = [
    0x67, 0x72, 0x61, 0x70, 0x68, 0x2d, 0x6e, 0x61, // "graph-na"
    0x74, 0x69, 0x76, 0x65, 0x2d, 0x73, 0x74, 0x61, // "tive-sta"
    0x72, 0x6b, 0x2d, 0x65, 0x78, 0x70, 0x61, 0x6e, // "rk-expan"
    0x64, 0x65, 0x72, 0x2d, 0x73, 0x65, 0x65, 0x64, // "der-seed"
];

/// Default Expander degree (number of XOR neighbors per stretched column).
pub const DEFAULT_DEGREE: usize = 8;

/// Default stretch factor (m = n * STRETCH_FACTOR).
pub const DEFAULT_STRETCH: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expander_construction() {
        let g = ExpanderMatrix::from_seed(16, 2, 8, DEFAULT_SEED);
        assert_eq!(g.n, 16);
        assert_eq!(g.m, 32);
        assert_eq!(g.degree, 8);
        assert_eq!(g.neighbors.len(), 32);
        // Each column has exactly degree neighbors
        for col in &g.neighbors {
            assert_eq!(col.len(), 8);
            // All neighbors are valid indices
            for &idx in col {
                assert!(idx < 16);
            }
            // All neighbors are distinct within a column
            let mut sorted = col.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), col.len());
        }
    }

    #[test]
    fn test_stretch_xor() {
        let g = ExpanderMatrix::from_seed(4, 2, 2, DEFAULT_SEED);
        // 4 columns, each 3 rows
        let trace = vec![
            vec![0xFF, 0x00, 0xAA],
            vec![0x00, 0xFF, 0x55],
            vec![0xAA, 0x55, 0x00],
            vec![0x55, 0xAA, 0xFF],
        ];
        let stretched = g.stretch(&trace);
        assert_eq!(stretched.len(), 8); // m = 4 * 2

        // Verify each stretched column is the XOR of its neighbors
        for (col_idx, col) in stretched.iter().enumerate() {
            let mut expected = vec![0u8; 3];
            for &neighbor in &g.neighbors[col_idx] {
                for (e, &src) in expected.iter_mut().zip(trace[neighbor].iter()) {
                    *e ^= src;
                }
            }
            assert_eq!(col, &expected, "stretched column {} mismatch", col_idx);
        }
    }

    #[test]
    fn test_deterministic() {
        let g1 = ExpanderMatrix::from_seed(32, 2, 8, DEFAULT_SEED);
        let g2 = ExpanderMatrix::from_seed(32, 2, 8, DEFAULT_SEED);
        assert_eq!(g1.neighbors, g2.neighbors);
    }
}
