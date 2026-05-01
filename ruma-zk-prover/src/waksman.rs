//! Waksman's recursive algorithm (1968) for computing switch settings
//! on a Beneš permutation network.
//!
//! Given a permutation π: [N] → [N] where N = 2^d, this module computes
//! the boolean switch assignments for a Beneš network of depth 2d - 1
//! such that routing through the network realizes π.
//!
//! Reference: Abraham Waksman, "A Permutation Network,"
//!            Journal of the ACM, vol. 15, no. 1, pp. 159–163, 1968.
//!            <https://doi.org/10.1145/321439.321449>

/// A Beneš network for N inputs (N must be a power of 2).
///
/// The network has `2 * log₂(N) - 1` layers, each with `N / 2` switches.
/// Each switch is a 2×2 crossbar:
/// - `false` (straight): top→top, bottom→bottom
/// - `true`  (cross):    top→bottom, bottom→top
#[derive(Debug, Clone)]
pub struct BenesNetwork {
    /// Number of inputs/outputs (power of 2).
    pub n: usize,
    /// log₂(n).
    pub log_n: usize,
    /// Switch settings: `switches[layer][switch_index]`.
    /// There are `2 * log_n - 1` layers, each with `n / 2` switches.
    pub switches: Vec<Vec<bool>>,
}

impl BenesNetwork {
    /// Compute Beneš switch settings that realize the given permutation.
    ///
    /// Uses Waksman's recursive chain-following algorithm.
    /// Complexity: O(N log N) time, O(N log N) space.
    ///
    /// # Panics
    /// Panics if `perm` is not a valid permutation of `0..N` where N is a power of 2.
    pub fn from_permutation(perm: &[usize]) -> Self {
        let n = perm.len();
        assert!(n >= 2, "N must be at least 2");
        assert!(n.is_power_of_two(), "N must be a power of 2, got {n}");
        assert_valid_permutation(perm);

        let log_n = n.trailing_zeros() as usize;
        let num_layers = 2 * log_n - 1;
        let mut switches = vec![vec![false; n / 2]; num_layers];

        solve_recursive(perm, 0, 0, &mut switches);

        Self { n, log_n, switches }
    }

    /// Route inputs through the network, producing outputs.
    ///
    /// If the network was built from permutation π, then
    /// `route(input)[i] == input[π⁻¹(i)]`, i.e., the value originally
    /// at position j ends up at position π(j).
    pub fn route<T: Copy>(&self, inputs: &[T]) -> Vec<T> {
        assert_eq!(inputs.len(), self.n);
        route_recursive(inputs, &self.switches, 0, 0)
    }

    /// Total number of switches in the network.
    pub fn num_switches(&self) -> usize {
        self.switches.iter().map(|layer| layer.len()).sum()
    }
}

/// Recursive solver: determine switch settings for a sub-network.
///
/// - `perm`: the sub-permutation to realize (length N, a power of 2)
/// - `layer_off`: global layer index where this sub-network's input column sits
/// - `sw_off`: global switch offset within each layer for this sub-network
/// - `switches`: the global switch array (mutated in place)
fn solve_recursive(perm: &[usize], layer_off: usize, sw_off: usize, switches: &mut [Vec<bool>]) {
    let n = perm.len();

    // Base case: single 2×2 switch
    if n == 2 {
        switches[layer_off][sw_off] = perm[0] == 1;
        return;
    }

    let half = n / 2;
    let num_layers = 2 * (n.trailing_zeros() as usize) - 1;
    let output_layer = layer_off + num_layers - 1;

    // Build inverse permutation
    let mut inv = vec![0usize; n];
    for (i, &p) in perm.iter().enumerate() {
        inv[p] = i;
    }

    // Assignment: 0 = upper, 1 = lower, 2 = unassigned
    let mut assign = vec![2u8; n];

    // Chain-following algorithm
    for start in 0..half {
        if assign[2 * start] != 2 {
            continue;
        }

        let mut cur = 2 * start;
        let side: u8 = 0; // upper

        loop {
            if assign[cur] != 2 {
                break;
            }

            // Assign current input
            assign[cur] = side;
            // Partner at same input switch gets opposite
            assign[cur ^ 1] = 1 - side;

            // Follow the chain through the output side
            let target = perm[cur];
            let out_partner = target ^ 1;
            let partner_src = inv[out_partner];

            // If partner_src is already assigned, chain is closed
            if assign[partner_src] != 2 {
                break;
            }

            // partner_src must go to opposite side
            assign[partner_src] = 1 - side;
            // partner_src's switch-partner goes to same side as `cur`
            cur = partner_src ^ 1;
            // side stays the same
        }
    }

    // Set input switches (layer_off)
    for i in 0..half {
        // If input 2i → lower (1): cross. If input 2i → upper (0): straight.
        switches[layer_off][sw_off + i] = assign[2 * i] == 1;
    }

    // Set output switches (output_layer)
    // Determine output assignment from input assignment
    let mut out_assign = vec![0u8; n];
    for i in 0..n {
        out_assign[perm[i]] = assign[i];
    }
    for j in 0..half {
        // If output 2j comes from lower (1): cross
        switches[output_layer][sw_off + j] = out_assign[2 * j] == 1;
    }

    // Build sub-permutations
    // Input switch i sends one value to upper sub-position i, one to lower sub-position i.
    // Output switch j receives one value from upper sub-position j, one from lower sub-position j.
    // upper_perm[i] = j means: the upper input from switch i routes to upper output at switch j.
    let mut upper_perm = vec![0usize; half];
    let mut lower_perm = vec![0usize; half];

    for i in 0..half {
        let upper_input = if assign[2 * i] == 0 { 2 * i } else { 2 * i + 1 };
        let lower_input = if assign[2 * i] == 0 { 2 * i + 1 } else { 2 * i };
        upper_perm[i] = perm[upper_input] / 2;
        lower_perm[i] = perm[lower_input] / 2;
    }

    // Recurse on sub-networks
    if half >= 2 {
        solve_recursive(&upper_perm, layer_off + 1, sw_off, switches);
        solve_recursive(&lower_perm, layer_off + 1, sw_off + half / 2, switches);
    }
}

/// Route data through a sub-network recursively.
fn route_recursive<T: Copy>(
    inputs: &[T],
    switches: &[Vec<bool>],
    layer_off: usize,
    sw_off: usize,
) -> Vec<T> {
    let n = inputs.len();

    if n == 2 {
        return if switches[layer_off][sw_off] {
            vec![inputs[1], inputs[0]]
        } else {
            inputs.to_vec()
        };
    }

    let half = n / 2;
    let num_layers = 2 * (n.trailing_zeros() as usize) - 1;
    let output_layer = layer_off + num_layers - 1;

    // Apply input switches → split into upper/lower
    let mut upper = Vec::with_capacity(half);
    let mut lower = Vec::with_capacity(half);
    for i in 0..half {
        if switches[layer_off][sw_off + i] {
            lower.push(inputs[2 * i]);
            upper.push(inputs[2 * i + 1]);
        } else {
            upper.push(inputs[2 * i]);
            lower.push(inputs[2 * i + 1]);
        }
    }

    // Route through sub-networks
    let upper_out = route_recursive(&upper, switches, layer_off + 1, sw_off);
    let lower_out = route_recursive(&lower, switches, layer_off + 1, sw_off + half / 2);

    // Apply output switches → merge
    let mut outputs = vec![inputs[0]; n];
    for j in 0..half {
        if switches[output_layer][sw_off + j] {
            outputs[2 * j] = lower_out[j];
            outputs[2 * j + 1] = upper_out[j];
        } else {
            outputs[2 * j] = upper_out[j];
            outputs[2 * j + 1] = lower_out[j];
        }
    }

    outputs
}

fn assert_valid_permutation(perm: &[usize]) {
    let n = perm.len();
    let mut seen = vec![false; n];
    for &p in perm {
        assert!(p < n, "permutation element {p} out of range 0..{n}");
        assert!(!seen[p], "duplicate element {p} in permutation");
        seen[p] = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: route(from_perm(π), identity) must equal π
    fn check_permutation(perm: &[usize]) {
        let net = BenesNetwork::from_permutation(perm);
        let input: Vec<usize> = (0..perm.len()).collect();
        let output = net.route(&input);

        for (i, &p) in perm.iter().enumerate() {
            assert_eq!(
                output[p], i,
                "routing failed: expected output[{}] = {}, got {} for perm {:?}",
                p, i, output[p], perm
            );
        }
    }

    #[test]
    fn test_identity_n2() {
        check_permutation(&[0, 1]);
    }

    #[test]
    fn test_swap_n2() {
        check_permutation(&[1, 0]);
    }

    #[test]
    fn test_identity_n4() {
        check_permutation(&[0, 1, 2, 3]);
    }

    #[test]
    fn test_reversal_n4() {
        check_permutation(&[3, 2, 1, 0]);
    }

    #[test]
    fn test_cycle_n4() {
        check_permutation(&[1, 2, 3, 0]);
    }

    #[test]
    fn test_identity_n8() {
        check_permutation(&[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_reversal_n8() {
        check_permutation(&[7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn test_single_swap_n8() {
        check_permutation(&[1, 0, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_derangement_n8() {
        check_permutation(&[1, 0, 3, 2, 5, 4, 7, 6]);
    }

    #[test]
    fn test_random_n16() {
        // A fixed "random" permutation for reproducibility
        check_permutation(&[11, 3, 14, 7, 0, 9, 5, 13, 2, 15, 8, 4, 10, 1, 12, 6]);
    }

    #[test]
    fn test_large_n64() {
        // A fixed permutation of 0..64 (generated offline, deterministic)
        let mut perm: Vec<usize> = (0..64).collect();
        // Fisher-Yates with fixed seed: swap i with (i * 37 + 7) % remaining
        for i in (1..64).rev() {
            let j = (i * 37 + 7) % (i + 1);
            perm.swap(i, j);
        }
        check_permutation(&perm);
    }

    #[test]
    fn test_large_n1024() {
        let mut perm: Vec<usize> = (0..1024).collect();
        for i in (1..1024).rev() {
            let j = (i * 37 + 7) % (i + 1);
            perm.swap(i, j);
        }
        check_permutation(&perm);
    }

    #[test]
    fn test_network_dimensions() {
        let perm: Vec<usize> = (0..16).collect();
        let net = BenesNetwork::from_permutation(&perm);
        assert_eq!(net.n, 16);
        assert_eq!(net.log_n, 4);
        assert_eq!(net.switches.len(), 7); // 2*4 - 1
        for layer in &net.switches {
            assert_eq!(layer.len(), 8); // 16/2
        }
    }
}
