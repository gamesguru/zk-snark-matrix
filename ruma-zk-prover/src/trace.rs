//! Execution trace builder for the graph-native STARK framework.
//!
//! The trace is a 2D grid of width W × depth D:
//!
//! ```text
//!   Layer 0        : Input layer (N events, padded to W = 2^d)
//!   Layers 1..2d-1 : Beneš routing layers (switch constraints)
//!   Layer 2d       : Logic layer (application-specific tie-breaking)
//! ```
//!
//! Each routing layer contains W/2 switches. Each switch has:
//!   - 1 switch flag (s ∈ {0,1})
//!   - 2 inputs (a, b)
//!   - 1 output (y)
//!
//! The constraint `y ⊕ a ⊕ s·(a ⊕ b) = 0` (Lemma 4.2) is checked per switch.

use crate::field::{routing_constraint, switch_validity, GF2};
use crate::waksman::BenesNetwork;

/// A single switch in a routing layer.
#[derive(Debug, Clone, Copy)]
pub struct SwitchWitness {
    /// Switch flag: 0 = straight, 1 = cross.
    pub flag: GF2,
    /// Top input.
    pub input_a: GF2,
    /// Bottom input.
    pub input_b: GF2,
    /// Output (must equal `a` if flag=0, `b` if flag=1).
    pub output: GF2,
}

impl SwitchWitness {
    /// Check that this switch satisfies the routing constraint (Lemma 4.2).
    #[inline]
    pub fn check(&self) -> bool {
        switch_validity(self.flag) == GF2::ZERO
            && routing_constraint(self.flag, self.input_a, self.input_b, self.output) == GF2::ZERO
    }
}

/// The full execution trace for a Beneš-routed DAG reduction.
#[derive(Debug)]
pub struct ExecutionTrace {
    /// Width of the trace (W = 2^d, padded).
    pub width: usize,
    /// Number of Beneš routing layers (2d - 1).
    pub routing_depth: usize,
    /// Input values (the DAG node data, in topological order).
    pub inputs: Vec<GF2>,
    /// Switch witnesses for each routing layer.
    /// `routing_layers[layer][switch_index]`
    pub routing_layers: Vec<Vec<SwitchWitness>>,
    /// Output values after routing (should match the permuted inputs).
    pub outputs: Vec<GF2>,
}

impl ExecutionTrace {
    /// Build an execution trace from input data and a Beneš network.
    ///
    /// `inputs`: the GF2 values to route (padded to 2^d with zeros).
    /// `network`: the Beneš network with pre-computed switch settings.
    pub fn build(inputs: &[GF2], network: &BenesNetwork) -> Self {
        let n = network.n;
        assert_eq!(inputs.len(), n);

        let mut routing_layers = Vec::with_capacity(network.switches.len());

        // Route data through the network layer by layer, recording witnesses.
        // We track the current state of all N wires.
        let mut wires = inputs.to_vec();

        for (_layer_idx, layer_switches) in network.switches.iter().enumerate() {
            let mut witnesses = Vec::with_capacity(layer_switches.len());
            let mut next_wires = vec![GF2::ZERO; n];

            // Apply switches at this layer
            // Each switch i operates on wire pair (2i, 2i+1)
            for (i, &is_cross) in layer_switches.iter().enumerate() {
                let a = wires[2 * i];
                let b = wires[2 * i + 1];
                let flag = GF2::from(is_cross);
                let output_top;
                let output_bot;

                if is_cross {
                    output_top = b;
                    output_bot = a;
                } else {
                    output_top = a;
                    output_bot = b;
                }

                witnesses.push(SwitchWitness {
                    flag,
                    input_a: a,
                    input_b: b,
                    output: output_top,
                });

                next_wires[2 * i] = output_top;
                next_wires[2 * i + 1] = output_bot;
            }

            routing_layers.push(witnesses);
            wires = next_wires;
        }

        ExecutionTrace {
            width: n,
            routing_depth: network.switches.len(),
            inputs: inputs.to_vec(),
            routing_layers,
            outputs: wires,
        }
    }

    /// Verify all routing constraints in the trace.
    /// Returns the number of constraint violations (0 = valid trace).
    pub fn verify_constraints(&self) -> usize {
        let mut violations = 0;
        for (layer_idx, layer) in self.routing_layers.iter().enumerate() {
            for (sw_idx, sw) in layer.iter().enumerate() {
                if !sw.check() {
                    violations += 1;
                    eprintln!(
                        "Constraint violation: layer={}, switch={}, flag={}, a={}, b={}, y={}",
                        layer_idx, sw_idx, sw.flag, sw.input_a, sw.input_b, sw.output
                    );
                }
            }
        }
        violations
    }

    /// Total number of switches (constraints) in the trace.
    pub fn num_constraints(&self) -> usize {
        self.routing_layers.iter().map(|layer| layer.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waksman::BenesNetwork;

    #[test]
    fn test_identity_trace() {
        let perm = vec![0, 1, 2, 3];
        let net = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<GF2> = vec![GF2::ZERO, GF2::ONE, GF2::ZERO, GF2::ONE];
        let trace = ExecutionTrace::build(&inputs, &net);

        assert_eq!(trace.verify_constraints(), 0);
        // Identity permutation: outputs should match inputs
        assert_eq!(trace.outputs, inputs);
    }

    #[test]
    fn test_reversal_trace() {
        let perm = vec![3, 2, 1, 0];
        let net = BenesNetwork::from_permutation(&perm);
        let inputs: Vec<GF2> = vec![GF2::ZERO, GF2::ONE, GF2::ONE, GF2::ZERO];
        let trace = ExecutionTrace::build(&inputs, &net);

        assert_eq!(trace.verify_constraints(), 0);
    }

    #[test]
    fn test_swap_trace() {
        let perm = vec![1, 0];
        let net = BenesNetwork::from_permutation(&perm);
        let inputs = vec![GF2::ONE, GF2::ZERO];
        let trace = ExecutionTrace::build(&inputs, &net);

        assert_eq!(trace.verify_constraints(), 0);
        assert_eq!(trace.outputs, vec![GF2::ZERO, GF2::ONE]);
    }

    #[test]
    fn test_large_trace_n16() {
        let perm = vec![11, 3, 14, 7, 0, 9, 5, 13, 2, 15, 8, 4, 10, 1, 12, 6];
        let net = BenesNetwork::from_permutation(&perm);
        // Alternating bits
        let inputs: Vec<GF2> = (0..16).map(|i| GF2::new(i as u8 & 1)).collect();
        let trace = ExecutionTrace::build(&inputs, &net);

        assert_eq!(trace.verify_constraints(), 0);
        assert_eq!(trace.width, 16);
        assert_eq!(trace.routing_depth, 7); // 2*4 - 1
    }

    #[test]
    fn test_constraint_count() {
        let perm: Vec<usize> = (0..8).collect();
        let net = BenesNetwork::from_permutation(&perm);
        let inputs = vec![GF2::ZERO; 8];
        let trace = ExecutionTrace::build(&inputs, &net);

        // 5 layers × 4 switches = 20 constraints
        assert_eq!(trace.num_constraints(), 20);
    }
}
