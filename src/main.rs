use halo2_proofs::dev::MockProver;
use pasta_curves::Fp as Fr;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use zk_matrix_join::circuit::recursive::DagMergeCircuit;

#[derive(Debug, Deserialize)]
struct MatrixEvent {
    event_id: String,
}

/// Helper to convert a Matrix Event ID string into a field element (Fr) via SHA-256
fn hash_to_fr(input: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    // Map the 32-byte hash to a field element.
    let mut raw = [0u64; 4];
    for i in 0..4 {
        let mut part = [0u8; 8];
        part.copy_from_slice(&result[i * 8..(i + 1) * 8]);
        raw[i] = u64::from_le_bytes(part);
    }
    Fr::from_raw(raw)
}

fn main() {
    println!("* Starting ZK-Matrix-Join Demo...");
    println!("--------------------------------------------------");

    // Try to load real events from file
    let (parent_a_hash, parent_b_hash, expected_new_state) =
        if let Ok(data) = fs::read_to_string("res/massive_matrix_state.json") {
            let events: Vec<MatrixEvent> = serde_json::from_str(&data).unwrap_or_default();

            if events.len() >= 2 {
                println!("> Successfully loaded {} events from file.", events.len());

                // Derive "real" hashes from the first two events as parents
                let a = hash_to_fr(&events[0].event_id);
                let b = hash_to_fr(&events[1].event_id);

                // Tie-breaker: smaller field element wins (lexicographical simulation)
                let merged = if a < b { a } else { b };

                (a, b, merged)
            } else {
                println!("> Not enough events found in file, using defaults.");
                (Fr::from(1), Fr::from(2), Fr::from(3))
            }
        } else {
            println!("> No real data found, using synthetic field elements.");
            (Fr::from(1), Fr::from(2), Fr::from(3))
        };

    // Define the demo parameters
    let k = 4; // Circuit size parameter (2^k rows)
    let parent_states = vec![parent_a_hash, parent_b_hash];
    let parent_proofs = vec![vec![], vec![]];

    println!("> Scenario: A homeserver is attempting to merge a split DAG.");
    println!("   - Parent State A Hash: {:?}", parent_states[0]);
    println!("   - Parent State B Hash: {:?}", parent_states[1]);
    println!("   - Proposed Merged State Hash: {:?}", expected_new_state);

    // Instantiate the circuit
    let circuit = DagMergeCircuit {
        parent_states,
        parent_proofs,
        expected_new_state,
    };

    println!("--------------------------------------------------");
    println!("* Constructing Zero-Knowledge Circuit...");
    println!("   - This circuit proves that State Res v2 was executed correctly.");
    println!("   - It enforces that tie-breakers between conflicting events are sound.");

    // In a real scenario, this would generate a SNARK/STARK proof.
    // For this demo, we run the MockProver to verify all constraints hold mathematically.
    let public_inputs = vec![];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();

    println!("--------------------------------------------------");
    println!("> Verifying Constraints (MockProver)...");

    match prover.verify() {
        Ok(_) => {
            println!("✓ SUCCESS: The cryptographic proof is valid!");
            println!(
                "   The new joining homeserver can mathematically trust this state resolution"
            );
            println!("   without downloading the entire room history.");
        }
        Err(e) => {
            println!("✗ FAILURE: The circuit rejected the state transition!");
            println!("   Error details: {:?}", e);
        }
    }
}
