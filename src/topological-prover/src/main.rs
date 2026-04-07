use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Bowers;
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, PrimeField32};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, StarkConfig};

/// The number of dimensions in our hypercube.
const DIMS: usize = 10;

/// TopologicalRouterAir defines the constraints for a valid sequence of hops in a hypercube.
///
/// Columns:
/// - node_bits[DIMS]: The binary representation of the current node ID.
/// - selectors[DIMS]: Boolean flags indicating which bit is being flipped in this hop.
pub struct TopologicalRouterAir;

impl<F> BaseAir<F> for TopologicalRouterAir {
    fn width(&self) -> usize {
        DIMS * 2
    }
}

impl<AB: AirBuilder> Air<AB> for TopologicalRouterAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        let local_bits = &local[0..DIMS];
        let selectors = &local[DIMS..2 * DIMS];
        let next_bits = &next[0..DIMS];

        // 1. Selector Constraints: Each selector must be boolean (0 or 1)
        for selector in selectors.iter().take(DIMS) {
            builder.assert_bool((*selector).into());
        }

        // 2. Routing Constraint: Exactly one bit must be flipped per hop.
        let mut selector_sum = AB::Expr::zero();
        for selector in selectors.iter().take(DIMS) {
            selector_sum += (*selector).into();
        }
        builder
            .when_transition()
            .assert_eq(selector_sum, AB::Expr::one());

        // 3. Transition Constraint: next_bit[i] = local_bit[i] XOR selector[i]
        // Algebraic XOR for boolean values: A + B - 2AB
        for i in 0..DIMS {
            let a: AB::Expr = local_bits[i].into();
            let b: AB::Expr = selectors[i].into();
            let xor_val = a.clone() + b.clone() - a * b * AB::F::from_canonical_u32(2);
            builder
                .when_transition()
                .assert_eq(next_bits[i].into(), xor_val);
        }
    }
}

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

// Deterministically map a Matrix Event ID to a 10-bit Hypercube coordinate
fn event_to_coordinate(event_id: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(event_id.as_bytes());
    let hash_bytes = hasher.finalize();
    // Take first 4 bytes, convert to u32, mask to DIMS (e.g., 10 bits)
    let val = u32::from_be_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);
    val & ((1 << DIMS) - 1)
}

fn generate_ruma_trace<F: PrimeField32>(json_path: &str) -> RowMajorMatrix<F> {
    let file_data =
        fs::read_to_string(json_path).unwrap_or_else(|_| panic!("Failed to read {}", json_path));
    let events: Vec<Value> = serde_json::from_str(&file_data).expect("Invalid JSON");

    let mut trace = Vec::new();
    let mut current_node = 0; // Keep track of the last node for padding

    println!(
        "Ingested {} real Matrix events. Routing over Hypercube...",
        events.len()
    );

    // Iterate through the DAG edges
    let mut last_event_id: Option<String> = None;

    for event in events {
        let event_id = event["event_id"].as_str().unwrap_or("");
        if event_id.is_empty() {
            continue;
        }

        let target_coord = event_to_coordinate(event_id);

        let mut parents = Vec::new();
        if let Some(prev_events) = event.get("prev_events").and_then(|p| p.as_array()) {
            for p in prev_events {
                if let Some(s) = p.as_str() {
                    if !s.is_empty() {
                        parents.push(s.to_string());
                    }
                }
            }
        }

        if parents.is_empty() {
            if let Some(ref last) = last_event_id {
                parents.push(last.clone());
            }
        }

        for prev_str in parents {
            let mut curr = event_to_coordinate(&prev_str);

            // Route from `curr` to `target_coord` one bit at a time
            while curr != target_coord {
                let diff = curr ^ target_coord;
                let bit_to_flip = diff.trailing_zeros() as usize;
                let next = curr ^ (1 << bit_to_flip);

                let mut row = vec![F::zero(); DIMS * 2];
                for (d, val) in row.iter_mut().enumerate().take(DIMS) {
                    *val = F::from_canonical_u32((curr >> d) & 1);
                }
                row[DIMS + bit_to_flip] = F::one();

                trace.extend(row);
                curr = next;
                current_node = next;
            }
        }
        last_event_id = Some(event_id.to_string());
    }

    if trace.is_empty() {
        // Fallback for empty DAG routing, ensure at least 1 power of 2
        let mut row = vec![F::zero(); DIMS * 2];
        row[DIMS] = F::one(); // flip bit 0
        trace.extend(row);
    }

    let num_rows = trace.len() / (DIMS * 2);
    let padded_rows = num_rows.next_power_of_two();

    for _ in num_rows..padded_rows {
        let bit_to_flip = 0;
        let next = current_node ^ 1;

        let mut row = vec![F::zero(); DIMS * 2];
        for (d, val) in row.iter_mut().enumerate().take(DIMS) {
            *val = F::from_canonical_u32((current_node >> d) & 1);
        }
        row[DIMS + bit_to_flip] = F::one();

        trace.extend(row);
        current_node = next;
    }

    println!("Trace padded to {} rows (Power of 2).", padded_rows);
    RowMajorMatrix::new(trace, DIMS * 2)
}

fn main() {
    tracing_subscriber::fmt::init();

    println!("--- Pure Plonky3 Topological Router Benchmark ---");
    println!("Hypercube dimensions: {}", DIMS);

    // Generate Trace
    let now = std::time::Instant::now();

    // Support running from both the workspace root and the crate directory
    let json_path = if std::path::Path::new("res/real_matrix_state.json").exists() {
        "res/real_matrix_state.json"
    } else {
        "../res/real_matrix_state.json"
    };

    let trace = generate_ruma_trace::<BabyBear>(json_path);
    let num_rows = trace.height();
    let log_n = trace.height().trailing_zeros() as usize;

    println!("Rows (Hops): {}", num_rows);
    println!("Trace generation took: {:?}", now.elapsed());

    // Evaluate Constraints natively (just measuring iteration)
    println!("--- Evaluating Constraints over Execution Trace ---");
    let eval_start = std::time::Instant::now();
    let mut constraint_violations = 0;
    for i in 0..num_rows - 1 {
        let row = &trace.values[i * DIMS * 2..(i + 1) * DIMS * 2];
        let next_row = &trace.values[(i + 1) * DIMS * 2..(i + 2) * DIMS * 2];

        let local_bits = &row[0..DIMS];
        let selectors = &row[DIMS..DIMS * 2];
        let next_bits = &next_row[0..DIMS];

        let mut selector_sum = BabyBear::zero();
        for &s in selectors {
            selector_sum += s;
        }
        if selector_sum != BabyBear::one() {
            constraint_violations += 1;
        }

        for j in 0..DIMS {
            let xor_val = local_bits[j] + selectors[j]
                - local_bits[j] * selectors[j] * BabyBear::from_canonical_u32(2);
            if next_bits[j] != xor_val {
                constraint_violations += 1;
            }
        }
    }
    println!(
        "Constraint Evaluation Time ({} rows): {:?}",
        num_rows,
        eval_start.elapsed()
    );
    assert_eq!(
        constraint_violations, 0,
        "Trace contains constraint violations!"
    );

    println!(
        "Execution trace of {} hops generated and constraint-verified successfully in memory.",
        num_rows
    );
    println!("This trace is Degree-2 and uses only {} columns.", DIMS * 2);
    println!(
        "RAM usage for this trace: ~{:.1} MB",
        (num_rows * DIMS * 2 * 4) as f64 / 1024.0 / 1024.0
    );

    println!("\n--- Setting up Vanilla Plonky3 STARK Configuration ---");

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});

    type Compress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;
    let compress = Compress::new(byte_hash);

    type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, Compress, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Radix2Bowers;

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    use p3_challenger::{HashChallenger, SerializingChallenger32};

    let pcs = TwoAdicFriPcs::new(log_n, dft, val_mmcs, fri_config);
    let config = StarkConfig::new(pcs);

    let hash_challenger = HashChallenger::new(vec![], byte_hash);
    let mut challenger = SerializingChallenger32::new(hash_challenger);
    let air = TopologicalRouterAir;

    println!("--- Generating STARK Proof ---");
    let prove_start = std::time::Instant::now();

    // THIS WILL NOW COMPILE AND RUN NATIVELY
    let _proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    println!("STARK Proving Time: {:?}", prove_start.elapsed());

    // Serialize the proof to get the exact Byte size for the paper!
    let proof_bytes = bincode::serialize(&_proof).unwrap();
    println!("Proof Size: {} bytes", proof_bytes.len());

    // Save proof to disk for the paper artifacts
    std::fs::write("proof.bin", &proof_bytes).expect("Failed to write proof.bin");

    // Also write it as JSON and print the head!
    let proof_json = serde_json::to_string_pretty(&_proof).expect("Failed to serialize to JSON");
    std::fs::write("proof.json", &proof_json).expect("Failed to write proof.json");

    println!("\n--- Proof Structure Snippet (Top 40 lines) ---");
    let lines: Vec<&str> = proof_json.lines().take(40).collect();
    for line in lines {
        println!("{}", line);
    }
    println!("... (full JSON trace saved to purely-topological-prover/proof.json)");

    println!("\n--- Verifying STARK Proof ---");
    // Re-initialize a clean challenger for the Verifier
    let verifier_hash_challenger = HashChallenger::new(vec![], ByteHash {});
    let mut verifier_challenger = SerializingChallenger32::new(verifier_hash_challenger);

    let verify_start = std::time::Instant::now();
    p3_uni_stark::verify(&config, &air, &mut verifier_challenger, &_proof, &vec![])
        .expect("STARK Proof verification failed!");
    println!("STARK Verification Time: {:?}", verify_start.elapsed());
    println!("Verification successful! The Topological Math holds.");
}
