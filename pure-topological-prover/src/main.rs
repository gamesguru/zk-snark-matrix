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
use rand::Rng;

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

fn generate_trace<F: PrimeField32>(num_hops: usize) -> RowMajorMatrix<F> {
    let mut rng = rand::thread_rng();
    let mut trace = Vec::with_capacity(num_hops * DIMS * 2);

    let mut current_node: u32 = 0;

    for _ in 0..num_hops {
        let mut row = vec![F::zero(); DIMS * 2];

        // Fill node bits
        for (i, val) in row.iter_mut().enumerate().take(DIMS) {
            *val = F::from_canonical_u32((current_node >> i) & 1);
        }

        // Randomly pick exactly one bit to flip for the next hop
        let flip_idx = rng.gen_range(0..DIMS);
        row[DIMS + flip_idx] = F::one();

        trace.extend(row);
        current_node ^= 1 << flip_idx;
    }

    RowMajorMatrix::new(trace, DIMS * 2)
}

fn main() {
    tracing_subscriber::fmt::init();

    let log_n = 17; // 131,072 rows
    let num_rows = 1 << log_n;

    println!("--- Pure Plonky3 Topological Router Benchmark ---");
    println!("Dimensions: {}", DIMS);
    println!("Rows (Hops): {}", num_rows);

    // Generate Trace
    let now = std::time::Instant::now();
    let trace = generate_trace::<BabyBear>(num_rows);
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
        "Execution trace of 131,072 hops generated and constraint-verified successfully in memory."
    );
    println!("This trace is Degree-2 and uses only {} columns.", DIMS * 2);
    println!(
        "RAM usage for this trace: ~{} MB",
        (num_rows * DIMS * 2 * 4) / 1024 / 1024
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
}
