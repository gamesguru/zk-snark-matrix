// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]

use clap::Parser;
use ruma_zk_topair::{prove_matrix_resolution, MatrixEvent, RawProof};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::time::Instant;

pub type StateMap<K> = BTreeMap<(String, String), K>;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum ProofCompression {
    #[default]
    Uncompressed,
    Intermediate,
    Groth16,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Run an end-to-end simulation
    Demo {
        /// Path to the Matrix state JSON fixture
        #[arg(short, long)]
        input: Option<String>,

        /// Enable cycle-accurate trace analysis (Warning: High CPU/RAM usage)
        #[arg(short, long)]
        trace: bool,

        /// Limit the number of events processed (max 2^24)
        #[arg(short, long, default_value = "1000")]
        limit: usize,
    },
    /// Generate a full cryptographic proof
    Prove {
        /// Path to the Matrix state JSON fixture
        #[arg(short, long)]
        input: Option<String>,

        /// Path to save the generated proof
        #[arg(short, long, default_value = "proof.bin")]
        output_path: String,

        /// Limit the number of events processed (max 2^24)
        #[arg(short, long, default_value = "1000")]
        limit: usize,

        /// Proof compression level
        #[arg(short, long, value_enum, default_value_t = ProofCompression::Uncompressed)]
        compression: ProofCompression,
    },
    /// Verify an existing cryptographic proof
    Verify {
        /// Path to the proof file
        #[arg(short, long, default_value = "proof.bin")]
        proof_path: String,
    },
}

struct ExecutionData {
    events: Vec<MatrixEvent>,
}

fn prepare_execution(input_path: Option<String>, limit: Option<usize>) -> ExecutionData {
    println!("> Loading Matrix state from fixture...");
    let mut file_content = String::new();
    let _fixture_path_str = if let Some(path) = input_path {
        File::open(&path)
            .expect("Failed to open input file")
            .read_to_string(&mut file_content)
            .expect("Failed to read input file");
        path
    } else {
        std::io::stdin()
            .read_to_string(&mut file_content)
            .expect("Failed to read from STDIN");
        "STDIN".to_string()
    };

    let raw_events: Vec<serde_json::Value> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");
    let limit = limit.unwrap_or(raw_events.len());
    let events: Vec<MatrixEvent> = raw_events
        .into_iter()
        .take(limit)
        .map(|v| MatrixEvent {
            event_id: v["event_id"].as_str().unwrap_or_default().to_string(),
            event_type: v["event_type"].as_str().unwrap_or_default().to_string(),
            state_key: v["state_key"].as_str().unwrap_or_default().to_string(),
            prev_events: v["prev_events"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect(),
            power_level: v["power_level"].as_u64().unwrap_or(100),
        })
        .collect();

    ExecutionData { events }
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Demo {
            input,
            trace: _,
            limit,
        } => {
            println!("* Starting ZK-Matrix-Join CTopology Demo (Topological AIR)...");
            println!("--------------------------------------------------");

            let data = prepare_execution(input, Some(limit));

            println!("Prover: Invoking CTopology resolution and proof generation...");
            let start = Instant::now();
            match prove_matrix_resolution(data.events, 10) {
                Ok(proof) => {
                    println!("✓ SUCCESS: Matrix state formally RESOLVED trustlessly.");
                    println!("  - Execution and Proof took {:?}", start.elapsed());
                    println!("Merkle Root: {}", hex::encode(proof.root));
                }
                Err(e) => {
                    println!("✗ FAILURE: {}", e);
                }
            }
        }
        Commands::Prove {
            input,
            output_path,
            limit,
            compression: _,
        } => {
            let data = prepare_execution(input, Some(limit));
            println!("Generating CTopology Proof...");
            match prove_matrix_resolution(data.events, 10) {
                Ok(proof) => {
                    println!("Saving proof to {}...", output_path);
                    let proof_bytes =
                        bincode::serialize(&proof).expect("Failed to serialize proof");
                    std::fs::write(output_path, proof_bytes).expect("Failed to write proof file");
                }
                Err(e) => println!("Error: {}", e),
            }
        }
        Commands::Verify { proof_path } => {
            println!("Loading CTopology proof from {}...", proof_path);
            let proof_bytes = std::fs::read(&proof_path).expect("Failed to read proof file");
            let proof: RawProof =
                bincode::deserialize(&proof_bytes).expect("Failed to deserialize proof");

            println!("Verifying Merkle openings...");
            let mut all_ok = true;
            for opening in &proof.openings {
                if !proof.verify_opening(opening) {
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                println!("✓ Proof verified successfully!");
                println!("Root: {}", hex::encode(proof.root));
            } else {
                println!("✗ Proof verification FAILED!");
            }
        }
    }
}
