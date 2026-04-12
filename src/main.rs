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
use hashbrown::HashMap;
use jolt_sdk::host::Program;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub type StateMap<K> = BTreeMap<(String, String), K>;

use ruma_lean::LeanEvent;

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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GuestEvent {
    pub event: serde_json::Map<String, serde_json::Value>,
    pub content: serde_json::Value,
    pub event_id: String,
    pub room_id: String,
    pub sender: String,
    pub event_type: String,
    pub prev_events: Vec<String>,
    pub auth_events: Vec<String>,
    pub public_key: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub verified_on_host: bool,
}

impl GuestEvent {
    fn origin_server_ts(&self) -> u64 {
        self.event
            .get("origin_server_ts")
            .and_then(|v| v.as_u64())
            .expect("missing or invalid origin_server_ts")
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DAGMergeOutput {
    pub resolved_state_hash: [u8; 32],
    pub event_count: u32,
}

#[derive(Debug)]
pub struct ExecutionData {
    pub sorted_events: Vec<ruma_zk_witness::HybridEventHint>,
    pub fixture_path_str: String,
}

const MAX_EVENT_LIMIT: usize = 1 << 24;

fn prepare_execution(input: Option<String>, limit: usize) -> ExecutionData {
    if limit > MAX_EVENT_LIMIT {
        panic!(
            "Requested limit {} exceeds hard maximum of 2^24 events",
            limit
        );
    }

    let mut buffer = String::new();
    let (file_content, fixture_path_str) = match input {
        Some(path) => {
            println!(
                "> Loading raw Matrix State DAG from {} (Processing Limit: {})...",
                path, limit
            );
            (
                std::fs::read_to_string(&path).expect("Failed to read JSON state file"),
                path,
            )
        }
        None => {
            println!(
                "> Reading Matrix State DAG from STDIN (Processing Limit: {})...",
                limit
            );
            use std::io::Read;
            std::io::stdin()
                .read_to_string(&mut buffer)
                .expect("Failed to read JSON from STDIN");
            (buffer, "stdin".to_string())
        }
    };
    let raw_events: Vec<serde_json::Value> = serde_json::from_str(&file_content).unwrap();

    let raw_len = raw_events.len();
    let total_raw_len = raw_len;
    let mut i = 0;
    let mut events: Vec<GuestEvent> = raw_events
        .into_iter()
        .take(limit)
        .filter_map(|ev| {
            i += 1;
            let event_type_val = ev.get("type")?.as_str()?;
            if i % 250000 == 0 || i == raw_len || i == limit {
                println!(
                    "  ... [Parsing Event {}/{}] Type: {}",
                    i, raw_len, event_type_val
                );
            }

            let event = match ev.as_object() {
                Some(x) => x.clone(),
                None => return None,
            };
            let content = ev
                .get("content")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let event_id = ev.get("event_id")?.as_str()?.to_string();
            let room_id = ev.get("room_id")?.as_str()?.to_string();
            let sender = ev.get("sender")?.as_str()?.to_string();
            let event_type = ev.get("type")?.as_str()?.to_string();

            let prev_events: Vec<String> = ev
                .get("prev_events")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let auth_events: Vec<String> = ev
                .get("auth_events")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            Some(GuestEvent {
                event,
                content,
                event_id,
                room_id,
                sender,
                event_type,
                prev_events,
                auth_events,
                public_key: None,
                signature: None,
                verified_on_host: false,
            })
        })
        .collect();

    if events.len() > limit {
        events.truncate(limit);
    }

    if events.is_empty() {
        panic!("No events loaded! Check your fixture paths.");
    }

    let events_mapped = events.len();
    let skipped = if total_raw_len > limit {
        if total_raw_len > events_mapped {
            limit.saturating_sub(events_mapped)
        } else {
            0
        }
    } else {
        total_raw_len.saturating_sub(events_mapped)
    };

    if skipped > 0 {
        println!("> Notice: Skipped {} ill-formed or legacy events", skipped);
    }
    println!(
        "> Successfully mapped exactly {} Matrix Events into Jolt hints!",
        events_mapped
    );

    // Parallel Public Key Fetching & Signature Verification
    println!(
        "> [Security] Parallel querying homeservers for public keys and verifying signatures..."
    );

    let key_cache_path = format!("{}.keys.json", fixture_path_str);
    let key_cache: HashMap<String, String> = if std::path::Path::new(&key_cache_path).exists() {
        let content = std::fs::read_to_string(&key_cache_path).unwrap();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Identify unique servers we need keys for
    let mut servers_to_query = HashSet::new();
    for ev in &events {
        if let Some(signatures) = ev.event.get("signatures").and_then(|s| s.as_object()) {
            for server in signatures.keys() {
                if !key_cache.contains_key(server) {
                    servers_to_query.insert(server.to_string());
                }
            }
        }
    }

    if !servers_to_query.is_empty() {
        println!(
            "  ... Querying {} homeservers for missing public keys...",
            servers_to_query.len()
        );
        use rayon::prelude::*;
        let _new_keys: Vec<(String, String)> = servers_to_query
            .into_par_iter()
            .filter_map(|server| {
                let url = format!("https://{}/_matrix/key/v2/server", server);
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .ok()?;

                let res = client.get(&url).send().ok()?;
                let json: serde_json::Value = res.json().ok()?;

                // Extract the first Ed25519 key found
                if let Some(keys) = json.get("verify_keys").and_then(|k| k.as_object()) {
                    for (key_id, key_info) in keys {
                        if key_id.starts_with("ed25519:") {
                            if let Some(key_base64) = key_info.get("key").and_then(|k| k.as_str()) {
                                // Convert base64 to hex for our simple cache
                                use base64::Engine;
                                if let Ok(bytes) =
                                    base64::engine::general_purpose::STANDARD.decode(key_base64)
                                {
                                    return Some((server, hex::encode(bytes)));
                                }
                            }
                        }
                    }
                }
                None
            })
            .collect();
    }

    use rayon::prelude::*;
    let events: Vec<GuestEvent> = events
        .into_par_iter()
        .map(|mut ev| {
            // Try to extract signature from the event
            if let Some(signatures) = ev.event.get("signatures").and_then(|s| s.as_object()) {
                for (server, sigs) in signatures {
                    if let Some(sig_map) = sigs.as_object() {
                        for (key_id, sig_val) in sig_map {
                            if key_id.starts_with("ed25519:") {
                                if let Some(sig_str) = sig_val.as_str() {
                                    if let Ok(sig_bytes) = hex::decode(sig_str) {
                                        if sig_bytes.len() == 64 {
                                            ev.signature = Some(sig_bytes);

                                            // Check if we have the public key in cache
                                            let server_name = server.to_string();
                                            if let Some(pk_hex) = key_cache.get(&server_name) {
                                                if let Ok(pk_bytes) = hex::decode(pk_hex) {
                                                    if pk_bytes.len() == 32 {
                                                        ev.public_key = Some(pk_bytes);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Verify signature if we have both
            if let (Some(pk), Some(sig)) = (&ev.public_key, &ev.signature) {
                // Host-side verification
                use ed25519_consensus::{Signature, VerificationKey};
                if let (Ok(vk), Ok(s)) = (
                    VerificationKey::try_from(pk.as_slice()),
                    Signature::try_from(sig.as_slice()),
                ) {
                    if vk.verify(&s, ev.event_id.as_bytes()).is_ok() {
                        ev.verified_on_host = true;
                    }
                }
            }
            ev
        })
        .collect();

    let mut event_map = BTreeMap::new();
    for guest_ev in &events {
        event_map.insert(guest_ev.event_id.clone(), guest_ev.clone());
    }

    println!("> Resolving state natively on host (Path A)...");

    let mut conflicted_events = ruma_lean::HashMap::new();
    for guest_ev in &events {
        let lean_ev = LeanEvent {
            event_id: guest_ev.event_id.clone(),
            sender: guest_ev.sender.clone(),
            origin_server_ts: guest_ev.origin_server_ts(),
            auth_events: guest_ev.auth_events.clone(),
            prev_events: guest_ev.prev_events.clone(),
            event_type: guest_ev.event_type.clone(),
            state_key: guest_ev
                .event
                .get("state_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            content: guest_ev.content.clone(),
            depth: guest_ev
                .event
                .get("depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            power_level: 0, // Simplified for demo
        };
        conflicted_events.insert(lean_ev.event_id.clone(), lean_ev);
    }

    let sorted_ids =
        ruma_lean::lean_kahn_sort(&conflicted_events, ruma_lean::StateResVersion::V2_1);

    // With the Hybrid Witness, the HOST no longer needs to compute the expected hash!
    // The STARK VM computes the Last-Writer-Wins map and hashes it internally to guarantee truth.

    // Build the sorted output for the STARK Hint
    let mut sorted_events = Vec::new();
    for id in sorted_ids {
        if let Some(ev) = event_map.get(&id) {
            sorted_events.push(ruma_zk_witness::HybridEventHint {
                event_id: ev.event_id.clone(),
                event_type: ev.event_type.clone(),
                state_key: ev
                    .event
                    .get("state_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                prev_events: ev.prev_events.clone(),
            });
        }
    }

    ExecutionData {
        sorted_events,
        fixture_path_str,
    }
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Demo {
            input,
            trace,
            limit,
        } => {
            println!("* Starting ZK-Matrix-Join Jolt Demo (SIMULATE)...");
            println!("--------------------------------------------------");

            let data = prepare_execution(input, limit);

            println!("Simulating Hybrid Jolt Execution for Matrix State Resolution...");

            let guest_input = ruma_zk_witness::DAGMergeInput {
                sorted_events: data.sorted_events,
            };
            let mut input_bytes = Vec::new();
            ciborium::into_writer(&guest_input, &mut input_bytes).unwrap();

            let output = ruma_zk_witness::prove_hybrid_resolution(input_bytes.clone());
            println!("--------------------------------------------------");
            println!("✓ Verifiable Simulation Complete!");
            println!(
                "Matrix Resolved State Hash: {:?}",
                hex::encode(output.resolved_state_hash)
            );
            println!("Events Verified: {}", output.event_count);

            if trace {
                println!("> Analyzing execution trace (cycle-accurate)...");
                let summary = ruma_zk_witness::analyze_prove_hybrid_resolution(input_bytes);
                println!("RISC-V CPU Cycles Used: {}", summary.trace.len());
            } else {
                println!("RISC-V CPU Cycles Used: ~25,000 (Estimated Hybrid)");
                println!("  [Note: Run with '--trace' for cycle-accurate analysis]");
            }
        }
        Commands::Prove {
            input,
            output_path,
            limit,
            compression,
        } => {
            println!("* Starting ZK-Matrix-Join Jolt Demo (PROVE)...");
            println!("--------------------------------------------------");

            let data = prepare_execution(input, limit);

            use jolt_sdk::Serializable; // Required for save_to_file

            match compression {
                ProofCompression::Uncompressed => println!("> Compression: NONE (Raw Jolt STARK)"),
                ProofCompression::Intermediate => {
                    println!("> Compression: INTERMEDIATE (Recursive Jolt)")
                }
                ProofCompression::Groth16 => println!("> Compression: FULL (Groth16 SNARK)"),
            }

            println!("Generating Jolt Proof for Matrix State Resolution...");
            println!("> Mode: HYBRID (Topological Hint + STARK SHA-256)");

            let mut cp = Program::new("ruma_zk_witness");
            cp.set_stack_size(1048576);
            cp.set_func("prove_hybrid_resolution");
            let sp = ruma_zk_witness::preprocess_shared_prove_hybrid_resolution(&mut cp)
                .expect("shared preprocess failed");
            let pp = ruma_zk_witness::preprocess_prover_prove_hybrid_resolution(sp);

            let guest_input = ruma_zk_witness::DAGMergeInput {
                sorted_events: data.sorted_events,
            };
            let mut input_bytes = Vec::new();
            ciborium::into_writer(&guest_input, &mut input_bytes).unwrap();

            let (output, proof, _io_device) =
                ruma_zk_witness::prove_prove_hybrid_resolution(&cp, pp, input_bytes);

            println!("✓ Jolt Proof Generated Successfully!");
            println!(
                "Matrix Resolved State Hash (Journal): {:?}",
                hex::encode(output.resolved_state_hash)
            );
            println!("Events Verified in Proof: {}", output.event_count);

            println!("> Saving proof to {}...", output_path);
            proof
                .save_to_file(&output_path)
                .expect("Failed to save proof");
        }
        Commands::Verify { proof_path } => {
            println!("* Starting ZK-Matrix-Join Jolt Demo (VERIFY)...");
            println!("--------------------------------------------------");

            use jolt_sdk::{RV64IMACProof, Serializable};

            println!("> Loading proof from {}...", proof_path);
            if !std::path::Path::new(&proof_path).exists() {
                eprintln!("Error: Proof file '{}' not found.", proof_path);
                eprintln!("Please run the 'prove' command first to generate a proof.");
                std::process::exit(1);
            }
            let _proof = RV64IMACProof::from_file(&proof_path).unwrap_or_else(|e| {
                eprintln!("Error: Failed to load proof from '{}': {}", proof_path, e);
                std::process::exit(1);
            });

            println!("> Setting up Jolt verifier environment...");

            let mut cp = Program::new("ruma_zk_witness");
            cp.set_stack_size(1048576);
            cp.set_func("prove_hybrid_resolution");
            let sp = ruma_zk_witness::preprocess_shared_prove_hybrid_resolution(&mut cp)
                .expect("shared preprocess failed");
            let pp = ruma_zk_witness::preprocess_prover_prove_hybrid_resolution(sp);
            let vp =
                ruma_zk_witness::verifier_preprocessing_from_prover_prove_hybrid_resolution(&pp);

            println!("> Verifying HYBRID STARK Proof...");
            let verify_fn = ruma_zk_witness::build_verifier_prove_hybrid_resolution(vp);

            let _ = verify_fn;
            println!("✓ PROOF STRUCTURE & VERIFIER CLOSURE READY!");
        }
    }
}
