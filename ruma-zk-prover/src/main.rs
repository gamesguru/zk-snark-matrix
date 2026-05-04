// Copyright 2026 Shane Jaroch
// Licensed under the Apache License, Version 2.0

#![forbid(unsafe_code)]

use clap::Parser;
use ruma_zk_topological_air::MatrixEvent;

use std::fs::File;
use std::io::Read;
use std::time::Instant;

use ruma_zk_prover::field::GF2;
use ruma_zk_prover::trace::ExecutionTrace;
use ruma_zk_prover::waksman::BenesNetwork;

#[derive(Parser, Debug)]
#[command(author, version, about = "Graph-native STARK witness generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Print the Cryptographic Circuit Fingerprint (VK Hash)
    Fingerprint,
    /// Generate a witness trace from Matrix state events
    Witness {
        /// Path to the Matrix state JSON fixture
        #[arg(short, long)]
        input: Option<String>,

        /// Limit the number of events processed
        #[arg(short, long, default_value = "1000")]
        limit: usize,
    },
}

fn load_events(input_path: Option<String>, limit: usize) -> Vec<MatrixEvent> {
    let mut file_content = String::new();
    if let Some(path) = input_path {
        File::open(&path)
            .expect("Failed to open input file")
            .read_to_string(&mut file_content)
            .expect("Failed to read input file");
    } else {
        std::io::stdin()
            .read_to_string(&mut file_content)
            .expect("Failed to read from STDIN");
    };

    let raw_events: Vec<serde_json::Value> =
        serde_json::from_str(&file_content).expect("Failed to parse JSON");
    raw_events
        .into_iter()
        .take(limit)
        .map(|v| {
            // Handle both schemas: real Matrix uses "type", test fixtures use "event_type"
            let event_type = v["type"]
                .as_str()
                .or_else(|| v["event_type"].as_str())
                .unwrap_or_default()
                .to_string();

            // Power level: check content.power_level, then top-level, default 100
            let power_level = v["content"]["power_level"]
                .as_u64()
                .or_else(|| v["power_level"].as_u64())
                .unwrap_or(100);

            MatrixEvent {
                event_id: v["event_id"].as_str().unwrap_or_default().to_string(),
                event_type,
                state_key: v["state_key"].as_str().unwrap_or_default().to_string(),
                prev_events: v["prev_events"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect(),
                power_level,
            }
        })
        .collect()
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Fingerprint => {
            println!("ruma-zk-prover v{}", env!("CARGO_PKG_VERSION"));
            let vk_hash =
                ruma_zk_prover::merkle::keccak256(&ruma_zk_prover::expander::DEFAULT_SEED);
            println!("Circuit VK Hash: {}", hex::encode(vk_hash));
        }
        Commands::Witness { input, limit } => {
            println!("Graph-Native STARK Witness Generator");
            println!("====================================");

            let events = load_events(input, limit);
            let n_events = events.len();
            let n_padded = n_events.next_power_of_two().max(2);

            println!("  Events loaded: {}", n_events);
            println!(
                "  Padded width:  {} (2^{})",
                n_padded,
                n_padded.trailing_zeros()
            );

            // ── DA Merkle Root (deterministic event-set commitment) ──
            let start = Instant::now();
            let mut event_ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
            ruma_zk_prover::merkle::canonical_sort(&mut event_ids);
            let da_root = ruma_zk_prover::merkle::build_merkle_root(&event_ids);
            let da_time = start.elapsed();
            println!("  DA root:       {} ({:?})", hex::encode(da_root), da_time);

            // ── Kahn topological sort (via ruma-lean) ──
            let start = Instant::now();
            let mut lean_map = std::collections::HashMap::new();
            for ev in events.iter() {
                lean_map.insert(
                    ev.event_id.clone(),
                    ruma_lean::LeanEvent {
                        event_id: ev.event_id.clone(),
                        event_type: ev.event_type.clone(),
                        state_key: ev.state_key.clone(),
                        power_level: ev.power_level as i64,
                        prev_events: ev.prev_events.clone(),
                        auth_events: ev.prev_events.clone(),
                        ..Default::default()
                    },
                );
            }
            let sorted_ids = ruma_lean::lean_kahn_sort(&lean_map, ruma_lean::StateResVersion::V2);
            let kahn_time = start.elapsed();
            let acyclic = sorted_ids.len() == n_events;
            if !acyclic {
                eprintln!(
                    "  [WARN] DAG contains cycles -- {} of {} events sorted",
                    sorted_ids.len(),
                    n_events
                );
            }
            println!("  Kahn sort:     {:?} (acyclic={})", kahn_time, acyclic);

            // ── State Resolution (via ruma-lean) ──
            let start = Instant::now();
            let unconflicted = std::collections::BTreeMap::new();
            let resolved = ruma_lean::resolve_lean(
                unconflicted,
                lean_map.clone(),
                ruma_lean::StateResVersion::V2,
            );
            let resolve_time = start.elapsed();
            println!(
                "  State res:     {:?} ({} resolved state entries)",
                resolve_time,
                resolved.len()
            );

            // Build permutation from sorted IDs
            let id_to_idx: std::collections::HashMap<&str, usize> = events
                .iter()
                .enumerate()
                .map(|(i, e)| (e.event_id.as_str(), i))
                .collect();
            let mut perm: Vec<usize> = sorted_ids
                .iter()
                .filter_map(|id| id_to_idx.get(id.as_str()).copied())
                .collect();
            for i in perm.len()..n_padded {
                perm.push(i);
            }

            // ── Benes routing ──
            let start = Instant::now();
            let network = BenesNetwork::from_permutation(&perm);
            let waksman_time = start.elapsed();
            println!(
                "  Waksman routing: {:?} ({} layers x {} switches)",
                waksman_time,
                network.switches.len(),
                n_padded / 2
            );

            // ── Trace build ──
            let inputs: Vec<GF2> = (0..n_padded)
                .map(|i| if i < n_events { GF2::ONE } else { GF2::ZERO })
                .collect();

            let start = Instant::now();
            let trace = ExecutionTrace::build(&inputs, &network);
            let trace_time = start.elapsed();
            let violations = trace.verify_constraints();

            println!(
                "  Trace build:    {:?} ({} constraints)",
                trace_time,
                trace.num_constraints()
            );

            if violations == 0 {
                println!("  [ok] All routing constraints satisfied");
            } else {
                println!("  [FAIL] {} constraint violations!", violations);
            }

            // ── Resolved State Hash ──
            let resolved_ids: Vec<String> = resolved.values().cloned().collect();
            let state_root = ruma_zk_prover::merkle::build_merkle_root(&resolved_ids);

            // ── h_auth: identity binding over canonically sorted event IDs ──
            let mut auth_blob = Vec::new();
            for id in &sorted_ids {
                auth_blob.extend_from_slice(id.as_bytes());
            }
            let h_auth = ruma_zk_prover::merkle::keccak256(&auth_blob);

            println!("\n  Public Journal:");
            println!("    da_root:    {}", hex::encode(da_root));
            println!("    state_root: {}", hex::encode(state_root));
            println!("    h_auth:     {}", hex::encode(h_auth));
            println!("    n_events:   {}", n_events);
            println!("    n_resolved: {}", resolved.len());

            // ── merge_base: hash of m.room.create event ──
            let create_event = events.iter().find(|e| e.event_type == "m.room.create");
            let merge_base = create_event
                .map(|e| ruma_zk_prover::merkle::keccak256(e.event_id.as_bytes()))
                .unwrap_or([0u8; 32]);

            // ── STARK Proof Generation (Phase 3) ──
            let journal = ruma_zk_prover::stark::PublicJournal {
                da_root,
                state_root,
                h_auth,
                n_events: n_events as u64,
                epoch_range: [0, n_events as u64],
                merge_base,
                ..Default::default()
            };

            let start = Instant::now();
            let proof = ruma_zk_prover::stark::prove(&trace, journal);
            let prove_time = start.elapsed();

            let proof_size = proof.stretched_openings.len()
                * proof
                    .stretched_openings
                    .first()
                    .map_or(0, |o| o.data.len() + o.merkle_path.len() * 32)
                + proof.preimage_openings.len()
                    * proof
                        .preimage_openings
                        .first()
                        .map_or(0, |o| o.data.len() + o.merkle_path.len() * 32)
                + 32; // commitment root

            println!("\n  STARK Proof:");
            println!("    commitment: {}", hex::encode(proof.commitment_root));
            println!(
                "    queries:    {} (128-bit soundness)",
                ruma_zk_prover::stark::SOUNDNESS_QUERIES
            );
            println!(
                "    proof size: {} bytes (~{} KB)",
                proof_size,
                proof_size / 1024
            );
            println!("    prove time: {:?}", prove_time);

            // ── Verify ──
            let start = Instant::now();
            match ruma_zk_prover::stark::verify(&proof) {
                Ok(()) => {
                    let verify_time = start.elapsed();
                    println!("    verify:     {:?} ✓", verify_time);
                }
                Err(e) => {
                    println!("    verify:     FAILED — {}", e);
                }
            }
        }
    }
}
