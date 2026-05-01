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
        .collect()
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Fingerprint => {
            println!("ruma-zk-prover v{}", env!("CARGO_PKG_VERSION"));
            println!("Circuit VK_HASH: {}", ruma_zk_topological_air::VK_HASH);
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

            // Identity permutation for now (topological sort = input order).
            let perm: Vec<usize> = (0..n_padded).collect();

            let start = Instant::now();
            let network = BenesNetwork::from_permutation(&perm);
            let waksman_time = start.elapsed();
            println!(
                "  Waksman routing: {:?} ({} layers x {} switches)",
                waksman_time,
                network.switches.len(),
                n_padded / 2
            );

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
                println!("  ✓ All routing constraints satisfied");
            } else {
                println!("  ✗ {} constraint violations!", violations);
            }

            println!("\n  [Witness ready — awaiting Binius prover backend]");
        }
    }
}
