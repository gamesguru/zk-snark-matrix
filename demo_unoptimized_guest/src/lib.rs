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

#![cfg_attr(not(feature = "host"), no_std)]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

#[cfg(not(feature = "host"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "host"))]
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "host")]
use std::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use jolt::provable;
use ruma_lean::{lean_kahn_sort, HashMap, LeanEvent, StateResVersion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GuestEvent {
    pub event: serde_json::Map<String, serde_json::Value>,
    pub content: Vec<u8>,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct DAGMergeInput {
    pub room_version: String,
    pub event_map: BTreeMap<String, GuestEvent>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DAGMergeOutput {
    pub resolved_state_hash: [u8; 32],
    pub event_count: u32,
}

#[provable(max_input_size = 10485760, max_trace_length = 104857600)]
pub fn resolve_full_spec(_input_bytes: Vec<u8>) -> DAGMergeOutput {
    let input: DAGMergeInput =
        ciborium::from_reader(_input_bytes.as_slice()).expect("Failed to deserialize input");
    let event_count = input.event_map.len() as u32;

    let mut conflicted_events = HashMap::new();
    for (id, guest_ev) in &input.event_map {
        let lean_ev = LeanEvent {
            event_id: id.clone(),
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
            content: serde_json::from_slice(&guest_ev.content).unwrap_or(serde_json::Value::Null),
            depth: guest_ev
                .event
                .get("depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            power_level: 0,
        };
        conflicted_events.insert(lean_ev.event_id.clone(), lean_ev);
    }

    let sorted_ids = lean_kahn_sort(&conflicted_events, StateResVersion::V2);

    let mut resolved_state = BTreeMap::new();
    for id in sorted_ids {
        if let Some(ev) = input.event_map.get(&id) {
            let key = (
                ev.event_type.clone(),
                ev.event
                    .get("state_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            resolved_state.insert(key, ev.event_id.clone());
        }
    }

    let mut hasher = Sha256::new();
    for (key, event_id) in resolved_state {
        hasher.update(key.0.as_bytes());
        hasher.update(key.1.as_bytes());
        hasher.update(event_id.as_bytes());
    }

    DAGMergeOutput {
        resolved_state_hash: hasher.finalize().into(),
        event_count,
    }
}
