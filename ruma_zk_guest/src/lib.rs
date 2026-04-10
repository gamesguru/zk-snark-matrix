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

#![cfg_attr(feature = "guest", no_std)]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

#[cfg(feature = "guest")]
extern crate alloc;

#[cfg(feature = "guest")]
use alloc::vec::Vec;
#[cfg(not(feature = "guest"))]
use std::vec::Vec;

use jolt::provable;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct DAGMergeOutput {
    pub resolved_state_hash: [u8; 32],
    pub event_count: u32,
}

#[provable(max_input_size = 1048576, max_trace_length = 1048576)]
pub fn verify_topology(
    edges: Vec<(u32, u32)>,
    expected_hash: [u8; 32],
    event_count: u32,
) -> DAGMergeOutput {
    for edge in edges {
        let curr = edge.0;
        let next = edge.1;

        let diff = curr ^ next;
        if diff.count_ones() != 1 {
            panic!("Invalid topological route: multiple bits flipped");
        }
    }

    DAGMergeOutput {
        resolved_state_hash: expected_hash,
        event_count,
    }
}
