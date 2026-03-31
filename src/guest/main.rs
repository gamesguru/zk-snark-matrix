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

#![no_main]
sp1_zkvm::entrypoint!(main);

use ruma_common::{
    CanonicalJsonObject, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, RoomVersionId, UserId,
};
use ruma_events::TimelineEventType;
use ruma_state_res::{resolve, Event, StateMap};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::collections::HashSet;

mod raw_value_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::value::RawValue;

    #[allow(clippy::borrowed_box)]
    pub fn serialize<S>(value: &Box<RawValue>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.get().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Box<RawValue>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RawValue::from_string(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GuestEvent {
    pub event: CanonicalJsonObject,
    #[serde(with = "raw_value_as_string")]
    pub content: Box<serde_json::value::RawValue>,
    pub event_id: OwnedEventId,
    pub room_id: OwnedRoomId,
    pub sender: OwnedUserId,
    pub event_type: TimelineEventType,
    pub prev_events: Vec<OwnedEventId>,
    pub auth_events: Vec<OwnedEventId>,
}

impl Event for GuestEvent {
    type Id = OwnedEventId;

    fn event_id(&self) -> &Self::Id {
        &self.event_id
    }

    fn room_id(&self) -> Option<&RoomId> {
        Some(&self.room_id)
    }

    fn sender(&self) -> &UserId {
        &self.sender
    }

    fn origin_server_ts(&self) -> ruma_common::MilliSecondsSinceUnixEpoch {
        let val = self
            .event
            .get("origin_server_ts")
            .expect("missing origin_server_ts");
        serde_json::from_value(val.clone().into()).expect("invalid origin_server_ts")
    }

    fn event_type(&self) -> &TimelineEventType {
        &self.event_type
    }

    fn content(&self) -> &serde_json::value::RawValue {
        &self.content
    }

    fn state_key(&self) -> Option<&str> {
        let val = self.event.get("state_key").expect("missing state_key");
        val.as_str()
    }

    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.prev_events.iter())
    }

    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.auth_events.iter())
    }

    fn redacts(&self) -> Option<&Self::Id> {
        None
    }

    fn rejected(&self) -> bool {
        false
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DAGMergeInput {
    pub room_version: RoomVersionId,
    pub state_to_resolve: Vec<StateMap<OwnedEventId>>,
    pub auth_chains: Vec<HashSet<OwnedEventId>>,
    pub event_map: BTreeMap<OwnedEventId, GuestEvent>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DAGMergeOutput {
    pub resolved_state_hash: [u8; 32],
}

pub fn main() {
    // Read the input from the Host (the world-state hint containing events)
    let input: DAGMergeInput = sp1_zkvm::io::read();

    println!("cycle-count-start: resolution-initialization");

    // Resolve rules based on room version
    let rules = input
        .room_version
        .rules()
        .expect("Unsupported room version");
    let state_res_v2_rules = rules
        .state_res
        .v2_rules()
        .expect("Room version does not use State Res V2");

    println!("cycle-count-start: ruma-state-resolution");
    println!("> Resolving {} state maps...", input.state_to_resolve.len());

    // ZK-Proven State Resolution: Execute the spec-mandated algorithm!
    let resolved_state = resolve(
        &rules.authorization,
        state_res_v2_rules,
        &input.state_to_resolve,
        input.auth_chains,
        |id| input.event_map.get(id).cloned(),
        |_| Some(HashSet::new()), // Simplified for demo; real join fetches subgraph if needed
    )
    .expect("Ruma State Resolution failed inside the zkVM!");

    println!("cycle-count-end: ruma-state-resolution");
    println!("cycle-count-start: state-hashing");

    // Journal Commitment: Fingerprint the resolved state
    let mut hasher = Sha256::new();

    for ((event_type, state_key), event_id) in resolved_state {
        hasher.update(event_type.to_string().as_bytes());
        hasher.update(state_key.as_bytes());
        hasher.update(event_id.as_str().as_bytes());
    }

    let expected_hash: [u8; 32] = hasher.finalize().into();

    let output = DAGMergeOutput {
        resolved_state_hash: expected_hash,
    };

    println!("cycle-count-end: state-hashing");
    println!("✓ Guest Resolution Protocol Complete!");

    sp1_zkvm::io::commit(&output);
}
