//! Matrix PDU (Protocol Data Unit) auth context extraction.
//!
//! Bridges the `ruma_lean` auth module (which operates on LeanEvent +
//! RoomState) with the ZK prover's GF(2) auth constraint system.

use crate::auth::{
    self, AuthWitness, MEMBERSHIP_BAN, MEMBERSHIP_INVITE, MEMBERSHIP_JOIN, MEMBERSHIP_NONE,
};
use ruma_lean::LeanEvent;
use std::collections::BTreeMap;

/// Room state type (same as ruma_lean::auth::RoomState).
pub type RoomState = BTreeMap<(String, String), LeanEvent>;

/// Extract the auth context for a single event given the room state
/// at its prev_events, and compute the GF(2) authorization witness.
///
/// This is the bridge between Matrix-land (JSON events, string fields)
/// and ZK-land (binary field constraints).
pub fn extract_auth_witness(event: &LeanEvent, state: &RoomState) -> AuthWitness {
    let sender_pl = get_sender_power_level(&event.sender, state);
    let required_pl = get_required_power_level(&event.event_type, state);
    let membership = get_membership(&event.sender, state);

    auth::compute_auth(
        sender_pl.max(0) as u64,
        required_pl.max(0) as u64,
        membership,
    )
}

/// Compute auth witnesses for all events in topological order,
/// iteratively updating state as events are accepted.
///
/// This mirrors `ruma_lean::auth::check_auth_chain` but produces
/// GF(2) witnesses instead of pass/fail results.
pub fn compute_auth_witnesses(
    sorted_events: &[LeanEvent],
    initial_state: &RoomState,
) -> Vec<AuthWitness> {
    let mut state = initial_state.clone();
    let mut witnesses = Vec::with_capacity(sorted_events.len());

    for event in sorted_events {
        let witness = extract_auth_witness(event, &state);
        witnesses.push(witness);

        // Apply event to state (same logic as check_auth_chain)
        if !event.state_key.is_empty() || event.event_type == "m.room.create" {
            state.insert(
                (event.event_type.clone(), event.state_key.clone()),
                event.clone(),
            );
        }
    }

    witnesses
}

/// Get the power level of a user from the current room state.
fn get_sender_power_level(sender: &str, state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        if let Some(users) = pl_event.content.get("users").and_then(|u| u.as_object()) {
            if let Some(pl) = users.get(sender).and_then(|v| v.as_i64()) {
                return pl;
            }
        }
        // Fall back to users_default
        if let Some(default) = pl_event
            .content
            .get("users_default")
            .and_then(|v| v.as_i64())
        {
            return default;
        }
    }
    0
}

/// Get the required power level to send a given event type.
fn get_required_power_level(event_type: &str, state: &RoomState) -> i64 {
    let pl_key = ("m.room.power_levels".into(), String::new());
    if let Some(pl_event) = state.get(&pl_key) {
        // Check specific event type overrides
        if let Some(events) = pl_event.content.get("events").and_then(|e| e.as_object()) {
            if let Some(pl) = events.get(event_type).and_then(|v| v.as_i64()) {
                return pl;
            }
        }
        // Fall back to state_default for state events, events_default for others
        if event_type.starts_with("m.room.") {
            if let Some(default) = pl_event
                .content
                .get("state_default")
                .and_then(|v| v.as_i64())
            {
                return default;
            }
        }
        if let Some(default) = pl_event
            .content
            .get("events_default")
            .and_then(|v| v.as_i64())
        {
            return default;
        }
    }
    0
}

/// Map a sender's membership string to a 2-bit MEMBERSHIP_* constant.
fn get_membership(sender: &str, state: &RoomState) -> u8 {
    let member_key = ("m.room.member".into(), sender.to_string());
    if let Some(member_event) = state.get(&member_key) {
        match member_event
            .content
            .get("membership")
            .and_then(|m| m.as_str())
        {
            Some("join") => MEMBERSHIP_JOIN,
            Some("invite") => MEMBERSHIP_INVITE,
            Some("ban") => MEMBERSHIP_BAN,
            _ => MEMBERSHIP_NONE,
        }
    } else {
        MEMBERSHIP_NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(
        id: &str,
        event_type: &str,
        state_key: &str,
        sender: &str,
        content: serde_json::Value,
    ) -> LeanEvent {
        LeanEvent {
            event_id: id.into(),
            event_type: event_type.into(),
            state_key: state_key.into(),
            sender: sender.into(),
            content,
            ..Default::default()
        }
    }

    #[test]
    fn test_extract_joined_user() {
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            make_event(
                "$join",
                "m.room.member",
                "@alice:example.com",
                "@alice:example.com",
                json!({"membership": "join"}),
            ),
        );

        let event = make_event(
            "$msg",
            "m.room.message",
            "",
            "@alice:example.com",
            json!({}),
        );
        let w = extract_auth_witness(&event, &state);
        assert_eq!(w.authorized, ruma_zk_topological_air::field::GF2::ONE);
        assert_eq!(auth::verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_extract_banned_user() {
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@evil:example.com".into()),
            make_event(
                "$ban",
                "m.room.member",
                "@evil:example.com",
                "@admin:example.com",
                json!({"membership": "ban"}),
            ),
        );

        let event = make_event("$msg", "m.room.message", "", "@evil:example.com", json!({}));
        let w = extract_auth_witness(&event, &state);
        assert_eq!(w.authorized, ruma_zk_topological_air::field::GF2::ZERO);
        assert_eq!(auth::verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_extract_insufficient_pl() {
        let mut state = RoomState::new();
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            make_event(
                "$join",
                "m.room.member",
                "@alice:example.com",
                "@alice:example.com",
                json!({"membership": "join"}),
            ),
        );
        state.insert(
            ("m.room.power_levels".into(), String::new()),
            make_event(
                "$pl",
                "m.room.power_levels",
                "",
                "@admin:example.com",
                json!({"state_default": 50, "users": {"@admin:example.com": 100}}),
            ),
        );

        // Alice (pl=0) tries to send a state event (requires pl=50)
        let event = make_event(
            "$topic",
            "m.room.topic",
            "",
            "@alice:example.com",
            json!({}),
        );
        let w = extract_auth_witness(&event, &state);
        assert_eq!(w.authorized, ruma_zk_topological_air::field::GF2::ZERO);
        assert_eq!(auth::verify_auth_constraints(&w), 0);
    }

    #[test]
    fn test_iterative_chain() {
        let create = make_event(
            "$create",
            "m.room.create",
            "",
            "@alice:example.com",
            json!({}),
        );
        let join = make_event(
            "$join",
            "m.room.member",
            "@alice:example.com",
            "@alice:example.com",
            json!({"membership": "join"}),
        );
        let msg = make_event(
            "$msg",
            "m.room.message",
            "",
            "@alice:example.com",
            json!({"body": "hello"}),
        );

        let witnesses = compute_auth_witnesses(&[create, join, msg], &RoomState::new());
        assert_eq!(witnesses.len(), 3);

        // All witnesses should have valid constraints
        for w in &witnesses {
            assert_eq!(auth::verify_auth_constraints(w), 0);
        }
    }
}
