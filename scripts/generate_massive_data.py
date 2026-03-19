import hashlib
import json
import random
import sys
import time

NUM_EVENTS = 1000000


def sha256_hash(data_str):
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


print(f"Generating {NUM_EVENTS} synthetic Matrix state events...", file=sys.stderr)

events = []
room_id = "!massive_test_room:example.com"

# Create initial event
events.append(
    {
        "event_id": f"$00000-m-room-create",
        "room_id": room_id,
        "sender": "@creator:example.com",
        "type": "m.room.create",
        "content": {"creator": "@creator:example.com", "room_version": "10"},
        "state_key": "",
        "origin_server_ts": int(time.time() * 1000) - 10000000,
        "prev_events": [],
        "auth_events": [],
    }
)

event_types = [
    "m.room.member",
    "m.room.message",
    "m.room.power_levels",
    "m.room.join_rules",
]
members = [f"@user_{i}:example.com" for i in range(100)]

for i in range(1, NUM_EVENTS):
    sender = random.choice(members)
    ev_type = random.choice(event_types)
    ts = events[-1]["origin_server_ts"] + random.randint(1, 1000)

    prev_event_id = events[-1]["event_id"]

    content = {}
    state_key = ""
    if ev_type == "m.room.member":
        content = {"membership": random.choice(["join", "leave", "invite"])}
        state_key = random.choice(members)
    elif ev_type == "m.room.message":
        content = {"body": f"Message {i}", "msgtype": "m.text"}
        # Messages usually don't have state_key, but for State Res we usually only care about state events.
        # Let's just generate state events to be safe.
        ev_type = "m.room.topic"
        content = {"topic": f"Topic number {i}"}
    elif ev_type == "m.room.power_levels":
        content = {"users": {sender: 100}}
    else:
        content = {"join_rule": "public"}

    # Mock event ID based on hash of index to ensure uniqueness
    event_id = f"${sha256_hash(str(i))[:20]}"

    events.append(
        {
            "event_id": event_id,
            "room_id": room_id,
            "sender": sender,
            "type": ev_type,
            "content": content,
            "state_key": state_key,
            "origin_server_ts": ts,
            "prev_events": [prev_event_id],
            "auth_events": [events[0]["event_id"]],  # Simplify auth chain
        }
    )

    if i % 10000 == 0:
        print(f"Generated {i} events...", file=sys.stderr)

output_file = "res/massive_matrix_state.json"
with open(output_file, "w") as f:
    json.dump(events, f, indent=2)

print(
    f"Successfully generated {NUM_EVENTS} events (File size: {sys.getsizeof(events)} approx bytes). Saved to {output_file}",
    file=sys.stderr,
)
