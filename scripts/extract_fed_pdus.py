#!/usr/bin/env python3
"""Extract federation-format PDUs from Continuwuity via admin room.

No /sync. Uses /messages to read bot responses. Auto-finds admin room.

Usage:
    source .env  # sets MATRIX_TOKEN
    python3 scripts/extract_fed_pdus.py \
        --server https://mdev.nutra.tk \
        --input /home/shane/nightly.json \
        --output fixtures/fed_state.json
"""

import argparse
import json
import os
import sys
import time
import uuid
from urllib.parse import quote

import requests

S = requests.Session()
HDR = {}


def api(method, url, **kw):
    r = S.request(method, url, headers=HDR, timeout=15, **kw)
    r.raise_for_status()
    return r.json()


def find_admin_room(server):
    """Find admin room by looking for the server bot user."""
    rooms = api("GET", f"{server}/_matrix/client/v3/joined_rooms")["joined_rooms"]
    for rid in rooms:
        try:
            members = api(
                "GET", f"{server}/_matrix/client/v3/rooms/{quote(rid)}/members"
            )
            for m in members.get("chunk", []):
                uid = m.get("state_key", "")
                if "conduit" in uid or "continuwuity" in uid or "admin" in uid.lower():
                    # Check if this is a DM-like room (small)
                    print(f"  [?] Candidate: {rid} (has bot user {uid})")
                    return rid
        except Exception:
            continue
    return None


def send_msg(server, room, body):
    txn = uuid.uuid4().hex
    return api(
        "PUT",
        f"{server}/_matrix/client/v3/rooms/{quote(room)}/send/m.room.message/{txn}",
        json={"msgtype": "m.text", "body": body},
    )["event_id"]


def read_latest(server, room, limit=5):
    return api(
        "GET",
        f"{server}/_matrix/client/v3/rooms/{quote(room)}/messages",
        params={"dir": "b", "limit": str(limit)},
    ).get("chunk", [])


def extract_pdu(text):
    depth = 0
    start = None
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = None
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--admin-room", help="Admin room ID (auto-detected if omitted)")
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="fixtures/fed_state.json")
    p.add_argument("--delay", type=float, default=2.0)
    args = p.parse_args()

    token = os.environ.get("MATRIX_TOKEN")
    if not token:
        print("Set MATRIX_TOKEN env var (source .env)")
        sys.exit(1)
    HDR["Authorization"] = f"Bearer {token}"

    with open(args.input) as f:
        events = json.load(f)
    eids = [e["event_id"] for e in events]
    print(f"[*] {len(eids)} events to fetch")

    # Find admin room
    admin_room = args.admin_room
    if not admin_room:
        print("[*] Looking for admin room...")
        admin_room = find_admin_room(args.server)
        if not admin_room:
            print("[!] Could not find admin room. Use --admin-room")
            sys.exit(1)
    print(f"[+] Admin room: {admin_room}")

    # Test connection
    print("[*] Testing...")
    msgs = read_latest(args.server, admin_room, 1)
    print(f"[+] Connected ({len(msgs)} messages)")

    pdus = []
    for i, eid in enumerate(eids):
        print(f"[{i+1}/{len(eids)}] {eid} ...", end=" ", flush=True)

        send_msg(args.server, admin_room, f"!admin debug get-pdu {eid}")
        time.sleep(args.delay)

        msgs = read_latest(args.server, admin_room, 3)
        found = False
        for msg in msgs:
            body = msg.get("content", {}).get("body", "")
            if "signatures" in body:
                pdu = extract_pdu(body)
                if pdu and "signatures" in pdu:
                    pdus.append(pdu)
                    print(f"✓ {list(pdu['signatures'].keys())}")
                    found = True
                    break
        if not found:
            print("✗")

    print(f"\n[+] {len(pdus)}/{len(eids)} PDUs")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(pdus, f, indent=2)
    print(f"[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
