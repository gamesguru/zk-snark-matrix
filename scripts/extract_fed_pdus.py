#!/usr/bin/env python3
"""Extract federation-format PDUs using the standard Matrix federation API.

Your homeserver makes the authenticated federation request for you.
We use the client API to trigger a backfill/event fetch, or we can
directly call the federation API on the target server.

Actually simplest: use /_matrix/client/v3/rooms/{roomId}/event/{eventId}
on your OWN server, which returns the event from local DB.
Then check if it includes signatures (it should for federation-received events).

Usage:
    export MATRIX_TOKEN="your_token"
    python3 scripts/extract_fed_pdus.py \
        --server https://mdev.nutra.tk \
        --input /home/shane/nightly.json \
        --output fixtures/fed_state.json
"""

import argparse
import json
import os
import sys
from urllib.parse import quote

import requests

S = requests.Session()


def fetch_event(server: str, token: str, room_id: str, event_id: str) -> dict | None:
    """Fetch a single event via client API."""
    url = f"{server}/_matrix/client/v3/rooms/{quote(room_id)}/event/{quote(event_id)}"
    r = S.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    if r.status_code == 200:
        return r.json()
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True, help="Your homeserver URL")
    p.add_argument("--input", required=True, help="Client-format fixture JSON")
    p.add_argument("--output", default="fixtures/fed_state.json")
    args = p.parse_args()

    token = os.environ.get("MATRIX_TOKEN")
    if not token:
        print("Set MATRIX_TOKEN env var")
        sys.exit(1)

    with open(args.input) as f:
        events = json.load(f)

    room_id = events[0]["room_id"]
    eids = [e["event_id"] for e in events]
    print(f"[*] Room: {room_id}")
    print(f"[*] {len(eids)} events to fetch")

    pdus = []
    client_only = []
    for i, eid in enumerate(eids):
        print(f"[{i+1}/{len(eids)}] {eid} ...", end=" ", flush=True)
        ev = fetch_event(args.server, token, room_id, eid)
        if ev is None:
            print("✗ not found")
            continue

        if "signatures" in ev:
            pdus.append(ev)
            sigs = list(ev["signatures"].keys())
            print(f"✓ fed format, sigs={sigs}")
        else:
            # Client API strips signatures -- save anyway
            client_only.append(ev)
            print(f"~ client format (no sigs)")

    print(f"\n[+] {len(pdus)} federation PDUs (with signatures)")
    print(f"[+] {len(client_only)} client-format events (no signatures)")

    if pdus:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(pdus, f, indent=2)
        print(f"[+] Saved federation PDUs to {args.output}")

    if not pdus and client_only:
        print("\n[!] Client API strips signatures.")
        print("[!] You need to use the admin room: !admin debug get-pdu <event_id>")
        # Save client events anyway
        with open(args.output, "w") as f:
            json.dump(client_only, f, indent=2)
        print(f"[+] Saved client-format events to {args.output}")


if __name__ == "__main__":
    main()
