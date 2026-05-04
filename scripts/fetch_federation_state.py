#!/usr/bin/env python3
"""Fetch federation-format room state (with ed25519 signatures) from a remote Matrix server.

Usage:
    python3 scripts/fetch_federation_state.py \
        --origin YOUR_SERVER \
        --signing-key /path/to/signing.key \
        --destination t2l.io \
        --room '!iMZEhwCvbfeAYUxAjZ:t2l.io' \
        --event-id '$vqOlax8We4wZBhFIE85wh7TeSOWmqTGaJvGx9fZZtPQ' \
        --output ruma-lean/res/real_matrix_fed_state.json

The signing key file is the ed25519 key from your Conduwuit/Synapse config.
For Conduwuit, this is typically in your data directory as a .signing.key file.
Format: "ed25519 <key_id> <base64_private_key>"

Requirements: pip install PyNaCl requests canonicaljson
"""

import argparse
import base64
import json
import sys
import time

try:
    import canonicaljson
    import nacl.signing
    import requests
except ImportError:
    print("Install dependencies: pip install PyNaCl requests canonicaljson")
    sys.exit(1)


def load_signing_key(path: str) -> tuple[str, nacl.signing.SigningKey]:
    """Load ed25519 signing key from Conduwuit/Synapse format."""
    with open(path) as f:
        line = f.read().strip()

    parts = line.split()
    if len(parts) != 3 or parts[0] != "ed25519":
        raise ValueError(
            f"Expected format: 'ed25519 <key_id> <base64_key>', got: {line[:50]}"
        )

    key_id = f"ed25519:{parts[1]}"
    seed = base64.b64decode(parts[2] + "==")  # pad if needed
    signing_key = nacl.signing.SigningKey(seed[:32])
    return key_id, signing_key


def sign_request(
    signing_key: nacl.signing.SigningKey,
    key_id: str,
    origin: str,
    destination: str,
    method: str,
    uri: str,
    content: dict | None = None,
) -> str:
    """Sign a federation request per Matrix spec S2S auth (§13.1)."""
    signed_obj = {
        "method": method,
        "uri": uri,
        "origin": origin,
        "destination": destination,
    }
    if content is not None:
        signed_obj["content"] = content

    canonical = canonicaljson.encode_canonical_json(signed_obj)
    signed = signing_key.sign(canonical)
    sig_b64 = base64.b64encode(signed.signature).decode("ascii").rstrip("=")

    return f'X-Matrix origin="{origin}",destination="{destination}",key="{key_id}",sig="{sig_b64}"'


def fetch_state(
    origin: str,
    destination: str,
    signing_key: nacl.signing.SigningKey,
    key_id: str,
    room_id: str,
    event_id: str,
) -> dict:
    """Fetch room state from a remote server via federation API."""
    # URL-encode the room_id and event_id
    from urllib.parse import quote

    uri = f"/_matrix/federation/v1/state/{quote(room_id)}?event_id={quote(event_id)}"
    url = f"https://{destination}{uri}"

    auth_header = sign_request(signing_key, key_id, origin, destination, "GET", uri)

    print(f"[*] Requesting federation state from {destination}")
    print(f"    Room: {room_id}")
    print(f"    Event: {event_id}")
    print(f"    URI: {uri}")

    resp = requests.get(
        url,
        headers={"Authorization": auth_header},
        timeout=30,
    )

    if resp.status_code != 200:
        print(f"[!] HTTP {resp.status_code}: {resp.text[:500]}")
        sys.exit(1)

    return resp.json()


def main():
    parser = argparse.ArgumentParser(
        description="Fetch federation-format room state with ed25519 signatures"
    )
    parser.add_argument("--origin", required=True, help="Your server name")
    parser.add_argument(
        "--signing-key", required=True, help="Path to ed25519 signing key file"
    )
    parser.add_argument(
        "--destination", default="t2l.io", help="Remote server to query"
    )
    parser.add_argument(
        "--room",
        default="!iMZEhwCvbfeAYUxAjZ:t2l.io",
        help="Room ID",
    )
    parser.add_argument(
        "--event-id",
        default="$vqOlax8We4wZBhFIE85wh7TeSOWmqTGaJvGx9fZZtPQ",
        help="Event ID to anchor state at",
    )
    parser.add_argument(
        "--output",
        default="ruma-lean/res/real_matrix_fed_state.json",
        help="Output file",
    )
    args = parser.parse_args()

    key_id, signing_key = load_signing_key(args.signing_key)
    print(f"[*] Loaded signing key: {key_id}")
    print(f"[*] Origin: {args.origin}")

    data = fetch_state(
        args.origin,
        args.destination,
        signing_key,
        key_id,
        args.room,
        args.event_id,
    )

    pdus = data.get("pdus", [])
    auth_chain = data.get("auth_chain", [])
    print(f"[+] Received {len(pdus)} state PDUs + {len(auth_chain)} auth chain PDUs")

    # Check for signatures
    has_sigs = sum(1 for p in pdus if "signatures" in p)
    print(f"[+] {has_sigs}/{len(pdus)} PDUs have signatures")

    # Save combined
    all_pdus = pdus + auth_chain
    with open(args.output, "w") as f:
        json.dump(all_pdus, f, indent=2)
    print(f"[+] Saved {len(all_pdus)} PDUs to {args.output}")


if __name__ == "__main__":
    main()
