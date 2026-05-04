#!/usr/bin/env python3
"""Extract event IDs from a client-format fixture and print admin commands
to fetch full federation-format PDUs from Continuwuity.

Usage:
    python3 scripts/batch_get_pdus.py /home/shane/nightly.json

Then paste the output into your Continuwuity admin room.
"""

import json
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <fixture.json>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    data = json.load(f)

ids = [e["event_id"] for e in data]
print(f"# {len(ids)} events to fetch")
print(f"# Paste each line into your admin room")
print()
for eid in ids:
    print(f"!admin debug get-pdu {eid}")
