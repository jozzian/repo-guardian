#!/usr/bin/env python3
"""Redaction proof: grep every planted dummy value out of the fixture
repos and confirm it does not appear in scanner JSON output.

Usage: python3 tests/redaction_proof.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
OUTPUTS = sys.argv[1:] or [
    "/tmp/rg_leaky_final.json",
    "/tmp/rg_pk_final.json",
    "/tmp/rg_env_final.json",
    "/tmp/rg_clean_final.json",
]

with open(os.path.join(FIXTURES, "manifest.json"), encoding="utf-8") as fh:
    manifest = json.load(fh)

blobs = {}
for path in OUTPUTS:
    with open(path, encoding="utf-8") as fh:
        blobs[path] = fh.read()

checked = 0
leaked = []
for entry in manifest:
    for value in entry.get("planted_values", []):
        if not value:
            continue
        checked += 1
        for path, blob in blobs.items():
            if value in blob:
                leaked.append((entry["name"], path, value[:6] + "..."))

# Also grep the distinctive first body line of the planted private key
# and the literal fixture file contents, belt and braces.
pk_file = os.path.join(FIXTURES, "leaky_private_key", "deploy", "id_ed25519")
with open(pk_file, encoding="utf-8") as fh:
    key_lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("-----")]
checked += len(key_lines)
for ln in key_lines:
    for path, blob in blobs.items():
        if ln in blob:
            leaked.append(("leaky_private_key(body)", path, ln[:10] + "..."))

print(f"checked {checked} planted values / key body lines against {len(blobs)} output files")
if leaked:
    for item in leaked:
        print(f"LEAKED: {item}")
    print("RESULT: FAIL")
    sys.exit(1)
print("no planted value appears in any scanner output")
print("RESULT: PASS")
