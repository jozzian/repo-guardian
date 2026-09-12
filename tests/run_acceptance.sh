#!/bin/sh
# Acceptance test entry point: generate fixtures, run the scanner
# against all six, assert detection and redaction invariants.
set -e
cd "$(dirname "$0")/.."
python3 tests/make_fixtures.py --force
exec python3 tests/run_acceptance.py
