#!/bin/sh
# Verification test entry point: generate fixtures, run the tier,
# gate, and fixture-level verification assertions (offline only).
set -e
cd "$(dirname "$0")/.."
python3 tests/make_fixtures.py --force
exec python3 tests/run_verification.py
