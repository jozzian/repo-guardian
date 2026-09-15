#!/usr/bin/env python3
"""Repo Guardian verification CLI (JOZ-180).

Reads a scanner JSON report (produced by rg-scan --output FILE),
tiers every finding by confidence, and emits an enriched report.
The scanner (rg-scan) is untouched; verification is a separate step
so a scan can be verified later, offline, or not at all.

Usage:
    rg-verify report.json                       # offline tiering
    rg-verify report.json --verify-network      # opt-in liveness checks
    rg-verify report.json --output verified.json --gate gate.json

Exit codes:
    0  verification completed, notification gate is empty
    1  verification completed, gate is non-empty (findings worth
       notifying: confirmed-live or format-valid-unknown)
    2  verification error (bad report, unreadable input)

Redaction: secret values are re-extracted transiently by hash match
to run checks, and are never written to the enriched report, the
gate file, stdout, stderr, or any error message.

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
if os.path.basename(HERE) == "repo_guardian" and PARENT not in sys.path:
    sys.path.insert(0, PARENT)

from repo_guardian.verifier import report as verifier_report
from repo_guardian.verifier.report import VERIFIED_SCHEMA_VERSION, VerificationError


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rg-verify",
        description=(
            "Repo Guardian: tier scanner findings by confidence and "
            "gate notifications."
        ),
    )
    parser.add_argument("report", help="scanner JSON report file (rg-scan --output)")
    parser.add_argument(
        "--verify-network",
        action="store_true",
        help=(
            "opt in to live credential checks (AWS STS identity, "
            "GitHub user lookup). Default: offline heuristics only."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="per-request network timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="write the enriched report to FILE as well as stdout",
    )
    parser.add_argument(
        "--gate",
        metavar="FILE",
        help="write the gated findings list (notification input) to FILE",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="do not print the report to stdout"
    )
    args = parser.parse_args(argv)

    try:
        with open(args.report, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        # The exception text may quote the file, never a secret: the
        # scanner report itself is redacted by construction.
        print(f"error: cannot read scanner report: {exc}", file=sys.stderr)
        return 2

    try:
        verified = verifier_report.verify_report(
            report, network=args.verify_network, timeout=args.timeout
        )
    except VerificationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    gated = verifier_report.gate(verified)

    rendered = json.dumps(verified, indent=2)
    if not args.quiet:
        print(rendered)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(rendered + "\n")
        except OSError as exc:
            print(f"error: cannot write output file: {exc}", file=sys.stderr)
            return 2
    if args.gate:
        try:
            with open(args.gate, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "schema_version": VERIFIED_SCHEMA_VERSION,
                        "source_report": os.path.abspath(args.report),
                        "notification_count": len(gated),
                        "findings": gated,
                    },
                    handle,
                    indent=2,
                )
                handle.write("\n")
        except OSError as exc:
            print(f"error: cannot write gate file: {exc}", file=sys.stderr)
            return 2

    return 1 if gated else 0


if __name__ == "__main__":
    sys.exit(main())
