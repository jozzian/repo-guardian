#!/usr/bin/env python3
"""Repo Guardian scanner CLI.

Wraps gitleaks (v8.24.x) to scan a local git repository for secrets.
Produces structured JSON findings with stable fingerprints. Secret
values are never emitted: they are hashed for fingerprinting and the
raw gitleaks fields (Secret, Match, and any other payload) are
stripped before output.

Exit codes:
    0  no findings
    1  findings present
    2  scanner error (bad path, gitleaks failure, malformed report)

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA_VERSION = 1
FINGERPRINT_LEN = 16  # hex chars of sha256

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "gitleaks.toml")
GITLEAKS_BIN = os.environ.get("RG_GITLEAKS_BIN", "gitleaks")

# gitleaks JSON report fields that may contain secret material.
# Anything in this set is stripped before a finding leaves the process.
FORBIDDEN_FIELDS = frozenset(
    {
        "Secret",
        "Match",
        "Line",
        "Description",  # descriptions can embed the matched context
        "Raw",
    }
)

# Severity mapping keyed by rule id, then by keyword fallback.
SEVERITY_BY_RULE = {
    "private-key": "critical",
    "aws-access-token": "high",
    "aws-secret-access-key": "high",
    "gitlab-pat": "high",
    "github-pat": "high",
    "github-fine-grained-pat": "high",
    "github-oauth": "high",
    "openai-api-key": "high",
    "slack-bot-token": "high",
    "slack-web-hook-url": "medium",
    "generic-api-key": "medium",
    "generic-secret": "medium",
}
SEVERITY_KEYWORDS = (
    ("private-key", "critical"),
    ("aws", "high"),
    ("gitlab", "high"),
    ("github", "high"),
    ("token", "medium"),
    ("secret", "medium"),
    ("key", "medium"),
)
DEFAULT_SEVERITY = "medium"


class ScannerError(Exception):
    """Fatal scanner problem; maps to exit code 2."""


def severity_for(rule_id: str) -> str:
    """Map a gitleaks rule id to a coarse severity label."""
    if rule_id in SEVERITY_BY_RULE:
        return SEVERITY_BY_RULE[rule_id]
    lowered = rule_id.lower()
    for keyword, severity in SEVERITY_KEYWORDS:
        if keyword in lowered:
            return severity
    return DEFAULT_SEVERITY


def short_sha256(value: str, length: int = FINGERPRINT_LEN) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def fingerprint(rule_id: str, file_path: str, secret_hash: str) -> str:
    """Stable identity for a finding.

    Computed over (rule id, file path, hash of the secret value).
    Line numbers and commits deliberately live in the locations list
    instead of the hash input: the same secret seen in the working
    tree and in one or more historical commits must collapse to a
    single fingerprint so dedupe works across scan modes.
    """
    return short_sha256(f"{rule_id}\x1f{file_path}\x1f{secret_hash}")


def gitleaks_version() -> str:
    try:
        proc = subprocess.run(
            [GITLEAKS_BIN, "version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScannerError(f"cannot execute gitleaks: {exc}") from exc
    if proc.returncode != 0:
        raise ScannerError(f"gitleaks version failed: {proc.stderr.strip()}")
    return proc.stdout.strip().splitlines()[-1].strip() if proc.stdout.strip() else "unknown"


def run_gitleaks(repo: str, mode: str, config: str, report_path: str) -> list:
    """Run one gitleaks detect pass and return its raw JSON findings."""
    cmd = [
        GITLEAKS_BIN,
        "detect",
        "--no-banner",
        "--log-level",
        "error",
        "--source",
        repo,
        "--config",
        config,
        "--report-format",
        "json",
        "--report-path",
        report_path,
    ]
    if mode == "working-tree":
        cmd.append("--no-git")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or proc.stdout).strip()
        raise ScannerError(f"gitleaks {mode} scan failed (exit {proc.returncode}): {detail}")
    if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
        return []
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ScannerError(f"cannot parse gitleaks report: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, list):
        raise ScannerError("unexpected gitleaks report shape (expected a JSON list)")
    return data


def normalize(raw: dict, mode: str, repo: str) -> tuple:
    """Convert one raw gitleaks finding to (fingerprint, finding skeleton).

    The raw dict is never copied wholesale; only an explicit allowlist
    of non-sensitive fields is read, and the secret value itself is
    consumed only through sha256.
    """
    rule_id = str(raw.get("RuleID", "unknown-rule"))
    file_path = str(raw.get("File", ""))
    # The --no-git pass reports absolute paths while the history pass
    # reports repo-relative paths. Normalize to repo-relative so the
    # same secret in the working tree and in history shares one
    # fingerprint and one reported path.
    if os.path.isabs(file_path):
        rel = os.path.relpath(file_path, repo)
        if not rel.startswith(os.pardir):
            file_path = rel
    secret_value = str(raw.get("Secret", ""))
    secret_hash = short_sha256(secret_value)
    fp = fingerprint(rule_id, file_path, secret_hash)

    if mode == "working-tree":
        source = "working-tree"
    elif raw.get("Commit"):
        source = "history"
    else:
        source = "working-tree"

    location = {
        "source": source,
        "commit": raw.get("Commit") or None,
        "line": raw.get("StartLine"),
    }
    if raw.get("Date"):
        location["date"] = raw.get("Date")

    finding = {
        "rule_id": rule_id,
        "file": file_path,
        "severity": severity_for(rule_id),
        "fingerprint": fp,
        "secret_sha256_prefix": secret_hash,
        "locations": [location],
    }
    return fp, finding


def scan(repo: str, mode: str, config: str) -> list:
    """Run the requested scan modes and return deduplicated findings."""
    deduped: dict = {}
    passes = []
    if mode in ("both", "working-tree"):
        passes.append("working-tree")
    if mode in ("both", "history"):
        passes.append("history")

    with tempfile.TemporaryDirectory(prefix="repo-guardian-") as tmpdir:
        for pass_mode in passes:
            report_path = os.path.join(tmpdir, f"report-{pass_mode}.json")
            for raw in run_gitleaks(repo, pass_mode, config, report_path):
                if not isinstance(raw, dict):
                    continue
                fp, finding = normalize(raw, pass_mode, repo)
                if fp in deduped:
                    existing = deduped[fp]["locations"]
                    if finding["locations"][0] not in existing:
                        existing.append(finding["locations"][0])
                else:
                    deduped[fp] = finding

    findings = sorted(
        deduped.values(),
        key=lambda f: (f["file"], f["rule_id"], f["fingerprint"]),
    )
    for finding in findings:
        finding["locations"].sort(
            key=lambda loc: (loc["source"], loc["commit"] or "", loc["line"] or 0)
        )
    return findings


def build_report(repo: str, mode: str, findings: list, version: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": "repo-guardian",
        "gitleaks_version": version,
        "repo": repo,
        "mode": mode,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "finding_count": len(findings),
        "findings": findings,
    }


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rg-scan",
        description="Repo Guardian: scan a git repository for secrets (gitleaks wrapper).",
    )
    parser.add_argument("repo", help="path to a local git repository")
    parser.add_argument(
        "--mode",
        choices=("both", "working-tree", "history"),
        default="both",
        help="what to scan (default: both)",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="write the JSON report to FILE as well as stdout",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"gitleaks config toml (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--quiet", action="store_true", help="do not print the report to stdout"
    )
    args = parser.parse_args(argv)

    repo = os.path.abspath(args.repo)
    try:
        if shutil.which(GITLEAKS_BIN) is None and not os.path.exists(GITLEAKS_BIN):
            raise ScannerError(f"gitleaks binary not found ({GITLEAKS_BIN})")
        if not os.path.isdir(repo):
            raise ScannerError(f"repo path does not exist or is not a directory: {repo}")
        if not os.path.isfile(args.config):
            raise ScannerError(f"gitleaks config not found: {args.config}")
        version = gitleaks_version()
        findings = scan(repo, args.mode, args.config)
        report = build_report(repo, args.mode, findings, version)
    except ScannerError as exc:
        json.dump(
            {"schema_version": SCHEMA_VERSION, "scanner": "repo-guardian", "error": str(exc)},
            sys.stderr,
        )
        sys.stderr.write("\n")
        return 2

    rendered = json.dumps(report, indent=2)
    if not args.quiet:
        print(rendered)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(rendered + "\n")
        except OSError as exc:
            print(f"error: cannot write output file: {exc}", file=sys.stderr)
            return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
