#!/usr/bin/env python3
"""Repo Guardian verification tests (JOZ-180).

Two layers, no network in either:
  * unit tests for the tier logic, class detection, the pure
    notification gate, and liveness outcome mapping, using synthetic
    in-memory findings built from dummy values only,
  * fixture tests that scan the six generated repositories, run the
    rg-verify CLI offline, and assert the planted dead dummies are
    never confirmed-live, clean fixtures never produce gated
    findings, placeholder-shaped values tier likely-fixture or
    false-positive, and no planted value leaks into verifier output.

Usage: python3 tests/run_verification.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, ROOT)

from repo_guardian.verifier import gate, tiers, verify_report
from repo_guardian.verifier.extraction import sha256_prefix
from repo_guardian.verifier.liveness import apply_outcome
from repo_guardian.verifier.report import VerificationError

SCAN_CLI = [sys.executable, os.path.join(ROOT, "repo_guardian", "cli.py")]
VERIFY_CLI = [sys.executable, os.path.join(ROOT, "repo_guardian", "verify_cli.py")]

PASSED = 0
FAILED = 0
FAILURES = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"PASS  {name}")
    else:
        FAILED += 1
        FAILURES.append(name)
        print(f"FAIL  {name}  {detail}")
    return ok


def ensure_fixtures() -> dict:
    manifest_path = os.path.join(FIXTURES, "manifest.json")
    if not os.path.exists(manifest_path):
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "make_fixtures.py")],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print("error: fixture generation failed:")
            print(proc.stdout + proc.stderr)
            sys.exit(2)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return {m["name"]: m for m in json.load(handle)}


def synthetic_finding(rule_id: str, file_path: str, value: str) -> dict:
    """An in-memory finding shaped like scanner output, for unit
    tests. The value is a dummy; only its hash is recorded, exactly
    as the real scanner does."""
    return {
        "rule_id": rule_id,
        "file": file_path,
        "severity": "medium",
        "fingerprint": sha256_prefix(rule_id + file_path),
        "secret_sha256_prefix": sha256_prefix(value),
        "locations": [{"source": "working-tree", "commit": None, "line": 1}],
    }


def synthetic_report(findings: list) -> dict:
    return {
        "schema_version": 1,
        "scanner": "repo-guardian",
        "repo": ROOT,
        "mode": "both",
        "finding_count": len(findings),
        "findings": findings,
    }


def dummy_value(n: int, seed: int) -> str:
    """A dummy high-entropy token for tests. Random, not a secret."""
    import random

    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(rng.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# Unit tests: class detection
# ---------------------------------------------------------------------------

def test_detect_class() -> None:
    check(
        "class: aws-access-token rule maps to aws-access-key-id",
        tiers.detect_class("aws-access-token", "AKIA" + "A" * 16)
        == tiers.CLASS_AWS_KEY_ID,
    )
    check(
        "class: value shape detects AWS key even under generic rule",
        tiers.detect_class("generic-api-key", "AKIA" + "B" * 16)
        == tiers.CLASS_AWS_KEY_ID,
    )
    check(
        "class: github-pat rule maps to github-token",
        tiers.detect_class("github-pat", "ghp_" + "a" * 36) == tiers.CLASS_GITHUB,
    )
    check(
        "class: github_pat_ prefix detected by value",
        tiers.detect_class("generic-api-key", "github_pat_" + "a" * 70)
        == tiers.CLASS_GITHUB,
    )
    check(
        "class: private-key block detected by value",
        tiers.detect_class("generic-secret", "-----BEGIN OPENSSH PRIVATE KEY-----\nx")
        == tiers.CLASS_PRIVATE_KEY,
    )
    check(
        "class: unclassifiable falls back to generic",
        tiers.detect_class("generic-api-key", dummy_value(32, 1)) == tiers.CLASS_GENERIC,
    )


# ---------------------------------------------------------------------------
# Unit tests: offline tier logic
# ---------------------------------------------------------------------------

def test_tiers_structure() -> None:
    check(
        "tier: valid AWS key id format-valid-unknown",
        tiers.offline_tier(tiers.CLASS_AWS_KEY_ID, "AKIA" + "Q" * 16, "config.ini")
        == (tiers.FORMAT_VALID_UNKNOWN, "format-valid"),
    )
    check(
        "tier: AWS example key is likely-fixture",
        tiers.offline_tier(
            tiers.CLASS_AWS_KEY_ID, "AKIA" + "IOSFODNN7EXA" + "MPLE", "docs/x.md"
        )[0]
        == tiers.LIKELY_FIXTURE,
    )
    check(
        "tier: bad-length AWS key id is false-positive",
        tiers.offline_tier(tiers.CLASS_AWS_KEY_ID, "AKIA123", "config.ini")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: lowercase AWS key id is false-positive",
        tiers.offline_tier(tiers.CLASS_AWS_KEY_ID, "AKIA" + "q" * 16, "config.ini")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: valid classic GitHub token format-valid-unknown",
        tiers.offline_tier(tiers.CLASS_GITHUB, "ghp_" + "Z" * 36, "app.js")[0]
        == tiers.FORMAT_VALID_UNKNOWN,
    )
    check(
        "tier: GitHub token bad length is false-positive",
        tiers.offline_tier(tiers.CLASS_GITHUB, "ghp_" + "Z" * 10, "app.js")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: your-api-key-here is likely-fixture",
        tiers.offline_tier(tiers.CLASS_GENERIC, "your-api-key-here", "README.md")[0]
        == tiers.LIKELY_FIXTURE,
    )
    check(
        "tier: changeme is likely-fixture",
        tiers.offline_tier(tiers.CLASS_GENERIC, "changeme-placeholder", "a.yaml")[0]
        == tiers.LIKELY_FIXTURE,
    )
    check(
        "tier: short generic value is false-positive",
        tiers.offline_tier(tiers.CLASS_GENERIC, "abc", ".env")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: whitespace-containing generic value is false-positive",
        tiers.offline_tier(tiers.CLASS_GENERIC, "two words here", ".env")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: high-entropy generic value format-valid-unknown",
        tiers.offline_tier(tiers.CLASS_GENERIC, dummy_value(32, 7), "src/app.py")[0]
        == tiers.FORMAT_VALID_UNKNOWN,
    )
    check(
        "tier: value in fixture-style path is likely-fixture",
        tiers.offline_tier(
            tiers.CLASS_GENERIC, dummy_value(32, 8), "tests/fixtures/leaky/.env"
        )[0]
        == tiers.LIKELY_FIXTURE,
    )
    check(
        "tier: .env.example path is likely-fixture",
        tiers.offline_tier(tiers.CLASS_GENERIC, dummy_value(24, 9), ".env.example")[0]
        == tiers.LIKELY_FIXTURE,
    )


def test_tiers_private_key() -> None:
    body = base64.b64encode(b"x" * 64).decode("ascii")
    good_block = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + body
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    bad_block = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "!!!!not-base64-at-all!!!!\n"
        + "-----END OPENSSH PRIVATE KEY-----\n"
    )
    mismatched = "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END EC PRIVATE KEY-----\n"
    check(
        "tier: decodable key block format-valid-unknown",
        tiers.offline_tier(tiers.CLASS_PRIVATE_KEY, good_block, "deploy/id")[0]
        == tiers.FORMAT_VALID_UNKNOWN,
    )
    check(
        "tier: undecodable base64 body is likely-fixture (checksum)",
        tiers.offline_tier(tiers.CLASS_PRIVATE_KEY, bad_block, "deploy/id")
        == (tiers.LIKELY_FIXTURE, "checksum-invalid-base64-body"),
    )
    check(
        "tier: mismatched PEM labels are false-positive",
        tiers.offline_tier(tiers.CLASS_PRIVATE_KEY, mismatched, "deploy/id")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: AWS secret with bad charset is false-positive",
        tiers.offline_tier(tiers.CLASS_AWS_SECRET, "!" * 40, "config.ini")[0]
        == tiers.FALSE_POSITIVE,
    )
    check(
        "tier: AWS secret with undecodable base64 body is likely-fixture",
        tiers.offline_tier(
            tiers.CLASS_AWS_SECRET, "A" * 20 + "=" + "A" * 19, "config.ini"
        )
        == (tiers.LIKELY_FIXTURE, "checksum-invalid-base64"),
    )
    secret_ok = base64.b64encode(b"y" * 30).decode("ascii")
    check(
        "tier: AWS secret with valid shape and base64 is format-valid-unknown",
        tiers.offline_tier(tiers.CLASS_AWS_SECRET, secret_ok, "config.ini")[0]
        == tiers.FORMAT_VALID_UNKNOWN,
    )


def test_apply_outcome() -> None:
    check(
        "outcome: live upgrades to confirmed-live",
        apply_outcome("live", tiers.FORMAT_VALID_UNKNOWN)
        == (tiers.CONFIRMED_LIVE, "network-confirmed-live"),
    )
    check(
        "outcome: dead downgrades to false-positive",
        apply_outcome("dead", tiers.FORMAT_VALID_UNKNOWN)
        == (tiers.FALSE_POSITIVE, "network-confirmed-dead"),
    )
    check(
        "outcome: inconclusive keeps offline tier",
        apply_outcome("inconclusive", tiers.FORMAT_VALID_UNKNOWN)
        == (tiers.FORMAT_VALID_UNKNOWN, "network-inconclusive"),
    )


def test_network_paths_safely() -> None:
    """Exercise the network-mode code paths without touching any
    external API: real check functions are pointed at a closed
    localhost port, and verify_report is driven with stubbed check
    outcomes for tier mapping."""
    from repo_guardian.verifier import liveness

    # Transport failure must map to inconclusive, not raise, and the
    # reason must not embed the credential.
    saved_host, saved_api = liveness.STS_HOST, liveness.GITHUB_API
    try:
        liveness.STS_HOST = "127.0.0.1:1"
        liveness.GITHUB_API = "http://127.0.0.1:1"
        outcome, reason = liveness.check_github("ghp_" + "a" * 36, 2)
        check(
            "network: github check transport failure is inconclusive",
            outcome == "inconclusive" and reason == "transport-failure",
            f"{outcome}/{reason}",
        )
        outcome, reason = liveness.check_aws("AKIA" + "A" * 16, "s" * 40, 2)
        check(
            "network: aws check transport failure is inconclusive",
            outcome == "inconclusive" and reason == "transport-failure",
            f"{outcome}/{reason}",
        )
    finally:
        liveness.STS_HOST, liveness.GITHUB_API = saved_host, saved_api

    # Stubbed outcomes: verify_report must upgrade/downgrade tiers
    # and mark network_checked, all in memory.
    saved_gh = liveness.check_github
    try:
        liveness.check_github = lambda token, timeout: ("live", "stub")
        with tempfile.TemporaryDirectory(prefix="rgv-net-") as tmp:
            token = "ghp_" + dummy_value(36, 99)
            path = os.path.join(tmp, "token.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(token + "\n")
            finding = synthetic_finding("github-pat", "token.txt", token)
            report = synthetic_report([finding])
            report["repo"] = tmp
            verified = verify_report(report, network=True, timeout=1)
            block = verified["findings"][0]["verification"]
            check(
                "network: stubbed live outcome tiers confirmed-live",
                block["tier"] == tiers.CONFIRMED_LIVE
                and block["network_checked"] is True,
                json.dumps(block),
            )
            check(
                "network: confirmed-live passes the gate",
                len(gate(verified)) == 1,
            )
            check(
                "network: verified output never contains the token",
                token not in json.dumps(verified),
            )
            liveness.check_github = lambda token, timeout: ("dead", "stub")
            verified = verify_report(report, network=True, timeout=1)
            block = verified["findings"][0]["verification"]
            check(
                "network: stubbed dead outcome tiers false-positive",
                block["tier"] == tiers.FALSE_POSITIVE,
                json.dumps(block),
            )
            check("network: dead finding does not pass the gate", gate(verified) == [])
    finally:
        liveness.check_github = saved_gh


# ---------------------------------------------------------------------------
# Unit tests: notification gate (pure function, synthetic findings)
# ---------------------------------------------------------------------------

def test_gate() -> None:
    findings = []
    for tier_name in tiers.TIERS:
        finding = synthetic_finding("generic-api-key", "src/app.py", dummy_value(32, hash(tier_name) % 1000))
        finding["verification"] = {
            "credential_class": tiers.CLASS_GENERIC,
            "tier": tier_name,
            "reason": "unit-test",
            "value_recovered": True,
            "network_checked": False,
        }
        findings.append(finding)
    report = synthetic_report(findings)
    gated = gate(report)
    gated_tiers = sorted(f["verification"]["tier"] for f in gated)
    check(
        "gate: only confirmed-live and format-valid-unknown pass",
        gated_tiers == sorted([tiers.CONFIRMED_LIVE, tiers.FORMAT_VALID_UNKNOWN]),
        str(gated_tiers),
    )
    check("gate: does not mutate the input report", report["findings"] == findings)
    check("gate: empty report gates to empty list", gate({"findings": []}) == [])
    check("gate: non-dict input gates to empty list", gate(None) == [])  # type: ignore[arg-type]
    check(
        "gate: finding without verification block is dropped",
        gate({"findings": [{"rule_id": "x"}]}) == [],
    )


def test_verify_report_synthetic() -> None:
    """verify_report over synthetic findings whose values live in a
    temp repo file, proving hash-matched recovery and tiering."""
    with tempfile.TemporaryDirectory(prefix="rgv-") as tmp:
        repo = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(repo, "src"))
        token = dummy_value(32, 42)
        with open(os.path.join(repo, "src", "app.py"), "w", encoding="utf-8") as handle:
            handle.write(f"API_TOKEN = '{token}'\n")
        finding = synthetic_finding("generic-api-key", "src/app.py", token)
        report = synthetic_report([finding])
        report["repo"] = repo
        verified = verify_report(report, network=False)
        check(
            "verify_report: schema_version bumped to 2",
            verified["schema_version"] == 2,
            str(verified.get("schema_version")),
        )
        block = verified["findings"][0]["verification"]
        check(
            "verify_report: recovered value tiers format-valid-unknown",
            block["tier"] == tiers.FORMAT_VALID_UNKNOWN and block["value_recovered"],
            json.dumps(block),
        )
        check(
            "verify_report: offline mode records network_checked false",
            block["network_checked"] is False,
        )
        check(
            "verify_report: gate passes the recovered finding",
            len(gate(verified)) == 1,
        )
        check(
            "verify_report: input report not mutated",
            "verification" not in report["findings"][0],
        )
        check(
            "verify_report: verified output never contains the value",
            token not in json.dumps(verified),
        )
        # Unrecoverable value: point the finding at a missing file.
        missing = synthetic_finding("generic-api-key", "src/gone.py", token)
        v2 = verify_report(synthetic_report([missing]) | {"repo": repo}, network=False)
        check(
            "verify_report: unrecoverable value tiers likely-fixture",
            v2["findings"][0]["verification"]
            == {
                "credential_class": tiers.CLASS_GENERIC,
                "tier": tiers.LIKELY_FIXTURE,
                "reason": "value-unrecoverable",
                "value_recovered": False,
                "network_checked": False,
            },
            json.dumps(v2["findings"][0]["verification"]),
        )
        check(
            "verify_report: unrecoverable finding does not pass the gate",
            gate(v2) == [],
        )
        try:
            verify_report({"nope": True})
            check("verify_report: malformed report raises", False)
        except VerificationError:
            check("verify_report: malformed report raises", True)


# ---------------------------------------------------------------------------
# Fixture tests: scan + verify the six generated repos, offline
# ---------------------------------------------------------------------------

def scan_and_verify(repo_path: str, tmpdir: str, label: str) -> tuple:
    scan_out = os.path.join(tmpdir, f"{label}_scan.json")
    verified_out = os.path.join(tmpdir, f"{label}_verified.json")
    gate_out = os.path.join(tmpdir, f"{label}_gate.json")
    proc = subprocess.run(
        SCAN_CLI + [repo_path, "--output", scan_out, "--quiet"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"scan failed for {label}: {proc.stderr.strip()}")
    vproc = subprocess.run(
        VERIFY_CLI + [scan_out, "--quiet", "--output", verified_out, "--gate", gate_out],
        capture_output=True, text=True, cwd=ROOT,
    )
    with open(verified_out, "r", encoding="utf-8") as handle:
        verified = json.load(handle)
    with open(gate_out, "r", encoding="utf-8") as handle:
        gated = json.load(handle)
    return vproc, verified, gated


def test_fixtures(manifest: dict) -> dict:
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="rgv-fix-") as tmp:
        for name in manifest:
            proc, verified, gated = scan_and_verify(
                os.path.join(FIXTURES, name), tmp, name
            )
            outputs[name] = (proc, verified, gated)

        non_gate = {tiers.LIKELY_FIXTURE, tiers.FALSE_POSITIVE}
        for name in ("leaky_aws_config", "leaky_private_key", "leaky_env_file"):
            proc, verified, gated = outputs[name]
            findings = verified["findings"]
            check(f"{name}: rg-verify exit code is 0 or 1", proc.returncode in (0, 1),
                  f"exit={proc.returncode}")
            check(f"{name}: findings were verified", len(findings) > 0)
            tiers_seen = {f["verification"]["tier"] for f in findings}
            check(
                f"{name}: no planted dummy is confirmed-live offline",
                tiers.CONFIRMED_LIVE not in tiers_seen,
                str(sorted(tiers_seen)),
            )
            check(
                f"{name}: every dummy tiers in an allowed offline tier",
                tiers_seen <= {tiers.FORMAT_VALID_UNKNOWN, tiers.LIKELY_FIXTURE},
                str(sorted(tiers_seen)),
            )
            check(
                f"{name}: offline run performed no network checks",
                all(not f["verification"]["network_checked"] for f in findings),
            )
            check(
                f"{name}: every finding recovered its value by hash",
                all(f["verification"]["value_recovered"] for f in findings),
            )
            check(
                f"{name}: gate list matches gated tier membership",
                len(gated["findings"])
                == sum(
                    1
                    for f in findings
                    if f["verification"]["tier"] in tiers.GATE_TIERS
                ),
            )

        pk_findings = outputs["leaky_private_key"][1]["findings"]
        pk_block = [f for f in pk_findings if f["rule_id"] == "private-key"]
        check(
            "leaky_private_key: private-key class detected by verifier",
            bool(pk_block)
            and pk_block[0]["verification"]["credential_class"]
            == tiers.CLASS_PRIVATE_KEY,
            json.dumps([f["verification"] for f in pk_findings]),
        )

        aws_findings = outputs["leaky_aws_config"][1]["findings"]
        aws_block = [f for f in aws_findings if f["rule_id"] == "aws-access-token"]
        check(
            "leaky_aws_config: aws-access-key-id class detected by verifier",
            bool(aws_block)
            and aws_block[0]["verification"]["credential_class"]
            == tiers.CLASS_AWS_KEY_ID,
            json.dumps([f["verification"] for f in aws_findings]),
        )

        for name in ("clean_docs", "clean_high_entropy", "clean_placeholders"):
            proc, verified, gated = outputs[name]
            check(f"{name}: verified report has zero findings",
                  verified["finding_count"] == 0)
            check(f"{name}: rg-verify exit code 0 (empty gate)",
                  proc.returncode == 0, f"exit={proc.returncode}")
            check(f"{name}: gate is empty", gated["notification_count"] == 0)

        # Placeholder-shaped values, tiered in memory as if a scanner
        # had passed them through (clean_placeholders itself never
        # reaches the verifier: the scanner allowlists it).
        placeholder_checks = [
            ("AKIA" + "IOSFODNN7EXA" + "MPLE", tiers.CLASS_AWS_KEY_ID),
            ("your-api-key-here", tiers.CLASS_GENERIC),
            ("changeme-placeholder", tiers.CLASS_GENERIC),
            ("https://user:pass@example.com/hook", tiers.CLASS_GENERIC),
        ]
        for value, klass in placeholder_checks:
            tier, _ = tiers.offline_tier(klass, value, "docs/credentials.md")
            check(
                f"placeholders: fixture-style value tiers likely-fixture or false-positive",
                tier in non_gate,
                f"tier={tier}",
            )

        # Redaction: no planted dummy value in any verifier output.
        blob = json.dumps(
            {"v": [o[1] for o in outputs.values()], "g": [o[2] for o in outputs.values()],
             "stderr": [o[0].stderr for o in outputs.values()],
             "stdout": [o[0].stdout for o in outputs.values()]}
        )
        leaks = []
        for name, info in manifest.items():
            for value in info.get("planted_values", []):
                if value and value in blob:
                    leaks.append((name, value[:6] + "..."))
        check("redaction: no planted value in verifier output", not leaks, str(leaks))
    return outputs


def main() -> int:
    test_detect_class()
    test_tiers_structure()
    test_tiers_private_key()
    test_apply_outcome()
    test_network_paths_safely()
    test_gate()
    test_verify_report_synthetic()
    test_fixtures(ensure_fixtures())

    print()
    print(f"{PASSED} passed, {FAILED} failed")
    if FAILED:
        for name in FAILURES:
            print(f"  failed: {name}")
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
