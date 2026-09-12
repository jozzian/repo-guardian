#!/usr/bin/env python3
"""Repo Guardian acceptance test.

Runs the scanner CLI against all six generated fixtures and asserts:
  * every leaky fixture reports its expected rule class (zero misses),
  * every clean fixture reports zero findings (zero false positives),
  * the scan mode flags behave (history-only and working-tree-only
    modes each find what they should),
  * no planted secret value appears anywhere in scanner JSON output,
  * fingerprints are stable across repeated scans and dedupe merges
    working-tree and history sightings of the same secret,
  * exit codes are correct (0 clean, 1 findings, 2 error).

Usage: python3 tests/run_acceptance.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
CLI = [sys.executable, os.path.join(ROOT, "repo_guardian", "cli.py")]

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


def scan(repo: str, mode: str = "both") -> tuple:
    """Run the CLI and return (exit_code, report_dict, raw_stdout)."""
    proc = subprocess.run(
        CLI + [repo, "--mode", mode], capture_output=True, text=True, cwd=ROOT
    )
    try:
        report = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        report = {}
    return proc.returncode, report, proc.stdout


def rules_found(report: dict) -> set:
    return {f["rule_id"] for f in report.get("findings", [])}


def ensure_fixtures() -> dict:
    manifest_path = os.path.join(FIXTURES, "manifest.json")
    if not os.path.exists(manifest_path):
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "make_fixtures.py")],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("error: fixture generation failed:")
            print(proc.stdout + proc.stderr)
            sys.exit(2)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return {m["name"]: m for m in json.load(handle)}


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def main() -> int:
    manifest = ensure_fixtures()
    check("fixtures generated", len(manifest) == 6, f"got {len(manifest)}")

    leaky_expected = {
        "leaky_aws_config": {"aws-access-token"},
        "leaky_private_key": {"private-key"},
        "leaky_env_file": {"generic-api-key"},
    }
    clean_names = ("clean_docs", "clean_high_entropy", "clean_placeholders")

    # 1. Leaky fixtures: every expected rule class detected, exit 1.
    reports = {}
    for name, expected in leaky_expected.items():
        code, report, _ = scan(fixture(name))
        reports[name] = report
        found = rules_found(report)
        check(
            f"{name}: exit code 1",
            code == 1,
            f"exit={code}",
        )
        check(
            f"{name}: detects {sorted(expected)}",
            expected.issubset(found),
            f"found={sorted(found)}",
        )

    # 2. History-only leaks must be found by history mode; the
    #    working-tree mode must NOT find them (they are gone from the
    #    tree) for the two removal fixtures.
    code, hist, _ = scan(fixture("leaky_aws_config"), "history")
    check(
        "leaky_aws_config: history mode finds aws-access-token",
        "aws-access-token" in rules_found(hist),
        f"found={sorted(rules_found(hist))}",
    )
    code, tree, _ = scan(fixture("leaky_aws_config"), "working-tree")
    check(
        "leaky_aws_config: working-tree mode is clean after removal",
        tree.get("finding_count") == 0,
        f"found={sorted(rules_found(tree))}",
    )

    # 3. Dedupe: the private key is in history AND working tree; in
    #    'both' mode it appears exactly once, with two locations.
    pk_findings = [
        f for f in reports["leaky_private_key"].get("findings", [])
        if f["rule_id"] == "private-key"
    ]
    check(
        "leaky_private_key: one deduped finding",
        len(pk_findings) == 1,
        f"count={len(pk_findings)}",
    )
    if pk_findings:
        sources = {loc["source"] for loc in pk_findings[0]["locations"]}
        check(
            "leaky_private_key: finding lists both working-tree and history locations",
            sources == {"working-tree", "history"},
            f"sources={sorted(sources)}",
        )

    # 4. Clean fixtures: zero findings, exit 0.
    for name in clean_names:
        code, report, _ = scan(fixture(name))
        reports[name] = report
        check(
            f"{name}: exit code 0",
            code == 0,
            f"exit={code}",
        )
        check(
            f"{name}: zero findings",
            report.get("finding_count") == 0,
            f"findings={[f['rule_id'] for f in report.get('findings', [])]}",
        )

    # 5. Redaction: no planted dummy value appears in any report.
    all_output = json.dumps(list(reports.values()))
    leaks = []
    for name, info in manifest.items():
        for value in info.get("planted_values", []):
            if value and value in all_output:
                leaks.append((name, value[:8] + "..."))
    check("redaction: no planted secret value in scanner output", not leaks, str(leaks))
    # Also check raw stdout for the forbidden gitleaks fields.
    forbidden_keys = ['"Secret"', '"Match"', '"Description"']
    present = [k for k in forbidden_keys if k in all_output]
    check("redaction: no Secret/Match/Description fields in output", not present, str(present))

    # 6. Fingerprint stability: same scan twice yields same fingerprints.
    _, first, _ = scan(fixture("leaky_private_key"))
    _, second, _ = scan(fixture("leaky_private_key"))
    fp1 = sorted(f["fingerprint"] for f in first.get("findings", []))
    fp2 = sorted(f["fingerprint"] for f in second.get("findings", []))
    check("fingerprint: stable across re-scans", fp1 == fp2 and fp1 != [], f"{fp1} vs {fp2}")
    check(
        "fingerprint: 16 hex chars",
        all(len(x) == 16 and all(c in "0123456789abcdef" for c in x) for x in fp1),
        str(fp1),
    )

    # 7. Schema sanity on one finding.
    finding = reports["leaky_aws_config"]["findings"][0]
    required = {"file", "rule_id", "severity", "fingerprint", "locations",
                "secret_sha256_prefix"}
    check("schema: finding has required fields", required.issubset(finding.keys()),
          str(sorted(finding.keys())))
    loc = finding["locations"][0]
    check("schema: location has source/commit/line", {"source", "commit", "line"}.issubset(loc.keys()),
          str(sorted(loc.keys())))

    # 8. Error handling: nonexistent path exits 2.
    proc = subprocess.run(CLI + ["/nonexistent/path/xyz"], capture_output=True, text=True, cwd=ROOT)
    check("errors: nonexistent path exits 2", proc.returncode == 2, f"exit={proc.returncode}")

    # 9. --output file works and matches stdout.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "report.json")
        proc = subprocess.run(
            CLI + [fixture("clean_docs"), "--output", out, "--quiet"],
            capture_output=True, text=True, cwd=ROOT,
        )
        ok = proc.returncode == 0 and os.path.exists(out)
        if ok:
            with open(out, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            ok = data.get("finding_count") == 0
        check("--output writes report file", ok, f"exit={proc.returncode}")

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
