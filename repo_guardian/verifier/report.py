"""Report-level verification: enrich a scanner report with tiers.

verify_report() consumes the scanner JSON report produced by rg-scan
and returns a new report (schema_version 2) where every finding
carries a verification block:

    "verification": {
        "credential_class": "aws-access-key-id",
        "tier": "format-valid-unknown",
        "reason": "format-valid",
        "value_recovered": true,
        "network_checked": false
    }

gate() is a pure function over a verified report that returns only
the findings allowed to reach the notification stage (tiers
confirmed-live and format-valid-unknown). JOZ-181 consumes it.

Redaction: the verification block contains fixed-vocabulary strings
only. A recovered secret value exists transiently in memory during
verification and is never written into the report, a reason, a log
line, or an error message.

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import extraction, tiers

VERIFIED_SCHEMA_VERSION = 2


class VerificationError(Exception):
    """Fatal verification problem; maps to exit code 2.

    Messages must never quote a secret value; they describe shapes
    and files only.
    """


def _load_checkers(network: bool, timeout: int) -> dict:
    """Import network checkers only when the caller opted in."""
    if not network:
        return {}
    from . import liveness

    return {"liveness": liveness, "timeout": timeout}


def verify_finding(
    repo: str, finding: dict, checkers: dict, network: bool
) -> dict:
    """Verify one finding and return its verification block.

    Steps: recover the value by hash match, classify it, tier it
    offline, then (network mode only) upgrade the tier with a safe
    liveness check for AWS key ids and GitHub tokens.
    """
    value, how = extraction.recover_value(
        repo, finding, finding.get("secret_sha256_prefix", "")
    )
    rule_id = finding.get("rule_id", "")
    file_path = finding.get("file", "")

    if value is None:
        # Nothing recoverable (file gone, blob missing, or drift).
        # Without a value no structural claim is possible; keep the
        # finding out of the gate rather than guessing.
        return {
            "credential_class": tiers.detect_class(rule_id, ""),
            "tier": tiers.LIKELY_FIXTURE,
            "reason": "value-unrecoverable",
            "value_recovered": False,
            "network_checked": False,
        }

    klass = tiers.detect_class(rule_id, value)
    tier, reason = tiers.offline_tier(klass, value, file_path)
    network_checked = False

    if (
        network
        and klass in tiers.NETWORK_CHECKABLE
        and tier == tiers.FORMAT_VALID_UNKNOWN
    ):
        liveness = checkers["liveness"]
        timeout = checkers["timeout"]
        outcome = None
        if klass == tiers.CLASS_AWS_KEY_ID:
            # Pair the access key id with a secret from the same
            # content; without a secret the signed check cannot run.
            secret = _find_pairing_secret(repo, finding, value)
            if secret is not None:
                network_checked = True
                outcome, check_reason = liveness.check_aws(value, secret, timeout)
                tier, reason = liveness.apply_outcome(outcome, tier)
        elif klass == tiers.CLASS_GITHUB:
            network_checked = True
            outcome, check_reason = liveness.check_github(value, timeout)
            tier, reason = liveness.apply_outcome(outcome, tier)
        if outcome == "inconclusive":
            reason = "network-inconclusive"

    return {
        "credential_class": klass,
        "tier": tier,
        "reason": reason,
        "value_recovered": True,
        "network_checked": network_checked,
    }


def _find_pairing_secret(repo: str, finding: dict, access_key: str):
    """Locate the AWS secret access key that pairs with an access key
    id finding, by reading the same file content the key came from.

    Returns the secret value transiently, or None. Never emitted.
    """
    for location in finding.get("locations", []):
        text = extraction.load_location_text(repo, finding.get("file", ""), location)
        if text is None:
            continue
        secret = extraction.find_aws_secret_near(text, access_key)
        if secret is not None:
            return secret
    return None


def verify_report(report: dict, network: bool = False, timeout: int = 10) -> dict:
    """Verify every finding in a scanner report and return a new
    report with schema_version 2 and per-finding verification blocks.

    The input report is not mutated. Raises VerificationError on a
    malformed report.
    """
    if not isinstance(report, dict) or "findings" not in report:
        raise VerificationError("report is not a scanner JSON report (no findings key)")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise VerificationError("report findings is not a list")

    checkers = _load_checkers(network, timeout)
    verified_findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise VerificationError("finding is not an object")
        enriched = dict(finding)
        enriched["verification"] = verify_finding(
            report.get("repo", ""), finding, checkers, network
        )
        verified_findings.append(enriched)

    summary = {tier: 0 for tier in tiers.TIERS}
    for finding in verified_findings:
        summary[finding["verification"]["tier"]] += 1

    verified = dict(report)
    verified["schema_version"] = VERIFIED_SCHEMA_VERSION
    verified["findings"] = verified_findings
    verified["verified_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    verified["verify_network"] = bool(network)
    verified["tier_summary"] = summary
    verified["notification_count"] = sum(
        1 for f in verified_findings if f["verification"]["tier"] in tiers.GATE_TIERS
    )
    return verified


def gate(verified_report: dict) -> list:
    """Pure notification gate (JOZ-180 requirement 3).

    Given a verified report, return the list of findings allowed to
    reach the notification stage: tier confirmed-live or
    format-valid-unknown. Findings tiered likely-fixture or
    false-positive are dropped. No I/O, no mutation: JOZ-181 can
    consume this directly.
    """
    if not isinstance(verified_report, dict):
        return []
    return [
        finding
        for finding in verified_report.get("findings", [])
        if isinstance(finding, dict)
        and finding.get("verification", {}).get("tier") in tiers.GATE_TIERS
    ]
