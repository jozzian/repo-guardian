# Repo Guardian

Repo Guardian scans git repositories for leaked secrets and
credentials with a low false positive rate. It wraps gitleaks for
candidate generation and adds three things gitleaks does not provide:
a strict redaction guarantee (secret values never reach the output,
not even partially), stable finding fingerprints that dedupe the same
secret across the working tree and the full commit history, and a
structured JSON report designed for downstream agent verification and
notification (planned future layers).

The architecture decision in one line: we wrap gitleaks rather than
write our own detectors, because the differentiator of this project is
verification and notification quality layered on top of detection, not
regex speed or coverage. Gitleaks maintains hundreds of curated rules;
duplicating them would be wasted effort. See
docs/design-decisions.md.

## Requirements

  * Python 3.10 or newer (standard library only, no third-party
    packages)
  * gitleaks 8.24.x on PATH (or set RG_GITLEAKS_BIN to its location)
  * git

## Usage

    ./rg-scan /path/to/repo                     # scan tree + history
    ./rg-scan /path/to/repo --mode working-tree # current files only
    ./rg-scan /path/to/repo --mode history      # commit history only
    ./rg-scan /path/to/repo --output report.json
    python3 repo_guardian/cli.py /path/to/repo  # equivalent

The JSON report goes to stdout, and optionally to the file given by
--output. Errors go to stderr.

## Output schema

Each finding carries a rule id, file path, severity, fingerprint, and
a list of locations (one per sighting: working tree and/or each
historical commit). The fingerprint is the first 16 hex characters of
a sha256 over (rule id, file path, hash of the secret value), so the
same secret seen in five commits appears once. Secret values are
hashed for the fingerprint but never emitted, and the gitleaks Secret,
Match, and Description fields are stripped. Example (values are
dummies):

    {
      "schema_version": 1,
      "scanner": "repo-guardian",
      "gitleaks_version": "8.24.3",
      "repo": "/srv/repos/example",
      "mode": "both",
      "scanned_at": "2026-09-12T12:00:00+00:00",
      "finding_count": 1,
      "findings": [
        {
          "rule_id": "aws-access-token",
          "file": "config.ini",
          "severity": "high",
          "fingerprint": "4ca0e911a978662f",
          "secret_sha256_prefix": "5369b0bed4babe9e",
          "locations": [
            {
              "source": "history",
              "commit": "ff8c2b9897780cadcfd463de2d98ea423bf6e2b8",
              "line": 2,
              "date": "2026-09-12T11:00:00Z"
            }
          ]
        }
      ]
    }

## Verification (agent layer)

Scanning and verification are separate steps. rg-scan finds candidate
secrets; rg-verify reads a scanner JSON report, re-extracts each
candidate value transiently by hash match (the value is never
emitted), tiers every finding by confidence, and gates notifications
so only plausible live leaks pass:

    ./rg-scan /path/to/repo --output report.json
    ./rg-verify report.json                       # offline tiering
    ./rg-verify report.json --verify-network      # opt-in live checks
    ./rg-verify report.json --output verified.json --gate gate.json

Liveness checks are opt-in via --verify-network. The default is
offline heuristic tiering, so tests and CI sandboxes never contact
external APIs with dummy credentials. In network mode the verifier
makes identity-confirmation calls only: AWS STS GetCallerIdentity
(SigV4 signed, read-only) for AWS access key ids, and GET
https://api.github.com/user for GitHub tokens. Every other class has
no safe liveness check and is tiered by format heuristics alone.

Confidence tiers:

  * confirmed-live        a liveness check proved the credential
                          works (network mode only).
  * format-valid-unknown  structurally valid and not a known
                          fixture; liveness unknown.
  * likely-fixture        matches a placeholder pattern
                          (AKIAIO...MPLE, your-api-key-here,
                          changeme, example.com), sits in a
                          fixture-style path, or fails a checksum
                          sanity test (a PEM block whose base64 body
                          does not decode).
  * false-positive        structurally invalid for its class, or
                          proven dead by a liveness check.

Only confirmed-live and format-valid-unknown findings pass the
notification gate. The gate is a pure function,
repo_guardian.verifier.gate(report), which the notification layer
(JOZ-181) consumes directly.

## Verified output schema

rg-verify emits the scanner report with schema_version bumped to 2:
every finding gains a verification block, and the report gains
verified_at, verify_network, tier_summary, and notification_count
fields. The bump is a new major shape (added keys per finding), so
consumers must detect it rather than assume scanner shape. The
--output file gets the full verified report; the --gate file holds
just the notification input (schema_version, source_report,
notification_count, and the gated findings list). Verification block
fields are fixed-vocabulary strings only; the recovered value exists
transiently in verifier memory and appears in no output, log line, or
error message. Example (values are dummies):

    {
      "schema_version": 2,
      "scanner": "repo-guardian",
      "repo": "/srv/repos/example",
      "verified_at": "2026-09-15T12:00:00+00:00",
      "verify_network": false,
      "finding_count": 1,
      "tier_summary": {
        "confirmed-live": 0,
        "format-valid-unknown": 1,
        "likely-fixture": 0,
        "false-positive": 0
      },
      "notification_count": 1,
      "findings": [
        {
          "rule_id": "aws-access-token",
          "file": "config.ini",
          "fingerprint": "4ca0e911a978662f",
          "verification": {
            "credential_class": "aws-access-key-id",
            "tier": "format-valid-unknown",
            "reason": "format-valid",
            "value_recovered": true,
            "network_checked": false
          }
        }
      ]
    }

## Exit codes

rg-scan:

  * 0  scan completed, no findings
  * 1  scan completed, findings present
  * 2  scanner error (missing repo, missing gitleaks, bad report)

rg-verify:

  * 0  verification completed, notification gate is empty
  * 1  verification completed, gate is non-empty (findings worth
       notifying)
  * 2  verification error (unreadable or malformed report)

## Configuration

The gitleaks config lives with the scanner at
repo_guardian/gitleaks.toml, not in scanned repositories. Rationale:
the scanner owns its precision policy. A repo that could edit its own
allowlist could silence its own findings. The config extends the
gitleaks default rule set and allowlists documented placeholder values
(the AWS example key AKIAIO...MPLE, "your-api-key-here", and lines
marked example/placeholder/dummy). Override per run with --config.

## Tests

    ./tests/run_acceptance.sh    # scanner acceptance tests
    ./tests/run_verification.sh  # verification tier, gate, and redaction

The scripts regenerate six fixture repositories under
tests/fixtures/ (gitignored; fixtures are built by
tests/make_fixtures.py, never committed, so no secret-shaped files
live in this repo tree). The acceptance run asserts: three leaky
fixtures each surface their expected rule class (including
history-only leaks), three clean fixtures produce zero findings
(plain docs, a lockfile full of high-entropy hashes plus base64 image
data, and documented placeholder keys), fingerprints are stable and
dedupe across modes, and no planted dummy value ever appears in
scanner output. The verification run adds: every planted dummy tiers
offline as format-valid-unknown or likely-fixture (never
confirmed-live), placeholder fixture values tier likely-fixture or
false-positive, tier and gate unit tests pass on synthetic findings,
transport failures degrade to inconclusive without leaking values
into reasons, and no secret value appears anywhere in verified or
gated output. Neither suite touches the network.
