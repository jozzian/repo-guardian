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

## Exit codes

  * 0  scan completed, no findings
  * 1  scan completed, findings present
  * 2  scanner error (missing repo, missing gitleaks, bad report)

## Configuration

The gitleaks config lives with the scanner at
repo_guardian/gitleaks.toml, not in scanned repositories. Rationale:
the scanner owns its precision policy. A repo that could edit its own
allowlist could silence its own findings. The config extends the
gitleaks default rule set and allowlists documented placeholder values
(the AWS example key AKIAIO...MPLE, "your-api-key-here", and lines
marked example/placeholder/dummy). Override per run with --config.

## Tests

    ./tests/run_acceptance.sh

The script regenerates six fixture repositories under
tests/fixtures/ (gitignored; fixtures are built by
tests/make_fixtures.py, never committed, so no secret-shaped files
live in this repo tree), then asserts: three leaky fixtures each
surface their expected rule class (including history-only leaks),
three clean fixtures produce zero findings (plain docs, a lockfile
full of high-entropy hashes plus base64 image data, and documented
placeholder keys), fingerprints are stable and dedupe across modes,
and no planted dummy value ever appears in scanner output.
