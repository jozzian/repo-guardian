# Design Decisions

## Wrap gitleaks, do not build detectors from scratch

Decision: use gitleaks 8.24.x as the detection engine and build the
value-add layer in Python around it.

Rationale: the differentiator of Repo Guardian is verification and
notification quality (later issues), not regex speed or rule
coverage. Gitleaks already maintains hundreds of curated rules with
tuned entropy checks, keyword guards, and allowlists. Writing our own
rule set would spend the entire project budget re-deriving worse
versions of what gitleaks ships, and then we would own its
maintenance forever.

Rejected alternative: a from-scratch scanner (custom regex and
entropy rules in Python). It would give full control and remove the
binary dependency, but it trades away years of rule curation for a
dependency that is a single static binary with a stable JSON report
format. Not worth it.

What the wrapper adds: strict redaction (gitleaks JSON includes
Secret and Match fields; the wrapper reads the value only through
sha256 and never copies it to output), fingerprinting and dedupe
across working tree and history (gitleaks reports one entry per
sighting), severity mapping, a stable output schema for downstream
consumers, and a scanner-owned precision config.

## Fingerprint design

Decision: fingerprint = sha256(rule id, file path, sha256(secret
value)), truncated to 16 hex characters. Commit hashes and line
numbers are excluded from the hash input and stored in a per-finding
locations list instead.

Rationale: the same secret typically appears in many places in
history: the commit that introduced it, later commits that touch the
file, and the working tree. A fingerprint over (rule, file, secret
hash) collapses all of those into one finding, which is what a
reviewer or a notification consumer wants: one issue, one location
list, one dedupe key across re-scans. Including the commit in the
hash would explode a single problem into N findings.

The secret hash term is required even though file and rule often
suffice, because one file can hold two different values matching the
same rule, and they are genuinely separate findings. Hashing the
value is safe; emitting it is not.

Rejected alternative: gitleaks fingerprint or (file, line, rule)
tuples. Line numbers drift between commits and edits, so any
line-based key fails the cross-commit dedupe requirement.

## Config lives with the scanner

Decision: the gitleaks allowlist config is repo_guardian/gitleaks.toml
in this repository, passed via --config on every run. It is not
placed in scanned repositories or fixtures.

Rationale: precision policy belongs to the scanner. If a scanned repo
carried its own .gitleaks.toml, that repo could weaken or silence its
own detection, and acceptance tests would be tuning the thing they
verify. Keeping one config in one reviewed place makes the false
positive policy auditable.

Rejected alternative: per-repo .gitleaks.toml (gitleaks default
behavior). Convenient for standalone gitleaks users, wrong trust
model for a guard tool.

## Fixtures are generated, never committed

Decision: tests/make_fixtures.py builds six small git repos under
tests/fixtures/ at test time; that directory is gitignored. Planted
secrets are deterministic dummies (seeded RNG, AWS documentation
style values), and the generator writes a manifest of planted values
so the acceptance test can prove none of them ever appear in scanner
output.

Rationale: committing secret-shaped files to this repo would make the
guard tool itself fail its own scan, and would put dummy credentials
into permanent history. Generation keeps the main tree clean and the
fixture content under review in one script.
