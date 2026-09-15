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

## Verification is offline by default (JOZ-180)

Decision: rg-verify tiers findings with local heuristics only.
Network liveness checks (AWS STS GetCallerIdentity, GitHub GET /user)
run exclusively behind the opt-in --verify-network flag.

Rationale: three reasons. First, safety: an automated pipeline must
never send credentials found in an untrusted repository to a
third-party API without a human deciding to do so; a leaked key
probing api.github.com from CI could itself be an abuse signal
against the victim account. Second, testability: the acceptance and
verification suites plant dead dummies and must run in sandboxes with
no network; offline defaults make every test hermetic. Third,
determinism: offline tiering gives the same verdict for the same
input, while network verdicts depend on transient API state.

Rejected alternative: always-on liveness. It produces the strongest
signal but breaks all three properties above, and the strongest
signal is only needed at notification time, which is exactly where
the opt-in flag sits.

Scope limit inside network mode: identity confirmation only. STS
GetCallerIdentity and GET /user answer "does this credential work"
and nothing more; no data calls, no write calls, no other endpoints.
A dead credential maps to false-positive rather than a fifth tier,
keeping the four-tier vocabulary from the brief intact. Inconclusive
results (timeouts, unexpected statuses) keep the offline tier, so a
flaky network can never silently suppress a real leak.

## Confidence tiers instead of binary live/dead

Decision: every verified finding carries one of four tiers:
confirmed-live, format-valid-unknown, likely-fixture, false-positive.

Rationale: a binary live/dead verdict is only honest after a network
check, and most findings will never get one (offline mode, classes
with no safe probe, values that cannot be paired). Tiers express the
actual epistemic state: what the verifier knows, and how it knows it.
The tiers also give the notification layer a policy surface: JOZ-181
decides whom to page per tier instead of inheriting one bit of
judgment from the verifier.

Rejected alternative: a confidence score from 0 to 1. It looks more
precise but the precision is fake: heuristics do not produce
calibrated probabilities, and consumers would have to invent
thresholds anyway. Four named states with machine-readable reason
strings are auditable; a float is not.

## The notification gate is a separate pure function

Decision: gate(verified_report) returns exactly the findings allowed
to reach notification (tiers confirmed-live and format-valid-unknown)
as a pure function with no I/O, no mutation, and no hidden state.

Rationale: the gate is the single point where a false negative
becomes a missed breach and a false positive becomes an alert nobody
trusts. Making it a pure function means its behavior is fully
determined by the verified report, trivially unit-testable, and
directly importable by JOZ-181 without re-implementing tier policy.
The CLI's --gate output file and exit code (0 empty, 1 non-empty)
are thin wrappers over the same function, so the file, the exit
code, and the library can never disagree.

Rejected alternative: filtering inside the notification layer. Two
consumers would eventually encode two policies, and the safety
property "fixtures and invalid values never reach a human channel"
would live in code that JOZ-180 does not own.

## The verifier recovers values transiently, by hash match

Decision: the scanner report stays redacted (schema_version 1 never
carries values), and rg-verify re-extracts each candidate value from
the repository at the reported location, accepting a candidate only
when its sha256 prefix equals the finding's secret_sha256_prefix.
The recovered value lives in process memory during checks and is
never written to the verified report, a reason string, a log line, or
an error message.

Rationale: structural validation and liveness checks need the raw
value, but the report is a durable artifact that may be stored,
shared, or pasted into tickets. Keeping redaction in the artifact and
value access in the process preserves the JOZ-179 guarantee without
weakening verification. The hash match proves the recovered string is
exactly what the scanner saw, so drift or a wrong candidate cannot
produce a verdict about a different value.

Fail-open note: a value that cannot be recovered (file deleted,
history rewritten) tiers as likely-fixture with reason
value-unrecoverable and leaves the gate, trading a possible missed
notification for immunity to noise from stale findings. Reviewers may
want to invert this; the choice is recorded here so it is a
decision, not an accident.
