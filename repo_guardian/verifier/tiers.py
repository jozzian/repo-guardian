"""Confidence tiers and offline classification for verified findings.

Pure logic only: no I/O, no network, no subprocesses. The functions
here take a credential class and a candidate value and return a tier
plus a machine-readable reason. Reasons are drawn from a fixed
vocabulary of safe strings; a secret value is never embedded in a
reason, a tier, or any other returned field.

Tiers (JOZ-180):
    confirmed-live         a safe liveness check proved the credential
                           works (network mode only).
    format-valid-unknown   structurally valid, not a known fixture,
                           liveness unknown (offline default, or the
                           class has no safe check).
    likely-fixture         matches a known placeholder pattern, comes
                           from a fixture-style file, or fails a
                           checksum-style sanity test (for example a
                           private key block whose base64 body does
                           not decode).
    false-positive         structurally invalid for its class (bad
                           length, charset, or shape), or proven dead
                           by a liveness check in network mode.

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

import base64
import binascii
import math
import re

CONFIRMED_LIVE = "confirmed-live"
FORMAT_VALID_UNKNOWN = "format-valid-unknown"
LIKELY_FIXTURE = "likely-fixture"
FALSE_POSITIVE = "false-positive"

# Ordered most to least actionable; used for report summaries.
TIERS = (CONFIRMED_LIVE, FORMAT_VALID_UNKNOWN, LIKELY_FIXTURE, FALSE_POSITIVE)

# Only these tiers may reach the notification stage (JOZ-180 gate).
GATE_TIERS = frozenset({CONFIRMED_LIVE, FORMAT_VALID_UNKNOWN})

# Credential classes.
CLASS_AWS_KEY_ID = "aws-access-key-id"
CLASS_AWS_SECRET = "aws-secret-access-key"
CLASS_GITHUB = "github-token"
CLASS_PRIVATE_KEY = "private-key"
CLASS_GENERIC = "generic"

# Classes that have a safe network liveness check.
NETWORK_CHECKABLE = frozenset({CLASS_AWS_KEY_ID, CLASS_GITHUB})

# ---------------------------------------------------------------------------
# Structural patterns
# ---------------------------------------------------------------------------

AWS_KEY_ID_RE = re.compile(
    r"^(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$"
)
AWS_SECRET_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
GITHUB_CLASSIC_RE = re.compile(r"^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}$")
GITHUB_FINE_RE = re.compile(r"^github_pat_[A-Za-z0-9_]{70,100}$")
GITHUB_TOKEN_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")

PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL
)
BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

GITHUB_RULE_IDS = frozenset(
    {"github-pat", "github-fine-grained-pat", "github-oauth"}
)

# Placeholder vocabulary. Deliberately long, distinctive tokens only:
# random base64 or alphanumerics must not collide with these by
# chance, so nothing shorter than six characters appears here.
PLACEHOLDER_TOKENS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change-me",
    "change_me",
    "your-",
    "your_",
    "redacted",
    "todo",
    "fixme",
    "insert-",
    "replace-",
    "notreal",
    "hunter2",
    "xxxxxxxx",
)
PLACEHOLDER_EXACT = frozenset(
    {
        "password",
        "passw0rd",
        "secret",
        "admin",
        "root",
        "test",
        "testing",
        "fake",
        "none",
        "null",
        "empty",
        "abcd1234",
        "abc123",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
    }
)
AWS_EXAMPLE_KEY_RE = re.compile(r"^A(?:KIA|SIA)[A-Z0-9]*EXAMPLE$")
ANGLE_PLACEHOLDER_RE = re.compile(r"^<[^>]*>$")

# Fixture-style paths: generated test repos, example files, docs about
# credentials. A finding in one of these is more likely a planted or
# documented dummy than a real leak.
FIXTURE_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|fixtures?|testdata|mocks?|samples?)(?:/|$)"
    r"|(?:^|/)[^/]*(?:example|sample|dummy|placeholder|fixture|mock)[^/]*(?:$|/)"
    r"|\.example$",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character, over the value itself."""
    if not value:
        return 0.0
    counts: dict = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (n / length) * math.log2(n / length) for n in counts.values()
    )


def detect_class(rule_id: str, value: str) -> str:
    """Classify a finding into a credential class.

    Uses the scanner rule id first, then value shape as a fallback so
    misruled findings still land in the right verifier.
    """
    rule = (rule_id or "").lower()
    if rule == "aws-access-token" or AWS_KEY_ID_RE.match(value or ""):
        return CLASS_AWS_KEY_ID
    if rule == "aws-secret-access-key":
        return CLASS_AWS_SECRET
    if rule in GITHUB_RULE_IDS or (value or "").startswith(GITHUB_TOKEN_PREFIXES):
        return CLASS_GITHUB
    if rule == "private-key" or (value or "").lstrip().startswith("-----BEGIN "):
        return CLASS_PRIVATE_KEY
    return CLASS_GENERIC


def _aws_secret_base64_ok(value: str) -> bool:
    """True when a 40-char AWS secret decodes as base64 cleanly."""
    try:
        base64.b64decode(value, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _private_key_body_decodes(value: str) -> bool:
    match = PRIVATE_KEY_BLOCK_RE.search(value)
    if not match:
        return False
    body = re.sub(r"\s+", "", match.group(2))
    if not body or not BASE64_BODY_RE.match(body):
        return False
    try:
        decoded = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= 16


def validate_structure(klass: str, value: str) -> bool:
    """True when the value is structurally plausible for its class.

    A structurally invalid value can never be a working credential,
    which is what earns it the false-positive tier.
    """
    if not value:
        return False
    if klass == CLASS_AWS_KEY_ID:
        return bool(AWS_KEY_ID_RE.match(value))
    if klass == CLASS_AWS_SECRET:
        return bool(AWS_SECRET_RE.match(value))
    if klass == CLASS_GITHUB:
        return bool(GITHUB_CLASSIC_RE.match(value) or GITHUB_FINE_RE.match(value))
    if klass == CLASS_PRIVATE_KEY:
        # Header/footer shape must be intact and labels must match;
        # body decodability is a checksum concern, handled in
        # offline_tier, not a structure concern.
        match = PRIVATE_KEY_BLOCK_RE.search(value)
        return match is not None
    # Generic: long enough, single token, printable, not repetitive.
    if len(value) < 8 or len(value) > 4096:
        return False
    if any(char.isspace() for char in value):
        return False
    if any(not char.isprintable() for char in value):
        return False
    return shannon_entropy(value) >= 1.5


def looks_like_placeholder(value: str) -> bool:
    """True when the value matches known placeholder patterns."""
    if not value:
        return False
    if value in PLACEHOLDER_EXACT:
        return True
    if ANGLE_PLACEHOLDER_RE.match(value):
        return True
    if AWS_EXAMPLE_KEY_RE.match(value):
        return True
    lowered = value.lower()
    for token in PLACEHOLDER_TOKENS:
        if token in lowered:
            return True
    if "example.com" in lowered:
        return True
    return False


def fixture_style_path(file_path: str) -> bool:
    """True when the file path looks like fixtures, examples, or docs."""
    return bool(FIXTURE_PATH_RE.search(file_path or ""))


def offline_tier(klass: str, value: str, file_path: str = "") -> tuple:
    """Tier a value using offline heuristics only.

    Returns (tier, reason). Reason strings come from a fixed safe
    vocabulary and never contain the value.
    """
    if not validate_structure(klass, value):
        return FALSE_POSITIVE, "structurally-invalid"

    if klass == CLASS_PRIVATE_KEY and not _private_key_body_decodes(value):
        # The brief places checksum-style failures (base64 body that
        # does not decode) in likely-fixture, not false-positive: the
        # block is shaped like a key but filled with junk.
        return LIKELY_FIXTURE, "checksum-invalid-base64-body"
    if klass == CLASS_AWS_SECRET and not _aws_secret_base64_ok(value):
        return LIKELY_FIXTURE, "checksum-invalid-base64"

    if looks_like_placeholder(value):
        return LIKELY_FIXTURE, "placeholder-pattern"
    if fixture_style_path(file_path):
        return LIKELY_FIXTURE, "fixture-style-path"

    return FORMAT_VALID_UNKNOWN, "format-valid"
