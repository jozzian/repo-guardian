"""Transient re-extraction of candidate secret values from a repo.

The scanner report never contains the secret value (redaction is
sacred), but the verifier needs the raw value in memory to run
structural checks and, in network mode, liveness checks. This module
re-reads the file at a reported location and recovers the value by
hash matching: a candidate is accepted only when its sha256 prefix
equals the finding's secret_sha256_prefix, which proves the recovered
string is exactly what the scanner saw.

Values live only as local variables in the calling process. Nothing
here writes a value to disk, to stdout, to stderr, or into any
exception message.

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess

from .tiers import AWS_SECRET_RE, PRIVATE_KEY_BLOCK_RE

# Maximum bytes read from any one file or git object before giving up.
MAX_CONTENT_BYTES = 4 * 1024 * 1024
# Lines inspected around the reported line number (files drift).
LINE_WINDOW = 3
GIT_TIMEOUT_SECONDS = 30

_TOKEN_SPLIT_RE = re.compile(r"[\s=:,\"'`\[\](){}<>|;]+")


def sha256_prefix(value: str, length: int = 16) -> str:
    """Same digest the scanner uses for secret_sha256_prefix."""
    return hashlib.sha256(
        value.encode("utf-8", errors="replace")
    ).hexdigest()[:length]


def load_location_text(repo: str, file_path: str, location: dict) -> str | None:
    """Return the file content behind one location, or None.

    Working-tree locations read from disk. History locations read the
    blob from the reported commit via git show. Failures are silent:
    a missing blob simply means the value is not recoverable.
    """
    if location.get("source") == "working-tree":
        candidate = os.path.join(repo, file_path)
        try:
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                    return handle.read(MAX_CONTENT_BYTES)
        except OSError:
            return None
        # The file may be gone from the tree; fall through to history
        # if this location also carries a commit.
    commit = location.get("commit")
    if not commit:
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "show", f"{commit}:{file_path}"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout[:MAX_CONTENT_BYTES]


def _line_candidates(text: str, line: int | None) -> list:
    """Candidate single-line values near the reported line number."""
    lines = text.splitlines()
    if line is None:
        window = lines
    else:
        start = max(0, line - 1 - LINE_WINDOW)
        end = min(len(lines), line + LINE_WINDOW)
        window = lines[start:end]
    candidates = []
    for raw_line in window:
        stripped = raw_line.strip()
        if not stripped:
            continue
        candidates.append(stripped)
        for token in _TOKEN_SPLIT_RE.split(stripped):
            if token:
                candidates.append(token.strip("\"',;"))
        for separator in ("=", ":"):
            if separator in stripped:
                tail = stripped.split(separator, 1)[1].strip().strip("\"'")
                if tail:
                    candidates.append(tail)
    return candidates


def _block_candidates(text: str) -> list:
    """Candidate PEM-style blocks anywhere in the content."""
    candidates = []
    for match in PRIVATE_KEY_BLOCK_RE.finditer(text):
        block = match.group(0)
        candidates.append(block)
        candidates.append(block + "\n")
    return candidates


def recover_value(
    repo: str, finding: dict, expected_prefix: str
) -> tuple:
    """Re-extract the secret value behind one finding.

    Returns (value, how) where value is the recovered string or None,
    and how is a safe label describing the recovery source
    ("working-tree", "history", or "unrecovered"). The value is for
    transient in-process use only and must never be emitted.
    """
    file_path = finding.get("file", "")
    locations = finding.get("locations", [])
    # Prefer the working tree (freshest copy), then history sightings.
    ordered = sorted(locations, key=lambda loc: loc.get("source") != "working-tree")
    for location in ordered:
        text = load_location_text(repo, file_path, location)
        if text is None:
            continue
        how = location.get("source") or "history"
        candidates = _block_candidates(text)
        candidates.extend(_line_candidates(text, location.get("line")))
        seen = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            if sha256_prefix(candidate) == expected_prefix:
                return candidate, how
    return None, "unrecovered"


def find_aws_secret_near(text: str, access_key_id: str) -> str | None:
    """Locate a plausible AWS secret access key in the same content.

    Used only in network mode to pair an access key id with its
    secret so the STS identity check can be signed. The pairing is
    positional: the secret must appear on the same line as the key id
    or within a few lines of it. Returns None when no candidate
    shape matches. The returned value is transient, like every value
    in this module.
    """
    lines = text.splitlines()
    anchor = None
    for index, line in enumerate(lines):
        if access_key_id in line:
            anchor = index
            match = AWS_SECRET_RE.search(
                line.split(access_key_id, 1)[1] if access_key_id in line else ""
            )
            if match:
                return match.group(0)
            break
    if anchor is None:
        return None
    start = max(0, anchor - LINE_WINDOW)
    end = min(len(lines), anchor + LINE_WINDOW + 1)
    for line in lines[start:end]:
        match = AWS_SECRET_RE.search(line)
        if match:
            return match.group(0)
    return None
