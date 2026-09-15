"""Repo Guardian verifier package.

Agent verification layer (JOZ-180): consumes a scanner JSON report,
re-extracts each candidate secret value transiently (never emitted),
tiers every finding by confidence, and gates notifications so only
confirmed-live and format-valid-unknown findings pass.

Liveness checks are opt-in (--verify-network); the default mode is
offline heuristic tiering only.
"""

from .report import verify_report, gate
from .tiers import (
    CONFIRMED_LIVE,
    FALSE_POSITIVE,
    FORMAT_VALID_UNKNOWN,
    GATE_TIERS,
    LIKELY_FIXTURE,
    TIERS,
)

__all__ = [
    "verify_report",
    "gate",
    "TIERS",
    "GATE_TIERS",
    "CONFIRMED_LIVE",
    "FORMAT_VALID_UNKNOWN",
    "LIKELY_FIXTURE",
    "FALSE_POSITIVE",
]
