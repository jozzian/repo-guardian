"""Safe network liveness checks, one per credential class (JOZ-180).

Rules this module must never break:
  * identity confirmation only. The AWS check calls STS
    GetCallerIdentity, a read-only call that works with any valid
    credential regardless of its permissions, and nothing else. The
    GitHub check calls GET /user and nothing else.
  * no credential beyond what the check requires, no writes, no
    calls to any other endpoint.
  * the value is never logged, never embedded in an exception
    message, and never returned. Callers get a tier outcome and a
    safe reason string only.

Network use is opt-in at the CLI (--verify-network); this module is
never imported by offline paths. Stdlib only (urllib, hmac, hashlib).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .tiers import CONFIRMED_LIVE, FALSE_POSITIVE, FORMAT_VALID_UNKNOWN

DEFAULT_TIMEOUT_SECONDS = 10
STS_HOST = "sts.amazonaws.com"
GITHUB_API = "https://api.github.com"
USER_AGENT = "repo-guardian-verifier (identity-check-only)"


class LivenessError(Exception):
    """Network or transport failure. Carries no secret material."""


def _http_status(url: str, headers: dict, timeout: int) -> tuple:
    """Return (status, body_text) for one GET request.

    HTTPError responses still carry a status and a body, so those
    are returned rather than raised. Transport errors raise
    LivenessError with the URL and reason only.
    """
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(8192).decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            pass
        return exc.code, body
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # exc may embed only the URL, never a header or a body.
        raise LivenessError(f"transport failure calling {url}: {type(exc).__name__}") from None


# ---------------------------------------------------------------------------
# AWS STS GetCallerIdentity, signed with SigV4 by hand (stdlib only).
# ---------------------------------------------------------------------------

def _sigv4_headers(access_key: str, secret_key: str, body: str) -> dict:
    """Build SigV4 headers for a POST to STS GetCallerIdentity."""
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    region = "us-east-1"
    service = "sts"
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        f"host:{STS_HOST}\n"
        f"x-amz-date:{amz_date}\n"
    )
    canonical_request = "\n".join(
        [
            "POST",
            "/",
            "",
            canonical_headers,
            "content-type;host;x-amz-date",
            payload_hash,
        ]
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signing_key = sign(sign(sign(sign(
        ("AWS4" + secret_key).encode("utf-8"), date_stamp), region),
        service), "aws4_request")
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders=content-type;host;x-amz-date, Signature={signature}"
    )
    return {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "host": STS_HOST,
        "x-amz-date": amz_date,
        "authorization": authorization,
        "user-agent": USER_AGENT,
    }


def check_aws(access_key: str, secret_key: str, timeout: int) -> tuple:
    """STS GetCallerIdentity liveness check.

    Returns (outcome, reason) where outcome is one of:
        live          200: the key pair is confirmed working.
        dead          403 InvalidClientTokenId (or SignatureDoesNotMatch,
                      which for a correctly signed request means a
                      revoked or nonexistent key pair).
        inconclusive  any other status, or a transport failure: the
                      key stays at its offline tier.
    The reason is a fixed safe string, never request or response
    detail that could embed the credential.
    """
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    headers = _sigv4_headers(access_key, secret_key, body)
    request = urllib.request.Request(
        f"https://{STS_HOST}/", data=body.encode("utf-8"),
        headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                return "live", "sts-getcalleridentity-200"
            return "inconclusive", f"sts-status-{response.status}"
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            try:
                payload = json.loads(exc.read(8192).decode("utf-8", errors="replace"))
                code = payload.get("Error", {}).get("Code", "")
            except (OSError, ValueError, AttributeError):
                code = ""
            if code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                return "dead", f"sts-403-{code}"
            return "inconclusive", "sts-403-other"
        return "inconclusive", f"sts-status-{exc.code}"
    except (urllib.error.URLError, OSError, ValueError):
        return "inconclusive", "transport-failure"


def check_github(token: str, timeout: int) -> tuple:
    """GET https://api.github.com/user liveness check.

    Returns (outcome, reason): live on 200, dead on 401, and
    inconclusive otherwise. The token travels only in the
    Authorization header; it is never echoed into a reason.
    """
    headers = {
        "authorization": f"Bearer {token}",
        "accept": "application/vnd.github+json",
        "user-agent": USER_AGENT,
        "x-github-api-version": "2022-11-28",
    }
    try:
        status, _ = _http_status(f"{GITHUB_API}/user", headers, timeout)
    except LivenessError:
        return "inconclusive", "transport-failure"
    if status == 200:
        return "live", "github-user-200"
    if status == 401:
        return "dead", "github-user-401"
    return "inconclusive", f"github-status-{status}"


def apply_outcome(outcome: str, offline_tier_value: str) -> tuple:
    """Map a liveness outcome onto a confidence tier.

    live becomes confirmed-live, dead becomes false-positive, and
    inconclusive (or a class with no safe check) keeps the offline
    tier. Returns (tier, reason).
    """
    if outcome == "live":
        return CONFIRMED_LIVE, "network-confirmed-live"
    if outcome == "dead":
        return FALSE_POSITIVE, "network-confirmed-dead"
    return offline_tier_value, "network-inconclusive"
