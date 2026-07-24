"""Credential redaction for artifacts intended to leave the engagement.

Audit and evidence artifacts retain exact request material. Submission and reply
renders are a different trust boundary: they are designed to be sent to a
vendor, so live bearer material must never cross it.
"""
from __future__ import annotations

import re
from typing import Any

_COOKIE_HEADER_RE = re.compile(
    r"(?i)(\bCookie\s*:\s*)([^\r\n'\"]+)"
)
_JSON_COOKIE_VALUE_RE = re.compile(
    r"""(?i)(["']Cookie["']\s*:\s*["'])(.*?)(["'])"""
)
_CURL_COOKIE_VALUE_RE = re.compile(
    r"""(?i)((?<![\w-])(?:--cookie|-b)(?:\s+|=))(?:"[^"]*"|'[^']*'|[^\s]+)"""
)
_BEARER_RE = re.compile(
    r"(?i)(\bBearer\s+)(?!<REDACTED_CREDENTIAL>)([A-Za-z0-9._~+/=-]{12,})"
)
_COOKIE_KEYS = frozenset(
    {
        "cookie",
        "set-cookie",
        "acme_session",
        "church_center_session",
    }
)
_CREDENTIAL_KEYS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "apikey",
        "api_key",
        "registration_access_token",
    }
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:acme_session|church_center_session|"
    r"registration_access_token|api[_-]?key)\s*[=:]\s*)"
    r"(?!<REDACTED_CREDENTIAL>)([^;\s'\"&,]{8,})"
)


def _redact_text(value: str) -> str:
    redacted = _COOKIE_HEADER_RE.sub(r"\1<YOUR_SESSION_COOKIE>", value)
    redacted = _JSON_COOKIE_VALUE_RE.sub(
        r"\1<YOUR_SESSION_COOKIE>\3",
        redacted,
    )
    redacted = _CURL_COOKIE_VALUE_RE.sub(
        r"\1<YOUR_SESSION_COOKIE>",
        redacted,
    )
    redacted = _BEARER_RE.sub(r"\1<REDACTED_CREDENTIAL>", redacted)
    return _CREDENTIAL_ASSIGNMENT_RE.sub(
        r"\1<REDACTED_CREDENTIAL>",
        redacted,
    )


def redact_outbound_credentials(value: Any) -> Any:
    """Recursively redact credential material while preserving payload shape."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in _COOKIE_KEYS:
                redacted[key] = "<YOUR_SESSION_COOKIE>"
            elif normalized_key in _CREDENTIAL_KEYS:
                redacted[key] = "<REDACTED_CREDENTIAL>"
            else:
                redacted[key] = redact_outbound_credentials(item)
        return redacted
    if isinstance(value, list):
        return [redact_outbound_credentials(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_outbound_credentials(item) for item in value)
    return value
