"""Value-type classifier and attack-variant mutation generator.

Classifies a single parameter *value* into a semantic type (integer,
sequential_id, uuid, jwt, email, url, path, base64, hex, json, boolean,
date/timestamp, short_token, opaque) and then generates semantically-aware
attack variant sets keyed by INTENT.

This is a different concern from ``assess.lib.classify`` (which classifies
REQUEST shapes like graphql/api/page) — keep the two modules separate.

Ported from reference-project ``pkg/mutation/types.go`` ValueType taxonomy and
``pkg/mutation`` IntentNeighbor / IntentBoundary / IntentEscalation /
IntentFormat / IntentEmpty intent taxonomy.

Design: pure functions, pre-compiled regexes, deterministic output, no
network, no LLM, no new dependencies (stdlib only).
"""
from __future__ import annotations

import base64
import json
import re
import string

# ---------------------------------------------------------------------------
# Pre-compiled patterns — priority-ordered, matching classify.py style
# ---------------------------------------------------------------------------

# JWT: three base64url segments separated by dots
_RE_JWT = re.compile(
    r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
)

# UUID: 8-4-4-4-12 hex groups
_RE_UUID = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

# Email
_RE_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# URL: must have scheme://
_RE_URL = re.compile(r'^https?://', re.IGNORECASE)

# File path: starts with / or ./ or ../ or contains path separators
_RE_PATH = re.compile(r'^\.{0,2}/', )

# Pure integer (decimal, optional leading minus, no leading zeros beyond "0")
_RE_INTEGER = re.compile(r'^-?(?:0|[1-9]\d*)$')

# Sequential / auto-increment ID: small positive integer (≤ 10 digits)
_RE_SEQUENTIAL_ID = re.compile(r'^[1-9]\d{0,9}$')

# Boolean-ish — only string-form booleans, not numeric 0/1 (those are integers)
_BOOLEAN_VALUES = frozenset({
    "true", "false", "yes", "no", "on", "off",
    "True", "False", "TRUE", "FALSE",
})

# ISO-8601 date: YYYY-MM-DD
_RE_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$')

# Unix timestamp: 10-digit (seconds) or 13-digit (milliseconds) integer
_RE_TIMESTAMP = re.compile(r'^1[0-9]{9}(?:[0-9]{3})?$')

# Hex string: even number of hex digits, at least 8 chars
_RE_HEX = re.compile(r'^[0-9a-fA-F]{8,}$')

# Base64 standard or URL-safe alphabet, with optional padding
_RE_BASE64 = re.compile(r'^[A-Za-z0-9+/=]{16,}$')
_RE_BASE64_URL = re.compile(r'^[A-Za-z0-9_-]{16,}$')

# Short opaque token: alphanumeric + hyphens/underscores, 8–31 chars
_RE_SHORT_TOKEN = re.compile(r'^[A-Za-z0-9_-]{8,31}$')


def _looks_like_base64(value: str) -> bool:
    """Return True if value looks like base64 and actually decodes.

    Rejects pure-hex strings (which match the base64 alphabet but are better
    classified as 'hex') and short tokens (< 32 chars without padding) that
    happen to be URL-safe alphanumeric.
    """
    if not (_RE_BASE64.match(value) or _RE_BASE64_URL.match(value)):
        return False
    # Reject pure hex: all chars are in [0-9a-fA-F] and even length
    if _RE_HEX.match(value) and len(value) % 2 == 0:
        return False
    # Must have alphabetic chars (not purely numeric)
    if not any(c in string.ascii_letters for c in value):
        return False
    # Require minimum length to avoid short tokens masquerading as base64.
    # Genuine base64 payloads (tokens, keys, blobs) are typically >= 32 chars.
    if len(value) < 32 and "=" not in value and "+" not in value and "/" not in value:
        return False
    # Try decoding
    try:
        pad = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(pad, validate=False)
        return len(decoded) >= 8
    except Exception:
        return False


def classify_value(value: str) -> str:
    """Classify a single parameter value into a semantic type.

    Priority-ordered: most-specific types are checked first so that a JWT
    (which also matches base64url) is identified as 'jwt', not 'base64'.

    Returns one of: integer, sequential_id, uuid, jwt, email, url, path,
    base64, hex, json, boolean, date, timestamp, short_token, opaque.
    """
    if not isinstance(value, str):
        return "opaque"

    stripped = value.strip()

    # 1. JWT — checked before base64url because JWT segments are base64url
    if _RE_JWT.match(stripped):
        # Validate it looks JWT-ish: first segment decodes to JSON-like object
        try:
            parts = stripped.split(".")
            pad = parts[0] + "=" * (-len(parts[0]) % 4)
            header = base64.b64decode(pad.encode(), validate=False)
            obj = json.loads(header)
            if isinstance(obj, dict) and ("alg" in obj or "typ" in obj):
                return "jwt"
        except Exception:
            pass
        # Accept as JWT even without valid header if it has 3 well-formed segments
        return "jwt"

    # 2. UUID
    if _RE_UUID.match(stripped):
        return "uuid"

    # 3. Email
    if _RE_EMAIL.match(stripped):
        return "email"

    # 4. URL
    if _RE_URL.match(stripped):
        return "url"

    # 5. Path
    if _RE_PATH.match(stripped):
        return "path"

    # 6. Boolean
    if stripped in _BOOLEAN_VALUES:
        return "boolean"

    # 7. Date / timestamp — before integer so "1234567890" hits timestamp
    if _RE_DATE.match(stripped):
        return "date"
    if _RE_TIMESTAMP.match(stripped):
        return "timestamp"

    # 8. JSON (object or array)
    if stripped and stripped[0] in ("{", "["):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, (dict, list)):
                return "json"
        except (json.JSONDecodeError, ValueError):
            pass

    # 9. Sequential ID — small positive integer (must come before generic integer
    #    so "42" → sequential_id, "-5" → integer)
    if _RE_SEQUENTIAL_ID.match(stripped):
        return "sequential_id"

    # 10. Generic integer (includes negatives and zero)
    if _RE_INTEGER.match(stripped):
        return "integer"

    # 11. Base64 — checked before hex because base64 alphabet is a superset
    if _looks_like_base64(stripped):
        return "base64"

    # 12. Hex — pure lowercase/uppercase hex digits, even length ≥ 8
    if _RE_HEX.match(stripped) and len(stripped) % 2 == 0:
        return "hex"

    # 13. Short opaque token (alphanumeric + dashes/underscores, 8–31 chars)
    if _RE_SHORT_TOKEN.match(stripped) and len(stripped) < 32:
        return "short_token"

    return "opaque"


# ---------------------------------------------------------------------------
# Mutation generators — one per intent, ported from reference-project
# ---------------------------------------------------------------------------

def _mutate_neighbor(value: str, vtype: str, max_n: int) -> list[str]:
    """Neighboring values — adjacent IDs, swapped chars, near-zero variants."""
    variants: list[str] = []

    if vtype in ("sequential_id", "integer"):
        try:
            n = int(value)
        except ValueError:
            return []
        candidates = [str(n + 1), str(n - 1), str(n + 2), str(n - 2), str(n * 2)]
        for c in candidates:
            if c != value and c not in variants:
                variants.append(c)

    elif vtype == "uuid":
        # Increment last hex digit group
        parts = value.split("-")
        if len(parts) == 5:
            try:
                last = int(parts[4], 16)
                variants.append(
                    "{}-{}-{}-{}-{:012x}".format(parts[0], parts[1], parts[2], parts[3], last + 1)
                )
                variants.append(
                    "{}-{}-{}-{}-{:012x}".format(parts[0], parts[1], parts[2], parts[3], max(0, last - 1))
                )
            except ValueError:
                pass
        # Swap two chars in first segment
        if len(parts[0]) >= 4:
            s = list(parts[0])
            s[0], s[1] = s[1], s[0]
            swapped = "".join(s)
            adj = "{}-{}-{}-{}-{}".format(swapped, parts[1], parts[2], parts[3], parts[4])
            if adj not in variants:
                variants.append(adj)

    elif vtype in ("short_token", "opaque"):
        # Append a digit suffix
        variants.extend([value + "1", value + "2", value[:-1] + chr(min(0x10FFFF, ord(value[-1]) + 1)) if value else ""])

    elif vtype == "hex":
        try:
            n = int(value, 16)
            fmt = f"0{len(value)}x"
            variants.append(format(n + 1, fmt))
            variants.append(format(max(0, n - 1), fmt))
        except ValueError:
            pass

    return [v for v in variants if v and v != value][:max_n]


def _mutate_boundary(value: str, vtype: str, max_n: int) -> list[str]:
    """Boundary values — zero, -1, very large, empty, max-length strings."""
    variants: list[str] = []

    if vtype in ("sequential_id", "integer"):
        candidates = ["0", "-1", "1", "99999999", "2147483647", "-2147483648", "9999999999999"]
    elif vtype == "uuid":
        candidates = [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]
    elif vtype == "boolean":
        candidates = ["true", "false", "1", "0", ""]
    elif vtype in ("date", "timestamp"):
        candidates = [
            "1970-01-01",
            "2038-01-19",
            "9999-12-31",
            "0",
            "1",
            "-1",
        ]
    elif vtype == "string":
        candidates = ["", " ", "a" * 255, "a" * 65535]
    elif vtype in ("short_token", "opaque", "base64", "hex", "jwt"):
        candidates = ["", "a", "a" * 255]
    elif vtype == "url":
        candidates = ["http://localhost/", "http://127.0.0.1/", "file:///etc/passwd", "javascript:alert(1)"]
    elif vtype == "path":
        candidates = ["/", ".", "", "/etc/passwd", "/proc/self/environ"]
    else:
        candidates = ["", "0", "-1", "null"]

    for c in candidates:
        if c != value and c not in variants:
            variants.append(c)

    return variants[:max_n]


def _mutate_escalation(value: str, vtype: str, max_n: int) -> list[str]:
    """Escalation / privilege-hint values — admin IDs, role hints, path traversal."""
    variants: list[str] = []

    if vtype in ("sequential_id", "integer"):
        candidates = ["1", "0", "2", "admin", "root", "-1", "99999999"]
    elif vtype == "uuid":
        candidates = [
            "00000000-0000-0000-0000-000000000000",   # well-known all-zeros
            "00000000-0000-0000-0000-000000000001",   # likely admin/first user
            value.upper(),                             # case confusion
        ]
    elif vtype == "email":
        candidates = [
            "admin@example.com",
            "root@localhost",
            "administrator@example.com",
        ]
    elif vtype == "path":
        candidates = [
            "../../etc/passwd",
            "../../../etc/shadow",
            "/etc/passwd",
            "/admin",
            "/internal",
            value.replace("/", "%2F"),              # encoded traversal
            value + "/..",
        ]
    elif vtype == "url":
        candidates = [
            "http://169.254.169.254/latest/meta-data/",  # AWS SSRF
            "http://localhost/admin",
            "http://[::1]/",
        ]
    elif vtype in ("short_token", "opaque", "base64"):
        candidates = ["admin", "root", "ADMIN", "0", "1", "true"]
    elif vtype == "boolean":
        candidates = ["true", "1", "yes", "on", "True"]
    elif vtype == "jwt":
        # alg:none bypass
        import base64 as _b64
        header = _b64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload_part = _b64.b64encode(b'{"role":"admin","sub":"1"}').decode().rstrip("=")
        candidates = [f"{header}.{payload_part}.", value.rsplit(".", 1)[0] + ".AAAA"]
    else:
        candidates = ["admin", "1", "root", "0"]

    for c in candidates:
        if c != value and c not in variants:
            variants.append(c)

    return variants[:max_n]


def _mutate_format(value: str, vtype: str, max_n: int) -> list[str]:
    """Type-confusion / format variants — int→string/array/null, json→malformed."""
    variants: list[str] = []

    if vtype in ("sequential_id", "integer"):
        candidates = [
            f'"{value}"',           # int as string
            f'[{value}]',           # int as array
            f'{{"id": {value}}}',   # int as object
            "null",
            "[]",
            "{}",
            value + ".0",           # int as float
        ]
    elif vtype == "boolean":
        candidates = ['"true"', "1", '["true"]', "null"]
    elif vtype == "json":
        # Malformed JSON variants
        s = value
        candidates = [
            s[:-1] if s else "",        # truncated
            s + "}",                     # extra brace
            s.replace("{", ""),          # missing opening brace
            "null",
            "[]",
            '""',
        ]
    elif vtype == "uuid":
        # Hex without hyphens, uppercase, etc.
        candidates = [
            value.replace("-", ""),      # no hyphens
            value.upper(),
            value.lower(),
            '"' + value + '"',
        ]
    elif vtype in ("base64", "hex"):
        candidates = [
            '"' + value + '"',
            "null",
            value + "==",
            value[:-2] if len(value) > 4 else value,  # truncated
        ]
    elif vtype == "url":
        candidates = [
            '"' + value + '"',
            value.replace("https://", "http://"),
            value.replace("://", ":"),
        ]
    elif vtype == "path":
        candidates = [
            '"' + value + '"',
            value.replace("/", "\\"),     # Windows-style
            value.replace("/", "%2F"),    # URL-encoded
        ]
    elif vtype in ("short_token", "opaque", "jwt"):
        candidates = ["null", '""', "0", "[]", '{}']
    else:
        candidates = ["null", '""', "0", "[]", "{}"]

    for c in candidates:
        if c != value and c not in variants:
            variants.append(c)

    return variants[:max_n]


def _mutate_empty(value: str, vtype: str, max_n: int) -> list[str]:  # noqa: ARG001
    """Empty / null / absent variants."""
    candidates = ["", "null", "undefined", " ", "\x00", "nil", "none", "None", "NULL"]
    variants = [c for c in candidates if c != value]
    return variants[:max_n]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_INTENT_GENERATORS = {
    "neighbor": _mutate_neighbor,
    "boundary": _mutate_boundary,
    "escalation": _mutate_escalation,
    "format": _mutate_format,
    "empty": _mutate_empty,
}

_ALL_INTENTS = ("neighbor", "boundary", "escalation", "format", "empty")


def mutate(value: str, *, max_per_intent: int = 5) -> dict:
    """Classify *value* and return semantically-aware attack variant sets.

    Returns::

        {
            "value": <original>,
            "type": <classified type>,
            "intents": {
                "neighbor":   [<variant>, ...],   # ≤ max_per_intent
                "boundary":   [...],
                "escalation": [...],
                "format":     [...],
                "empty":      [...],
            }
        }

    All output is deterministic. No network calls, no LLM.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    vtype = classify_value(value)
    intents: dict[str, list[str]] = {}
    for intent in _ALL_INTENTS:
        gen = _INTENT_GENERATORS[intent]
        raw = gen(value, vtype, max_per_intent)
        # Deduplicate while preserving order, and enforce cap
        seen: set[str] = set()
        deduped: list[str] = []
        for v in raw:
            if v not in seen:
                seen.add(v)
                deduped.append(v)
            if len(deduped) >= max_per_intent:
                break
        intents[intent] = deduped
    return {"value": value, "type": vtype, "intents": intents}
