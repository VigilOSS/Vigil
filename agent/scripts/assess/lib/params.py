"""URL/query/path parameter extraction — replaces lib/params.sh.

Uses urllib.parse + hashlib.md5 instead of jq/awk/md5 subprocesses.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qs, urlparse

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUMERIC_RE = re.compile(r"^[0-9]+$")
_HEX_LONG_RE = re.compile(r"^[0-9a-fA-F]{24,}$")


def extract_url_path(url: str) -> str:
    """Extract the path portion of a URL, stripping scheme, host, query, fragment."""
    parsed = urlparse(url)
    path = parsed.path
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def extract_query_params(url: str) -> dict[str, str]:
    """Parse URL query string into a flat {key: value} dict."""
    parsed = urlparse(url)
    if not parsed.query:
        return {}
    qs = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten: take last value for each key (matches bash behavior)
    return {k: v[-1] for k, v in qs.items()}


def extract_path_params(url_path: str) -> dict[str, str]:
    """Identify dynamic URL segments using heuristics. Returns {seg_N: value}."""
    stripped = url_path.lstrip("/")
    if not stripped:
        return {}
    result: dict[str, str] = {}
    for idx, seg in enumerate(stripped.split("/"), start=1):
        if _NUMERIC_RE.match(seg):
            result[f"seg_{idx}"] = seg
        elif _UUID_RE.match(seg):
            result[f"seg_{idx}"] = seg
        elif _HEX_LONG_RE.match(seg):
            result[f"seg_{idx}"] = seg
    return result


# Request headers dropped from the captured ``header_schema``. header_schema is
# PART of the request-variant dedup hash (a header-name change forks a variant)
# and drives the depth ledger's CORS/proxy *presence* triggers — so it must carry
# only STABLE, attack-relevant header NAMES, not the per-request transport and
# browser-fingerprint noise that would fork variants without adding any coverage
# signal. Two groups are dropped:
#   - hop-by-hop / transport-framing headers (RFC 7230 §6.1 + framing) — never
#     application inputs;
#   - volatile or already-captured-elsewhere headers (cookie/content-type live in
#     their own schema slots; authorization is captured as auth_context; caching/
#     conditional/range/date and browser fingerprint headers are per-request
#     volatile) whose presence would churn the dedup hash with no benefit.
# Everything NOT in this set survives (when in doubt, capture the name) so
# app-specific and attacker-relevant headers (X-Forwarded-*, X-Requested-With,
# X-Api-Key, X-Csrf-Token, custom X-*) land in the schema.
_HEADER_SCHEMA_DROP: frozenset[str] = frozenset({
    # hop-by-hop / transport framing
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
    # captured in their own schema slot or as the target identity
    "host", "cookie", "content-type", "content-length",
    # identity/token material (captured as auth_context; token-varying)
    "authorization",
    # per-request volatile: caching / conditional / range / date
    "date", "cache-control", "pragma", "range", "if-match", "if-none-match",
    "if-modified-since", "if-unmodified-since", "if-range", "expires",
    # browser transport / fingerprint noise (no per-app coverage signal)
    "accept", "accept-encoding", "accept-language", "accept-charset",
    "user-agent", "referer", "origin", "dnt", "upgrade-insecure-requests",
    "priority", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-platform-version", "sec-gpc", "via",
})


def _header_names(value: object) -> list[str]:
    """Best-effort extraction of header NAMES from the shapes capture paths hold.

    Accepts a dict[name, value] (mitmproxy ``dict(req.headers)`` / HAR-style map),
    a list of header names, or a pre-serialized JSON string of either. Returns
    ``[]`` for anything unparseable (raw non-JSON text, scalars, None) so callers
    get a clean no-op rather than a bogus schema.
    """
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            value = json.loads(text)
        except (ValueError, TypeError):
            return []
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def header_schema_from_headers(value: object) -> dict[str, str]:
    """Reduce captured request headers to a stable ``{name: ""}`` header_schema.

    VALUES are intentionally discarded — only header NAMES matter for the
    request-variant dedup hash and the depth ledger's CORS/proxy presence
    triggers, and header values are per-request volatile (tokens, dates) that
    would fork variants without adding coverage signal. Hop-by-hop / transport
    framing and browser/caching noise are dropped (see ``_HEADER_SCHEMA_DROP``)
    and HTTP/2 pseudo-headers (``:method`` …) are skipped, so only stable,
    attack-relevant and app-specific header names survive. Casing of the first
    occurrence of each surviving name is preserved (consumers lowercase on read).
    Returns ``{}`` for empty/unparseable input (a clean no-op — the observation
    still ingests with no header data).
    """
    schema: dict[str, str] = {}
    for name in _header_names(value):
        clean = str(name).strip()
        if not clean or clean.startswith(":"):
            continue
        if clean.lower() in _HEADER_SCHEMA_DROP:
            continue
        schema.setdefault(clean, "")
    return schema


def generate_params_sig(query_params: dict | str, body_params: dict | str) -> str:
    """Generate a dedup signature: md5 hash of sorted parameter key names."""
    if isinstance(query_params, str):
        try:
            query_params = json.loads(query_params)
        except (json.JSONDecodeError, TypeError):
            query_params = {}
    if isinstance(body_params, str):
        try:
            body_params = json.loads(body_params)
        except (json.JSONDecodeError, TypeError):
            body_params = {}

    keys = sorted(set(list(query_params.keys()) + list(body_params.keys())))
    joined = ",".join(keys)
    return hashlib.md5(joined.encode()).hexdigest()
