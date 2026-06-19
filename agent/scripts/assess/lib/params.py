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
