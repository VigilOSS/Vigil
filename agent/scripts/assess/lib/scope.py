"""Scope parsing — replaces lib/scope.sh for Python callers."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def normalize_scope_payload(scope: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    changed = False
    raw_targets = scope.get("approved_targets")
    if not isinstance(raw_targets, list):
        raw_targets = scope.get("approved_findings")
    if not isinstance(raw_targets, list):
        raw_targets = []
    normalized = [str(item) for item in raw_targets]
    if scope.get("approved_targets") != normalized:
        scope["approved_targets"] = normalized
        changed = True
    if "approved_findings" in scope:
        del scope["approved_findings"]
        changed = True
    return scope, changed


def _write_scope_file(scope_path: Path, scope: dict[str, Any]) -> None:
    tmp_path = scope_path.with_name("scope.tmp.json")
    tmp_path.write_text(
        json.dumps(scope, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp_path.rename(scope_path)


def load_scope(engagement_dir: str) -> dict[str, Any]:
    """Load and return scope.json from the engagement directory."""
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        raise SystemExit(f"scope.json not found in {engagement_dir}")
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    if not isinstance(scope, dict):
        raise SystemExit(f"scope.json is not a JSON object in {engagement_dir}")
    scope, changed = normalize_scope_payload(scope)
    if changed:
        _write_scope_file(scope_path, scope)
    return scope


def save_scope(engagement_dir: str, scope: dict[str, Any]) -> None:
    """Atomically write scope.json."""
    scope_path = Path(engagement_dir) / "scope.json"
    normalized, _ = normalize_scope_payload(dict(scope))
    normalized.pop("approved_findings", None)
    _write_scope_file(scope_path, normalized)


def scope_entries(scope: dict[str, Any]) -> list[dict[str, str]]:
    """Return normalized host entries from ``scope.json``.

    Entries use the same coarse semantics as ``check-scope-coverage``: URL
    entries collapse to their host, bare hosts match exactly, and wildcards
    match the apex plus subdomains.
    """
    raw_hosts = scope.get("hosts") or []
    if not isinstance(raw_hosts, list):
        raise SystemExit("scope.json `hosts` must be a list")
    entries: list[dict[str, str]] = []
    for item in raw_hosts:
        if not isinstance(item, str):
            continue
        entry = classify_scope_entry(item)
        if entry is not None:
            entries.append(entry)
    return entries


def classify_scope_entry(raw: str) -> dict[str, str] | None:
    stripped = raw.strip()
    if not stripped:
        return None

    if stripped.startswith("*.") and len(stripped) > 2:
        host = stripped[2:].strip().rstrip(".").lower()
        if not host:
            return None
        return {
            "scope_entry": stripped,
            "entry_kind": "wildcard",
            "host": host,
        }

    if "://" in stripped:
        try:
            host = (urlsplit(stripped).hostname or "").rstrip(".").lower()
        except ValueError:
            return None
        if not host:
            return None
        return {
            "scope_entry": stripped,
            "entry_kind": "url",
            "host": host,
        }

    host = host_from_token(stripped)
    if not host:
        return None
    return {
        "scope_entry": stripped,
        "entry_kind": "bare_host",
        "host": host,
    }


def host_from_token(raw: str) -> str:
    """Extract a lowercased host from a URL, host:port, or line token."""
    token = raw.strip()
    if not token or token.startswith("-"):
        return ""
    first = token.split()[0].strip("'\"<>()").rstrip(",;")
    if not first:
        return ""
    if "://" in first:
        try:
            host = urlsplit(first).hostname or ""
        except ValueError:
            return ""
    elif first.startswith("["):
        host = _host_from_bracketed_authority(first)
    elif "/" in first and ("." in first or ":" in first):
        try:
            host = urlsplit("http://" + first).hostname or ""
        except ValueError:
            return ""
    else:
        host = _host_from_authority(first)
    return _validated_host(host)


def _host_from_authority(raw: str) -> str:
    authority = raw.strip().strip("'\"<>()").rstrip(",;").rstrip(".").lower()
    if not authority:
        return ""
    if authority.startswith("["):
        return _host_from_bracketed_authority(authority)
    if _ip_literal(authority):
        return authority
    if authority.count(":") >= 2:
        host, _, port = authority.rpartition(":")
        if port.isdigit() and _ip_literal(host):
            return host
        return authority
    return authority.split(":", 1)[0]


def _host_from_bracketed_authority(raw: str) -> str:
    closing = raw.find("]")
    if closing <= 1:
        return ""
    return raw[1:closing]


def _validated_host(raw: str) -> str:
    host = raw.strip().strip("[]").rstrip(".").lower()
    if not host:
        return ""
    ip_literal = _ip_literal(host)
    if ip_literal:
        return ip_literal
    return host if looks_like_host(host) else ""


def _ip_literal(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def looks_like_host(host: str) -> bool:
    if not host:
        return False
    if _ip_literal(host):
        return True
    if host == "localhost":
        return True
    if "." in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def entry_matches_host(entry: dict[str, str], host: str) -> bool:
    if not host:
        return False
    normalized = host.rstrip(".").lower()
    entry_host = entry["host"]
    if entry["entry_kind"] == "wildcard":
        return normalized == entry_host or normalized.endswith("." + entry_host)
    return normalized == entry_host


def host_in_scope(host: str, entries: list[dict[str, str]]) -> bool:
    return any(entry_matches_host(entry, host) for entry in entries)
