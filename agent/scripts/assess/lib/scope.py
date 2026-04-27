"""Scope parsing — replaces lib/scope.sh for Python callers."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# Vendor-SaaS heuristics
# ---------------------------------------------------------------------------
#
# Hosts whose underlying application is vendor-managed SaaS (Salesforce,
# ServiceNow, hosted status pages, hosted helpdesks, identity providers, etc.)
# need a scope-decision checkpoint before recon-specialist dispatches against
# them — testing the underlying vendor platform rather than the customer's
# integration is usually out of scope for a VDP and produces noise instead of
# signal. The matcher is best-effort: it pattern-matches CNAME / rDNS suffix
# indicators and a small list of HTTP banner regexes against fingerprint
# strings the operator already collected during recon. The operator confirms
# every match via the Vendor-SaaS scope checkpoint before any recon dispatch
# fires.
#
# Suffix matches use the "endswith on a hostname segment boundary" rule so
# ``foo.salesforce.com.evil.test`` does not match Salesforce. Prefix the
# pattern with a leading dot in the table; the matcher checks both
# ``host == suffix.lstrip(".")`` and ``host.endswith(suffix)``.
_VENDOR_SAAS_SUFFIXES: list[tuple[str, str]] = [
    # (vendor label, hostname suffix)
    ("salesforce", ".salesforce.com"),
    ("salesforce", ".lightning.force.com"),
    ("salesforce", ".my.salesforce.com"),
    ("salesforce", ".force.com"),
    ("servicenow", ".service-now.com"),
    ("servicenow", ".servicenowservices.com"),
    ("statuspage", ".statuspage.io"),
    ("statuspage", ".statuspage.amazon.com"),
    ("govdelivery", ".govdelivery.com"),
    ("awsconnect", ".awsconnect.com"),
    ("awsconnect", ".amazonconnect.com"),
    ("auth0", ".auth0.com"),
    ("okta", ".okta.com"),
    ("okta", ".oktapreview.com"),
    ("zendesk", ".zendesk.com"),
    ("freshdesk", ".freshdesk.com"),
    ("intercom", ".intercom.io"),
]

# Banner / page-title / canonical-URL regex hints. Each entry is a
# ``(label, compiled-pattern)`` tuple. The lookup is best-effort and matches
# substrings on case-insensitive input — the operator confirms the result via
# the user-facing checkpoint before any recon dispatch.
_VENDOR_SAAS_BANNER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("salesforce", re.compile(r"salesforce", re.IGNORECASE)),
    ("salesforce", re.compile(r"lightning\.force\.com", re.IGNORECASE)),
    ("servicenow", re.compile(r"service-?now", re.IGNORECASE)),
    ("statuspage", re.compile(r"statuspage(\.io)?", re.IGNORECASE)),
    ("govdelivery", re.compile(r"govdelivery", re.IGNORECASE)),
    ("awsconnect", re.compile(r"amazon ?connect|awsconnect", re.IGNORECASE)),
    ("auth0", re.compile(r"auth0", re.IGNORECASE)),
    ("okta", re.compile(r"\bokta\b", re.IGNORECASE)),
    ("zendesk", re.compile(r"zendesk", re.IGNORECASE)),
    ("freshdesk", re.compile(r"freshdesk", re.IGNORECASE)),
    ("intercom", re.compile(r"intercom\.io", re.IGNORECASE)),
]


def host_is_vendor_saas(host: str | None) -> str | None:
    """Return the vendor label for a known SaaS-platform-fronted host or None.

    Pattern matching is suffix-based on the hostname (CNAME / rDNS shape) and
    is purely lexical — no DNS resolution, HTTP probing, or backend lookup
    happens at call time, so the function is safe to invoke inside scope
    filters and admission gates. The operator already has rDNS / banner data
    in intel before this gate fires; this helper is the deterministic part of
    the operator's vendor-SaaS scope checkpoint.

    Returns the vendor label (e.g. ``"salesforce"``, ``"servicenow"``,
    ``"statuspage"``, ``"govdelivery"``, ``"awsconnect"``) on the first
    matching suffix, or ``None`` when nothing matches. Lookup is O(N) over a
    small fixed list; the cost is negligible.
    """
    if not host:
        return None
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        return None
    for label, suffix in _VENDOR_SAAS_SUFFIXES:
        bare = suffix.lstrip(".")
        if normalized == bare or normalized.endswith(suffix):
            return label
    return None


def banner_matches_vendor_saas(banner: str | None) -> str | None:
    """Return the vendor label for a banner / page-title hint or None.

    Best-effort secondary signal for hosts whose CNAME / rDNS shape does not
    expose the vendor (e.g. CNAME flattened to the customer apex). The
    operator-side flow combines this with ``host_is_vendor_saas`` and only
    treats a match as authoritative after the user-facing checkpoint
    records the scope decision.
    """
    if not banner:
        return None
    for label, pattern in _VENDOR_SAAS_BANNER_PATTERNS:
        if pattern.search(banner):
            return label
    return None


# AITH_STRICT_APEX_WILDCARD gates whether wildcard-only entries match the bare
# apex. Default ON: ``*.example.test`` matches ``sub.example.test`` and deeper,
# but NOT the bare ``example.test`` apex — the apex must be listed explicitly
# (``example.test`` or ``https://example.test/*``) for the operator to assert
# VDP authorization on it. Set ``AITH_STRICT_APEX_WILDCARD=0`` (or ``false`` /
# ``no`` / ``off``) to opt back into the legacy apex-permissive behavior for
# one cycle while migrating an existing engagement.
#
# Deprecation horizon: the opt-out flag is removed in the next minor release;
# the strict semantics become the only behavior. Migrate existing scopes by
# adding an explicit apex entry alongside any wildcard-only entry whose apex
# you intend to authorize.
_STRICT_APEX_WILDCARD_ENV = "AITH_STRICT_APEX_WILDCARD"


def strict_apex_wildcard_enabled() -> bool:
    """Return True when wildcard-only entries must NOT match the bare apex."""
    raw = os.environ.get(_STRICT_APEX_WILDCARD_ENV, "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    return True


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
    match subdomains only. Bare apex inclusion requires an explicit scope
    entry (``example.test`` or ``https://example.test/*`` listed alongside
    the wildcard) — the apex is NOT covered by ``*.example.test`` on its own.
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
    """Return True when ``host`` is covered by this scope entry.

    Wildcard semantics under strict mode (the default): ``*.example.test``
    matches ``sub.example.test`` and deeper subdomains, but NOT the bare
    ``example.test`` apex. Bare apex inclusion requires an explicit scope
    entry (``example.test`` or ``https://example.test/*``) listed alongside
    the wildcard. Set ``AITH_STRICT_APEX_WILDCARD=0`` to fall back to the
    legacy apex-permissive behavior for a migration cycle; this opt-out is
    scheduled for removal in the next minor release.

    The legacy variants of this helper supported one or two argument orders
    in the codebase. We accept both ``entry_matches_host(entry, host)`` and
    ``entry_matches_host(host, entry_or_scope)`` so callers don't have to be
    rewritten — the dict form is detected and handled.
    """
    if not host:
        return False
    normalized = host.rstrip(".").lower()
    entry_host = entry["host"]
    if entry["entry_kind"] == "wildcard":
        if normalized.endswith("." + entry_host):
            return True
        if normalized == entry_host:
            return not strict_apex_wildcard_enabled()
        return False
    return normalized == entry_host


def host_in_scope(host: str, entries: list[dict[str, str]]) -> bool:
    return any(entry_matches_host(entry, host) for entry in entries)


def wildcard_only_entries_lacking_apex(scope: dict[str, Any]) -> list[str]:
    """Return wildcard host strings whose apex has no explicit scope entry.

    Given a scope object, this walks the ``hosts`` list and returns each
    raw wildcard string (e.g. ``*.example.test``) for which the apex
    (``example.test``) has no companion explicit entry — neither a bare
    host nor a URL-form entry. Callers use this to surface the warning
    described in the strict apex-wildcard semantics: such entries used to
    silently match the apex and now do not.

    Returned strings are the raw scope entries as written in scope.json so
    the operator can find and edit them directly. The order matches the
    order they appear in ``scope["hosts"]``; duplicates are not collapsed
    so the operator sees every authoring location.
    """
    raw_hosts = scope.get("hosts") if isinstance(scope, dict) else None
    if not isinstance(raw_hosts, list):
        return []

    explicit_apex_hosts: set[str] = set()
    wildcard_seen: list[tuple[str, str]] = []
    for item in raw_hosts:
        if not isinstance(item, str):
            continue
        entry = classify_scope_entry(item)
        if entry is None:
            continue
        if entry["entry_kind"] == "wildcard":
            wildcard_seen.append((item, entry["host"]))
        else:
            explicit_apex_hosts.add(entry["host"])

    return [raw for raw, host in wildcard_seen if host not in explicit_apex_hosts]


def host_matches_wildcard_only_apex(host: str, scope: dict[str, Any]) -> bool:
    """Return True when ``host`` would have matched a wildcard-only scope entry.

    Used by callers that need to detect "would-have-matched-under-old-semantics"
    cases for warning emission. Returns True if ``host`` equals the apex of
    any wildcard scope entry that has no explicit apex companion. Strict mode
    excludes such hosts from in-scope matching, so this helper exposes the
    informational gap without changing matching semantics.
    """
    if not host:
        return False
    normalized = host.rstrip(".").lower()
    for raw in wildcard_only_entries_lacking_apex(scope):
        entry = classify_scope_entry(raw)
        if entry is None:
            continue
        if normalized == entry["host"]:
            return True
    return False
