"""Scope parsing — replaces lib/scope.sh for Python callers."""
from __future__ import annotations

import ipaddress
import json
import re
import sys
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
# signal. The matcher is purely lexical on hostname shape; the operator
# confirms every match via the Vendor-SaaS scope checkpoint before any recon
# dispatch fires.
#
# Suffix matches require a strict subdomain boundary. Vendor SaaS shows up
# as ``<tenant>.salesforce.com``, never as the bare ``salesforce.com`` apex
# (which is the vendor's own corporate site, not a customer asset). Prefix
# every entry with a leading dot in the table; the matcher uses
# ``host.endswith(suffix)`` only.
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


def host_is_vendor_saas(host: str | None) -> str | None:
    """Return the vendor label for a known SaaS-platform-fronted host or None.

    Pattern matching is strict-subdomain on the hostname (CNAME / rDNS shape)
    and is purely lexical — no DNS resolution, HTTP probing, or backend
    lookup happens at call time, so the function is safe to invoke inside
    scope filters and admission gates. A bare ``salesforce.com`` apex is
    never a customer asset; only ``<tenant>.salesforce.com`` and similar
    subdomains return a vendor label.

    Returns the vendor label on the first matching suffix (e.g.
    ``"salesforce"``, ``"servicenow"``, ``"statuspage"``, ``"govdelivery"``,
    ``"awsconnect"``, ``"auth0"``, ``"okta"``, ``"zendesk"``,
    ``"freshdesk"``, ``"intercom"``), or ``None`` when nothing matches.
    Lookup is O(N) over a small fixed list.
    """
    if not host:
        return None
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        return None
    for label, suffix in _VENDOR_SAAS_SUFFIXES:
        if normalized.endswith(suffix):
            return label
    return None



_DNS_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

_warned_scope_keys: set[str] = set()


def _is_dns_label(token: str) -> bool:
    """True when ``token`` is a syntactically valid single DNS label.

    Single-label hosts (``intranet``, ``api``) are legitimate scope entries on
    internal engagements but fail ``looks_like_host`` (which requires a dot).
    They are admitted only on the explicitly-authored scope path, never from
    free-text token parsing, so log noise can't silently widen scope.
    """
    if not token:
        return False
    return bool(_DNS_LABEL_RE.match(token))


def _parse_cidr(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the IP network for a CIDR token (``10.0.0.0/24``) or None.

    A bare CIDR has no scheme and no ``*.`` prefix, so it would otherwise fall
    through to host parsing where ``urlsplit`` drops the ``/24`` and silently
    collapses a whole subnet to a single host (lost coverage = missed bugs).
    Parsing it as a network instead lets ``entry_matches_host`` admit every
    address in range.
    """
    if "/" not in token:
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _warn_scope(key: str, message: str) -> None:
    """Emit a scope warning to stderr once per process per unique key."""
    if key in _warned_scope_keys:
        return
    _warned_scope_keys.add(key)
    print(message, file=sys.stderr)


def _to_a_label(host: str) -> str:
    """Return the A-label (punycode) form of a hostname, lowercased.

    IDN scope entries can be authored as U-labels (``café.test``) while
    incoming hostnames arrive A-label-encoded (``xn--caf-dma.test``) or
    vice versa. Comparing the raw strings would miss the match. Falling
    back to the input on encode failure preserves IP literals and other
    non-IDNA strings.
    """
    if not host:
        return ""
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return cleaned


def _normalize_host_for_match(host: str) -> str:
    """Return a normalized host suitable for scope matching (lowercase, no trailing dot, A-label)."""
    if not host:
        return ""
    return _to_a_label(host)


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

    Entries use the same coarse semantics as ``check-phase-readiness``: URL
    entries collapse to their host, bare hosts match exactly, and wildcards
    match the bare apex AND every subdomain (HackerOne / Bugcrowd / VDP
    convention).
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


def out_of_scope_entries(scope: dict[str, Any]) -> list[dict[str, str]]:
    """Return normalized out-of-scope (denylist) entries from ``scope.json``.

    Mirrors ``scope_entries`` but reads ``scope.get("out_of_scope")``. A missing
    key defaults to an empty list (no carve-outs). Entries use the same coarse
    host semantics as the in-scope allowlist; a wildcard carve-out excludes the
    apex AND every subdomain.
    """
    raw_hosts = scope.get("out_of_scope")
    if raw_hosts is None:
        return []
    if not isinstance(raw_hosts, list):
        raise SystemExit("scope.json `out_of_scope` must be a list")
    entries: list[dict[str, str]] = []
    for item in raw_hosts:
        if not isinstance(item, str):
            continue
        entry = classify_scope_entry(item)
        if entry is not None:
            entries.append(entry)
    return entries


def rate_limit(scope: dict[str, Any]) -> float | None:
    """Return the engagement's configured PER-INVOCATION / GLOBAL request-rate
    ceiling (req/s), or ``None`` when unset.

    The cap is the optional ``rate_limit`` field written by ``vigil engagement
    create --rate-limit`` (req/s). httpx ``-rate-limit`` and katana ``-rl`` are
    SINGLE GLOBAL token buckets, so this value caps the *aggregate* request rate
    of the stage it is applied to over the WHOLE in-scope host set probed in that
    one invocation — it bounds per-host only as a side effect (a global cap of N
    spread over M hosts is at most N/M req/s per host). Coverage is honest and
    narrow: only the recon pipeline's bulk web stages consume it today — httpx
    liveness, katana crawl, and js-mining body-fetch. It does NOT throttle the
    recon-specialist's nuclei/ffuf/nmap/whatweb/nikto probes or gau body-fetches.

    ``None`` is the unchanged default: those bulk web stages fall through to their
    per-tool rate defaults and the agent keeps discretion — there is NO hard gate.
    A non-positive or non-numeric value is treated as unset (returns ``None``) so
    a malformed scope can never produce a zero/negative throttle.
    """
    raw = scope.get("rate_limit")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return value


def required_headers(scope: dict[str, Any]) -> dict[str, str]:
    """Return the engagement's program-mandated attribution headers
    (e.g. ``{"X-Bug-Bounty": "<handle>"}``) from ``scope.json``, or ``{}``.

    Mirrors ``assess.lib.kali_output._required_headers`` (the kali_exec reader)
    so recon stages that resolve a loaded scope dict, rather than a directory,
    share the same string→string filtering: only ``str`` name → ``str`` value
    pairs survive, with the name stripped, so a malformed scope can never inject
    a non-header value into argv.
    """
    raw = scope.get("required_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if isinstance(name, str) and name.strip() and isinstance(value, str):
            headers[name.strip()] = value
    return headers


def rate_caps_for_dir(engagement_dir: str) -> tuple[float | None, dict[str, str]]:
    """Read both target-facing knobs for a recon stage from an engagement dir:
    ``(rate_limit, required_headers)``.

    A convenience over ``load_scope`` + ``rate_limit`` + ``required_headers`` for
    stage callers that hold an ``engagement_dir`` (e.g. ``cfg.engagement_dir``)
    rather than a loaded scope dict. ``rate_limit`` is the per-invocation / global
    req/s ceiling or ``None`` (unset = today's per-tool defaults, no hard gate);
    it bounds per-host only as a side effect, and only the bulk web stages (httpx
    liveness, katana crawl, js-mining body-fetch) consume it. ``required_headers``
    is the program attribution header map (``{}`` when none).

    A MISSING scope degrades quietly to ``(None, {})`` (an unconfigured
    engagement). But a scope.json that EXISTS yet cannot be read/parsed for the
    cap emits a loud stderr WARNING before degrading: silently dropping a
    politeness/legal rate ceiling would let a malformed scope un-throttle the
    pass back to the verb default (fail-open), so the operator is told the cap is
    not being enforced rather than failing open in silence.
    """
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        return None, {}
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _warn_scope(
            f"rate_caps_for_dir:{scope_path}",
            f"scope: WARNING: scope.json exists at {scope_path} but could not be "
            f"read for the rate cap ({type(exc).__name__}: {exc}); the configured "
            "per-invocation req/s ceiling is NOT being enforced and this stage "
            "will probe at the verb default rate. Fix the scope file to re-apply "
            "the cap.",
        )
        return None, {}
    if not isinstance(scope, dict):
        _warn_scope(
            f"rate_caps_for_dir:{scope_path}",
            f"scope: WARNING: scope.json at {scope_path} is not a JSON object; the "
            "configured per-invocation req/s ceiling is NOT being enforced and "
            "this stage will probe at the verb default rate.",
        )
        return None, {}
    rl = rate_limit(scope)
    if rl is None and scope.get("rate_limit") is not None:
        # Present-but-invalid value (non-numeric / non-positive / bool) — same
        # silent-un-throttle hazard as a malformed file, so warn rather than fail
        # open: the operator set a rate_limit that does not parse and the cap is
        # NOT being enforced.
        _warn_scope(
            f"rate_caps_for_dir:rate_limit:{scope_path}",
            f"scope: WARNING: scope.json at {scope_path} has a rate_limit value "
            f"({scope.get('rate_limit')!r}) that is not a positive number; the "
            "per-invocation req/s ceiling is NOT being enforced and this stage "
            "will probe at the verb default rate.",
        )
    return rl, required_headers(scope)


def classify_scope_entry(raw: str) -> dict[str, str] | None:
    stripped = raw.strip()
    if not stripped:
        return None

    if stripped.startswith("*.") and len(stripped) > 2:
        host = _to_a_label(stripped[2:])
        if not host:
            return None
        return {
            "scope_entry": stripped,
            "entry_kind": "wildcard",
            "host": host,
        }

    network = _parse_cidr(stripped)
    if network is not None:
        return {
            "scope_entry": stripped,
            "entry_kind": "cidr",
            "host": str(network),
        }

    if "://" in stripped:
        try:
            split = urlsplit(stripped)
        except ValueError:
            return None
        host = _to_a_label(split.hostname or "")
        if not host:
            return None
        path = (split.path or "").strip("/")
        if path:
            _warn_scope(
                stripped,
                f"scope: entry '{stripped}' carries a path; scope is matched at host "
                f"granularity, so this admits the whole host '{host}'. The path boundary "
                "is not enforced — narrow the engagement in-band if it matters.",
            )
        return {
            "scope_entry": stripped,
            "entry_kind": "url",
            "host": host,
        }

    host = host_from_token(stripped, allow_single_label=True)
    if not host:
        return None
    return {
        "scope_entry": stripped,
        "entry_kind": "bare_host",
        "host": _to_a_label(host) or host,
    }


def host_from_token(raw: str, *, allow_single_label: bool = False) -> str:
    """Extract a lowercased host from a URL, host:port, or line token.

    ``allow_single_label`` admits bare single-label hosts (``intranet``). It is
    set only on the explicitly-authored scope-entry path; free-text token
    parsing leaves it False so log lines can't widen scope with stray words.
    """
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
    return _validated_host(host, allow_single_label=allow_single_label)


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


def _validated_host(raw: str, *, allow_single_label: bool = False) -> str:
    host = raw.strip().strip("[]").rstrip(".").lower()
    if not host:
        return ""
    ip_literal = _ip_literal(host)
    if ip_literal:
        return ip_literal
    return host if looks_like_host(host, allow_single_label=allow_single_label) else ""


def _ip_literal(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def looks_like_host(host: str, *, allow_single_label: bool = False) -> bool:
    if not host:
        return False
    if _ip_literal(host):
        return True
    if host == "localhost":
        return True
    if "." in host:
        return True
    if allow_single_label and _is_dns_label(host):
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def entry_matches_host(entry: dict[str, str], host: str) -> bool:
    """Return True when ``host`` is covered by this scope entry.

    Wildcard semantics: ``*.example.test`` matches the bare ``example.test``
    apex AND every subdomain (HackerOne / Bugcrowd / VDP convention).
    """
    if not host:
        return False
    entry_host = entry["host"]
    if entry["entry_kind"] == "cidr":
        ip = _ip_literal(host)
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(entry_host, strict=False)
        except ValueError:
            return False
    normalized = _normalize_host_for_match(host)
    if entry["entry_kind"] == "wildcard":
        if normalized.endswith("." + entry_host):
            return True
        return normalized == entry_host
    return normalized == entry_host


def host_in_scope(host: str, entries: list[dict[str, str]]) -> bool:
    return any(entry_matches_host(entry, host) for entry in entries)


def host_admitted(
    host: str,
    allow_entries: list[dict[str, str]],
    deny_entries: list[dict[str, str]],
) -> bool:
    """Return True IFF ``host`` matches the allowlist AND no denylist entry.

    The denylist wins: a host covered by an in-scope wildcard but matching an
    ``out_of_scope`` carve-out is rejected. This is the single admission
    primitive every scope-matching surface must call.
    """
    return host_in_scope(host, allow_entries) and not host_in_scope(host, deny_entries)


def explain_target(
    token: str,
    allow_entries: list[dict[str, str]],
    deny_entries: list[dict[str, str]],
    scope: dict[str, Any],
) -> dict[str, Any]:
    """Return a read-only scope verdict struct for one url-or-host ``token``.

    Pure composition over the existing scope primitives — no new matching logic,
    no writes, no network. Parses ``token`` to a host with
    :func:`host_from_token`, then reports the admission decision AND *which*
    entries drove it: :func:`host_admitted` only returns a bool, so the matching
    allow/deny entries are recovered by iterating :func:`entry_matches_host` over
    the pre-classified ``allow_entries`` / ``deny_entries``. Denylist wins (same
    rule as :func:`host_admitted`): a host covered by an in-scope wildcard but
    also by an ``out_of_scope`` carve-out is denied.

    The struct carries a stable key set (every key always present):
    ``target`` (the raw token), ``host`` (parsed host or ``None`` for an
    unparseable token), ``admitted`` (bool), ``reason`` (human-readable),
    ``allow_entry`` / ``allow_entry_kind`` (the matched allowlist scope string +
    its kind, or ``None``), ``deny_entry`` / ``deny_entry_kind`` (matched
    carve-out, or ``None``), ``required_headers`` (program attribution headers),
    ``rate_limit`` (per-invocation req/s ceiling or ``None``), and
    ``vendor_saas`` (vendor label when the host's shape matches a known
    SaaS-fronted suffix, else ``None``).
    """
    host = host_from_token(token)
    headers = required_headers(scope)
    rl = rate_limit(scope)

    if not host:
        return {
            "target": token,
            "host": None,
            "admitted": False,
            "reason": "invalid token: could not parse a host",
            "allow_entry": None,
            "allow_entry_kind": None,
            "deny_entry": None,
            "deny_entry_kind": None,
            "required_headers": headers,
            "rate_limit": rl,
            "vendor_saas": None,
        }

    allow_match = next(
        (e for e in allow_entries if entry_matches_host(e, host)), None
    )
    deny_match = next(
        (e for e in deny_entries if entry_matches_host(e, host)), None
    )
    admitted = host_admitted(host, allow_entries, deny_entries)

    if deny_match is not None:
        reason = f"denied by out-of-scope entry '{deny_match['scope_entry']}'"
    elif allow_match is None:
        reason = "not in scope: no allowlist entry matches"
    else:
        reason = f"in scope via allow entry '{allow_match['scope_entry']}'"

    return {
        "target": token,
        "host": host,
        "admitted": admitted,
        "reason": reason,
        "allow_entry": allow_match["scope_entry"] if allow_match else None,
        "allow_entry_kind": allow_match["entry_kind"] if allow_match else None,
        "deny_entry": deny_match["scope_entry"] if deny_match else None,
        "deny_entry_kind": deny_match["entry_kind"] if deny_match else None,
        "required_headers": headers,
        "rate_limit": rl,
        "vendor_saas": host_is_vendor_saas(host),
    }


def ingest_scope_filter(
    engagement_dir: str,
) -> tuple[list[dict[str, str]], list[dict[str, str]], bool]:
    """Return ``(allow_entries, deny_entries, active)`` for an ingest-time scope gate.

    ``active`` is False — the gate admits every host — when scope.json cannot be
    loaded or declares no allowlist. This is a deliberate fail-open:
    :func:`host_admitted` returns False for ALL hosts against an empty allowlist,
    so activating the gate with no real scope entries would reject the entire
    batch. The ``vigil assess recon`` pipeline scope-filters the resolved host set
    upstream; this gate is defense-in-depth for the third-party / spec-declared
    URL sources (gau/wayback history, an OpenAPI ``servers`` url, a curated
    candidate row) that bypass that filter, not the primary scope boundary.

    The single resolver shared by ``ingest-endpoints`` / ``ingest-candidates``
    (per-URL via :func:`host_admitted`) and ``ingest-spec`` (per-base-host), so
    every ingest path applies identical admission semantics and the same
    fail-open rule.
    """
    try:
        scope = load_scope(engagement_dir)
        allow = scope_entries(scope)
        deny = out_of_scope_entries(scope)
    except SystemExit:
        # No scope.json, or a shape load_scope/scope_entries rejects — treated as
        # "no scope configured": gate inactive, every host admitted (the recon
        # pipeline remains the primary scope gate).
        return [], [], False
    except Exception as exc:  # noqa: BLE001 — scope load must never abort an ingest batch
        _warn_scope(
            "ingest-scope-filter",
            f"WARN: could not load scope for the ingest scope filter ({exc}); "
            "admitting all hosts (gate inactive).",
        )
        return [], [], False
    return allow, deny, bool(allow)
