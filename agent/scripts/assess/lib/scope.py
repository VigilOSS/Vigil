"""Scope parsing — replaces lib/scope.sh for Python callers."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Literal, NamedTuple
from urllib.parse import urlsplit

from assess.lib import no_fire


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

_TARGET_LIST_FLAGS = frozenset(
    {
        "-dL",
        "-iL",
        "-l",
        "-list",
        "-tL",
        "--list",
        "--input-file",
        "--targets-file",
        "--url-file",
        "-i",
    }
)

_LIST_TARGET_TOOLS = frozenset(
    {
        "alterx",
        "arjun",
        "asnmap",
        "bbot",
        "dnsx",
        "httpx",
        "katana",
        "naabu",
        "nmap",
        "nuclei",
        "subfinder",
        "tlsx",
    }
)

_TARGET_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "alterx": frozenset({"-d", "--domain"}),
    "arjun": frozenset({"-u"}),
    "asnmap": frozenset({"-d"}),
    "bbot": frozenset({"-t", "--target"}),
    "cero": frozenset({"-d", "--domain"}),
    "ffuf": frozenset({"-u", "--url"}),
    "httpx": frozenset({"-u", "--url", "-target"}),
    "katana": frozenset({"-u", "--url", "-target"}),
    "nikto": frozenset({"-h", "--host"}),
    "nuclei": frozenset({"-u", "--target", "-target"}),
    "sqlmap": frozenset({"-u", "--url"}),
    "subfinder": frozenset({"-d", "--domain"}),
    "tlsx": frozenset({"-u"}),
}

_POSITIONAL_TARGET_TOOLS = frozenset(
    {"cero", "curl", "gau", "nmap", "wafw00f", "whatweb"}
)

_SHELL_BINARIES = frozenset({"sh", "bash", "dash", "zsh"})
_SHELL_BOUNDARIES = frozenset({"|", "||", "&&", ";", "&", "(", ")"})
_SHELL_CONTROL_WORDS = frozenset(
    {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in"}
)
_TARGET_FACING_TOOLS = frozenset(
    {
        "arjun", "bbot", "cero", "curl", "dalfox", "dnsx", "ffuf", "httpx",
        "katana", "naabu", "nikto", "nmap", "nuclei", "puredns", "sqlmap",
        "subfinder", "tlsx", "wafw00f", "whatweb", "wget",
    }
)

_NON_TARGET_VALUE_FLAGS = frozenset(
    {
        "-H",
        "-header",
        "--header",
        "-o",
        "--output",
        "-t",
        "-tags",
        "-exclude-tags",
        "-etags",
        "-w",
        "--wordlist",
        "-A",
        "--user-agent",
        "--resolve",
    }
)


class ScopePolicyError(RuntimeError):
    """Raised before execution when engagement target/tool policy rejects a run."""


class ExecutionDestination(NamedTuple):
    """One explicitly classified network destination in an execution plan."""

    value: str
    role: Literal["target", "passive_source", "control"] = "target"


def execution_policy_notes(policy: dict[str, Any]) -> str:
    """Serialize an audit-safe summary below the command-run 4096-byte limit."""
    summarized = dict(policy)
    checked = sorted(
        {str(value).strip() for value in summarized.pop("checked_targets", []) if str(value).strip()}
    )
    if checked:
        encoded = json.dumps(checked, ensure_ascii=True, separators=(",", ":"))
        summarized["checked_target_count"] = len(checked)
        summarized["checked_targets_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
        summarized["checked_targets_sample"] = checked[:16]
    external = summarized.pop("external_destinations", [])
    if external:
        normalized_external = sorted(
            (
                {
                    "host": str(item.get("host") or "").strip(),
                    "role": str(item.get("role") or "").strip(),
                }
                for item in external
                if isinstance(item, dict) and str(item.get("host") or "").strip()
            ),
            key=lambda item: (item["role"], item["host"]),
        )
        encoded = json.dumps(normalized_external, ensure_ascii=True, separators=(",", ":"))
        summarized["external_destination_count"] = len(normalized_external)
        summarized["external_destinations_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
        summarized["external_destinations_sample"] = normalized_external[:16]
    refusal = str(summarized.get("policy_refusal") or "")
    if len(refusal) > 1024:
        summarized["policy_refusal"] = refusal[:1024]
        summarized["policy_refusal_sha256"] = hashlib.sha256(refusal.encode()).hexdigest()
    rendered = json.dumps(summarized, ensure_ascii=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) >= 4096:
        summarized.pop("checked_targets_sample", None)
        summarized.pop("external_destinations_sample", None)
        rendered = json.dumps(summarized, ensure_ascii=True, separators=(",", ":"))
    return rendered


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


def scope_enforcement(scope: dict[str, Any]) -> str:
    """Return the engagement-wide target-admission mode.

    Enforcement is the safe default for new and legacy engagements.  The only
    value that disables admission checks is the exact, durable
    ``scope_enforcement: \"bypass\"`` setting in ``scope.json``; unknown values
    deliberately fall back to enforcement so a typo cannot widen authorization.
    """
    value = scope.get("scope_enforcement", "enforce")
    return "bypass" if isinstance(value, str) and value.strip().lower() == "bypass" else "enforce"


def denied_tools(scope: dict[str, Any]) -> set[str]:
    """Return the normalized engagement-wide tool denylist.

    A present-but-malformed policy fails closed instead of silently dropping
    governance. Non-string list members are ignored because they cannot name an
    executable.
    """
    policy = scope.get("tool_policy")
    if policy is not None and not isinstance(policy, dict):
        raise SystemExit("scope.json `tool_policy` must be an object")
    sources = [scope.get("denied_tools")]
    if isinstance(policy, dict):
        sources.append(policy.get("denied_tools"))
    denied: set[str] = set()
    for raw in sources:
        if raw is None:
            continue
        if not isinstance(raw, list):
            raise SystemExit("scope.json `denied_tools` must be a list")
        denied.update(
            item.strip().lower()
            for item in raw
            if isinstance(item, str) and item.strip()
        )
    return denied


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


def aggregate_rate_limit(scope: dict[str, Any]) -> float | None:
    """Return the engagement-wide concurrent target-rate ceiling, if valid."""
    raw = scope.get("rate_limit_aggregate_rps")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


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


def target_admission(scope: dict[str, Any], token: str) -> dict[str, Any]:
    """Return the canonical admission verdict for one target token.

    This is the policy-bearing front door for execution callers. Matching stays
    single-sourced in :func:`explain_target`; this layer only applies the one
    engagement-wide bypass and makes that choice explicit in the verdict so
    command audit can preserve it.
    """
    allow_entries = scope_entries(scope)
    deny_entries = out_of_scope_entries(scope)
    target_network = _parse_cidr(token.strip())
    if target_network is None:
        verdict = explain_target(token, allow_entries, deny_entries, scope)
    else:
        allow_match = None
        for entry in allow_entries:
            if entry["entry_kind"] != "cidr":
                continue
            try:
                if target_network.subnet_of(ipaddress.ip_network(entry["host"])):
                    allow_match = entry
                    break
            except (TypeError, ValueError):
                continue
        deny_match = None
        for entry in deny_entries:
            try:
                if entry["entry_kind"] == "cidr":
                    denied_network = ipaddress.ip_network(entry["host"])
                    if target_network.overlaps(denied_network):
                        deny_match = entry
                        break
                else:
                    denied_ip = ipaddress.ip_address(entry["host"])
                    if denied_ip in target_network:
                        deny_match = entry
                        break
            except (TypeError, ValueError):
                continue
        admitted = allow_match is not None and deny_match is None
        reason = (
            f"denied by out-of-scope entry '{deny_match['scope_entry']}'"
            if deny_match is not None
            else (
                f"in scope via allow entry '{allow_match['scope_entry']}'"
                if allow_match is not None
                else "not in scope: no allowlist network contains target CIDR"
            )
        )
        verdict = {
            "target": token,
            "host": str(target_network),
            "admitted": admitted,
            "reason": reason,
            "allow_entry": allow_match["scope_entry"] if allow_match else None,
            "allow_entry_kind": allow_match["entry_kind"] if allow_match else None,
            "deny_entry": deny_match["scope_entry"] if deny_match else None,
            "deny_entry_kind": deny_match["entry_kind"] if deny_match else None,
            "required_headers": required_headers(scope),
            "rate_limit": rate_limit(scope),
            "vendor_saas": None,
        }
    enforcement = scope_enforcement(scope)
    bypassed = enforcement == "bypass" and verdict["host"] is not None
    verdict["scope_enforcement"] = enforcement
    verdict["bypassed"] = bypassed
    if bypassed:
        verdict["admitted"] = True
        verdict["reason"] = "admitted by engagement-wide global scope bypass"
    return verdict


def _host_list_path(raw: str, engagement_dir: Path, engagement_key: str) -> Path:
    container_prefix = f"/engagements/{engagement_key}/"
    if raw.startswith(container_prefix):
        return engagement_dir / raw[len(container_prefix):]
    path = Path(raw).expanduser()
    return path if path.is_absolute() else engagement_dir / path


def _target_tokens_from_file(path: Path) -> list[str]:
    tokens: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith("{"):
            try:
                record = json.loads(value)
            except json.JSONDecodeError:
                record = None
            if isinstance(record, dict):
                value = str(
                    record.get("url")
                    or record.get("endpoint")
                    or record.get("host")
                    or record.get("target")
                    or ""
                ).strip()
        if value:
            tokens.append(value)
    return tokens


_LAUNCHERS = frozenset(
    {
        "command", "env", "exec", "nice", "nohup", "setsid", "stdbuf",
        "sudo", "time", "timeout", "xargs",
    }
)


def _launcher_inner_index(argv: list[str], launcher: str) -> tuple[int | None, bool]:
    """Locate a transparent launcher's child argv without guessing option values."""
    index = 1
    if launcher == "sudo":
        value_options = {
            "-C", "--close-from", "-D", "--chdir", "-g", "--group", "-h",
            "--host", "-p", "--prompt", "-R", "--chroot", "-T",
            "--command-timeout", "-u", "--user",
        }
        flag_options = {
            "-A", "--askpass", "-b", "--background", "-E", "--preserve-env",
            "-H", "--set-home", "-K", "--remove-timestamp", "-k", "--reset-timestamp",
            "-n", "--non-interactive", "-S", "--stdin", "-V", "--version",
        }
    elif launcher == "env":
        value_options = {
            "-C", "--chdir", "-S", "--split-string", "-u", "--unset",
        }
        flag_options = {"-0", "--null", "-i", "--ignore-environment"}
    elif launcher == "timeout":
        value_options = {"-k", "--kill-after", "-s", "--signal"}
        flag_options = {"--foreground", "--preserve-status", "-v", "--verbose"}
    elif launcher == "exec":
        value_options = {"-a"}
        flag_options = {"-c", "-l"}
    elif launcher == "nice":
        value_options = {"-n", "--adjustment"}
        flag_options = set()
    elif launcher == "setsid":
        value_options = set()
        flag_options = {"-c", "--ctty", "-f", "--fork", "-w", "--wait"}
    elif launcher == "stdbuf":
        value_options = {
            "-e", "--error", "-i", "--input", "-o", "--output",
        }
        flag_options = set()
    elif launcher == "time":
        value_options = {"-f", "--format", "-o", "--output"}
        flag_options = {"-a", "--append", "-p", "--portability", "-v", "--verbose"}
    elif launcher == "xargs":
        value_options = {
            "-a", "--arg-file", "-d", "--delimiter", "-E", "--eof", "-I",
            "--replace", "-L", "--max-lines", "-n", "--max-args", "-P",
            "--max-procs", "-s", "--max-chars",
        }
        flag_options = {
            "-0", "--null", "-o", "--open-tty", "-p", "--interactive", "-r",
            "--no-run-if-empty", "-t", "--verbose", "-x", "--exit",
        }
    elif launcher == "command":
        value_options = set()
        flag_options = {"-p"}
    else:  # nohup
        value_options = set()
        flag_options = set()

    while index < len(argv):
        token = str(argv[index])
        if token == "--":
            index += 1
            if launcher == "timeout":
                if index >= len(argv):
                    return None, True
                index += 1
            break
        if launcher == "env" and "=" in token and token.split("=", 1)[0].isidentifier():
            index += 1
            continue
        if launcher == "timeout" and not token.startswith("-"):
            # timeout's first positional is the duration, not the executable.
            index += 1
            break
        if token in value_options:
            if index + 1 >= len(argv):
                return None, True
            index += 2
            continue
        if any(token.startswith(option + "=") for option in value_options if option.startswith("--")):
            index += 1
            continue
        if token in flag_options:
            index += 1
            continue
        if launcher == "sudo" and token.startswith("--preserve-env="):
            index += 1
            continue
        if launcher == "sudo" and token.startswith("-") and not token.startswith("--"):
            # Common no-value short options may be clustered (`sudo -nEH`).
            if len(token) > 2 and set(token[1:]) <= set("AbEHKnS Vk".replace(" ", "")):
                index += 1
                continue
            # Common value options may carry the value in the same argv token.
            if len(token) > 2 and token[:2] in {"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u"}:
                index += 1
                continue
        if launcher == "env" and token.startswith("-") and not token.startswith("--"):
            if len(token) > 2 and token[:2] in {"-C", "-S", "-u"}:
                index += 1
                continue
        if launcher == "timeout" and token.startswith("-") and not token.startswith("--"):
            if len(token) > 2 and token[:2] in {"-k", "-s"}:
                index += 1
                continue
        if launcher in {"nice", "stdbuf", "time", "xargs"} and token.startswith("-"):
            attached_value_flags = {
                "nice": {"-n"},
                "stdbuf": {"-e", "-i", "-o"},
                "time": {"-f", "-o"},
                "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"},
            }[launcher]
            if len(token) > 2 and token[:2] in attached_value_flags:
                index += 1
                continue
        if token.startswith("-"):
            return None, True
        break

    if launcher == "timeout" and index >= len(argv):
        return None, True
    if launcher == "command" and index < len(argv) and argv[index] in {"-v", "-V"}:
        return None, False
    return (index if index < len(argv) else None), index >= len(argv)


def _argv_tool_analysis(argv: list[str], *, depth: int = 0) -> tuple[set[str], bool]:
    if depth > 16:
        return set(), True
    index = 0
    while index < len(argv):
        token = str(argv[index]).strip()
        if "=" in token and token.split("=", 1)[0].isidentifier():
            index += 1
            continue
        break
    if index >= len(argv):
        return set(), False
    raw_head = str(argv[index]).strip()
    if raw_head.startswith("$"):
        return set(), True
    head = Path(raw_head).name.lower()
    if not head or head.startswith("-"):
        return set(), True
    tools = {head}
    command = [str(value) for value in argv[index:]]
    if head in _SHELL_BINARIES:
        scripts = [
            command[pos + 1]
            for pos, option in enumerate(command[:-1])
            if option.startswith("-") and option.endswith("c")
        ]
        if not scripts:
            return tools, False
        ambiguous = False
        for script in scripts:
            nested_tools, nested_ambiguous = _shell_tool_analysis(script, depth=depth + 1)
            tools.update(nested_tools)
            ambiguous = ambiguous or nested_ambiguous
        return tools, ambiguous
    if head in _LAUNCHERS:
        inner_index, ambiguous = _launcher_inner_index(command, head)
        if inner_index is None:
            return tools, ambiguous
        nested_tools, nested_ambiguous = _argv_tool_analysis(
            command[inner_index:], depth=depth + 1
        )
        tools.update(nested_tools)
        return tools, ambiguous or nested_ambiguous
    return tools, False


def _shell_command_segments(script: str) -> tuple[list[list[str]], bool]:
    """Parse a shell script into simple-command argv segments."""
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars="|;&()\n")
        # Preserve newlines as command separators instead of discarding them as
        # generic whitespace; otherwise `echo ok\nnuclei ...` hides nuclei.
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [], True
    segments: list[list[str]] = []
    segment: list[str] = []

    def append_segment() -> None:
        if not segment:
            return
        command = list(segment)
        while command and command[0] in {"!", "{", "then", "do", "else", "elif"}:
            command.pop(0)
        if not command or command[0] in {"done", "fi", "esac", "}"}:
            return
        if command[0] in {"for", "select", "case", "function"}:
            return
        if command[0] in {"if", "until", "while"}:
            command.pop(0)
        if command:
            segments.append(command)

    for raw in tokens:
        token = str(raw)
        if token == "\n" or (
            token and set(token) <= {"|", ";", "&", "(", ")"}
        ):
            append_segment()
            segment = []
            continue
        if token.strip():
            segment.append(token)
    append_segment()
    return segments, False


def _shell_tool_analysis(script: str, *, depth: int = 0) -> tuple[set[str], bool]:
    segments, ambiguous = _shell_command_segments(script)
    tools: set[str] = set()
    for command in segments:
        nested_tools, nested_ambiguous = _argv_tool_analysis(command, depth=depth + 1)
        tools.update(nested_tools)
        ambiguous = ambiguous or nested_ambiguous
    return {tool for tool in tools if tool}, ambiguous


def execution_tools(cmd: list[str]) -> set[str]:
    """Return every executable visible in a direct or shell-wrapped command."""
    tools, _ = _argv_tool_analysis([str(token) for token in cmd])
    return tools


def _unwrap_launcher_argv(cmd: list[str]) -> list[str]:
    """Return the direct child argv behind supported transparent launchers."""
    current = [str(token) for token in cmd]
    for _ in range(16):
        if not current:
            return current
        head = Path(current[0]).name.lower()
        if head not in _LAUNCHERS:
            return current
        inner_index, ambiguous = _launcher_inner_index(current, head)
        if ambiguous or inner_index is None:
            return current
        current = current[inner_index:]
    return current


def _has_dynamic_target_shell(cmd: list[str], tools: set[str]) -> bool:
    if not cmd or Path(str(cmd[0])).name.lower() not in _SHELL_BINARIES:
        return False
    scripts = [
        str(cmd[index + 1])
        for index, token in enumerate(cmd[:-1])
        if token.startswith("-") and token.endswith("c")
    ]
    return any(
        "$" in script and bool(tools & _TARGET_FACING_TOOLS)
        for script in scripts
    )


_SHELL_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")


def _expand_shell_token(token: str, assignments: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("plain") or ""
        return assignments.get(name, match.group(0))

    return _SHELL_VARIABLE.sub(replace, token)


def _shell_target_tokens(
    cmd: list[str], *, engagement_dir: Path, engagement_key: str
) -> tuple[list[str], set[str]]:
    """Resolve shell targets and identify URLs with unresolved path components."""
    if not cmd or Path(str(cmd[0])).name.lower() not in _SHELL_BINARIES:
        return [], set()
    scripts = [
        str(cmd[index + 1])
        for index, token in enumerate(cmd[:-1])
        if token.startswith("-") and token.endswith("c")
    ]
    candidates: list[str] = []
    unresolved_paths: set[str] = set()
    for script in scripts:
        try:
            lexer = shlex.shlex(script, posix=True, punctuation_chars="|;&()")
            lexer.whitespace_split = True
            lexer.commenters = ""
            words = list(lexer)
        except ValueError:
            return candidates, set(candidates)
        assignments: dict[str, str] = {}
        segment: list[str] = []

        def inspect_segment() -> None:
            if not segment:
                return
            expanded: list[str] = []
            for word in segment:
                if "=" in word and word.split("=", 1)[0].isidentifier():
                    name, value = word.split("=", 1)
                    assignments[name] = _expand_shell_token(value, assignments)
                    continue
                expanded.append(_expand_shell_token(word, assignments))
            if not expanded:
                return
            tool = Path(expanded[0]).name.lower()
            if tool not in _TARGET_FACING_TOOLS:
                return
            found = _command_target_tokens(
                expanded,
                tool_name=tool,
                engagement_dir=engagement_dir,
                engagement_key=engagement_key,
            )
            candidates.extend(found)
            for value in found:
                try:
                    parsed = urlsplit(value)
                    path = parsed.path
                    netloc = parsed.netloc
                except ValueError:
                    path = value
                    netloc = ""
                host_is_single_variable = bool(
                    re.fullmatch(
                        r"\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)",
                        netloc,
                    )
                )
                if _SHELL_VARIABLE.search(path) or (
                    _SHELL_VARIABLE.search(netloc) and not host_is_single_variable
                ):
                    unresolved_paths.add(value)

        for word in words:
            if word in _SHELL_BOUNDARIES or (
                word and set(word) <= {"|", ";", "&", "(", ")"}
            ):
                inspect_segment()
                segment = []
            else:
                segment.append(word)
        inspect_segment()
    return candidates, unresolved_paths


def _command_target_tokens(
    cmd: list[str], *, tool_name: str, engagement_dir: Path, engagement_key: str
) -> list[str]:
    """Extract direct and list-backed target tokens from an execution argv."""
    candidates: list[str] = []
    tool = Path(tool_name or (cmd[0] if cmd else "")).name.lower()
    target_flags = _TARGET_VALUE_FLAGS.get(tool, frozenset())
    index = 1
    while index < len(cmd):
        token = str(cmd[index]).strip()
        previous = str(cmd[index - 1]).strip() if index else ""
        if tool in _LIST_TARGET_TOOLS and previous in _TARGET_LIST_FLAGS:
            path = _host_list_path(token, engagement_dir, engagement_key)
            if not path.is_file():
                raise ScopePolicyError(f"cannot inspect target list before execution: {token}")
            candidates.extend(_target_tokens_from_file(path))
            index += 1
            continue
        if previous in target_flags:
            candidates.append(token)
            index += 1
            continue
        if tool == "puredns" and len(cmd) > 3 and cmd[1] == "bruteforce" and index == 3:
            candidates.append(token)
            index += 1
            continue
        if tool == "puredns" and len(cmd) > 2 and cmd[1] == "resolve" and index == 2:
            path = _host_list_path(token, engagement_dir, engagement_key)
            if not path.is_file():
                raise ScopePolicyError(f"cannot inspect target list before execution: {token}")
            candidates.extend(_target_tokens_from_file(path))
            index += 1
            continue
        if tool == "dalfox" and len(cmd) > 2 and cmd[1] in {"url", "file"} and index == 2:
            if cmd[1] == "url":
                candidates.append(token)
            else:
                path = _host_list_path(token, engagement_dir, engagement_key)
                if not path.is_file():
                    raise ScopePolicyError(f"cannot inspect target list before execution: {token}")
                candidates.extend(_target_tokens_from_file(path))
            index += 1
            continue
        # Shell wrappers hide the real argv in one script string. Recursively
        # inspect it so `bash -c 'curl https://target'` cannot evade admission.
        if previous.startswith("-") and previous.endswith("c") and cmd and Path(str(cmd[0])).name in _SHELL_BINARIES:
            try:
                inner = shlex.split(token)
            except ValueError:
                inner = []
            if tool == "cero" and len(inner) >= 2 and Path(inner[0]).name == "cat":
                path = _host_list_path(inner[1], engagement_dir, engagement_key)
                if not path.is_file():
                    raise ScopePolicyError(
                        f"cannot inspect target list before execution: {inner[1]}"
                    )
                candidates.extend(_target_tokens_from_file(path))
            if inner:
                candidates.extend(
                    _command_target_tokens(
                        inner,
                        tool_name=Path(inner[0]).name if inner else "",
                        engagement_dir=engagement_dir,
                        engagement_key=engagement_key,
                    )
                )
            index += 1
            continue
        if (
            previous not in _NON_TARGET_VALUE_FLAGS
            and not token.startswith("-")
            and token.startswith(("http://", "https://"))
        ):
            candidates.append(token)
            index += 1
            continue
        if (
            tool in _POSITIONAL_TARGET_TOOLS
            and previous not in _NON_TARGET_VALUE_FLAGS
            and not token.startswith("-")
            and host_from_token(token)
        ):
            candidates.append(token)
        index += 1
    return candidates


def enforce_execution_policy(
    cmd: list[str],
    *,
    tool_name: str,
    engagement_dir: str | Path,
    engagement_key: str | None = None,
    explicit_targets: list[str] | tuple[str, ...] = (),
    destinations: tuple[ExecutionDestination, ...] = (),
    require_declared_tool: bool = False,
) -> dict[str, Any]:
    """Apply engagement-wide tool and target admission before any process starts.

    The return value is deliberately audit-ready. Every execution lane can store
    the same enforcement/bypass marker without reinterpreting ``scope.json``.
    """
    eng_dir = Path(engagement_dir).expanduser().resolve()
    key = str(engagement_key or eng_dir.name).strip()
    if not key:
        raise ScopePolicyError("engagement key is empty")
    try:
        scope_doc = load_scope(str(eng_dir))
    except (OSError, json.JSONDecodeError, SystemExit) as exc:
        raise ScopePolicyError(f"cannot load scope policy before execution: {exc}") from exc

    normalized_tool = Path(str(tool_name or (cmd[0] if cmd else ""))).name.strip().lower()
    observed_tools, tool_analysis_ambiguous = _argv_tool_analysis(
        [str(token) for token in cmd]
    )
    policy_tools = set(observed_tools)
    policy_tools.add(normalized_tool)
    if require_declared_tool and normalized_tool not in observed_tools:
        observed = ", ".join(sorted(observed_tools)) or "(none)"
        raise ScopePolicyError(
            f"declared tool '{normalized_tool}' contradicts executable(s): {observed}"
        )
    try:
        denied = denied_tools(scope_doc)
    except SystemExit as exc:
        raise ScopePolicyError(str(exc)) from exc
    blocked_tool = next((name for name in sorted(policy_tools) if name in denied), None)
    if blocked_tool:
        raise ScopePolicyError(
            f"tool '{blocked_tool}' is denied by engagement scope policy"
        )

    # Pre-machine-scope engagement fixtures/files used ``hostname`` alone.
    # They cannot be interpreted as an allowlist without silently changing
    # exact-vs-wildcard authorization, so preserve their legacy behavior. Every
    # engagement created by the supported CLI has an explicit ``hosts`` list.
    target_gate_configured = "hosts" in scope_doc
    typed_destinations: list[tuple[str, str]] = []
    for destination in destinations:
        if destination.role not in {"target", "passive_source", "control"}:
            raise ScopePolicyError(f"unknown execution destination role: {destination.role}")
        host = host_from_token(destination.value)
        if not host:
            raise ScopePolicyError(
                f"typed execution destination is not a resolvable host: {destination.value}"
            )
        typed_destinations.append((host, destination.role))
    typed_by_host: dict[str, str] = {}
    for host, role in typed_destinations:
        previous_role = typed_by_host.get(host)
        if previous_role is not None and previous_role != role:
            raise ScopePolicyError(
                f"conflicting typed destination roles for {host}: "
                f"{previous_role!r} and {role!r}"
            )
        typed_by_host[host] = role
    if tool_analysis_ambiguous and any(
        role == "target" for _, role in typed_destinations
    ):
        raise ScopePolicyError(
            "ambiguous executable launcher form for a target-facing command; "
            "use supported launcher options or invoke the tool directly"
        )
    dynamic_target_shell = _has_dynamic_target_shell(cmd, observed_tools)
    if dynamic_target_shell and not typed_destinations:
        raise ScopePolicyError(
            "dynamic target in shell command cannot be resolved before execution; "
            "provide an explicit typed destination"
        )

    raw_targets = list(explicit_targets)
    raw_targets.extend(
        destination.value
        for destination in destinations
        if destination.role == "target"
    )
    if target_gate_configured:
        inspection_cmd = _unwrap_launcher_argv(cmd)
        raw_targets.extend(
            _command_target_tokens(
                inspection_cmd,
                tool_name=normalized_tool,
                engagement_dir=eng_dir,
                engagement_key=key,
            )
        )
        actual_tool = (
            Path(str(inspection_cmd[0])).name.strip().lower()
            if inspection_cmd
            else ""
        )
        if actual_tool and actual_tool != normalized_tool:
            raw_targets.extend(
                _command_target_tokens(
                    inspection_cmd,
                    tool_name=actual_tool,
                    engagement_dir=eng_dir,
                    engagement_key=key,
                )
            )
    shell_targets, unresolved_shell_paths = _shell_target_tokens(
        cmd,
        engagement_dir=eng_dir,
        engagement_key=key,
    )
    raw_targets.extend(shell_targets)
    if tool_analysis_ambiguous and any(
        (host := host_from_token(token))
        and typed_by_host.get(host) not in {"passive_source", "control"}
        for token in raw_targets
    ):
        raise ScopePolicyError(
            "ambiguous executable launcher form for a target-facing command; "
            "use supported launcher options or invoke the tool directly"
        )
    try:
        no_fire_patterns = no_fire.patterns(scope_doc)
    except no_fire.NoFirePolicyError as exc:
        raise ScopePolicyError(str(exc)) from exc
    if no_fire_patterns:
        for token in unresolved_shell_paths:
            host = host_from_token(token)
            if host and typed_by_host.get(host) in {"passive_source", "control"}:
                continue
            raise ScopePolicyError(
                "unresolved shell target URL path may match no-fire paths; typed "
                "target destinations authorize hosts only, never unresolved paths"
            )
    for token in raw_targets:
        token_host = host_from_token(token)
        if token_host and typed_by_host.get(token_host) in {"passive_source", "control"}:
            continue
        try:
            blocked_pattern = no_fire.match_url(scope_doc, token)
        except no_fire.NoFirePolicyError as exc:
            raise ScopePolicyError(str(exc)) from exc
        if blocked_pattern:
            raise ScopePolicyError(
                f"refusing no-fire URL {token!r}; matched off_limits_paths pattern "
                f"{blocked_pattern!r}"
            )
    checked_hosts: list[str] = []
    external_destinations: list[dict[str, str]] = []
    for host, role in typed_destinations:
        if role != "target" and {"host": host, "role": role} not in external_destinations:
            external_destinations.append({"host": host, "role": role})
    bypassed = False
    for token in raw_targets:
        try:
            verdict = target_admission(scope_doc, token)
        except SystemExit as exc:
            raise ScopePolicyError(str(exc)) from exc
        host = verdict.get("host")
        if not host:
            continue
        host = str(host)
        if typed_by_host.get(host) in {"passive_source", "control"}:
            continue
        if host not in checked_hosts:
            checked_hosts.append(host)
        if not target_gate_configured:
            continue
        bypassed = bypassed or bool(verdict.get("bypassed"))
        if not verdict["admitted"]:
            raise ScopePolicyError(
                f"refusing target outside engagement scope: {host} ({verdict['reason']})"
            )

    target_facing = bool(checked_hosts) or any(
        role == "target" for _, role in typed_destinations
    )
    if not typed_destinations and observed_tools & _TARGET_FACING_TOOLS:
        target_facing = True
    result: dict[str, Any] = {
        "scope_enforcement": scope_enforcement(scope_doc),
        "scope_bypassed": bypassed,
        "checked_targets": checked_hosts,
    }
    if external_destinations:
        result["external_destinations"] = external_destinations
    if typed_destinations or dynamic_target_shell or (not checked_hosts and target_facing):
        result["target_facing"] = target_facing
    return result


def filter_recon_targets(
    scope_doc: dict[str, Any], targets: list[str]
) -> tuple[list[str], dict[str, Any]]:
    """Apply the shared host-admission policy to a recon target collection."""
    values = [str(value).strip() for value in targets if str(value).strip()]
    enforcement = scope_enforcement(scope_doc)
    allow = scope_entries(scope_doc)
    if enforcement == "bypass" or not allow:
        return values, {
            "scope_enforcement": enforcement,
            "scope_bypassed": enforcement == "bypass" and bool(values),
            "input_count": len(values),
            "kept_count": len(values),
            "dropped_count": 0,
        }
    kept = [
        token for token in values if target_admission(scope_doc, token).get("admitted")
    ]
    return kept, {
        "scope_enforcement": enforcement,
        "scope_bypassed": False,
        "input_count": len(values),
        "kept_count": len(kept),
        "dropped_count": len(values) - len(kept),
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
