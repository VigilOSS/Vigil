"""Scope parsing — replaces lib/scope.sh for Python callers."""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from assess.lib.tracks import track_phases

try:
    from vigil_cli.scope_entries import (
        _warned_scope_keys,
        classify_scope_entry,
        ip_literal as _canonical_ip_literal,
        is_dns_label as _canonical_is_dns_label,
        normalize_host as _canonical_normalize_host,
        normalize_host_for_match as _canonical_normalize_host_for_match,
        parse_cidr as _canonical_parse_cidr,
        to_a_label as _canonical_to_a_label,
    )
except ModuleNotFoundError as exc:
    if exc.name != "vigil_cli":
        raise
    source_root = Path(__file__).resolve().parents[4] / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from vigil_cli.scope_entries import (
        _warned_scope_keys,
        classify_scope_entry,
        ip_literal as _canonical_ip_literal,
        is_dns_label as _canonical_is_dns_label,
        normalize_host as _canonical_normalize_host,
        normalize_host_for_match as _canonical_normalize_host_for_match,
        parse_cidr as _canonical_parse_cidr,
        to_a_label as _canonical_to_a_label,
    )

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
    scope filters and coverage accounting. A bare ``salesforce.com`` apex is
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



_SHELL_BINARIES = frozenset({"sh", "bash", "dash", "zsh"})

# Executables that put requests on the wire against whatever they are pointed at.
# This is a TOOL classifier, NOT a destination filter. Execution lanes consume
# it for target-traffic context and to require that target-facing activity has
# an explicit authorization-root set. It never decides whether a named
# destination is in scope and makes no request-rate claim.
#
# ``browser`` is not an executable — it is the tool name ``kali browser``
# declares. Its argv is ``python3 -c <driver> <json-plan>``, so neither the
# executable nor the plan's URLs are visible as argv words, and without the
# declared name a Playwright run would drive a real browser against the target
# without the cross-lane target-traffic advisory.
_TARGET_FACING_TOOLS = frozenset(
    {
        "arjun", "bbot", "browser", "cero", "curl", "dalfox", "dnsx", "ffuf",
        "httpx", "katana", "naabu", "nikto", "nmap", "nuclei", "puredns",
        "sqlmap", "subfinder", "tlsx", "wafw00f", "whatweb", "wget",
    }
)

# Executables that cannot put a request on the wire — they read, write, filter or
# print text. The request classifier skips their argv so writing or grepping a
# URL does not get labelled as a target-facing command.
#
# Deliberately small and literal. It is a skip-list, not an allowlist, so an
# unknown or future HTTP tool carrying a URL is still classified as
# target-facing. Launchers (env/sudo/timeout/…) are not here: they are unwrapped
# to their child by :func:`_unwrap_launcher_argv`.
_NON_REQUESTING_HEADS = frozenset(
    {
        "echo", "printf", "cat", "tee", "grep", "egrep", "fgrep", "rg", "sed",
        "awk", "cut", "sort", "uniq", "wc", "head", "tail", "tr", "jq", "yq",
        "comm", "paste", "rev", "basename", "dirname", "true", "false",
    }
)

# Option flags whose value is something other than a URL the command requests —
# headers, output paths, wordlists, request bodies, credentials. Keeping those
# values out of the request classifier avoids reserving aggregate target-rate
# capacity for an inert URL in a header or body.
_NON_REQUEST_VALUE_FLAGS = frozenset(
    {
        "-H", "-header", "--header", "-o", "--output", "-t", "-tags",
        "-exclude-tags", "-etags", "-w", "--wordlist", "-A", "--user-agent",
        "--resolve",
    }
)

# Per-tool additions to the above. Kept tool-scoped because the same short flag
# means different things to different tools: ``-u`` is credentials to curl but
# the target URL to nuclei/httpx/ffuf/sqlmap.
_TOOL_NON_REQUEST_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "curl": frozenset(
        {
            "-X", "--request", "-d", "--data", "--data-raw", "--data-binary",
            "--data-urlencode", "-F", "--form", "-u", "--user", "-b",
            "--cookie", "--cert", "--key",
        }
    ),
    "wget": frozenset(
        {
            "--post-data", "--post-file", "--body-data", "--body-file",
            "--method", "--user", "--password",
        }
    ),
}


class ScopePolicyError(RuntimeError):
    """Raised before execution when engagement tool policy rejects a run."""


def execution_policy_notes(policy: dict[str, Any]) -> str:
    """Serialize an audit-safe summary below the command-run 4096-byte limit."""
    summarized = dict(policy)
    refusal = str(summarized.get("policy_refusal") or "")
    if len(refusal) > 1024:
        summarized["policy_refusal"] = refusal[:1024]
        summarized["policy_refusal_sha256"] = hashlib.sha256(refusal.encode()).hexdigest()
    return json.dumps(summarized, ensure_ascii=True, separators=(",", ":"))


def _is_dns_label(token: str) -> bool:
    """True when ``token`` is a syntactically valid single DNS label.

    Single-label hosts (``intranet``, ``api``) are legitimate scope entries on
    internal engagements but fail ``looks_like_host`` (which requires a dot).
    They are admitted only on the explicitly-authored scope path, never from
    free-text token parsing, so log noise can't silently widen scope.
    """
    return _canonical_is_dns_label(token)


def _parse_cidr(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the IP network for a CIDR token (``10.0.0.0/24``) or None.

    A bare CIDR has no scheme and no ``*.`` prefix, so it would otherwise fall
    through to host parsing where ``urlsplit`` drops the ``/24`` and silently
    collapses a whole subnet to a single host (lost coverage = missed bugs).
    Parsing it as a network instead lets ``entry_matches_host`` admit every
    address in range.
    """
    return _canonical_parse_cidr(token)


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
    return _canonical_to_a_label(host)


def _normalize_host_for_match(host: str) -> str:
    """Return a normalized host suitable for scope matching (lowercase, no trailing dot, A-label)."""
    return _canonical_normalize_host_for_match(host)


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


def _read_scope_file(scope_path: Path, engagement_dir: str) -> dict[str, Any]:
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"scope.json is not valid JSON in {engagement_dir}") from exc
    if not isinstance(scope, dict):
        raise SystemExit(f"scope.json is not a JSON object in {engagement_dir}")
    return scope


@contextmanager
def _scope_lock(scope_path: Path) -> Iterator[None]:
    """Serialize every in-repository scope.json read-modify-write operation."""
    lock_path = scope_path.parent / ".locks" / "scope-json.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _write_scope_file(scope_path: Path, scope: dict[str, Any]) -> None:
    """Replace scope.json from a unique same-directory temporary file."""
    mode = stat.S_IMODE(scope_path.stat().st_mode) if scope_path.exists() else 0o600
    fd, tmp_name = tempfile.mkstemp(
        prefix=".scope.",
        suffix=".tmp",
        dir=scope_path.parent,
    )
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(json.dumps(scope, indent=2, sort_keys=True) + "\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, scope_path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp_path.unlink(missing_ok=True)
        raise


def load_scope(engagement_dir: str, *, persist_migration: bool = True) -> dict[str, Any]:
    """Load and return scope.json from the engagement directory.

    Normalizing the payload can rewrite the file (migrating the legacy
    ``approved_findings`` key, or materializing an absent ``approved_targets``),
    which also re-serializes it with sorted keys. Callers that only READ scope —
    exporters especially — pass ``persist_migration=False`` so merely rendering a
    report never reformats engagement state on disk. The in-memory normalization
    still happens either way, so every caller sees the same shape.
    """
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        raise SystemExit(f"scope.json not found in {engagement_dir}")
    scope = _read_scope_file(scope_path, engagement_dir)
    scope, changed = normalize_scope_payload(scope)
    if changed and persist_migration:
        # The initial read happened without a lock. Re-read after acquiring the
        # shared writer lock so migration cannot overwrite a concurrent update.
        with _scope_lock(scope_path):
            scope = _read_scope_file(scope_path, engagement_dir)
            scope, changed = normalize_scope_payload(scope)
            if changed:
                _write_scope_file(scope_path, scope)
    return scope


def mutate_scope(
    engagement_dir: str,
    mutator: Callable[[dict[str, Any]], object],
) -> dict[str, Any]:
    """Apply an in-place scope mutation without losing concurrent updates."""
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        raise SystemExit(f"scope.json not found in {engagement_dir}")
    with _scope_lock(scope_path):
        scope = _read_scope_file(scope_path, engagement_dir)
        scope, _ = normalize_scope_payload(scope)
        before = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        mutator(scope)
        scope, _ = normalize_scope_payload(scope)
        scope.pop("approved_findings", None)
        after = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        if after != before:
            _write_scope_file(scope_path, scope)
    return scope


def record_discovered_hosts(engagement_dir: str, candidates: list[str]) -> None:
    """Merge confirmed strict wildcard children into derived scope inventory."""

    def merge(scope: dict[str, Any]) -> None:
        allow_entries = scope_entries(scope)
        deny_entries = out_of_scope_entries(scope)
        wildcard_entries = [
            entry for entry in allow_entries if entry["entry_kind"] == "wildcard"
        ]

        def inventory_host(raw: object) -> str:
            if not isinstance(raw, str):
                return ""
            host = host_from_token(raw)
            if not host or not host_admitted(host, allow_entries, deny_entries):
                return ""
            if not any(host.endswith("." + entry["host"]) for entry in wildcard_entries):
                return ""
            return host

        existing = scope.get("discovered_hosts")
        existing_values = existing if isinstance(existing, list) else []
        discovered = sorted(
            host
            for host in {
                inventory_host(raw) for raw in [*existing_values, *candidates]
            }
            if host
        )
        if discovered or "discovered_hosts" in scope:
            scope["discovered_hosts"] = discovered

    mutate_scope(engagement_dir, merge)


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
    """Return the engagement-wide host-shaping mode.

    This governs the surfaces that SHAPE a discovered host set rather than
    refuse an operator's command: the recon pipeline's filter over enumerated
    hosts, the standalone-ingest gate, and the shared proxy's decision about
    which engagement owns a captured flow. ``bypass`` says "do not drop hosts
    that scope.json does not list" — useful when the declared estate is broader
    than the file. It grants NOTHING at execution time; ``vigil assess kali``
    does not filter by destination at all.

    Shaping is the default for new and legacy engagements. The only value that
    turns it off is the exact, durable ``scope_enforcement: \"bypass\"`` setting
    in ``scope.json``; unknown values deliberately fall back to shaping so a
    typo cannot silently widen an enumerated host set.
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


def host_from_token(raw: str, *, allow_single_label: bool = False) -> str:
    """Extract a lowercased host from a URL, host:port, or line token.

    ``allow_single_label`` admits bare single-label hosts (``intranet``). It is
    set for structured target admission; free-text token parsing leaves it False
    so log lines can't widen scope with stray words.
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
    return _canonical_normalize_host(raw, allow_single_label=allow_single_label)


def _ip_literal(host: str) -> str:
    return _canonical_ip_literal(host)


def looks_like_host(host: str, *, allow_single_label: bool = False) -> bool:
    return bool(_canonical_normalize_host(host, allow_single_label=allow_single_label))


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
    """Return True IFF ``host`` matches ``hosts`` AND no ``out_of_scope`` entry.

    The denylist wins: a host covered by an in-scope wildcard but matching an
    ``out_of_scope`` carve-out is not declared. This is the single matching
    primitive every scope-reading surface must call, so recon shaping, coverage
    accounting, and the read-only ``scope explain`` oracle all answer the same
    question the same way. It is a predicate over what ``scope.json`` declares —
    it does not gate execution.
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
    host = host_from_token(token, allow_single_label=True)
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
    """Return the declared-scope verdict for one host/URL/CIDR token.

    Used by the surfaces that SHAPE a host set — :func:`filter_recon_targets`
    and the dns-discovery parent selector — never to gate an operator's command.
    Matching stays single-sourced in :func:`explain_target`; this layer adds the
    CIDR-token case (a ``10.0.0.0/24`` argument is a network, not a host) and
    applies the engagement-wide ``scope_enforcement`` mode, making that choice
    explicit in the verdict.
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


_LAUNCHERS = frozenset(
    {
        "command", "env", "exec", "nice", "nohup", "setsid", "stdbuf",
        "sudo", "time", "timeout", "xargs",
    }
)


def _expand_env_split_argv(argv: list[str]) -> tuple[list[str], bool]:
    """Expand GNU ``env -S/--split-string`` into the argv it launches.

    ``env -S`` is itself a command-line parser: its value is split and inserted
    back into env's argument stream. Treating that value as ordinary option
    data hides the real executable from the denied-tool boundary. We accept the
    shell-like quoting supported by the ordinary cases and mark GNU-specific
    expansion syntax ambiguous so a configured denylist can fail closed.
    """
    current = [str(value) for value in argv]
    ambiguous = False
    for _ in range(16):
        index = 1
        split_index: int | None = None
        split_value = ""
        consumed = 1
        while index < len(current):
            token = current[index]
            if token == "--":
                break
            if "=" in token and token.split("=", 1)[0].isidentifier():
                index += 1
                continue
            if token in {"-S", "--split-string"}:
                if index + 1 >= len(current):
                    return current, True
                split_index = index
                split_value = current[index + 1]
                consumed = 2
                break
            if token.startswith("--split-string="):
                split_index = index
                split_value = token.split("=", 1)[1]
                break
            if token.startswith("-S") and len(token) > 2:
                split_index = index
                split_value = token[2:]
                break
            if token in {"-C", "--chdir", "-u", "--unset"}:
                if index + 1 >= len(current):
                    return current, True
                index += 2
                continue
            if any(
                token.startswith(option + "=")
                for option in {"--chdir", "--unset"}
            ) or (len(token) > 2 and token[:2] in {"-C", "-u"}):
                index += 1
                continue
            if token in {"-0", "--null", "-i", "--ignore-environment"}:
                index += 1
                continue
            break
        if split_index is None:
            return current, ambiguous
        if any(character in split_value for character in ("$", "\\", "#")):
            ambiguous = True
        try:
            expanded = shlex.split(split_value, posix=True)
        except ValueError:
            return current, True
        current = [
            *current[:split_index],
            *expanded,
            *current[split_index + consumed :],
        ]
    return current, True


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


def _launcher_child_argv(
    argv: list[str], launcher: str
) -> tuple[list[str] | None, bool]:
    """Return the effective child argv behind one transparent launcher."""
    effective = [str(value) for value in argv]
    ambiguous = False
    if launcher == "env":
        effective, ambiguous = _expand_env_split_argv(effective)
    inner_index, parse_ambiguous = _launcher_inner_index(effective, launcher)
    if inner_index is None:
        return None, ambiguous or parse_ambiguous
    return effective[inner_index:], ambiguous or parse_ambiguous


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
        child_argv, ambiguous = _launcher_child_argv(command, head)
        if child_argv is None:
            return tools, ambiguous
        nested_tools, nested_ambiguous = _argv_tool_analysis(
            child_argv, depth=depth + 1
        )
        tools.update(nested_tools)
        return tools, ambiguous or nested_ambiguous
    return tools, False


def execution_script_path(
    raw_path: str | Path,
    engagement_dir: str | Path,
    *,
    execution_cwd: str | Path | None = None,
    container_paths: bool = True,
) -> Path | None:
    """Resolve a script only when its executed file is engagement-owned.

    Kali paths use ``/engagements/<key>/...`` while host execution may select a
    different working directory. The classifier must inspect the same file the
    process would execute. Explicit foreign-engagement paths and container-path
    escapes are refused as a cross-engagement evidence boundary; unrelated
    outside paths are merely uninspectable and do not become an HTTP veto.
    """
    root = Path(engagement_dir).expanduser().resolve()
    raw = Path(raw_path)
    if raw.is_absolute() and len(raw.parts) >= 2 and raw.parts[1] == "engagements":
        if not container_paths:
            raise ScopePolicyError(
                f"container-namespace script path '{raw}' cannot be executed by "
                "host-exec; use the host path selected by --cwd"
            )
        if len(raw.parts) < 4:
            return None
        if raw.parts[2] != root.name:
            raise ScopePolicyError(
                f"container script path engagement '{raw.parts[2]}' does not match "
                f"current engagement '{root.name}'"
            )
        candidate = root.joinpath(*raw.parts[3:]).resolve()
        if not candidate.is_relative_to(root):
            raise ScopePolicyError(
                f"container script path '{raw}' escapes current engagement "
                f"'{root.name}'"
            )
    elif raw.is_absolute():
        candidate = raw.expanduser().resolve()
    else:
        base = (
            Path(execution_cwd).expanduser().resolve()
            if execution_cwd is not None
            else root
        )
        candidate = (base / raw).resolve()
    if not candidate.is_relative_to(root):
        try:
            sibling_name = candidate.relative_to(root.parent).parts[0]
        except (IndexError, ValueError):
            sibling_name = ""
        sibling = root.parent / sibling_name if sibling_name else None
        if (
            sibling is not None
            and sibling != root
            and (sibling / "scope.json").is_file()
        ):
            raise ScopePolicyError(
                f"script path '{raw}' resolves into engagement '{sibling_name}', "
                f"not current engagement '{root.name}'"
            )
        return None
    try:
        is_file = candidate.is_file()
    except OSError:
        # A classifier mistake must never turn arbitrary program text into an
        # unbounded filesystem operation (for example Node ``-e`` source long
        # enough to exceed NAME_MAX). Unknown/unusable paths are simply not
        # inspectable; explicit engagement-boundary violations were handled
        # above before this stat.
        return None
    if not is_file:
        return None
    return candidate


_SCRIPT_FILE_EXECUTORS = _SHELL_BINARIES | {
    "node", "nodejs", "perl", "php", "python", "python3", "ruby",
}
_INTERPRETER_INLINE_SOURCE_FLAGS: dict[str, frozenset[str]] = {
    "bash": frozenset({"-c"}),
    "dash": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "perl": frozenset({"-e", "-E"}),
    "php": frozenset({"-r", "--run"}),
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "ruby": frozenset({"-e"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
}

# Options whose following word configures the interpreter rather than naming
# the executed file. This is the one argv-shape table shared by evidence-path
# isolation and required-header inspection. Unknown options make the result
# unknown instead of guessing that their value is a script path.
_INTERPRETER_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "bash": frozenset({"-O", "+O", "-o", "+o", "--init-file", "--rcfile"}),
    "dash": frozenset({"-o", "+o"}),
    "node": frozenset(
        {
            "-C", "--conditions", "--diagnostic-dir", "--env-file",
            "--env-file-if-exists", "--experimental-loader",
            "--experimental-sea-config", "--icu-data-dir", "--import",
            "--inspect-port", "--loader", "--openssl-config",
            "--redirect-warnings", "-r", "--require", "--title",
        }
    ),
    "nodejs": frozenset(
        {
            "-C", "--conditions", "--diagnostic-dir", "--env-file",
            "--env-file-if-exists", "--experimental-loader",
            "--experimental-sea-config", "--icu-data-dir", "--import",
            "--inspect-port", "--loader", "--openssl-config",
            "--redirect-warnings", "-r", "--require", "--title",
        }
    ),
    "perl": frozenset({"-F", "-I", "-M", "-m"}),
    "php": frozenset(
        {
            "-c", "--php-ini", "-d", "--define", "-S", "--server",
            "-t", "--docroot", "-z", "--zend-extension",
        }
    ),
    "python": frozenset({"-W", "-X", "--check-hash-based-pycs"}),
    "python3": frozenset({"-W", "-X", "--check-hash-based-pycs"}),
    "ruby": frozenset(
        {
            "-C", "-E", "-F", "-I", "-K", "-r", "--encoding",
            "--external-encoding", "--internal-encoding",
        }
    ),
    "sh": frozenset({"-o", "+o"}),
    "zsh": frozenset({"-o", "+o"}),
}

_INTERPRETER_MODE_OPTIONS: dict[str, frozenset[str]] = {
    "python": frozenset({"-m"}),
    "python3": frozenset({"-m"}),
    "ruby": frozenset({"-S"}),
}

_INTERPRETER_FILE_OPTIONS: dict[str, frozenset[str]] = {
    "php": frozenset({"-f", "--file"}),
}

_INTERPRETER_FLAG_OPTIONS: dict[str, frozenset[str]] = {
    "bash": frozenset(
        {
            "--debugger", "--help", "--login", "--noediting", "--noprofile",
            "--norc", "--posix", "--pretty-print", "--restricted", "--verbose",
            "--version",
        }
    ),
    "dash": frozenset(),
    "node": frozenset(),
    "nodejs": frozenset(),
    "perl": frozenset(),
    "php": frozenset({"-n", "--no-php-ini", "-q", "--no-header"}),
    "python": frozenset(),
    "python3": frozenset(),
    "ruby": frozenset(),
    "sh": frozenset(),
    "zsh": frozenset(),
}


def _option_has_attached_value(token: str, options: frozenset[str]) -> bool:
    for option in options:
        if option.startswith("--") and token.startswith(option + "="):
            return True
        if option.startswith("-") and not option.startswith("--"):
            if token.startswith(option) and len(token) > len(option):
                return True
    return False


def execution_script_argv(argv: list[str]) -> str:
    """Return the selected script-file argument for a known interpreter.

    The result is positive-only. Inline source, module modes, stdin, a missing
    option value, or an option whose arity is not in the shared table returns
    ``""`` rather than treating source/config text as a path. That keeps both
    cross-engagement evidence isolation and required-header inspection on the
    exact same conservative argv interpretation.
    """
    effective = _unwrap_launcher_argv(argv)
    if not effective:
        return ""
    head = Path(str(effective[0])).name.lower()
    if head not in _SCRIPT_FILE_EXECUTORS:
        return ""

    inline_flags = _INTERPRETER_INLINE_SOURCE_FLAGS[head]
    value_options = _INTERPRETER_VALUE_OPTIONS[head]
    mode_options = _INTERPRETER_MODE_OPTIONS.get(head, frozenset())
    file_options = _INTERPRETER_FILE_OPTIONS.get(head, frozenset())
    flag_options = _INTERPRETER_FLAG_OPTIONS[head]
    index = 1
    while index < len(effective):
        token = str(effective[index])
        if token == "--":
            return str(effective[index + 1]) if index + 1 < len(effective) else ""
        if token == "-":
            return ""
        if token in inline_flags or _option_has_attached_value(token, inline_flags):
            return ""
        if token in mode_options or _option_has_attached_value(token, mode_options):
            return ""
        if token in file_options:
            return str(effective[index + 1]) if index + 1 < len(effective) else ""
        if any(
            token.startswith(option + "=")
            for option in file_options
            if option.startswith("--")
        ):
            return token.split("=", 1)[1]
        if token in value_options:
            if index + 1 >= len(effective):
                return ""
            index += 2
            continue
        if _option_has_attached_value(token, value_options):
            index += 1
            continue
        if token in flag_options:
            index += 1
            continue
        if head in _SHELL_BINARIES and token.startswith(("-", "+")):
            # POSIX shell single-letter flags may be clustered. Any cluster
            # containing ``c`` is inline source; the rest consume no argv word.
            if not token.startswith("--") and "c" in token[1:]:
                return ""
            if not token.startswith("--"):
                index += 1
                continue
        if token.startswith("-"):
            return ""
        return token
    return ""


def _script_execution_tools(
    argv: list[str],
    engagement_dir: Path,
    *,
    execution_cwd: Path | None = None,
    container_paths: bool = True,
) -> set[str]:
    """Find denied tool names in a readable engagement-owned shell script."""
    effective = _unwrap_launcher_argv(argv)
    if not effective:
        return set()
    head = Path(str(effective[0])).name.lower()
    if head not in _SHELL_BINARIES:
        return set()
    script = execution_script_argv(argv)
    if not script:
        return set()
    path = execution_script_path(
        script,
        engagement_dir,
        execution_cwd=execution_cwd,
        container_paths=container_paths,
    )
    if path is None:
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    tools, _ambiguous = _shell_tool_analysis(text)
    return tools


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
        child_argv, ambiguous = _launcher_child_argv(current, head)
        if ambiguous or child_argv is None:
            return current
        current = child_argv
    return current


_SHELL_VARIABLE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)


def _expand_shell_token(token: str, assignments: dict[str, str]) -> str:
    """Substitute known ``NAME=value`` assignments into one shell word."""

    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("plain") or ""
        return assignments.get(name, match.group(0))

    return _SHELL_VARIABLE.sub(replace, token)


def _shell_request_urls(script: str, *, depth: int) -> list[str]:
    """Collect requested URLs from a ``sh -c`` script body.

    Leading ``NAME=value`` assignments are tracked and substituted so a URL
    assembled from shell variables still marks the run target-facing. An unset
    variable stays literal and simply fails URL classification.

    Comment text is dropped. :func:`_shell_command_segments` deliberately keeps
    ``#`` inert (so a commented-out executable is still visible to the TOOL
    denylist, which must over-count), but a URL written in a comment is not a
    URL the command requests.
    """
    segments, _ = _shell_command_segments(script)
    assignments: dict[str, str] = {}
    urls: list[str] = []
    for segment in segments:
        expanded: list[str] = []
        for word in segment:
            if word.startswith("#"):
                # Comment word (checked pre-expansion: a variable that expands
                # to `#...` is an argument to the shell, not a comment).
                break
            value = _expand_shell_token(word, assignments)
            if not expanded and "=" in value and value.split("=", 1)[0].isidentifier():
                # Shell assignment prefix (`FOO=bar cmd ...`) — record, don't run.
                name, _, assigned = value.partition("=")
                assignments[name] = assigned
                continue
            expanded.append(value)
        if expanded:
            urls.extend(_request_urls(expanded, depth=depth + 1))
    return urls


def _request_urls(cmd: list[str], *, depth: int = 0) -> list[str]:
    """Return the http(s) URLs this command asks for.

    Purely lexical and deliberately shallow: every argv word — plus the words
    inside a ``sh -c`` script body and an attached ``--flag=<url>`` value — that
    is an http(s) URL, minus the values of flags that carry something other than
    a requested URL (:data:`_NON_REQUEST_VALUE_FLAGS`) and minus commands that
    cannot request anything (:data:`_NON_REQUESTING_HEADS`).

    Nothing here decides whether a destination is authorized. Its only consumer
    is target-facing command classification.
    """
    if depth > 8:
        return []
    words = _unwrap_launcher_argv([str(token) for token in cmd])
    head = Path(words[0]).name.lower() if words else ""
    if head in _NON_REQUESTING_HEADS:
        return []
    is_shell = head in _SHELL_BINARIES
    skip_flags = _NON_REQUEST_VALUE_FLAGS | _TOOL_NON_REQUEST_VALUE_FLAGS.get(
        head, frozenset()
    )
    urls: list[str] = []
    previous = ""
    for word in words:
        if previous in skip_flags:
            previous = word
            continue
        if word.startswith(("http://", "https://")):
            urls.append(word)
        elif word.startswith("-") and "=" in word:
            flag, _, attached = word.partition("=")
            if flag not in skip_flags and attached.startswith(
                ("http://", "https://")
            ):
                urls.append(attached)
        elif is_shell and previous.startswith("-") and previous.endswith("c"):
            urls.extend(_shell_request_urls(word, depth=depth))
        previous = word
    return urls


def enforce_execution_policy(
    cmd: list[str],
    *,
    tool_name: str,
    engagement_dir: str | Path,
    execution_cwd: str | Path | None = None,
    container_paths: bool = True,
    require_declared_tool: bool = False,
    target_host: str = "",
    execution_phase: str = "",
) -> dict[str, Any]:
    """Apply engagement-wide tool policy before any process starts.

    There is deliberately NO destination filtering here: this function never
    refuses a command for the host it names. Which hosts the engagement is
    authorized against is declared in ``scope.json`` ``hosts``, and staying
    inside that declaration is the operator's and the specialist's
    responsibility — it is not a decision that can be made by reading hostnames
    out of an argv, where a hand-rolled ``curl`` or ``python3 -c`` reaches
    exactly as far as ``nmap`` and neither is distinguishable from a benign
    fetch.

    What is enforced is the engagement policy that does not require guessing a
    destination: the ``denied_tools`` list, the declared-vs-actual tool check,
    and a non-empty canonical host set for target-facing web work.
    ``off_limits_paths`` is operator guidance, never an execution veto.

    The return value is audit-ready. ``target_facing`` is a positive static
    signal for the caller's cross-lane rate advisory and the non-empty-host
    gate — true when a declared/directly observed tool or argv URL is
    recognizable as target-facing. In a CODE-only engagement, a positively
    identified declared target emits an advisory and is returned as
    ``code_target_warning``; it never refuses the command. Readable program text is not promoted into
    this gate: static syntax does not establish that code executes. False means
    "not recognized", not proof of no network activity; dynamic code, custom
    clients, raw sockets, and native binaries require a runtime isolation
    boundary rather than another lexical rule.
    """
    eng_dir = Path(engagement_dir).expanduser().resolve()
    try:
        scope_doc = load_scope(str(eng_dir))
    except (OSError, json.JSONDecodeError, SystemExit) as exc:
        raise ScopePolicyError(f"cannot load scope policy before execution: {exc}") from exc

    normalized_tool = Path(str(tool_name or (cmd[0] if cmd else ""))).name.strip().lower()
    observed_tools, argv_ambiguous = _argv_tool_analysis([str(token) for token in cmd])
    positive_tools = set(observed_tools)
    positive_tools.add(normalized_tool)
    script_argv = execution_script_argv([str(token) for token in cmd])
    if script_argv:
        execution_script_path(
            script_argv,
            eng_dir,
            execution_cwd=execution_cwd,
            container_paths=container_paths,
        )
    script_tools = _script_execution_tools(
        [str(token) for token in cmd],
        eng_dir,
        execution_cwd=(
            Path(execution_cwd).expanduser().resolve()
            if execution_cwd is not None
            else None
        ),
        container_paths=container_paths,
    )
    observed_tools.update(script_tools)
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
    if denied and argv_ambiguous:
        raise ScopePolicyError(
            "command shape cannot be inspected reliably against engagement "
            "scope policy denied_tools"
        )

    request_urls = _request_urls([str(token) for token in cmd])

    # ``policy_tools`` — not ``observed_tools`` — so a caller that DECLARES a
    # target-facing tool whose argv hides it (``kali browser``, whose argv is
    # ``python3 -c <driver> <json-plan>``) still receives the cross-lane
    # advisory. The declared name is supplied by the caller, not guessed from
    # argv.
    target_facing = bool(positive_tools & _TARGET_FACING_TOOLS) or bool(request_urls)
    phases = track_phases(scope_doc)
    legacy_both = scope_doc.get("engagement_type") == "both" and "tracks" not in scope_doc
    code_only = "code" in phases and "web" not in phases
    declared_hosts: list[dict[str, str]] = []
    if target_facing:
        try:
            declared_hosts = scope_entries(scope_doc)
        except SystemExit as exc:
            raise ScopePolicyError(str(exc)) from exc
        if not declared_hosts and not code_only:
            recovery = f"Run `vigil engagement add-host {eng_dir.name} <host>`"
            raise ScopePolicyError(
                "target-facing execution requires a non-empty, valid scope.json "
                f"`hosts` list. {recovery} before retrying; execution cannot create "
                "or infer authorization from its argv."
            )
        _require_program_brief_resolution(eng_dir)

    result: dict[str, Any] = {"target_facing": target_facing}
    code_lane = code_only or (
        ("code" in phases or legacy_both)
        and str(execution_phase or "").strip().lower().startswith("code-")
    )
    if code_lane and declared_hosts:
        deny_entries = out_of_scope_entries(scope_doc)
        candidates = [str(target_host or "").strip(), *request_urls]
        for candidate in candidates:
            host = host_from_token(candidate, allow_single_label=True)
            if not host or not host_admitted(host, declared_hosts, deny_entries):
                continue
            result["code_target_warning"] = host
            print(
                "WARNING: CODE engagement command appears to contact declared "
                f"target '{host}'. CODE workflow is for source analysis; use "
                "research-only network access, an explicitly approved web proof-work "
                "route, or an explicitly enabled web track for live target work. "
                "This is advisory; execution is continuing.",
                file=sys.stderr,
            )
            break
    return result


def _program_brief_decisions(eng_dir: Path) -> list[dict[str, Any]]:
    from assess.lib.client import AssessmentClient, AssessError
    from assess.lib.config import load_config

    try:
        cfg = load_config(str(eng_dir))
        client = AssessmentClient(cfg.base_url, eng_dir.name)
        try:
            return client.list_all_decisions(kind="program_brief")
        finally:
            client.close()
    except (AssessError, OSError, SystemExit) as exc:
        raise ScopePolicyError(
            f"ENGAGEMENT.md is a STUB and its operator decision cannot be checked: {exc}"
        ) from exc


def _require_program_brief_resolution(eng_dir: Path) -> None:
    """A generated brief is a placeholder, not an operator ROE decision."""
    brief_path = eng_dir / "ENGAGEMENT.md"
    try:
        brief = brief_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return  # Legacy engagement without the generated stub.
    except OSError as exc:
        raise ScopePolicyError(f"cannot read engagement program brief: {exc}") from exc
    if not re.search(r"^> \*\*STUB\b", brief, flags=re.MULTILINE):
        return

    decisions = _program_brief_decisions(eng_dir)
    if any(
        isinstance(row, dict)
        and isinstance(row.get("payload"), dict)
        and row["payload"].get("choice") == "no_separate_program_brief"
        and str(row["payload"].get("reason") or "").strip()
        for row in decisions
    ):
        return
    raise ScopePolicyError(
        "ENGAGEMENT.md is a STUB. Fill it with the actual program ROE before "
        "target traffic, or record the operator's no-separate-brief declaration "
        "once with `vigil assess agent decision --kind program_brief "
        "--choice no_separate_program_brief --reason '<operator instruction>'`."
    )


def filter_recon_targets(
    scope_doc: dict[str, Any], targets: list[str]
) -> tuple[list[str], dict[str, Any]]:
    """Shape a recon-discovered host set down to what ``scope.json`` declares.

    This filters an ENUMERATED list before it is probed or ingested — wildcard
    expansion routinely surfaces hosts the program carved out. It is not a gate
    on anything the operator asked for by name.
    """
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

    A valid, non-empty ``scope.json`` is required. ``active`` is False only when
    the engagement explicitly enables the global scope bypass; a missing,
    malformed, unreadable, or empty scope must stop ingestion rather than turn a
    broken authorization boundary into permission to admit every host.

    The single resolver shared by ``ingest-endpoints`` / ``ingest-candidates``
    (per-URL via :func:`host_admitted`) and ``ingest-spec`` (per-base-host), so
    every ingest path applies identical admission semantics.
    """
    try:
        scope = load_scope(engagement_dir)
        allow = scope_entries(scope)
        deny = out_of_scope_entries(scope)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — normalize unexpected load failures for the CLI
        raise SystemExit(f"could not load scope.json in {engagement_dir}: {exc}") from exc

    enforcement = scope_enforcement(scope)
    if enforcement != "bypass" and not allow:
        raise SystemExit("scope.json must declare at least one host unless scope enforcement is bypassed")
    return allow, deny, enforcement != "bypass"
