"""mitmproxy addon — intercepts HTTP traffic and routes each flow to the
matching engagement's scope, credential store, and orchestrator backend.

Managed launch:
    vigil mitmproxy start

The CLI runs this addon inside the vigil-proxy Docker container.
The container bind-mounts the install's ``agent/engagements`` directory at
``/engagements`` so every active engagement is visible to the addon at once,
and the addon picks the matching engagement per request from a registry kept
in sync with the orchestrator (filesystem scan as fallback).
"""

import calendar
import email.utils
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from assess.lib.classify import classify_type
from assess.lib.classify_buckets import (
    CLASSIFIER_VERSION,
    INERT_TYPES,
    classify_from_fields,
)
from assess.lib.params import header_schema_from_headers
from assess.lib.scope import required_headers as _scope_required_headers
from assess.lib.scope import scope_enforcement as _scope_enforcement
from mitmproxy import ctx, http

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOISE_DOMAINS = {
    "google-analytics.com",
    "www.google-analytics.com",
    "googletagmanager.com",
    "www.googletagmanager.com",
    "facebook.net",
    "connect.facebook.net",
    "doubleclick.net",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "ajax.googleapis.com",
}

NOISE_PATH_RE = re.compile(r"(\.gif\?|pixel|beacon)", re.IGNORECASE)

BODY_TRUNCATE = 100 * 1024  # 100 KB — request body cap
RESPONSE_SNIPPET_BYTES = 16 * 1024  # 16 KB — response preview cap. Matches
# `INDEXED_TEXT_BYTES` for assessment_artifacts so an engagement can grep
# both data sources at the same depth. The cap exists so the work-item snapshot
# stays small; truncation is surfaced explicitly via `response_truncated`.

BINARY_PREFIXES = ("image/", "video/", "audio/", "font/")

LOGIN_URL_RE = re.compile(r"(login|auth|signin|session|token)", re.IGNORECASE)

# Any key that looks like it holds a token — used to accumulate the ``tokens``
# delta (refresh_token / csrf_token / access_token / …). Storing these is safe;
# they are NOT, on their own, promoted to an ``Authorization: Bearer`` header.
TOKEN_KEYS_RE = re.compile(r"(token|jwt)", re.IGNORECASE)
# EXACT keys (case-insensitive) whose value may be synthesized into an
# ``Authorization: Bearer`` header, in priority order. Deliberately excludes the
# bare ``token`` substring so ``refresh_token`` / ``csrf_token`` / ``token_type``
# never seed the wrong bearer (which previously produced ``Bearer Bearer`` or a
# refresh/csrf value in Authorization).
BEARER_TOKEN_PRIORITY = ("access_token", "id_token", "jwt")
# Token values that are actually type labels, never a credential to bear.
_NON_BEARER_VALUES = frozenset({"bearer", "basic"})

# Traffic-store (Phase 5 full-flow capture) layout, engagement-root-relative.
TRAFFIC_BODIES_DIR = "traffic/mitmproxy/bodies"
TRAFFIC_FLOWS_DIR = "traffic/mitmproxy/flows"

# Dynamic path-segment patterns
_DYNAMIC_RE = re.compile(
    r"(?:^[0-9]+$"  # numeric ID
    r"|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"  # UUID
    r"|^[0-9a-f]{24,}$)",  # hex 24+ chars (e.g. MongoDB ObjectId)
    re.IGNORECASE,
)

DEFAULT_REGISTRY_POLL_SECONDS = 30
RELOAD_SENTINEL = ".mitmproxy-reload-requested"
ROUTES_CACHE = ".mitmproxy-routes.json"
DELETED_ENGAGEMENTS_DIR = ".deleted-engagements"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dequote_cookie_value(value: str) -> str:
    """Strip a single pair of surrounding DQUOTEs from a cookie value.

    RFC 6265 permits a quoted cookie-value (``name="value"``). A logout that
    sends ``MRHSession=""`` must be recognized as a deletion (its unquoted value
    is empty), and a live quoted value must be STORED unquoted so downstream
    injection doesn't double-quote it. Only a matched leading+trailing pair is
    removed; an unbalanced quote is left untouched.
    """
    v = (value or "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _is_deletion_set_cookie(sc: str) -> bool:
    """Return True if a Set-Cookie directive is a cookie deletion / logout signal.

    Detects RFC 6265 deletion patterns and the F5/APM (CMS portal) convention:

    * value is the literal string ``deleted`` (case-insensitive) — F5/APM sends
      ``Set-Cookie: MRHSession=deleted; ...`` on logout.
    * value is empty — ``Set-Cookie: MRHSession=; ...``
    * ``Max-Age=0`` (or negative) — RFC 6265 §5.3 step 3 expiry trigger.
    * ``Expires`` attribute with a date in the past — legacy deletion method.

    Returning True causes the caller to skip the cookie entirely rather than
    overwriting a stored live session value with a deletion sentinel.
    """
    parts = [p.strip() for p in sc.split(";")]
    if not parts:
        return False
    name_val = parts[0]
    if "=" not in name_val:
        return False
    _, v = name_val.split("=", 1)
    # Dequote before evaluating: a quoted-empty logout cookie (MRHSession="")
    # is a deletion sentinel whose surrounding quotes would otherwise mask the
    # empty value and let the logout overwrite a live session.
    v = _dequote_cookie_value(v)
    # Empty value or literal "deleted" — skip immediately.
    if not v or v.lower() == "deleted":
        return True
    # Scan directives for Max-Age / Expires deletion markers.
    now = time.time()
    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower.startswith("max-age="):
            try:
                age = int(attr[len("max-age="):].strip())
                if age <= 0:
                    return True
            except ValueError:
                pass
        elif attr_lower.startswith("expires="):
            exp_str = attr[len("expires="):].strip()
            try:
                parsed = email.utils.parsedate(exp_str)
                if parsed and calendar.timegm(parsed) < now:
                    return True
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# Engagement registry
# ---------------------------------------------------------------------------


@dataclass
class EngagementEntry:
    """Per-engagement state the addon needs to route a single flow.

    The addon keeps one ``EngagementEntry`` per active engagement and normally
    looks one up by hostname on every captured response. An otherwise-unclaimed
    host may bind to the active global-bypass engagement. The captured work item rides
    in the request-observation POST (the backend derives the
    ``assessment_work_items`` row server-side), so the entry holds no local
    SQLite handle.
    """

    key: str
    root: Path
    scope_patterns: list[str]
    out_of_scope_patterns: list[str] = field(default_factory=list)
    scope_enforcement: str = "enforce"
    scope_priority: int = 0
    updated_at: str = ""
    capture_policy: dict = field(default_factory=dict)
    # Program-mandated attribution headers (e.g. BugCrowd ``X-Bug-Bounty``) the
    # ``request`` hook injects onto this engagement's outbound in-scope requests.
    required_headers: dict = field(default_factory=dict)


def _normalize_scope_entry(raw: str) -> str:
    return raw.strip().lower()


def _scope_match_score(pattern: str, hostname: str) -> int | None:
    """Return a match score for ``pattern`` against ``hostname``, or None on no match.

    Higher score wins. Literal matches outrank wildcards; narrower wildcards
    outrank broader ones. The score encodes "literal vs wildcard" in the high
    bits so a literal always beats any wildcard regardless of length.
    """
    if not pattern:
        return None
    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. ".example.com"
        apex = pattern[2:]
        if hostname == apex or hostname.endswith(suffix):
            # Wildcard: narrower (longer) suffix wins; cap at <1M so literal stays above.
            return len(suffix)
        return None
    if hostname == pattern:
        # Literal: encode in the high bits so it always beats wildcards.
        return 1_000_000 + len(pattern)
    return None


def _content_type_family(content_type: str) -> str:
    """Bucket a Content-Type into a coarse family for indexing/filtering.

    ``html``/``xml`` are tested BEFORE the generic ``text/`` fallback so
    ``text/html`` records as ``html`` (previously the ``text/`` branch shadowed
    it and the html/xml families were dead).
    """
    ct = (content_type or "").lower()
    if not ct:
        return "unknown"
    if "json" in ct:
        return "json"
    if "javascript" in ct or "ecmascript" in ct:
        return "javascript"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if ct.startswith("text/"):
        return "text"
    return "unknown"


def _entry_host(entry: str) -> str:
    """Extract the bare hostname from a URL-form scope entry (``https://h/x``)."""
    try:
        parsed = urlparse(entry)
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


def _parse_cidr(entry: str):
    """Return an ``ip_network`` for a CIDR entry, or None if it is not one."""
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _coerce_ip(value):
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _out_of_scope_covers(
    patterns: list[str],
    hostname: str,
    resolved_ip: str | None = None,
    *,
    defer_unresolved_cidr: bool = False,
) -> bool:
    """Return True when ANY out_of_scope entry could plausibly cover ``hostname``.

    The caller uses this as the fail-closed deny primitive under normal scope
    enforcement; the explicit engagement-wide global bypass skips it. Beyond literal and ``*.``
    wildcard host patterns, this understands:

    * URL-form entries (``https://host/path``) — reduced to their bare host and
      matched as a host pattern.
    * CIDR entries (``10.0.0.0/8``) — matched against the flow's resolved server
      IP (or an IP-literal hostname) when one is available.

    FAIL-CLOSED, BUT PER-FLOW: a CIDR carve-out whose IP cannot be resolved for
    THIS flow drops THIS flow (host_ip is per-flow, so the failure is scoped to the
    single unevaluable flow, not the whole engagement). Host/path and URL-form
    entries are reduced to their host component and matched as host patterns; an
    entry with NO bindable host (a bare path like ``/api/internal`` or an
    unparseable URL) is host-blind and is SKIPPED here — a single unbindable entry
    must never wipe out an entire engagement's capture. Path-level scoping the
    proxy cannot enforce by host is still honored on the IP-aware surfaces
    (scope.host_admitted).
    """
    hostname = (hostname or "").lower()
    host_ip = _coerce_ip(resolved_ip) or _coerce_ip(hostname)
    for raw in patterns:
        entry = (raw or "").strip().lower()
        if not entry:
            continue
        if "://" in entry:
            host = _entry_host(entry)
            if host and _scope_match_score(host, hostname) is not None:
                return True
            # Host-less/unparseable URL-form (e.g. bare "://"): there is no host
            # to bind the carve-out to, so it is host-blind. SKIP it rather than
            # dropping every host in the engagement — a single unparseable entry
            # must never wipe out the whole engagement's capture. Path-level
            # scoping is still honored on the IP-aware surfaces (scope.host_admitted).
            continue
        if "/" in entry:
            network = _parse_cidr(entry)
            if network is not None:
                # CIDR carve-out — match against the flow's resolved server IP.
                if host_ip is None:
                    # CIDR present but no IP to test THIS flow. At request time the
                    # upstream is usually not connected yet, so failing closed here
                    # would drop in-scope traffic (and suppress required-header
                    # injection). ``defer_unresolved_cidr`` skips this one CIDR
                    # entry so host/URL carve-outs still apply now and the CIDR
                    # gate is re-evaluated on the response path where the resolved
                    # IP is available. Otherwise fail closed (per-flow).
                    if defer_unresolved_cidr:
                        continue
                    return True
                if host_ip in network:
                    return True
                continue
            # A slash-bearing entry that is NOT a valid CIDR is a host/path or
            # host-relative carve-out (e.g. "example.com/admin", "/api/internal").
            # The proxy can only filter by HOST, so reduce it to its host
            # component and match as a host pattern. A leading-slash / host-less
            # path ("/api/internal") has no host to bind → SKIP it (host-blind);
            # never drop the whole engagement's traffic on an unbindable entry.
            host = entry.split("/", 1)[0].strip()
            if host and _scope_match_score(host, hostname) is not None:
                return True
            continue
        # Plain host pattern (literal or ``*.`` wildcard).
        if _scope_match_score(entry, hostname) is not None:
            return True
    return False


def _normalize_capture_policy(raw) -> dict:
    """Coerce a registry/​filesystem capture-policy blob into the addon's shape.

    Matches the backend ``DEFAULT_CAPTURE_POLICY`` contract: full-flow metadata
    recording is OFF unless ``enabled`` is true; each body side remains opt-in.
    """
    data = raw if isinstance(raw, dict) else {}

    def _flag(key: str) -> bool:
        return bool(data.get(key, False))

    try:
        max_body = int(data.get("max_body_bytes", BODY_TRUNCATE))
    except (TypeError, ValueError):
        max_body = BODY_TRUNCATE

    def _ct_list(key: str) -> list[str]:
        value = data.get(key, [])
        if not isinstance(value, list):
            return []
        return [str(item).lower() for item in value if isinstance(item, str) and item]

    return {
        "enabled": _flag("enabled"),
        "capture_request_bodies": _flag("capture_request_bodies"),
        "capture_response_bodies": _flag("capture_response_bodies"),
        "max_body_bytes": max(0, max_body),
        "content_type_allow": _ct_list("content_type_allow"),
        "content_type_deny": _ct_list("content_type_deny"),
        "redaction_profile": str(data.get("redaction_profile") or "none"),
    }


def _content_type_pattern_matches(pattern: str, content_type: str) -> bool:
    """Match one allow/deny entry against a content type.

    Understands the standard MIME wildcard ``type/*`` (e.g. ``image/*`` — the
    exact form the capture-policy API stores) as a family PREFIX match so
    ``image/*`` covers ``image/png``; a bare ``type`` with no subtype is also
    covered. Every other entry keeps the historical substring semantics
    (``image/`` or ``json`` still match ``image/png`` / ``application/json``).
    """
    if not pattern:
        return False
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # "image/*" -> "image/"
        base = pattern[:-2]    # "image/*" -> "image"
        return content_type.startswith(prefix) or content_type == base
    return pattern in content_type


def _body_capture_allowed(content_type: str, allow: list[str], deny: list[str]) -> bool:
    """Apply the policy content-type allow/deny lists.

    Entries match by substring, except ``type/*`` MIME wildcards which match the
    whole family by prefix (see ``_content_type_pattern_matches``) so a deny of
    ``image/*`` actually excludes ``image/png`` instead of silently capturing it.
    """
    ct = (content_type or "").lower()
    for item in deny:
        if _content_type_pattern_matches(item, ct):
            return False
    if allow:
        return any(_content_type_pattern_matches(item, ct) for item in allow)
    return True


# ---------------------------------------------------------------------------
# Addon
# ---------------------------------------------------------------------------


class CaseCollector:
    """Collects HTTP request/response pairs and routes each flow to the
    matching engagement's storage + backend.
    """

    def __init__(self):
        self.engagements_root: Path | None = None
        self.orchestrator_base_url = os.getenv("ORCHESTRATOR_BASE_URL", "").rstrip("/")
        self.backend_warning_emitted = False
        self.registry: dict[str, EngagementEntry] = {}
        self._registry_lock = threading.RLock()
        self._reload_stop = threading.Event()
        self._reload_thread: threading.Thread | None = None
        self._poll_seconds = DEFAULT_REGISTRY_POLL_SECONDS
        self._last_sentinel_mtime: float | None = None
        # Suppress per-host routing log spam — only log first match per (host, key) pair.
        self._routed_log_seen: set[tuple[str, str]] = set()
        self._ambiguity_log_seen: set[str] = set()

    @staticmethod
    def _safe_content(msg) -> bytes:
        """Get message content without crashing on missing/streamed bodies."""
        try:
            return msg.get_content() or b""
        except Exception:
            return b""

    # -- mitmproxy lifecycle ------------------------------------------------

    def load(self, loader):
        loader.add_option(
            "engagements_root",
            str,
            "",
            "Path to the directory containing all engagement subdirectories",
        )
        loader.add_option(
            "registry_poll_seconds",
            int,
            DEFAULT_REGISTRY_POLL_SECONDS,
            "Seconds between automatic engagement-registry reloads.",
        )

    def configure(self, updates):
        if "registry_poll_seconds" in updates:
            try:
                self._poll_seconds = max(1, int(ctx.options.registry_poll_seconds))
            except (TypeError, ValueError):
                self._poll_seconds = DEFAULT_REGISTRY_POLL_SECONDS
        if "engagements_root" in updates and ctx.options.engagements_root:
            self.engagements_root = Path(ctx.options.engagements_root)
        if self.engagements_root is not None and not self.registry:
            self._reload_registry(force=True)
            self._start_reload_thread()

    def done(self):
        """mitmproxy lifecycle hook called on shutdown."""
        self._reload_stop.set()
        if self._reload_thread is not None:
            self._reload_thread.join(timeout=2)

    # -- registry loading ---------------------------------------------------

    def _start_reload_thread(self) -> None:
        if self._reload_thread is not None and self._reload_thread.is_alive():
            return
        self._reload_stop.clear()
        thread = threading.Thread(
            target=self._reload_loop,
            name="proxy-addon-registry-reload",
            daemon=True,
        )
        thread.start()
        self._reload_thread = thread

    def _reload_loop(self) -> None:
        while not self._reload_stop.is_set():
            if self._reload_stop.wait(timeout=1):
                return
            forced = self._check_reload_sentinel()
            if forced or self._elapsed_since_last_reload() >= self._poll_seconds:
                try:
                    self._reload_registry(force=forced)
                except Exception as exc:
                    ctx.log.warn(f"proxy_addon: registry reload failed — {exc}")

    _last_reload_at: float = 0.0

    def _elapsed_since_last_reload(self) -> float:
        return time.monotonic() - self._last_reload_at

    def _check_reload_sentinel(self) -> bool:
        if self.engagements_root is None:
            return False
        sentinel = self.engagements_root / RELOAD_SENTINEL
        try:
            mtime = sentinel.stat().st_mtime
        except OSError:
            return False
        if self._last_sentinel_mtime is None or mtime != self._last_sentinel_mtime:
            self._last_sentinel_mtime = mtime
            return True
        return False

    def _reload_registry(self, *, force: bool = False) -> None:
        if self.engagements_root is None:
            return
        entries = self._fetch_registry_from_backend()
        if entries is None:
            entries = self._fetch_registry_from_filesystem()
        new_registry: dict[str, EngagementEntry] = {}
        with self._registry_lock:
            for entry in entries:
                # Reuse the existing entry object so a registry reload does not
                # churn per-engagement state for engagements that are still
                # active.
                existing = self.registry.get(entry.key)
                if existing is not None:
                    existing.root = entry.root
                    existing.scope_patterns = entry.scope_patterns
                    existing.out_of_scope_patterns = entry.out_of_scope_patterns
                    existing.scope_enforcement = entry.scope_enforcement
                    existing.scope_priority = entry.scope_priority
                    existing.updated_at = entry.updated_at
                    existing.capture_policy = entry.capture_policy
                    existing.required_headers = entry.required_headers
                    new_registry[entry.key] = existing
                else:
                    new_registry[entry.key] = entry
            self.registry = new_registry
            self._last_reload_at = time.monotonic()
            self._write_routes_cache()
        ctx.log.info(
            f"proxy_addon: registry loaded — {len(new_registry)} engagement(s): "
            + ", ".join(sorted(new_registry))
        )
        if force:
            # Force-reload invalidates the per-host log-suppression set so any
            # newly arrived engagement gets its first-match audit line.
            self._routed_log_seen.clear()
            self._ambiguity_log_seen.clear()

    def _fetch_registry_from_backend(self) -> list[EngagementEntry] | None:
        if not self.orchestrator_base_url or self.engagements_root is None:
            return None
        url = f"{self.orchestrator_base_url}/engagements?status=in_progress"
        request = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            ctx.log.warn(
                f"proxy_addon: orchestrator registry fetch failed ({exc}); "
                "falling back to filesystem scan"
            )
            return None
        if not isinstance(payload, list):
            return None
        entries: list[EngagementEntry] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "").strip()
            if not key:
                continue
            # The ``engagement_root`` field in the backend response is an
            # install-host path; inside the container the engagement always
            # lives at ``/engagements/<key>``, so resolve by basename to keep
            # the bind mount portable.
            root = self.engagements_root / key
            if not root.is_dir():
                # Stale backend row pointing at a directory that doesn't
                # exist (install-root mismatch, deleted-but-not-tombstoned
                # engagement, etc.). Skipping here keeps routing from binding a
                # phantom engagement whose root the full-flow sidecar writes
                # cannot reach.
                ctx.log.warn(
                    f"proxy_addon: backend lists engagement {key!r} but {root} is not a directory; skipping"
                )
                continue
            scope_hosts = row.get("scope_hosts")
            if not isinstance(scope_hosts, list):
                scope_hosts = []
            scope_patterns = [
                _normalize_scope_entry(str(item))
                for item in scope_hosts
                if isinstance(item, str) and str(item).strip()
            ]
            out_of_scope_raw = row.get("scope_out_of_scope")
            if not isinstance(out_of_scope_raw, list):
                out_of_scope_raw = row.get("out_of_scope")
            if not isinstance(out_of_scope_raw, list):
                out_of_scope_raw = []
            out_of_scope_patterns = [
                _normalize_scope_entry(str(item))
                for item in out_of_scope_raw
                if isinstance(item, str) and str(item).strip()
            ]
            scope_priority_raw = row.get("scope_priority", 0)
            try:
                scope_priority = int(scope_priority_raw) if scope_priority_raw is not None else 0
            except (TypeError, ValueError):
                scope_priority = 0
            updated_at = str(row.get("updated_at") or "")
            capture_policy = _normalize_capture_policy(row.get("capture_policy"))
            # The backend ``/engagements`` payload does not carry
            # ``required_headers``, so read them from the engagement's on-disk
            # scope.json (authoritative). The addon always knows the root even on
            # the backend path, so injection works whether or not the backend is
            # up — without this the marker would silently never inject in the
            # common case where the backend registry fetch succeeds.
            required_headers, scope_enforcement = (
                self._scope_request_policy_from_root(root)
            )
            entries.append(
                EngagementEntry(
                    key=key,
                    root=root,
                    scope_patterns=scope_patterns,
                    out_of_scope_patterns=out_of_scope_patterns,
                    scope_enforcement=scope_enforcement,
                    scope_priority=scope_priority,
                    updated_at=updated_at,
                    capture_policy=capture_policy,
                    required_headers=required_headers,
                )
            )
        return entries

    def _fetch_registry_from_filesystem(self) -> list[EngagementEntry]:
        if self.engagements_root is None or not self.engagements_root.is_dir():
            return []
        entries: list[EngagementEntry] = []
        for engagement_dir in sorted(self.engagements_root.iterdir()):
            if not engagement_dir.is_dir():
                continue
            if engagement_dir.name == DELETED_ENGAGEMENTS_DIR:
                continue
            scope_path = engagement_dir / "scope.json"
            if not scope_path.is_file():
                continue
            try:
                with scope_path.open("r", encoding="utf-8") as fh:
                    scope_data = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                ctx.log.warn(
                    f"proxy_addon: cannot read {scope_path} during registry scan — {exc}"
                )
                continue
            if not isinstance(scope_data, dict):
                continue
            # Mirror the backend filter (`/engagements?status=in_progress`):
            # archived/completed engagements must not re-enter routing on a
            # backend-fetch failure or they would steal captures from active
            # engagements that share overlapping scope patterns.
            status_value = str(scope_data.get("status") or "").strip().lower()
            if status_value and status_value != "in_progress":
                continue
            scope_patterns = self._scope_patterns_from_dict(scope_data)
            out_of_scope_patterns = self._out_of_scope_patterns_from_dict(scope_data)
            scope_enforcement = _scope_enforcement(scope_data)
            scope_priority_raw = scope_data.get("scope_priority", 0)
            try:
                scope_priority = int(scope_priority_raw) if scope_priority_raw is not None else 0
            except (TypeError, ValueError):
                scope_priority = 0
            try:
                mtime = scope_path.stat().st_mtime
                updated_at = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except OSError:
                updated_at = ""
            capture_policy = self._capture_policy_from_root(engagement_dir)
            # scope_data is already parsed here; reuse it rather than re-reading
            # scope.json from disk like the backend path must.
            required_headers = _scope_required_headers(scope_data)
            entries.append(
                EngagementEntry(
                    key=engagement_dir.name,
                    root=engagement_dir,
                    scope_patterns=scope_patterns,
                    out_of_scope_patterns=out_of_scope_patterns,
                    scope_enforcement=scope_enforcement,
                    scope_priority=scope_priority,
                    updated_at=updated_at,
                    capture_policy=capture_policy,
                    required_headers=required_headers,
                )
            )
        return entries

    @staticmethod
    def _capture_policy_from_root(engagement_dir: Path) -> dict:
        """Read the ``capture-policy.json`` mirror the backend writes next to
        ``scope.json``. This is the filesystem fallback the shared proxy uses
        when the orchestrator registry fetch is unavailable."""
        policy_path = engagement_dir / "capture-policy.json"
        try:
            with policy_path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return _normalize_capture_policy({})
        return _normalize_capture_policy(raw)

    @staticmethod
    def _scope_request_policy_from_root(
        engagement_dir: Path,
    ) -> tuple[dict, str]:
        """Load attribution and routing policy the backend registry omits."""
        scope_path = engagement_dir / "scope.json"
        try:
            with scope_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}, "enforce"
        if not isinstance(data, dict):
            return {}, "enforce"
        return _scope_required_headers(data), _scope_enforcement(data)

    @staticmethod
    def _scope_patterns_from_dict(scope_data: dict) -> list[str]:
        raw: list[str] = []
        for key in ("hosts", "scope_hosts", "scope"):
            value = scope_data.get(key)
            if isinstance(value, list):
                raw.extend(value)
        hostname = scope_data.get("hostname")
        if isinstance(hostname, str) and hostname:
            raw.append(hostname)
        seen: set[str] = set()
        result: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            normalized = _normalize_scope_entry(item)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(normalized)
        return result

    @staticmethod
    def _out_of_scope_patterns_from_dict(scope_data: dict) -> list[str]:
        raw = scope_data.get("out_of_scope")
        if not isinstance(raw, list):
            return []
        seen: set[str] = set()
        result: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            normalized = _normalize_scope_entry(item)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(normalized)
        return result

    def _write_routes_cache(self) -> None:
        if self.engagements_root is None:
            return
        path = self.engagements_root / ROUTES_CACHE
        snapshot = sorted(
            (
                {
                    "key": entry.key,
                    "scope_patterns": list(entry.scope_patterns),
                    "out_of_scope": list(entry.out_of_scope_patterns),
                    "scope_enforcement": entry.scope_enforcement,
                    "scope_priority": entry.scope_priority,
                    "updated_at": entry.updated_at,
                    "required_headers": dict(entry.required_headers),
                }
                for entry in self.registry.values()
            ),
            key=lambda item: item["key"],
        )
        payload = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engagements": snapshot,
        }
        try:
            tmp_path = path.with_name(path.name + ".tmp")
            tmp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            tmp_path.rename(path)
        except OSError as exc:
            ctx.log.warn(f"proxy_addon: cannot write routes cache {path} — {exc}")

    # -- matching -----------------------------------------------------------

    def _match_engagement(
        self,
        hostname: str,
        resolved_ip: str | None = None,
        *,
        defer_unresolved_cidr: bool = False,
    ) -> EngagementEntry | None:
        if not hostname:
            return None
        hostname = hostname.lower()
        best: tuple[int, int, str, EngagementEntry] | None = None
        runners_up: list[EngagementEntry] = []
        with self._registry_lock:
            for entry in self.registry.values():
                best_pattern_score: int | None = None
                for pattern in entry.scope_patterns:
                    score = _scope_match_score(pattern, hostname)
                    if score is None:
                        continue
                    if best_pattern_score is None or score > best_pattern_score:
                        best_pattern_score = score
                if best_pattern_score is None:
                    continue
                # Tiebreakers after best-pattern score: scope_priority, then updated_at desc.
                key = (best_pattern_score, entry.scope_priority, entry.updated_at)
                if best is None or key > (best[0], best[1], best[2]):
                    if best is not None:
                        runners_up.append(best[3])
                    best = (best_pattern_score, entry.scope_priority, entry.updated_at, entry)
                else:
                    runners_up.append(entry)
        if best is None:
            chosen = self._active_global_bypass_entry()
            if chosen is None:
                return None
        else:
            chosen = best[3]
        # Out-of-scope carve-out: a host admitted by an in-scope wildcard but
        # covered by ANY of the engagement's out_of_scope entries must not be
        # captured or routed under normal enforcement. The explicit global
        # bypass overrides target allow/deny admission.
        # ``_out_of_scope_covers`` understands literal/``*.`` host patterns,
        # URL-form entries (reduced to their host) and CIDR entries (matched
        # against ``resolved_ip`` when the flow carries the server IP), and
        # FAILS CLOSED on any entry it cannot evaluate with certainty so an
        # unparseable carve-out never silently admits an out-of-scope host.
        if (
            chosen.scope_enforcement != "bypass"
            and _out_of_scope_covers(
                chosen.out_of_scope_patterns,
                hostname,
                resolved_ip,
                defer_unresolved_cidr=defer_unresolved_cidr,
            )
        ):
            suppress_key = (hostname, chosen.key)
            if suppress_key not in self._routed_log_seen:
                self._routed_log_seen.add(suppress_key)
                ctx.log.info(
                    f"proxy_addon: suppressed {hostname} — matches out_of_scope "
                    f"carve-out for engagement {chosen.key}"
                )
            return None
        log_key = (hostname, chosen.key)
        if log_key not in self._routed_log_seen:
            self._routed_log_seen.add(log_key)
            ctx.log.info(
                f"proxy_addon: routed {hostname} → engagement {chosen.key}"
            )
            if runners_up and hostname not in self._ambiguity_log_seen:
                self._ambiguity_log_seen.add(hostname)
                other_keys = ", ".join(sorted({e.key for e in runners_up}))
                ctx.log.info(
                    f"proxy_addon: scope overlap for {hostname} — chose {chosen.key} over [{other_keys}] "
                    f"(score={best[0]}, priority={best[1]})"
                )
        return chosen

    def _active_global_bypass_entry(self) -> EngagementEntry | None:
        """Bind an otherwise-unclaimed proxy flow to the selected bypass engagement.

        Normal hostname ownership always wins. The active pointer is consulted
        only when no engagement scope pattern claims the host, which gives a
        global-bypass engagement an unambiguous capture/attribution owner without
        letting it steal traffic from another active engagement.
        """
        if self.engagements_root is None:
            return None
        try:
            key = (self.engagements_root / ".active").read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not key:
            return None
        with self._registry_lock:
            entry = self.registry.get(key)
            if entry is None or entry.scope_enforcement != "bypass":
                return None
            return entry

    # -- noise --------------------------------------------------------------

    def _is_noise(self, hostname: str, path: str) -> bool:
        hostname = hostname.lower()
        for nd in NOISE_DOMAINS:
            if hostname == nd or hostname.endswith("." + nd):
                return True
        if NOISE_PATH_RE.search(path):
            return True
        return False

    # -- classification -----------------------------------------------------

    def _classify_type(
        self, method: str, path: str, content_type: str, req_headers: dict
    ) -> str:
        if req_headers.get("upgrade", "").lower() == "websocket":
            return "websocket"
        return classify_type(method, path, content_type)

    # -- parameter extraction -----------------------------------------------

    def _extract_params(self, flow: http.HTTPFlow) -> dict:
        req = flow.request
        parsed = urlparse(req.pretty_url)

        # query params
        query_params = {}
        if parsed.query:
            query_params = {k: v if len(v) > 1 else v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        # body params
        body_params = {}
        ct = (req.headers.get("content-type", "") or "").lower()
        raw_body = self._safe_content(req)
        if raw_body:
            if "application/x-www-form-urlencoded" in ct:
                try:
                    body_params = {
                        k: v if len(v) > 1 else v[0]
                        for k, v in parse_qs(raw_body.decode("utf-8", errors="replace"), keep_blank_values=True).items()
                    }
                except Exception:
                    pass
            elif "application/json" in ct or "text/json" in ct:
                try:
                    body_params = json.loads(raw_body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        # path params — dynamic segments
        path_parts = [seg for seg in parsed.path.split("/") if seg]
        path_params = {
            f"seg_{idx}": seg
            for idx, seg in enumerate(path_parts, start=1)
            if _DYNAMIC_RE.match(seg)
        }

        # cookie params — use mitmproxy's parsed cookies to avoid
        # comma-vs-semicolon ambiguity in raw Cookie header serialization
        cookie_params = {}
        for k, v in req.cookies.items():
            cookie_params[k] = v

        return {
            "query_params": json.dumps(query_params) if query_params else None,
            "body_params": json.dumps(body_params) if body_params else None,
            "path_params": json.dumps(path_params) if path_params else None,
            "cookie_params": json.dumps(cookie_params) if cookie_params else None,
        }

    # -- dedup signature ----------------------------------------------------

    def _generate_sig(self, query_json: str | None, body_json: str | None) -> str:
        keys: list[str] = []
        if query_json:
            try:
                q = json.loads(query_json)
                if isinstance(q, dict):
                    keys.extend(q.keys())
            except json.JSONDecodeError:
                pass
        if body_json:
            try:
                b = json.loads(body_json)
                if isinstance(b, dict):
                    keys.extend(b.keys())
            except json.JSONDecodeError:
                pass
        return hashlib.md5(",".join(sorted(set(keys))).encode()).hexdigest()

    # -- body save policy ---------------------------------------------------

    def _apply_body_policy(self, body: bytes | None, content_type: str) -> tuple[str | None, bool]:
        """Return (saved_text, truncated). The flag is True only when the
        body was saveable AND larger than BODY_TRUNCATE — so callers can
        flag the work-item snapshot, never silently dropping bytes.
        """
        if not body:
            return None, False
        ct = (content_type or "").lower()
        # Skip binary types entirely
        if any(ct.startswith(p) for p in BINARY_PREFIXES):
            return None, False
        # Only save text-ish bodies
        saveable = (
            "json" in ct
            or "form-urlencoded" in ct
            or "html" in ct
            or "xml" in ct
            or "text/" in ct
        )
        if not saveable:
            return None, False
        truncated = len(body) > BODY_TRUNCATE
        text = body[:BODY_TRUNCATE].decode("utf-8", errors="replace")
        return text, truncated

    def _backend_configured(self) -> bool:
        return bool(self.orchestrator_base_url)

    def _warn_backend_unavailable(self):
        if not self.backend_warning_emitted:
            ctx.log.error(
                "proxy_addon: orchestrator assessment backend is not configured; "
                "captured traffic will not be queued"
            )
            self.backend_warning_emitted = True

    def _post_request_observation(
        self,
        *,
        entry: EngagementEntry,
        url: str,
        method: str,
        auth_context: str,
        content_type: str,
        params: dict,
        response_status: int,
        evidence_ref: str,
        observation_payload: dict,
        request_headers: dict | None = None,
        # Flow-derived work-item snapshot. These ride in the observation's
        # ``work_item`` block; the backend derives the ``assessment_work_items``
        # row from it in the SAME transaction as the request-variant/coverage
        # item (ADR 0013 — no dual write). The proxy no longer holds a local
        # cases.db handle.
        case_type: str = "unknown",
        url_path: str = "",
        request_content_type: str = "",
        headers: str = "",
        body: str | None = None,
        content_length: int = 0,
        request_body_truncated: bool = False,
        response_headers: str = "",
        response_size: int = 0,
        response_snippet: str | None = None,
        response_truncated: bool = False,
        params_key_sig: str = "",
    ) -> dict | None:
        if not self._backend_configured():
            self._warn_backend_unavailable()
            return None

        parsed = urlparse(url)
        content_family = _content_type_family(content_type)

        # ``body_schema`` is typed dict[str, Any] on the backend. A request with
        # a top-level JSON ARRAY or SCALAR body decodes to a list/str/number
        # here; sending that would 422 the observation and drop the WHOLE
        # capture (silent data loss). Only forward a parsed body when it is a
        # dict; otherwise send {} — the raw body is still preserved in the
        # ``work_item`` block's ``body_params`` and the full-flow sidecar.
        body_schema = json.loads(params.get("body_params") or "{}")
        if not isinstance(body_schema, dict):
            body_schema = {}

        # Classify the captured flow client-side (the classifier globs the agent
        # skills tree, so it must stay off the backend). Mirrors the inline
        # classification ``db_insert_work_item`` used to run at insert time.
        # Guarded so a classification failure never aborts a capture.
        try:
            assignment = classify_from_fields(
                case_type=case_type,
                url_path=url_path,
                query_params=params.get("query_params") or "{}",
                body_params=params.get("body_params") or "{}",
                path_params=params.get("path_params") or "{}",
                url=url,
                source="proxy",
            )
        except Exception as exc:  # noqa: BLE001 — classification must never drop a capture
            ctx.log.warn(
                f"proxy_addon: work-item classification failed for {url} — {exc}"
            )
            assignment = {
                "priority_score": 0,
                "priority_reason": None,
                "cluster_key": None,
                "terminal_reason": None,
            }

        payload = {
            "url": url,
            "method": method,
            "auth_context": auth_context,
            "content_type_family": content_family,
            "query_schema": json.loads(params.get("query_params") or "{}"),
            "body_schema": body_schema,
            "path_schema": json.loads(params.get("path_params") or "{}"),
            "cookie_schema": json.loads(params.get("cookie_params") or "{}"),
            # Capture the request header NAMES (values discarded; hop-by-hop /
            # browser noise filtered — see header_schema_from_headers) so the
            # depth ledger's CORS/proxy presence triggers fire on live-proxy
            # traffic, not only the spec/candidate slice. The full headers are
            # still preserved verbatim in observation_payload.request_headers.
            "header_schema": header_schema_from_headers(request_headers),
            "path_template": parsed.path or "",
            "discovery_source": "proxy",
            "notes": "",
            "response_status": response_status,
            "evidence_ref": evidence_ref,
            "observation_payload": observation_payload,
            "target_identity": parsed.hostname or "",
            "target_kind": "host",
            "target_notes": "",
            "target_ip_address": None,
            "target_hostname": parsed.hostname,
            "banner": "",
            "coverage_candidates": [],
            "auto_generate_coverage": True,
            # Work-buffer derivation block — the backend derives the
            # assessment_work_items row from this in the same transaction as the
            # request-variant/coverage item. All fields are optional/defaulted
            # and extra keys are ignored, so this can never 422 an otherwise
            # well-formed observation. The backend computes ``queue_key`` itself
            # (``variant:<id>:<case_type>``); ``request_variant_id`` /
            # ``service_id`` / ``auth_context`` are derived from the observation.
            "work_item": {
                "case_type": case_type,
                "source": "proxy",
                "status": "skipped" if case_type in INERT_TYPES else "pending",
                "url_path": url_path,
                "query_params": params.get("query_params") or "{}",
                "body_params": params.get("body_params") or "{}",
                "path_params": params.get("path_params") or "{}",
                "cookie_params": params.get("cookie_params") or "{}",
                "headers": headers or "",
                "body": body or "",
                "content_type": request_content_type,
                "content_length": content_length,
                "request_body_truncated": request_body_truncated,
                "response_status": response_status,
                "response_headers": response_headers or "",
                "response_size": response_size,
                "response_snippet": response_snippet or "",
                "response_truncated": response_truncated,
                "params_key_sig": params_key_sig,
                "priority_score": assignment.get("priority_score", 0),
                "priority_reason": assignment.get("priority_reason") or "",
                "cluster_key": assignment.get("cluster_key") or "",
                "terminal_reason": assignment.get("terminal_reason") or "",
                "classifier_version": CLASSIFIER_VERSION,
            },
        }
        request = Request(
            f"{self.orchestrator_base_url}/engagements/{entry.key}/assessment/request-observations",
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                response_body = response.read().decode("utf-8")
            data = json.loads(response_body)
        except Exception as exc:
            ctx.log.error(
                f"proxy_addon: backend write failed for {url} (engagement {entry.key}) — {exc}"
            )
            return None

        request_variant = data.get("request_variant") if isinstance(data, dict) else None
        if not isinstance(request_variant, dict) or not request_variant.get("id"):
            ctx.log.error(
                f"proxy_addon: backend response missing request_variant.id for {url} "
                f"(engagement {entry.key})"
            )
            return None
        return data

    # -- auth context + capture (centralized credential store) --------------

    def _request_auth_context(
        self,
        entry: EngagementEntry,
        req_headers_dict: dict,
        params: dict,
    ) -> str:
        """Label a captured request's auth tier from the request material.

        Derived purely from the flow (presence of an Authorization header or
        cookies) — "authenticated" vs "anonymous". Named-identity labeling
        happens at probe time via ``vigil assess kali --identity``, so the proxy
        does not need a per-request lookup into the credential store.
        """
        has_authorization = bool(
            req_headers_dict.get("authorization") or req_headers_dict.get("Authorization")
        )
        cookie_values = params.get("cookie_params") or "{}"
        try:
            has_cookies = bool(json.loads(cookie_values))
        except (TypeError, json.JSONDecodeError):
            has_cookies = False
        return "authenticated" if (has_authorization or has_cookies) else "anonymous"

    def _post_credentials_capture(
        self,
        entry: EngagementEntry,
        *,
        host: str,
        scope_host: str,
        cookies: dict,
        headers: dict,
        tokens: dict,
    ) -> None:
        """POST a captured credential delta to the backend, which DERIVES the
        session identity server-side from the delta's session-anchor material
        (session-hint cookies + JWT/bearer sub) and merges into that identity —
        appending a new row for a distinct login, refreshing the row for the same
        login (host-cookie buckets, flat cookie recompute, header/token merge).
        The addon stays a thin client and posts no identity_name. Mirrors
        ``_post_request_observation``.
        """
        if not self._backend_configured():
            self._warn_backend_unavailable()
            return
        payload = {
            "host": host,
            "scope_host": scope_host,
            "cookies": cookies,
            "headers": headers,
            "tokens": tokens,
        }
        request = Request(
            f"{self.orchestrator_base_url}/engagements/{entry.key}/credentials/capture",
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                response.read()
            ctx.log.info(
                f"proxy_addon: captured credentials for {entry.key} "
                f"({len(cookies)} cookies, {len(headers)} headers from {host})"
            )
        except Exception as exc:
            ctx.log.error(
                f"proxy_addon: credential capture failed for {entry.key} — {exc}"
            )

    @staticmethod
    def _collect_token_pairs(obj) -> dict[str, str]:
        """Collect string token-keyed fields from ONE object level.

        The capture endpoint types tokens as str->str, so a non-string
        token-keyed field (null / number / further-nested object) is skipped —
        forwarding it would 422 the whole POST and silently drop the capture.
        """
        out: dict[str, str] = {}
        if not isinstance(obj, dict):
            return out
        for key, value in obj.items():
            if not isinstance(key, str) or not TOKEN_KEYS_RE.search(key):
                continue
            if isinstance(value, str) and value:
                out.setdefault(key, value)
        return out

    def _extract_login_tokens(self, body_json) -> dict[str, str]:
        """Extract token fields from a login response, recursing ONE level.

        Top-level string token fields win over nested ones of the same name.
        Recurses one level into nested objects and into objects inside arrays so
        a bearer nested under e.g. ``{"data": {"access_token": ...}}`` or
        ``{"tokens": [{"jwt": ...}]}`` still enters the store (previously only
        top-level string keys were read).
        """
        tokens: dict[str, str] = {}
        if not isinstance(body_json, dict):
            return tokens
        tokens.update(self._collect_token_pairs(body_json))
        for value in body_json.values():
            if isinstance(value, dict):
                for k, v in self._collect_token_pairs(value).items():
                    tokens.setdefault(k, v)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for k, v in self._collect_token_pairs(item).items():
                            tokens.setdefault(k, v)
        return tokens

    @staticmethod
    def _bearer_from_tokens(tokens: dict[str, str]) -> str | None:
        """Synthesize an ``Authorization: Bearer`` value from token fields.

        Picks by PRIORITY (access_token > id_token > jwt), matched on the EXACT
        key name (case-insensitive) — never the bare ``token`` substring, so
        ``refresh_token`` / ``csrf_token`` / ``token_type`` cannot seed the
        bearer. Values that are themselves type labels (``bearer`` / ``basic``)
        are skipped so we never emit ``Bearer bearer``.
        """
        lowered = {str(k).lower(): v for k, v in tokens.items()}
        for pref in BEARER_TOKEN_PRIORITY:
            value = lowered.get(pref)
            if not isinstance(value, str) or not value:
                continue
            if value.strip().lower() in _NON_BEARER_VALUES:
                continue
            return value if value.lower().startswith("bearer ") else f"Bearer {value}"
        return None

    def _capture_auth(
        self,
        entry: EngagementEntry,
        flow: http.HTTPFlow,
        resolved_ip: str | None = None,
    ):
        """Capture auth material from a flow into the centralized credential
        store (the ``default`` identity).

        The addon extracts the per-flow delta (this host's request + Set-Cookie
        cookies, the request Authorization header, any bearer token from a login
        response) and POSTs it; the backend owns the merge (host buckets, flat
        cookies, header/token accumulation). mitmproxy hooks run single-threaded
        so captures serialize naturally — no client-side lock needed.
        """
        req = flow.request
        resp = flow.response
        if not resp or (resp.status_code and resp.status_code >= 400):
            return

        parsed = urlparse(req.pretty_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return

        # Defense in depth: under normal enforcement, never harvest credentials
        # for a host an out_of_scope entry could plausibly cover, even if a
        # routing change ever let this run. The explicit global bypass overrides
        # target allow/deny admission.
        if (
            entry.scope_enforcement != "bypass"
            and _out_of_scope_covers(entry.out_of_scope_patterns, hostname, resolved_ip)
        ):
            return

        # -- 1. Request cookies (mitmproxy parses them correctly) ------------
        merged: dict[str, str] = {
            k: _dequote_cookie_value(v) for k, v in req.cookies.items()
        }

        # -- 2. Set-Cookie response headers ----------------------------------
        set_cookies = resp.headers.get_all("set-cookie")
        if set_cookies:
            for sc in set_cookies:
                # Skip logout/expiry deletions — a logout must NEVER overwrite
                # a stored live session cookie with a deletion sentinel.
                # F5/APM sends ``MRHSession=deleted`` on CMS logout; RFC 6265
                # deletions use Max-Age=0 or an Expires in the past; a
                # quoted-empty ``MRHSession=""`` is also a deletion.
                if _is_deletion_set_cookie(sc):
                    ctx.log.debug(
                        f"proxy_addon: skipping deletion Set-Cookie: {sc.split(';')[0]!r}"
                    )
                    continue
                name_val = sc.split(";")[0]
                if "=" in name_val:
                    k, v = name_val.split("=", 1)
                    # Store the DEQUOTED value so a live quoted cookie is not
                    # persisted (and later re-injected) with surrounding quotes.
                    merged[k.strip()] = _dequote_cookie_value(v)

        # -- 3. Token / Authorization extraction -----------------------------
        tokens: dict[str, str] = {}
        headers: dict[str, str] = {}

        # 3a. Bearer-only / already-authenticated sessions: the REQUEST carries
        # the live credential in its Authorization header. Capture it directly
        # so a session that never issues a login-JSON response (or nests its
        # token) still enters the store.
        req_authorization = req.headers.get("authorization", "") or ""
        if req_authorization.strip():
            headers["Authorization"] = req_authorization.strip()

        # 3b. Login-like JSON responses: accumulate token fields (recursing one
        # level) and synthesize a bearer from the highest-priority token key.
        if req.method == "POST" and LOGIN_URL_RE.search(req.pretty_url):
            resp_body = self._safe_content(resp)
            if resp_body:
                try:
                    body_json = json.loads(resp_body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body_json = None
                tokens.update(self._extract_login_tokens(body_json))
                if "Authorization" not in headers:
                    bearer = self._bearer_from_tokens(tokens)
                    if bearer:
                        headers["Authorization"] = bearer

        if not (merged or tokens or headers):
            return

        # scope_host gates which host_cookies buckets get flattened into the
        # identity's legacy single-host `cookies` view (capture_material /
        # _flat_cookies_for_scope). It must be the host that was ACTUALLY
        # captured, not an arbitrary "primary" scope pattern — a multi-host
        # engagement (several unrelated domains in one scope.json) would
        # otherwise only ever populate the flat view for whichever host
        # happens to be first in scope.json's `hosts` list, silently dropping
        # every other host's session from `cookies` (host_cookies still has
        # it, but flat-view consumers like `vigil auth export` do not).
        self._post_credentials_capture(
            entry,
            host=hostname,
            scope_host=hostname,
            cookies=merged,
            headers=headers,
            tokens=tokens,
        )

    # -- main entry point ---------------------------------------------------

    def _any_required_headers(self) -> bool:
        """True if any active engagement mandates attribution headers.

        Lets the ``request`` hook skip its per-request scope match entirely on
        the common (capture-only) path, so proxying stays zero-overhead for
        engagements that do not configure ``required_headers``."""
        with self._registry_lock:
            return any(entry.required_headers for entry in self.registry.values())

    def request(self, flow: http.HTTPFlow):
        """Inject a matched engagement's scope.json ``required_headers`` onto its
        outbound in-scope requests (ROE researcher-attribution markers, e.g.
        BugCrowd's ``X-Bug-Bounty``).

        The shared proxy is the single chokepoint every browser/proxied request
        passes through, so this closes the attribution gap the tool-exec fail-
        closed backstop (ADR 0010) cannot see: manual browsing / login capture
        through FoxyProxy, and any proxied client that did not set the marker
        itself. On a required-headers program, un-attributed in-scope traffic is
        a ban-risk, not a nicety.

        Gated + non-destructive: fires only for a request whose hostname a live
        engagement claims (the SAME ``_match_engagement`` scope + out-of-scope
        gating the capture path uses) AND that declares ``required_headers``;
        never overwrites a header the client already set; leaves out-of-scope
        hosts and header-less engagements untouched."""
        if self.engagements_root is None:
            return
        # Fast path: nothing to inject unless an engagement requires attribution.
        if not self._any_required_headers():
            return
        req = flow.request
        hostname = (urlparse(req.pretty_url).hostname or "").lower()
        if not hostname:
            return
        # The upstream server IP may be unresolved at request time (pre-connect);
        # that is fine — _match_engagement keys on hostname and only uses the IP
        # to tighten the out-of-scope CIDR carve-out. Defer that CIDR fail-closed
        # to the response path (where the IP is resolved) so a required-header
        # engagement that ALSO carries a CIDR out_of_scope entry still gets its
        # attribution header injected on in-scope browser traffic.
        resolved_ip = self._resolved_server_ip(flow)
        entry = self._match_engagement(
            hostname, resolved_ip=resolved_ip, defer_unresolved_cidr=True
        )
        if entry is None:
            return
        for name, value in entry.required_headers.items():
            # mitmproxy Headers membership is case-insensitive — never overwrite
            # or duplicate a marker the client already sent.
            if name not in req.headers:
                req.headers[name] = value

    def response(self, flow: http.HTTPFlow):
        """Called by mitmproxy for every completed request/response pair."""
        if self.engagements_root is None:
            return

        req = flow.request
        resp = flow.response
        if not resp:
            return

        parsed = urlparse(req.pretty_url)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"

        # The flow's resolved server IP (when mitmproxy has it) lets the
        # out-of-scope carve-out evaluate CIDR denylist entries. Routing itself
        # still keys on the canonical request HOSTNAME — the IP only tightens the
        # out-of-scope gate, never widens matching.
        resolved_ip = self._resolved_server_ip(flow)

        # Engagement routing replaces the old global is_in_scope: hostname →
        # the best-matching engagement, or drop if no engagement claims it (or if
        # an out_of_scope carve-out covers it).
        entry = self._match_engagement(hostname, resolved_ip=resolved_ip)
        if entry is None:
            return

        # Noise filter
        if self._is_noise(hostname, req.pretty_url):
            return

        # Auth capture (side-effect: POSTs captured credentials to the backend)
        self._capture_auth(entry, flow, resolved_ip=resolved_ip)

        params = self._extract_params(flow)

        req_headers_dict = dict(req.headers)
        req_headers_json = json.dumps(req_headers_dict)
        auth_context = self._request_auth_context(entry, req_headers_dict, params)

        # Two distinct content types. Classification/case_type PREFER the response
        # type (a GET's request type is empty and would misclassify normal pages
        # as unknown). The stored request-side row fields (content_type stored
        # alongside body/content_length/request_body_truncated) use the REQUEST
        # type so the saved request body and its content_type are consistent.
        request_content_type = req.headers.get("content-type", "") or ""
        response_content_type = resp.headers.get("content-type", "") or ""
        classify_content_type = response_content_type or request_content_type
        content_family = _content_type_family(classify_content_type)

        raw_req_body = self._safe_content(req)
        content_length = len(raw_req_body)

        case_type = self._classify_type(
            req.method, path, classify_content_type, req_headers_dict
        )

        # Gate the REQUEST body save on the REQUEST content type — the previous
        # code gated it on the RESPONSE type, so a JSON POST answered by e.g.
        # image/png had its request body silently dropped (data loss).
        saved_body, request_body_truncated = self._apply_body_policy(
            raw_req_body, request_content_type
        )

        response_status = resp.status_code
        resp_headers_json = json.dumps(dict(resp.headers))
        resp_body = self._safe_content(resp)
        response_size = len(resp_body)

        # Response snippet: first RESPONSE_SNIPPET_BYTES of text responses.
        # `response_truncated` is True when the on-the-wire body was larger
        # than the cap — callers see explicit truncation instead of having to
        # compare response_size vs len(response_snippet).
        response_snippet = None
        response_truncated = False
        resp_ct = (resp.headers.get("content-type", "") or "").lower()
        if resp_body and not any(resp_ct.startswith(p) for p in BINARY_PREFIXES):
            response_snippet = resp_body[:RESPONSE_SNIPPET_BYTES].decode("utf-8", errors="replace")
            response_truncated = len(resp_body) > RESPONSE_SNIPPET_BYTES

        params_key_sig = self._generate_sig(
            params.get("query_params"), params.get("body_params")
        )

        # POST the observation with its work-item block. The backend derives the
        # assessment_work_items row from the block in the SAME transaction as the
        # request-variant/coverage item — no local cases.db write. The observation
        # POST was already the capture's hard dependency, so this adds no new
        # failure mode: the "silent capture loss" invariant is preserved because a
        # captured flow still results in exactly one backend row.
        assessment_record = self._post_request_observation(
            entry=entry,
            url=req.pretty_url,
            method=req.method,
            auth_context=auth_context,
            content_type=classify_content_type,
            params=params,
            response_status=response_status,
            evidence_ref="proxy",
            observation_payload={
                "request_headers": req_headers_dict,
                "response_headers": dict(resp.headers),
            },
            request_headers=req_headers_dict,
            case_type=case_type,
            url_path=path,
            request_content_type=request_content_type,
            headers=req_headers_json,
            body=saved_body,
            content_length=content_length,
            request_body_truncated=request_body_truncated,
            response_headers=resp_headers_json,
            response_size=response_size,
            response_snippet=response_snippet,
            response_truncated=response_truncated,
            params_key_sig=params_key_sig,
        )

        request_variant_id = None
        if assessment_record:
            request_variant_id = assessment_record["request_variant"]["id"]

        # Phase 5 full-flow capture. Runs regardless of the observation POST
        # (which needs the backend) so raw sidecars + the JSONL index are still
        # written locally when the backend is unreachable — no silent data loss.
        # A no-op when the engagement's capture policy leaves full-flow metadata
        # OFF (the default). Never raises up through the flow hook.
        self._maybe_capture_full_flow(
            entry,
            flow,
            hostname=hostname,
            path=path,
            resolved_ip=resolved_ip,
            request_variant_id=request_variant_id,
            auth_context=auth_context,
            content_family=content_family,
            request_content_type=request_content_type,
            response_content_type=response_content_type,
            response_status=response_status,
            raw_req_body=raw_req_body,
            resp_body=resp_body,
        )

    # -- Phase 5: full-flow capture -----------------------------------------

    @staticmethod
    def _resolved_server_ip(flow) -> str | None:
        """Best-effort extraction of the flow's resolved server IP.

        mitmproxy has usually connected upstream by ``response()`` time, so the
        server IP is available for CIDR out-of-scope evaluation. Returns None for
        stubbed/streamed flows without a server connection.
        """
        try:
            server_conn = getattr(flow, "server_conn", None)
            if server_conn is None:
                return None
            peer = getattr(server_conn, "ip_address", None) or getattr(
                server_conn, "peername", None
            )
            if isinstance(peer, (tuple, list)) and peer:
                return str(peer[0])
        except Exception:
            return None
        return None

    @staticmethod
    def _flow_timing(flow) -> tuple[str | None, int | None]:
        """Return (started_at ISO-8601, timing_ms) from the flow timestamps."""
        try:
            req = flow.request
            resp = flow.response
            start = getattr(req, "timestamp_start", None)
            end = getattr(resp, "timestamp_end", None) if resp else None
            started_at = None
            if start:
                started_at = datetime.fromtimestamp(
                    float(start), tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            timing_ms = None
            if start and end and end >= start:
                timing_ms = int((float(end) - float(start)) * 1000)
            return started_at, timing_ms
        except Exception:
            return None, None

    def _write_body_sidecar(
        self, root: Path, body: bytes, policy: dict, content_type: str
    ) -> tuple[str | None, str, int, bool]:
        """Persist a body under ``traffic/mitmproxy/bodies/<sha256>.bin``.

        Honors the content-type allow/deny lists and ``max_body_bytes``. Returns
        ``(relative_path, sha256, stored_bytes, truncated)``. The sha256 is over
        the STORED bytes so the sidecar content hashes to its own filename and
        identical bodies dedupe. Returns ``(None, "", 0, False)`` when the body is
        empty or the policy excludes this content type. Degrades gracefully: a
        write failure logs and returns no path rather than raising.
        """
        if not body:
            return None, "", 0, False
        if not _body_capture_allowed(
            content_type,
            policy.get("content_type_allow") or [],
            policy.get("content_type_deny") or [],
        ):
            return None, "", 0, False
        cap = policy.get("max_body_bytes", BODY_TRUNCATE)
        if not isinstance(cap, int) or cap < 0:
            cap = BODY_TRUNCATE
        stored = body[:cap]
        truncated = len(body) > len(stored)
        sha = hashlib.sha256(stored).hexdigest()
        rel_path = f"{TRAFFIC_BODIES_DIR}/{sha}.bin"
        try:
            bodies_dir = root / TRAFFIC_BODIES_DIR
            bodies_dir.mkdir(parents=True, exist_ok=True)
            target = bodies_dir / f"{sha}.bin"
            if not target.exists():
                tmp = target.with_name(f"{sha}.bin.{os.getpid()}.tmp")
                tmp.write_bytes(stored)
                tmp.rename(target)
        except OSError as exc:
            ctx.log.warn(f"proxy_addon: cannot write body sidecar {rel_path} — {exc}")
            return None, sha, len(stored), truncated
        return rel_path, sha, len(stored), truncated

    def _append_flow_index(self, root: Path, record: dict) -> str | None:
        """Append one JSONL line to ``traffic/mitmproxy/flows/<date>.jsonl``.

        Returns the engagement-root-relative path, or None on write failure
        (logged, never raised)."""
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rel_path = f"{TRAFFIC_FLOWS_DIR}/{date}.jsonl"
        try:
            flows_dir = root / TRAFFIC_FLOWS_DIR
            flows_dir.mkdir(parents=True, exist_ok=True)
            with (flows_dir / f"{date}.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError as exc:
            ctx.log.warn(f"proxy_addon: cannot append flow index {rel_path} — {exc}")
            return None
        return rel_path

    def _post_http_flow(self, entry: EngagementEntry, record: dict) -> None:
        """POST the compact full-flow record to the Stage-1 ingest route.

        Best-effort: the route never 422s a well-formed flow, but any transport
        failure only costs the backend row — the sidecar + JSONL index are
        already durable on disk."""
        if not self._backend_configured():
            self._warn_backend_unavailable()
            return
        request = Request(
            f"{self.orchestrator_base_url}/engagements/{entry.key}/assessment/http-flows",
            data=json.dumps(record, ensure_ascii=True).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                response.read()
        except Exception as exc:
            ctx.log.error(
                f"proxy_addon: http-flow ingest failed for {entry.key} — {exc}"
            )

    def _maybe_capture_full_flow(
        self,
        entry: EngagementEntry,
        flow,
        *,
        hostname: str,
        path: str,
        resolved_ip: str | None,
        request_variant_id: int | None,
        auth_context: str,
        content_family: str,
        request_content_type: str,
        response_content_type: str,
        response_status,
        raw_req_body: bytes,
        resp_body: bytes,
    ) -> None:
        """Write the full-flow index/backend row and any selected body sidecars.

        No-op unless full-flow metadata recording is enabled. Request and response
        bodies remain independently opt-in. Wrapped so a capture failure NEVER
        crashes the flow hook.
        """
        try:
            policy = _normalize_capture_policy(entry.capture_policy)
            if not policy.get("enabled"):
                return

            req = flow.request
            resp = flow.response
            parsed = urlparse(req.pretty_url)
            root = entry.root

            req_path = None
            req_sha = ""
            req_bytes = 0
            req_trunc = False
            if policy.get("capture_request_bodies"):
                req_path, req_sha, req_bytes, req_trunc = self._write_body_sidecar(
                    root, raw_req_body, policy, request_content_type
                )

            resp_path = None
            resp_sha = ""
            resp_bytes = 0
            resp_trunc = False
            if policy.get("capture_response_bodies"):
                resp_path, resp_sha, resp_bytes, resp_trunc = self._write_body_sidecar(
                    root, resp_body, policy, response_content_type
                )

            started_at, timing_ms = self._flow_timing(flow)

            # Host-mismatch telemetry: compare the canonical request authority to
            # the Host header and the negotiated SNI. Routing already used the
            # canonical hostname — this is diagnostic only (never changes routing).
            url_authority = parsed.netloc or ""
            host_header = req.headers.get("host", "") or ""
            sni = ""
            try:
                client_conn = getattr(flow, "client_conn", None)
                sni = (getattr(client_conn, "sni", None) or "") if client_conn else ""
                if not sni:
                    server_conn = getattr(flow, "server_conn", None)
                    sni = (getattr(server_conn, "sni", None) or "") if server_conn else ""
            except Exception:
                sni = ""
            host_header_host = host_header.split(":", 1)[0].strip().lower()
            sni_l = (sni or "").strip().lower()
            host_mismatch = bool(
                (host_header_host and host_header_host != hostname)
                or (sni_l and sni_l != hostname)
            )

            flow_uid = str(getattr(flow, "id", "") or "")
            if not flow_uid:
                digest = hashlib.sha256(
                    f"{req.method}\n{req.pretty_url}\n{started_at or ''}\n{response_status}".encode(
                        "utf-8"
                    )
                ).hexdigest()
                flow_uid = digest

            record = {
                "flow_uid": flow_uid,
                "method": req.method,
                "scheme": parsed.scheme or "",
                "host": hostname,
                "port": parsed.port,
                "url": req.pretty_url,
                "path": path,
                "response_status": response_status,
                "request_content_type": request_content_type,
                "response_content_type": response_content_type,
                "content_type_family": content_family,
                "auth_context": auth_context,
                "request_body_sha256": req_sha,
                "response_body_sha256": resp_sha,
                "request_body_bytes": req_bytes,
                "response_body_bytes": resp_bytes,
                "request_body_truncated": req_trunc,
                "response_body_truncated": resp_trunc,
                "request_body_artifact_path": req_path,
                "response_body_artifact_path": resp_path,
                "request_headers": dict(req.headers),
                "response_headers": dict(resp.headers) if resp else {},
                "redaction_status": policy.get("redaction_profile") or "none",
                "host_mismatch": host_mismatch,
                "url_authority": url_authority,
                "host_header": host_header,
                "sni": sni,
                "timing_ms": timing_ms,
                "started_at": started_at,
                "request_variant_id": request_variant_id,
            }

            index_path = self._append_flow_index(root, record)
            post_record = dict(record)
            if index_path:
                post_record["index_artifact_path"] = index_path
            self._post_http_flow(entry, post_record)
        except Exception as exc:  # never crash the flow hook
            ctx.log.error(
                f"proxy_addon: full-flow capture failed for {entry.key} — {exc}"
            )


addons = [CaseCollector()]
