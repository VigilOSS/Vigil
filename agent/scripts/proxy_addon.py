"""mitmproxy addon — intercepts HTTP traffic and routes each flow to the
matching engagement's scope, credential store, cases.db, and orchestrator backend.

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
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen

from mitmproxy import http, ctx

from assess.lib.classify import classify_type
from assess.lib.db import db_init, db_insert_work_item

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
# both data sources at the same depth. The cap exists so cases.db rows stay
# small; truncation is surfaced explicitly via `response_truncated`.

BINARY_PREFIXES = ("image/", "video/", "audio/", "font/")

LOGIN_URL_RE = re.compile(r"(login|auth|signin|session|token)", re.IGNORECASE)

TOKEN_KEYS_RE = re.compile(r"(token|access_token|jwt)", re.IGNORECASE)
BEARER_TOKEN_KEYS_RE = re.compile(r"(access_token|id_token|jwt|token)", re.IGNORECASE)

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
    v = v.strip()
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

    The addon keeps one ``EngagementEntry`` per active engagement and looks one
    up by hostname on every captured response. ``db`` is lazily populated by
    ``CaseCollector`` rather than at registry-load time so we never open a
    SQLite handle for an engagement that never sees traffic.
    """

    key: str
    root: Path
    scope_patterns: list[str]
    out_of_scope_patterns: list[str] = field(default_factory=list)
    scope_priority: int = 0
    updated_at: str = ""
    db: sqlite3.Connection | None = None


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
        with self._registry_lock:
            for entry in self.registry.values():
                if entry.db is not None:
                    try:
                        entry.db.close()
                    except Exception:
                        pass
                    entry.db = None

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
                # Reuse the existing entry (and its open DB handle + auth lock)
                # so a registry reload does not flap connections for engagements
                # that are still active.
                existing = self.registry.get(entry.key)
                if existing is not None:
                    existing.root = entry.root
                    existing.scope_patterns = entry.scope_patterns
                    existing.out_of_scope_patterns = entry.out_of_scope_patterns
                    existing.scope_priority = entry.scope_priority
                    existing.updated_at = entry.updated_at
                    new_registry[entry.key] = existing
                else:
                    new_registry[entry.key] = entry
            removed = set(self.registry) - set(new_registry)
            for key in removed:
                old = self.registry[key]
                if old.db is not None:
                    try:
                        old.db.close()
                    except Exception:
                        pass
                    # Clear the cached connection so a flow still holding a
                    # reference to the dropped entry re-opens (or no-ops via
                    # ``_open_db_for``) instead of writing through a closed
                    # handle.
                    old.db = None
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
                # engagement, etc.). Skipping here keeps `_open_db_for` from
                # attempting `db_path.touch()` against a missing parent and
                # crashing the flow hook.
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
            entries.append(
                EngagementEntry(
                    key=key,
                    root=root,
                    scope_patterns=scope_patterns,
                    out_of_scope_patterns=out_of_scope_patterns,
                    scope_priority=scope_priority,
                    updated_at=updated_at,
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
            entries.append(
                EngagementEntry(
                    key=engagement_dir.name,
                    root=engagement_dir,
                    scope_patterns=scope_patterns,
                    out_of_scope_patterns=out_of_scope_patterns,
                    scope_priority=scope_priority,
                    updated_at=updated_at,
                )
            )
        return entries

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
                    "scope_priority": entry.scope_priority,
                    "updated_at": entry.updated_at,
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

    def _match_engagement(self, hostname: str) -> EngagementEntry | None:
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
            return None
        chosen = best[3]
        # Out-of-scope carve-out: a host admitted by an in-scope wildcard but
        # matching ANY of the engagement's out_of_scope patterns must not be
        # captured or routed. The denylist wins — drop the flow entirely.
        # NOTE: ``_scope_match_score`` understands only literal and ``*.``
        # wildcard patterns, so a CIDR or URL out_of_scope entry is inert HERE
        # (same limitation the in-scope match path has — the proxy routes by
        # hostname and never resolves an IP). CIDR/URL carve-outs are still
        # honored on the IP-aware surfaces (filter-scope / dispatch gate /
        # ingest-spec) via ``scope.host_admitted``.
        for pattern in chosen.out_of_scope_patterns:
            if _scope_match_score(pattern, hostname) is not None:
                suppress_key = (hostname, chosen.key)
                if suppress_key not in self._routed_log_seen:
                    self._routed_log_seen.add(suppress_key)
                    ctx.log.info(
                        f"proxy_addon: suppressed {hostname} — matches out_of_scope "
                        f"carve-out '{pattern}' for engagement {chosen.key}"
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
        flag the cases.db row, never silently dropping bytes.
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
    ) -> dict | None:
        if not self._backend_configured():
            self._warn_backend_unavailable()
            return None

        parsed = urlparse(url)
        ct_lower = (content_type or "").lower()
        content_family = "unknown"
        if "json" in ct_lower:
            content_family = "json"
        elif "javascript" in ct_lower:
            content_family = "javascript"
        elif "xml" in ct_lower:
            content_family = "xml"
        elif "text/" in ct_lower:
            content_family = "text"
        elif "html" in ct_lower:
            content_family = "html"

        payload = {
            "url": url,
            "method": method,
            "auth_context": auth_context,
            "content_type_family": content_family,
            "query_schema": json.loads(params.get("query_params") or "{}"),
            "body_schema": json.loads(params.get("body_params") or "{}"),
            "path_schema": json.loads(params.get("path_params") or "{}"),
            "cookie_schema": json.loads(params.get("cookie_params") or "{}"),
            "header_schema": {},
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
        """POST a captured credential delta to the backend, which merges it into
        the engagement's ``default`` identity (host-cookie buckets, flat cookie
        recompute, header/token merge). Mirrors ``_post_request_observation``.
        """
        if not self._backend_configured():
            self._warn_backend_unavailable()
            return
        payload = {
            "identity_name": "default",
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

    def _capture_auth(self, entry: EngagementEntry, flow: http.HTTPFlow):
        """Capture auth material from a flow into the centralized credential
        store (the ``default`` identity).

        The addon extracts the per-flow delta (this host's request + Set-Cookie
        cookies, any bearer token / Authorization header from a login response)
        and POSTs it; the backend owns the merge (host buckets, flat cookies,
        header/token accumulation). mitmproxy hooks run single-threaded so
        captures serialize naturally — no client-side lock needed.
        """
        req = flow.request
        resp = flow.response
        if not resp or (resp.status_code and resp.status_code >= 400):
            return

        parsed = urlparse(req.pretty_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return

        # -- 1. Request cookies (mitmproxy parses them correctly) ------------
        merged: dict[str, str] = dict(req.cookies.items())

        # -- 2. Set-Cookie response headers ----------------------------------
        set_cookies = resp.headers.get_all("set-cookie")
        if set_cookies:
            for sc in set_cookies:
                # Skip logout/expiry deletions — a logout must NEVER overwrite
                # a stored live session cookie with a deletion sentinel.
                # F5/APM sends ``MRHSession=deleted`` on CMS logout; RFC 6265
                # deletions use Max-Age=0 or an Expires in the past.
                if _is_deletion_set_cookie(sc):
                    ctx.log.debug(
                        f"proxy_addon: skipping deletion Set-Cookie: {sc.split(';')[0]!r}"
                    )
                    continue
                name_val = sc.split(";")[0]
                if "=" in name_val:
                    k, v = name_val.split("=", 1)
                    merged[k.strip()] = v.strip()

        # -- 3. Token extraction from login-like JSON responses --------------
        tokens: dict[str, str] = {}
        headers: dict[str, str] = {}
        if req.method == "POST" and LOGIN_URL_RE.search(req.pretty_url):
            resp_body = self._safe_content(resp)
            if resp_body:
                try:
                    body_json = json.loads(resp_body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body_json = None
                if isinstance(body_json, dict):
                    for key in list(body_json.keys()):
                        if not TOKEN_KEYS_RE.search(key):
                            continue
                        token_value = body_json[key]
                        # The capture endpoint types tokens as str->str; a
                        # non-string token-keyed field (null / number / nested)
                        # would 422 the whole POST and silently drop the
                        # capture, so skip non-string values.
                        if not isinstance(token_value, str) or not token_value:
                            continue
                        tokens[key] = token_value
                        if (
                            BEARER_TOKEN_KEYS_RE.search(key)
                            and "Authorization" not in headers
                        ):
                            headers["Authorization"] = (
                                token_value
                                if token_value.lower().startswith("bearer ")
                                else f"Bearer {token_value}"
                            )

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

    # -- DB insert ----------------------------------------------------------

    def _open_db_for(self, entry: EngagementEntry) -> sqlite3.Connection | None:
        with self._registry_lock:
            if entry.db is not None:
                return entry.db
            db_path = entry.root / "cases.db"
            try:
                if not entry.root.is_dir():
                    # Root vanished between registry load and the next flow
                    # (deleted engagement, unmounted volume). Returning None
                    # cleanly lets the flow hook continue without writing
                    # rather than raising up through mitmproxy.
                    ctx.log.warn(
                        f"proxy_addon: engagement root {entry.root} is missing — skipping DB open for {entry.key}"
                    )
                    return None
                if not db_path.exists():
                    db_path.touch()
                db_init(str(db_path))
                connection = sqlite3.connect(str(db_path), check_same_thread=False)
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA busy_timeout=5000")
                entry.db = connection
                ctx.log.info(f"proxy_addon: opened {db_path} for engagement {entry.key}")
                return connection
            except (sqlite3.OperationalError, OSError) as exc:
                # OSError covers FileNotFoundError (root deleted between
                # registry load and open), PermissionError (read-only mount),
                # and bind-mount surprises. Log and degrade — losing one
                # capture is better than aborting the whole flow hook.
                ctx.log.error(
                    f"proxy_addon: cannot open DB for engagement {entry.key} — {exc.__class__.__name__}: {exc}"
                )
                return None

    def _drop_db_for(self, entry: EngagementEntry) -> None:
        """Close and forget the cached connection so the next _open_db_for
        re-opens a fresh one.

        A long-lived SQLite connection can stop persisting writes after the
        underlying cases.db file is checkpointed, VACUUMed, or replaced (new
        inode) out from under it — e.g. an external ``.recover`` rebuild or a
        WAL truncate from another process. The connection keeps accepting
        execute()/commit() without raising, but the rows land in a detached/old
        file image that other readers never see. This was observed in
        production: the proxy held a connection for ~2h while work_items in the
        engagement DB silently stopped growing even though flows were arriving
        and the backend POSTs succeeded. Dropping the connection here lets the
        verify-and-retry path in _insert_case recover without a manual restart.
        """
        with self._registry_lock:
            if entry.db is not None:
                try:
                    entry.db.close()
                except sqlite3.Error:
                    pass
                entry.db = None

    @staticmethod
    def _row_persisted(db_path: str, queue_key: str) -> bool:
        """Confirm a just-written row is visible to an INDEPENDENT reader.

        Staleness is defined relative to what *other* processes see: the
        backend and CLI read cases.db through fresh short-lived connections, so
        the only probe that reliably detects a wedged writer is one that also
        reads through a fresh connection. A read-back on the *writing*
        connection would still see its own (un-persisted) write when the file
        was replaced underneath it — masking exactly the failure we are trying
        to catch. In WAL mode a fresh reader sees any committed write on the
        current file, and sees nothing when the writer is stranded on a stale
        inode, which is precisely the discrimination we need. The cost is one
        file open plus one indexed lookup per capture, negligible on this path.
        """
        try:
            probe = sqlite3.connect(db_path, timeout=5.0)
        except sqlite3.Error:
            return False
        try:
            row = probe.execute(
                "SELECT 1 FROM work_items WHERE queue_key = ? LIMIT 1",
                (queue_key,),
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False
        finally:
            probe.close()

    def _insert_case(
        self,
        entry: EngagementEntry,
        *,
        queue_key: str,
        request_variant_id: int | None,
        service_id: int | None,
        auth_context: str,
        method: str,
        url: str,
        url_path: str,
        params: dict,
        headers: str,
        body: str | None,
        content_type: str,
        content_length: int,
        request_body_truncated: bool,
        response_status: int,
        response_headers: str,
        response_size: int,
        response_snippet: str | None,
        response_truncated: bool,
        case_type: str,
        params_key_sig: str,
    ):
        db_path = str(entry.root / "cases.db")

        def _do_insert(conn: sqlite3.Connection) -> None:
            db_insert_work_item(
                db_path,
                queue_key=queue_key,
                request_variant_id=request_variant_id,
                service_id=service_id,
                coverage_item_id=None,
                auth_context=auth_context,
                method=method,
                url=url,
                url_path=url_path,
                query_params=params.get("query_params"),
                body_params=params.get("body_params"),
                path_params=params.get("path_params"),
                cookie_params=params.get("cookie_params"),
                headers=headers,
                body=body,
                content_type=content_type,
                content_length=content_length,
                request_body_truncated=request_body_truncated,
                response_status=response_status,
                response_headers=response_headers,
                response_size=response_size,
                response_snippet=response_snippet,
                response_truncated=response_truncated,
                case_type=case_type,
                source="proxy",
                params_key_sig=params_key_sig,
                connection=conn,
            )

        connection = self._open_db_for(entry)
        if connection is None:
            return
        try:
            _do_insert(connection)
        except sqlite3.OperationalError as exc:
            ctx.log.warn(f"proxy_addon: DB busy/error for {entry.key} — {exc}")
            return

        # Verify the write is visible to independent readers (see _drop_db_for
        # / _row_persisted). If it is not, the cached connection is stale:
        # drop it, reopen fresh, and retry once. INSERT OR IGNORE on
        # UNIQUE(queue_key) makes the retry idempotent.
        if self._row_persisted(db_path, queue_key):
            return
        ctx.log.warn(
            f"proxy_addon: write to {entry.key} not visible to readers "
            f"(stale connection) — reconnecting and retrying"
        )
        self._drop_db_for(entry)
        connection = self._open_db_for(entry)
        if connection is None:
            return
        try:
            _do_insert(connection)
        except sqlite3.OperationalError as exc:
            ctx.log.warn(
                f"proxy_addon: DB busy/error for {entry.key} on retry — {exc}"
            )
            return
        if not self._row_persisted(db_path, queue_key):
            ctx.log.error(
                f"proxy_addon: write to {entry.key} still not visible after "
                f"reconnect — capture lost for {url}"
            )

    # -- main entry point ---------------------------------------------------

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

        # Engagement routing replaces the old global is_in_scope: hostname →
        # the best-matching engagement, or drop if no engagement claims it.
        entry = self._match_engagement(hostname)
        if entry is None:
            return

        # Noise filter
        if self._is_noise(hostname, req.pretty_url):
            return

        # Auth capture (side-effect: POSTs captured credentials to the backend)
        self._capture_auth(entry, flow)

        params = self._extract_params(flow)

        req_headers_dict = dict(req.headers)
        req_headers_json = json.dumps(req_headers_dict)
        auth_context = self._request_auth_context(entry, req_headers_dict, params)

        # Prefer response content type for classification/storage. Request content
        # type is often empty for GETs and would misclassify normal pages as unknown.
        content_type = resp.headers.get("content-type", "") or req.headers.get("content-type", "") or ""
        raw_req_body = self._safe_content(req)
        content_length = len(raw_req_body)

        case_type = self._classify_type(req.method, path, content_type, req_headers_dict)

        saved_body, request_body_truncated = self._apply_body_policy(raw_req_body, content_type)

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

        assessment_record = self._post_request_observation(
            entry=entry,
            url=req.pretty_url,
            method=req.method,
            auth_context=auth_context,
            content_type=content_type,
            params=params,
            response_status=response_status,
            evidence_ref="proxy",
            observation_payload={
                "request_headers": req_headers_dict,
                "response_headers": dict(resp.headers),
            },
        )
        if not assessment_record:
            return

        request_variant_id = assessment_record["request_variant"]["id"]
        service = assessment_record.get("service") or {}
        service_id = service.get("id")
        queue_key = f"variant:{request_variant_id}:{case_type}"

        self._insert_case(
            entry,
            queue_key=queue_key,
            request_variant_id=request_variant_id,
            service_id=service_id,
            auth_context=auth_context,
            method=req.method,
            url=req.pretty_url,
            url_path=path,
            params=params,
            headers=req_headers_json,
            body=saved_body,
            content_type=content_type,
            content_length=content_length,
            request_body_truncated=request_body_truncated,
            response_status=response_status,
            response_headers=resp_headers_json,
            response_size=response_size,
            response_snippet=response_snippet,
            response_truncated=response_truncated,
            case_type=case_type,
            params_key_sig=params_key_sig,
        )


addons = [CaseCollector()]
