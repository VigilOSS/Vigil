"""mitmproxy addon — intercepts HTTP traffic and queues transient work items into SQLite.

Managed launch:
    aith mitmproxy start /path/to/engagement

The CLI runs this addon inside the security-research-proxy Docker container.
"""

import json
import hashlib
import sqlite3
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen

from mitmproxy import http, ctx

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

BODY_TRUNCATE = 100 * 1024  # 100 KB

SKIP_TYPES = {"image", "video", "font", "archive"}

BINARY_PREFIXES = ("image/", "video/", "audio/", "font/")

LOGIN_URL_RE = re.compile(r"(login|auth|signin|session|token)", re.IGNORECASE)

TOKEN_KEYS_RE = re.compile(r"(token|access_token|jwt)", re.IGNORECASE)
BEARER_TOKEN_KEYS_RE = re.compile(r"(access_token|id_token|jwt|token)", re.IGNORECASE)

# Maps file extensions / content-type fragments to a classification label.
# Order matters — first match wins (highest priority first).
_EXT_GRAPHQL = {"/graphql"}
_EXT_WS = set()  # detected via Upgrade header
_EXT_API = {"/api/", "/rest/", "/v1/", "/v2/", "/v3/"}
_EXT_UPLOAD_CT = {"multipart/form-data"}
_EXT_FORM_CT = {"application/x-www-form-urlencoded"}
_EXT_JS = {".js", ".mjs", ".cjs"}
_EXT_CSS = {".css"}
_EXT_PAGE = {".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}
_EXT_DATA = {".json", ".xml", ".csv", ".yaml", ".yml"}
_EXT_IMAGE = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp"}
_EXT_VIDEO = {".mp4", ".webm", ".avi", ".mov", ".flv"}
_EXT_FONT = {".woff", ".woff2", ".ttf", ".eot", ".otf"}
_EXT_ARCHIVE = {".zip", ".gz", ".tar", ".rar", ".7z", ".bz2"}

# Dynamic path-segment patterns
_DYNAMIC_RE = re.compile(
    r"(?:^[0-9]+$"  # numeric ID
    r"|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"  # UUID
    r"|^[0-9a-f]{24,}$)",  # hex 24+ chars (e.g. MongoDB ObjectId)
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Addon
# ---------------------------------------------------------------------------


class CaseCollector:
    """Collects HTTP request/response pairs and stores them in the transient work buffer."""

    def __init__(self):
        self.db: sqlite3.Connection | None = None
        self.scope: list[str] = []
        self.engagement_dir: str = ""
        self.engagement_key: str = ""
        self.orchestrator_base_url = os.getenv("ORCHESTRATOR_BASE_URL", "").rstrip("/")
        self.backend_warning_emitted = False

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
            "engagement_dir", str, "", "Path to engagement directory"
        )
        loader.add_option(
            "engagement_key", str, "", "Engagement key for backend API (defaults to basename of engagement_dir)"
        )

    def configure(self, updates):
        if "engagement_key" in updates:
            self.engagement_key = ctx.options.engagement_key
        if "engagement_dir" in updates:
            self.engagement_dir = ctx.options.engagement_dir
            if self.engagement_dir:
                if not self.engagement_key:
                    self.engagement_key = os.environ.get("ENGAGEMENT_KEY", "") or os.path.basename(self.engagement_dir)
                self._init_db()
                self._load_scope()

    # -- initialisation -----------------------------------------------------

    def _init_db(self):
        db_path = os.path.join(self.engagement_dir, "cases.db")
        try:
            self.db = sqlite3.connect(db_path, check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS work_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    queue_key TEXT NOT NULL,
                    request_variant_id INTEGER,
                    service_id INTEGER,
                    coverage_item_id INTEGER,
                    auth_context TEXT NOT NULL DEFAULT 'anonymous',
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    url_path TEXT NOT NULL,
                    query_params TEXT,
                    body_params TEXT,
                    path_params TEXT,
                    cookie_params TEXT,
                    headers TEXT,
                    body TEXT,
                    content_type TEXT,
                    content_length INTEGER,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_size INTEGER,
                    response_snippet TEXT,
                    type TEXT NOT NULL DEFAULT 'unknown',
                    source TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    assigned_agent TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now')),
                    consumed_at TEXT,
                    params_key_sig TEXT,
                    UNIQUE(queue_key)
                )"""
            )
            ctx.log.info(f"proxy_addon: connected to {db_path}")
        except sqlite3.OperationalError as exc:
            ctx.log.error(f"proxy_addon: cannot open DB — {exc}")
            self.db = None

    def _load_scope(self):
        scope_path = os.path.join(self.engagement_dir, "scope.json")
        try:
            with open(scope_path, "r") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                raw_hosts = []
                for key in ("hosts", "scope_hosts", "scope"):
                    value = data.get(key, [])
                    if isinstance(value, list):
                        raw_hosts.extend(value)
                hostname = data.get("hostname")
                if isinstance(hostname, str) and hostname:
                    raw_hosts.append(hostname)
                self.scope = list(dict.fromkeys(
                    item for item in raw_hosts if isinstance(item, str) and item
                ))
            else:
                self.scope = []
            ctx.log.info(f"proxy_addon: loaded {len(self.scope)} scope entries")
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            ctx.log.warn(f"proxy_addon: cannot load scope — {exc}")
            self.scope = []

    def _backend_configured(self) -> bool:
        return bool(self.orchestrator_base_url and self.engagement_dir)

    def _warn_backend_unavailable(self):
        if not self.backend_warning_emitted:
            ctx.log.error(
                "proxy_addon: orchestrator assessment backend is not configured; "
                "captured traffic will not be queued"
            )
            self.backend_warning_emitted = True

    # -- checks -------------------------------------------------------------

    def _is_in_scope(self, hostname: str) -> bool:
        if not self.scope:
            return False
        hostname = hostname.lower()
        for pattern in self.scope:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                suffix = pattern[1:]  # e.g. ".example.com"
                if hostname == pattern[2:] or hostname.endswith(suffix):
                    return True
            else:
                if hostname == pattern:
                    return True
        return False

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
        ct = (content_type or "").lower()
        path_lower = path.lower()

        # Strip query string for extension matching
        base_path = path_lower.split("?")[0]

        # graphql
        if any(seg in base_path for seg in _EXT_GRAPHQL):
            return "graphql"

        # websocket
        if req_headers.get("upgrade", "").lower() == "websocket":
            return "websocket"

        # api — path heuristic or JSON content-type on non-page paths
        if any(seg in base_path for seg in _EXT_API):
            return "api"
        if "application/json" in ct and method in ("POST", "PUT", "PATCH", "DELETE"):
            return "api"

        # upload
        if any(seg in ct for seg in _EXT_UPLOAD_CT):
            return "upload"

        # form
        if any(seg in ct for seg in _EXT_FORM_CT):
            return "form"

        # static asset types by extension
        _, ext = os.path.splitext(base_path)
        if ext in _EXT_JS:
            return "javascript"
        if ext in _EXT_CSS:
            return "stylesheet"
        if ext in _EXT_PAGE or "text/html" in ct:
            return "page"
        if ext in _EXT_DATA or "application/json" in ct or "text/xml" in ct or "application/xml" in ct:
            return "data"
        if ext in _EXT_IMAGE or ct.startswith("image/"):
            return "image"
        if ext in _EXT_VIDEO or ct.startswith("video/"):
            return "video"
        if ext in _EXT_FONT or ct.startswith("font/"):
            return "font"
        if ext in _EXT_ARCHIVE:
            return "archive"

        return "unknown"

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

    def _apply_body_policy(self, body: bytes | None, content_type: str) -> str | None:
        if not body:
            return None
        ct = (content_type or "").lower()
        # Skip binary types entirely
        if any(ct.startswith(p) for p in BINARY_PREFIXES):
            return None
        # Only save text-ish bodies
        saveable = (
            "json" in ct
            or "form-urlencoded" in ct
            or "html" in ct
            or "xml" in ct
            or "text/" in ct
        )
        if not saveable:
            return None
        text = body[:BODY_TRUNCATE].decode("utf-8", errors="replace")
        return text

    def _post_request_observation(
        self,
        *,
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
            f"{self.orchestrator_base_url}/engagements/{self.engagement_key}/assessment/request-observations",
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
            ctx.log.error(f"proxy_addon: backend write failed for {url} — {exc}")
            return None

        request_variant = data.get("request_variant") if isinstance(data, dict) else None
        if not isinstance(request_variant, dict) or not request_variant.get("id"):
            ctx.log.error(f"proxy_addon: backend response missing request_variant.id for {url}")
            return None
        return data

    def _load_auth_state(self) -> dict:
        auth_path = os.path.join(self.engagement_dir, "auth.json")
        if not os.path.exists(auth_path):
            return {}
        try:
            with open(auth_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _request_auth_context(self, req_headers_dict: dict, params: dict) -> str:
        auth_state = self._load_auth_state()
        configured_context = str(auth_state.get("auth_context") or "").strip()
        has_authorization = bool(req_headers_dict.get("authorization") or req_headers_dict.get("Authorization"))
        cookie_values = params.get("cookie_params") or "{}"
        has_cookies = False
        try:
            has_cookies = bool(json.loads(cookie_values))
        except (TypeError, json.JSONDecodeError):
            has_cookies = False

        if has_authorization or has_cookies:
            if configured_context and configured_context != "anonymous":
                return configured_context
            return "authenticated"
        return "anonymous"

    # -- auth capture ---------------------------------------------------------

    def _capture_auth(self, flow: http.HTTPFlow):
        """Capture auth material from every in-scope response.

        Collects:
        - Set-Cookie response headers (per host)
        - Request Cookie header (per host, via mitmproxy's parsed cookies)
        - Bearer/token values from login-like JSON responses

        Stores per-host cookies in ``host_cookies`` (list of dicts) and keeps
        the flat ``cookies`` dict populated with the primary scope target's
        cookies for backward compatibility with downstream consumers.
        """
        req = flow.request
        resp = flow.response
        if not resp or (resp.status_code and resp.status_code >= 400):
            return

        parsed = urlparse(req.pretty_url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return

        auth_path = os.path.join(self.engagement_dir, "auth.json")

        # Load existing auth.json
        auth_data: dict = {}
        if os.path.exists(auth_path):
            try:
                with open(auth_path, "r", encoding="utf-8") as fh:
                    auth_data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                auth_data = {}

        auth_data.setdefault("mode", "proxy_capture")
        auth_data.setdefault("use_for_requests", True)
        auth_data.setdefault("auth_context", "authenticated")
        auth_data.setdefault("headers", {})
        auth_data.setdefault("cookies", {})
        host_cookies_list: list[dict] = auth_data.get("host_cookies", [])
        if not isinstance(host_cookies_list, list):
            host_cookies_list = []

        # Build lookup: hostname -> index in host_cookies_list
        host_index: dict[str, int] = {}
        for idx, entry in enumerate(host_cookies_list):
            if isinstance(entry, dict) and isinstance(entry.get("host"), str):
                host_index[entry["host"].lower()] = idx

        updated = False

        # -- 1. Collect request cookies (mitmproxy parses them correctly) ------
        req_cookies: dict[str, str] = {}
        for k, v in req.cookies.items():
            req_cookies[k] = v

        # -- 2. Collect Set-Cookie response headers ----------------------------
        resp_cookies: dict[str, str] = {}
        set_cookies = resp.headers.get_all("set-cookie")
        if set_cookies:
            for sc in set_cookies:
                name_val = sc.split(";")[0]
                if "=" in name_val:
                    k, v = name_val.split("=", 1)
                    resp_cookies[k.strip()] = v.strip()

        # Merge: response Set-Cookie wins over request Cookie
        merged: dict[str, str] = {}
        merged.update(req_cookies)
        merged.update(resp_cookies)

        if merged:
            if hostname in host_index:
                existing = host_cookies_list[host_index[hostname]].get("cookies", {})
                if not isinstance(existing, dict):
                    existing = {}
                existing.update(merged)
                host_cookies_list[host_index[hostname]]["cookies"] = existing
            else:
                host_cookies_list.append({"host": hostname, "cookies": merged})
                host_index[hostname] = len(host_cookies_list) - 1
            updated = True

        # -- 3. Token extraction from login-like JSON responses ----------------
        if req.method == "POST" and LOGIN_URL_RE.search(req.pretty_url):
            resp_body = self._safe_content(resp)
            if resp_body:
                try:
                    body_json = json.loads(resp_body)
                    if isinstance(body_json, dict):
                        for key in list(body_json.keys()):
                            if TOKEN_KEYS_RE.search(key):
                                token_value = body_json[key]
                                auth_data.setdefault("tokens", {})[key] = token_value
                                if (
                                    isinstance(token_value, str)
                                    and token_value
                                    and BEARER_TOKEN_KEYS_RE.search(key)
                                ):
                                    auth_data.setdefault("headers", {})
                                    if "Authorization" not in auth_data["headers"]:
                                        bearer_value = (
                                            token_value
                                            if token_value.lower().startswith("bearer ")
                                            else f"Bearer {token_value}"
                                        )
                                        auth_data["headers"]["Authorization"] = bearer_value
                                updated = True
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        # -- 4. Write auth.json ------------------------------------------------
        if updated:
            # Flat cookies = primary scope target's cookies (first scope host)
            primary_host = (self.scope[0].lstrip("*.") if self.scope else "").lower()
            flat_cookies: dict[str, str] = {}
            for entry in host_cookies_list:
                h = (entry.get("host") or "").lower()
                entry_cookies = entry.get("cookies", {})
                if not isinstance(entry_cookies, dict):
                    continue
                if h == primary_host or (primary_host and h.endswith("." + primary_host)):
                    flat_cookies.update(entry_cookies)

            auth_data["cookies"] = flat_cookies
            auth_data["host_cookies"] = host_cookies_list
            auth_data["state"] = "available" if flat_cookies else auth_data.get("state", "missing")
            auth_data["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                with open(auth_path, "w", encoding="utf-8") as fh:
                    json.dump(auth_data, fh, indent=2)
                ctx.log.info(
                    f"proxy_addon: updated auth.json — "
                    f"{len(flat_cookies)} flat cookies, "
                    f"{len(host_cookies_list)} hosts"
                )
            except OSError as exc:
                ctx.log.warn(f"proxy_addon: cannot write auth.json — {exc}")

    # -- DB insert ----------------------------------------------------------

    def _insert_case(
        self,
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
        response_status: int,
        response_headers: str,
        response_size: int,
        response_snippet: str | None,
        case_type: str,
        status: str,
        params_key_sig: str,
    ):
        if not self.db:
            return
        try:
            self.db.execute(
                """INSERT OR IGNORE INTO work_items (
                    queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                    method, url, url_path,
                    query_params, body_params, path_params, cookie_params,
                    headers, body, content_type, content_length,
                    response_status, response_headers, response_size, response_snippet,
                    type, source, status, params_key_sig
                ) VALUES (
                    ?, ?, ?, NULL, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, 'proxy', ?, ?
                )""",
                (
                    queue_key,
                    request_variant_id,
                    service_id,
                    auth_context,
                    method,
                    url,
                    url_path,
                    params.get("query_params"),
                    params.get("body_params"),
                    params.get("path_params"),
                    params.get("cookie_params"),
                    headers,
                    body,
                    content_type,
                    content_length,
                    response_status,
                    response_headers,
                    response_size,
                    response_snippet,
                    case_type,
                    status,
                    params_key_sig,
                ),
            )
            self.db.commit()
        except sqlite3.OperationalError as exc:
            ctx.log.warn(f"proxy_addon: DB busy/error — {exc}")

    # -- main entry point ---------------------------------------------------

    def response(self, flow: http.HTTPFlow):
        """Called by mitmproxy for every completed request/response pair."""
        if not self.db:
            return

        req = flow.request
        resp = flow.response
        if not resp:
            return

        parsed = urlparse(req.pretty_url)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"

        # Scope check
        if not self._is_in_scope(hostname):
            return

        # Noise filter
        if self._is_noise(hostname, req.pretty_url):
            return

        # Auth capture (side-effect: writes auth.json with per-host cookies)
        self._capture_auth(flow)

        # Extract parameters
        params = self._extract_params(flow)

        # Request headers as JSON
        req_headers_dict = dict(req.headers)
        req_headers_json = json.dumps(req_headers_dict)
        auth_context = self._request_auth_context(req_headers_dict, params)

        # Prefer response content type for classification/storage. Request content
        # type is often empty for GETs and would misclassify normal pages as unknown.
        content_type = resp.headers.get("content-type", "") or req.headers.get("content-type", "") or ""
        raw_req_body = self._safe_content(req)
        content_length = len(raw_req_body)

        # Classification
        case_type = self._classify_type(req.method, req.pretty_url, content_type, req_headers_dict)

        # Body save policy
        saved_body = self._apply_body_policy(raw_req_body, content_type)

        # Response info
        response_status = resp.status_code
        resp_headers_json = json.dumps(dict(resp.headers))
        resp_body = self._safe_content(resp)
        response_size = len(resp_body)

        # Response snippet: first 512 bytes of text responses
        response_snippet = None
        resp_ct = (resp.headers.get("content-type", "") or "").lower()
        if resp_body and not any(resp_ct.startswith(p) for p in BINARY_PREFIXES):
            response_snippet = resp_body[:512].decode("utf-8", errors="replace")

        # Dedup signature
        params_key_sig = self._generate_sig(
            params.get("query_params"), params.get("body_params")
        )

        # Status
        status = "skipped" if case_type in SKIP_TYPES else "pending"

        assessment_record = self._post_request_observation(
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

        # Insert
        self._insert_case(
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
            response_status=response_status,
            response_headers=resp_headers_json,
            response_size=response_size,
            response_snippet=response_snippet,
            case_type=case_type,
            status=status,
            params_key_sig=params_key_sig,
        )


addons = [CaseCollector()]
