"""Canonical full-flow HTTP store (Phase 5).

Companion to ``coverage.py``: where that module keeps the compact
request-VARIANT / request-OBSERVATION grain, this one owns the Burp-style
full-flow record the mitmproxy addon writes — one row per captured flow in
``assessment_http_flows`` plus the per-engagement ``assessment_capture_policy``.

Raw request/response BODIES never live in these rows. They are written to disk
as engagement-local artifact sidecars (``traffic/mitmproxy/bodies/<sha>.bin``)
and registered in ``assessment_artifacts``; the flow row carries only the
artifact relative_path + sha256 + byte counts + truncation flags, plus the small
header maps needed to reconstruct a HAR entry.

HAR interoperability (export/import) is a thin adapter around this store; the
canonical row — not HAR — preserves Vigil routing/auth/truncation/redaction
metadata via a ``_vigil`` custom field on each HAR entry so an export→import
round-trip reconstructs the flow metadata.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import _common
from ._common import _engagement_or_404, _fetch_all, _json_text

# Reuse the shared list caps so http-flow listing behaves like the other
# request-grain lists (variants/observations).
DEFAULT_HTTP_FLOW_LIMIT = 250
MAX_HTTP_FLOW_LIST_LIMIT = 5000

# Default per-engagement capture policy. Raw-body capture is OFF by default
# (``enabled = False``) per plan item 1 so restarting the shared proxy never
# silently changes capture behavior. ``max_body_bytes`` mirrors the addon's
# BODY_TRUNCATE (100 KB).
DEFAULT_MAX_BODY_BYTES = 102400
DEFAULT_CAPTURE_POLICY: dict[str, Any] = {
    "enabled": False,
    "capture_request_bodies": False,
    "capture_response_bodies": False,
    "max_body_bytes": DEFAULT_MAX_BODY_BYTES,
    "content_type_allow": [],
    "content_type_deny": [],
    "redaction_profile": "none",
}

# Hard cap on inlined HAR body text so an export of a large corpus can't balloon
# unbounded regardless of the per-flow byte counts recorded.
HAR_BODY_INLINE_CAP = 262144

# Columns whose bare presence in the row maps 1:1 into the serialized dict. The
# two ``*_headers_json`` columns are parsed to objects; the four INTEGER flags
# are coerced to bool.
_HEADER_JSON_COLUMNS = ("request_headers_json", "response_headers_json")
_BOOL_COLUMNS = (
    "request_body_truncated",
    "response_body_truncated",
    "host_mismatch",
)


def _bounded_http_flow_window(limit: int, offset: int) -> tuple[int, int]:
    return (
        max(1, min(int(limit), MAX_HTTP_FLOW_LIST_LIMIT)),
        max(0, int(offset)),
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _json_object_text(value: Any) -> str:
    """Serialize a header map for storage; non-dicts collapse to ``{}``."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return "{}"
        value = parsed
    if not isinstance(value, dict):
        return "{}"
    return _json_text(value)


def _parse_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _serialize_http_flow(row: Any) -> dict[str, Any]:
    data = dict(row)
    for column in _HEADER_JSON_COLUMNS:
        key = column[: -len("_json")]  # request_headers_json -> request_headers
        data[key] = _parse_json_object(data.pop(column, None))
    for column in _BOOL_COLUMNS:
        if column in data:
            data[column] = bool(data[column])
    return data


def insert_http_flow(
    engagement_id: int,
    *,
    flow_uid: str,
    method: str = "",
    scheme: str = "",
    host: str = "",
    port: int | None = None,
    url: str = "",
    path: str = "",
    response_status: int | None = None,
    request_content_type: str = "",
    response_content_type: str = "",
    content_type_family: str = "unknown",
    auth_context: str = "anonymous",
    request_body_sha256: str = "",
    response_body_sha256: str = "",
    request_body_bytes: int = 0,
    response_body_bytes: int = 0,
    request_body_truncated: bool = False,
    response_body_truncated: bool = False,
    request_body_artifact_path: str | None = None,
    response_body_artifact_path: str | None = None,
    request_headers: dict[str, Any] | None = None,
    response_headers: dict[str, Any] | None = None,
    redaction_status: str = "none",
    host_mismatch: bool = False,
    url_authority: str = "",
    host_header: str = "",
    sni: str = "",
    timing_ms: int | None = None,
    started_at: str | None = None,
    request_variant_id: int | None = None,
) -> dict[str, Any]:
    """Insert one full-flow record. Idempotent: ``INSERT OR IGNORE`` on the
    ``UNIQUE(engagement_id, flow_uid)`` key, so a retried ingest of the same
    ``flow_uid`` returns the already-stored row rather than duplicating it (and
    never silently drops the capture)."""
    engagement = _engagement_or_404(engagement_id)
    flow_uid = str(flow_uid or "").strip()
    if not flow_uid:
        # A missing flow_uid would make every capture collide on the empty
        # string; synthesize a stable one from the identifying fields rather
        # than reject (a rejection here re-creates the silent-loss class).
        flow_uid = _synthesize_flow_uid(method, url, started_at, response_status)
    with _common.get_connection() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO assessment_http_flows (
                engagement_id, request_variant_id, flow_uid, method, scheme, host,
                port, url, path, response_status, request_content_type,
                response_content_type, content_type_family, auth_context,
                request_body_sha256, response_body_sha256, request_body_bytes,
                response_body_bytes, request_body_truncated, response_body_truncated,
                request_body_artifact_path, response_body_artifact_path,
                request_headers_json, response_headers_json, redaction_status,
                host_mismatch, url_authority, host_header, sni, timing_ms, started_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                request_variant_id,
                flow_uid,
                str(method or "").upper(),
                str(scheme or ""),
                str(host or "").lower(),
                port,
                str(url or ""),
                str(path or ""),
                response_status,
                str(request_content_type or ""),
                str(response_content_type or ""),
                str(content_type_family or "unknown"),
                str(auth_context or "anonymous"),
                str(request_body_sha256 or ""),
                str(response_body_sha256 or ""),
                int(request_body_bytes or 0),
                int(response_body_bytes or 0),
                1 if request_body_truncated else 0,
                1 if response_body_truncated else 0,
                request_body_artifact_path or None,
                response_body_artifact_path or None,
                _json_object_text(request_headers),
                _json_object_text(response_headers),
                str(redaction_status or "none"),
                1 if host_mismatch else 0,
                str(url_authority or ""),
                str(host_header or ""),
                str(sni or ""),
                timing_ms,
                started_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_http_flows WHERE engagement_id = ? AND flow_uid = ?",
            (engagement.id, flow_uid),
        ).fetchone()
    assert row is not None
    return _serialize_http_flow(row)


def _synthesize_flow_uid(
    method: str, url: str, started_at: str | None, response_status: int | None
) -> str:
    material = "|".join(
        [
            str(method or ""),
            str(url or ""),
            str(started_at or ""),
            str(response_status if response_status is not None else ""),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def list_http_flows(
    engagement_id: int,
    *,
    host: str = "",
    method: str = "",
    response_status: int | None = None,
    content_type_family: str = "",
    auth_context: str = "",
    truncated: bool | None = None,
    q: str = "",
    limit: int = DEFAULT_HTTP_FLOW_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Server-side-filtered full-flow listing, newest first.

    ``q`` is a LIKE-based substring match over url/path/host (NOT FTS: the flow
    corpus is engagement-scoped and modest, and a LIKE keeps the ingest path
    trigger-free — noted as the deliberate choice). ``truncated`` filters to
    flows where either body side was truncated.
    """
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_http_flow_window(limit, offset)
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if host.strip():
        clauses.append("host = ?")
        params.append(host.strip().lower())
    if method.strip():
        clauses.append("method = ?")
        params.append(method.strip().upper())
    if response_status is not None:
        clauses.append("response_status = ?")
        params.append(int(response_status))
    if content_type_family.strip():
        clauses.append("content_type_family = ?")
        params.append(content_type_family.strip())
    if auth_context.strip():
        clauses.append("auth_context = ?")
        params.append(auth_context.strip())
    if truncated is True:
        clauses.append("(request_body_truncated = 1 OR response_body_truncated = 1)")
    elif truncated is False:
        clauses.append("(request_body_truncated = 0 AND response_body_truncated = 0)")
    if q.strip():
        like = f"%{_escape_like(q.strip())}%"
        clauses.append(
            "(url LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like])
    where = " AND ".join(clauses)
    params.extend([limit, offset])
    with _common.get_connection() as connection:
        rows = _fetch_all(
            connection,
            f"""
            SELECT *
            FROM assessment_http_flows
            WHERE {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
    return [_serialize_http_flow(row) for row in rows]


def get_http_flow(engagement_id: int, flow_uid_or_id: str | int) -> dict[str, Any] | None:
    """Fetch a single full-flow row by ``flow_uid`` (preferred) or numeric id."""
    engagement = _engagement_or_404(engagement_id)
    identifier = str(flow_uid_or_id).strip()
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_http_flows WHERE engagement_id = ? AND flow_uid = ?",
            (engagement.id, identifier),
        ).fetchone()
        if row is None and identifier.isdigit():
            row = connection.execute(
                "SELECT * FROM assessment_http_flows WHERE engagement_id = ? AND id = ?",
                (engagement.id, int(identifier)),
            ).fetchone()
    return _serialize_http_flow(row) if row is not None else None


# ── Capture policy ──────────────────────────────────────────────────────────


def _serialize_capture_policy(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "enabled": bool(data["enabled"]),
        "capture_request_bodies": bool(data["capture_request_bodies"]),
        "capture_response_bodies": bool(data["capture_response_bodies"]),
        "max_body_bytes": int(data["max_body_bytes"]),
        "content_type_allow": _parse_json_list(data["content_type_allow_json"]),
        "content_type_deny": _parse_json_list(data["content_type_deny_json"]),
        "redaction_profile": str(data["redaction_profile"] or "none"),
        "updated_at": str(data["updated_at"] or ""),
    }


def _parse_json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return []
        return [str(item) for item in parsed] if isinstance(parsed, list) else []
    return []


def normalize_capture_policy(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Coerce an arbitrary (file / API) policy dict into the canonical shape,
    filling every field from ``DEFAULT_CAPTURE_POLICY`` for missing keys. Used
    both for the capture-policy.json filesystem mirror the proxy registry reads
    and as the empty-row default."""
    source = raw if isinstance(raw, dict) else {}

    def _flag(key: str) -> bool:
        return bool(source.get(key, DEFAULT_CAPTURE_POLICY[key]))

    try:
        max_body = int(source.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES))
    except (TypeError, ValueError):
        max_body = DEFAULT_MAX_BODY_BYTES
    return {
        "enabled": _flag("enabled"),
        "capture_request_bodies": _flag("capture_request_bodies"),
        "capture_response_bodies": _flag("capture_response_bodies"),
        "max_body_bytes": max(0, max_body),
        "content_type_allow": _parse_json_list(source.get("content_type_allow", [])),
        "content_type_deny": _parse_json_list(source.get("content_type_deny", [])),
        "redaction_profile": str(source.get("redaction_profile") or "none"),
    }


def get_capture_policy(engagement_id: int) -> dict[str, Any]:
    """Return the engagement's capture policy, defaulting to OFF when unset."""
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_capture_policy WHERE engagement_id = ?",
            (engagement.id,),
        ).fetchone()
    if row is None:
        return {**DEFAULT_CAPTURE_POLICY, "updated_at": ""}
    return _serialize_capture_policy(row)


def set_capture_policy(
    engagement_id: int,
    *,
    enabled: bool | None = None,
    capture_request_bodies: bool | None = None,
    capture_response_bodies: bool | None = None,
    max_body_bytes: int | None = None,
    content_type_allow: list[str] | None = None,
    content_type_deny: list[str] | None = None,
    redaction_profile: str | None = None,
) -> dict[str, Any]:
    """Upsert the engagement's capture policy. Fields left ``None`` retain their
    current stored (or default) value, so a partial PUT never resets unrelated
    knobs."""
    engagement = _engagement_or_404(engagement_id)
    current = get_capture_policy(engagement.id)
    merged = {
        "enabled": current["enabled"] if enabled is None else bool(enabled),
        "capture_request_bodies": (
            current["capture_request_bodies"]
            if capture_request_bodies is None
            else bool(capture_request_bodies)
        ),
        "capture_response_bodies": (
            current["capture_response_bodies"]
            if capture_response_bodies is None
            else bool(capture_response_bodies)
        ),
        "max_body_bytes": (
            current["max_body_bytes"] if max_body_bytes is None else max(0, int(max_body_bytes))
        ),
        "content_type_allow": (
            current["content_type_allow"]
            if content_type_allow is None
            else [str(item) for item in content_type_allow]
        ),
        "content_type_deny": (
            current["content_type_deny"]
            if content_type_deny is None
            else [str(item) for item in content_type_deny]
        ),
        "redaction_profile": (
            current["redaction_profile"]
            if redaction_profile is None
            else str(redaction_profile or "none")
        ),
    }
    with _common.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO assessment_capture_policy (
                engagement_id, enabled, capture_request_bodies, capture_response_bodies,
                max_body_bytes, content_type_allow_json, content_type_deny_json,
                redaction_profile, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(engagement_id) DO UPDATE SET
                enabled = excluded.enabled,
                capture_request_bodies = excluded.capture_request_bodies,
                capture_response_bodies = excluded.capture_response_bodies,
                max_body_bytes = excluded.max_body_bytes,
                content_type_allow_json = excluded.content_type_allow_json,
                content_type_deny_json = excluded.content_type_deny_json,
                redaction_profile = excluded.redaction_profile,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                engagement.id,
                1 if merged["enabled"] else 0,
                1 if merged["capture_request_bodies"] else 0,
                1 if merged["capture_response_bodies"] else 0,
                int(merged["max_body_bytes"]),
                _json_text(merged["content_type_allow"]),
                _json_text(merged["content_type_deny"]),
                merged["redaction_profile"],
            ),
        )
    stored = get_capture_policy(engagement.id)
    # Mirror to capture-policy.json next to scope.json so the shared proxy addon
    # has a durable filesystem fallback (mirrors the scope.json pattern) when the
    # backend is unreachable. Best-effort: a filesystem failure must not fail the
    # authoritative DB write.
    _write_capture_policy_file(Path(engagement.engagement_root), stored)
    # The /engagements registry payload (which the proxy polls) reads the policy
    # off the filesystem mirror through a 1s-TTL list cache keyed on scope-file
    # signatures — a capture-policy.json change is NOT in that signature, so drop
    # the cache here to make the new policy visible on the next poll.
    from .. import engagements as _engagements  # local import avoids any cycle

    _engagements.clear_list_engagements_cache()
    return stored


def _write_capture_policy_file(root: Path, policy: dict[str, Any]) -> None:
    try:
        root.mkdir(parents=True, exist_ok=True)
        payload = {key: value for key, value in policy.items() if key != "updated_at"}
        target = root / "capture-policy.json"
        tmp = target.with_name(f"{target.name}.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.rename(target)
    except OSError:
        return


# ── HAR 1.2 export / import ──────────────────────────────────────────────────


def _headers_to_har(headers: dict[str, Any]) -> list[dict[str, str]]:
    return [{"name": str(name), "value": str(value)} for name, value in headers.items()]


def _har_to_headers(entries: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict) and "name" in item:
                result[str(item["name"])] = str(item.get("value", ""))
    return result


def _read_body_text(root: Path | None, artifact_path: str | None, cap: int) -> str | None:
    if not root or not artifact_path:
        return None
    candidate = (root / artifact_path).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    try:
        raw = candidate.read_bytes()[: max(0, cap)]
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def har_from_flows(
    flows: list[dict[str, Any]],
    *,
    root: Path | None = None,
    max_body_bytes: int = HAR_BODY_INLINE_CAP,
) -> dict[str, Any]:
    """Build a HAR 1.2 ``log`` object from serialized flow rows.

    When ``root`` is provided, request/response body sidecars are read from the
    engagement root and inlined into ``postData`` / ``content`` up to
    ``max_body_bytes``. Vigil-specific routing/auth/truncation/redaction fields
    ride on a ``_vigil`` custom object per entry so import can reconstruct them.
    """
    entries: list[dict[str, Any]] = []
    for flow in flows:
        request_headers = flow.get("request_headers") or {}
        response_headers = flow.get("response_headers") or {}
        timing = flow.get("timing_ms")
        request: dict[str, Any] = {
            "method": str(flow.get("method") or ""),
            "url": str(flow.get("url") or ""),
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _headers_to_har(request_headers),
            "queryString": [],
            "headersSize": -1,
            "bodySize": int(flow.get("request_body_bytes") or 0),
        }
        request_body = _read_body_text(root, flow.get("request_body_artifact_path"), max_body_bytes)
        if request_body is not None:
            request["postData"] = {
                "mimeType": str(flow.get("request_content_type") or ""),
                "text": request_body,
            }
        response: dict[str, Any] = {
            "status": int(flow["response_status"]) if flow.get("response_status") is not None else 0,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _headers_to_har(response_headers),
            "content": {
                "size": int(flow.get("response_body_bytes") or 0),
                "mimeType": str(flow.get("response_content_type") or ""),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": int(flow.get("response_body_bytes") or 0),
        }
        response_body = _read_body_text(root, flow.get("response_body_artifact_path"), max_body_bytes)
        if response_body is not None:
            response["content"]["text"] = response_body
        entries.append(
            {
                "startedDateTime": str(flow.get("started_at") or flow.get("created_at") or ""),
                "time": int(timing) if timing is not None else 0,
                "request": request,
                "response": response,
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": int(timing) if timing is not None else 0,
                    "receive": 0,
                },
                "_vigil": {
                    "flow_uid": flow.get("flow_uid"),
                    "auth_context": flow.get("auth_context"),
                    "content_type_family": flow.get("content_type_family"),
                    "scheme": flow.get("scheme"),
                    "host": flow.get("host"),
                    "port": flow.get("port"),
                    "path": flow.get("path"),
                    "host_mismatch": bool(flow.get("host_mismatch")),
                    "url_authority": flow.get("url_authority"),
                    "host_header": flow.get("host_header"),
                    "sni": flow.get("sni"),
                    "redaction_status": flow.get("redaction_status"),
                    "request_body_sha256": flow.get("request_body_sha256"),
                    "response_body_sha256": flow.get("response_body_sha256"),
                    "request_body_bytes": flow.get("request_body_bytes"),
                    "response_body_bytes": flow.get("response_body_bytes"),
                    "request_body_truncated": bool(flow.get("request_body_truncated")),
                    "response_body_truncated": bool(flow.get("response_body_truncated")),
                    "request_body_artifact_path": flow.get("request_body_artifact_path"),
                    "response_body_artifact_path": flow.get("response_body_artifact_path"),
                    "request_variant_id": flow.get("request_variant_id"),
                },
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "vigil", "version": "1.0"},
            "entries": entries,
        }
    }


def flows_from_har(har: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse a HAR ``log`` into a list of ``insert_http_flow`` kwargs dicts.

    Vigil metadata is read back from each entry's ``_vigil`` object when present
    (so an export→import round-trip is lossless for flow metadata); otherwise the
    fields are derived from the standard HAR request/response shape.
    """
    log = har.get("log") if isinstance(har, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return []
    results: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        vigil = entry.get("_vigil") if isinstance(entry.get("_vigil"), dict) else {}
        url = str(request.get("url") or "")
        method = str(request.get("method") or "")
        parsed = urlparse(url)
        scheme = str(vigil.get("scheme") or parsed.scheme or "")
        host = str(vigil.get("host") or parsed.hostname or "")
        port = vigil.get("port")
        if port is None and parsed.port is not None:
            port = parsed.port
        path = str(vigil.get("path") or parsed.path or "")
        request_headers = _har_to_headers(request.get("headers"))
        response_headers = _har_to_headers(response.get("headers"))
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        request_content_type = str(
            post_data.get("mimeType") or request_headers.get("Content-Type") or ""
        )
        response_content_type = str(
            content.get("mimeType") or response_headers.get("Content-Type") or ""
        )
        response_status = response.get("status")
        started_at = str(entry.get("startedDateTime") or "")
        timing = entry.get("time")
        flow_uid = str(vigil.get("flow_uid") or "").strip()
        if not flow_uid:
            flow_uid = _synthesize_flow_uid(method, url, started_at or str(index), response_status)
        request_body_bytes = vigil.get("request_body_bytes")
        if request_body_bytes is None:
            request_body_bytes = len(str(post_data.get("text") or "").encode("utf-8"))
        response_body_bytes = vigil.get("response_body_bytes")
        if response_body_bytes is None:
            response_body_bytes = len(str(content.get("text") or "").encode("utf-8"))
        results.append(
            {
                "flow_uid": flow_uid,
                "method": method,
                "scheme": scheme,
                "host": host,
                "port": int(port) if isinstance(port, int) else None,
                "url": url,
                "path": path,
                "response_status": int(response_status) if isinstance(response_status, int) and response_status else None,
                "request_content_type": request_content_type,
                "response_content_type": response_content_type,
                "content_type_family": str(vigil.get("content_type_family") or "unknown"),
                "auth_context": str(vigil.get("auth_context") or "anonymous"),
                "request_body_sha256": str(vigil.get("request_body_sha256") or ""),
                "response_body_sha256": str(vigil.get("response_body_sha256") or ""),
                "request_body_bytes": int(request_body_bytes or 0),
                "response_body_bytes": int(response_body_bytes or 0),
                "request_body_truncated": bool(vigil.get("request_body_truncated")),
                "response_body_truncated": bool(vigil.get("response_body_truncated")),
                "request_body_artifact_path": vigil.get("request_body_artifact_path"),
                "response_body_artifact_path": vigil.get("response_body_artifact_path"),
                "request_headers": request_headers,
                "response_headers": response_headers,
                "redaction_status": str(vigil.get("redaction_status") or "none"),
                "host_mismatch": bool(vigil.get("host_mismatch")),
                "url_authority": str(vigil.get("url_authority") or ""),
                "host_header": str(vigil.get("host_header") or ""),
                "sni": str(vigil.get("sni") or ""),
                "timing_ms": int(timing) if isinstance(timing, (int, float)) else None,
                "started_at": started_at or None,
                "request_variant_id": vigil.get("request_variant_id"),
            }
        )
    return results
