"""HTTP client with retry and connection reuse — replaces post/fetch_assessment_record.sh."""
from __future__ import annotations

import http.client
import json
import socket
import sys
import time
from typing import Any
from urllib.parse import urlparse


class AssessError(Exception):
    """Raised on non-recoverable API errors."""
    pass


class AssessmentClient:
    """HTTP client for the orchestrator assessment API.

    Uses http.client.HTTPConnection for keep-alive connection reuse.
    Retry: 3 attempts with 1s/2s/4s backoff on 429, 500, 502, 503, 504, connection errors.
    """

    RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
    MAX_RETRIES = 3
    BACKOFF_BASE = 1  # seconds

    def __init__(
        self,
        base_url: str,
        engagement_key: str,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.engagement_key = engagement_key
        parsed = urlparse(self.base_url)
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._scheme = parsed.scheme
        # Preserve any path prefix (e.g. /orchestrator from http://host/orchestrator)
        self._path_prefix = (parsed.path or "").rstrip("/")
        self._conn: http.client.HTTPConnection | None = None

    @property
    def _assessment_prefix(self) -> str:
        return f"{self._path_prefix}/engagements/{self.engagement_key}/assessment"

    @property
    def _engagement_prefix(self) -> str:
        return f"{self._path_prefix}/engagements/{self.engagement_key}"

    @property
    def _events_path(self) -> str:
        return f"{self._path_prefix}/engagements/{self.engagement_key}/events"

    def _get_conn(self, connect_timeout: float = 2.0) -> http.client.HTTPConnection:
        """Get or create a keep-alive connection."""
        if self._conn is not None:
            return self._conn
        if self._scheme == "https":
            self._conn = http.client.HTTPSConnection(
                self._host, self._port, timeout=connect_timeout
            )
        else:
            self._conn = http.client.HTTPConnection(
                self._host, self._port, timeout=connect_timeout
            )
        return self._conn

    def _reset_conn(self) -> None:
        """Close and discard the current connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        connect_timeout: float = 2.0,
        read_timeout: float = 10.0,
        max_retries: int | None = None,
        accept_409: bool = False,
    ) -> tuple[int, str]:
        """Execute an HTTP request with retry logic.

        ``accept_409`` lets callers treat HTTP 409 as success and receive the
        canonical row payload back. The finalize PATCH on assessment
        command-runs uses 409 as a "you raced another writer; here is the
        row that won" signal — surfacing it as ``AssessError`` would force
        callers to parse exception text to recover the canonical row.
        """
        retries = max_retries if max_retries is not None else self.MAX_RETRIES
        headers = {"Content-Type": "application/json"} if body else {}

        last_error: Exception | None = None
        for attempt in range(retries):
            try:
                conn = self._get_conn(connect_timeout)
                conn.timeout = read_timeout
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                resp_body = resp.read().decode("utf-8", errors="replace")

                if resp.status < 400:
                    return resp.status, resp_body

                if accept_409 and resp.status == 409:
                    return resp.status, resp_body

                if resp.status in self.RETRYABLE_STATUSES and attempt < retries - 1:
                    self._reset_conn()
                    time.sleep(self.BACKOFF_BASE * (2 ** attempt))
                    continue

                # Non-retryable error — report it
                if resp.status == 422:
                    msg = _format_validation_error(resp_body)
                    raise AssessError(f"HTTP 422 validation error:\n{msg}")

                raise AssessError(f"HTTP {resp.status}:\n{resp_body}")

            except AssessError:
                raise
            except (ConnectionError, socket.error, http.client.HTTPException, OSError) as exc:
                last_error = exc
                self._reset_conn()
                if attempt < retries - 1:
                    time.sleep(self.BACKOFF_BASE * (2 ** attempt))
                    continue

        raise AssessError(f"Failed after {retries} attempts: {last_error}")

    def get(self, endpoint: str) -> Any:
        """GET /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        _, body = self._request("GET", path)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    def post(self, endpoint: str, payload: dict) -> dict:
        """POST /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        _, resp_body = self._request("POST", path, body=body)
        return json.loads(resp_body)

    def patch(self, endpoint: str, payload: dict, *, accept_409: bool = False) -> dict:
        """PATCH /assessment/{endpoint}.

        When ``accept_409`` is True, an HTTP 409 from the backend is treated
        as success and the parsed body is returned. The finalize PATCH on
        command-runs uses 409 to surface the canonical row when a second
        writer races a terminal-state row — see `_patch_finalize` in
        ``lib/kali.py``.
        """
        path = f"{self._assessment_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status_code, resp_body = self._request("PATCH", path, body=body, accept_409=accept_409)
        parsed = json.loads(resp_body)
        if accept_409 and status_code == 409 and isinstance(parsed, dict):
            # Backend shape: {"detail": {"message": ..., "existing": <row>}}
            detail = parsed.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("existing"), dict):
                row = dict(detail["existing"])
                row["finalize_409"] = True
                return row
        return parsed

    def get_engagement(self, endpoint: str, query: str = "") -> Any:
        """GET /engagements/{key}/{endpoint} — non-assessment scoped (intel, activity)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        if query:
            path = f"{path}?{query}"
        _, body = self._request("GET", path)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    def post_engagement(self, endpoint: str, payload: dict) -> dict:
        """POST /engagements/{key}/{endpoint} — non-assessment scoped (intel, activity)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        _, resp_body = self._request("POST", path, body=body)
        try:
            return json.loads(resp_body)
        except json.JSONDecodeError:
            return {"raw": resp_body}

    # ── Round 9: dispatch / handoff / decision helpers ────────────────────

    def record_dispatch(self, payload: dict) -> dict:
        return self.post("dispatches", payload)

    def update_dispatch(self, agent_id: str, patch: dict) -> dict:
        return self.patch(f"dispatches/{agent_id}", patch)

    def get_dispatch(self, agent_id: str) -> dict | None:
        try:
            row = self.get(f"dispatches/{agent_id}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        return row if isinstance(row, dict) else None

    def list_dispatches(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatches" if not query else f"dispatches?{query}"
        rows = self.get(endpoint)
        return rows if isinstance(rows, list) else []

    # HandoffUpdate (the PATCH body) forbids `agent_id` (it's in the URL) and
    # `agent_role` (immutable once the row exists). Everything else round-trips.
    _HANDOFF_PATCHABLE_FIELDS = (
        "summary",
        "phase",
        "confidence",
        "finding_slugs",
        "coverage_gaps",
        "next_steps",
        "runtime_issues",
        "working_artifacts",
        "open_questions",
        "recommended_next_agent",
        "extras",
    )

    def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
        """POST a handoff row.

        When ``upsert`` is True, an HTTP 409 (existing row collision on
        ``(engagement, agent_id)``) is caught and re-issued as a PATCH against
        the existing row, so callers can checkpoint the same agent_id
        repeatedly without bookkeeping. Latest write wins.
        """
        if not upsert:
            return self.post("dispatch-handoffs", payload)
        try:
            return self.post("dispatch-handoffs", payload)
        except AssessError as exc:
            if "HTTP 409" not in str(exc):
                raise
            agent_id = payload.get("agent_id")
            if not agent_id:
                # Backend ought never to 409 without an agent_id, but if the
                # caller forgot it the upsert can't address the prior row.
                raise
            # PATCH only with the patchable fields; HandoffUpdate forbids
            # agent_id (URL-bound) and agent_role (immutable). Omitted fields
            # leave the existing row unchanged.
            patch = {
                k: v for k, v in payload.items()
                if k in self._HANDOFF_PATCHABLE_FIELDS
            }
            return self.update_handoff(str(agent_id), patch)

    def update_handoff(self, agent_id: str, patch: dict) -> dict:
        return self.patch(f"dispatch-handoffs/{agent_id}", patch)

    def get_handoff(self, agent_id: str) -> dict | None:
        try:
            row = self.get(f"dispatch-handoffs/{agent_id}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        return row if isinstance(row, dict) else None

    def list_handoffs(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatch-handoffs" if not query else f"dispatch-handoffs?{query}"
        rows = self.get(endpoint)
        return rows if isinstance(rows, list) else []

    def record_decision(self, payload: dict) -> dict:
        return self.post("dispatch-decisions", payload)

    def update_decision(self, decision_id: int, patch: dict) -> dict:
        return self.patch(f"dispatch-decisions/{int(decision_id)}", patch)

    def list_decisions(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatch-decisions" if not query else f"dispatch-decisions?{query}"
        rows = self.get(endpoint)
        return rows if isinstance(rows, list) else []

    def post_event(self, payload: dict) -> dict | None:
        """POST /events. Fire-and-forget: warn on failure, never raise."""
        try:
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            _, resp_body = self._request(
                "POST",
                self._events_path,
                body=body,
                connect_timeout=1.0,
                read_timeout=2.0,
                max_retries=1,
            )
            return json.loads(resp_body)
        except Exception as exc:
            print(f"warning: failed to emit event: {exc}", file=sys.stderr)
            return None

    def close(self) -> None:
        """Close the underlying connection."""
        self._reset_conn()


def _build_query(filters: dict[str, Any]) -> str:
    """Build a URL query string from a filters dict, dropping None/empty values."""
    from urllib.parse import urlencode

    cleaned: dict[str, str] = {}
    for k, v in filters.items():
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            cleaned[k] = "true" if v else "false"
        else:
            cleaned[k] = str(v)
    return urlencode(cleaned)


def _format_validation_error(resp_body: str) -> str:
    try:
        detail = json.loads(resp_body)
    except (json.JSONDecodeError, TypeError):
        return resp_body

    if isinstance(detail, dict):
        validation_items = detail.get("detail")
        if isinstance(validation_items, list):
            lines = ["Validation errors:"]
            for item in validation_items:
                if not isinstance(item, dict):
                    lines.append(f"  - {item}")
                    continue
                loc = ".".join(str(part) for part in item.get("loc", []))
                msg = str(item.get("msg", "invalid value"))
                if loc:
                    lines.append(f"  - {loc}: {msg}")
                else:
                    lines.append(f"  - {msg}")
            return "\n".join(lines)
        detail_value = detail.get("detail")
        if isinstance(detail_value, str):
            return detail_value
    return json.dumps(detail, indent=2)
