"""HTTP client with retry and connection reuse — replaces post/fetch_assessment_record.sh."""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse


def default_runtime_container() -> str:
    """Shared source of truth for the runtime container name.

    Lives in this lowest-level module so every assess-lib caller
    (``kali_runtime_exec``, ``kali_jobs``, ``kali_sweep_orphans``, and the
    ``kali job`` CLI via re-export) imports the same definition rather than
    hardcoding the literal independently — which previously let vigil_cli and
    the assess lib silently drift. Mirrors ``vigil_cli.paths`` so the env
    override is honoured on both sides of the contract. Default stays
    ``"vigil"``.
    """
    return os.environ.get("VIGIL_RUNTIME_CONTAINER", "vigil")


class AssessError(Exception):
    """Raised on non-recoverable API errors."""
    pass


def require_finding_write_response(
    response: dict[str, Any], *, finding_slug: str, operation: str
) -> dict[str, Any]:
    """Validate the finding-write envelope at its command-owned boundary.

    Finding create/update/verify responses carry ``finding.slug``. A syntactically
    valid object without that identity cannot prove which row was written; the
    mutation may nevertheless be durable, so the diagnostic forbids automatic
    retry and points at the point-read used to reconcile the outcome.
    """
    finding = response.get("finding")
    returned_slug = finding.get("slug") if isinstance(finding, dict) else None
    if returned_slug != finding_slug:
        raise AssessError(
            f"{operation}: backend did not return canonical finding {finding_slug}; "
            "the write may have committed, so inspect "
            f"`vigil assess finding get {finding_slug}` and do not retry automatically"
        )
    return response


def require_artifact_write_response(
    response: dict[str, Any], *, artifact_path: str | None, operation: str
) -> dict[str, Any]:
    """Require the canonical identity of an artifact registration response."""

    artifact_id = response.get("id")
    returned_path = response.get("relative_path")
    valid_id = isinstance(artifact_id, int) and not isinstance(artifact_id, bool)
    valid_path = isinstance(returned_path, str) and bool(returned_path.strip())
    if artifact_path is not None:
        valid_path = valid_path and returned_path == artifact_path
    if not valid_id or artifact_id < 1 or not valid_path:
        raise AssessError(
            f"{operation}: backend did not return canonical artifact "
            f"id/path for {artifact_path or 'the submitted file'!r}; the write may have committed, so "
            "inspect `vigil assess artifact search --json` and do not retry "
            "automatically"
        )
    return response


def require_write_result(
    response: dict[str, Any],
    *,
    operation: str,
    expected: dict[str, Any] | None = None,
    positive_ids: tuple[str, ...] = (),
    nonnegative_counts: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate endpoint-owned identity/count fields after a durable write."""

    invalid: list[str] = []
    for field, value in (expected or {}).items():
        returned = response.get(field)
        if field not in response or type(returned) is not type(value) or returned != value:
            invalid.append(field)
    for field in positive_ids:
        value = response.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
        ):
            invalid.append(field)
    for field in nonnegative_counts:
        value = response.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            invalid.append(field)
    if invalid:
        fields = ", ".join(sorted(set(invalid)))
        raise AssessError(
            f"{operation}: backend response did not identify the durable result "
            f"({fields}); the write may have committed, so inspect durable state "
            "and do not retry automatically"
        )
    return response


def _require_read_shape(response: Any, *, endpoint: str, expected: type) -> Any:
    if not isinstance(response, expected):
        raise AssessError(
            f"GET {endpoint} returned malformed JSON: expected "
            f"{expected.__name__}, got {type(response).__name__}"
        )
    return response


_COMMAND_RUN_TERMINAL_STATUSES = frozenset(
    {"completed", "failed", "timed_out", "killed", "lost"}
)
_COMMAND_RUN_FINALIZE_CONFLICT = re.compile(
    r"^command run id=(?P<id>[1-9][0-9]*) already finalized with "
    r"status='(?P<status>[a-z_]+)'; refusing to overwrite$"
)
_COMMAND_RUN_ENDPOINT = re.compile(r"^command-runs/(?P<id>[1-9][0-9]*)$")
_JOB_ENDPOINT = re.compile(r"^jobs/(?P<id>[1-9][0-9]*)$")
_JOB_STATUSES = frozenset(
    {"queued", "running", "completed", "failed", "killed", "lost", "stop_failed"}
)
_JOB_TERMINAL_STATUSES = frozenset({"completed", "failed", "killed", "lost"})


def require_command_run_finalize_response(
    response: object,
    *,
    run_id: int,
    run_uuid: str,
    requested_status: str,
) -> dict[str, Any]:
    """Require a terminal command-run receipt bound to the attempted row."""

    valid_id = (
        isinstance(response, dict)
        and isinstance(response.get("id"), int)
        and not isinstance(response.get("id"), bool)
        and response.get("id") == run_id
    )
    returned_status = response.get("status") if isinstance(response, dict) else None
    raced = response.get("finalize_409") is True if isinstance(response, dict) else False
    valid_status = (
        isinstance(returned_status, str)
        and returned_status in _COMMAND_RUN_TERMINAL_STATUSES
        and (raced or returned_status == requested_status)
    )
    valid_uuid = (
        bool(run_uuid)
        and isinstance(response, dict)
        and response.get("run_uuid") == run_uuid
    )
    if not valid_id or not valid_status or not valid_uuid:
        raise AssessError(
            "finalize command run: backend response did not identify the exact "
            "terminal run id/uuid/status; the write may have committed, so inspect "
            f"`vigil assess command-run get {run_id}` and do not retry automatically"
        )
    return response


def _is_handoff_duplicate_conflict(exc: AssessError) -> bool:
    """Return True only for the backend's duplicate handoff 409.

    Handoff POST can also return 409 for validation failures such as
    agent_role mismatch. Those must not fall through to PATCH because PATCH
    intentionally omits immutable fields such as agent_role.
    """
    message = str(exc)
    if not message.startswith("HTTP 409"):
        return False
    _, _, body = message.partition("\n")
    candidates = [body]
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            candidates.append(detail)
        elif isinstance(detail, dict):
            nested = detail.get("message")
            if isinstance(nested, str):
                candidates.append(nested)
    return any(
        "handoff with agent_id=" in candidate
        and "already exists; PATCH to update" in candidate
        for candidate in candidates
    )


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

    def _request_raw(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        connect_timeout: float = 2.0,
        read_timeout: float = 10.0,
        max_retries: int | None = None,
        accept_409: bool = False,
    ) -> tuple[int, bytes]:
        """Execute an HTTP request with retry logic and preserve response bytes.

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
                resp_body = resp.read()

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
                    msg = _format_validation_error(
                        resp_body.decode("utf-8", errors="replace")
                    )
                    raise AssessError(f"HTTP 422 validation error:\n{msg}")

                raise AssessError(
                    f"HTTP {resp.status}:\n"
                    f"{resp_body.decode('utf-8', errors='replace')}"
                )

            except AssessError:
                raise
            except (ConnectionError, socket.error, http.client.HTTPException, OSError) as exc:
                last_error = exc
                self._reset_conn()
                if attempt < retries - 1:
                    time.sleep(self.BACKOFF_BASE * (2 ** attempt))
                    continue

        raise AssessError(
            f"Failed after {retries} attempts: {last_error}\n"
            f"{self._orchestrator_hint()}"
        )

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
        """Execute a text API request, decoding only after preserving transport bytes."""

        status_code, response_body = self._request_raw(
            method,
            path,
            body=body,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            max_retries=max_retries,
            accept_409=accept_409,
        )
        return status_code, response_body.decode("utf-8", errors="replace")

    def _orchestrator_hint(self) -> str:
        return (
            "Hint: `vigil assess` backend reads/writes require the orchestrator backend, "
            "not the Kali runtime. Run `vigil orchestrator status` or "
            f"`vigil orchestrator start`, and verify ORCHESTRATOR_BASE_URL={self.base_url!r}."
        )

    def _get_json(self, path: str) -> Any:
        status, body = self._request("GET", path)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise AssessError(
                f"GET {path} returned HTTP {status} with invalid JSON. "
                "Expected an orchestrator API response; check the API URL and route "
                "(a frontend page may have been returned).\n"
                f"{self._orchestrator_hint()}"
            ) from exc

    def _decode_write_json(self, method: str, path: str, status: int, body: str) -> Any:
        """Decode a mutation response without pretending the mutation failed.

        A successful HTTP status proves only that the server accepted the request. If
        its response cannot be read, the mutation may already be durable, so callers
        must inspect state instead of retrying and potentially duplicating it.
        """
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AssessError(
                f"{method} {path} returned HTTP {status} with invalid JSON; "
                "the write may have committed, so its outcome is uncertain. "
                "Inspect durable state and do not retry automatically.\n"
                f"{self._orchestrator_hint()}"
            ) from exc
        return parsed

    def _write_json_object(self, method: str, path: str, status: int, body: str) -> dict:
        parsed = self._decode_write_json(method, path, status, body)
        if not isinstance(parsed, dict):
            raise AssessError(
                f"{method} {path} returned HTTP {status}, but expected a JSON object; "
                "the write may have committed, so its outcome is uncertain. "
                "Inspect durable state and do not retry automatically."
            )
        if not parsed:
            raise AssessError(
                f"{method} {path} returned HTTP {status} with an empty JSON object, "
                "which does not identify a mutation result; the write may have committed, "
                "so its outcome is uncertain. Inspect durable state and do not retry "
                "automatically."
            )
        return parsed

    def _write_json_array(self, method: str, path: str, status: int, body: str) -> list:
        parsed = self._decode_write_json(method, path, status, body)
        if not isinstance(parsed, list):
            raise AssessError(
                f"{method} {path} returned HTTP {status}, but expected a JSON array; "
                "the write may have committed, so its outcome is uncertain. "
                "Inspect durable state and do not retry automatically."
            )
        return parsed

    def get(self, endpoint: str) -> Any:
        """GET /assessment/{endpoint}."""
        return self._get_json(f"{self._assessment_prefix}/{endpoint}")

    def get_bytes(self, endpoint: str) -> bytes:
        """GET exact transport bytes from an assessment download route.

        Callers own any endpoint-specific integrity check. Sent-reply downloads,
        for example, are verified by the backend and then again by the exporter.
        """

        _status, body = self._request_raw(
            "GET", f"{self._assessment_prefix}/{endpoint}"
        )
        return body

    def post(self, endpoint: str, payload: dict) -> Any:
        """POST /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status, resp_body = self._request("POST", path, body=body, max_retries=1)
        # These assessment mutations have documented top-level array responses.
        # Keep the exceptions exact instead of weakening every write to accept
        # arbitrary JSON values.
        endpoint_name = endpoint.strip("/")
        if endpoint_name in {"code/modules", "code/analysis-queue/fetch"} or re.fullmatch(
            r"assessment-runs/\d+/sources", endpoint_name
        ):
            return self._write_json_array("POST", path, status, resp_body)
        return self._write_json_object("POST", path, status, resp_body)

    def put(self, endpoint: str, payload: dict) -> dict:
        """PUT /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status, resp_body = self._request("PUT", path, body=body, max_retries=1)
        return self._write_json_object("PUT", path, status, resp_body)

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
        status_code, resp_body = self._request(
            "PATCH", path, body=body, max_retries=1, accept_409=accept_409
        )
        parsed = self._write_json_object("PATCH", path, status_code, resp_body)
        endpoint_name = endpoint.strip("/")
        command_run_match = _COMMAND_RUN_ENDPOINT.fullmatch(endpoint_name)
        job_match = _JOB_ENDPOINT.fullmatch(endpoint_name)
        if accept_409 and status_code == 409:
            # Backend shape: {"detail": {"message": ..., "existing": <row>}}
            detail = parsed.get("detail")
            existing = detail.get("existing") if isinstance(detail, dict) else None
            message = detail.get("message") if isinstance(detail, dict) else None
            match = (
                _COMMAND_RUN_FINALIZE_CONFLICT.fullmatch(message)
                if isinstance(message, str)
                else None
            )
            if command_run_match:
                requested_id = int(command_run_match.group("id"))
                valid_existing = (
                    match is not None
                    and isinstance(existing, dict)
                    and existing.get("noop") is True
                    and isinstance(existing.get("id"), int)
                    and not isinstance(existing.get("id"), bool)
                    and existing.get("id") == requested_id
                    and int(match.group("id")) == requested_id
                    and existing.get("status") == match.group("status")
                    and existing.get("status") in _COMMAND_RUN_TERMINAL_STATUSES
                )
                if not valid_existing:
                    raise AssessError(
                        f"PATCH {path} returned HTTP 409 without the documented "
                        "already-finalized canonical row; inspect durable state and "
                        "do not retry automatically"
                    )
            elif job_match:
                requested_id = int(job_match.group("id"))
                requested_status = payload.get("status")
                valid_existing = (
                    message == "job already terminal"
                    and isinstance(existing, dict)
                    and isinstance(existing.get("id"), int)
                    and not isinstance(existing.get("id"), bool)
                    and existing.get("id") == requested_id
                    and isinstance(requested_status, str)
                    and requested_status in _JOB_TERMINAL_STATUSES
                    and existing.get("status") in _JOB_TERMINAL_STATUSES
                )
                if not valid_existing:
                    raise AssessError(
                        f"PATCH {path} returned HTTP 409 without the documented "
                        "terminal job row; inspect durable state and do not retry "
                        "automatically"
                    )
            else:
                raise AssessError(
                    f"PATCH {path} returned HTTP 409, but this is not a recognized "
                    "finalize endpoint; inspect durable state and do not retry automatically"
                )
            if isinstance(existing, dict):
                row = dict(existing)
                row["finalize_409"] = True
                return row
        if job_match:
            requested_id = int(job_match.group("id"))
            returned_id = parsed.get("id")
            returned_status = parsed.get("status")
            requested_status = payload.get("status")
            valid_status = (
                isinstance(returned_status, str)
                and returned_status in _JOB_STATUSES
                and (requested_status is None or returned_status == requested_status)
            )
            if (
                not isinstance(returned_id, int)
                or isinstance(returned_id, bool)
                or returned_id != requested_id
                or not valid_status
            ):
                raise AssessError(
                    f"PATCH {path} did not return the exact job id/status; the write "
                    "may have committed, so inspect durable state and do not retry "
                    "automatically"
                )
        return parsed

    def delete(self, endpoint: str) -> dict:
        """DELETE /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        status, resp_body = self._request("DELETE", path, max_retries=1)
        return self._write_json_object("DELETE", path, status, resp_body)

    def get_engagement(self, endpoint: str, query: str = "") -> Any:
        """GET /engagements/{key}/{endpoint} — non-assessment scoped (intel, activity)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        if query:
            path = f"{path}?{query}"
        return self._get_json(path)

    def post_engagement(self, endpoint: str, payload: dict) -> dict:
        """POST /engagements/{key}/{endpoint} — non-assessment scoped (intel, activity)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status, resp_body = self._request("POST", path, body=body, max_retries=1)
        return self._write_json_object("POST", path, status, resp_body)

    def patch_engagement(self, endpoint: str, payload: dict) -> dict:
        """PATCH /engagements/{key}/{endpoint} with uncertain-write handling."""
        path = f"{self._engagement_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status, resp_body = self._request("PATCH", path, body=body, max_retries=1)
        return self._write_json_object("PATCH", path, status, resp_body)

    def put_engagement(self, endpoint: str, payload: dict) -> dict:
        """PUT /engagements/{key}/{endpoint} — non-assessment scoped (credentials)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        status, resp_body = self._request("PUT", path, body=body, max_retries=1)
        return self._write_json_object("PUT", path, status, resp_body)

    def delete_engagement(self, endpoint: str) -> None:
        """DELETE /engagements/{key}/{endpoint} — non-assessment scoped (credentials)."""
        path = f"{self._engagement_prefix}/{endpoint}"
        self._request("DELETE", path, max_retries=1)

    def record_dispatch(self, payload: dict) -> dict:
        return require_write_result(
            self.post("dispatches", payload),
            operation="record dispatch",
            expected={"agent_id": payload.get("agent_id")},
            positive_ids=("id",),
        )

    def update_dispatch(self, agent_id: str, patch: dict) -> dict:
        return require_write_result(
            self.patch(f"dispatches/{agent_id}", patch),
            operation="update dispatch",
            expected={"agent_id": agent_id},
            positive_ids=("id",),
        )

    def get_dispatch(self, agent_id: str) -> dict | None:
        try:
            row = self.get(f"dispatches/{agent_id}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        return _require_read_shape(
            row, endpoint=f"dispatches/{agent_id}", expected=dict
        )

    def list_dispatches(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatches" if not query else f"dispatches?{query}"
        rows = self.get(endpoint)
        return _require_read_shape(rows, endpoint=endpoint, expected=list)

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
        "handoff_status",
        "closed_dispatch_status",
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
            return require_write_result(
                self.post("dispatch-handoffs", payload),
                operation="record handoff",
                expected={"agent_id": payload.get("agent_id")},
                positive_ids=("id",),
            )
        try:
            return require_write_result(
                self.post("dispatch-handoffs", payload),
                operation="record handoff",
                expected={"agent_id": payload.get("agent_id")},
                positive_ids=("id",),
            )
        except AssessError as exc:
            if not _is_handoff_duplicate_conflict(exc):
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
        return require_write_result(
            self.patch(f"dispatch-handoffs/{agent_id}", patch),
            operation="update handoff",
            expected={"agent_id": agent_id},
            positive_ids=("id",),
        )

    def get_handoff(self, agent_id: str) -> dict | None:
        try:
            row = self.get(f"dispatch-handoffs/{agent_id}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        return _require_read_shape(
            row, endpoint=f"dispatch-handoffs/{agent_id}", expected=dict
        )

    def list_handoffs(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatch-handoffs" if not query else f"dispatch-handoffs?{query}"
        rows = self.get(endpoint)
        return _require_read_shape(rows, endpoint=endpoint, expected=list)

    def record_decision(self, payload: dict) -> dict:
        result = require_write_result(
            self.post("dispatch-decisions", payload),
            operation="record dispatch decision",
            expected={"kind": payload.get("kind")},
            positive_ids=("id",),
        )
        if "payload" in result and result["payload"] != payload.get("payload", {}):
            raise AssessError(
                "record dispatch decision: backend response did not identify the "
                "requested decision payload; the write may have committed, so inspect "
                "durable state and do not retry automatically"
            )
        return result

    def update_decision(self, decision_id: int, patch: dict) -> dict:
        return require_write_result(
            self.patch(f"dispatch-decisions/{int(decision_id)}", patch),
            operation="update dispatch decision",
            expected={"id": int(decision_id)},
        )

    def list_decisions(self, **filters: Any) -> list[dict]:
        query = _build_query(filters)
        endpoint = "dispatch-decisions" if not query else f"dispatch-decisions?{query}"
        rows = self.get(endpoint)
        return _require_read_shape(rows, endpoint=endpoint, expected=list)

    def list_all_decisions(self, **filters: Any) -> list[dict]:
        """Paginate ``/dispatch-decisions`` to return EVERY row matching the
        filters, not just the first page. Use for internal gating/coverage
        projections where silently dropping older decisions (the
        ``list_decisions`` default behavior, intended for paginated UI
        consumption) would let stage transitions miss previously-recorded
        scope decisions on long-running engagements.

        Pages at the backend's per-request cap (1000). Stops when a page
        returns fewer rows than the page size.
        """
        page_size = 1000
        all_rows: list[dict] = []
        offset = 0
        # Caller-supplied limit/offset would conflict with our pagination —
        # drop them so callers don't accidentally re-cap the result.
        scoped = {k: v for k, v in filters.items() if k not in ("limit", "offset")}
        while True:
            page = self.list_decisions(limit=page_size, offset=offset, **scoped)
            if not page:
                break
            all_rows.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_rows

    def get_all_pages(self, endpoint: str, *, page_size: int = 5000) -> list[Any]:
        """Paginate an assessment list endpoint to completion.

        Use this for correctness-sensitive CLI/export paths where the backend's
        default bounded list responses are intentionally tuned for UI safety.
        Caller-supplied ``limit`` or ``offset`` is respected as an explicit
        request for one page.
        """
        path, _sep, raw_query = endpoint.partition("?")
        normalized_path = path.strip("/")
        query_items = parse_qsl(raw_query, keep_blank_values=True)
        if any(key in {"limit", "offset"} for key, _value in query_items):
            rows = self.get(endpoint)
            if not isinstance(rows, list):
                raise AssessError(f"Expected list response from {endpoint!r}")
            return rows

        rows: list[Any] = []
        offset = 0
        while True:
            paged_query_items = [
                item for item in query_items if item[0] not in {"limit", "offset"}
            ]
            paged_query_items.extend(
                [("limit", str(page_size)), ("offset", str(offset))]
            )
            page = self.get(f"{normalized_path}?{urlencode(paged_query_items)}")
            if not isinstance(page, list):
                raise AssessError(f"Expected list response from {endpoint!r}")
            rows.extend(page)
            if len(page) < page_size:
                return rows
            offset += page_size

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

    def __enter__(self) -> "AssessmentClient":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False


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
