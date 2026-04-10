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

    def __init__(self, base_url: str, engagement_key: str) -> None:
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
    ) -> tuple[int, str]:
        """Execute an HTTP request with retry logic."""
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

    def patch(self, endpoint: str, payload: dict) -> dict:
        """PATCH /assessment/{endpoint}."""
        path = f"{self._assessment_prefix}/{endpoint}"
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        _, resp_body = self._request("PATCH", path, body=body)
        return json.loads(resp_body)

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
