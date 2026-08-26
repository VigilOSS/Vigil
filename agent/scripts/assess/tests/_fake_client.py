"""A stateful in-memory fake for ``assess.lib.client.AssessmentClient``.

The per-engagement local SQLite ``cases.db`` ``work_items`` table was folded
into the orchestrator backend (``assessment_work_items``) and is now reached
over HTTP through ``AssessmentClient``. The assess CLI test-suite runs with NO
FastAPI backend and NO runtime container (see ``conftest.py``), so any command
that talks to the backend must be driven with this fake, injected via
``monkeypatch`` in place of ``AssessmentClient``.

``FakeAssessmentClient`` models just enough of the backend to let the host-side
CLI run end to end:

* it is a context manager (``with AssessmentClient(...) as client:``) with a
  no-op ``close()``;
* every POST is recorded on ``self.posts`` as ``(endpoint, payload)`` so a test
  can assert on the exact request bodies the command sent;
* it DERIVES a work-item row from each posted request-observation's ``work_item``
  block (mirroring the backend's ADR-0013 single-transaction derivation), keyed
  on a synthesized ``request_variant_id`` that is STABLE per ``(method, url)`` —
  so re-observing an already-admitted URL upserts the same row instead of
  minting a new one, exactly like the real backend;
* it serves reads through ``get`` / ``get_all_pages`` from ``self.rows`` (a list
  of full work-item row dicts), honoring the ``?type=`` / ``?status=`` filters
  the commands use, so a test can seed rows and drive a classify / list-clusters
  / arjun / link command against them;
* responses match the SHAPE each caller unpacks (``bulk_ingest`` records,
  ``{"count": N}`` / ``{"affected": N}`` acks, ``request_variant.id`` for
  surface linking, ...).

Tests seed rows with :meth:`add_row` / :meth:`seed_rows` and read them back
after a command runs, re-expressing the former ``cases.db`` row assertions
against the same durable state now living behind the client.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse


def host_of(url: str | None) -> str:
    """Lowercased hostname of ``url`` (empty string when absent/unparseable)."""
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").rstrip(".").lower()
    except (ValueError, TypeError):
        return ""


class FakeAssessmentClient:
    """In-memory stand-in for :class:`assess.lib.client.AssessmentClient`."""

    def __init__(self, base_url: str | None = None, engagement_key: str | None = None,
                 *args: Any, **kwargs: Any) -> None:
        self.base_url = base_url
        self.engagement_key = engagement_key
        # Raw request captures.
        self.posts: list[tuple[str, dict]] = []
        self.observations: list[dict] = []
        self.links: list[dict] = []
        # Durable work-item state (the folded-in assessment_work_items table).
        self.rows: list[dict] = []
        self._by_qk: dict[str, dict] = {}
        self._next_id = 0
        self._next_variant_id = 1000
        self._variant_ids: dict[tuple[str, str], int] = {}
        self.closed = False
        # Seedable canned responses for non-work-item reads / claim endpoints.
        self.get_responses: dict[str, Any] = {}
        self.fetch_response: dict[str, Any] = {"claimed": [], "non_routable": []}

    # -- context manager -------------------------------------------------- #
    def __enter__(self) -> "FakeAssessmentClient":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False

    def close(self) -> None:
        self.closed = True

    # -- row seeding ------------------------------------------------------ #
    def add_row(self, **fields: Any) -> dict:
        """Insert a work-item row, auto-assigning ``id`` and ``host`` if absent.

        Returns the stored row dict (mutated in place by later updates), so a
        test can hold the reference or re-fetch by id/url.
        """
        row = dict(fields)
        if row.get("id") is None:
            self._next_id += 1
            row["id"] = self._next_id
        else:
            self._next_id = max(self._next_id, int(row["id"]))
        if "host" not in row and row.get("url"):
            row["host"] = host_of(row.get("url"))
        qk = row.get("queue_key")
        if qk is not None:
            self._by_qk[str(qk)] = row
        self.rows.append(row)
        return row

    def seed_rows(self, rows: list[dict]) -> None:
        for row in rows:
            self.add_row(**row)

    def row_for_url(self, url: str) -> list[dict]:
        return [row for row in self.rows if row.get("url") == url]

    def row_by_id(self, row_id: Any) -> dict | None:
        for row in self.rows:
            if row.get("id") == row_id:
                return row
        return None

    def posts_to(self, endpoint: str) -> list[dict]:
        return [payload for ep, payload in self.posts if ep == endpoint]

    def bulk_work_items(self) -> list[dict]:
        """Every item POSTed to ``work-items/bulk`` across the run."""
        items: list[dict] = []
        for payload in self.posts_to("work-items/bulk"):
            items.extend(payload.get("items", []))
        return items

    # -- internal derivation --------------------------------------------- #
    def _variant_for(self, method: str, url: str) -> int:
        key = (method, url)
        if key not in self._variant_ids:
            self._next_variant_id += 1
            self._variant_ids[key] = self._next_variant_id
        return self._variant_ids[key]

    def _upsert_row(self, queue_key: str, fields: dict) -> dict:
        existing = self._by_qk.get(queue_key)
        if existing is not None:
            # Backend UPSERT always-refreshes the provided columns and keeps the
            # rest (id, and any column this write did not carry).
            existing.update(fields)
            return existing
        return self.add_row(**fields)

    def _derive_from_observation(self, observation: dict) -> tuple[int, dict]:
        work_item = dict(observation.get("work_item") or {})
        case_type = work_item.pop("case_type", None) or work_item.get("type") or "unknown"
        work_item.pop("type", None)
        url = observation.get("url")
        method = observation.get("method") or "GET"
        variant_id = self._variant_for(method, url)
        queue_key = f"variant:{variant_id}:{case_type}"
        derived = dict(work_item)
        derived["type"] = case_type
        derived["url"] = url
        derived["method"] = method
        derived["host"] = host_of(url)
        derived["request_variant_id"] = variant_id
        derived["queue_key"] = queue_key
        row = self._upsert_row(queue_key, derived)
        return variant_id, row

    def _observation_record(self, observation: dict) -> dict:
        variant_id, row = self._derive_from_observation(observation)
        return {
            "request_variant": {"id": variant_id},
            "service": {"id": variant_id},
            "coverage_items": list(observation.get("coverage_candidates") or []),
            "work_item": dict(row),
        }

    # -- reads ------------------------------------------------------------ #
    def get(self, endpoint: str) -> Any:
        path, _sep, query = endpoint.partition("?")
        path = path.strip("/")
        if path == "work-items":
            return self._filter_work_items(query)
        if endpoint in self.get_responses:
            return self.get_responses[endpoint]
        if path in self.get_responses:
            return self.get_responses[path]
        return []

    def get_all_pages(self, endpoint: str, *, page_size: int = 5000) -> list[Any]:
        path, _sep, query = endpoint.partition("?")
        path = path.strip("/")
        if path == "work-items":
            return self._filter_work_items(query)
        result = self.get(endpoint)
        return result if isinstance(result, list) else []

    def _filter_work_items(self, query: str) -> list[dict]:
        params = parse_qs(query)
        status = params.get("status", [None])[0]
        row_type = params.get("type", [None])[0]
        result: list[dict] = []
        for row in self.rows:
            if status is not None and str(row.get("status") or "") != status:
                continue
            if row_type is not None and str(row.get("type") or "") != row_type:
                continue
            result.append(row)
        return result

    # -- writes ----------------------------------------------------------- #
    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))

        if endpoint == "request-observations/bulk":
            records = []
            for observation in payload.get("items", []):
                self.observations.append(observation)
                records.append(self._observation_record(observation))
            return {"count": len(records), "records": records}

        if endpoint == "request-observations":
            self.observations.append(payload)
            return self._observation_record(payload)

        if endpoint == "work-items/bulk":
            items = payload.get("items", [])
            for item in items:
                queue_key = item.get("queue_key")
                if queue_key is None:
                    self.add_row(**item)
                else:
                    self._upsert_row(str(queue_key), dict(item))
            return {"count": len(items)}

        if endpoint == "work-items/update":
            updates = payload.get("updates", [])
            affected = 0
            for update in updates:
                row = self.row_by_id(update.get("id"))
                if row is None:
                    continue
                for key, value in update.items():
                    if key == "id":
                        continue
                    row[key] = value
                affected += 1
            return {"affected": affected}

        if endpoint in ("work-items/fetch", "work-items/fetch-by-priority",
                        "work-items/peek"):
            return dict(self.fetch_response)

        if endpoint == "surface-request-variant-links":
            self.links.append(payload)
            return {"id": len(self.links), **payload}

        if endpoint == "coverage-items/bulk":
            return {"count": len(payload.get("items", [])), "records": []}

        if endpoint == "coverage-items":
            return {"id": len(self.posts)}

        return {}
