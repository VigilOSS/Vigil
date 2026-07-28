"""Backend-owned work buffer (``assessment_work_items``).

Folds the former per-engagement ``cases.db`` ``work_items`` queue into the
orchestrator ledger. The buffer is the transient queue of captured/ingested HTTP
requests awaiting triage and probing; it is now a normal engagement-scoped table
so there is a single write, a single store, and no cross-database drift.

Two write paths land here:

1. **Derivation** — ``_derive_work_item`` is called from
   ``coverage._ingest_request_observation`` inside the SAME transaction as the
   request-variant / observation / coverage-item upserts, so an ingested
   observation atomically produces its work item (no dual write).
2. **Direct bulk** — ``record_work_items_bulk`` handles rows with no
   request-variant (out-of-scope / egress-blocked skips, arjun/dns/gau-only
   producers, ``requeue``, and the one-time cases.db migration tool).

Both funnel into ``_upsert_work_item`` (ON CONFLICT(engagement_id, queue_key)),
which refreshes the request/response snapshot and FK links on re-ingest and
preserves operator-tuned rows stamped ``classifier_version='manual'``.

Scope note: when scope.json is loosened, a previously out-of-scope URL is
re-admitted through the derivation path with a NEW ``variant:*`` queue key. The
UPSERT atomically removes the superseded URL-keyed ``skipped:out-of-scope:*``
row before storing that canonical derived item, so work-buffer totals describe
current work rather than retaining a stale scope decision.

Classification (``type`` / ``priority_score`` / ``cluster_key`` / …) is computed
CLIENT-SIDE (``assess.lib.classify_buckets``, which globs the agent skills tree
at import) and passed in as facts — the backend never re-runs it. Only the
``manual`` sentinel below is duplicated here, deliberately, to protect hand-tuned
rows in the UPSERT.
"""
from __future__ import annotations

import enum
import json
from typing import Any

from ..events import _engagement_or_404
from . import _common
from ._common import _fetch_all, _parse_url


# ---------------------------------------------------------------------------
# Enums / routing constants (ported verbatim from the former agent-side
# dispatch/work_items.py so the CLI↔backend contract has one source of truth;
# guarded against drift by tests/test_work_buffer.py).
# ---------------------------------------------------------------------------
class WorkItemStatus(enum.StrEnum):
    """Lifecycle status of a buffered work item. ``StrEnum`` so members
    serialize/compare as their bare lowercase string, identical to the values
    the former cases.db stored (no migration)."""

    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    ERROR = "error"
    SKIPPED = "skipped"
    DEFERRED = "deferred"


WORK_ITEM_STATUSES = frozenset(WorkItemStatus)

# The ``manual`` classifier-version sentinel (mirrors
# classify_buckets.MANUAL_CLASSIFIER_VERSION). A ``manual`` row is hand-tuned;
# the UPSERT below never overwrites its scores on re-ingest.
MANUAL_CLASSIFIER_VERSION = "manual"

# Type→specialist routing. Ported from dispatch/work_items.py; used by
# fetch-by-priority to keep priority-mode dispatch respecting ownership.
_VULN_ANALYST_TYPES: tuple[str, ...] = (
    "api",
    "api-spec",
    "form",
    "upload",
    "graphql",
    "websocket",
    "auth_entry",
    "workflow",
    "api_route",
    "event_feed",
    "debug_config",
    "portal_session",
    "unknown",
)
_SOURCE_ANALYZER_TYPES: tuple[str, ...] = (
    "page",
    "javascript",
    "stylesheet",
    "data",
    "host_root",
    "sourcemap",
)
_ROUTED_TYPES: tuple[str, ...] = _VULN_ANALYST_TYPES + _SOURCE_ANALYZER_TYPES


def _agent_route(agent: str) -> tuple[str, ...] | None:
    """Return the work-item types this agent can safely receive (or None)."""
    normalized = (agent or "").strip().lower()
    if not normalized:
        return None
    if "vulnerability" in normalized or normalized.startswith("vuln"):
        return _VULN_ANALYST_TYPES
    if "source" in normalized:
        return _SOURCE_ANALYZER_TYPES
    return None


def _assigned_agent_for_row(row: Any) -> str | None:
    case_type = row["type"]
    if case_type in _VULN_ANALYST_TYPES:
        return "vulnerability-analyst"
    if case_type in _SOURCE_ANALYZER_TYPES:
        return "source-analyzer"
    return None


def _work_scope_filter(engagement: Any) -> tuple[list[str], list[str]] | None:
    """(allow, deny) host-set filter for ``engagement`` or None (fail OPEN).

    Lazy import of the coverage scope reader avoids the coverage<->work_buffer
    module import cycle (coverage imports ``_derive_work_item`` /
    ``mark_work_items_done`` from here). None => scope undeterminable / no
    allowlist => the caller keeps every candidate row (never drops all work).
    """
    from .coverage import _engagement_scope_admission

    return _engagement_scope_admission(engagement)


def _row_host_filtered_out(host: Any, scope: tuple[list[str], list[str]] | None) -> bool:
    """True only when the filter is known and a non-empty host is not retained.

    I-07 dataset shaping: an observed-but-not-owned co-tenant ``pending`` row
    (``otherchurch.acme-portal.example`` under a specific-host allowlist, or a host
    named in ``out_of_scope``) is excluded from every claim projection — the SAME
    predicate ``web_uncovered_high_route_hosts`` applies. A row with an EMPTY
    host fails OPEN (kept): shaping excludes KNOWN-foreign rows, it never requires
    a host and never rejects a specialist dispatch.
    """
    if scope is None:
        return False
    h = str(host or "").strip().lower()
    if not h:
        return False
    from .coverage import _host_admitted_by_scope

    return not _host_admitted_by_scope(h, scope[0], scope[1])


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _as_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _as_params_text(value: Any) -> str:
    """Params columns default to ``'{}'`` (the former schema default)."""
    if value is None or value == "":
        return "{}"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_ids(ids: Any) -> list[int]:
    out: list[int] = []
    seen: set[int] = set()
    for raw in ids or []:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


# ---------------------------------------------------------------------------
# Core UPSERT
# ---------------------------------------------------------------------------
_WORK_ITEM_INSERT_COLUMNS: tuple[str, ...] = (
    "engagement_id",
    "queue_key",
    "request_variant_id",
    "service_id",
    "coverage_item_id",
    "application_unit_id",
    "auth_context",
    "method",
    "url",
    "url_path",
    "host",
    "query_params",
    "body_params",
    "path_params",
    "cookie_params",
    "headers",
    "body",
    "content_type",
    "content_length",
    "request_body_truncated",
    "response_status",
    "response_headers",
    "response_size",
    "response_snippet",
    "response_truncated",
    "type",
    "source",
    "status",
    "params_key_sig",
    "priority_score",
    "priority_reason",
    "cluster_key",
    "terminal_reason",
    "classifier_version",
    "signals",
    "selected_by",
    "triage_rationale",
    "live_status",
)


def _upsert_work_item(connection, engagement_id: int, *, fields: dict[str, Any]) -> dict[str, Any] | None:
    """Insert or refresh one work item on the shared ``connection``.

    On conflict (same ``engagement_id, queue_key``):
      * always refresh the request/response snapshot + FK links (fixes the
        stale-empty-row hazard of the former ``INSERT OR IGNORE``);
      * refresh classifier scores UNLESS the existing row is ``manual``;
      * supersede an exact URL-keyed ``skipped:out-of-scope`` row when a
        request-variant-backed item is admitted, or re-admit it if the SAME skip
        queue key is reposted;
      * otherwise preserve the existing lifecycle status (never reset an
        in-flight ``processing``/``done`` row on re-ingest).
    """
    url = str(fields.get("url") or "")
    if not url or url == "null":
        return None
    queue_key = str(fields.get("queue_key") or "")
    if not queue_key:
        return None

    method = str(fields.get("method") or "GET")
    if method == "null":
        method = "GET"
    url_path = str(fields.get("url_path") or "")
    host = str(fields.get("host") or "")
    if not host:
        _, host, _, _ = _parse_url(url)

    values = {
        "engagement_id": engagement_id,
        "queue_key": queue_key,
        "request_variant_id": _int_or_none(fields.get("request_variant_id")),
        "service_id": _int_or_none(fields.get("service_id")),
        "coverage_item_id": _int_or_none(fields.get("coverage_item_id")),
        "application_unit_id": _int_or_none(fields.get("application_unit_id")),
        "auth_context": str(fields.get("auth_context") or "anonymous"),
        "method": method,
        "url": url,
        "url_path": url_path,
        "host": host,
        "query_params": _as_params_text(fields.get("query_params")),
        "body_params": _as_params_text(fields.get("body_params")),
        "path_params": _as_params_text(fields.get("path_params")),
        "cookie_params": _as_params_text(fields.get("cookie_params")),
        "headers": _as_text(fields.get("headers")),
        "body": fields.get("body"),
        "content_type": str(fields.get("content_type") or ""),
        "content_length": int(fields.get("content_length") or 0),
        "request_body_truncated": 1 if fields.get("request_body_truncated") else 0,
        "response_status": int(fields.get("response_status") or 0),
        "response_headers": _as_text(fields.get("response_headers")),
        "response_size": int(fields.get("response_size") or 0),
        "response_snippet": fields.get("response_snippet"),
        "response_truncated": 1 if fields.get("response_truncated") else 0,
        "type": str(fields.get("type") or "unknown"),
        "source": str(fields.get("source") or ""),
        "status": str(fields.get("status") or "pending"),
        "params_key_sig": str(fields.get("params_key_sig") or ""),
        "priority_score": int(fields.get("priority_score") or 0),
        "priority_reason": fields.get("priority_reason") or None,
        "cluster_key": fields.get("cluster_key") or None,
        "terminal_reason": fields.get("terminal_reason") or None,
        "classifier_version": fields.get("classifier_version") or None,
        "signals": fields.get("signals") or None,
        "selected_by": fields.get("selected_by") or None,
        "triage_rationale": fields.get("triage_rationale") or None,
        "live_status": fields.get("live_status") or None,
    }

    placeholders = ", ".join("?" for _ in _WORK_ITEM_INSERT_COLUMNS)
    columns = ", ".join(_WORK_ITEM_INSERT_COLUMNS)
    params = tuple(values[col] for col in _WORK_ITEM_INSERT_COLUMNS)

    if values["request_variant_id"] is not None:
        # Direct out-of-scope rows intentionally have a URL-keyed identity and no
        # request variant. Once the exact URL is admitted, its derived variant row
        # is the canonical work item; retain only that row so status/reason counts
        # do not keep reporting a scope decision that is no longer true. This runs
        # on the caller's ingest transaction, so a failed derived write rolls the
        # supersession back with the rest of the observation.
        connection.execute(
            """
            DELETE FROM assessment_work_items
            WHERE engagement_id = ?
              AND request_variant_id IS NULL
              AND status = 'skipped'
              AND terminal_reason LIKE 'skipped:out-of-scope%'
              AND url = ?
            """,
            (engagement_id, url),
        )

    connection.execute(
        f"""
        INSERT INTO assessment_work_items ({columns})
        VALUES ({placeholders})
        ON CONFLICT(engagement_id, queue_key) DO UPDATE SET
            request_variant_id = excluded.request_variant_id,
            service_id = excluded.service_id,
            coverage_item_id = COALESCE(excluded.coverage_item_id, assessment_work_items.coverage_item_id),
            application_unit_id = COALESCE(excluded.application_unit_id, assessment_work_items.application_unit_id),
            auth_context = excluded.auth_context,
            method = excluded.method,
            url = excluded.url,
            url_path = excluded.url_path,
            host = excluded.host,
            query_params = excluded.query_params,
            body_params = excluded.body_params,
            path_params = excluded.path_params,
            cookie_params = excluded.cookie_params,
            headers = excluded.headers,
            body = excluded.body,
            content_type = excluded.content_type,
            content_length = excluded.content_length,
            request_body_truncated = excluded.request_body_truncated,
            response_status = excluded.response_status,
            response_headers = excluded.response_headers,
            response_size = excluded.response_size,
            response_snippet = excluded.response_snippet,
            response_truncated = excluded.response_truncated,
            type = excluded.type,
            source = excluded.source,
            params_key_sig = excluded.params_key_sig,
            -- Preserve hand-tuned rows; refresh classifier facts otherwise.
            priority_score = CASE WHEN assessment_work_items.classifier_version = ?
                                  THEN assessment_work_items.priority_score ELSE excluded.priority_score END,
            priority_reason = CASE WHEN assessment_work_items.classifier_version = ?
                                  THEN assessment_work_items.priority_reason ELSE excluded.priority_reason END,
            cluster_key = CASE WHEN assessment_work_items.classifier_version = ?
                                  THEN assessment_work_items.cluster_key ELSE excluded.cluster_key END,
            classifier_version = CASE WHEN assessment_work_items.classifier_version = ?
                                  THEN assessment_work_items.classifier_version ELSE excluded.classifier_version END,
            -- Re-admit an out-of-scope skip when it comes back in scope; never
            -- reset an in-flight lifecycle status on plain re-ingest.
            status = CASE
                WHEN assessment_work_items.status = 'skipped'
                     AND assessment_work_items.terminal_reason LIKE 'skipped:out-of-scope%'
                THEN excluded.status
                ELSE assessment_work_items.status END,
            terminal_reason = CASE
                WHEN assessment_work_items.status = 'skipped'
                     AND assessment_work_items.terminal_reason LIKE 'skipped:out-of-scope%'
                THEN excluded.terminal_reason
                ELSE assessment_work_items.terminal_reason END,
            assigned_agent = CASE
                WHEN assessment_work_items.status = 'skipped'
                     AND assessment_work_items.terminal_reason LIKE 'skipped:out-of-scope%'
                THEN NULL ELSE assessment_work_items.assigned_agent END,
            consumed_at = CASE
                WHEN assessment_work_items.status = 'skipped'
                     AND assessment_work_items.terminal_reason LIKE 'skipped:out-of-scope%'
                THEN NULL ELSE assessment_work_items.consumed_at END,
            signals = COALESCE(excluded.signals, assessment_work_items.signals),
            selected_by = COALESCE(excluded.selected_by, assessment_work_items.selected_by),
            triage_rationale = COALESCE(excluded.triage_rationale, assessment_work_items.triage_rationale),
            live_status = COALESCE(excluded.live_status, assessment_work_items.live_status),
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            *params,
            MANUAL_CLASSIFIER_VERSION,
            MANUAL_CLASSIFIER_VERSION,
            MANUAL_CLASSIFIER_VERSION,
            MANUAL_CLASSIFIER_VERSION,
        ),
    )
    row = connection.execute(
        "SELECT * FROM assessment_work_items WHERE engagement_id = ? AND queue_key = ?",
        (engagement_id, queue_key),
    ).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------
# Derivation (called from coverage._ingest_request_observation)
# ---------------------------------------------------------------------------
def _pick_coverage_item_id(coverage_items: list[dict[str, Any]], request_variant_id: int | None) -> int | None:
    """Link the work item to the deterministic endpoint-slot coverage item;
    the full set stays reachable via ``request_variant_id``."""
    if not coverage_items:
        return None
    for item in coverage_items:
        if str(item.get("input_slot")) == "endpoint" and item.get("request_variant_id") == request_variant_id:
            return _int_or_none(item.get("id"))
    for item in coverage_items:
        if item.get("request_variant_id") == request_variant_id:
            return _int_or_none(item.get("id"))
    return _int_or_none(coverage_items[0].get("id"))


def _derive_work_item(
    connection,
    engagement_id: int,
    *,
    request_variant: dict[str, Any],
    service: dict[str, Any] | None,
    coverage_items: list[dict[str, Any]],
    auth_context: str,
    discovery_source: str,
    work_item: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Derive one work item from an ingested observation, on the shared txn.

    Returns ``None`` when the caller did not supply a ``work_item`` block (an
    internal observation POST that does not want a buffered row); real producers
    (ingest verbs, proxy) always send it, so nothing is dropped in practice.
    """
    if work_item is None:
        return None
    variant_id = _int_or_none(request_variant.get("id"))
    case_type = str(work_item.get("case_type") or "unknown")
    queue_key = str(work_item.get("queue_key") or f"variant:{variant_id}:{case_type}")

    fields = {
        "queue_key": queue_key,
        "request_variant_id": variant_id,
        "service_id": _int_or_none((service or {}).get("id")),
        "coverage_item_id": _pick_coverage_item_id(coverage_items, variant_id),
        "auth_context": auth_context,
        "method": request_variant.get("method"),
        "url": request_variant.get("canonical_url") or work_item.get("url"),
        "url_path": work_item.get("url_path") or request_variant.get("normalized_path"),
        "host": request_variant.get("host"),
        "query_params": work_item.get("query_params"),
        "body_params": work_item.get("body_params"),
        "path_params": work_item.get("path_params"),
        "cookie_params": work_item.get("cookie_params"),
        "headers": work_item.get("headers"),
        "body": work_item.get("body"),
        "content_type": work_item.get("content_type"),
        "content_length": work_item.get("content_length"),
        "request_body_truncated": work_item.get("request_body_truncated"),
        "response_status": work_item.get("response_status"),
        "response_headers": work_item.get("response_headers"),
        "response_size": work_item.get("response_size"),
        "response_snippet": work_item.get("response_snippet"),
        "response_truncated": work_item.get("response_truncated"),
        "type": case_type,
        "source": work_item.get("source") or discovery_source,
        "status": work_item.get("status") or "pending",
        "params_key_sig": work_item.get("params_key_sig"),
        "priority_score": work_item.get("priority_score"),
        "priority_reason": work_item.get("priority_reason"),
        "cluster_key": work_item.get("cluster_key"),
        "terminal_reason": work_item.get("terminal_reason"),
        "classifier_version": work_item.get("classifier_version"),
        "signals": work_item.get("signals"),
        "selected_by": work_item.get("selected_by"),
        "triage_rationale": work_item.get("triage_rationale"),
        "live_status": work_item.get("live_status"),
    }
    return _upsert_work_item(connection, engagement_id, fields=fields)


def record_work_items_bulk(engagement_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
    """Direct bulk write for rows with no request-variant (out-of-scope /
    egress skips, arjun/dns/gau-only producers, requeue, migration tool)."""
    engagement = _engagement_or_404(engagement_id)
    records: list[dict[str, Any]] = []
    with _common.get_connection() as connection:
        for item in items:
            record = _upsert_work_item(connection, engagement.id, fields=item)
            if record is not None:
                records.append(record)
    return {"engagement_id": engagement.id, "count": len(records), "records": records}


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
def work_buffer_stats(
    engagement_id: int, *, by: str = "status", status_value: str = ""
) -> dict[str, Any]:
    """Grouped counts for ``work-buffer stats``. Returns raw grouped rows; the
    CLI renders them identically to the former local-SQLite output (including
    the Python-side reason-tag rollup for ``by=reason``)."""
    engagement = _engagement_or_404(engagement_id)
    eid = engagement.id
    with _common.get_connection() as connection:
        if by == "status":
            return {
                "by": "status",
                "status_type": _fetch_all(
                    connection,
                    "SELECT status, type, COUNT(*) AS count FROM assessment_work_items "
                    "WHERE engagement_id = ? GROUP BY status, type ORDER BY status, type",
                    (eid,),
                ),
                "status": _fetch_all(
                    connection,
                    "SELECT status, COUNT(*) AS count FROM assessment_work_items "
                    "WHERE engagement_id = ? GROUP BY status ORDER BY status",
                    (eid,),
                ),
                "total": connection.execute(
                    "SELECT COUNT(*) FROM assessment_work_items WHERE engagement_id = ?", (eid,)
                ).fetchone()[0],
            }
        if by == "source":
            return {"by": "source", "rows": _fetch_all(
                connection,
                "SELECT COALESCE(source, '') AS source, status, COUNT(*) AS count "
                "FROM assessment_work_items WHERE engagement_id = ? "
                "GROUP BY source, status ORDER BY source, status",
                (eid,),
            )}
        if by == "cluster":
            return {"by": "cluster", "rows": _fetch_all(
                connection,
                "SELECT COALESCE(cluster_key, '') AS cluster_key, status, COUNT(*) AS count, "
                "MAX(priority_score) AS max_priority FROM assessment_work_items WHERE engagement_id = ? "
                "GROUP BY cluster_key, status ORDER BY max_priority DESC, cluster_key",
                (eid,),
            )}
        if by == "classifier_version":
            return {"by": "classifier_version", "rows": _fetch_all(
                connection,
                "SELECT COALESCE(classifier_version, '(none)') AS classifier_version, status, COUNT(*) AS count "
                "FROM assessment_work_items WHERE engagement_id = ? "
                "GROUP BY classifier_version, status ORDER BY classifier_version, status",
                (eid,),
            )}
        if by == "host":
            where = "engagement_id = ?"
            params: tuple[Any, ...] = (eid,)
            if status_value:
                where += " AND status = ?"
                params = (eid, status_value)
            return {"by": "host", "rows": _fetch_all(
                connection,
                "SELECT CASE WHEN host = '' THEN '(none)' ELSE host END AS host, status, COUNT(*) AS count "
                f"FROM assessment_work_items WHERE {where} "
                "GROUP BY host, status ORDER BY host, status",
                params,
            )}
        if by == "reason":
            return {"by": "reason", "rows": _fetch_all(
                connection,
                "SELECT COALESCE(terminal_reason, '') AS terminal_reason, COUNT(*) AS count "
                "FROM assessment_work_items WHERE engagement_id = ? AND status IN ('skipped', 'deferred') "
                "GROUP BY terminal_reason",
                (eid,),
            )}
    return {"by": by, "rows": []}


def peek_work_items(engagement_id: int, *, type_val: str, limit: int) -> list[dict[str, Any]]:
    """Read-only preview of pending items of a type (leaves them pending)."""
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT * FROM assessment_work_items
            WHERE engagement_id = ? AND status = 'pending' AND type = ?
            ORDER BY priority_score DESC, cluster_key, id
            LIMIT ?
            """,
            (engagement.id, type_val, int(limit)),
        )


def list_work_items(
    engagement_id: int,
    *,
    status: str | None = None,
    limit: int = 5000,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Full-row listing, offset-paginated (readers/classifiers/migration tool).

    Supports ``get_all_pages`` on the client so a large buffer is read to
    completion without an unbounded single response.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        if status:
            return _fetch_all(
                connection,
                "SELECT * FROM assessment_work_items WHERE engagement_id = ? AND status = ? "
                "ORDER BY id LIMIT ? OFFSET ?",
                (engagement.id, status, int(limit), int(offset)),
            )
        return _fetch_all(
            connection,
            "SELECT * FROM assessment_work_items WHERE engagement_id = ? ORDER BY id LIMIT ? OFFSET ?",
            (engagement.id, int(limit), int(offset)),
        )


# ---------------------------------------------------------------------------
# Claims (atomic, single backend connection)
# ---------------------------------------------------------------------------
def _stamp_liveness_sql() -> str:
    """Correlated subquery that annotates a claimed row's ``live_status`` with
    the host's current ledger verdict + age (``live@9m``), joined on the stored
    ``host`` column. Replaces the former per-fetch client→backend round trip.
    Clamped to >=0 so a skewed ``probed_at`` never emits a negative age."""
    return (
        "COALESCE((SELECT hl.reachability_class || "
        "  CASE WHEN hl.probed_at IS NOT NULL AND hl.probed_at != '' "
        "       THEN '@' || CAST(MAX(0, (julianday('now') - julianday(hl.probed_at)) * 1440) AS INTEGER) || 'm' "
        "       ELSE '' END "
        " FROM assessment_host_liveness hl "
        " WHERE hl.engagement_id = assessment_work_items.engagement_id "
        "   AND hl.host = assessment_work_items.host AND assessment_work_items.host != ''), "
        " assessment_work_items.live_status)"
    )


def fetch_work_items(engagement_id: int, *, type_val: str, limit: int, agent: str) -> dict[str, Any]:
    """Atomically claim up to ``limit`` pending items of a type for ``agent``."""
    engagement = _engagement_or_404(engagement_id)
    scope = _work_scope_filter(engagement)
    with _common.get_connection() as connection:
        # I-07: exclude observed-but-not-owned co-tenant / out-of-scope pending
        # rows from the claim. Out-of-scope rows are RARE, so the excluded set is
        # usually empty and the claim SQL is unchanged (fast path). The candidate
        # read and the claim run on the same re-entrant connection; the UPDATE
        # still re-checks status='pending', so a concurrent claim is never taken
        # twice even if a row's state shifts between the read and the write.
        exclude_sql = ""
        exclude_params: tuple[Any, ...] = ()
        if scope is not None:
            candidates = connection.execute(
                "SELECT id, host FROM assessment_work_items "
                "WHERE engagement_id = ? AND status = 'pending' AND type = ?",
                (engagement.id, type_val),
            ).fetchall()
            excluded = [
                row["id"]
                for row in candidates
                if _row_host_filtered_out(row["host"], scope)
            ]
            if excluded:
                exclude_sql = f" AND id NOT IN ({','.join('?' * len(excluded))})"
                exclude_params = tuple(excluded)
        rows = connection.execute(
            f"""
            UPDATE assessment_work_items
               SET status = 'processing',
                   assigned_agent = ?,
                   consumed_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP,
                   live_status = {_stamp_liveness_sql()}
             WHERE id IN (
                 SELECT id FROM assessment_work_items
                  WHERE engagement_id = ? AND status = 'pending' AND type = ?{exclude_sql}
                  ORDER BY priority_score DESC, cluster_key, id
                  LIMIT ?
             )
            RETURNING *
            """,
            (agent, engagement.id, type_val, *exclude_params, int(limit)),
        ).fetchall()
        claimed = [dict(r) for r in rows]
    claimed.sort(key=lambda r: (-(r.get("priority_score") or 0), r.get("cluster_key") or "", r.get("id") or 0))
    return {"claimed": claimed, "non_routable": []}


def fetch_work_items_by_priority(engagement_id: int, *, limit: int, agent: str) -> dict[str, Any]:
    """Claim the top-K pending rows by priority, respecting type→agent ownership.

    ``auto`` claims the highest-signal routable rows globally and assigns each to
    its canonical specialist; a concrete specialist name claims only the types it
    can handle. Rows with a terminal_reason are excluded (already skip-worthy).
    ``unknown`` rows remain vulnerability-analyst work: classification weakness
    must never make a pending coverage obligation unreachable.
    """
    engagement = _engagement_or_404(engagement_id)
    scope = _work_scope_filter(engagement)
    agent = (agent or "auto").strip()
    auto_route = agent.lower() in {"auto", "routed", "route"}
    allowed_types = _ROUTED_TYPES if auto_route else _agent_route(agent)
    if allowed_types is None:
        return {"claimed": [], "non_routable": [], "error": "not-routed-agent"}

    type_ph = ",".join("?" * len(allowed_types))
    stamp = _stamp_liveness_sql()
    with _common.get_connection() as connection:
        candidates = connection.execute(
            f"""
            SELECT * FROM assessment_work_items
             WHERE engagement_id = ? AND status = 'pending' AND terminal_reason IS NULL
               AND type IN ({type_ph})
             ORDER BY priority_score DESC, cluster_key, id
             LIMIT ?
            """,
            (engagement.id, *allowed_types, int(limit)),
        ).fetchall()
        claimed: list[dict[str, Any]] = []
        for row in candidates:
            if _row_host_filtered_out(row["host"], scope):
                continue
            row_agent = _assigned_agent_for_row(row) if auto_route else agent
            if not row_agent:
                continue
            updated = connection.execute(
                f"""
                UPDATE assessment_work_items
                   SET status = 'processing',
                       assigned_agent = ?,
                       consumed_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP,
                       live_status = {stamp}
                 WHERE id = ? AND engagement_id = ? AND status = 'pending'
                RETURNING *
                """,
                (row_agent, row["id"], engagement.id),
            ).fetchone()
            if updated is not None:
                claimed.append(dict(updated))
        claimed.sort(key=lambda r: (-(r.get("priority_score") or 0), r.get("cluster_key") or "", r.get("id") or 0))

        non_routable: list[dict[str, Any]] = []
        if not claimed:
            rows = connection.execute(
                "SELECT type, COUNT(*) AS count FROM assessment_work_items "
                "WHERE engagement_id = ? AND status = 'pending' AND terminal_reason IS NULL GROUP BY type",
                (engagement.id,),
            ).fetchall()
            non_routable = [
                {"type": r["type"], "count": r["count"]}
                for r in rows
                if r["type"] not in allowed_types
            ]
    return {"claimed": claimed, "non_routable": non_routable, "allowed_types": list(allowed_types)}


_UNIT_BATCH_BY_TIER = {
    "application": 12,
    "app-unit": 8,
    "endpoint-cluster": 5,
    "thin": 2,
}


def _literal_like_prefix(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.rstrip("/") + "/%"


def fetch_work_items_by_unit(
    engagement_id: int,
    *,
    unit_id: int | None,
    path: str,
    work_class: str,
    limit: int | None,
    agent: str,
) -> dict[str, Any]:
    """Atomically claim one coherent application unit selected explicitly or by EV.

    EV selection uses the depth scorer's persisted facts and only considers units
    with pending, routable work. It never rewrites work-item priority. When the
    operator omits ``limit``, the tier batch is reduced by recent probe saturation
    so already-active units yield smaller follow-on batches.
    """
    engagement = _engagement_or_404(engagement_id)
    scope = _work_scope_filter(engagement)
    normalized_agent = (agent or "auto").strip()
    auto_route = normalized_agent.lower() in {"auto", "routed", "route"}
    allowed_types = _ROUTED_TYPES if auto_route else _agent_route(normalized_agent)
    if allowed_types is None:
        return {"claimed": [], "error": "not-routed-agent"}
    if work_class and work_class not in allowed_types:
        return {"claimed": [], "error": "class-not-routed"}

    type_ph = ",".join("?" * len(allowed_types))
    class_sql = " AND wi.type = ?" if work_class else ""
    claim_class_sql = " AND type = ?" if work_class else ""
    class_params: tuple[Any, ...] = (work_class,) if work_class else ()
    path_value = (path or "").strip()
    unit_filter = " AND au.id = ?" if unit_id is not None else ""
    unit_params: tuple[Any, ...] = (int(unit_id),) if unit_id is not None else ()
    path_sql = " AND (wi.url_path = ? OR wi.url_path LIKE ? ESCAPE '\\')" if path_value else ""
    claim_path_sql = " AND (url_path = ? OR url_path LIKE ? ESCAPE '\\')" if path_value else ""
    path_params: tuple[Any, ...] = (
        (path_value, _literal_like_prefix(path_value)) if path_value else ()
    )

    with _common.get_connection() as connection:
        # Selection, saturation sizing, and the row claims are one write
        # transaction. Serializing before the SELECT prevents two workers from
        # both sizing/claiming the same highest-EV unit from a stale snapshot.
        connection.execute("BEGIN IMMEDIATE")
        unit = connection.execute(
            f"""
            SELECT au.*
              FROM assessment_application_units au
             WHERE au.engagement_id = ?
               {unit_filter}
               AND EXISTS (
                   SELECT 1 FROM assessment_work_items wi
                    WHERE wi.engagement_id = au.engagement_id
                      AND wi.application_unit_id = au.id
                      AND wi.status = 'pending' AND wi.terminal_reason IS NULL
                      AND wi.type IN ({type_ph})
                      {class_sql}
                      {path_sql}
               )
             ORDER BY au.deep_required DESC, au.total_score DESC,
                      au.risk_score DESC, au.structure_score DESC, au.id
             LIMIT 1
            """,
            (
                engagement.id,
                *unit_params,
                *allowed_types,
                *class_params,
                *path_params,
            ),
        ).fetchone()
        if unit is None:
            return {
                "claimed": [],
                "unit": None,
                "selection": "explicit" if unit_id is not None else "highest-ev-unsatisfied",
                "error": "no-unsatisfied-unit",
            }
        unit_row = dict(unit)
        recent_probes = int(
            connection.execute(
                "SELECT COUNT(*) FROM assessment_probe_runs "
                "WHERE engagement_id = ? AND application_unit_id = ? "
                "AND created_at >= datetime('now', '-24 hours')",
                (engagement.id, unit["id"]),
            ).fetchone()[0]
        )
        if limit is None:
            tier_limit = _UNIT_BATCH_BY_TIER.get(str(unit["depth_tier"]), 4)
            effective_limit = max(1, tier_limit - min(tier_limit - 1, recent_probes // 4))
            limit_source = "depth-tier-and-saturation"
        else:
            effective_limit = int(limit)
            limit_source = "explicit"

        candidates = connection.execute(
            f"""
            SELECT * FROM assessment_work_items
             WHERE engagement_id = ? AND application_unit_id = ?
               AND status = 'pending' AND terminal_reason IS NULL
               AND type IN ({type_ph})
               {claim_class_sql}
               {claim_path_sql}
             ORDER BY priority_score DESC, cluster_key, id
             LIMIT ?
            """,
            (
                engagement.id,
                unit["id"],
                *allowed_types,
                *class_params,
                *path_params,
                effective_limit,
            ),
        ).fetchall()
        stamp = _stamp_liveness_sql()
        claimed: list[dict[str, Any]] = []
        for candidate in candidates:
            if _row_host_filtered_out(candidate["host"], scope):
                continue
            row_agent = _assigned_agent_for_row(candidate) if auto_route else normalized_agent
            if not row_agent:
                continue
            updated = connection.execute(
                f"""
                UPDATE assessment_work_items
                   SET status = 'processing', assigned_agent = ?,
                       consumed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP,
                       live_status = {stamp}
                 WHERE id = ? AND engagement_id = ? AND status = 'pending'
                RETURNING *
                """,
                (row_agent, candidate["id"], engagement.id),
            ).fetchone()
            if updated is not None:
                claimed.append(dict(updated))
    claimed.sort(
        key=lambda row: (
            -(row.get("priority_score") or 0),
            row.get("cluster_key") or "",
            row.get("id") or 0,
        )
    )
    return {
        "claimed": claimed,
        "unit": unit_row,
        "selection": "explicit" if unit_id is not None else "highest-ev-unsatisfied",
        "effective_limit": effective_limit,
        "effective_limit_source": limit_source,
        "recent_probe_count": recent_probes,
        "allowed_types": list(allowed_types),
    }


# ---------------------------------------------------------------------------
# Lifecycle mutations
# ---------------------------------------------------------------------------
def mark_work_items_done(engagement_id: int, ids: list[int]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    valid = _int_ids(ids)
    if not valid:
        return {"affected": 0, "ids": []}
    ph = ",".join("?" * len(valid))
    with _common.get_connection() as connection:
        affected = connection.execute(
            f"UPDATE assessment_work_items SET status = 'done', updated_at = CURRENT_TIMESTAMP "
            f"WHERE engagement_id = ? AND id IN ({ph})",
            (engagement.id, *valid),
        ).rowcount
    return {"affected": affected, "ids": valid}


def mark_work_items_error(engagement_id: int, ids: list[int]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    valid = _int_ids(ids)
    if not valid:
        return {"affected": 0, "ids": []}
    ph = ",".join("?" * len(valid))
    with _common.get_connection() as connection:
        affected = connection.execute(
            f"UPDATE assessment_work_items SET status = 'error', "
            f"retry_count = COALESCE(retry_count, 0) + 1, updated_at = CURRENT_TIMESTAMP "
            f"WHERE engagement_id = ? AND id IN ({ph})",
            (engagement.id, *valid),
        ).rowcount
    return {"affected": affected, "ids": valid}


_SQL_ID_CHUNK = 300


def defer_work_items(
    engagement_id: int, *, ids: list[int], reason: str, dry_run: bool = False
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    valid = _int_ids(ids)
    if not valid:
        return {"affected": 0, "ids": []}
    matched: list[int] = []
    with _common.get_connection() as connection:
        if not dry_run:
            connection.execute("BEGIN IMMEDIATE")
        for start in range(0, len(valid), _SQL_ID_CHUNK):
            chunk = valid[start:start + _SQL_ID_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            rows = connection.execute(
                "SELECT id FROM assessment_work_items WHERE engagement_id = ? "
                f"AND status = 'pending' AND id IN ({placeholders}) ORDER BY id",
                (engagement.id, *chunk),
            ).fetchall()
            chunk_ids = [int(row["id"]) for row in rows]
            matched.extend(chunk_ids)
            if dry_run or not chunk_ids:
                continue
            update_placeholders = ",".join("?" * len(chunk_ids))
            connection.execute(
                "UPDATE assessment_work_items SET status = 'skipped', terminal_reason = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE engagement_id = ? "
                f"AND status = 'pending' AND id IN ({update_placeholders})",
                (reason, engagement.id, *chunk_ids),
            )
    return {"affected": len(matched), "ids": matched, "dry_run": bool(dry_run)}


def defer_work_item_cluster(
    engagement_id: int, *, cluster_key: str, reason: str, dry_run: bool = False
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        if not dry_run:
            connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT id FROM assessment_work_items WHERE engagement_id = ? "
            "AND status = 'pending' AND cluster_key = ? ORDER BY id",
            (engagement.id, cluster_key),
        ).fetchall()
        ids = [int(row["id"]) for row in rows]
        if ids and not dry_run:
            connection.execute(
                "UPDATE assessment_work_items SET status = 'skipped', terminal_reason = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE engagement_id = ? "
                "AND status = 'pending' AND cluster_key = ?",
                (reason, engagement.id, cluster_key),
            )
    return {
        "affected": len(ids),
        "ids": ids,
        "cluster_key": cluster_key,
        "dry_run": bool(dry_run),
    }


def mark_work_items_manual(engagement_id: int, ids: list[int]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    valid = _int_ids(ids)
    if not valid:
        return {"affected": 0, "ids": []}
    ph = ",".join("?" * len(valid))
    with _common.get_connection() as connection:
        affected = connection.execute(
            f"UPDATE assessment_work_items SET classifier_version = ?, updated_at = CURRENT_TIMESTAMP "
            f"WHERE engagement_id = ? AND id IN ({ph})",
            (MANUAL_CLASSIFIER_VERSION, engagement.id, *valid),
        ).rowcount
    return {"affected": affected, "ids": valid}


def reset_stale_work_items(engagement_id: int, *, minutes: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    window = f"-{int(minutes)} minutes"
    with _common.get_connection() as connection:
        before = connection.execute(
            "SELECT COUNT(*) FROM assessment_work_items "
            "WHERE engagement_id = ? AND status = 'processing' AND consumed_at < datetime('now', ?)",
            (engagement.id, window),
        ).fetchone()[0]
        connection.execute(
            "UPDATE assessment_work_items SET status = 'pending', assigned_agent = NULL, "
            "consumed_at = NULL, updated_at = CURRENT_TIMESTAMP "
            "WHERE engagement_id = ? AND status = 'processing' AND consumed_at < datetime('now', ?)",
            (engagement.id, window),
        )
    return {"affected": int(before), "minutes": int(minutes)}


# Fields the classify-work maintenance command may force-write on an existing
# row by id. Unlike the ingest UPSERT, this is a plain by-id UPDATE — it does
# NOT protect ``manual`` rows and CAN flip lifecycle status / retype / rewrite
# queue_key, which is exactly what re-classification / re-typing / reclaim-skipped
# require. ``UPDATE OR IGNORE`` skips a queue_key collision during a retype pass.
_WORK_ITEM_UPDATE_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "queue_key",
    "priority_score",
    "priority_reason",
    "cluster_key",
    "terminal_reason",
    "classifier_version",
    "triage_rationale",
)


def apply_work_item_updates(engagement_id: int, updates: list[dict[str, Any]]) -> dict[str, Any]:
    """Force-apply per-id field updates (the ``classify-work`` maintenance path).

    Each update carries an ``id`` plus any subset of ``_WORK_ITEM_UPDATE_FIELDS``;
    only the keys present are written. Engagement-scoped ``UPDATE OR IGNORE`` by id.
    """
    engagement = _engagement_or_404(engagement_id)
    affected = 0
    with _common.get_connection() as connection:
        for upd in updates:
            wid = _int_or_none(upd.get("id"))
            if wid is None:
                continue
            set_cols: list[str] = []
            params: list[Any] = []
            for col in _WORK_ITEM_UPDATE_FIELDS:
                if col in upd:
                    set_cols.append(f"{col} = ?")
                    params.append(upd[col])
            if not set_cols:
                continue
            set_cols.append("updated_at = CURRENT_TIMESTAMP")
            params.extend([engagement.id, wid])
            cursor = connection.execute(
                f"UPDATE OR IGNORE assessment_work_items SET {', '.join(set_cols)} "
                f"WHERE engagement_id = ? AND id = ?",
                params,
            )
            affected += cursor.rowcount
    return {"affected": affected}


def retry_error_work_items(engagement_id: int, *, max_retries: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        before = connection.execute(
            "SELECT COUNT(*) FROM assessment_work_items "
            "WHERE engagement_id = ? AND status = 'error' AND COALESCE(retry_count, 0) < ?",
            (engagement.id, int(max_retries)),
        ).fetchone()[0]
        connection.execute(
            "UPDATE assessment_work_items SET status = 'pending', assigned_agent = NULL, "
            "consumed_at = NULL, updated_at = CURRENT_TIMESTAMP "
            "WHERE engagement_id = ? AND status = 'error' AND COALESCE(retry_count, 0) < ?",
            (engagement.id, int(max_retries)),
        )
    return {"affected": int(before), "max_retries": int(max_retries)}
