"""Work-buffer (cases.db) implementation helpers.

The ``vigil assess work-buffer`` verbs operate on the local SQLite work buffer:
stats / peek / fetch / fetch-by-priority / defer-* / done / error /
reset-stale / retry-errors / requeue. ``_stamp_liveness`` reaches the
orchestrator backend (via ``AssessmentClient``) to annotate claimed rows with
the host's current liveness verdict; it is best-effort and never blocks a
fetch.
"""
from __future__ import annotations

import json
import sys

from urllib.parse import quote

from assess.lib.classify_buckets import reason_tag_of
from assess.lib.client import AssessmentClient
from assess.lib.discovery import normalize_host
from assess.lib.db import (
    db_query,
    db_exec,
    db_exec_returning,
    db_connect,
    db_insert_work_item,
)
from assess.lib.params import extract_url_path, generate_params_sig

from assess.commands.dispatch._shared import _validate_id_list


# Actions that DO need a cases.db (work-buffer SQLite) — listed once so the
# Unknown-action help text and the operator-facing docs stay aligned with the
# actual dispatch surface. Add new actions here and the help string updates
# automatically.
_DB_ACTIONS = (
    "stats",
    "peek",
    "fetch",
    "fetch-by-priority",
    "defer-cluster",
    "defer-items",
    "done",
    "error",
    "reset-stale",
    "retry-errors",
    "migrate",
    "requeue",
)


def _stats(db_path: str, *, by: str = "status") -> None:
    """Print work-buffer statistics grouped by ``by``.

    Default (``status``) preserves the legacy three-block output that every
    operator script and dashboard depends on. Alternative axes (``source``,
    ``cluster``, ``host``) emit a single grouped block keyed by the chosen
    axis so the operator can decide which specialist to dispatch next from
    the same dataset.
    """
    if by == "status":
        print("--- Work Buffer Statistics ---")
        rows = db_query(
            db_path,
            "SELECT status, type, COUNT(*) as count FROM work_items "
            "GROUP BY status, type ORDER BY status, type",
        )
        for row in rows:
            print(f"{row['status']}|{row['type']}|{row['count']}")
        print()
        print("--- Summary ---")
        rows = db_query(
            db_path,
            "SELECT status, COUNT(*) as count FROM work_items GROUP BY status ORDER BY status",
        )
        for row in rows:
            print(f"{row['status']}|{row['count']}")
        print()
        rows = db_query(
            db_path,
            "SELECT 'TOTAL' as label, COUNT(*) as count FROM work_items",
        )
        for row in rows:
            print(f"{row['label']}|{row['count']}")
        return

    if by == "source":
        print("--- Work Buffer by Source ---")
        rows = db_query(
            db_path,
            "SELECT COALESCE(source, '') AS source, status, COUNT(*) as count "
            "FROM work_items GROUP BY source, status ORDER BY source, status",
        )
        for row in rows:
            label = row["source"] or "(none)"
            print(f"{label}|{row['status']}|{row['count']}")
        return

    if by == "cluster":
        print("--- Work Buffer by Cluster ---")
        rows = db_query(
            db_path,
            "SELECT COALESCE(cluster_key, '') AS cluster_key, status, COUNT(*) as count, "
            "MAX(priority_score) as max_priority "
            "FROM work_items GROUP BY cluster_key, status "
            "ORDER BY max_priority DESC, cluster_key",
        )
        for row in rows:
            label = row["cluster_key"] or "(none)"
            print(
                f"{label}|{row['status']}|{row['count']}|max_priority={row['max_priority'] or 0}"
            )
        return

    if by == "host":
        print("--- Work Buffer by Host ---")
        # url_path stores everything after the host; we extract the host from
        # the full URL via SQL substring functions so this stays a single
        # GROUP BY without per-row Python work. Schemeless URLs (instr(url,
        # '://') = 0) bucket under 'unknown' instead of slicing into the path.
        rows = db_query(
            db_path,
            """
            SELECT
                CASE
                    WHEN instr(url, '://') = 0 THEN 'unknown'
                    WHEN instr(substr(url, instr(url, '://') + 3), '/') > 0
                        THEN substr(
                            substr(url, instr(url, '://') + 3),
                            1,
                            instr(substr(url, instr(url, '://') + 3), '/') - 1
                        )
                    ELSE substr(url, instr(url, '://') + 3)
                END AS host,
                status,
                COUNT(*) as count
            FROM work_items
            WHERE url IS NOT NULL AND url != ''
            GROUP BY host, status
            ORDER BY host, status
            """,
        )
        for row in rows:
            host = row["host"] or "(none)"
            print(f"{host}|{row['status']}|{row['count']}")
        return

    if by == "reason":
        # Group skipped/deferred rows by their structured reason tag so a query
        # can tell a correct exclusion from a bare, un-reasoned drop. The tag is
        # derived in Python (classify_buckets.reason_tag_of) because terminal_reason
        # is free-text; `untagged` is the state worth watching ("dropped without
        # a machine-readable reason").
        print("--- Work Buffer by Reason Tag (skipped/deferred) ---")
        rows = db_query(
            db_path,
            "SELECT COALESCE(terminal_reason, '') AS terminal_reason, COUNT(*) AS count "
            "FROM work_items WHERE status IN ('skipped', 'deferred') "
            "GROUP BY terminal_reason",
        )
        by_tag: dict[str, int] = {}
        for row in rows:
            tag = reason_tag_of(row["terminal_reason"]) or "none"
            by_tag[tag] = by_tag.get(tag, 0) + int(row["count"])
        for tag in sorted(by_tag):
            print(f"{tag}|{by_tag[tag]}")
        return


def _peek(db_path: str, type_val: str, limit: int) -> None:
    """Read-only preview of pending items of the given type.

    Unlike ``fetch``, this leaves the rows in ``pending`` so the operator
    can inspect them before claiming. Use this when you need to decide
    whether to ``defer-cluster``, ``defer-items``, or dispatch a
    specialist.
    """
    rows = db_query(
        db_path,
        """
        SELECT * FROM work_items
        WHERE status = 'pending' AND type = ?
        ORDER BY priority_score DESC, cluster_key, id
        LIMIT ?
        """,
        (type_val, limit),
    )
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def _defer_items(db_path: str, id_list, reason: str) -> None:
    """Mark specific work-item ids as skipped with a terminal reason.

    Symmetric to ``defer-cluster`` but per-id. Only flips pending rows so a
    processing dispatch is not clobbered mid-work; rerun ``reset-stale``
    first if you need to defer in-flight rows. When zero rows match, exit
    non-zero so an operator typo (or stale id list) does not look like a
    successful defer.
    """
    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    affected = db_exec(
        db_path,
        f"""UPDATE work_items
            SET status = 'skipped',
                terminal_reason = ?
            WHERE status = 'pending' AND id IN ({placeholders})""",
        (reason, *ids),
    )
    ids_repr = ",".join(str(i) for i in ids)
    if affected == 0:
        print(
            f"defer-items: no pending items matched the given ids "
            f"(already processed or invalid?): {ids_repr}\n"
            f"  note: items in 'processing'/'done'/'skipped' are not affected; "
            f"run reset-stale before defer if you need to flip in-flight rows.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"Deferred {affected} pending item(s): {ids_repr} (reason: {reason})"
    )


def _fetch(db_path: str, type_val: str, limit: int, agent: str) -> None:
    result = db_exec_returning(
        db_path,
        """UPDATE work_items
           SET status = 'processing',
               assigned_agent = ?,
               consumed_at = datetime('now')
           WHERE id IN (
               SELECT id FROM work_items
               WHERE status = 'pending' AND type = ?
               LIMIT ?
           )
           RETURNING *""",
        (agent, type_val, limit),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


_VULN_ANALYST_TYPES = (
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
)
_SOURCE_ANALYZER_TYPES = ("page", "javascript", "stylesheet", "data")
_ROUTED_TYPES = _VULN_ANALYST_TYPES + _SOURCE_ANALYZER_TYPES
_VULN_SIGNAL_FALLBACK_TYPES = ("unknown",)


def _agent_route(agent: str) -> tuple[str, ...] | None:
    """Return the work-item types this agent can safely receive."""
    normalized = (agent or "").strip().lower()
    if not normalized:
        return None
    if "vulnerability" in normalized or normalized.startswith("vuln"):
        return _VULN_ANALYST_TYPES + _VULN_SIGNAL_FALLBACK_TYPES
    if "source" in normalized:
        return _SOURCE_ANALYZER_TYPES
    return None


def _is_vuln_signal_fallback(row) -> bool:
    """Unknown type with explicit gf signal is vulnerability-analyst work.

    `unknown` is not broadly routable because many rows are low-context
    leftovers. The inline classifier can still assign strong gf buckets from
    path or parameter signal (for example `gf:trust_surface`); those rows
    should not wait for manual type fetches.
    """
    return (
        row["type"] in _VULN_SIGNAL_FALLBACK_TYPES
        and int(row["priority_score"] or 0) > 0
        and str(row["cluster_key"] or "").startswith("gf:")
    )


def _assigned_agent_for_row(row) -> str | None:
    case_type = row["type"]
    if case_type in _VULN_ANALYST_TYPES or _is_vuln_signal_fallback(row):
        return "vulnerability-analyst"
    if case_type in _SOURCE_ANALYZER_TYPES:
        return "source-analyzer"
    return None


def _stamp_liveness(conn, result: list[dict], cfg) -> None:
    """Best-effort: stamp each claimed row's ``live_status`` with the host's
    current ledger verdict + age (e.g. ``live@9m``, ``blackholed@5m``), so the
    dispatched specialist starts from "this host answered N minutes ago" instead
    of re-probing or writing it off on a stale sample (§10.5, context-only —
    informational, never blocks). Silently skips when there is no backend, no
    rows, or no liveness data; the fetch always succeeds.
    """
    if not result or cfg is None:
        return
    hosts = sorted({normalize_host(r.get("url") or "") for r in result})
    hosts = [h for h in hosts if h]
    if not hosts:
        return
    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            rows = client.get("host-liveness?host=" + quote(",".join(hosts)))
    except Exception:
        return
    if not isinstance(rows, list):
        return
    by_host: dict[str, str] = {}
    for lv in rows:
        if not isinstance(lv, dict):
            continue
        host = (lv.get("host") or "").lower()
        klass = lv.get("reachability_class") or "unknown"
        age = lv.get("age_seconds")
        # Clamp to >=0: a future/skewed probed_at yields a negative age; a
        # nonsense `@-NNNm` stamp is worse than omitting the age.
        age_str = f"@{int(age // 60)}m" if isinstance(age, (int, float)) and age >= 0 else ""
        by_host[host] = f"{klass}{age_str}"
    stamped = False
    for r in result:
        stamp = by_host.get(normalize_host(r.get("url") or ""))
        if stamp:
            r["live_status"] = stamp
            try:
                conn.execute("UPDATE work_items SET live_status = ? WHERE id = ?", (stamp, r["id"]))
                stamped = True
            except Exception:
                pass
    if stamped:
        conn.commit()


def _fetch_by_priority(db_path: str, limit: int, agent: str, cfg=None) -> None:
    """Claim the top-K pending rows ranked by priority_score DESC.

    Priority mode still respects type-to-agent ownership. ``auto`` claims the
    highest-signal routable rows globally and assigns each row to the canonical
    specialist for its type. A concrete specialist name claims only the types
    that specialist can handle, preserving custom instance labels like
    ``vulnerability-analyst-1`` without handing it JavaScript/page work.

    We exclude rows with terminal_reason set because classify-work already
    stamped those as skip-worthy. High-signal `unknown` rows are a narrow
    vulnerability-analyst fallback when inline classification assigned a
    positive `gf:*` bucket; plain unknown rows remain unrouted.
    """
    agent = (agent or "auto").strip()
    auto_route = agent.lower() in {"auto", "routed", "route"}
    allowed_types = (_ROUTED_TYPES + _VULN_SIGNAL_FALLBACK_TYPES) if auto_route else _agent_route(agent)
    if allowed_types is None:
        print(
            "fetch-by-priority: agent is not a routed agent; use 'auto', "
            "'vulnerability-analyst', or 'source-analyzer'",
            file=sys.stderr,
        )
        sys.exit(1)

    placeholders = ",".join("?" * len(allowed_types))
    with db_connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        candidates = conn.execute(
            f"""SELECT *
                FROM work_items
                WHERE status = 'pending'
                  AND terminal_reason IS NULL
                  AND type IN ({placeholders})
                  AND (
                      type NOT IN ({",".join("?" * len(_VULN_SIGNAL_FALLBACK_TYPES))})
                      OR (priority_score > 0 AND cluster_key LIKE 'gf:%')
                  )
                ORDER BY priority_score DESC, cluster_key, id
                LIMIT ?""",
            (*allowed_types, *_VULN_SIGNAL_FALLBACK_TYPES, limit),
        ).fetchall()
        claimed: list[dict] = []
        for row in candidates:
            row_agent = _assigned_agent_for_row(row) if auto_route else agent
            if not row_agent:
                continue
            updated = conn.execute(
                """UPDATE work_items
                   SET status = 'processing',
                       assigned_agent = ?,
                       consumed_at = datetime('now')
                   WHERE id = ? AND status = 'pending'
                   RETURNING *""",
                (row_agent, row["id"]),
            ).fetchone()
            if updated is not None:
                claimed.append(dict(updated))
        conn.commit()
        # Preserve the SELECT ordering for downstream dispatch context.
        result = sorted(
            claimed,
            key=lambda r: (
                -(r.get("priority_score") or 0),
                r.get("cluster_key") or "",
                r.get("id") or 0,
            ),
        )
        if not result:
            non_routable = conn.execute(
                """SELECT type, COUNT(*) as count
                   FROM work_items
                   WHERE status = 'pending' AND terminal_reason IS NULL
                   GROUP BY type""",
            ).fetchall()
            non_routable_pairs = [
                (row["type"], row["count"]) for row in non_routable if row["type"] not in allowed_types
            ]
            if non_routable_pairs:
                total = sum(count for _, count in non_routable_pairs)
                types_summary = ", ".join(f"{t}={c}" for t, c in non_routable_pairs)
                print(
                    f"WARN fetch-by-priority: queue has {total} pending item(s) "
                    f"but all are in non-routable types ({types_summary}); "
                    f"routable types are: {', '.join(allowed_types)}.",
                    file=sys.stderr,
                )
        _stamp_liveness(conn, result, cfg)
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _defer_cluster(db_path: str, cluster_key: str, reason: str) -> None:
    """Mark every pending row in a cluster as skipped with a terminal reason.

    Operators use this after review to silence low-signal clusters from the
    priority dispatcher. We only flip pending rows so that an in-flight
    `processing` dispatch is not clobbered mid-work; the operator can
    reset-stale + defer if they want to pull a cluster back.
    """
    affected = db_exec(
        db_path,
        """UPDATE work_items
           SET status = 'skipped',
               terminal_reason = ?
           WHERE status = 'pending' AND cluster_key = ?""",
        (reason, cluster_key),
    )
    print(f"Deferred {affected} pending item(s) in cluster '{cluster_key}' (reason: {reason})")


def _done(db_path: str, id_list) -> None:
    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    db_exec(db_path, f"UPDATE work_items SET status='done' WHERE id IN ({placeholders})", tuple(ids))
    print(f"Marked done: {','.join(str(i) for i in ids)}")


def _error(db_path: str, id_list) -> None:
    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    db_exec(
        db_path,
        f"UPDATE work_items SET status='error', retry_count = COALESCE(retry_count,0) + 1 WHERE id IN ({placeholders})",
        tuple(ids),
    )
    print(f"Marked error: {','.join(str(i) for i in ids)}")


def _reset_stale(db_path: str, minutes: int) -> None:
    rows = db_query(
        db_path,
        "SELECT COUNT(*) as count FROM work_items WHERE status='processing' AND consumed_at < datetime('now', ?)",
        (f"-{minutes} minutes",),
    )
    before = rows[0]["count"] if rows else 0
    db_exec(
        db_path,
        "UPDATE work_items SET status='pending', assigned_agent=NULL, consumed_at=NULL WHERE status='processing' AND consumed_at < datetime('now', ?)",
        (f"-{minutes} minutes",),
    )
    print(f"Reset {before} stale work item(s) (stuck > {minutes} min)")


def _retry_errors(db_path: str, max_retries: int) -> None:
    rows = db_query(
        db_path,
        "SELECT COUNT(*) as count FROM work_items WHERE status='error' AND COALESCE(retry_count,0) < ?",
        (max_retries,),
    )
    before = rows[0]["count"] if rows else 0
    db_exec(
        db_path,
        "UPDATE work_items SET status='pending', assigned_agent=NULL, consumed_at=NULL WHERE status='error' AND COALESCE(retry_count,0) < ?",
        (max_retries,),
    )
    print(f"Retried {before} error work item(s) (max retries: {max_retries})")


def _requeue(db_path: str) -> None:
    count = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        row = json.loads(line)
        method = row.get("method") or "GET"
        url = row.get("url") or ""
        url_path_val = row.get("url_path") or ""
        case_type = row.get("type") or "unknown"
        source = row.get("source") or "requeue"
        auth_context = row.get("auth_context") or "anonymous"

        query_params = row.get("query_params") or {}
        body_params = row.get("body_params") or {}
        path_params = row.get("path_params") or {}
        cookie_params = row.get("cookie_params") or {}
        headers = row.get("headers") or ""
        body = row.get("body") or ""
        content_type = row.get("content_type") or ""
        content_length = int(row.get("content_length") or 0)
        response_status = int(row.get("response_status") or 0)
        response_headers = row.get("response_headers") or ""
        response_size = int(row.get("response_size") or 0)
        response_snippet = row.get("response_snippet") or ""
        params_key_sig = row.get("params_key_sig") or ""

        request_variant_id = row.get("request_variant_id")
        service_id = row.get("service_id")
        coverage_item_id = row.get("coverage_item_id")
        queue_key = row.get("queue_key") or ""

        if method == "null":
            method = "GET"
        if url == "null":
            url = ""
        if case_type == "null":
            case_type = "unknown"

        if not url_path_val:
            url_path_val = extract_url_path(url)
        if not params_key_sig:
            qp = json.dumps(query_params) if isinstance(query_params, dict) else str(query_params)
            bp = json.dumps(body_params) if isinstance(body_params, dict) else str(body_params)
            params_key_sig = generate_params_sig(qp, bp)

        if not queue_key:
            if request_variant_id and str(request_variant_id).isdigit():
                queue_key = f"variant:{request_variant_id}:{case_type}"
            elif service_id and str(service_id).isdigit():
                queue_key = f"service:{service_id}:{case_type}"
            elif coverage_item_id and str(coverage_item_id).isdigit():
                queue_key = f"coverage:{coverage_item_id}:{case_type}"
            else:
                print("ERROR: requeue line missing variant/service/coverage ID for queue_key", file=sys.stderr)
                sys.exit(1)

        if not url or not url_path_val:
            print("ERROR: requeue line missing usable url/url_path", file=sys.stderr)
            sys.exit(1)

        # Serialize dicts to JSON strings for storage
        qp_str = json.dumps(query_params) if isinstance(query_params, dict) else str(query_params)
        bp_str = json.dumps(body_params) if isinstance(body_params, dict) else str(body_params)
        pp_str = json.dumps(path_params) if isinstance(path_params, dict) else str(path_params)
        cp_str = json.dumps(cookie_params) if isinstance(cookie_params, dict) else str(cookie_params)
        rh_str = json.dumps(response_headers) if isinstance(response_headers, dict) else str(response_headers)
        h_str = json.dumps(headers) if isinstance(headers, dict) else str(headers)

        rv_id = int(request_variant_id) if request_variant_id and str(request_variant_id).isdigit() else None
        s_id = int(service_id) if service_id and str(service_id).isdigit() else None
        c_id = int(coverage_item_id) if coverage_item_id and str(coverage_item_id).isdigit() else None

        db_insert_work_item(
            db_path,
            queue_key=queue_key,
            method=method,
            url=url,
            url_path=url_path_val,
            query_params=qp_str,
            body_params=bp_str,
            path_params=pp_str,
            cookie_params=cp_str,
            headers=h_str,
            body=body,
            content_type=content_type,
            content_length=content_length,
            response_status=response_status,
            response_headers=rh_str,
            response_size=response_size,
            response_snippet=response_snippet,
            case_type=case_type,
            source=source,
            params_key_sig=params_key_sig,
            request_variant_id=rv_id,
            service_id=s_id,
            coverage_item_id=c_id,
            auth_context=auth_context,
        )
        count += 1

    print(f"Requeued {count} new work item(s)")
