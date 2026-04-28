"""aith assess dispatch — SQLite work-buffer consumption engine.

Replaces dispatcher.sh with parameterized SQL.
"""
from __future__ import annotations

import json
import os
import sys

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.db import db_init, db_query, db_exec, db_insert_work_item
from assess.lib.params import extract_url_path, extract_query_params, extract_path_params, generate_params_sig


# Actions that don't need a cases.db (work-buffer SQLite). When the first
# positional arg matches one of these names, we treat it as the action and
# leave db_path empty rather than forcing the operator to pass a useless path.
# render-handoff is operator-glue for cross-dispatch continuity (Fix #7) — it
# pulls from $DIR/agent-registry.json and the backend, never the work buffer.
_DBLESS_ACTIONS = ("render-handoff",)


def register(subparsers) -> None:
    p = subparsers.add_parser("dispatch", help="Work-buffer dispatch engine")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "action",
        nargs="?",
        default="",
        help=(
            "stats|fetch|fetch-by-priority|peek|defer-cluster|defer-items|done|error|"
            "reset-stale|retry-errors|migrate|requeue|render-handoff"
        ),
    )
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument(
        "--reason",
        default="",
        help="Reason for defer-cluster / defer-items (required for those actions). Free text; "
        "stored in terminal_reason so operators can audit why a cluster or item was skipped.",
    )
    p.add_argument(
        "--by",
        default="status",
        choices=("status", "source", "cluster", "host"),
        help="Group axis for `stats` (default: status). 'cluster' / 'host' / 'source' "
        "let the operator slice the buffer along the axis that matters for the next dispatch.",
    )
    p.add_argument(
        "--max-lines",
        type=int,
        default=40,
        help="render-handoff: hard cap on output lines (default 40). The findings list "
        "is truncated with a '... and N more' tail when the rendered blob would exceed "
        "the cap.",
    )
    p.add_argument(
        "--include-evidence",
        action="store_true",
        help="render-handoff: include one short evidence excerpt per finding slug. Off by "
        "default to keep the handoff blob bounded.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    action = args.action
    extra = args.extra or []

    # render-handoff and other dbless actions don't take a cases.db; the
    # operator types `aith assess dispatch render-handoff <agent-id>` and
    # argparse parks the action name in the db_path slot. Shift it so the
    # rest of the dispatcher can route normally.
    if (db_path or "") in _DBLESS_ACTIONS:
        if action:
            # Operator typed the action where db_path goes; whatever landed
            # in the action slot is actually the first action-specific arg.
            extra = [action] + list(extra)
        action = db_path
        db_path = ""

    if not action:
        print(
            "Usage: aith assess dispatch <db> <action> [...]\n"
            "       aith assess dispatch render-handoff <agent-id> [--max-lines N] [--include-evidence]",
            file=sys.stderr,
        )
        sys.exit(1)

    if action == "render-handoff":
        _render_handoff(args, extra)
        return

    if not db_path:
        print(
            f"Usage: aith assess dispatch <db> {action} [...]\n"
            f"  '{action}' requires a path to cases.db as the first positional.",
            file=sys.stderr,
        )
        sys.exit(1)

    db_init(db_path)

    if action == "stats":
        by = getattr(args, "by", "status") or "status"
        _stats(db_path, by=by)
    elif action == "peek":
        if len(extra) < 1:
            print("Usage: dispatch <db> peek <type> [limit]", file=sys.stderr)
            sys.exit(1)
        peek_type = extra[0]
        peek_limit = _safe_int_arg(extra[1], "limit") if len(extra) > 1 else 10
        _peek(db_path, peek_type, peek_limit)
    elif action == "fetch":
        if len(extra) < 3:
            print("Usage: dispatch <db> fetch <type> <limit> <agent>", file=sys.stderr)
            sys.exit(1)
        _fetch(db_path, extra[0], _safe_int_arg(extra[1], "limit"), extra[2])
    elif action == "fetch-by-priority":
        if len(extra) < 1:
            print(
                "Usage: dispatch <db> fetch-by-priority <limit> [auto|agent]",
                file=sys.stderr,
            )
            sys.exit(1)
        _fetch_by_priority(
            db_path,
            _safe_int_arg(extra[0], "limit"),
            extra[1] if len(extra) > 1 else "auto",
        )
    elif action == "defer-cluster":
        if not extra:
            print(
                "Usage: dispatch <db> defer-cluster <cluster_key> --reason TEXT",
                file=sys.stderr,
            )
            sys.exit(1)
        reason = (getattr(args, "reason", "") or "").strip()
        if not reason:
            print(
                "defer-cluster: --reason is required so terminal_reason records why "
                "the cluster was deferred; rerun with --reason \"<explanation>\".",
                file=sys.stderr,
            )
            sys.exit(1)
        _defer_cluster(db_path, extra[0], reason)
    elif action == "defer-items":
        if not extra:
            print(
                "Usage: dispatch <db> defer-items <id> [<id> ...] --reason TEXT\n"
                "       dispatch <db> defer-items <id1,id2,...> --reason TEXT",
                file=sys.stderr,
            )
            sys.exit(1)
        reason = (getattr(args, "reason", "") or "").strip()
        if not reason:
            print(
                "defer-items: --reason is required so terminal_reason records why "
                "the items were deferred; rerun with --reason \"<explanation>\".",
                file=sys.stderr,
            )
            sys.exit(1)
        _defer_items(db_path, extra, reason)
    elif action == "done":
        if not extra:
            print("Usage: dispatch <db> done <id> [<id> ...]", file=sys.stderr)
            sys.exit(1)
        _done(db_path, extra)
    elif action == "error":
        if not extra:
            print("Usage: dispatch <db> error <id> [<id> ...]", file=sys.stderr)
            sys.exit(1)
        _error(db_path, extra)
    elif action == "reset-stale":
        if not extra:
            print("Usage: dispatch <db> reset-stale <minutes>", file=sys.stderr)
            sys.exit(1)
        _reset_stale(db_path, _safe_int_arg(extra[0], "minutes"))
    elif action == "retry-errors":
        max_retries = _safe_int_arg(extra[0], "max_retries") if extra else 2
        _retry_errors(db_path, max_retries)
    elif action == "migrate":
        pass  # db_init already ran
    elif action == "requeue":
        _requeue(db_path)
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        print(
            "Actions: stats, peek, fetch, fetch-by-priority, defer-cluster, "
            "defer-items, done, error, reset-stale, retry-errors, migrate, requeue",
            file=sys.stderr,
        )
        sys.exit(1)


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


def _peek(db_path: str, type_val: str, limit: int) -> None:
    """Read-only preview of pending items of the given type.

    Unlike ``fetch``, this leaves the rows in ``pending`` so the operator
    can inspect them before claiming. Use this when you need to decide
    whether to ``defer-cluster``, ``defer-items``, or dispatch a
    specialist.
    """
    import sqlite3
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        rows = conn.execute(
            """
            SELECT * FROM work_items
            WHERE status = 'pending' AND type = ?
            ORDER BY priority_score DESC, cluster_key, id
            LIMIT ?
            """,
            (type_val, limit),
        ).fetchall()
    finally:
        conn.close()
    print(json.dumps([dict(row) for row in rows], indent=2, ensure_ascii=False))


def _safe_int_arg(value: str, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        print(f"ERROR: {name} must be an integer (got '{value}')", file=sys.stderr)
        sys.exit(1)


def _defer_items(db_path: str, id_list, reason: str) -> None:
    """Mark specific work-item ids as skipped with a terminal reason.

    Symmetric to ``defer-cluster`` but per-id. Only flips pending rows so a
    processing dispatch is not clobbered mid-work; rerun ``reset-stale``
    first if you need to defer in-flight rows. When zero rows match, exit
    non-zero so an operator typo (or stale id list) does not look like a
    successful defer.
    """
    import sqlite3

    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            f"""UPDATE work_items
                SET status = 'skipped',
                    terminal_reason = ?
                WHERE status = 'pending' AND id IN ({placeholders})""",
            (reason, *ids),
        )
        conn.commit()
        affected = cursor.rowcount
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
    finally:
        conn.close()


def _fetch(db_path: str, type_val: str, limit: int, agent: str) -> None:
    import sqlite3
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        rows = conn.execute(
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
        ).fetchall()
        conn.commit()
        result = [dict(row) for row in rows]
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        conn.close()


_VULN_ANALYST_TYPES = ("api", "api-spec", "form", "upload", "graphql", "websocket")
_SOURCE_ANALYZER_TYPES = ("page", "javascript", "stylesheet", "data")
_ROUTED_TYPES = _VULN_ANALYST_TYPES + _SOURCE_ANALYZER_TYPES
_SKIP_TYPES = ("image", "font", "media", "binary", "archive", "unknown")


def _agent_route(agent: str) -> tuple[str, ...] | None:
    """Return the work-item types this agent can safely receive."""
    normalized = (agent or "").strip().lower()
    if not normalized:
        return None
    if "vulnerability" in normalized or normalized.startswith("vuln"):
        return _VULN_ANALYST_TYPES
    if "source" in normalized:
        return _SOURCE_ANALYZER_TYPES
    return None


def _assigned_agent_for_type(case_type: str) -> str | None:
    if case_type in _VULN_ANALYST_TYPES:
        return "vulnerability-analyst"
    if case_type in _SOURCE_ANALYZER_TYPES:
        return "source-analyzer"
    return None


def _fetch_by_priority(db_path: str, limit: int, agent: str) -> None:
    """Claim the top-K pending rows ranked by priority_score DESC.

    Priority mode still respects type-to-agent ownership. ``auto`` claims the
    highest-signal routable rows globally and assigns each row to the canonical
    specialist for its type. A concrete specialist name claims only the types
    that specialist can handle, preserving custom instance labels like
    ``vulnerability-analyst-1`` without handing it JavaScript/page work.

    We exclude rows with terminal_reason set because classify-work already
    stamped those as skip-worthy, and we exclude inert types as a belt-and-
    suspenders guard in case an older DB predates the terminal_reason stamp.
    """
    import sqlite3

    agent = (agent or "auto").strip()
    auto_route = agent.lower() in {"auto", "routed", "route"}
    allowed_types = _ROUTED_TYPES if auto_route else _agent_route(agent)
    if allowed_types is None:
        print(
            "fetch-by-priority: agent is not a routed agent; use 'auto', "
            "'vulnerability-analyst', or 'source-analyzer'",
            file=sys.stderr,
        )
        sys.exit(1)

    placeholders = ",".join("?" * len(allowed_types))
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("BEGIN IMMEDIATE")
        candidates = conn.execute(
            f"""SELECT *
                FROM work_items
                WHERE status = 'pending'
                  AND terminal_reason IS NULL
                  AND type IN ({placeholders})
                ORDER BY priority_score DESC, cluster_key, id
                LIMIT ?""",
            (*allowed_types, limit),
        ).fetchall()
        claimed: list[dict] = []
        for row in candidates:
            row_agent = _assigned_agent_for_type(row["type"]) if auto_route else agent
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
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        conn.close()


def _defer_cluster(db_path: str, cluster_key: str, reason: str) -> None:
    """Mark every pending row in a cluster as skipped with a terminal reason.

    Operators use this after review to silence low-signal clusters from the
    priority dispatcher. We only flip pending rows so that an in-flight
    `processing` dispatch is not clobbered mid-work; the operator can
    reset-stale + defer if they want to pull a cluster back.
    """
    import sqlite3

    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            """UPDATE work_items
               SET status = 'skipped',
                   terminal_reason = ?
               WHERE status = 'pending' AND cluster_key = ?""",
            (reason, cluster_key),
        )
        conn.commit()
        print(f"Deferred {cursor.rowcount} pending item(s) in cluster '{cluster_key}' (reason: {reason})")
    finally:
        conn.close()


def _validate_id_list(id_list) -> list[int]:
    """Parse and validate IDs given as a comma-separated string OR a list of tokens.

    Accepts either ``"1,2,3"``, ``["1", "2", "3"]``, or mixed forms like
    ``["1,2", "3"]``. Pure-comma strings (``","``) and empty inputs raise so a
    typo doesn't silently turn into a no-op UPDATE.
    """
    if isinstance(id_list, (list, tuple)):
        tokens: list[str] = []
        for entry in id_list:
            tokens.extend(str(entry).split(","))
    else:
        tokens = str(id_list).split(",")
    cleaned = [token.strip() for token in tokens if token.strip()]
    if not cleaned:
        print(
            "ERROR: id_list must contain at least one numeric ID (got empty/comma-only input)",
            file=sys.stderr,
        )
        sys.exit(1)
    ids: list[int] = []
    for token in cleaned:
        if not token.isdigit():
            print(
                f"ERROR: id_list must contain only numeric IDs (got '{token}')",
                file=sys.stderr,
            )
            sys.exit(1)
        ids.append(int(token))
    return ids


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
                print(f"ERROR: requeue line missing variant/service/coverage ID for queue_key", file=sys.stderr)
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


# ---------------------------------------------------------------------------
# render-handoff — bounded handoff blob generator (Fix #7)
#
# Cross-Dispatch Continuity in operator-core.md tells the operator to keep
# handoff prompts bounded ("two or three excerpted lines + finding slugs +
# file paths"). Without a helper the operator's discretion was the only
# protection; under parallelism that degrades — operators paste full
# transcripts because it's fast and the dispatch prompt arrives bloated.
#
# render-handoff replaces that discretion with a deterministic emitter that
# pulls from durable state ($DIR/agent-registry.json + the assessment backend)
# and emits a markdown blob the operator pastes verbatim into the next
# dispatch prompt. The output is hard-capped at --max-lines (default 40); the
# findings list collapses to "... and N more" before any fixed sections drop.
# ---------------------------------------------------------------------------


def _render_handoff(args, extra: list[str]) -> None:
    """Emit a bounded markdown handoff blob for a prior dispatch.

    Reads ``$DIR/agent-registry.json`` for the entry whose ``agent_id``
    matches the given id, then enriches with backend finding records and
    optional credential rows so the operator can paste the result into the
    next dispatch prompt without copying transcript excerpts.
    """
    if not extra:
        print(
            "Usage: aith assess dispatch render-handoff <agent-id> "
            "[--max-lines N] [--include-evidence]",
            file=sys.stderr,
        )
        sys.exit(1)

    agent_id = extra[0].strip()
    if not agent_id:
        print(
            "render-handoff: agent-id must be a non-empty string",
            file=sys.stderr,
        )
        sys.exit(1)

    max_lines = max(1, int(getattr(args, "max_lines", 40) or 40))
    include_evidence = bool(getattr(args, "include_evidence", False))

    # Resolve engagement directory the same way other helper-owned commands do
    # (config layer): CLI --engagement-dir, then $ENGAGEMENT_DIR, then cwd if
    # it contains scope.json.
    cfg = load_config(getattr(args, "engagement_dir", None))
    registry_path = os.path.join(cfg.engagement_dir, "agent-registry.json")
    entry = _registry_lookup(registry_path, agent_id)
    if entry is None:
        print(
            f"render-handoff: agent-id '{agent_id}' not found in "
            f"{registry_path}; the registry is the durable record of who was "
            f"dispatched, so a missing entry means the prior dispatch never "
            f"appended (or the id was mistyped).",
            file=sys.stderr,
        )
        sys.exit(2)

    role = str(entry.get("role") or "<unknown role>")
    task = str(entry.get("task") or "<unrecorded task>")
    skill_loaded = entry.get("skill_loaded") or entry.get("skill") or ""
    scope_host = entry.get("scope_host") or ""
    dispatched_at = entry.get("dispatched_at") or entry.get("timestamp") or ""
    status = entry.get("status") or ""
    finding_slugs = entry.get("finding_slugs") or entry.get("findings") or []
    if not isinstance(finding_slugs, list):
        finding_slugs = [finding_slugs]
    finding_slugs = [str(s).strip() for s in finding_slugs if str(s).strip()]

    next_step = entry.get("next_step")
    if not isinstance(next_step, str):
        next_step = ""
    next_step = next_step.strip()

    working_artifacts = entry.get("working_artifacts") or []
    if not isinstance(working_artifacts, list):
        working_artifacts = [working_artifacts]
    working_artifacts = [str(p).strip() for p in working_artifacts if str(p).strip()]

    # Per-slug enrichment from the backend. Tolerate 404s gracefully — the
    # operator may have killed a finding between dispatch and handoff render.
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    finding_rows: list[dict] = []
    try:
        for slug in finding_slugs:
            try:
                row = client.get(f"findings/{slug}")
            except AssessError as exc:
                if "HTTP 404" in str(exc):
                    finding_rows.append({"slug": slug, "_missing": True})
                    continue
                # Any other error: surface but continue so the operator gets
                # the rest of the blob. Network blips shouldn't fail the
                # whole render.
                finding_rows.append({"slug": slug, "_error": str(exc).splitlines()[0]})
                continue
            if isinstance(row, dict):
                row.setdefault("slug", slug)
                finding_rows.append(row)
            else:
                finding_rows.append({"slug": slug, "_error": "non-dict response"})

        credential_rows: list[dict] = []
        if role in ("vulnerability-analyst", "exploit-developer"):
            try:
                creds = client.get("credentials")
            except AssessError:
                creds = []
            if isinstance(creds, list):
                # The credentials table doesn't carry a formal agent_id
                # column, so we filter by source_name == role as the closest
                # available signal. Operators who need stricter tracking can
                # widen the filter later; this is enough to surface "the
                # vulnerability-analyst dispatch captured 2 cred rows".
                credential_rows = [
                    c for c in creds
                    if isinstance(c, dict) and (c.get("source_name") or "") == role
                ]
    finally:
        client.close()

    # Local-disk presence check for working artifacts. The convention is that
    # tools live under $DIR/tools/, but the registry may record other paths
    # under $DIR/scans/ or $DIR/downloads/ — resolve every entry against the
    # engagement dir so the operator catches references to deleted files.
    artifact_states: list[tuple[str, str]] = []
    for path in working_artifacts:
        if os.path.isabs(path):
            full = path
        else:
            full = os.path.join(cfg.engagement_dir, path)
        artifact_states.append((path, "present" if os.path.exists(full) else "missing"))

    # Build the rendered blob, then truncate the findings tail if the line
    # budget would be exceeded. The fixed sections (header + meta + next step)
    # are always preserved; only the findings list collapses, since that is
    # the unbounded axis.
    blob = _render_handoff_blob(
        agent_id=agent_id,
        role=role,
        task=task,
        skill_loaded=skill_loaded,
        scope_host=scope_host,
        dispatched_at=dispatched_at,
        status=status,
        finding_rows=finding_rows,
        artifact_states=artifact_states,
        credential_rows=credential_rows,
        next_step=next_step,
        include_evidence=include_evidence,
        max_lines=max_lines,
    )
    print(blob)


def _registry_lookup(registry_path: str, agent_id: str) -> dict | None:
    """Return the registry entry whose agent_id matches, or None.

    Tolerates a missing or malformed registry — the helper should fail with a
    clear "agent-id not found" rather than crashing the operator's terminal
    on a JSON parse error.
    """
    try:
        with open(registry_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    for entry in data:
        if isinstance(entry, dict) and str(entry.get("agent_id") or "").strip() == agent_id:
            return entry
    return None


def _render_handoff_blob(
    *,
    agent_id: str,
    role: str,
    task: str,
    skill_loaded: str,
    scope_host: str,
    dispatched_at: str,
    status: str,
    finding_rows: list[dict],
    artifact_states: list[tuple[str, str]],
    credential_rows: list[dict],
    next_step: str,
    include_evidence: bool,
    max_lines: int,
) -> str:
    """Build the markdown handoff blob with the documented section order.

    The section order matches the spec in operator-core.md "Cross-Dispatch
    Continuity": header, prior task, skill loaded, scope host, dispatched at,
    findings recorded, working artifacts, credentials captured, next step.
    The next-step line is always emitted (even when blank) so the new
    dispatch prompt sees an explicit "set this in the next prompt" reminder
    if the prior agent did not record one.
    """
    head = [
        f"#### Handoff from {role} dispatch {agent_id}",
        f"- **Prior task:** {task}",
        f"- **Skill loaded:** {skill_loaded or '(none recorded)'}",
        f"- **Scope host:** {scope_host or '(none recorded)'}",
        f"- **Dispatched at:** {dispatched_at or '(unknown)'} (status: {status or 'unknown'})",
    ]

    finding_lines = _findings_section(finding_rows, include_evidence=include_evidence)
    artifact_lines = _artifacts_section(artifact_states)
    credentials_line = _credentials_section(credential_rows)
    next_step_line = _next_step_section(next_step)

    fixed_section_count = (
        len(head)
        + 1  # findings header line
        + len(artifact_lines)
        + 1  # credentials line
        + 1  # next step line
    )

    # Reserve room for the fixed scaffolding plus at least one finding row
    # (or the "(none recorded)" placeholder) so the cap can never produce a
    # blob that omits the findings header entirely.
    findings_budget = max(1, max_lines - fixed_section_count)
    finding_body, truncated_count = _truncate_findings(finding_lines, findings_budget)

    lines: list[str] = []
    lines.extend(head)
    lines.append("- **Findings recorded:**")
    lines.extend(finding_body)
    if truncated_count > 0:
        lines.append(f"  - ... and {truncated_count} more")
    lines.extend(artifact_lines)
    lines.append(credentials_line)
    lines.append(next_step_line)
    return "\n".join(lines)


def _findings_section(finding_rows: list[dict], *, include_evidence: bool) -> list[str]:
    """One indented bullet per recorded slug; '(none recorded)' when empty."""
    if not finding_rows:
        return ["  - (none recorded)"]
    lines: list[str] = []
    for row in finding_rows:
        slug = str(row.get("slug") or "<no-slug>")
        if row.get("_missing"):
            lines.append(f"  - `{slug}` — slug missing (deleted or never recorded)")
            continue
        if row.get("_error"):
            lines.append(f"  - `{slug}` — fetch error: {row['_error']}")
            continue
        title = str(row.get("title") or "(untitled)")
        severity = str(row.get("severity") or "unknown")
        lines.append(f"  - `{slug}` — {title} [severity={severity}]")
        if include_evidence:
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            evidence = ""
            if isinstance(details, dict):
                evidence = str(details.get("evidence") or "").strip()
            if not evidence:
                evidence = str(row.get("notes") or "").strip()
            if evidence:
                snippet = evidence.splitlines()[0][:160]
                lines.append(f"    - evidence: {snippet}")
    return lines


def _artifacts_section(artifact_states: list[tuple[str, str]]) -> list[str]:
    """Working-artifact bullets with on-disk present/missing state."""
    lines = ["- **Working artifacts:**"]
    if not artifact_states:
        lines.append("  - (none recorded)")
        return lines
    for path, state in artifact_states:
        lines.append(f"  - `{path}` (state: {state})")
    return lines


def _credentials_section(credential_rows: list[dict]) -> str:
    """Single-line summary: count + comma-separated ids."""
    count = len(credential_rows)
    ids = ", ".join(
        str(c.get("id"))
        for c in credential_rows
        if isinstance(c, dict) and c.get("id") is not None
    )
    if count == 0:
        return "- **Credentials captured:** 0 rows"
    return f"- **Credentials captured:** {count} rows (ids: {ids or 'unknown'})"


def _next_step_section(next_step: str) -> str:
    """Always-present next-step line so the new dispatch can't silently drop it."""
    if not next_step:
        return (
            "- **Next step (per registry):** not recorded — set explicitly in this dispatch"
        )
    return f"- **Next step (per registry):** {next_step}"


def _truncate_findings(
    lines: list[str], budget: int
) -> tuple[list[str], int]:
    """Trim the findings section to ``budget`` lines.

    Returns ``(kept_lines, truncated_count)`` where ``truncated_count`` is the
    number of finding bullets dropped from the tail. A finding bullet is any
    line starting with ``  - `` (two spaces); evidence sub-lines (``    - ``)
    are dropped together with their parent bullet so the output never shows
    an orphaned evidence line.
    """
    if budget <= 0:
        budget = 1
    if len(lines) <= budget:
        return lines, 0

    kept: list[str] = []
    truncated = 0
    # Walk the input and group each top-level finding bullet with any of its
    # evidence sub-lines (indented four spaces). When the group would push
    # us past the budget, we drop the rest as a single "... and N more" tail.
    i = 0
    while i < len(lines):
        line = lines[i]
        group = [line]
        j = i + 1
        while j < len(lines) and lines[j].startswith("    - "):
            group.append(lines[j])
            j += 1
        if len(kept) + len(group) <= budget:
            kept.extend(group)
            i = j
            continue
        # No room: count this and every later top-level bullet as truncated.
        truncated = 1
        i = j
        while i < len(lines):
            if lines[i].startswith("  - ") and not lines[i].startswith("    - "):
                truncated += 1
            i += 1
        break
    return kept, truncated
