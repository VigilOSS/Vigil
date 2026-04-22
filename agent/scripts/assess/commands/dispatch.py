"""assess.py dispatch — SQLite work-buffer consumption engine.

Replaces dispatcher.sh with parameterized SQL.
"""
from __future__ import annotations

import json
import sys

from assess.lib.db import db_init, db_query, db_exec, db_insert_work_item
from assess.lib.params import extract_url_path, extract_query_params, extract_path_params, generate_params_sig


def register(subparsers) -> None:
    p = subparsers.add_parser("dispatch", help="Work-buffer dispatch engine")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "action",
        help="stats|fetch|fetch-by-priority|defer-cluster|done|error|reset-stale|retry-errors|migrate|requeue",
    )
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument(
        "--reason",
        default="",
        help="Reason for defer-cluster (required for that action). Free text; "
        "stored in terminal_reason so operators can audit why a cluster was skipped.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    action = args.action
    extra = args.extra or []

    db_init(db_path)

    if action == "stats":
        _stats(db_path)
    elif action == "fetch":
        if len(extra) < 3:
            print("Usage: dispatch <db> fetch <type> <limit> <agent>", file=sys.stderr)
            sys.exit(1)
        _fetch(db_path, extra[0], int(extra[1]), extra[2])
    elif action == "fetch-by-priority":
        if len(extra) < 1:
            print(
                "Usage: dispatch <db> fetch-by-priority <limit> [auto|agent]",
                file=sys.stderr,
            )
            sys.exit(1)
        _fetch_by_priority(db_path, int(extra[0]), extra[1] if len(extra) > 1 else "auto")
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
    elif action == "done":
        if not extra:
            print("Usage: dispatch <db> done <id_list>", file=sys.stderr)
            sys.exit(1)
        _done(db_path, extra[0])
    elif action == "error":
        if not extra:
            print("Usage: dispatch <db> error <id_list>", file=sys.stderr)
            sys.exit(1)
        _error(db_path, extra[0])
    elif action == "reset-stale":
        if not extra:
            print("Usage: dispatch <db> reset-stale <minutes>", file=sys.stderr)
            sys.exit(1)
        _reset_stale(db_path, int(extra[0]))
    elif action == "retry-errors":
        max_retries = int(extra[0]) if extra else 2
        _retry_errors(db_path, max_retries)
    elif action == "migrate":
        pass  # db_init already ran
    elif action == "requeue":
        _requeue(db_path)
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        print(
            "Actions: stats, fetch, fetch-by-priority, defer-cluster, done, error, "
            "reset-stale, retry-errors, migrate, requeue",
            file=sys.stderr,
        )
        sys.exit(1)


def _stats(db_path: str) -> None:
    print("--- Work Buffer Statistics ---")
    rows = db_query(db_path, "SELECT status, type, COUNT(*) as count FROM work_items GROUP BY status, type ORDER BY status, type")
    for row in rows:
        print(f"{row['status']}|{row['type']}|{row['count']}")
    print()
    print("--- Summary ---")
    rows = db_query(db_path, "SELECT status, COUNT(*) as count FROM work_items GROUP BY status ORDER BY status")
    for row in rows:
        print(f"{row['status']}|{row['count']}")
    print()
    rows = db_query(db_path, "SELECT 'TOTAL' as label, COUNT(*) as count FROM work_items")
    for row in rows:
        print(f"{row['label']}|{row['count']}")


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


def _validate_id_list(id_list: str) -> list[int]:
    """Validate and parse comma-separated ID list."""
    import re
    if not re.match(r"^[0-9,]+$", id_list):
        print("ERROR: id_list must contain only numeric IDs separated by commas", file=sys.stderr)
        sys.exit(1)
    return [int(x) for x in id_list.split(",") if x]


def _done(db_path: str, id_list: str) -> None:
    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    db_exec(db_path, f"UPDATE work_items SET status='done' WHERE id IN ({placeholders})", tuple(ids))
    print(f"Marked done: {id_list}")


def _error(db_path: str, id_list: str) -> None:
    ids = _validate_id_list(id_list)
    placeholders = ",".join("?" * len(ids))
    db_exec(
        db_path,
        f"UPDATE work_items SET status='error', retry_count = COALESCE(retry_count,0) + 1 WHERE id IN ({placeholders})",
        tuple(ids),
    )
    print(f"Marked error: {id_list}")


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
