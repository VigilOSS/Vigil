"""Internal work-buffer and agent lifecycle implementation helpers.

Replaces dispatcher.sh with parameterized SQL.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from typing import Any

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import validate_specialist_dispatch_contract
from assess.lib.db import db_init, db_query, db_exec, db_insert_work_item
from assess.lib.params import extract_url_path, extract_query_params, extract_path_params, generate_params_sig


# Actions that don't need a cases.db (work-buffer SQLite). When the first
# positional arg matches one of these names, we treat it as the action and
# leave db_path empty rather than forcing the operator to pass a useless path.
# Round 9: internal action names register/update-status/list/get/record-decision/
# record-handoff (plus render-handoff) hit the orchestrator backend, not the work buffer.
# Operator CLI maps these to ``aith assess agent start|done|list|get|handoff|decision|...``.
_DBLESS_ACTIONS = (
    "render-handoff",
    "register",
    "update-status",
    "abort-duplicate",
    "list",
    "get",
    "record-decision",
    "record-handoff",
)

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


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def _load_json_arg(value: str | None) -> Any:
    """Read a `--*-json` flag that may be inline JSON or a path to a JSON file."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.startswith("@") or text.startswith("/") or text.endswith(".json"):
        candidate = text[1:] if text.startswith("@") else text
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            # Fall through and try parsing as inline JSON.
            pass
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: failed to read JSON from {candidate}: {exc}", file=sys.stderr)
            sys.exit(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)


def register(subparsers) -> None:
    """LEGACY INTERNAL: attach the historical ``dispatch`` argparse subcommand.

    The operator-facing surface is ``aith assess agent`` and ``aith assess work-buffer``.
    Unit tests and older tooling may still call ``register`` to obtain the combined
    parser; do not wire this into ``cli.py`` as a top-level subcommand.
    """
    p = subparsers.add_parser(
        "dispatch",
        help="INTERNAL: legacy combined parser (use: aith assess agent / work-buffer)",
        usage=(
            "aith assess agent <backend-action> [args...] OR "
            "aith assess work-buffer <cases.db> <work-buffer-action> [args...]"
        ),
    )
    p.add_argument(
        "db_path",
        metavar="action_or_db",
        help=(
            f"Backend action name ({'/'.join(_DBLESS_ACTIONS)}) OR "
            f"path to cases.db for work-buffer actions"
        ),
    )
    p.add_argument(
        "action",
        nargs="?",
        default="",
        help="|".join((*_DB_ACTIONS, *_DBLESS_ACTIONS)),
    )
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument(
        "--reason",
        default="",
        help="Reason for defer-cluster / defer-items / abort-duplicate / agent decision "
        "(required for defer-* and abort-duplicate; optional for decision). Free text; "
        "stored in terminal_reason (defer-*) or the decision payload so operators can audit why "
        "a cluster, item, duplicate dispatch, or operator decision was skipped/aborted/recorded.",
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

    # Backend lifecycle / handoff / decision flags. Internal action names
    # (register/update-status/list/get/record-handoff/record-decision) map to
    # ``aith assess agent start/done/list/get/handoff/decision``.
    p.add_argument("--agent-id", dest="agent_id", default=None,
                   help="(start / done / get / internal handoff) Dispatch agent_id.")
    p.add_argument("--agent-role", dest="agent_role", default=None,
                   help="(start / internal handoff) Specialist role.")
    p.add_argument("--task", dest="task", default=None, help="(start) Task description.")
    p.add_argument("--scope-host", dest="scope_host", default=None, help="(start) Scope host.")
    p.add_argument("--model", dest="dispatch_model", default=None,
                   help="(start) Requested model name (stored as requested_model / model).")
    p.add_argument("--reasoning", dest="reasoning", default=None,
                   choices=("low", "medium", "high"), help="(start) Requested reasoning level.")
    p.add_argument("--dispatch-mode", dest="dispatch_mode_arg", default=None,
                   choices=("hypothesis-driven", "item-iterating", "deep-manual", "variant-rotation"),
                   help="(start) Dispatch loop shape.")
    p.add_argument("--skills", dest="skills", default=None,
                   help="(start) Comma-separated skill names the specialist must load "
                        "(e.g. 'surface-collection,gau-triage'). Required for non-operator "
                        "roles to make skill scope explicit at dispatch time.")
    p.add_argument("--from-json", dest="from_json", default=None,
                   help="(start / internal handoff) Path to JSON payload (overrides flag-based fields).")
    p.add_argument("--allow-duplicate", dest="allow_duplicate", action="store_true",
                   help="(start) Suppress advisory warnings for active overlapping dispatch rows.")
    p.add_argument("--status", dest="dispatch_status", default=None,
                   choices=("in-progress", "completed", "failed", "aborted", "blocked"),
                   help="(done / list) Dispatch lifecycle status.")
    p.add_argument("--completed-at", dest="completed_at", default=None,
                   help="(done) ISO timestamp; defaults to now() when --status is terminal.")
    p.add_argument("--finding-slugs", dest="finding_slugs", default=None,
                   help="(done / internal handoff) Comma-separated slugs.")
    p.add_argument("--replacement-agent-id", dest="replacement_agent_id", default=None,
                   help="(abort-duplicate) Agent ID replacing the accidental duplicate.")
    p.add_argument("--role", dest="filter_role", default=None,
                   help="(list) Filter by agent_role.")
    p.add_argument("--since", dest="filter_since", default=None,
                   help="(list) Filter by dispatched_at >= ISO timestamp.")
    p.add_argument("--task-q", dest="task_q", default=None,
                   help="(list) Substring match against task field.")
    p.add_argument("--limit", dest="dispatch_limit", default=None, type=int,
                   help="(list) Result limit (default 100).")
    # decision / handoff — internal actions map to ``aith assess agent decision|handoff``.
    p.add_argument("--kind", dest="decision_kind", default=None,
                   help="(decision) Decision kind: scope_decision|egress_decision|dispatch_blocked|...")
    p.add_argument("--payload-json", dest="payload_json", default=None,
                   help="(decision) Decision payload (inline JSON or path).")
    p.add_argument("--surfaced-to-user", dest="surfaced_to_user", action="store_true",
                   help="(decision) Mark decision as user-facing.")
    p.add_argument("--host", dest="decision_host", default=None,
                   help="(decision scope_decision shorthand) Host name.")
    p.add_argument("--vendor", dest="decision_vendor", default=None,
                   help="(decision scope_decision shorthand) Vendor name.")
    p.add_argument("--choice", dest="decision_choice", default=None,
                   help="(decision shorthand) User choice / decision label.")
    p.add_argument("--note", dest="decision_note", default=None,
                   help="(decision shorthand) Free-text note attached to payload.")
    p.add_argument("--phase", dest="decision_phase", default=None,
                   help="(decision dispatch_blocked shorthand) Phase tag.")
    # Handoff payload flags (internal action name remains record-handoff).
    p.add_argument("--summary", dest="hf_summary", default=None,
                   help="(handoff) Required summary text (≤2000 chars).")
    p.add_argument("--confidence", dest="hf_confidence", default=None,
                   choices=("low", "medium", "high"), help="(handoff) Confidence level.")
    p.add_argument("--next-step", dest="hf_next_steps", action="append", default=None,
                   help="(handoff) Next-step action; repeat to add multiple.")
    p.add_argument("--coverage-gap", dest="hf_coverage_gaps", action="append", default=None,
                   help="(handoff) '<area>: <reason>' coverage-gap entry; repeatable.")
    p.add_argument("--runtime-issue", dest="hf_runtime_issues", action="append", default=None,
                   help="(handoff) '<kind>: <detail>' runtime-issue entry; repeatable.")
    p.add_argument("--working-artifact", dest="hf_working_artifacts", action="append", default=None,
                   help="(handoff) Path to a working artifact; repeatable.")
    p.add_argument("--open-question", dest="hf_open_questions", action="append", default=None,
                   help="(handoff) Open question; repeatable.")
    p.add_argument("--recommended-next-agent", dest="hf_recommended_next_agent", default=None,
                   help="(handoff) Suggested next role.")
    p.add_argument("--extras-json", dest="hf_extras_json", default=None,
                   help="(handoff) Extras dict (inline JSON or path).")
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    action = args.action
    extra = args.extra or []

    # render-handoff and other dbless actions don't take a cases.db; the
    # operator types `aith assess agent render-handoff <agent-id>` and
    # argparse parks the action name in the db_path slot. Shift it so the
    # rest of the dispatcher can route normally.
    if (db_path or "") in _DBLESS_ACTIONS:
        if action:
            # Operator typed the action where db_path goes; whatever landed
            # in the action slot is actually the first action-specific arg.
            extra = [action] + list(extra)
        action = db_path
        db_path = ""

    if action in _DBLESS_ACTIONS and db_path:
        suggested_action = {
            "record-handoff": "handoff",
            "record-decision": "decision",
            "register": "start",
            "update-status": "done",
        }.get(action, action)
        print(
            f"ERROR: '{action}' is a backend agent lifecycle action and must not take a cases.db path.\n"
            f"Use: aith assess agent {suggested_action} {' '.join(extra)}".rstrip(),
            file=sys.stderr,
        )
        sys.exit(1)

    if not action:
        print(
            "Usage: aith assess agent <backend-action> [args...]\n"
            "       aith assess work-buffer <cases.db> <work-buffer-action> [...]\n"
            "       aith assess agent render-handoff <agent-id> [--max-lines N] [--include-evidence]",
            file=sys.stderr,
        )
        sys.exit(1)

    if action == "render-handoff":
        _render_handoff(args, extra)
        return
    if action == "register":
        _register_dispatch(args)
        return
    if action == "update-status":
        _update_dispatch_status(args, extra)
        return
    if action == "abort-duplicate":
        _abort_duplicate_dispatch(args, extra)
        return
    if action == "list":
        _list_dispatches(args)
        return
    if action == "get":
        _get_dispatch(args, extra)
        return
    if action == "record-decision":
        _record_decision(args)
        return
    if action == "record-handoff":
        _record_handoff(args)
        return

    if not db_path:
        print(
            f"Usage: aith assess work-buffer <db> {action} [...]\n"
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
            print("Usage: work-buffer <db> peek <type> [limit]", file=sys.stderr)
            sys.exit(1)
        peek_type = extra[0]
        peek_limit = _safe_int_arg(extra[1], "limit") if len(extra) > 1 else 10
        _peek(db_path, peek_type, peek_limit)
    elif action == "fetch":
        if len(extra) < 3:
            print("Usage: work-buffer <db> fetch <type> <limit> <agent>", file=sys.stderr)
            sys.exit(1)
        _fetch(db_path, extra[0], _safe_int_arg(extra[1], "limit"), extra[2])
    elif action == "fetch-by-priority":
        if len(extra) < 1:
            print(
                "Usage: work-buffer <db> fetch-by-priority <limit> [auto|agent]",
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
                "Usage: work-buffer <db> defer-cluster <cluster_key> --reason TEXT",
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
                "Usage: work-buffer <db> defer-items <id> [<id> ...] --reason TEXT\n"
                "       work-buffer <db> defer-items <id1,id2,...> --reason TEXT",
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
            print("Usage: work-buffer <db> done <id> [<id> ...]", file=sys.stderr)
            sys.exit(1)
        _done(db_path, extra)
    elif action == "error":
        if not extra:
            print("Usage: work-buffer <db> error <id> [<id> ...]", file=sys.stderr)
            sys.exit(1)
        _error(db_path, extra)
    elif action == "reset-stale":
        if not extra:
            print("Usage: work-buffer <db> reset-stale <minutes>", file=sys.stderr)
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
            f"Work-buffer actions: {', '.join(_DB_ACTIONS)}\n"
            f"Agent lifecycle actions (no cases.db): {', '.join(_DBLESS_ACTIONS)}",
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


def _fetch_by_priority(db_path: str, limit: int, agent: str) -> None:
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
    import sqlite3

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
# pulls from durable state (the orchestrator's assessment_dispatches +
# assessment_dispatch_handoffs tables) and emits a markdown blob the operator
# pastes verbatim into the next dispatch prompt. The output is hard-capped
# at --max-lines (default 40); the
# findings list collapses to "... and N more" before any fixed sections drop.
# ---------------------------------------------------------------------------


def _render_handoff(args, extra: list[str]) -> None:
    """Emit a bounded markdown handoff blob for a prior dispatch.

    Reads from the orchestrator backend (assessment_dispatches +
    assessment_dispatch_handoffs). The handoff payload provides
    summary / coverage gaps / next steps / runtime issues / working artifacts
    / open questions / extras; the dispatch row provides metadata (role,
    task, scope_host, dispatched_at, status). 404 on the
    handoff exits 2; 404 on the dispatch row is non-fatal — the renderer
    still produces output from the handoff.
    """
    if not extra:
        print(
            "Usage: aith assess agent render-handoff <agent-id> "
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

    cfg = load_config(getattr(args, "engagement_dir", None))
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        handoff = client.get_handoff(agent_id)
        if handoff is None:
            print(
                f"render-handoff: agent-id '{agent_id}' has no recorded handoff in the backend "
                f"(GET dispatch-handoffs/{agent_id} -> 404). Specialist dispatches should call "
                f"`aith assess agent handoff` before exiting; a missing handoff means "
                f"the prior dispatch never wrote one (or the id was mistyped).",
                file=sys.stderr,
            )
            sys.exit(2)

        dispatch = client.get_dispatch(agent_id)  # 404 -> None, render with handoff-only data
        # ── Pull metadata from dispatch row when present, fall back to the
        # handoff itself otherwise.
        if dispatch is not None:
            role = str(dispatch.get("agent_role") or handoff.get("agent_role") or "<unknown role>")
            task = str(dispatch.get("task") or "<unrecorded task>")
            scope_host = dispatch.get("scope_host") or ""
            dispatched_at = dispatch.get("dispatched_at") or ""
            dispatch_status = dispatch.get("status") or ""
            skills = str(dispatch.get("skills") or "")
        else:
            role = str(handoff.get("agent_role") or "<unknown role>")
            task = "<unrecorded task>"
            scope_host = ""
            dispatched_at = handoff.get("created_at") or ""
            dispatch_status = "(dispatch row missing)"
            skills = ""

        # Handoff payload extraction. JSON columns deserialize to lists/dicts
        # in the state-manager serializer; treat anything else defensively.
        finding_slugs = handoff.get("finding_slugs") or []
        if not isinstance(finding_slugs, list):
            finding_slugs = []
        finding_slugs = [str(s).strip() for s in finding_slugs if str(s).strip()]

        next_steps = handoff.get("next_steps") or []
        if not isinstance(next_steps, list):
            next_steps = []
        coverage_gaps = handoff.get("coverage_gaps") or []
        if not isinstance(coverage_gaps, list):
            coverage_gaps = []
        runtime_issues = handoff.get("runtime_issues") or []
        if not isinstance(runtime_issues, list):
            runtime_issues = []
        working_artifacts_payload = handoff.get("working_artifacts") or []
        if not isinstance(working_artifacts_payload, list):
            working_artifacts_payload = []
        open_questions = handoff.get("open_questions") or []
        if not isinstance(open_questions, list):
            open_questions = []
        recommended_next_agent = str(handoff.get("recommended_next_agent") or "")
        summary = str(handoff.get("summary") or "")
        confidence = str(handoff.get("confidence") or "")

        # Per-slug enrichment from the backend. Tolerate 404s — the operator
        # may have killed a finding between dispatch and handoff render.
        # ISSUE-010 fix: the previous fallback emitted "non-dict response" when
        # GET findings/{slug} responded with anything other than a dict, which
        # confused operators because the same wording fired for both "slug
        # missing" and "backend returned a list / unexpected payload". The
        # 404 path now emits "slug missing in backend (deleted or never
        # recorded)" explicitly, distinct from "fetch error: <reason>".
        finding_rows: list[dict] = []
        for slug in finding_slugs:
            try:
                row = client.get(f"findings/{slug}")
            except AssessError as exc:
                if "HTTP 404" in str(exc):
                    finding_rows.append({"slug": slug, "_missing": True})
                    continue
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
                credential_rows = [
                    c for c in creds
                    if isinstance(c, dict) and (c.get("source_name") or "") == role
                ]
    finally:
        client.close()

    # Local-disk presence check for working artifacts. The new payload uses
    # objects with a 'path' key; tolerate plain strings for forward-compat.
    artifact_states: list[tuple[str, str]] = []
    for entry in working_artifacts_payload:
        if isinstance(entry, dict):
            raw_path = str(entry.get("path") or "").strip()
        else:
            raw_path = str(entry).strip()
        if not raw_path:
            continue
        full = raw_path if os.path.isabs(raw_path) else os.path.join(cfg.engagement_dir, raw_path)
        artifact_states.append((raw_path, "present" if os.path.exists(full) else "missing"))

    blob = _render_handoff_blob(
        agent_id=agent_id,
        role=role,
        task=task,
        scope_host=scope_host,
        dispatched_at=dispatched_at,
        status=dispatch_status,
        skills=skills,
        summary=summary,
        confidence=confidence,
        finding_rows=finding_rows,
        coverage_gaps=coverage_gaps,
        next_steps=next_steps,
        open_questions=open_questions,
        artifact_states=artifact_states,
        runtime_issues=runtime_issues,
        recommended_next_agent=recommended_next_agent,
        credential_rows=credential_rows,
        include_evidence=include_evidence,
        max_lines=max_lines,
    )
    print(blob)


def _render_handoff_blob(
    *,
    agent_id: str,
    role: str,
    task: str,
    scope_host: str,
    dispatched_at: str,
    status: str,
    skills: str,
    summary: str,
    confidence: str,
    finding_rows: list[dict],
    coverage_gaps: list[dict],
    next_steps: list[dict],
    open_questions: list,
    artifact_states: list[tuple[str, str]],
    runtime_issues: list[dict],
    recommended_next_agent: str,
    credential_rows: list[dict],
    include_evidence: bool,
    max_lines: int,
) -> str:
    """Build the markdown handoff blob with the documented section order.

    Round 9 section order: header / summary / confidence / findings /
    coverage gaps / next steps / open questions / working artifacts /
    runtime issues / recommended next agent. Trim policy on overflow:
    findings list collapses first ("... and N more"), then runtime_issues,
    then working_artifacts. Summary, next_steps, coverage_gaps are NEVER
    trimmed (they are the load-bearing handoff content).
    """
    head = [
        f"#### Handoff from {role} dispatch {agent_id}",
        f"- **Prior task:** {task}",
        f"- **Scope host:** {scope_host or '(none recorded)'}",
        f"- **Dispatched at:** {dispatched_at or '(unknown)'} (status: {status or 'unknown'})",
    ]
    # Skills loaded by the prior dispatch are part of the audit surface — the
    # next dispatch should know which procedure context the previous agent
    # carried so it can either continue with the same skills or change loadout
    # deliberately. Operators are exempt from declaring skills, so an empty
    # value is rendered as a clear marker rather than dropped silently.
    if skills:
        head.append(f"- **Skills loaded:** {skills}")
    elif role and role != "operator":
        head.append("- **Skills loaded:** (not recorded)")

    summary_lines = _summary_section(summary, confidence)
    finding_lines = _findings_section(finding_rows, include_evidence=include_evidence)
    coverage_lines = _coverage_gaps_section(coverage_gaps)
    next_steps_lines = _next_steps_section(next_steps)
    open_questions_lines = _open_questions_section(open_questions)
    recommended_line = _recommended_next_agent_section(recommended_next_agent)
    credentials_line = _credentials_section(credential_rows)

    # Compose the line list. Trim order: findings → runtime_issues →
    # artifacts. Summary, coverage_gaps, next_steps stay intact.
    def _compose(findings_kept: list[str], findings_dropped: int,
                 artifacts_kept: list[tuple[str, str]],
                 runtime_kept: list[dict], runtime_dropped: int,
                 artifacts_dropped: int) -> list[str]:
        out: list[str] = []
        out.extend(head)
        out.extend(summary_lines)
        out.append("- **Findings recorded:**")
        out.extend(findings_kept)
        if findings_dropped > 0:
            out.append(f"  - ... and {findings_dropped} more")
        out.extend(coverage_lines)
        out.extend(next_steps_lines)
        out.extend(open_questions_lines)
        artifacts_section_lines = _artifacts_section(artifacts_kept)
        out.extend(artifacts_section_lines)
        if artifacts_dropped > 0:
            out.append(f"  - ... and {artifacts_dropped} more")
        runtime_section_lines = _runtime_issues_section(runtime_kept)
        out.extend(runtime_section_lines)
        if runtime_dropped > 0:
            out.append(f"  - ... and {runtime_dropped} more")
        out.append(recommended_line)
        out.append(credentials_line)
        return out

    composed = _compose(finding_lines, 0, artifact_states, runtime_issues, 0, 0)
    if len(composed) <= max_lines:
        return "\n".join(composed)

    # First-pass trim: findings.
    overhead_no_findings = len(_compose([], len(finding_lines), artifact_states, runtime_issues, 0, 0))
    findings_budget = max(1, max_lines - (overhead_no_findings - 1))
    findings_kept, findings_dropped = _truncate_findings(finding_lines, findings_budget)
    composed = _compose(findings_kept, findings_dropped, artifact_states, runtime_issues, 0, 0)
    if len(composed) <= max_lines:
        return "\n".join(composed)

    # Second-pass trim: runtime issues.
    overhead_no_runtime = len(
        _compose(findings_kept, findings_dropped, artifact_states, [], len(runtime_issues), 0)
    )
    runtime_budget = max(0, max_lines - overhead_no_runtime)
    runtime_kept = runtime_issues[:runtime_budget]
    runtime_dropped = max(0, len(runtime_issues) - runtime_budget)
    composed = _compose(
        findings_kept, findings_dropped, artifact_states, runtime_kept, runtime_dropped, 0
    )
    if len(composed) <= max_lines:
        return "\n".join(composed)

    # Third-pass trim: working artifacts.
    overhead_no_artifacts = len(
        _compose(findings_kept, findings_dropped, [], runtime_kept, runtime_dropped, len(artifact_states))
    )
    artifacts_budget = max(0, max_lines - overhead_no_artifacts)
    artifacts_kept = artifact_states[:artifacts_budget]
    artifacts_dropped = max(0, len(artifact_states) - artifacts_budget)
    composed = _compose(
        findings_kept,
        findings_dropped,
        artifacts_kept,
        runtime_kept,
        runtime_dropped,
        artifacts_dropped,
    )
    return "\n".join(composed)


def _summary_section(summary: str, confidence: str) -> list[str]:
    text = summary.strip() if summary else ""
    lines: list[str] = ["- **Summary:**"]
    if not text:
        lines.append("  - (none recorded)")
    else:
        for chunk in text.splitlines() or [text]:
            chunk = chunk.rstrip()
            if chunk:
                lines.append(f"  {chunk}")
    if confidence:
        lines.append(f"- **Confidence:** {confidence}")
    return lines


def _coverage_gaps_section(rows: list) -> list[str]:
    lines = ["- **Coverage gaps:**"]
    if not rows:
        lines.append("  - (none recorded)")
        return lines
    for row in rows:
        if isinstance(row, dict):
            area = str(row.get("area") or "<area>")
            reason = str(row.get("reason") or "")
            followup = str(row.get("recommended_followup") or row.get("followup") or "")
            tail = f" — {reason}" if reason else ""
            if followup:
                tail += f" (next: {followup})"
            lines.append(f"  - {area}{tail}")
        else:
            lines.append(f"  - {row}")
    return lines


def _next_steps_section(rows: list) -> list[str]:
    lines = ["- **Next steps:**"]
    if not rows:
        lines.append("  - (none recorded — set explicitly in this dispatch)")
        return lines
    for row in rows:
        if isinstance(row, dict):
            action = str(row.get("action") or "<action>")
            target = str(row.get("target") or "")
            agent = str(row.get("recommended_agent") or "")
            rationale = str(row.get("rationale") or "")
            extras = []
            if target:
                extras.append(f"target={target}")
            if agent:
                extras.append(f"agent={agent}")
            if rationale:
                extras.append(rationale)
            tail = f" ({'; '.join(extras)})" if extras else ""
            lines.append(f"  - {action}{tail}")
        else:
            lines.append(f"  - {row}")
    return lines


def _open_questions_section(rows: list) -> list[str]:
    if not rows:
        return []
    lines = ["- **Open questions:**"]
    for row in rows:
        lines.append(f"  - {row}")
    return lines


def _runtime_issues_section(rows: list) -> list[str]:
    if not rows:
        return []
    lines = ["- **Runtime issues:**"]
    for row in rows:
        if isinstance(row, dict):
            kind = str(row.get("kind") or "<kind>")
            detail = str(row.get("detail") or "")
            severity = str(row.get("severity") or "")
            tail = f" — {detail}" if detail else ""
            if severity:
                tail += f" [severity={severity}]"
            lines.append(f"  - {kind}{tail}")
        else:
            lines.append(f"  - {row}")
    return lines


def _recommended_next_agent_section(value: str) -> str:
    if not value:
        return "- **Recommended next agent:** (none recorded)"
    return f"- **Recommended next agent:** {value}"


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


# ---------------------------------------------------------------------------
# Backend agent lifecycle verbs (internal action names register / update-status /
# record-decision / record-handoff) — backend-table writes via the orchestrator API.
# ---------------------------------------------------------------------------


def _client_for(args) -> tuple[AssessmentClient, Any]:
    cfg = load_config(getattr(args, "engagement_dir", None))
    return AssessmentClient(cfg.base_url, cfg.engagement_key), cfg


def _build_register_payload(args) -> dict:
    payload: dict[str, Any] = {}
    if getattr(args, "from_json", None):
        loaded = _load_json_arg(args.from_json)
        if not isinstance(loaded, dict):
            print("agent start --from-json: file must contain a JSON object", file=sys.stderr)
            sys.exit(1)
        payload.update(loaded)
    # CLI flags override / supplement the JSON payload.
    cli_fields = {
        "agent_id": getattr(args, "agent_id", None),
        "agent_role": getattr(args, "agent_role", None),
        "task": getattr(args, "task", None),
        "scope_host": getattr(args, "scope_host", None),
        "requested_model": getattr(args, "dispatch_model", None),
        "requested_reasoning": getattr(args, "reasoning", None),
        "dispatch_mode": getattr(args, "dispatch_mode_arg", None),
        "skills": getattr(args, "skills", None),
    }
    for k, v in cli_fields.items():
        if v is not None:
            payload[k] = v
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        payload["finding_slugs"] = finding_slugs
    if not payload.get("agent_id"):
        print("agent start: --agent-id is required (or include 'agent_id' in --from-json)", file=sys.stderr)
        sys.exit(1)
    if not payload.get("agent_role"):
        print("agent start: --agent-role is required (or include 'agent_role' in --from-json)", file=sys.stderr)
        sys.exit(1)
    errors, warnings = validate_specialist_dispatch_contract(payload)
    for warning in warnings:
        print(f"WARN agent start: {warning}", file=sys.stderr)
    if errors:
        for error in errors:
            print(f"agent start: {error}", file=sys.stderr)
        sys.exit(1)
    skills_value = payload.get("skills")
    if isinstance(skills_value, list):
        payload["skills"] = ",".join(str(skill).strip() for skill in skills_value)
    return payload


def _register_dispatch(args) -> None:
    payload = _build_register_payload(args)
    client, _ = _client_for(args)
    try:
        if not getattr(args, "allow_duplicate", False):
            _warn_on_overlapping_dispatch(client, payload)
        row = client.record_dispatch(payload)
    finally:
        client.close()
    print(json.dumps({
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "status": row.get("status"),
    }, ensure_ascii=False))


def _warn_on_overlapping_dispatch(client: AssessmentClient, payload: dict[str, Any]) -> None:
    """Emit an advisory warning for exact structured overlap.

    This intentionally does not block. Parallel dispatches often share a role,
    host, or prose objective for legitimate reasons; only concrete overlap on
    refs or an exact copied task gets surfaced.
    """
    role = str(payload.get("agent_role") or "")
    if not role:
        return
    try:
        rows = client.list_dispatches(role=role, status="in-progress", limit=1000)
    except AssessError as exc:
        print(f"WARN agent start: duplicate-overlap check skipped: {exc}", file=sys.stderr)
        return
    current_agent_id = str(payload.get("agent_id") or "")
    overlaps: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        if str(row.get("agent_id") or "") == current_agent_id:
            continue
        reason = _dispatch_overlap_reason(payload, row)
        if reason:
            overlaps.append((row, reason))
    if not overlaps:
        return
    print(
        "WARN agent start: active dispatch rows appear to overlap this dispatch. "
        "Registration will continue; use --allow-duplicate to suppress this advisory "
        "when the overlap is intentional.",
        file=sys.stderr,
    )
    for row, reason in overlaps[:5]:
        print(
            f"  - {row.get('agent_id', '?')} ({row.get('agent_role', '?')}): {reason}",
            file=sys.stderr,
        )


def _dispatch_overlap_reason(payload: dict[str, Any], row: dict[str, Any]) -> str:
    finding_overlap = _set_overlap(payload.get("finding_slugs"), row.get("finding_slugs"))
    if finding_overlap:
        return "same finding_slugs: " + ",".join(sorted(finding_overlap))
    task = _norm_text(payload.get("task"))
    if task and task == _norm_text(row.get("task")):
        return "exact same task text"
    return ""


def _norm_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _same_nonempty(left: dict[str, Any], right: dict[str, Any], key: str) -> bool:
    left_value = _norm_text(left.get(key))
    return bool(left_value) and left_value == _norm_text(right.get(key))


def _set_overlap(left: Any, right: Any) -> set[str]:
    return _string_set(left) & _string_set(right)


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        return set()
    return {str(item).strip() for item in items if str(item).strip()}


def _update_dispatch_status(args, extra: list[str]) -> None:
    agent_id = (extra[0].strip() if extra else (getattr(args, "agent_id", "") or ""))
    if not agent_id:
        print("Usage: aith assess agent done <agent-id> --status ...", file=sys.stderr)
        sys.exit(1)
    patch: dict[str, Any] = {}
    if getattr(args, "dispatch_status", None):
        patch["status"] = args.dispatch_status
        if args.dispatch_status in ("completed", "failed", "aborted", "blocked"):
            patch["completed_at"] = getattr(args, "completed_at", None) or _utcnow_iso()
    elif getattr(args, "completed_at", None):
        patch["completed_at"] = args.completed_at
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        patch["finding_slugs"] = finding_slugs
    if not patch:
        print(
            "agent done: pass at least one of --status, --completed-at, --finding-slugs",
            file=sys.stderr,
        )
        sys.exit(1)
    client, _ = _client_for(args)
    try:
        row = client.update_dispatch(agent_id, patch)
    finally:
        client.close()
    print(json.dumps(row, ensure_ascii=False))


def _abort_duplicate_dispatch(args, extra: list[str]) -> None:
    agent_id = (extra[0].strip() if extra else (getattr(args, "agent_id", "") or ""))
    replacement = (getattr(args, "replacement_agent_id", "") or "").strip()
    reason = (getattr(args, "reason", "") or "").strip()
    if not agent_id or not replacement or not reason:
        print(
            "Usage: aith assess agent abort-duplicate <agent-id> "
            "--replacement-agent-id <agent-id> --reason TEXT",
            file=sys.stderr,
        )
        sys.exit(1)
    if agent_id == replacement:
        print(
            "abort-duplicate: --replacement-agent-id must point at the dispatch to keep, "
            "not the duplicate being aborted.",
            file=sys.stderr,
        )
        sys.exit(1)
    client, _ = _client_for(args)
    now = _utcnow_iso()
    try:
        replacement_row = client.get_dispatch(replacement)
        if replacement_row is None:
            print(
                f"abort-duplicate: replacement dispatch '{replacement}' was not found; "
                "register the canonical replacement before aborting the duplicate.",
                file=sys.stderr,
            )
            sys.exit(2)
        row = client.update_dispatch(agent_id, {"status": "aborted", "completed_at": now})
        decision = client.record_decision(
            {
                "kind": "dispatch_duplicate",
                "payload": {
                    "aborted_agent_id": agent_id,
                    "replacement_agent_id": replacement,
                    "reason": reason,
                },
                "surfaced_to_user": False,
            }
        )
    finally:
        client.close()
    print(json.dumps({"dispatch": row, "decision": decision}, ensure_ascii=False))


def _list_dispatches(args) -> None:
    filters: dict[str, Any] = {}
    role = getattr(args, "filter_role", None)
    if role:
        filters["role"] = role
    status_value = getattr(args, "dispatch_status", None)
    if status_value:
        filters["status"] = status_value
    since = getattr(args, "filter_since", None)
    if since:
        filters["since"] = since
    task_q = getattr(args, "task_q", None)
    if task_q:
        filters["task_q"] = task_q
    limit = getattr(args, "dispatch_limit", None)
    if limit:
        filters["limit"] = int(limit)
    client, _ = _client_for(args)
    try:
        rows = client.list_dispatches(**filters)
    finally:
        client.close()
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))


def _get_dispatch(args, extra: list[str]) -> None:
    agent_id = (extra[0].strip() if extra else (getattr(args, "agent_id", "") or ""))
    if not agent_id:
        print("Usage: aith assess agent get <agent-id>", file=sys.stderr)
        sys.exit(1)
    client, _ = _client_for(args)
    try:
        row = client.get_dispatch(agent_id)
    finally:
        client.close()
    if row is None:
        print(f"agent get: agent_id '{agent_id}' not found", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(row, ensure_ascii=False))


def _record_decision(args) -> None:
    kind = getattr(args, "decision_kind", None)
    if not kind:
        print("agent decision: --kind is required", file=sys.stderr)
        sys.exit(1)
    payload_json = getattr(args, "payload_json", None)
    if payload_json:
        loaded = _load_json_arg(payload_json)
        if not isinstance(loaded, dict):
            print("agent decision --payload-json: must produce a JSON object", file=sys.stderr)
            sys.exit(1)
        payload = dict(loaded)
    else:
        # Build payload from friendly flags. The fields we collect depend on
        # the kind, but we do not enforce strict per-kind shape — the backend
        # accepts any dict. Operators can always fall back to --payload-json.
        payload = {}
        host = getattr(args, "decision_host", None)
        vendor = getattr(args, "decision_vendor", None)
        choice = getattr(args, "decision_choice", None)
        note = getattr(args, "decision_note", None)
        reason = getattr(args, "reason", None)
        phase = getattr(args, "decision_phase", None)
        if host:
            payload["host"] = host
        if vendor:
            payload["vendor"] = vendor
        if choice:
            payload["choice"] = choice
        if note:
            payload["note"] = note
        if reason:
            payload["reason"] = reason
        if phase:
            payload["phase"] = phase
        if not payload:
            print(
                "agent decision: pass --payload-json or at least one of "
                "--host/--vendor/--choice/--note/--reason/--phase",
                file=sys.stderr,
            )
            sys.exit(1)
    body = {
        "kind": kind,
        "payload": payload,
        "surfaced_to_user": bool(getattr(args, "surfaced_to_user", False)),
    }
    client, _ = _client_for(args)
    try:
        row = client.record_decision(body)
    finally:
        client.close()
    print(json.dumps(row, ensure_ascii=False))


def _build_handoff_payload(args) -> dict:
    if getattr(args, "from_json", None):
        loaded = _load_json_arg(args.from_json)
        if not isinstance(loaded, dict):
            print("agent handoff --from-json: file must contain a JSON object", file=sys.stderr)
            sys.exit(1)
        # When --from-json is given we honour it as the authoritative shape,
        # but explicit identity flags are integrity checks. A mismatch usually
        # means the handoff is about to be written under a label that the
        # operator cannot retrieve by the actual spawned agent id.
        for key, val in (
            ("agent_id", getattr(args, "agent_id", None)),
            ("agent_role", getattr(args, "agent_role", None)),
            ("summary", getattr(args, "hf_summary", None)),
        ):
            if not val:
                continue
            existing = loaded.get(key)
            if existing and str(existing) != str(val):
                print(
                    f"agent handoff: --from-json {key}={existing!r} does not match "
                    f"explicit --{key.replace('_', '-')} {val!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            loaded[key] = val
        return loaded

    payload: dict[str, Any] = {}
    agent_id = getattr(args, "agent_id", None)
    agent_role = getattr(args, "agent_role", None)
    summary = getattr(args, "hf_summary", None)
    if not agent_id or not agent_role or not summary:
        print(
            "agent handoff: --agent-id, --agent-role, and --summary are required "
            "(or pass --from-json with a payload that supplies them)",
            file=sys.stderr,
        )
        sys.exit(1)
    payload["agent_id"] = agent_id
    payload["agent_role"] = agent_role
    payload["summary"] = summary
    if getattr(args, "hf_confidence", None):
        payload["confidence"] = args.hf_confidence
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        payload["finding_slugs"] = finding_slugs
    next_steps_raw = getattr(args, "hf_next_steps", None) or []
    if next_steps_raw:
        payload["next_steps"] = [{"action": item} for item in next_steps_raw]
    coverage_raw = getattr(args, "hf_coverage_gaps", None) or []
    if coverage_raw:
        coverage_rows = []
        for item in coverage_raw:
            area, _, reason = item.partition(":")
            coverage_rows.append({"area": area.strip(), "reason": reason.strip()})
        payload["coverage_gaps"] = coverage_rows
    runtime_raw = getattr(args, "hf_runtime_issues", None) or []
    if runtime_raw:
        runtime_rows = []
        for item in runtime_raw:
            kind_part, _, detail = item.partition(":")
            runtime_rows.append({
                "kind": kind_part.strip(),
                "detail": detail.strip(),
                "severity": "info",
            })
        payload["runtime_issues"] = runtime_rows
    artifacts_raw = getattr(args, "hf_working_artifacts", None) or []
    if artifacts_raw:
        payload["working_artifacts"] = [{"path": p} for p in artifacts_raw]
    open_qs = getattr(args, "hf_open_questions", None) or []
    if open_qs:
        payload["open_questions"] = list(open_qs)
    if getattr(args, "hf_recommended_next_agent", None):
        payload["recommended_next_agent"] = args.hf_recommended_next_agent
    extras_json = getattr(args, "hf_extras_json", None)
    if extras_json:
        loaded = _load_json_arg(extras_json)
        if not isinstance(loaded, dict):
            print("agent handoff --extras-json: must produce a JSON object", file=sys.stderr)
            sys.exit(1)
        payload["extras"] = loaded
    return payload


def _record_handoff(args) -> None:
    # If both --from-json and flag-based content are given, honour --from-json
    # but warn so the operator notices they're mixing modes (the JSON wins).
    has_flag_based = any(
        getattr(args, name, None)
        for name in (
            "hf_summary",
            "hf_confidence",
            "hf_next_steps",
            "hf_coverage_gaps",
            "hf_runtime_issues",
            "hf_working_artifacts",
            "hf_open_questions",
            "hf_recommended_next_agent",
            "hf_extras_json",
        )
    )
    if getattr(args, "from_json", None) and has_flag_based:
        print(
            "agent handoff: --from-json is set and flag-based content was also "
            "supplied; flag-based fields are ignored except as fallback for "
            "agent_id / agent_role / summary.",
            file=sys.stderr,
        )
    payload = _build_handoff_payload(args)
    client, _ = _client_for(args)
    try:
        # Idempotent by design: agents call record-handoff after every major
        # step in their methodology, so the same (engagement, agent_id) tuple
        # collides on each subsequent call. The client retries the POST as a
        # PATCH on 409 transparently.
        row = client.record_handoff(payload, upsert=True)
    finally:
        client.close()
    print(json.dumps({
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
    }, ensure_ascii=False))
