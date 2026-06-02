"""Internal work-buffer and agent lifecycle implementation helpers.

Replaces dispatcher.sh with parameterized SQL.

This package keeps the historical ``from assess.commands import dispatch`` +
``dispatch.<symbol>`` seam intact. ``agent.py`` (the operator-facing ``vigil
assess agent`` command) and ``work_buffer.py`` reach into this module by
attribute, so the public names they use are re-exported here from the owning
submodules:

- ``_shared``           — CLI arg / time / JSON helpers
- ``work_items``        — cases.db work-buffer verbs (stats/peek/fetch/defer/...)
- ``handoff_renderer``  — render-handoff bounded blob emitter
- ``agent``             — backend lifecycle verbs (register/update-status/...)

``run`` itself stays here because it is the single dispatch entry point that
fans out across all three behavioural areas.
"""
from __future__ import annotations

import sys

from assess.lib.classify_buckets import tagged_terminal_reason
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.db import db_init

# Submodules — imported so the package object exposes them as attributes
# (e.g. ``dispatch.work_items``, ``dispatch.agent``) for monkeypatch targeting.
# The redundant ``as`` aliases mark these as intentional re-exports.
from assess.commands.dispatch import _shared as _shared
from assess.commands.dispatch import work_items as work_items
from assess.commands.dispatch import handoff_renderer as handoff_renderer
from assess.commands.dispatch import agent as agent

# Public seam re-exports. Production callers (agent.py / work_buffer.py) and
# the test suite reach these as ``dispatch.<name>``.
from assess.commands.dispatch._shared import _safe_int_arg
from assess.commands.dispatch.work_items import (
    _DB_ACTIONS,
    _stats,
    _peek,
    _fetch,
    _fetch_by_priority,
    _defer_cluster,
    _defer_items,
    _done,
    _error,
    _reset_stale,
    _retry_errors,
    _requeue,
    _stamp_liveness,
)
from assess.commands.dispatch.handoff_renderer import _render_handoff
from assess.commands.dispatch.agent import (
    _DBLESS_ACTIONS,
    _client_for,
    _build_register_payload,
    _register_dispatch,
    _warn_on_overlapping_dispatch,
    _update_dispatch_status,
    _abort_duplicate_dispatch,
    _list_dispatches,
    _get_dispatch,
    _record_decision,
    _record_handoff,
)

__all__ = [
    "run",
    "_DB_ACTIONS",
    "_DBLESS_ACTIONS",
    "_record_handoff",
    "_render_handoff",
    "_record_decision",
    "_list_dispatches",
    "_get_dispatch",
    "_abort_duplicate_dispatch",
    "_update_dispatch_status",
    "_client_for",
    "_build_register_payload",
    "_warn_on_overlapping_dispatch",
    "_stamp_liveness",
    "AssessmentClient",
    "AssessError",
    "load_config",
]


def run(args) -> None:
    db_path = args.db_path
    action = args.action
    extra = args.extra or []

    # render-handoff and other dbless actions don't take a cases.db; the
    # operator types `vigil assess agent render-handoff <agent-id>` and
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
            f"Use: vigil assess agent {suggested_action} {' '.join(extra)}".rstrip(),
            file=sys.stderr,
        )
        sys.exit(1)

    if not action:
        print(
            "Usage: vigil assess agent <backend-action> [args...]\n"
            "       vigil assess work-buffer <cases.db> <work-buffer-action> [...]\n"
            "       vigil assess agent render-handoff <agent-id> [--max-lines N] [--include-evidence]",
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
            f"Usage: vigil assess work-buffer <db> {action} [...]\n"
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
        # Best-effort backend config so claimed rows can carry the host's current
        # liveness verdict into the dispatch context. None → stamping is skipped.
        try:
            liveness_cfg = load_config(getattr(args, "engagement_dir", None))
        except SystemExit:
            liveness_cfg = None
        _fetch_by_priority(
            db_path,
            _safe_int_arg(extra[0], "limit"),
            extra[1] if len(extra) > 1 else "auto",
            cfg=liveness_cfg,
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
        reason_tag = (getattr(args, "reason_tag", "") or "").strip()
        stored = tagged_terminal_reason(reason_tag, reason) if reason_tag else reason
        _defer_cluster(db_path, extra[0], stored)
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
        reason_tag = (getattr(args, "reason_tag", "") or "").strip()
        stored = tagged_terminal_reason(reason_tag, reason) if reason_tag else reason
        _defer_items(db_path, extra, stored)
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
