"""Internal work-buffer and agent lifecycle implementation helpers.

Replaces dispatcher.sh with parameterized SQL.

This package keeps the historical ``from assess.commands import dispatch`` +
``dispatch.<symbol>`` seam intact. ``agent.py`` (the operator-facing ``vigil
assess agent`` command) and ``work_buffer.py`` reach into this module by
attribute, so the public names they use are re-exported here from the owning
submodules:

- ``_shared``           — CLI arg / time / JSON helpers
- ``work_items``        — backend work-buffer verbs (stats/peek/fetch/defer/...)
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
    _fetch_by_unit,
    _defer_cluster,
    _defer_items,
    _set_rationale,
    _mark_manual,
    _done,
    _error,
    _reset_stale,
    _retry_errors,
    _requeue,
    _reclassify,
    _link_surface,
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
    "_reclassify",
    "_link_surface",
    "_record_handoff",
    "_render_handoff",
    "_record_decision",
    "_list_dispatches",
    "_get_dispatch",
    "_abort_duplicate_dispatch",
    "_update_dispatch_status",
    "_register_dispatch",
    "_client_for",
    "_build_register_payload",
    "_warn_on_overlapping_dispatch",
    "AssessmentClient",
    "AssessError",
    "load_config",
]


def run(args) -> None:
    """Route ``vigil assess work-buffer <action>`` to the backend work buffer.

    The work buffer lives in the orchestrator ledger (ADR 0013); every verb is
    an ``AssessmentClient`` call. The engagement is resolved from the standard
    binding (explicit ``--engagement-dir`` or matching cwd/launcher session)
    via ``load_config`` — there is no cases.db path to pass.
    """
    action = args.action
    extra = args.extra or []

    if not action:
        print(
            "Usage: vigil assess work-buffer <action> [args...]\n"
            "       vigil assess agent <backend-action> [args...]",
            file=sys.stderr,
        )
        sys.exit(1)

    cfg = load_config(getattr(args, "engagement_dir", None))
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if action == "stats":
            by = getattr(args, "by", "status") or "status"
            _stats(
                client,
                by=by,
                status=getattr(args, "cluster_status", "") or "",
            )
        elif action == "peek":
            if len(extra) < 1:
                print("Usage: work-buffer peek <type> [limit]", file=sys.stderr)
                sys.exit(1)
            peek_type = extra[0]
            peek_limit = _safe_int_arg(extra[1], "limit") if len(extra) > 1 else 10
            _peek(client, peek_type, peek_limit)
        elif action == "fetch":
            if len(extra) < 3:
                print("Usage: work-buffer fetch <type> <limit> <agent>", file=sys.stderr)
                sys.exit(1)
            _fetch(client, extra[0], _safe_int_arg(extra[1], "limit"), extra[2])
        elif action == "fetch-by-priority":
            if len(extra) < 1:
                print(
                    "Usage: work-buffer fetch-by-priority <limit> [auto|agent]",
                    file=sys.stderr,
                )
                sys.exit(1)
            _fetch_by_priority(
                client,
                _safe_int_arg(extra[0], "limit"),
                extra[1] if len(extra) > 1 else "auto",
            )
        elif action == "fetch-by-unit":
            if extra:
                print(
                    "Usage: work-buffer fetch-by-unit [--unit-id ID] [--path PREFIX] "
                    "[--class TYPE] [--limit N] [--agent auto|NAME]",
                    file=sys.stderr,
                )
                sys.exit(1)
            _fetch_by_unit(
                client,
                unit_id=getattr(args, "unit_id", None),
                path=getattr(args, "path", "") or "",
                work_class=getattr(args, "work_class", "") or "",
                limit=getattr(args, "unit_limit", None),
                agent=getattr(args, "unit_agent", "auto") or "auto",
            )
        elif action == "defer-cluster":
            if not extra:
                print(
                    "Usage: work-buffer defer-cluster <cluster_key> --reason TEXT",
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
            _defer_cluster(
                client,
                extra[0],
                stored,
                dry_run=bool(getattr(args, "dry_run", False)),
            )
        elif action == "defer-items":
            if not extra:
                print(
                    "Usage: work-buffer defer-items <id> [<id> ...] --reason TEXT\n"
                    "       work-buffer defer-items <id1,id2,...> --reason TEXT",
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
            _defer_items(
                client,
                extra,
                stored,
                dry_run=bool(getattr(args, "dry_run", False)),
            )
        elif action == "set-rationale":
            if not extra:
                print(
                    "Usage: work-buffer set-rationale <id> [<id> ...] "
                    "--rationale TEXT",
                    file=sys.stderr,
                )
                sys.exit(1)
            rationale = (
                getattr(args, "triage_rationale", "") or ""
            ).strip()
            if not rationale:
                print("set-rationale: --rationale is required", file=sys.stderr)
                sys.exit(1)
            _set_rationale(client, extra, rationale)
        elif action == "mark-manual":
            if not extra:
                print(
                    "Usage: work-buffer mark-manual <id> [<id> ...]\n"
                    "       work-buffer mark-manual <id1,id2,...>\n"
                    "  Stamps classifier_version='manual' so --reclassify-stale skips these rows.",
                    file=sys.stderr,
                )
                sys.exit(1)
            _mark_manual(client, extra)
        elif action == "done":
            if not extra:
                print("Usage: work-buffer done <id> [<id> ...]", file=sys.stderr)
                sys.exit(1)
            _done(client, extra)
        elif action == "error":
            if not extra:
                print("Usage: work-buffer error <id> [<id> ...]", file=sys.stderr)
                sys.exit(1)
            _error(client, extra)
        elif action == "reset-stale":
            if not extra:
                print("Usage: work-buffer reset-stale <minutes>", file=sys.stderr)
                sys.exit(1)
            _reset_stale(client, _safe_int_arg(extra[0], "minutes"))
        elif action == "retry-errors":
            max_retries = _safe_int_arg(extra[0], "max_retries") if extra else 2
            _retry_errors(client, max_retries)
        elif action == "requeue":
            _requeue(client)
        elif action == "reclassify":
            _reclassify(client, args)
        elif action == "link-surface":
            _link_surface(client, args)
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            print(f"Work-buffer actions: {', '.join(_DB_ACTIONS)}", file=sys.stderr)
            sys.exit(1)
