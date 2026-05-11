"""aith assess agent — backend agent lifecycle, handoff, and decision rows."""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

from assess.commands import dispatch


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "agent",
        help="Record and inspect backend agent lifecycle rows and handoffs.",
    )
    p.add_argument(
        "action",
        choices=("start", "done", "list", "get", "handoff", "render-handoff", "decision", "abort-duplicate"),
    )
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument("--agent-id", dest="agent_id", default=None)
    p.add_argument("--role", dest="agent_role", default=None, help="Agent role for start/handoff.")
    p.add_argument("--agent-role", dest="agent_role_alias", default=None, help="Alias for --role.")
    p.add_argument("--task", dest="task", default=None)
    p.add_argument("--scope-host", dest="scope_host", default=None)
    p.add_argument("--model", dest="dispatch_model", default=None)
    p.add_argument("--reasoning", dest="reasoning", default=None, choices=("low", "medium", "high"))
    p.add_argument(
        "--dispatch-mode",
        dest="dispatch_mode_arg",
        default=None,
        choices=("hypothesis-driven", "item-iterating", "deep-manual", "variant-rotation"),
    )
    p.add_argument("--skills", dest="skills", default=None)
    p.add_argument("--from-json", dest="from_json", default=None)
    p.add_argument("--allow-duplicate", dest="allow_duplicate", action="store_true")
    p.add_argument("--status", dest="dispatch_status", default=None, choices=("in-progress", "completed", "failed", "aborted", "blocked"))
    p.add_argument("--completed-at", dest="completed_at", default=None)
    p.add_argument("--finding-slugs", dest="finding_slugs", default=None)
    p.add_argument("--replacement-agent-id", dest="replacement_agent_id", default=None)
    p.add_argument("--filter-role", dest="filter_role", default=None)
    p.add_argument("--since", dest="filter_since", default=None)
    p.add_argument("--task-q", dest="task_q", default=None)
    p.add_argument("--limit", dest="dispatch_limit", default=None, type=int)
    p.add_argument("--max-lines", type=int, default=40)
    p.add_argument("--include-evidence", action="store_true")
    p.add_argument("--kind", dest="decision_kind", default=None)
    p.add_argument("--payload-json", dest="payload_json", default=None)
    p.add_argument("--surfaced-to-user", dest="surfaced_to_user", action="store_true")
    p.add_argument("--host", dest="decision_host", default=None)
    p.add_argument("--vendor", dest="decision_vendor", default=None)
    p.add_argument("--choice", dest="decision_choice", default=None)
    p.add_argument("--note", dest="decision_note", default=None)
    p.add_argument("--phase", dest="decision_phase", default=None)
    p.add_argument("--summary", dest="hf_summary", default=None)
    p.add_argument("--confidence", dest="hf_confidence", default=None, choices=("low", "medium", "high"))
    p.add_argument("--next-step", dest="hf_next_steps", action="append", default=None)
    p.add_argument("--coverage-gap", dest="hf_coverage_gaps", action="append", default=None)
    p.add_argument("--runtime-issue", dest="hf_runtime_issues", action="append", default=None)
    p.add_argument("--working-artifact", dest="hf_working_artifacts", action="append", default=None)
    p.add_argument("--open-question", dest="hf_open_questions", action="append", default=None)
    p.add_argument("--recommended-next-agent", dest="hf_recommended_next_agent", default=None)
    p.add_argument("--extras-json", dest="hf_extras_json", default=None)
    p.add_argument("--reason", default="", help="Reason for abort-duplicate / decision shorthand.")
    p.set_defaults(func=run)


def run(args) -> None:
    if getattr(args, "agent_role_alias", None) and not getattr(args, "agent_role", None):
        args.agent_role = args.agent_role_alias
    action = args.action
    if action == "start":
        _start(args)
    elif action == "done":
        _done(args)
    elif action == "handoff":
        dispatch._record_handoff(args)  # noqa: SLF001 - new command surface over existing backend helper.
    elif action == "render-handoff":
        dispatch._render_handoff(args, _agent_id_extra(args))  # noqa: SLF001
    elif action == "decision":
        dispatch._record_decision(args)  # noqa: SLF001
    elif action == "list":
        dispatch._list_dispatches(args)  # noqa: SLF001
    elif action == "get":
        dispatch._get_dispatch(args, _agent_id_extra(args))  # noqa: SLF001
    elif action == "abort-duplicate":
        dispatch._abort_duplicate_dispatch(args, _agent_id_extra(args))  # noqa: SLF001
    else:
        raise SystemExit(f"unknown agent action: {action}")


def _agent_id_extra(args) -> list[str]:
    if getattr(args, "extra", None):
        return list(args.extra)
    if getattr(args, "agent_id", None):
        return [args.agent_id]
    return []


def _done(args) -> None:
    if not getattr(args, "agent_id", None):
        if args.extra:
            args.agent_id = args.extra[0]
        else:
            print("agent done: agent id required as positional arg or --agent-id", file=sys.stderr)
            sys.exit(1)
    if not getattr(args, "dispatch_status", None):
        args.dispatch_status = "completed"
    dispatch._update_dispatch_status(args, [])  # noqa: SLF001


def _start(args) -> None:
    if not getattr(args, "agent_id", None):
        role = getattr(args, "agent_role", None) or "agent"
        args.agent_id = f"{role.replace('_', '-').replace(' ', '-')}-{uuid.uuid4().hex[:8]}"
    payload = dispatch._build_register_payload(args)  # noqa: SLF001
    client, cfg = dispatch._client_for(args)  # noqa: SLF001
    try:
        if not getattr(args, "allow_duplicate", False):
            dispatch._warn_on_overlapping_dispatch(client, payload)  # noqa: SLF001
        row = client.record_dispatch(payload)
    finally:
        client.close()
    _warn_missing_native_wrapper(Path(cfg.engagement_dir), str(row.get("agent_role") or ""))
    print(json.dumps({
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "status": row.get("status"),
    }, ensure_ascii=False))
    print(
        "\n".join(
            [
                "## Runtime Identity",
                f"agent_id: {row.get('agent_id')}",
                f"agent_role: {row.get('agent_role')}",
                "authorized_phase: <set-by-operator>",
            ]
        )
    )


def _warn_missing_native_wrapper(engagement_dir: Path, role: str) -> None:
    if not role:
        return
    claude = engagement_dir / ".claude" / "agents" / f"{role}.md"
    codex = engagement_dir / ".codex" / "agents" / f"{role}.toml"
    if not claude.exists() and not codex.exists():
        print(
            f"WARN agent start: no native wrapper found for role {role!r} under .claude/agents or .codex/agents",
            file=sys.stderr,
        )
