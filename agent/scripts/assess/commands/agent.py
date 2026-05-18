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
        choices=(
            "start",
            "start-swarm",
            "done",
            "list",
            "get",
            "handoff",
            "render-handoff",
            "decision",
            "abort-duplicate",
        ),
    )
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument("--agent-id", dest="agent_id", default=None)
    p.add_argument("--role", dest="agent_role", default=None, help="Agent role for start/handoff.")
    p.add_argument("--agent-role", dest="agent_role_alias", default=None, help="Alias for --role.")
    p.add_argument("--task", dest="task", default=None)
    p.add_argument("--scope-host", dest="scope_host", default=None)
    p.add_argument("--model", dest="dispatch_model", default=None)
    p.add_argument("--reasoning", dest="reasoning", default=None,
                   choices=("low", "medium", "high", "xhigh", "max"))
    p.add_argument(
        "--dispatch-mode",
        dest="dispatch_mode_arg",
        default=None,
        choices=("hypothesis-driven", "item-iterating", "deep-manual", "variant-rotation", "swarm"),
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
    # start-swarm flags. Reuse --role / --task / --skills / --model / --reasoning
    # from the existing start flag set; add three new flags below.
    p.add_argument(
        "--workers",
        dest="swarm_workers",
        type=int,
        default=None,
        help="(start-swarm) Number of parallel workers to record. Each worker gets its own dispatch row and agent_id.",
    )
    p.add_argument(
        "--batch-size",
        dest="swarm_batch_size",
        type=int,
        default=None,
        help="(start-swarm) Items per worker. Total items consumed = workers * batch-size unless --items-file is shorter.",
    )
    p.add_argument(
        "--items-file",
        dest="swarm_items_file",
        default=None,
        help="(start-swarm) Path to a file with one item per line (URL, file path, etc.). Lines are split into --batch-size chunks across --workers workers; per-worker batch ranges are encoded in each dispatch row's task.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    if getattr(args, "agent_role_alias", None) and not getattr(args, "agent_role", None):
        args.agent_role = args.agent_role_alias
    action = args.action
    if action == "start":
        _start(args)
    elif action == "start-swarm":
        _start_swarm(args)
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


def _start_swarm(args) -> None:
    """Record N parallel dispatch rows for a swarm-mode workload.

    This does NOT spawn specialist agents. It writes N backend rows (one per
    worker), encodes each worker's batch range in its ``task`` field, and
    prints the agent_id table so the operator can manually fire the N
    specialists via @agent-name (Claude Code) or spawn_agent (Codex).

    Rationale: swarm dispatch is intentionally low-reasoning fan-out for
    corpus-scale work (exposed-bucket secret scanning, large URL coverage
    sweeps, file-classification at scale). Doing it inside one
    ``item-iterating`` agent runs out of context at 30-100 items; doing it
    with one ``hypothesis-driven`` agent picks the wrong shape (there is no
    hypothesis, there is a corpus). The helper writes the audit trail up
    front so list-command-runs / dispatch list show the full swarm
    immediately, even if the operator dispatches the workers staggered.
    """
    role = getattr(args, "agent_role", None)
    if not role:
        print("agent start-swarm: --role is required", file=sys.stderr)
        sys.exit(1)
    workers = getattr(args, "swarm_workers", None)
    batch_size = getattr(args, "swarm_batch_size", None)
    items_file = getattr(args, "swarm_items_file", None)
    if not workers or workers < 1:
        print("agent start-swarm: --workers must be >= 1", file=sys.stderr)
        sys.exit(1)
    if not batch_size or batch_size < 1:
        print("agent start-swarm: --batch-size must be >= 1", file=sys.stderr)
        sys.exit(1)
    if not items_file:
        print("agent start-swarm: --items-file is required", file=sys.stderr)
        sys.exit(1)

    items_path = Path(items_file)
    if not items_path.is_file():
        print(f"agent start-swarm: items file not found: {items_file}", file=sys.stderr)
        sys.exit(1)
    items = [line.strip() for line in items_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not items:
        print(f"agent start-swarm: items file is empty: {items_file}", file=sys.stderr)
        sys.exit(1)

    # Split items into worker batches. Workers receive contiguous ranges so
    # operators can correlate batch_i with items[i*batch_size : (i+1)*batch_size]
    # without re-reading the splitter logic.
    batches: list[list[str]] = []
    cursor = 0
    for _ in range(workers):
        chunk = items[cursor : cursor + batch_size]
        if not chunk:
            break
        batches.append(chunk)
        cursor += batch_size
    if not batches:
        print(
            "agent start-swarm: nothing to dispatch; items file shorter than --batch-size",
            file=sys.stderr,
        )
        sys.exit(1)
    if cursor < len(items):
        leftover = len(items) - cursor
        print(
            f"WARN agent start-swarm: {leftover} item(s) past worker {len(batches)} are NOT covered "
            f"by this swarm. Increase --workers or --batch-size, or re-run start-swarm against the tail.",
            file=sys.stderr,
        )

    user_task = (getattr(args, "task", None) or "").strip()
    if not user_task:
        print("agent start-swarm: --task is required", file=sys.stderr)
        sys.exit(1)

    client, cfg = dispatch._client_for(args)  # noqa: SLF001
    rows_emitted: list[dict[str, str | int | None]] = []
    try:
        base_uuid_short = uuid.uuid4().hex[:6]
        role_slug = role.replace("_", "-").replace(" ", "-")
        for worker_idx, batch in enumerate(batches, start=1):
            args.agent_id = f"{role_slug}-swarm-{base_uuid_short}-{worker_idx:02d}"
            start_offset = (worker_idx - 1) * batch_size + 1
            end_offset = start_offset + len(batch) - 1
            # Encode the worker's batch range and the user's task so the
            # specialist sees its own slice when fetching its dispatch row.
            args.task = (
                f"[swarm {worker_idx}/{len(batches)} items {start_offset}-{end_offset} "
                f"from {items_path.name}] {user_task}"
            )
            args.dispatch_mode_arg = "swarm"
            payload = dispatch._build_register_payload(args)  # noqa: SLF001
            try:
                row = client.record_dispatch(payload)
            except Exception as exc:  # noqa: BLE001 - surface and continue
                print(
                    f"WARN agent start-swarm: worker {worker_idx} failed to record: {exc}",
                    file=sys.stderr,
                )
                rows_emitted.append({
                    "worker": worker_idx,
                    "agent_id": args.agent_id,
                    "status": "failed_to_record",
                    "items": f"{start_offset}-{end_offset}",
                })
                continue
            rows_emitted.append({
                "worker": worker_idx,
                "agent_id": row.get("agent_id"),
                "status": row.get("status"),
                "items": f"{start_offset}-{end_offset}",
            })
    finally:
        client.close()

    # Print summary table the operator pastes into the N spawn commands.
    print(json.dumps({"swarm": rows_emitted}, ensure_ascii=False))
    print("\n## Swarm Dispatch Table")
    print(f"items_file: {items_file} ({len(items)} items)")
    print(f"workers: {len(rows_emitted)} | batch_size: {batch_size} | mode: swarm | role: {role}")
    print("")
    print("| worker | agent_id | items | status |")
    print("|---|---|---|---|")
    for r in rows_emitted:
        print(f"| {r['worker']} | {r['agent_id']} | {r['items']} | {r['status']} |")
    print("")
    print(
        "Next: fire one specialist per row using your runtime's wrapper "
        "(@<role> in Claude Code, or spawn_agent in Codex), passing the row's "
        "agent_id in the Runtime Identity block. The specialist reads its "
        "batch range from its own dispatch row via `aith assess agent get <agent_id>`."
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
