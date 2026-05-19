"""aith assess agent — backend agent lifecycle, handoff, and decision rows."""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
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
            "close",
            "reconcile-stale",
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
    p.add_argument("--handoff-status", dest="hf_handoff_status", default=None, choices=("checkpointed", "ready", "blocked", "superseded"))
    p.add_argument("--closed-dispatch-status", dest="hf_closed_dispatch_status", default=None, choices=("completed", "blocked", "failed", "aborted"))
    p.add_argument("--extras-json", dest="hf_extras_json", default=None)
    p.add_argument("--reason", default="", help="Reason for abort-duplicate / decision shorthand.")
    p.add_argument("--dry-run", dest="dry_run", action="store_true", help="(reconcile-stale) Print candidates without closing dispatches.")
    p.add_argument(
        "--max-age-hours",
        dest="max_age_hours",
        type=float,
        default=None,
        help=(
            "(reconcile-stale) Override the per-role age threshold for in-progress dispatches. "
            "Defaults: 24h for most roles, 48h for exploit-developer / report-writer / code-* "
            "(except 72h for code-fuzz-engineer). Matches `resume-brief --max-age-hours` semantics."
        ),
    )
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
    elif action == "close":
        _close(args)
    elif action == "reconcile-stale":
        _reconcile_stale(args)
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
    _warn_if_handoff_is_closable(args)
    dispatch._update_dispatch_status(args, [])  # noqa: SLF001


def _warn_if_handoff_is_closable(args) -> None:
    """Stderr-warn when `agent done` is used on a dispatch with a closable handoff.

    `agent close` consumes a ready/blocked handoff and writes an audit decision
    row; `agent done` is a raw status PATCH. Both work, but operators usually
    want `close` once the specialist has produced a ready handoff so the
    closure is traceable in the decision ledger. Warn but do not block.
    """
    try:
        client, _ = dispatch._client_for(args)  # noqa: SLF001
    except Exception:  # noqa: BLE001 - non-fatal precheck
        return
    try:
        handoff = client.get_handoff(args.agent_id)
    except Exception:  # noqa: BLE001 - non-fatal precheck
        return
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
    if not handoff:
        return
    status_value = str(handoff.get("handoff_status") or "")
    if status_value in {"ready", "blocked"}:
        print(
            f"WARN agent done: handoff for {args.agent_id} is handoff_status={status_value!r}; "
            f"`aith assess agent close {args.agent_id}` would write a dispatch_closed_from_handoff "
            "decision row for the audit ledger. Proceeding with raw done — pass --status explicitly "
            "and ignore this warning if that is intended.",
            file=sys.stderr,
        )


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _close(args) -> None:
    agent_id = getattr(args, "agent_id", None) or (args.extra[0] if args.extra else "")
    if not agent_id:
        print("agent close: agent id required as positional arg or --agent-id", file=sys.stderr)
        sys.exit(1)
    client, _ = dispatch._client_for(args)  # noqa: SLF001
    try:
        handoff = client.get_handoff(agent_id)
        if not handoff:
            print(f"agent close: no handoff found for agent_id={agent_id}", file=sys.stderr)
            sys.exit(2)
        dispatch_row = client.get_dispatch(agent_id)
        if not dispatch_row:
            print(f"agent close: no dispatch found for agent_id={agent_id}", file=sys.stderr)
            sys.exit(2)
        handoff_status = str(handoff.get("handoff_status") or "checkpointed")
        if handoff_status == "ready":
            target_status = str(handoff.get("closed_dispatch_status") or "completed")
        elif handoff_status == "blocked":
            target_status = str(handoff.get("closed_dispatch_status") or "blocked")
        else:
            print(
                f"agent close: handoff_status={handoff_status!r} is not closable. Options:\n"
                f"  1. Re-dispatch the specialist to write a final handoff with "
                f"--handoff-status ready (or blocked) — preferred.\n"
                f"  2. Force-complete without an audit row: "
                f"`aith assess agent done {agent_id} --status completed` "
                f"(or --status failed / blocked / aborted).\n"
                f"  3. Operator override: write the closing handoff manually with "
                f"`aith assess agent handoff --agent-id {agent_id} --role <role> "
                f"--summary \"...\" --handoff-status blocked` then re-run "
                f"`agent close`.",
                file=sys.stderr,
            )
            sys.exit(2)
        if target_status not in {"completed", "blocked", "failed", "aborted"}:
            print(f"agent close: closed status {target_status!r} is not valid", file=sys.stderr)
            sys.exit(2)
        patch = {
            "status": target_status,
            "completed_at": getattr(args, "completed_at", None) or _utcnow_iso(),
        }
        if handoff.get("finding_slugs"):
            patch["finding_slugs"] = handoff.get("finding_slugs")
        updated = client.update_dispatch(agent_id, patch)
        decision = client.record_decision(
            {
                "kind": "dispatch_closed_from_handoff",
                "payload": {
                    "agent_id": agent_id,
                    "handoff_status": handoff_status,
                    "closed_dispatch_status": target_status,
                    "handoff_version": handoff.get("handoff_version"),
                    "reason": getattr(args, "reason", "") or "agent close",
                },
                "surfaced_to_user": False,
            }
        )
    finally:
        client.close()
    print(json.dumps({"dispatch": updated, "decision": decision}, ensure_ascii=False))


def _parse_iso(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


# Mirrors orchestrator/backend/app/services/assessment_memory.py
# `_STALE_THRESHOLD_BY_ROLE` so `reconcile-stale` and `resume-brief` agree on
# which dispatches are stale. A drift between the two would surface stale
# candidates that `resume-brief` never flagged, confusing the operator.
_STALE_THRESHOLD_BY_ROLE: dict[str, float] = {
    "exploit-developer": 48.0,
    "report-writer": 48.0,
    "code-architect": 48.0,
    "code-vuln-hunter": 48.0,
    "code-variant-hunter": 48.0,
    "code-vuln-verifier": 48.0,
    "code-fuzz-engineer": 72.0,
}
_DEFAULT_STALE_THRESHOLD_HOURS = 24.0


def _stale_threshold_for(role: str | None, *, override: float | None) -> float:
    if override is not None:
        return float(override)
    return _STALE_THRESHOLD_BY_ROLE.get(str(role or ""), _DEFAULT_STALE_THRESHOLD_HOURS)


def _reconcile_stale(args) -> None:
    override = getattr(args, "max_age_hours", None)
    cutoff_override: float | None = float(override) if override is not None else None
    dry_run = bool(getattr(args, "dry_run", False))
    now = datetime.now(timezone.utc)
    client, _ = dispatch._client_for(args)  # noqa: SLF001
    rows_out: list[dict] = []
    try:
        dispatches = client.list_dispatches(status="in-progress", limit=1000)
        handoffs = {row.get("agent_id"): row for row in client.list_handoffs(limit=1000)}
        for row in dispatches:
            agent_role = row.get("agent_role")
            cutoff_hours = _stale_threshold_for(agent_role, override=cutoff_override)
            started = _parse_iso(str(row.get("dispatched_at") or ""))
            age_hours = ((now - started).total_seconds() / 3600.0) if started else None
            if age_hours is not None and age_hours < cutoff_hours:
                continue
            handoff = handoffs.get(row.get("agent_id"))
            handoff_status = str((handoff or {}).get("handoff_status") or "none")
            category = "no_handoff"
            if handoff_status == "ready":
                category = "ready_handoff"
            elif handoff_status == "blocked":
                category = "blocked_handoff"
            elif handoff:
                category = "checkpointed_handoff"
            item: dict = {
                "agent_id": row.get("agent_id"),
                "agent_role": agent_role,
                "age_hours": round(age_hours, 2) if age_hours is not None else None,
                "threshold_hours": cutoff_hours,
                "category": category,
                "handoff_status": handoff_status,
                "closed": False,
                "closed_status": None,
                "skip_reason": None,
            }
            if dry_run:
                item["skip_reason"] = "dry-run"
            elif category in {"ready_handoff", "blocked_handoff"}:
                try:
                    closed = _close_via_client(client, str(row.get("agent_id") or ""), reason="reconcile-stale")
                    item["closed"] = True
                    item["closed_status"] = closed["dispatch"].get("status")
                except _ReconcileSkipped as exc:
                    item["skip_reason"] = str(exc)
            else:
                item["skip_reason"] = (
                    "no handoff to close" if category == "no_handoff"
                    else "handoff is checkpointed; specialist must mark ready|blocked before close"
                )
            rows_out.append(item)
    finally:
        client.close()
    print(json.dumps(rows_out, indent=2, ensure_ascii=False))


class _ReconcileSkipped(Exception):
    """Raised when a reconcile candidate cannot be closed cleanly."""


def _close_via_client(client, agent_id: str, *, reason: str) -> dict:
    """Close one dispatch using an already-open client. Returns {'dispatch', 'decision'}."""
    if not agent_id:
        raise _ReconcileSkipped("missing agent_id")
    handoff = client.get_handoff(agent_id)
    if not handoff:
        raise _ReconcileSkipped("no handoff for agent_id")
    dispatch_row = client.get_dispatch(agent_id)
    if not dispatch_row:
        raise _ReconcileSkipped("no dispatch for agent_id")
    handoff_status = str(handoff.get("handoff_status") or "checkpointed")
    if handoff_status == "ready":
        target_status = str(handoff.get("closed_dispatch_status") or "completed")
    elif handoff_status == "blocked":
        target_status = str(handoff.get("closed_dispatch_status") or "blocked")
    else:
        raise _ReconcileSkipped(f"handoff_status={handoff_status} is not closable")
    if target_status not in {"completed", "blocked", "failed", "aborted"}:
        raise _ReconcileSkipped(f"invalid closed status {target_status}")
    patch: dict = {"status": target_status, "completed_at": _utcnow_iso()}
    if handoff.get("finding_slugs"):
        patch["finding_slugs"] = handoff.get("finding_slugs")
    updated = client.update_dispatch(agent_id, patch)
    decision = client.record_decision(
        {
            "kind": "dispatch_closed_from_handoff",
            "payload": {
                "agent_id": agent_id,
                "handoff_status": handoff_status,
                "closed_dispatch_status": target_status,
                "handoff_version": handoff.get("handoff_version"),
                "reason": reason,
            },
            "surfaced_to_user": False,
        }
    )
    return {"dispatch": updated, "decision": decision}


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
