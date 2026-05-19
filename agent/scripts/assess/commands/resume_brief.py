"""aith assess resume-brief — compact backend operating picture."""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "resume-brief",
        help="Render a bounded resume brief from backend state, command history, handoffs, and indexed artifacts.",
    )
    p.add_argument("--q", default="", help="Optional topic/query for command and artifact context.")
    p.add_argument("--finding", default="", help="Optional finding slug or alias, e.g. VA-047 or VA047.")
    p.add_argument("--agent-id", default="", help="Optional dispatch agent_id to include handoff/dispatch details.")
    p.add_argument(
        "--max-age-hours",
        dest="max_age_hours",
        type=float,
        default=24.0,
        help="Age threshold for in-progress dispatches flagged stale. Defaults to 24h (matches `agent reconcile-stale`).",
    )
    p.add_argument("--json", dest="as_json", action="store_true")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    params = []
    if args.q:
        params.append(("q", args.q))
    if args.finding:
        params.append(("finding", args.finding))
    if args.agent_id:
        params.append(("agent_id", args.agent_id))
    if getattr(args, "max_age_hours", None) and float(args.max_age_hours) != 24.0:
        params.append(("max_age_hours", str(float(args.max_age_hours))))
    endpoint = "resume-brief"
    if params:
        endpoint += "?" + urlencode(params, quote_via=quote)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        brief = client.get(endpoint)
    finally:
        client.close()
    if args.as_json:
        print(json.dumps(brief, indent=2, ensure_ascii=False))
        return
    print(_render_markdown(brief))


def _render_markdown(brief: dict) -> str:
    engagement = brief.get("engagement") or {}
    query = brief.get("query") or {}
    lines = [
        f"# Resume Brief: {engagement.get('key', '')}",
        "",
        f"- phase: {engagement.get('current_phase', 'unknown')}",
        f"- scope_status: {engagement.get('scope_status', 'unknown')}",
        f"- hosts: {engagement.get('host_count', 0)}",
    ]
    if query.get("q") or query.get("finding") or query.get("agent_id"):
        lines.append(f"- query: q={query.get('q') or '-'} finding={query.get('finding') or '-'} agent_id={query.get('agent_id') or '-'}")
    lines.extend(["", "## Finding Counts"])
    counts = brief.get("finding_counts") or {}
    for key in ("workflow", "verification_state", "verification_disposition", "severity", "source"):
        values = counts.get(key) or {}
        compact = ", ".join(f"{name}={count}" for name, count in sorted(values.items())) or "-"
        lines.append(f"- {key}: {compact}")
    target = brief.get("target_finding")
    if target:
        lines.extend(["", "## Target Finding", _finding_line(target)])
    lines.extend(["", "## Findings"])
    findings = brief.get("findings") or {}
    for bucket in ("active", "unreviewed", "verified", "killed", "merged", "chain_required"):
        rows = findings.get(bucket) or []
        lines.append(f"- {bucket}:")
        if not rows:
            lines.append("  - none")
        for row in rows[:6]:
            lines.append("  - " + _finding_line(row))
    lines.extend(["", "## Dispatches"])
    dispatches = brief.get("dispatches") or {}
    for row in dispatches.get("stale_in_progress_dispatches") or []:
        lines.append(f"- stale: {row.get('agent_id')} role={row.get('agent_role')} age_h={row.get('age_hours')} handoff={row.get('handoff_status')}")
    for row in dispatches.get("handoff_gaps") or []:
        lines.append(f"- gap: {row.get('agent_id')} role={row.get('agent_role')} reason={row.get('reason')}")
    if not (dispatches.get("stale_in_progress_dispatches") or dispatches.get("handoff_gaps")):
        lines.append("- no stale in-progress dispatches or handoff gaps in the brief window")
    selected = dispatches.get("selected_dispatch")
    if selected:
        lines.extend(["", "## Selected Dispatch"])
        lines.append(
            f"- agent_id: {selected.get('agent_id')} role={selected.get('agent_role')} "
            f"status={selected.get('status')} dispatched_at={selected.get('dispatched_at')}"
        )
        if selected.get("task"):
            lines.append(f"- task: {_trim(str(selected.get('task') or ''), 200)}")
        if selected.get("finding_slugs"):
            lines.append(f"- finding_slugs: {', '.join(selected.get('finding_slugs') or [])}")
    selected_handoff = dispatches.get("selected_handoff")
    if selected_handoff:
        lines.extend(["", "## Selected Handoff"])
        lines.append(
            f"- agent_id: {selected_handoff.get('agent_id')} "
            f"status={selected_handoff.get('handoff_status')} "
            f"version={selected_handoff.get('handoff_version')} "
            f"last_checkpoint_at={selected_handoff.get('last_checkpoint_at')}"
        )
        if selected_handoff.get("summary"):
            lines.append(f"- summary: {_trim(str(selected_handoff.get('summary') or ''), 400)}")
        if selected_handoff.get("finding_slugs"):
            lines.append(f"- finding_slugs: {', '.join(selected_handoff.get('finding_slugs') or [])}")
        for step in (selected_handoff.get("next_steps") or [])[:3]:
            if isinstance(step, dict):
                lines.append(
                    f"- next: {step.get('action') or '-'} → {step.get('target') or '-'} "
                    f"({step.get('recommended_agent') or '-'})"
                )
    lines.extend(["", "## Command Runs"])
    for row in brief.get("command_runs") or []:
        lines.append(f"- #{row.get('id')} {row.get('created_at')} {row.get('tool_bin') or row.get('tool_name')} {row.get('agent_name')} :: {_trim(row.get('intent') or row.get('command') or '', 120)}")
    if not brief.get("command_runs"):
        lines.append("- none")
    lines.extend(["", "## Artifacts"])
    for row in brief.get("artifacts") or []:
        lines.append(f"- #{row.get('id')} {row.get('kind')} present={row.get('present')} {row.get('relative_path')}")
    if not brief.get("artifacts"):
        lines.append("- none")
    lines.extend(["", "## Next Actions"])
    for row in brief.get("recommended_next_actions") or []:
        entity = ""
        if row.get("entity_kind") and row.get("entity_id") is not None:
            entity = f" [{row.get('entity_kind')} {row.get('entity_id')}]"
        lines.append(f"- {row.get('reason')}{entity}: `{row.get('command')}`")
    return "\n".join(lines)


def _finding_line(row: dict) -> str:
    return (
        f"{row.get('slug')} {row.get('severity')} "
        f"{row.get('workflow_status')}/{row.get('verification_state')} "
        f"{_trim(row.get('title') or '', 100)}"
    )


def _trim(value: str, limit: int) -> str:
    text = str(value).replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
