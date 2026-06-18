"""vigil assess resume-brief — compact backend operating picture."""
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
        "--since",
        default="",
        help=(
            "ISO datetime cutoff. When set, findings / decisions / command runs / artifacts "
            "are filtered to entries updated at or after this point — useful for 'what's new "
            "since I last looked' between sessions."
        ),
    )
    p.add_argument(
        "--max-age-hours",
        dest="max_age_hours",
        type=float,
        default=None,
        help=(
            "Override the per-role stale threshold for in-progress dispatches. "
            "Default: 24h for most roles, 48h for exploit-developer / report-writer / code-*, "
            "72h for code-fuzz-engineer."
        ),
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
    max_age = getattr(args, "max_age_hours", None)
    if max_age is not None:
        params.append(("max_age_hours", str(float(max_age))))
    since = getattr(args, "since", "")
    if since:
        params.append(("since", since))
    endpoint = "resume-brief"
    if params:
        endpoint += "?" + urlencode(params, quote_via=quote)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        brief = client.get(endpoint)
    # A fresh/empty engagement (or a backend that served the SPA index.html for an
    # unknown route) makes client.get return a raw string instead of a dict. Render
    # a clean "no prior state" notice rather than crashing on brief.get(...).
    if not isinstance(brief, dict):
        note = "No prior state for this engagement (backend returned no resume brief)."
        if args.as_json:
            print(json.dumps({"engagement": {}, "note": note}, indent=2, ensure_ascii=False))
        else:
            print(f"# Resume Brief\n\n- {note}")
        return
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
    if query.get("q") or query.get("finding") or query.get("agent_id") or query.get("since"):
        lines.append(
            f"- query: q={query.get('q') or '-'} finding={query.get('finding') or '-'} "
            f"agent_id={query.get('agent_id') or '-'} since={query.get('since') or '-'}"
        )
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
            continue
        shown = _select_findings(rows)
        for row in shown:
            lines.append("  - " + _finding_line(row))
        if len(shown) < len(rows):
            lines.append(f"  - … showing {len(shown)} of {len(rows)} (medium+ always shown)")
    _render_surfaces(lines, brief.get("surfaces") or {})
    _render_work_buffer(lines, brief.get("work_buffer") or {})
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
    intel = brief.get("intel") or {}
    if intel:
        lines.extend(["", "## Intel"])
        summary = intel.get("summary") or {}
        compact = ", ".join(f"{name}={count}" for name, count in sorted(summary.items()) if count) or "-"
        lines.append(f"- counts: {compact}")
        open_cves = intel.get("open_high_cves") or []
        lines.append(f"- open high CVEs ({len(open_cves)}):")
        if not open_cves:
            lines.append("  - none")
        for row in open_cves:
            link = row.get("linked_finding_slug") or "UNLINKED"
            lines.append(
                f"  - id={row.get('id')} {row.get('cve_id')} cvss {row.get('cvss_score')} "
                f"[{row.get('validation_status')}] → {link}"
                + (f" ({_trim(row.get('affected_component') or '', 60)})" if row.get("affected_component") else "")
            )
        open_leads = intel.get("open_leads") or []
        lines.append(f"- open leads ({len(open_leads)}):")
        if not open_leads:
            lines.append("  - none")
        for row in open_leads:
            lines.append(f"  - id={row.get('id')} [{row.get('lead_status')}] {_trim(row.get('title') or '', 100)}")
        read_first = intel.get("read_first_notes") or []
        if read_first:
            lines.append(f"- read-first / coverage notes ({len(read_first)}):")
            for row in read_first:
                tags = ", ".join(row.get("tags") or []) or "-"
                status_suffix = f" [{row.get('lead_status')}]" if row.get("lead_status") else ""
                lines.append(
                    f"  - id={row.get('id')} ({tags}){status_suffix} {_trim(row.get('title') or '', 100)}"
                )
    lines.extend(["", "## Next Actions"])
    for row in brief.get("recommended_next_actions") or []:
        entity = ""
        if row.get("entity_kind") and row.get("entity_id") is not None:
            entity = f" [{row.get('entity_kind')} {row.get('entity_id')}]"
        lines.append(f"- {row.get('reason')}{entity}: `{row.get('command')}`")
    return "\n".join(lines)


_SURFACE_ROLLUP_LIMIT = 12
_WORK_BUFFER_BUCKET_LIMIT = 12


def _render_surfaces(lines: list, surfaces: dict) -> None:
    """Render the ## Surfaces coverage rollup. No-op when the brief carries no
    surfaces block (older backend or empty engagement)."""
    if not surfaces:
        return
    lines.extend(["", "## Surfaces"])
    lines.append(f"- total: {surfaces.get('total', 0)} (open: {surfaces.get('open_count', 0)})")
    by_status = surfaces.get("by_status") or {}
    compact = ", ".join(f"{name}={count}" for name, count in sorted(by_status.items())) or "-"
    lines.append(f"- by status: {compact}")
    rollup = surfaces.get("by_status_type") or []
    if rollup:
        lines.append("- by status×type:")
        for entry in rollup[:_SURFACE_ROLLUP_LIMIT]:
            lines.append(f"  - {entry.get('status')}/{entry.get('surface_type')}: {entry.get('count')}")
        if len(rollup) > _SURFACE_ROLLUP_LIMIT:
            lines.append(f"  - … showing {_SURFACE_ROLLUP_LIMIT} of {len(rollup)} combinations")
    top = surfaces.get("top_uncovered") or []
    lines.append(f"- top uncovered ({len(top)}):")
    if not top:
        lines.append("  - none")
    for entry in top:
        src = f" [{entry.get('source_name')}]" if entry.get("source_name") else ""
        lines.append(
            f"  - {entry.get('status')} {entry.get('surface_type')}: "
            f"{_trim(entry.get('target_descriptor') or '', 100)}{src}"
        )


def _render_work_buffer(lines: list, work_buffer: dict) -> None:
    """Render the ## Work Buffer pending-by-gf-bucket rollup. No-op when absent."""
    if not work_buffer:
        return
    lines.extend(["", "## Work Buffer"])
    lines.append(f"- pending total: {work_buffer.get('pending_total', 0)}")
    by_bucket = work_buffer.get("by_bucket") or {}
    if not by_bucket:
        lines.append("- pending by gf-bucket: -")
        return
    lines.append("- pending by gf-bucket:")
    items = list(by_bucket.items())
    for name, count in items[:_WORK_BUFFER_BUCKET_LIMIT]:
        lines.append(f"  - {name}: {count}")
    if len(items) > _WORK_BUFFER_BUCKET_LIMIT:
        lines.append(f"  - … showing {_WORK_BUFFER_BUCKET_LIMIT} of {len(items)} buckets")


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_MEDIUM_RANK = 2
_FINDING_ROW_FLOOR = 6


def _severity_rank(value) -> int:
    return _SEVERITY_RANK.get(str(value or "").strip().lower(), 0)


def _select_findings(rows: list) -> list:
    """Always include every medium+ finding; fill the rest up to a floor of 6.

    The old ``rows[:6]`` slice could bury a critical behind six low/info rows.
    Medium-and-above are never truncated; lower-severity rows are shown only
    while the running total is under the floor. Original order is preserved.
    """
    shown: list = []
    for row in rows:
        if _severity_rank(row.get("severity")) >= _MEDIUM_RANK or len(shown) < _FINDING_ROW_FLOOR:
            shown.append(row)
    return shown


def _finding_line(row: dict) -> str:
    return (
        f"{row.get('slug')} {row.get('severity')} "
        f"{row.get('workflow_status')}/{row.get('verification_state')} "
        f"{_trim(row.get('title') or '', 100)}"
    )


def _trim(value: str, limit: int) -> str:
    text = str(value).replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
