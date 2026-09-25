"""vigil assess resume-brief — compact backend operating picture."""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from types import SimpleNamespace
from urllib.parse import quote, urlencode

from assess.commands import kali_sweep_orphans
from assess.commands.code_dispatch import _format_lease_age
from assess.commands.operator_checkpoint import (
    render_checkpoint_reference_lines,
    render_intent_lines,
    render_phase_field,
)
from assess.lib.client import AssessError, AssessmentClient, default_runtime_container
from assess.lib.config import load_config
from assess.lib.finding_render import UNTRUSTED_DATA_NOTICE, blocked_reason_summary
from assess.lib.render_containment import append_contained_value, contain_separators

_COVERING_STATUSES = {"tested", "signal"}
_DEGRADED_OUTPUT_RETENTION = {
    "integrity_failure",
    "measurement_conflict",
    "partially_measured",
    "preview_only",
    "suppression_deferred",
    "unmeasured",
    "untrusted",
}


# The write-shaped verb that actually reconciles what the dry-run observes.
# resume-brief names it verbatim rather than performing the write itself.
_SWEEP_ORPHANS_COMMAND = "vigil assess kali sweep-orphans --scope all"


def _orphan_attention(output: str) -> str:
    payload = None
    for line in reversed(output.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            payload = candidate
            break
    if payload is None:
        return ""
    # Each section names ONLY its genuinely-actionable fields, so the WARN fires
    # for stuck work — not for benign bookkeeping. For command_runs/jobs the
    # sweep's ``skipped`` counter is a benign-vs-genuine union (the backend
    # ignores ?status=running, so it pages ALL historical rows and "skips" every
    # already-terminal one — a benign count that can reach the thousands). Key on
    # ``skipped_unverifiable`` (liveness/pid/PATCH/pending-recovery failures),
    # NOT the conflated ``skipped``, mirroring how host_processes already keys
    # on its bad states (unverifiable/failed) rather than a catch-all (I-05).
    # Under the dry run the counters read as "would": `finalized` is the row the
    # sweep WOULD reconcile to lost and `recovered_pending`/`reaped` are the
    # recoveries it WOULD perform, so those are the genuinely actionable states
    # and each section names them alongside the states that are actionable in
    # either mode. `recovered_degraded` stays listed because the wet run still
    # reports it and the attention line carries its ids.
    sections = (
        (
            "command_runs",
            payload.get("summary"),
            (
                "still_running",
                "skipped_unverifiable",
                "pending_recovery_failed",
                "recovered_degraded",
                "recovered_pending",
                "finalized",
            ),
        ),
        (
            "jobs",
            payload.get("jobs_summary"),
            ("still_running", "skipped_unverifiable", "finalized"),
        ),
        (
            "host_processes",
            payload.get("host_processes_summary"),
            ("unverifiable", "failed", "reaped"),
        ),
    )
    rendered: list[str] = []
    for name, summary, fields in sections:
        if not isinstance(summary, dict):
            continue
        counts = [
            f"{field}={int(summary.get(field) or 0)}"
            for field in fields
            if int(summary.get(field) or 0) > 0
        ]
        if counts:
            attention = f"{name}:{','.join(counts)}"
            if name == "command_runs":
                degraded_ids = [
                    str(row_id)
                    for row_id in (summary.get("recovered_degraded_ids") or [])
                    if type(row_id) is int
                ][: kali_sweep_orphans._ATTENTION_ID_LIMIT]
                if degraded_ids:
                    attention += f" ids={','.join(degraded_ids)}"
                degraded_omitted = int(
                    summary.get("recovered_degraded_ids_omitted") or 0
                )
                if degraded_omitted > 0:
                    attention += f" ids_omitted={degraded_omitted}"
                failed_ids = [
                    str(row_id)
                    for row_id in (
                        summary.get("pending_recovery_failed_ids") or []
                    )
                    if type(row_id) is int
                ][: kali_sweep_orphans._ATTENTION_ID_LIMIT]
                if failed_ids:
                    attention += f" failed_ids={','.join(failed_ids)}"
                failed_omitted = int(
                    summary.get("pending_recovery_failed_ids_omitted") or 0
                )
                if failed_omitted > 0:
                    attention += f" failed_ids_omitted={failed_omitted}"
                if (
                    summary.get("output_attention_action")
                    == kali_sweep_orphans._OUTPUT_ATTENTION_ACTION
                ):
                    attention += (
                        f" action=`{kali_sweep_orphans._OUTPUT_ATTENTION_ACTION}`"
                    )
            rendered.append(attention)
    return "; ".join(rendered)


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
    p.add_argument(
        "--per-input-limit",
        dest="per_input_limit",
        type=int,
        default=None,
        help=(
            "Cap on Per-Input Coverage cells returned (default 20). The grid also "
            "reports the true total (cells_count), so a capped sample still signals "
            "breadth. Use a larger N, or --all-cells, when you need every cell."
        ),
    )
    p.add_argument(
        "--all-cells",
        dest="all_cells",
        action="store_true",
        help="Return every Per-Input Coverage cell (no cap). Equivalent to --per-input-limit 0.",
    )
    p.add_argument("--json", dest="as_json", action="store_true")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    # `resume-brief` is a READ. It OBSERVES abandoned command runs, jobs, and
    # precisely-owned host children (dry_run=True) and names the write-shaped
    # verb that reconciles them; it does not reconcile them itself. A
    # read-shaped command that silently wrote was a hazard the moment a hook or
    # another command could invoke it automatically. The reconciling write stays
    # owned by `vigil assess kali sweep-orphans`, which says on the tin that it
    # writes; the one-hour cutoff keeps the observation bounded and the sweep's
    # own stdout is internal plumbing, not part of the response contract.
    try:
        sweep_output = io.StringIO()
        with redirect_stdout(sweep_output):
            kali_sweep_orphans.run(
                SimpleNamespace(
                    engagement_dir=getattr(cfg, "engagement_dir", args.engagement_dir),
                    scope="all",
                    max_age_seconds=3600,
                    container_name=default_runtime_container(),
                    dry_run=True,
                )
            )
        attention = _orphan_attention(sweep_output.getvalue())
        if attention:
            print(
                "WARN: resume-brief observed unreconciled orphans "
                f"(nothing was written): {attention}",
                file=sys.stderr,
            )
            print(
                f"WARN: reconcile them with `{_SWEEP_ORPHANS_COMMAND}`",
                file=sys.stderr,
            )
    except (AssessError, OSError, SystemExit) as exc:
        print(
            f"WARN: resume-brief orphan observation failed: {exc}",
            file=sys.stderr,
        )
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
    if getattr(args, "all_cells", False):
        params.append(("per_input_limit", "0"))
    elif getattr(args, "per_input_limit", None) is not None:
        params.append(("per_input_limit", str(int(args.per_input_limit))))
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
        UNTRUSTED_DATA_NOTICE,
        "",
        f"- phase: {engagement.get('current_phase', 'unknown')}",
        f"- scope_status: {engagement.get('scope_status', 'unknown')}",
        f"- hosts: {engagement.get('host_count', 0)}",
    ]
    if query.get("q") or query.get("finding") or query.get("agent_id") or query.get("since"):
        lines.append(contain_separators(
            f"- query: q={query.get('q') or '-'} finding={query.get('finding') or '-'} "
            f"agent_id={query.get('agent_id') or '-'} since={query.get('since') or '-'}"
        ))
    _render_operator_checkpoint(lines, brief.get("operator_checkpoint"))
    lines.extend(["", "## Finding Counts"])
    counts = brief.get("finding_counts") or {}
    for key in ("workflow", "verification_status", "severity", "source"):
        values = counts.get(key) or {}
        compact = ", ".join(f"{name}={count}" for name, count in sorted(values.items())) or "-"
        lines.append(contain_separators(f"- {key}: {compact}"))
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
    _render_attempts(lines, brief.get("attempts") or {})
    _render_credential_needs(lines, brief.get("credential_needs") or {})
    _render_contradiction_reviews(lines, brief.get("contradiction_reviews") or {})
    _render_per_input_coverage(lines, brief.get("per_input_coverage") or {})
    _render_code_analysis(lines, brief.get("code_analysis") or {})
    _render_decisions(
        lines,
        brief.get("recent_decisions") or [],
        brief.get("recent_decisions_count"),
    )
    lines.extend(["", "## Dispatches"])
    dispatches = brief.get("dispatches") or {}
    closable_rows = dispatches.get("closable_handoffs") or []
    for row in closable_rows:
        lines.append(contain_separators(
            f"- closeout: {row.get('agent_id')} role={row.get('agent_role')} "
            f"handoff={row.get('handoff_status')} action=`vigil assess agent close {row.get('agent_id')}`"
        ))
    _render_dispatch_more(lines, len(closable_rows), dispatches.get("closable_handoffs_count"), "closable handoffs")
    # The lists are capped by the backend; the *_count fields carry the TRUE
    # totals so a stale row that sorts below the display window is still counted
    # (I-10). Surface a "showing N of M" hint whenever the list was truncated.
    stale_rows = dispatches.get("stale_in_progress_dispatches") or []
    for row in stale_rows:
        lines.append(contain_separators(f"- stale: {row.get('agent_id')} role={row.get('agent_role')} age_h={row.get('age_hours')} handoff={row.get('handoff_status')}"))
    _render_dispatch_more(lines, len(stale_rows), dispatches.get("stale_in_progress_dispatches_count"), "stale in-progress dispatches")
    gap_rows = dispatches.get("handoff_gaps") or []
    for row in gap_rows:
        lines.append(contain_separators(f"- gap: {row.get('agent_id')} role={row.get('agent_role')} reason={row.get('reason')}"))
    _render_dispatch_more(lines, len(gap_rows), dispatches.get("handoff_gaps_count"), "handoff gaps")
    terminal_rows = dispatches.get("terminal_no_handoff") or []
    for row in terminal_rows:
        lines.append(contain_separators(
            f"- terminal-no-handoff: {row.get('agent_id')} role={row.get('agent_role')} "
            f"status={row.get('status')} completed_at={row.get('completed_at')} "
            "(silent state-loss — no handoff was ever written)"
        ))
    _render_dispatch_more(lines, len(terminal_rows), dispatches.get("terminal_no_handoff_count"), "terminal handoff-less dispatches")
    if not (closable_rows or stale_rows or gap_rows or terminal_rows):
        lines.append(
            "- no stale in-progress dispatches, handoff gaps, or terminal "
            "handoff-less dispatches across the engagement"
        )
    _render_recent_dispatches(
        lines,
        dispatches.get("recent_dispatches") or [],
        dispatches.get("recent_dispatches_count"),
    )
    _render_latest_handoffs(
        lines,
        dispatches.get("latest_handoffs") or [],
        dispatches.get("latest_handoffs_count"),
    )
    selected = dispatches.get("selected_dispatch")
    if selected:
        lines.extend(["", "## Selected Dispatch"])
        lines.append(contain_separators(
            f"- agent_id: {selected.get('agent_id')} role={selected.get('agent_role')} "
            f"status={selected.get('status')} dispatched_at={selected.get('dispatched_at')}"
        ))
        lines.extend(
            contain_separators(line)
            for line in (
                f"- requested: model={selected.get('requested_model') or 'unknown'} "
                f"reasoning={selected.get('requested_reasoning') or 'unknown'}",
                "- launcher-effective: "
                f"model={selected.get('launcher_effective_model') or 'unknown'} "
                f"reasoning={selected.get('launcher_effective_reasoning') or 'unknown'} "
                f"source={selected.get('launcher_effective_source') or 'unknown'}",
                f"- provider-observed: model={selected.get('actual_model') or 'unknown'} "
                f"reasoning={selected.get('actual_reasoning') or 'unknown'}",
            )
        )
        if selected.get("task"):
            append_contained_value(lines, "- task:", selected.get("task"))
        if selected.get("finding_slugs"):
            lines.append(contain_separators(f"- finding_slugs: {', '.join(selected.get('finding_slugs') or [])}"))
    selected_handoff = dispatches.get("selected_handoff")
    if selected_handoff:
        lines.extend(["", "## Selected Handoff"])
        lines.append(contain_separators(
            f"- agent_id: {selected_handoff.get('agent_id')} "
            f"status={selected_handoff.get('handoff_status')} "
            f"version={selected_handoff.get('handoff_version')} "
            f"last_checkpoint_at={selected_handoff.get('last_checkpoint_at')}"
        ))
        if selected_handoff.get("summary"):
            append_contained_value(
                lines, "- summary:", selected_handoff.get("summary")
            )
        if selected_handoff.get("finding_slugs"):
            lines.append(contain_separators(f"- finding_slugs: {', '.join(selected_handoff.get('finding_slugs') or [])}"))
        for step in (selected_handoff.get("next_steps") or [])[:3]:
            if isinstance(step, dict):
                lines.append(contain_separators(
                    f"- next: {step.get('action') or '-'} → {step.get('target') or '-'} "
                    f"({step.get('recommended_agent') or '-'})"
                ))
    lines.extend(["", "## Command Runs"])
    for row in brief.get("command_runs") or []:
        output_truth = _command_output_truth(row)
        lines.append(contain_separators(
            f"- #{row.get('id')} {row.get('created_at')} "
            f"{row.get('tool_bin') or row.get('tool_name')} {row.get('agent_name')} "
            f":: {_trim(row.get('intent') or row.get('command') or '', 120)}"
            f"{output_truth}"
        ))
    if not brief.get("command_runs"):
        lines.append("- none")
    _render_page_truth(lines, brief.get("command_runs_page"), "command runs")
    lines.extend(["", "## Artifacts"])
    for row in brief.get("artifacts") or []:
        lines.append(contain_separators(f"- #{row.get('id')} {row.get('kind')} present={row.get('present')} {row.get('relative_path')}"))
    if not brief.get("artifacts"):
        lines.append("- none")
    _render_page_truth(lines, brief.get("artifacts_page"), "artifacts")
    _render_knowledge_drift(lines, brief.get("knowledge_drift") or {})
    intel = brief.get("intel") or {}
    if intel:
        lines.extend(["", "## Intel"])
        summary = intel.get("summary") or {}
        compact = ", ".join(f"{name}={count}" for name, count in sorted(summary.items()) if count) or "-"
        lines.append(contain_separators(f"- counts: {compact}"))
        open_cves = intel.get("open_high_cves") or []
        lines.append(f"- open high CVEs ({len(open_cves)}):")
        if not open_cves:
            lines.append("  - none")
        for row in open_cves:
            link = row.get("linked_finding_slug") or "UNLINKED"
            lines.append(contain_separators(
                f"  - id={row.get('id')} {row.get('cve_id')} cvss {row.get('cvss_score')} "
                f"[{row.get('validation_status')}] → {link}"
                + (f" ({_trim(row.get('affected_component') or '', 60)})" if row.get("affected_component") else "")
            ))
        open_leads = intel.get("open_leads") or []
        lines.append(f"- open leads ({len(open_leads)}):")
        if not open_leads:
            lines.append("  - none")
        for row in open_leads:
            lines.append(contain_separators(f"  - id={row.get('id')} [{row.get('lead_status')}] {_trim(row.get('title') or '', 100)}"))
        read_first = intel.get("read_first_notes") or []
        if read_first:
            lines.append(f"- read-first / coverage notes ({len(read_first)}):")
            for row in read_first:
                tags = ", ".join(row.get("tags") or []) or "-"
                status_suffix = f" [{row.get('lead_status')}]" if row.get("lead_status") else ""
                lines.append(contain_separators(
                    f"  - id={row.get('id')} ({tags}){status_suffix} {_trim(row.get('title') or '', 100)}"
                ))
    lines.extend(["", "## Next Actions"])
    for row in brief.get("recommended_next_actions") or []:
        entity = ""
        if row.get("entity_kind") and row.get("entity_id") is not None:
            entity = f" [{row.get('entity_kind')} {row.get('entity_id')}]"
        lines.append(contain_separators(f"- {row.get('reason')}{entity}: `{row.get('command')}`"))
    return "\n".join(lines)


def _render_operator_checkpoint(lines: list, checkpoint: object) -> None:
    """Render the operator's own last checkpoint, intent clearly UNVERIFIED.

    Specialists leave handoff rows; before `operator-checkpoint` the operator
    left nothing, so a resumed session had to guess what it had been doing. The
    intent line is the one free-text field on that row and is labelled so it can
    never be read back as a finding or as evidence."""
    if not isinstance(checkpoint, dict) or not checkpoint:
        return
    lines.extend(["", "## Operator Checkpoint"])
    # `render_phase_field` inside the header, and the reference-list and intent
    # renders below, are shared with `operator-checkpoint show` so the two views
    # cannot drift — on which tracks a combined engagement reports, on the
    # reference lists, and on the
    # UNVERIFIED label / containment that keeps a reference or multi-line note
    # from forging one of this brief's own section boundaries.
    header = (
        f"- checkpoint #{checkpoint.get('checkpoint_version')} "
        f"{render_phase_field(checkpoint)} "
        f"source={checkpoint.get('source') or 'unknown'} "
        f"at={checkpoint.get('created_at') or 'unknown'}"
    )
    lines.append(header)
    lines.extend(render_checkpoint_reference_lines(checkpoint))
    lines.extend(render_intent_lines(checkpoint.get("intent_note")))
    lines.append(
        "  - full chain: `vigil assess operator-checkpoint show --all`"
    )


def _render_decisions(lines: list, rows: list, total) -> None:
    """Render the recent operator decision ledger.

    The backend has always carried `recent_decisions` and both the resume rule
    and the operator prompt promise "recent decisions" in the brief — the
    markdown path (the one the agent actually reads) never rendered them."""
    if not rows:
        return
    lines.extend(["", "## Recent Decisions"])
    lines.append("- point read: `vigil assess fetch dispatch-decisions/<id>`")
    for row in rows:
        resolved = bool(row.get("resolved"))
        state = "resolved" if resolved else "open"
        surfaced = " surfaced" if row.get("surfaced_to_user") else ""
        payload = row.get("payload")
        detail = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True)
            if isinstance(payload, dict) and payload
            else "-"
        )
        append_contained_value(
            lines,
            f"- #{row.get('id')} {row.get('created_at')} {row.get('kind')} "
            f"[{state}{surfaced}] ::",
            detail,
        )
        # `[resolved]` says a call was made, not which one; without the
        # resolution a resumed operator can only re-ask the question it already
        # answered, or contradict it. Every resolved row gets the line —
        # "settled with nothing recorded" is a real state, and the one most
        # worth seeing — and an unresolved row gets it only when the backend
        # carries a resolution anyway, which is state to surface, not hide.
        resolution = row.get("resolution")
        if resolved or resolution:
            # Narrowing to dicts the way `payload` does would blank any other
            # shape the column holds — the loss this line exists to close.
            append_contained_value(
                lines,
                "  - resolution ::",
                json.dumps(resolution, ensure_ascii=False, sort_keys=True)
                if resolution
                else "-",
            )
    _render_dispatch_more(lines, len(rows), total, "recent decisions")


def _render_recent_dispatches(lines: list, rows: list, total) -> None:
    """Render the newest dispatch rows across every status."""
    if not rows:
        return
    lines.append(f"- recent dispatches ({len(rows)}):")
    for row in rows:
        slugs = ", ".join(row.get("finding_slugs") or []) or "-"
        binding = row.get("client_binding") or {}
        # Where this specialist is reachable right now. `agent_id` is a name the
        # operator chose; it identifies the dispatch row, never the live session.
        # Resume is exactly when that mapping has been lost, so the brief carries
        # it. All THREE asserted fields render: `bind-client-handle` requires a
        # session namespace because a bare handle is ambiguous across clients and
        # machines, so client+handle alone is the half a reader cannot act on.
        # A count above 1 means the binding was corrected; every superseded
        # version stays readable through
        # `vigil assess fetch dispatches/<agent-id>/client-bindings`.
        binding_count = int(row.get("client_binding_count") or 0)
        if binding:
            client = (
                f"{binding.get('asserted_client')}:"
                f"{binding.get('asserted_session_namespace')}:"
                f"{binding.get('asserted_client_handle')}"
            )
            if binding_count > 1:
                client += f" (v{binding.get('binding_version')} of {binding_count})"
        else:
            # The version suffix describes the CURRENT binding, so an unbound row
            # has no version to name — reading one off an empty binding printed
            # `(vNone of 2)`. The count still matters: it says a history exists.
            client = "unbound"
            if binding_count:
                client += f" ({binding_count} in history)"
        append_contained_value(
            lines,
            f"  - {row.get('agent_id')} role={row.get('agent_role')} "
            f"status={row.get('status')} dispatched_at={row.get('dispatched_at')} "
            f"client={client} findings={slugs} ::",
            str(row.get("task") or ""),
        )
    _render_dispatch_more(lines, len(rows), total, "dispatches")


def _render_latest_handoffs(lines: list, rows: list, total) -> None:
    """Render the newest specialist handoff rows — the "what was done" ledger."""
    if not rows:
        return
    lines.append(f"- latest handoffs ({len(rows)}):")
    for row in rows:
        slugs = ", ".join(row.get("finding_slugs") or []) or "-"
        append_contained_value(
            lines,
            f"  - {row.get('agent_id')} role={row.get('agent_role')} "
            f"status={row.get('handoff_status')} v{row.get('handoff_version')} "
            f"last_checkpoint_at={row.get('last_checkpoint_at')} findings={slugs} "
            "::",
            str(row.get("summary") or ""),
        )
    _render_dispatch_more(lines, len(rows), total, "handoffs")


def _render_page_truth(lines: list[str], page: object, noun: str) -> None:
    if not isinstance(page, dict) or not page.get("truncated"):
        return
    returned = int(page.get("returned_count") or 0)
    total = int(page.get("total_count") or returned)
    qualifier = "at least " if page.get("total_is_lower_bound") else ""
    lines.append(f"- … showing {returned} of {qualifier}{total} {noun}")


def _render_knowledge_drift(lines: list, drift: dict) -> None:
    """Render session-start drift as an advisory, never a readiness verdict."""
    if not drift:
        return
    lines.extend(["", "## Knowledge Drift (advisory)"])
    if drift.get("detector_status") != "complete":
        detail = _trim(drift.get("detector_detail") or "unknown detector error", 300)
        lines.append(contain_separators(
            "- unlinked-markdown detector unavailable; do not infer that no "
            f"unlinked prose exists: {detail}"
        ))
        return
    rows = drift.get("unlinked_markdown_notes") or []
    total = drift.get("unlinked_markdown_note_count")
    if not isinstance(total, int):
        total = len(rows)
    lines.append(f"- unlinked markdown notes ({total}):")
    if not rows:
        lines.append("  - none")
        return
    for row in rows:
        path = _trim(row.get("path") or "", 160) or "-"
        detail = _trim(row.get("detail") or "", 300)
        artifact_id = row.get("artifact_id")
        prefix = f"#{artifact_id} " if artifact_id is not None else ""
        lines.append(
            contain_separators(f"  - {prefix}{path}" + (f" :: {detail}" if detail else ""))
        )
    if drift.get("truncated") or len(rows) < total:
        lines.append(f"  - … showing {len(rows)} of {total}")


def _command_output_truth(row: dict) -> str:
    retention = str(row.get("output_retention_status") or "").strip().lower()
    cleanup = str(row.get("output_cleanup_status") or "").strip().lower()
    integrity = str(row.get("output_integrity_status") or "").strip().lower()
    if not (
        retention in _DEGRADED_OUTPUT_RETENTION
        or cleanup in {"deferred", "pending", "warning"}
        or integrity in {"pending", "warning"}
    ):
        return ""
    recovery_observed_at = str(
        row.get("output_recovery_observed_at") or ""
    ).strip()
    observed = (
        f" output_recovery_observed_at={recovery_observed_at}"
        if recovery_observed_at
        else ""
    )
    return (
        f" [output={retention or 'unknown'} cleanup={cleanup or 'unknown'} "
        f"integrity={integrity or 'unknown'}{observed}]"
    )


def _render_dispatch_more(lines: list, shown: int, total, label: str) -> None:
    """Emit a '… showing N of M' hint when the backend capped a dispatch worklist
    (stale / gaps / terminal) but reported a larger true total via its ``*_count``
    field (I-10). A ``None`` total (older backend) or an un-truncated list emits
    nothing. The reconcile-stale action for the full set is already surfaced under
    ## Next Actions, so this only signals depth."""
    if isinstance(total, int) and total > shown:
        lines.append(f"  - … showing {shown} of {total} {label}")


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
    lines.append(contain_separators(f"- by status: {compact}"))
    rollup = surfaces.get("by_status_type") or []
    if rollup:
        lines.append("- by status×type:")
        for entry in rollup[:_SURFACE_ROLLUP_LIMIT]:
            lines.append(contain_separators(f"  - {entry.get('status')}/{entry.get('surface_type')}: {entry.get('count')}"))
        if len(rollup) > _SURFACE_ROLLUP_LIMIT:
            lines.append(f"  - … showing {_SURFACE_ROLLUP_LIMIT} of {len(rollup)} combinations")
    top = surfaces.get("top_uncovered") or []
    lines.append(f"- top uncovered ({len(top)}):")
    if not top:
        lines.append("  - none")
    for entry in top:
        src = f" [{entry.get('source_name')}]" if entry.get("source_name") else ""
        lines.append(contain_separators(
            f"  - {entry.get('status')} {entry.get('surface_type')}: "
            f"{_trim(entry.get('target_descriptor') or '', 100)}{src}"
        ))


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
        lines.append(contain_separators(f"  - {name}: {count}"))
    if len(items) > _WORK_BUFFER_BUCKET_LIMIT:
        lines.append(f"  - … showing {_WORK_BUFFER_BUCKET_LIMIT} of {len(items)} buckets")


_ATTEMPTS_RENDER_LIMIT = 8


def _render_credential_needs(lines: list[str], section: dict) -> None:
    count = int(section.get("count") or 0)
    if not count:
        return
    items = section.get("items") or []
    lines.extend(["", f"## Credential and Identity Needs ({count})"])
    for item in items:
        reference = item.get("slug") or f"decision #{item.get('id')}"
        lines.append(contain_separators(
            f"- {reference}: identity={item.get('identity') or '-'} "
            f"surface={item.get('surface') or '-'} "
            f"need={item.get('need') or '-'} "
            f"requested_from={item.get('requested_from') or '-'}"
        ))
    if count > len(items):
        lines.append(f"- … showing {len(items)} of {count}")


def _render_contradiction_reviews(lines: list[str], section: dict) -> None:
    count = int(section.get("count") or 0)
    if not count:
        return
    items = section.get("items") or []
    lines.extend(["", f"## Contradiction Reviews ({count})"])
    for item in items:
        lines.append(contain_separators(
            f"- link #{item.get('link_id')}: {item.get('source_slug')} contradicts "
            f"{item.get('target_slug')} — {_trim(item.get('notes') or '', 160)}; "
            f"review with `vigil assess finding get {item.get('target_slug')}`"
        ))
    if count > len(items):
        lines.append(f"- … showing {len(items)} of {count}")


def _render_attempts(lines: list, attempts: dict) -> None:
    """Render the ## Attempts do-today ledger (P1-C). No-op when the brief
    carries no attempts block (older backend) or both sources are empty — a
    fresh engagement should not accrue a noise section.

    Surfaces two previously resume-invisible signals so a re-dispatch reads what
    was already tried-and-walled-off on a surface: recorded blocked techniques
    and roe_blocked findings. Per-input probe coverage moved to its own
    ## Per-Input Coverage section (see _render_per_input_coverage)."""
    if not attempts:
        return
    blocked = attempts.get("blocked_techniques") or []
    roe = attempts.get("roe_blocked_findings") or []
    if not (blocked or roe):
        return
    lines.extend(["", "## Attempts"])

    blocked_count = attempts.get("blocked_techniques_count", len(blocked))
    lines.append(f"- blocked techniques ({blocked_count}):")
    if not blocked:
        lines.append("  - none")
    shown_blocked = blocked[:_ATTEMPTS_RENDER_LIMIT]
    for row in shown_blocked:
        target = f"{row.get('target_kind') or '-'}:{row.get('target_ref') or '-'}"
        line = (
            f"  - #{row.get('id')} {row.get('technique') or '-'} "
            f"[{row.get('retry_state') or '-'}] {target} :: "
            f"{_trim(row.get('reason') or '', 120)}"
        )
        notes = _trim(row.get("notes") or "", 120)
        if notes:
            line += f" — unblock: {notes}"
        lines.append(contain_separators(line))
    _render_attempts_more(lines, len(shown_blocked), blocked_count)

    roe_count = attempts.get("roe_blocked_findings_count", len(roe))
    lines.append(f"- roe-blocked findings ({roe_count}):")
    if not roe:
        lines.append("  - none")
    shown_roe = roe[:_ATTEMPTS_RENDER_LIMIT]
    for row in shown_roe:
        lines.append("  - " + _finding_line(row))
    _render_attempts_more(lines, len(shown_roe), roe_count)


def _render_attempts_more(lines: list, shown: int, total: int) -> None:
    """Emit a truncation hint when the rendered (since-filtered, capped) list is
    shorter than the absolute count. The counts are deliberate absolute totals
    (like finding_counts), so shown < total is expected under --since or capping;
    the hint keeps the reconciliation unambiguous, mirroring the Findings section."""
    if shown < total:
        lines.append(f"  - … showing {shown} of {total}")


_PER_INPUT_RENDER_LIMIT = 20


def _render_per_input_coverage(lines: list, per_input: dict) -> None:
    """Render the ## Per-Input Coverage grid (WS2). No-op when the brief carries
    no grid (older backend) or no cells — a fresh engagement gets no section.

    Each cell is one (host × path × attack_family × input_slot × auth_context)
    tuple; cells are grouped under their host+path so the operator reads, per
    surface, which input was tested for which class as which identity, the latest
    verdict, and the wall code (e.g. a 403). Both covering (tested/signal) and
    non-covering probes appear — the verdict word distinguishes them — so this is
    a coverage view, not just a dead-ends ledger. It supersedes the old flat
    non-covering probe list that used to live under ## Attempts."""
    if not per_input:
        return
    cells = per_input.get("cells") or []
    if not cells:
        return
    total = per_input.get("cells_count", len(cells))
    lines.extend(["", "## Per-Input Coverage"])

    shown = cells[:_PER_INPUT_RENDER_LIMIT]
    # Group by host+path, preserving the backend's recency order.
    groups: dict[str, list] = {}
    for cell in shown:
        host_path = f"{cell.get('target_host') or '-'}{cell.get('target_path') or ''}"
        groups.setdefault(_trim(host_path, 80), []).append(cell)

    for host_path, group in groups.items():
        lines.append(contain_separators(f"- {host_path}:"))
        for cell in group:
            family = cell.get("attack_family") or "-"
            slot = _trim(cell.get("input_slot") or "-", 48)
            auth = cell.get("auth_context") or "-"
            status = cell.get("latest_status") or "-"
            wall = cell.get("observed_http_status")
            verdict = f"{status}({wall})" if wall is not None else status
            if cell.get("covering") and status not in _COVERING_STATUSES:
                verdict = f"covered; latest={verdict}"
            count = cell.get("count") or 1
            line = f"  - {family} {slot} [{auth}] {verdict} x{count}"
            lens = _trim(cell.get("lens") or "", 40)
            if lens:
                line += f" — {lens}"
            lines.append(contain_separators(line))

    if len(shown) < total:
        lines.append(f"- … showing {len(shown)} of {total} input-cells")


def _render_code_analysis(lines: list, code_analysis: dict) -> None:
    """Render the code gate and open leases. No-op for a web-only engagement.

    A queue row still in `processing` is a dispatch that was authoring durable
    state when it stopped: the lease is held, receipts may already be recorded,
    and no closeout ever ran. Nothing else in this brief reports it — the
    dispatch sections describe `assessment_dispatches`, not the analysis queue —
    so a resumed session would either re-dispatch the file or reach for
    `reset-stale`, which discards what the dead lease already wrote.
    """
    if not code_analysis:
        return
    leases = code_analysis.get("open_leases") or []
    if not leases and not any(
        key in code_analysis for key in (
            "queue_count", "coverage_by_classification", "trigger_counts",
            "next_gate", "reference_repos",
        )
    ):
        return
    lease_total = code_analysis.get("open_leases_count", len(leases))
    lines.extend(["", "## Code Analysis"])
    trigger_counts = code_analysis.get("trigger_counts") or {}
    lines.append(contain_separators(
        f"- remaining queue={code_analysis.get('queue_count', 0)} "
        f"triggers_pending={trigger_counts.get('pending', 0)} "
        f"triggers_queued={trigger_counts.get('queued', 0)}"
    ))
    tiers = code_analysis.get("coverage_by_classification") or {}
    if tiers:
        lines.append("- review coverage by classification:")
        for classification in ("critical", "high", "medium", "low", "skip"):
            row = tiers.get(classification)
            if not isinstance(row, dict):
                continue
            tier_total = int(row.get("count") or 0)
            reviewed = int(row.get("analyzed") or 0)
            remaining = int(row.get("remaining") or 0)
            pct = reviewed / tier_total * 100 if tier_total else 100.0
            lines.append(contain_separators(
                f"  - {classification}: {reviewed}/{tier_total} reviewed "
                f"({pct:.0f}%); {remaining} remaining"
            ))
    next_gate = code_analysis.get("next_gate")
    if isinstance(next_gate, dict):
        target = next_gate.get("target_phase") or "unknown"
        state = "READY" if next_gate.get("transition_ready") is True else "BLOCKED"
        blockers = ", ".join(next_gate.get("blocker_codes") or []) or "none"
        lines.append(contain_separators(
            f"- next phase transition ({target}): {state}; blockers={blockers}; "
            f"structural debt: {int(next_gate.get('structural_debt_count') or 0)} files"
        ))
    elif next_gate:
        lines.append(contain_separators(f"- next phase transition: {next_gate}"))
    else:
        lines.append("- next phase transition: none")
    coverage_gate = code_analysis.get("coverage_gate") or {}
    if coverage_gate:
        state = "PASS" if coverage_gate.get("passed") is True else "NEEDS ATTENTION"
        reasons = "; ".join(str(item) for item in coverage_gate.get("reasons", [])[:3])
        lines.append(contain_separators(
            f"- coverage quality gate: {state}"
            + (f" ({reasons})" if reasons else "")
        ))
    references = code_analysis.get("reference_repos") or []
    for repo in references:
        lines.append(contain_separators(
            f"- reference repo: id={repo.get('repo_id')} key={repo.get('repo_key')} "
            f"generation={repo.get('repo_generation')} (navigation only)"
        ))
    reference_total = code_analysis.get("reference_repos_count", len(references))
    if reference_total > len(references):
        lines.append(f"- … showing {len(references)} of {reference_total} reference repos")
    if not leases:
        return
    lines.append(f"- open analysis leases ({lease_total}):")
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        lines.append(contain_separators(
            f"  - item {lease.get('queue_item_id')} "
            f"{_trim(lease.get('file_path') or '', 80)} "
            f"[{lease.get('classification') or '-'}] agent={lease.get('agent_name') or '-'} "
            f"lease={lease.get('lease_token') or '-'} "
            f"silent={_format_lease_age(lease.get('heartbeat_age_seconds'))} "
            f"receipts={lease.get('current_result_count', 0)}"
        ))
    if isinstance(lease_total, int) and lease_total > len(leases):
        lines.append(f"  - … showing {len(leases)} of {lease_total}")
    lines.append(
        "  - inspect: `vigil assess code-dispatch progress <item-id>`; recover with "
        "`code-dispatch adopt-lease` (keeps receipts) or `code-dispatch reset-stale` "
        "(discards them)"
    )


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
    line = (
        f"{row.get('slug')} {row.get('severity')} "
        f"{row.get('workflow_status')}/{row.get('verification_status')} "
        f"{_trim(row.get('title') or '', 100)}"
    )
    # A blocked-for-provisioning finding shows its status above, but not why.
    # Append the reason so a resume
    # reads it without opening the finding. No-op for non-blocked findings.
    blocked = blocked_reason_summary(row)
    if blocked:
        line += f" — {_trim(blocked, 160)}"
    # Contained here rather than at each of the three call sites (target
    # finding, findings buckets, roe-blocked attempts) so no caller can forget.
    return contain_separators(line)


def _trim(value: str, limit: int) -> str:
    """Bound one field to a one-row preview. This is NOT containment.

    The newline-to-space collapse is a LAYOUT decision — these fields render
    mid-row (`- #12 … :: <intent>`), so a preview that wrapped would break the
    one-record-per-row shape the brief is read at. It is not a security
    boundary and must never be mistaken for one: it leaves bare CR, VT/FF, the
    C0 separator controls, NEL and U+2028/U+2029 exactly as they were, and it
    truncates, which containment never does.

    `render_containment.contain_separators` is the boundary, and every call
    site here passes its assembled line through it — grep `_trim(` to check
    that stays true. Splitting the two is deliberate: the layout bound applies
    to a chosen subset of fields, containment applies to every rendered line.
    """
    text = str(value).replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
