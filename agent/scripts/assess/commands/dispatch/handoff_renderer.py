"""render-handoff — bounded handoff blob generator (Fix #7).

Cross-Dispatch Continuity in operator-core.md tells the operator to keep
handoff prompts bounded ("two or three excerpted lines + finding slugs +
file paths"). Without a helper the operator's discretion was the only
protection; under parallelism that degrades — operators paste full
transcripts because it's fast and the dispatch prompt arrives bloated.

render-handoff replaces that discretion with a deterministic emitter that
pulls from durable state (the orchestrator's assessment_dispatches +
assessment_dispatch_handoffs tables) and emits a markdown blob the operator
pastes verbatim into the next dispatch prompt. The context excerpt is capped at
--max-lines (default 40; 0 renders the complete recorded handoff); the findings list collapses to "... and N more"
before any fixed sections drop.
"""
from __future__ import annotations

import json
import os
import sys

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import UNTRUSTED_DATA_NOTICE
from assess.lib.render_containment import contain_separators


def _render_handoff(args, extra: list[str]) -> None:
    """Emit a bounded markdown handoff blob for a prior dispatch.

    Reads from the orchestrator backend (assessment_dispatches +
    assessment_dispatch_handoffs). The handoff payload provides
    summary / coverage gaps / next steps / runtime issues / working artifacts
    / open questions / extras; the dispatch row provides metadata (role,
    task, application_unit_id, dispatched_at, status). 404 on the
    handoff exits 2; 404 on the dispatch row is non-fatal — the renderer
    still produces output from the handoff.
    """
    if not extra:
        print(
            "Usage: vigil assess agent render-handoff <agent-id> "
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

    max_lines = int(getattr(args, "max_lines", 40))
    if max_lines < 0:
        print("render-handoff: --max-lines must be non-negative (0 renders all)", file=sys.stderr)
        sys.exit(1)
    include_evidence = bool(getattr(args, "include_evidence", False))

    cfg = load_config(getattr(args, "engagement_dir", None))
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        handoff = client.get_handoff(agent_id)
        if handoff is None:
            print(
                f"render-handoff: agent-id '{agent_id}' has no recorded handoff in the backend "
                f"(GET dispatch-handoffs/{agent_id} -> 404). Specialist dispatches should call "
                f"`vigil assess agent handoff` before exiting; a missing handoff means "
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
            application_unit_id = dispatch.get("application_unit_id")
            dispatched_at = dispatch.get("dispatched_at") or ""
            dispatch_status = dispatch.get("status") or ""
            skills = str(dispatch.get("skills") or "")
        else:
            role = str(handoff.get("agent_role") or "<unknown role>")
            task = "<unrecorded task>"
            application_unit_id = None
            dispatched_at = handoff.get("created_at") or ""
            dispatch_status = "(dispatch row missing)"
            skills = ""

        # Handoff payload extraction. JSON columns deserialize to lists/dicts
        # in the state-manager serializer; treat anything else defensively.
        handoff_finding_slugs = _normalise_finding_slugs(handoff.get("finding_slugs"))
        dispatch_finding_slugs = _normalise_finding_slugs(
            dispatch.get("finding_slugs") if dispatch is not None else None
        )
        # The two rows are independently useful audit surfaces. Enrich their
        # stable union so a slug recorded at dispatch closure is not silently
        # lost merely because the handoff author omitted it (or vice versa).
        finding_slugs = list(dict.fromkeys(dispatch_finding_slugs + handoff_finding_slugs))

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
        extras_payload = handoff.get("extras") or {}
        summary = str(handoff.get("summary") or "")
        confidence = str(handoff.get("confidence") or "")

        # Handoff-row provenance. Every specialist's closing sequence is "write
        # the handoff, then render it as a self-check". A REJECTED write (e.g.
        # HTTP 422 on an over-long summary) leaves the PRIOR row intact, so the
        # render succeeded and exited 0 against stale content — the self-check
        # could not detect the failure it exists to detect. The renderer has no
        # way to know what the caller tried to write, so it surfaces the row's
        # own identity instead: handoff_version and last_checkpoint_at both move
        # on every accepted write, so an unchanged pair after a "successful"
        # write is the tell. `dispatched_at` is the DISPATCH timestamp and never
        # moves on a handoff write, which is why it must not be read as one.
        handoff_status = str(handoff.get("handoff_status") or "")
        handoff_version = handoff.get("handoff_version")
        handoff_written_at = str(
            handoff.get("last_checkpoint_at") or handoff.get("created_at") or ""
        )

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
        try:
            # Credentials are engagement-scoped, not under /assessment. The
            # continuity line describes the store the next worker inherits,
            # independent of which role originally captured each identity.
            creds = client.get_engagement("credentials")
        except AssessError:
            creds = []
        if isinstance(creds, list):
            credential_rows = [c for c in creds if isinstance(c, dict)]

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
        application_unit_id=application_unit_id,
        dispatched_at=dispatched_at,
        status=dispatch_status,
        skills=skills,
        handoff_status=handoff_status,
        handoff_version=handoff_version,
        handoff_written_at=handoff_written_at,
        summary=summary,
        confidence=confidence,
        dispatch_finding_slugs=dispatch_finding_slugs,
        handoff_finding_slugs=handoff_finding_slugs,
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
        extras=extras_payload,
    )
    print(blob)


def _render_handoff_blob(
    *,
    agent_id: str,
    role: str,
    task: str,
    application_unit_id: object,
    dispatched_at: str,
    status: str,
    skills: str,
    handoff_status: str = "",
    handoff_version: object = None,
    handoff_written_at: str = "",
    summary: str,
    confidence: str,
    dispatch_finding_slugs: list[str],
    handoff_finding_slugs: list[str],
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
    extras: object = None,
) -> str:
    """Build the markdown handoff blob with the documented section order.

    Section order: header / summary / confidence / findings / coverage gaps /
    next steps / open questions / specialist observations / working artifacts / runtime issues /
    recommended next agent. Trim policy on overflow: findings list collapses
    first ("... and N more"), then runtime_issues, then working_artifacts. If
    multiline load-bearing prose alone still exceeds the caller's hard cap, the
    final blob is visibly truncated rather than silently violating --max-lines.
    A zero cap returns every recorded field for inspection; context selection
    happens when the operator builds the next dispatch, not during storage.
    """
    head = [
        f"#### Handoff from {role} dispatch {agent_id}",
        UNTRUSTED_DATA_NOTICE,
        f"- **Prior task:** {task}",
        f"- **Application unit:** {application_unit_id or '(none recorded)'}",
        f"- **Dispatched at:** {dispatched_at or '(unknown)'} (status: {status or 'unknown'})",
        _handoff_provenance_line(handoff_status, handoff_version, handoff_written_at),
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
    finding_lines = (
        _findings_section(finding_rows, include_evidence=include_evidence)
        if finding_rows
        else ["  - (none declared in handoff or dispatch)"]
    )
    coverage_lines = _coverage_gaps_section(coverage_gaps)
    next_steps_lines = _next_steps_section(next_steps)
    open_questions_lines = _open_questions_section(open_questions)
    if extras:
        open_questions_lines.extend(["- **Specialist observations:**", f"  {json.dumps(extras, ensure_ascii=False, sort_keys=True)}"])
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
        out.append(
            "- **Finding declarations:** "
            f"**Dispatch-declared findings:** {_finding_declaration_value(dispatch_finding_slugs)}; "
            f"**Handoff-declared findings:** {_finding_declaration_value(handoff_finding_slugs)}"
        )
        out.extend(findings_kept)
        if findings_dropped > 0:
            out.append(f"  - ... and {findings_dropped} more")
        out.extend(coverage_lines)
        out.extend(next_steps_lines)
        out.extend(open_questions_lines)
        out.extend(_artifacts_section(artifacts_kept, omitted_count=artifacts_dropped))
        out.extend(_runtime_issues_section(runtime_kept, omitted_count=runtime_dropped))
        out.append(recommended_line)
        out.append(credentials_line)
        return out

    composed = _compose(finding_lines, 0, artifact_states, runtime_issues, 0, 0)
    if max_lines == 0 or len(composed) <= max_lines:
        return _join_with_hard_cap(composed, max_lines)

    # First-pass trim: findings.
    overhead_no_findings = len(_compose([], len(finding_lines), artifact_states, runtime_issues, 0, 0))
    findings_budget = max(1, max_lines - (overhead_no_findings - 1))
    findings_kept, findings_dropped = _truncate_findings(finding_lines, findings_budget)
    composed = _compose(findings_kept, findings_dropped, artifact_states, runtime_issues, 0, 0)
    if len(composed) <= max_lines:
        return _join_with_hard_cap(composed, max_lines)

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
        return _join_with_hard_cap(composed, max_lines)

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
    return _join_with_hard_cap(composed, max_lines)


def _join_with_hard_cap(lines: list[str], max_lines: int) -> str:
    """Join renderer lines without letting embedded newlines defeat the cap."""
    physical_lines = "\n".join(contain_separators(line) for line in lines).splitlines()
    if max_lines == 0 or len(physical_lines) <= max_lines:
        return "\n".join(physical_lines)
    omitted = len(physical_lines) - max(0, max_lines - 1)
    marker = (
        f"... handoff truncated: {omitted} line(s) omitted; rerun "
        "render-handoff with --max-lines 0 for the complete recorded handoff"
    )
    if max_lines == 1:
        return marker
    return "\n".join([*physical_lines[: max_lines - 1], marker])


def _handoff_provenance_line(
    handoff_status: str, handoff_version: object, handoff_written_at: str
) -> str:
    """Render the handoff row's OWN identity: status, version, write time.

    This is what makes the "write the handoff, then render it" self-check able
    to fail. Both the version and the write timestamp advance on every accepted
    write, so a specialist that just wrote a handoff can confirm the write
    landed instead of reading a stale prior row as success. The wording names
    the timestamp as the HANDOFF write time so it is never confused with the
    ``Dispatched at`` line above, which does not move on a handoff write.
    """
    try:
        version = int(handoff_version)  # type: ignore[arg-type]
        version_text = f"v{version}"
    except (TypeError, ValueError):
        version_text = "v(unrecorded)"
    return (
        f"- **Handoff row:** {handoff_status or '(status unrecorded)'} "
        f"{version_text}, last written {handoff_written_at or '(unknown)'} "
        "(this is the handoff write time, NOT the dispatch time — if it did not "
        "advance, your write did not land)"
    )


def _normalise_finding_slugs(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(slug).strip() for slug in value if str(slug).strip()]


def _finding_declaration_value(slugs: list[str]) -> str:
    """Render a bounded source summary without defeating --max-lines."""
    if not slugs:
        return "(none declared)"
    preview_limit = 8
    preview = ", ".join(f"`{slug}`" for slug in slugs[:preview_limit])
    remaining = len(slugs) - preview_limit
    suffix = f" … and {remaining} more" if remaining > 0 else ""
    return f"{preview}{suffix}"


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


def _runtime_issues_section(rows: list, *, omitted_count: int = 0) -> list[str]:
    if not rows and not omitted_count:
        return []
    lines = ["- **Runtime issues:**"]
    if not rows:
        lines.append(f"  - ({omitted_count} recorded runtime issue(s) omitted)")
        return lines
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
    if omitted_count:
        lines.append(f"  - ... and {omitted_count} more runtime issue(s) omitted")
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


def _artifacts_section(
    artifact_states: list[tuple[str, str]], *, omitted_count: int = 0
) -> list[str]:
    """Working-artifact bullets with on-disk state and explicit omissions."""
    lines = ["- **Working artifacts:**"]
    if not artifact_states:
        lines.append(
            f"  - ({omitted_count} recorded artifact(s) omitted)"
            if omitted_count else "  - (none recorded)"
        )
        return lines
    for path, state in artifact_states:
        lines.append(f"  - `{path}` (state: {state})")
    if omitted_count:
        lines.append(f"  - ... and {omitted_count} more artifact(s) omitted")
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
