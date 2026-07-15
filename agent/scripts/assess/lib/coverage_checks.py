"""Reusable coverage / readiness checks shared by ``check-phase-readiness``.

Wave 6d (command consolidation, depth-gate §6) folded three standalone CLI
commands into the one phase-aware ``check-phase-readiness`` command. To lose
NOTHING in that consolidation, the reusable bodies of the deleted commands live
here as importable helpers:

  * ``check-coverage``        → :func:`render_surface_coverage` (surface-
    resolution gate over ``/coverage-readiness``).
  * ``check-scope-coverage``  → the per-scope-entry audit (:func:`build_scope_coverage_report`
    + :func:`build_redispatch_block` + the ``--by-host`` annotation helpers +
    all the C40 / ``--auto-redispatch`` machinery), plus the text renderers.
  * ``check-report-readiness`` → :func:`render_report_readiness` (terminal
    report gate over ``/report-readiness``).
  * ``check-intel-readiness`` → :func:`render_intel_readiness` (advisory intel-
    closure view; red engagements only).

The new command imports these and composes them per phase. The backend gates
(``coverage_readiness`` / ``report_readiness`` / ``per_host_coverage`` /
``depth_ledger`` / intel readiness) and their HTTP routes are UNCHANGED — this
module is CLI-side glue only.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from assess.lib.classify_buckets import BUCKET_SKILLS, classify_from_fields
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.scope import (
    classify_scope_entry,
    entry_matches_host,
    host_admitted,
    host_from_token,
    host_in_scope,
    host_is_vendor_saas,
    out_of_scope_entries,
    scope_entries,
)


# ===========================================================================
# surface-coverage — surface-resolution gate (former check-coverage body)
# ===========================================================================
def render_surface_coverage(readiness: Any) -> tuple[bool, list[str], list[str]]:
    """Render the surface-coverage gate from a ``/coverage-readiness`` payload.

    Returns ``(ready, ok_lines, blocker_lines)``. ``ready`` is the gate verdict;
    ``blocker_lines`` enumerate uncovered / partially-covered / high-risk-deferred
    surfaces (the old ``check-coverage`` stderr block) and ``ok_lines`` carry the
    success line. The caller decides exit code + stream.
    """
    if not isinstance(readiness, dict):
        return False, [], ["surface-coverage: unexpected response from backend"]

    unresolved = readiness.get("unresolved_surfaces") or []
    partially_covered = readiness.get("partially_covered_surfaces") or []
    blocked_deferred = readiness.get("high_risk_deferred_surfaces") or []

    if readiness.get("ready", False):
        return True, ["surface coverage: ok"], []

    blockers: list[str] = []
    if unresolved:
        blockers.append("Uncovered surfaces remain:")
        for item in unresolved:
            blockers.append(
                f"  - {item.get('surface_type')} | {item.get('target_descriptor')}"
            )
    if partially_covered:
        blockers.append("Partially covered surfaces need follow-up:")
        for item in partially_covered:
            blockers.append(
                f"  - {item.get('surface_type')} | {item.get('target_descriptor')} | "
                f"{item.get('followup_condition')}"
            )
    if blocked_deferred:
        blockers.append("High-risk surfaces cannot remain deferred:")
        for item in blocked_deferred:
            blockers.append(
                f"  - {item.get('surface_type')} | {item.get('target_descriptor')}"
            )
        blockers.append(
            "Resolve them as covered or not_applicable before finishing Test/Report."
        )
    return False, [], blockers


# ===========================================================================
# check-report-readiness — terminal report gate (old check_report_readiness.py)
# ===========================================================================
def _report_line(item: object) -> str:
    """Render a blocker/advisory dict into a single human line (kind/slug/detail)."""
    if not isinstance(item, dict):
        return ""
    slug = item.get("slug")
    slugs = item.get("slugs")
    detail = item.get("detail", "")
    prefix = f"{item.get('kind', 'item')}"
    if slug:
        prefix = f"{prefix} | {slug}"
    elif isinstance(slugs, list) and slugs:
        prefix = f"{prefix} | {', '.join(str(s) for s in slugs)}"
    return f"  - {prefix}: {detail}"


def render_report_readiness(readiness: Any) -> tuple[bool, list[str], list[str], list[str]]:
    """Render the report-readiness gate from a ``/report-readiness`` payload.

    Returns ``(ready, ok_lines, blocker_lines, advisory_lines)``. Advisories
    (L1-1/L1-8/S21) are surfaced loudly but never affect the exit code — only
    real blockers / not-ready cause a non-zero exit (preserved from the old
    ``check-report-readiness`` semantics).
    """
    if not isinstance(readiness, dict):
        return False, [], ["check-report-readiness: unexpected response from backend"], []

    advisories = [a for a in (readiness.get("advisories") or []) if isinstance(a, dict)]
    advisory_lines: list[str] = []
    if advisories:
        advisory_lines.append("Advisories (not blocking — disposition recommended):")
        for advisory in advisories:
            rendered = _report_line(advisory)
            if rendered:
                advisory_lines.append(rendered)

    if readiness.get("ready", False):
        return True, ["report readiness: ok"], [], advisory_lines

    blocker_lines = ["Final report blockers remain:"]
    for blocker in readiness.get("blockers") or []:
        rendered = _report_line(blocker)
        if rendered:
            blocker_lines.append(rendered)
    return False, [], blocker_lines, advisory_lines


# ===========================================================================
# check-intel-readiness — advisory intel-closure view (old check_intel_readiness.py)
# ===========================================================================
def render_intel_readiness(data: Any) -> tuple[bool, list[str]]:
    """Render the intel-closure advisory from a ``/intel/readiness`` payload.

    Returns ``(has_open_items, lines)``. ``has_open_items`` drives the old
    ``--strict`` exit (exit 1 when any open item is present). Blue / non-red
    engagements report not-applicable and never have open items. The lines are
    the same advisory block the old command printed.
    """
    if not isinstance(data, dict):
        return False, ["check-intel-readiness: unexpected response from backend"]

    if not data.get("applicable", True):
        return False, [
            "intel readiness: not applicable for engagement_type="
            f"{data.get('engagement_type', 'unknown')!r} (red engagements only)."
        ]

    open_high = data.get("open_high_cves") or []
    open_leads = data.get("open_leads") or []
    exploited_unlinked = data.get("exploited_unlinked_cves") or []
    dangling = data.get("dangling_links") or []
    total = len(open_high) + len(open_leads) + len(exploited_unlinked) + len(dangling)

    if total == 0:
        return False, ["intel readiness: ok — no open CVEs, leads, or dangling links"]

    lines = [f"Open intel needing a disposition ({total}):"]
    if open_high:
        lines.append(f"- open PoC-backed high CVEs ({len(open_high)}):")
        for row in open_high:
            lines.append(
                f"  - id={row.get('id')} {row.get('cve_id')} cvss {row.get('cvss_score')} "
                f"[{row.get('validation_status')}] {row.get('affected_component') or ''}".rstrip()
            )
    if exploited_unlinked:
        lines.append(f"- exploited CVEs with no linked finding ({len(exploited_unlinked)}):")
        for row in exploited_unlinked:
            lines.append(
                f"  - id={row.get('id')} {row.get('cve_id')} {row.get('affected_component') or ''}".rstrip()
            )
    if dangling:
        lines.append(f"- dangling linked_finding_slug references ({len(dangling)}):")
        for row in dangling:
            lines.append(
                f"  - id={row.get('id')} {row.get('cve_id')} → {row.get('linked_finding_slug')} "
                f"({row.get('reason')}: {row.get('workflow_status') or 'no such finding'})"
            )
    if open_leads:
        lines.append(f"- open leads ({len(open_leads)}):")
        for row in open_leads:
            lines.append(f"  - id={row.get('id')} [{row.get('lead_status')}] {row.get('title')}")
    lines.append(
        "\nDisposition by id: "
        "`vigil assess update-intel cve <id> --inline '{\"validation_status\": \"ruled_out\"}'` "
        "or `update-intel note <id> --inline '{\"lead_status\": \"resolved\"}'`."
    )
    return True, lines


def render_stage_audit(audit: Any) -> tuple[bool, list[str]]:
    """Render the recon-pipeline stage-completion audit (item 2.1 / P-1).

    Consumes the ``stage_audit`` block the backend folds into the
    ``/phase-readiness`` payload for the recon/collect pipeline phases. Returns
    ``(has_open_gaps, lines)`` — ``has_open_gaps`` drives the ``--strict`` exit
    (exit 1 when ≥1 expected stage timed out / produced partial results / never
    ran). Without ``--strict`` the block is a WARN/report only and the caller
    leaves the exit code untouched.

    A phase with no EXPECTED-STAGE checklist (``applicable=False``) renders
    nothing, so the caller can append unconditionally.
    """
    if not isinstance(audit, dict) or not audit.get("applicable", False):
        return False, []

    phase = str(audit.get("phase") or "")
    expected = [s for s in (audit.get("expected_stages") or [])]
    gaps = [g for g in (audit.get("gaps") or []) if isinstance(g, dict)]

    if not gaps:
        return False, [
            f"stage-completion audit ({phase} pipeline): ok — all "
            f"{len(expected)} expected stage(s) ran to completion"
        ]

    lines = [
        f"stage-completion audit ({phase} pipeline): {len(gaps)} open stage gap(s) "
        f"of {len(expected)} expected — re-run or accept-with-reason:"
    ]
    for gap in gaps:
        ids = [i for i in (gap.get("command_run_ids") or [])]
        ids_str = (
            f" [run(s) {', '.join('#' + str(i) for i in ids)}]" if ids else ""
        )
        disposition = str(gap.get("disposition") or "gap")
        verb = "never ran" if disposition == "never_ran" else disposition
        lines.append(
            f"  - {gap.get('stage')} ({gap.get('label')}): {verb}{ids_str}"
        )
    return True, lines


# ===========================================================================
# check-scope-coverage — per-scope-entry audit (old check_scope_coverage.py body)
# ===========================================================================

# Services count as "live" when the backend state is anything except
# `down`/`filtered`/`unreachable`. This denylist keeps the audit optimistic
# during backend schema evolution (new state values default to counting as live).
_NON_LIVE_SERVICE_STATES: frozenset[str] = frozenset({"down", "filtered", "unreachable"})


# Mirror of `state_manager.PER_HOST_OBJECTIVES`. Kept duplicated here to avoid
# importing backend modules into the CLI; the test asserts the lists agree.
_PER_HOST_OBJECTIVES: tuple[str, ...] = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "tech_fingerprint",
    "osint",
)


# Canonical specialist names referenced in dispatch hints below. Centralizing
# them keeps a future role-file rename from silently leaving stale references in
# the hint strings; the regression test asserts each value has a matching
# `agent/agents/<name>.md` file on disk.
_HINT_RECON_SPECIALIST = "recon-specialist"
_HINT_OSINT_ANALYST = "osint-analyst"


# Per-objective remediation hint. Operators read this when the gate WARNs so
# they know exactly what to dispatch (or what coverage_deferral to record).
_OBJECTIVE_DISPATCH_HINTS: dict[str, str] = {
    "waf_tier": (
        f"dispatch {_HINT_RECON_SPECIALIST} with skill web-recon (records "
        "intel_tech_components via wafw00f / httpx --tech-detect / whatweb), "
        "OR record `vigil assess agent decision --kind coverage_deferral "
        "--payload-json '{{\"host\": \"{host}\", \"deferred_objectives\": "
        "[\"waf_tier\"], \"reason\": \"...\"}}' --surfaced-to-user`"
    ),
    "service_inventory": (
        f"dispatch {_HINT_RECON_SPECIALIST} (records assessment_services / "
        "assessment_surfaces) or ingest endpoints via `vigil assess "
        "ingest-endpoints`, OR record a coverage_deferral for the host"
    ),
    "directory_fuzz": (
        f"dispatch {_HINT_RECON_SPECIALIST} with skill directory-fuzzing "
        "(records assessment_surfaces via record-surface), OR record a "
        "coverage_deferral with reason='brute-force forbidden by scope brief' "
        "if the program disallows directory brute-force"
    ),
    "tech_fingerprint": (
        f"dispatch {_HINT_RECON_SPECIALIST} with web-recon (any of whatweb / "
        "httpx -tech-detect / nuclei tech templates / nikto recording a "
        "tech-component intel row satisfies this), OR record a coverage_deferral"
    ),
    "osint": (
        f"dispatch {_HINT_OSINT_ANALYST} (records intel_tech_components, "
        "intel_people, intel_breach_records), OR record an engagement-level "
        "coverage_deferral if OSINT is explicitly out of scope"
    ),
}


# stage gap -> base role. enum is recon's job, collection is the
# surface-collector's, consumption is the vulnerability analyst's.
_STAGE_TO_ROLE: dict[str, str] = {
    "enum": "recon-specialist",
    "collection": "surface-collector",
    "consumption": "vulnerability-analyst",
}
_STAGE_PARALLEL_ROLE: dict[str, str] = {
    "enum": "source-analyzer",
}

# role -> default dispatch-mode (mirrors operator-core per-role defaults).
_ROLE_TO_MODE: dict[str, str] = {
    "recon-specialist": "hypothesis-driven",
    "source-analyzer": "item-iterating",
    "surface-collector": "item-iterating",
    "vulnerability-analyst": "item-iterating",
    "fuzzer": "variant-rotation",
}

# Fixed skills for the non-data-driven stages.
_ENUM_SKILLS: tuple[str, ...] = ("web-recon", "subdomain-enumeration")
_COLLECTION_SKILLS: tuple[str, ...] = ("surface-collection", "gau-triage")

# Generic / trust-delegation / environment buckets that don't map to a single
# testing skill (intentionally absent from BUCKET_SKILLS). When the dominant
# bucket is one of these, OR the pending items split roughly evenly across >= 3
# buckets, the recommendation degrades to a ranked shortlist flagged
# confidence=low rather than forcing one guess.
_AMBIGUOUS_BUCKETS: frozenset[str] = frozenset(
    {
        "interestingparams",
        "interestingext",
        "trust_surface",
        "debug_logic",
    }
)

# gap token (from _build_entry_report) -> stage name; ordered earliest-first.
_GAP_TO_STAGE: tuple[tuple[str, str], ...] = (
    ("no-enum", "enum"),
    ("no-collection", "collection"),
    ("pending-work-remains", "consumption"),
    ("work-stuck-processing-or-error", "consumption"),
    ("work-buffer-missing", "consumption"),
)

# A high-volume consumption gap (many untested pending items on one dominant
# bucket) is fuzzing-shaped: rotate payloads with the fuzzer.
_FUZZER_VOLUME_THRESHOLD = 100

# Dispatch lifecycle status values, mirrored from the backend literals. A
# dispatch is "active" (in-flight) only while ``in-progress``; the rest are
# terminal. Dedup only suppresses against ACTIVE dispatches.
_DISPATCH_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "aborted", "blocked"}
)
_DISPATCH_ACTIVE_STATUSES: frozenset[str] = frozenset({"in-progress"})


def _explicit_literal_scope_hosts(entries: list[dict[str, Any]]) -> set[str]:
    """Hosts authored explicitly in ``scope.json`` (bare host or URL entry).

    Wildcard entries are excluded — a vendor-SaaS subdomain under wildcard
    expansion is the genuinely ambiguous case the Vendor-SaaS scope checkpoint
    exists to resolve; an explicit literal is already the operator's in-scope
    decision.
    """
    return {
        entry["host"]
        for entry in entries
        if entry.get("entry_kind") in ("bare_host", "url") and entry.get("host")
    }


def _vendor_saas_decided_hosts(client: AssessmentClient) -> set[str]:
    """Hosts that already carry a vendor-SaaS ``scope_decision`` row.

    Uses ``list_all_decisions`` (paginated) so older decisions on long-running
    engagements are not silently dropped. A backend failure returns the empty
    set (the gate fires conservatively).
    """
    try:
        rows = client.list_all_decisions(kind="scope_decision")
    except AssessError:
        return set()
    decisions: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        host = host_from_token(str(payload.get("host") or payload.get("target") or ""))
        if host:
            decisions.add(host)
    return decisions


def _bucket_of_cluster_key(cluster_key: str) -> str:
    """Map a stored ``cluster_key`` to its gf bucket name, or ``""``."""
    key = (cluster_key or "").strip()
    if key.startswith("gf:"):
        return key[len("gf:"):]
    return ""


def _pending_buckets_for_host(
    client: AssessmentClient,
    entry: dict[str, Any],
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, int]:
    """Tally untested/unconsumed work-item buckets for a scope entry's host(s).

    Mirrors the consumption gate's definition (S8): a row is unconsumed when it
    is ``pending`` with no ``terminal_reason``, OR stuck in ``processing``, OR in
    ``error`` — in every case ``type != 'host_root'``. Reuses the stored
    ``cluster_key`` (``gf:<bucket>``) when present, re-classifying otherwise.
    Returns ``{bucket_name: count}`` summed across matching hosts. Reads the
    backend work buffer; an empty buffer yields ``{}``.
    """
    tally: dict[str, int] = {}
    for row in client.get_all_pages("work-items"):
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or "") == "host_root":
            continue
        status = str(row.get("status") or "")
        terminal_reason = str(row.get("terminal_reason") or "")
        if not (
            (status == "pending" and terminal_reason == "")
            or status == "processing"
            or status == "error"
        ):
            continue
        # Prefer the row's stored ``host`` column (lowercased hostname, no port)
        # over re-parsing the URL.
        host = str(row.get("host") or "")
        if not host or not entry_matches_host(entry, host) or host_in_scope(host, deny_entries):
            continue
        bucket = _bucket_of_cluster_key(str(row.get("cluster_key") or ""))
        if not bucket:
            assignment = classify_from_fields(
                case_type=str(row.get("type") or "unknown"),
                url_path=str(row.get("url_path") or ""),
                query_params=str(row.get("query_params") or "{}"),
                body_params=str(row.get("body_params") or "{}"),
                path_params=str(row.get("path_params") or "{}"),
            )
            bucket = _bucket_of_cluster_key(str(assignment.get("cluster_key") or ""))
        tally[bucket] = tally.get(bucket, 0) + 1
    return tally


def _skill_resolves(skills_root: Path | None, name: str) -> bool:
    """True when ``agent/skills/<name>/SKILL.md`` exists on disk.

    A ``None``/missing skills root means we cannot verify — treat as resolving.
    """
    if skills_root is None or not skills_root.is_dir():
        return True
    return (skills_root / name / "SKILL.md").is_file()


def _validate_skills(
    skills_root: Path | None,
    names: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Split ``names`` into (resolved, dropped) by on-disk SKILL.md presence."""
    resolved: list[str] = []
    dropped: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        if _skill_resolves(skills_root, name):
            resolved.append(name)
        else:
            dropped.append(name)
    return resolved, dropped


def _agent_skills_root_for_recommendations() -> Path | None:
    """Resolve ``agent/skills`` for skill validation, reusing contracts' logic."""
    try:
        from assess.lib.contracts import _agent_skills_root
    except Exception:
        return None
    try:
        root = _agent_skills_root()
    except Exception:
        return None
    return root if root.is_dir() else None


def _consumption_skill_selection(
    bucket_tally: dict[str, int],
) -> dict[str, Any]:
    """Pick role + skills + confidence for a consumption gap from the tally."""
    pending_total = sum(bucket_tally.values())
    mapped = sorted(
        (
            (bucket, count)
            for bucket, count in bucket_tally.items()
            if bucket in BUCKET_SKILLS
        ),
        key=lambda kv: (-kv[1], kv[0]),
    )

    if not mapped:
        return {
            "role": "vulnerability-analyst",
            "skills": (),
            "confidence": "low",
            "dominant_bucket": None,
            "dominant_count": 0,
            "pending_total": pending_total,
            "reason": (
                "no pending item maps to a recognizable vuln class "
                "(all unbucketed/generic) — triage the buffer or pick a skill "
                "by hand"
            ),
        }

    top_bucket, top_count = mapped[0]
    distinct_mapped = len(mapped)
    second_count = mapped[1][1] if distinct_mapped > 1 else 0

    split_evenly = distinct_mapped >= 3 and second_count * 2 >= top_count

    if split_evenly:
        shortlist: list[str] = []
        for bucket, _ in mapped:
            for skill in BUCKET_SKILLS[bucket]:
                if skill not in shortlist:
                    shortlist.append(skill)
                    break
        return {
            "role": "vulnerability-analyst",
            "skills": tuple(shortlist),
            "confidence": "low",
            "dominant_bucket": None,
            "dominant_count": top_count,
            "pending_total": pending_total,
            "reason": (
                "pending items split roughly evenly across "
                f"{distinct_mapped} buckets ("
                + ", ".join(f"{b}:{c}" for b, c in mapped)
                + ") — ranked shortlist, pick per surface"
            ),
        }

    role = "vulnerability-analyst"
    if top_count >= _FUZZER_VOLUME_THRESHOLD:
        role = "fuzzer"
    return {
        "role": role,
        "skills": tuple(BUCKET_SKILLS[top_bucket]),
        "confidence": "high",
        "dominant_bucket": top_bucket,
        "dominant_count": top_count,
        "pending_total": pending_total,
        "reason": (
            f"dominant pending bucket '{top_bucket}' ({top_count} untested "
            f"item(s))"
            + (
                f"; high volume (>= {_FUZZER_VOLUME_THRESHOLD}) -> fuzzer"
                if role == "fuzzer"
                else ""
            )
        ),
    }


def _ambiguous_dominant(bucket_tally: dict[str, int]) -> bool:
    """True when the single largest bucket is a generic/ambiguous one."""
    if not bucket_tally:
        return False
    ranked = sorted(bucket_tally.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[0][0] in _AMBIGUOUS_BUCKETS


def _gap_stage_for_entry(entry: dict[str, Any]) -> str | None:
    """Return the earliest unmet stage for an entry, or ``None`` if clean."""
    gaps = set(entry.get("gaps", []))
    for token, stage in _GAP_TO_STAGE:
        if token in gaps:
            return stage
    return None


def _build_recommendation(
    *,
    entry: dict[str, Any],
    stage: str,
    client: AssessmentClient,
    skills_root: Path | None,
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a single recommendation dict for a failing scope entry+stage."""
    host = entry["host"]
    dropped_skills: list[str] = []

    if stage == "consumption":
        bucket_tally = _pending_buckets_for_host(client, entry, deny_entries)
        selection = _consumption_skill_selection(bucket_tally)
        if selection["confidence"] == "high" and _ambiguous_dominant(bucket_tally):
            shortlist: list[str] = []
            for bucket, _ in sorted(
                ((b, c) for b, c in bucket_tally.items() if b in BUCKET_SKILLS),
                key=lambda kv: (-kv[1], kv[0]),
            ):
                for skill in BUCKET_SKILLS[bucket]:
                    if skill not in shortlist:
                        shortlist.append(skill)
                        break
            selection = {
                **selection,
                "skills": tuple(shortlist),
                "confidence": "low",
                "dominant_bucket": None,
                "reason": (
                    "dominant pending bucket is generic/ambiguous "
                    f"({sorted(bucket_tally.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]})"
                    " — ranked shortlist, pick per surface"
                ),
            }
        role = selection["role"]
        raw_skills = selection["skills"]
        confidence = selection["confidence"]
        dominant_bucket = selection["dominant_bucket"]
        pending_total = selection["pending_total"]
        reason = selection["reason"]
    else:
        role = _STAGE_TO_ROLE[stage]
        raw_skills = _ENUM_SKILLS if stage == "enum" else _COLLECTION_SKILLS
        confidence = "high"
        dominant_bucket = None
        pending_total = int(entry.get("work_queued", {}).get("pending", 0))
        reason = (
            "no enumeration evidence under this entry"
            if stage == "enum"
            else "no collection evidence (surfaces/work_items) under this entry"
        )

    skills, dropped_skills = _validate_skills(skills_root, tuple(raw_skills))
    mode = _ROLE_TO_MODE.get(role, "item-iterating")
    parallel_role = _STAGE_PARALLEL_ROLE.get(stage)

    command = _format_start_command(role=role, scope_host=host, mode=mode, skills=skills)
    task_skeleton = _format_task_skeleton(
        host=host,
        stage=stage,
        dominant_bucket=dominant_bucket,
        pending_total=pending_total,
        confidence=confidence,
    )

    return {
        "scope_entry": entry["scope_entry"],
        "scope_host": host,
        "stage": stage,
        "role": role,
        "parallel_role": parallel_role,
        "dispatch_mode": mode,
        "skills": skills,
        "dropped_skills": dropped_skills,
        "confidence": confidence,
        "dominant_bucket": dominant_bucket,
        "pending_count": pending_total,
        "reason": reason,
        "command": command,
        "task_skeleton": task_skeleton,
    }


def _format_start_command(
    *,
    role: str,
    scope_host: str,
    mode: str,
    skills: list[str],
) -> str:
    parts = [
        "vigil assess agent start",
        f"--role {role}",
        f"--scope-host {scope_host}",
        f"--dispatch-mode {mode}",
    ]
    if skills:
        parts.append(f"--skills {','.join(skills)}")
    return " ".join(parts)


def _format_task_skeleton(
    *,
    host: str,
    stage: str,
    dominant_bucket: str | None,
    pending_total: int,
    confidence: str,
) -> str:
    if stage == "enum":
        return (
            f"Enumerate {host}: no enumeration evidence recorded. Establish live "
            "services / surfaces so collection and consumption have real data."
        )
    if stage == "collection":
        return (
            f"Collect URLs/surfaces for {host}: enumeration produced hosts but no "
            "collection evidence (surfaces/work_items). Populate the work buffer."
        )
    if dominant_bucket:
        return (
            f"Test {host}: {pending_total} untested pending item(s), dominant "
            f"cluster '{dominant_bucket}'. Validate the surface, produce durable "
            "evidence, defer the rest with a reason."
        )
    return (
        f"Test {host}: {pending_total} untested pending item(s) with no single "
        f"dominant vuln class (confidence={confidence}). Triage the shortlisted "
        "skills against the actual surfaces before committing."
    )


def build_redispatch_block(
    *,
    entries: list[dict[str, Any]],
    client: AssessmentClient,
    skills_root: Path | None,
    prior_dispatches: list[dict[str, Any]] | None,
    dedup_degraded: bool,
    max_recommendations: int,
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Assemble the full --auto-redispatch recommendation block."""
    prior_index = _index_prior_dispatches(prior_dispatches or [])
    recommendations: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    for entry in entries:
        stage = _gap_stage_for_entry(entry)
        if stage is None:
            continue
        rec = _build_recommendation(
            entry=entry, stage=stage, client=client, skills_root=skills_root,
            deny_entries=deny_entries,
        )
        key = (rec["role"], rec["scope_host"])
        if key in prior_index:
            suppressed.append(
                {
                    "scope_host": rec["scope_host"],
                    "role": rec["role"],
                    "stage": rec["stage"],
                    "reason": (
                        f"prior dispatch already exists for role={rec['role']} "
                        f"scope_host={rec['scope_host']} "
                        f"(agent_id={prior_index[key]})"
                    ),
                }
            )
            continue
        recommendations.append(rec)

    overflow = 0
    cap = max(0, int(max_recommendations)) if max_recommendations is not None else 10
    if max_recommendations is not None and len(recommendations) > cap:
        overflow = len(recommendations) - cap
        recommendations = recommendations[:cap]

    notes: list[str] = []
    if dedup_degraded:
        notes.append(
            "dedup degraded: prior-dispatch fetch failed; recommendations are "
            "NOT de-duplicated against existing dispatches"
        )
    if overflow:
        notes.append(
            f"{overflow} more failing entr(y/ies) past --max-recommendations "
            f"({cap}) not shown"
        )
    dropped_any = sorted(
        {s for rec in recommendations for s in rec.get("dropped_skills", [])}
    )
    if dropped_any:
        notes.append(
            "dropped non-resolving skill(s) (no SKILL.md on disk): "
            + ", ".join(dropped_any)
        )

    return {
        "recommendations": recommendations,
        "suppressed": suppressed,
        "overflow": overflow,
        "notes": notes,
    }


def _index_prior_dispatches(rows: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    """Map ``(role, scope_host) -> agent_id`` for prior dispatch rows."""
    index: dict[tuple[str, str], str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        role = str(row.get("agent_role") or row.get("role") or "").strip()
        scope_host = host_from_token(str(row.get("scope_host") or ""))
        if not role or not scope_host:
            continue
        key = (role, scope_host)
        if key not in index:
            index[key] = str(row.get("agent_id") or row.get("id") or "")
    return index


def fetch_prior_dispatches(
    client: AssessmentClient,
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch ACTIVE prior dispatches for dedup. Returns ``(rows, degraded)``."""
    try:
        rows = client.list_dispatches(limit=1000, status="in-progress")
    except AssessError:
        return [], True
    rows = rows if isinstance(rows, list) else []
    active = [
        row
        for row in rows
        if not (
            isinstance(row, dict)
            and str(row.get("status") or "").strip().lower()
            in _DISPATCH_TERMINAL_STATUSES
        )
    ]
    return active, False


# ---------------------------------------------------------------------------
# Host extraction helpers
# ---------------------------------------------------------------------------
def _endpoint_host(endpoint: str) -> str:
    """Return the lowercased host portion of a service endpoint / surface
    target descriptor."""
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    first = raw.split()[0]
    if "://" in first:
        return host_from_token(first)
    ipv6_host = _ipv6_endpoint_host(first)
    if ipv6_host:
        return ipv6_host
    return host_from_token(first)


def _ipv6_endpoint_host(endpoint: str) -> str:
    first = endpoint.strip().strip("'\"<>()").rstrip(",;").rstrip(".").lower()
    if not first or first.count(":") < 2:
        return ""
    if first.startswith("["):
        return host_from_token(first)
    host, _, port = first.rpartition(":")
    if port.isdigit() and _ip_literal(host):
        return _ip_literal(host)
    return _ip_literal(first)


def _ip_literal(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Per-entry roll-up
# ---------------------------------------------------------------------------
def _build_entry_report(
    *,
    entry: dict[str, Any],
    services: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    work_by_host: dict[str, dict[str, int]],
    scope_metadata: dict[str, dict[str, Any]],
    required_stage: str | None,
    buffer_present: bool = True,
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, Any]:
    live_hosts_set: set[str] = set()
    live_host_samples: list[str] = []
    total_services = 0

    for svc in services:
        endpoint_host = _endpoint_host(str(svc.get("endpoint") or ""))
        if not entry_matches_host(entry, endpoint_host) or host_in_scope(endpoint_host, deny_entries):
            continue
        total_services += 1
        state = str(svc.get("state") or "").lower()
        if state in _NON_LIVE_SERVICE_STATES:
            continue
        if endpoint_host and endpoint_host not in live_hosts_set:
            live_hosts_set.add(endpoint_host)
            if len(live_host_samples) < 10:
                live_host_samples.append(endpoint_host)

    surface_hosts: set[str] = set()
    surfaces_count = 0
    for surface in surfaces:
        descriptor = str(surface.get("target_descriptor") or "")
        host = _endpoint_host(descriptor)
        if not entry_matches_host(entry, host) or host_in_scope(host, deny_entries):
            continue
        surfaces_count += 1
        if host:
            surface_hosts.add(host)

    host_work = (
        _aggregate_matching_work(entry, work_by_host, deny_entries)
        if entry["entry_kind"] in ("wildcard", "cidr")
        else work_by_host.get(entry["host"], {})
    )
    work_queued = {
        "pending": int(host_work.get("pending", 0)),
        "processing": int(host_work.get("processing", 0)),
        "done": int(host_work.get("done", 0)),
        "skipped": int(host_work.get("skipped", 0)),
        "error": int(host_work.get("error", 0)),
        "pending_without_terminal_reason": int(host_work.get("pending_without_terminal_reason", 0)),
    }
    work_total = sum(
        work_queued[key] for key in ("pending", "processing", "done", "skipped", "error")
    )

    enum_evidence: list[str] = []
    if entry["entry_kind"] in ("bare_host", "url"):
        enum_evidence.append("bare_host")
    if live_hosts_set:
        enum_evidence.append("services")
    if surface_hosts:
        enum_evidence.append("surfaces")
    if work_total > 0:
        enum_evidence.append("work_items")
    enum_attempted = bool(enum_evidence)

    collection_evidence: list[str] = []
    if surfaces_count > 0:
        collection_evidence.append("surfaces")
    if work_total > 0:
        collection_evidence.append("work_items")
    collection_attempted = bool(collection_evidence)

    metadata = scope_metadata.get(_scope_metadata_lookup_key(entry), {})
    entry_status = str(metadata.get("status") or "").lower()

    gaps: list[str] = []
    if entry["entry_kind"] == "wildcard" and enum_attempted and not live_hosts_set:
        gaps.append("no-live-hosts")
    if required_stage is None:
        pass
    elif required_stage == "enum":
        if not enum_attempted:
            gaps.append("no-enum")
    elif required_stage == "collection":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
    elif required_stage == "consumption":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
        if not _consumption_satisfied(
            work_queued,
            entry_status,
            buffer_present=buffer_present,
            has_surfaces=surfaces_count > 0,
        ):
            if entry_status != "deferred":
                if not buffer_present and surfaces_count > 0:
                    gaps.append("work-buffer-missing")
                elif work_queued.get("processing", 0) > 0 or work_queued.get("error", 0) > 0:
                    gaps.append("work-stuck-processing-or-error")
                else:
                    gaps.append("pending-work-remains")
            else:
                gaps.append("pending-work-remains")

    return {
        "scope_entry": entry["scope_entry"],
        "entry_kind": entry["entry_kind"],
        "host": entry["host"],
        "enum_attempted": enum_attempted,
        "enum_evidence": enum_evidence,
        "total_services": total_services,
        "live_hosts": len(live_hosts_set),
        "live_host_samples": live_host_samples,
        "surfaces_count": surfaces_count,
        "collection_attempted": collection_attempted,
        "collection_evidence": collection_evidence,
        "work_queued": work_queued,
        "status": entry_status or None,
        "gaps": gaps,
    }


def _aggregate_matching_work(
    entry: dict[str, Any],
    work_by_host: dict[str, dict[str, int]],
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, int]:
    """Sum per-host work counts for an entry that matches many hosts."""
    aggregate: dict[str, int] = {}
    for host, counts in work_by_host.items():
        if not entry_matches_host(entry, host) or host_in_scope(host, deny_entries):
            continue
        for key, val in counts.items():
            aggregate[key] = aggregate.get(key, 0) + int(val)
    return aggregate


def _consumption_satisfied(
    work_queued: dict[str, int],
    entry_status: str,
    *,
    buffer_present: bool = True,
    has_surfaces: bool = False,
) -> bool:
    """Return True when the consumption gate is satisfied.

    S8 — stuck (``processing``/``error``) work is NOT consumed. S9 — a missing
    work buffer with real surfaces is missing/lost work, NOT a silent pass.
    A ``status=deferred`` scope entry is a valid terminal state.
    """
    if entry_status == "deferred":
        return True
    if not buffer_present and has_surfaces:
        return False
    if int(work_queued.get("processing", 0)) > 0:
        return False
    if int(work_queued.get("error", 0)) > 0:
        return False
    if int(work_queued.get("pending", 0)) == 0:
        return True
    if int(work_queued.get("pending_without_terminal_reason", 0)) == 0:
        return True
    return False


# ---------------------------------------------------------------------------
# scope.json metadata helpers
# ---------------------------------------------------------------------------
def _extract_scope_metadata(scope_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Parse optional per-host status metadata from scope.json."""
    metadata: dict[str, dict[str, Any]] = {}
    raw_map = scope_data.get("host_metadata")
    if isinstance(raw_map, dict):
        for host, info in raw_map.items():
            if isinstance(host, str) and isinstance(info, dict):
                normalized_key = _normalize_scope_metadata_key(host)
                if normalized_key:
                    metadata[normalized_key] = dict(info)

    raw_deferred = scope_data.get("deferred_hosts")
    if isinstance(raw_deferred, list):
        for host in raw_deferred:
            if isinstance(host, str):
                normalized_key = _normalize_scope_metadata_key(host)
                if not normalized_key:
                    continue
                bucket = metadata.setdefault(normalized_key, {})
                if "status" not in bucket:
                    bucket["status"] = "deferred"
    return metadata


def _normalize_scope_metadata_key(raw: str) -> str:
    entry = classify_scope_entry(raw)
    if entry is None:
        return ""
    return _scope_metadata_lookup_key(entry)


def _scope_metadata_lookup_key(entry: dict[str, Any]) -> str:
    if entry["entry_kind"] == "wildcard":
        return f"wildcard:{entry['host']}"
    return f"host:{entry['host']}"


# ---------------------------------------------------------------------------
# backend work buffer
# ---------------------------------------------------------------------------
def _load_work_items_by_host(client: AssessmentClient) -> dict[str, dict[str, int]]:
    """Return a ``{host: {status: count, ...}}`` rollup from the backend work buffer.

    Tracks ``pending_without_terminal_reason`` so the consumption gate can
    distinguish "really pending" from "deferred by work-buffer reclassify". ``host_root``
    crawl seeds are excluded from that count. An empty buffer yields an empty map.
    """
    agg: dict[str, dict[str, int]] = {}
    for row in client.get_all_pages("work-items"):
        if not isinstance(row, dict):
            continue
        # Prefer the row's stored ``host`` column over re-parsing the URL.
        host = str(row.get("host") or "")
        if not host:
            continue
        status = str(row.get("status") or "")
        bucket = agg.setdefault(host, {})
        bucket[status] = bucket.get(status, 0) + 1
        if (
            status == "pending"
            and str(row.get("terminal_reason") or "") == ""
            and str(row.get("type") or "") != "host_root"
        ):
            bucket["pending_without_terminal_reason"] = (
                bucket.get("pending_without_terminal_reason", 0) + 1
            )
    return agg


# ---------------------------------------------------------------------------
# W2 — per-host route stats for the coverage ledger
# ---------------------------------------------------------------------------
# A "route" is a distinct LIVE ``url_path`` for the host. "Live" is a BLUNT
# heuristic: a row whose ``live_status`` ledger stamp begins with ``live`` (the
# dispatch-time liveness stamp, e.g. ``live@9m``), OR whose ``response_status``
# is in a live HTTP band (2xx/3xx, or an auth/method-gated 401/403/405 — the
# route still EXISTS and answers). ``host_root`` crawl seeds are not routes.
_LIVE_RESPONSE_EXTRA: frozenset[int] = frozenset({401, 403, 405})

# url_path fragments that flag a high-value API / auth / GraphQL surface. The
# ledger's real_app OR-inclusion uses these so a few-path crown-jewel
# microservice (UNDER the route threshold) is still treated as a real app.
_API_PATH_TOKENS: tuple[str, ...] = (
    "/api/", "/api.", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql",
    "/swagger", "/openapi", "/oauth", "/jsonrpc", "/.well-known/",
)
_API_PATH_SUFFIXES: tuple[str, ...] = (".json", "/api", "/graphql", "/v1", "/v2", "/v3")
_AUTH_PATH_TOKENS: tuple[str, ...] = (
    "/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso", "/saml",
    "/oidc", "/session", "/logout", "/register", "/signup", "/password",
    "/mfa", "/2fa", "/token", "/authorize",
)
_GRAPHQL_PATH_TOKENS: tuple[str, ...] = ("/graphql", "/gql", "/graphiql")


def _path_matches(path: str, tokens: tuple[str, ...], suffixes: tuple[str, ...] = ()) -> bool:
    low = (path or "").lower()
    if not low:
        return False
    if any(tok in low for tok in tokens):
        return True
    return any(low.endswith(suf) for suf in suffixes)


def _response_is_live(response_status: Any) -> bool:
    if not isinstance(response_status, int):
        return False
    if 200 <= response_status < 400:
        return True
    return response_status in _LIVE_RESPONSE_EXTRA


def load_route_stats_by_host(client: AssessmentClient) -> dict[str, dict[str, Any]]:
    """Return ``{host: {live_routes, total_routes, api_like, auth_like,
    graphql_like}}`` from the backend work buffer.

    Mirrors :func:`_load_work_items_by_host` (same stored-``host`` grouping) but
    counts DISTINCT ``url_path`` per host instead of status rows, and flags
    API/auth/GraphQL surfaces for the ledger's real_app OR-inclusion. An empty
    buffer yields an empty map.
    """
    acc: dict[str, dict[str, Any]] = {}
    for row in client.get_all_pages("work-items"):
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or "").lower() == "host_root":
            continue
        path = str(row.get("url_path") or "").strip()
        if not path:
            continue
        # Prefer the row's stored ``host`` column over re-parsing the URL.
        host = str(row.get("host") or "")
        if not host:
            continue
        response_status = row.get("response_status")
        live_status = str(row.get("live_status") or "")
        bucket = acc.setdefault(
            host,
            {
                "_live_paths": set(),
                "_all_paths": set(),
                "api_like": False,
                "auth_like": False,
                "graphql_like": False,
            },
        )
        bucket["_all_paths"].add(path)
        if live_status.strip().lower().startswith("live") or _response_is_live(response_status):
            bucket["_live_paths"].add(path)
        if _path_matches(path, _API_PATH_TOKENS, _API_PATH_SUFFIXES):
            bucket["api_like"] = True
        if _path_matches(path, _AUTH_PATH_TOKENS):
            bucket["auth_like"] = True
        if _path_matches(path, _GRAPHQL_PATH_TOKENS):
            bucket["graphql_like"] = True

    return {
        host: {
            "live_routes": len(bucket["_live_paths"]),
            "total_routes": len(bucket["_all_paths"]),
            "api_like": bucket["api_like"],
            "auth_like": bucket["auth_like"],
            "graphql_like": bucket["graphql_like"],
        }
        for host, bucket in acc.items()
    }


# ---------------------------------------------------------------------------
# Overall gate and rendering
# ---------------------------------------------------------------------------
def _vendor_saas_hosts_pending_decision(
    *,
    services: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    work_by_host: dict[str, dict[str, int]],
    decided_hosts: set[str],
) -> list[tuple[str, str]]:
    """Return ``[(host, vendor), ...]`` for vendor-SaaS hosts lacking a decision."""
    seen: dict[str, str] = {}
    for svc in services:
        host = _endpoint_host(str(svc.get("endpoint") or ""))
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    for surface in surfaces:
        host = _endpoint_host(str(surface.get("target_descriptor") or ""))
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    for host in work_by_host.keys():
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    return sorted(seen.items())


def _collect_overall_gaps(entries: list[dict[str, Any]], required_stage: str | None) -> list[str]:
    if required_stage is None:
        return []
    messages: list[str] = []
    for entry in entries:
        stage_gaps = [g for g in entry.get("gaps", []) if g != "no-live-hosts"]
        if not stage_gaps:
            continue
        for gap in stage_gaps:
            messages.append(f"scope-entry: {entry['scope_entry']} — {gap}")
    return messages


def build_scope_coverage_report(
    *,
    engagement_key: str,
    scope_data: dict[str, Any],
    services: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    work_by_host: dict[str, dict[str, int]],
    decided_hosts: set[str],
    required_stage: str | None,
    buffer_present: bool,
    strict_vendor_saas: bool,
) -> dict[str, Any]:
    """Build the per-scope-entry coverage report (old check-scope-coverage core).

    The report dict is the same shape the old command emitted under ``--json``
    (minus the ``per_host_coverage`` / ``redispatch`` sections, which the caller
    attaches). ``ready`` is the stage-gate verdict.
    """
    raw_hosts = scope_data.get("hosts") or []
    entries = [classify_scope_entry(h) for h in raw_hosts if isinstance(h, str) and h.strip()]
    entries = [e for e in entries if e is not None]
    # OOS carve-outs must not be counted toward the in-scope wildcard that would
    # otherwise match them — else an out-of-scope host inflates live/service/work
    # tallies and can help satisfy a stage gate.
    deny_entries = out_of_scope_entries(scope_data)

    scope_metadata = _extract_scope_metadata(scope_data)

    report_entries: list[dict[str, Any]] = []
    for entry in entries:
        report_entries.append(
            _build_entry_report(
                entry=entry,
                services=services,
                surfaces=surfaces,
                work_by_host=work_by_host,
                scope_metadata=scope_metadata,
                required_stage=required_stage,
                buffer_present=buffer_present,
                deny_entries=deny_entries,
            )
        )

    explicit_literal_hosts = _explicit_literal_scope_hosts(entries)
    vendor_saas_pending = _vendor_saas_hosts_pending_decision(
        services=services,
        surfaces=surfaces,
        work_by_host=work_by_host,
        decided_hosts=decided_hosts | explicit_literal_hosts,
    )

    overall_gaps = _collect_overall_gaps(report_entries, required_stage)
    if vendor_saas_pending and required_stage is not None and strict_vendor_saas:
        for host, vendor in vendor_saas_pending:
            overall_gaps.append(
                f"vendor-saas: {host} (vendor={vendor}) has no scope_decision recorded "
                f"(record via `vigil assess agent decision --kind scope_decision --host {host} --vendor {vendor} --choice ...`)"
            )
    ready = not overall_gaps

    return {
        "engagement_key": engagement_key,
        "required_stage": required_stage,
        "entries": report_entries,
        "overall_gaps": overall_gaps,
        "vendor_saas_pending_decision": [
            {"host": host, "vendor": vendor} for host, vendor in vendor_saas_pending
        ],
        "strict_vendor_saas": strict_vendor_saas,
        "ready": ready,
        "explicit_literal_hosts": sorted(explicit_literal_hosts),
    }


def render_scope_coverage_text(report: dict[str, Any], *, verbose: bool) -> list[str]:
    """Render the per-scope-entry report as text lines (old _render_text)."""
    lines: list[str] = []
    entries = report["entries"]
    ready = report["ready"]
    stage = report["required_stage"]
    header = f"scope-coverage: {'ok' if ready else 'blocked'}"
    if stage:
        header = f"{header} (stage={stage})"
    lines.append(header)
    if not entries:
        lines.append("  (no scope entries in scope.json `hosts`)")
        return lines

    if not verbose and ready:
        for entry in entries:
            live = entry["live_hosts"]
            samples = ", ".join(entry["live_host_samples"][:3]) if entry["live_host_samples"] else "-"
            lines.append(
                f"  - {entry['scope_entry']} [{entry['entry_kind']}] live={live} "
                f"surfaces={entry['surfaces_count']} "
                f"enum={'y' if entry['enum_attempted'] else 'n'} "
                f"collect={'y' if entry['collection_attempted'] else 'n'} "
                f"pending={entry['work_queued']['pending']} samples={samples}"
            )
        return lines

    for entry in entries:
        lines.append(f"  - {entry['scope_entry']} [{entry['entry_kind']}] host={entry['host']}")
        lines.append(f"      enum: attempted={entry['enum_attempted']} evidence={entry['enum_evidence']}")
        lines.append(
            f"      live_hosts={entry['live_hosts']} total_services={entry['total_services']} samples={entry['live_host_samples']}"
        )
        lines.append(
            f"      collection: attempted={entry['collection_attempted']} evidence={entry['collection_evidence']} surfaces={entry['surfaces_count']}"
        )
        lines.append(f"      work_queued={entry['work_queued']}")
        if entry.get("status"):
            lines.append(f"      status={entry['status']}")
        if entry["gaps"]:
            lines.append(f"      gaps={entry['gaps']}")

    if report["overall_gaps"]:
        lines.append("gaps:")
        for msg in report["overall_gaps"]:
            lines.append(f"  - {msg}")

    vendor_saas_pending = report.get("vendor_saas_pending_decision") or []
    if vendor_saas_pending:
        lines.append("vendor-saas-pending-decision:")
        for row in vendor_saas_pending:
            lines.append(
                f"  - {row['host']} (vendor={row['vendor']}) — record a "
                f"scope_decision via `vigil assess agent decision "
                f"--kind scope_decision --host {row['host']} --vendor {row['vendor']} "
                f"--choice ...` before recon dispatch"
            )
    return lines


# ---------------------------------------------------------------------------
# C40 — per-host outcome rendering helpers
# ---------------------------------------------------------------------------
def annotate_by_host_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize the backend per-host payload into a stable rendering shape."""
    objectives_from_payload = payload.get("objectives") if isinstance(payload, dict) else None
    if not isinstance(objectives_from_payload, list) or not objectives_from_payload:
        objectives = list(_PER_HOST_OBJECTIVES)
    else:
        objectives = [str(name) for name in objectives_from_payload if isinstance(name, str)]

    raw_hosts = payload.get("hosts") if isinstance(payload, dict) else None
    hosts: list[dict[str, Any]] = []
    if isinstance(raw_hosts, list):
        for row in raw_hosts:
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or "").strip().lower()
            if not host:
                continue
            outcomes_payload = row.get("outcomes")
            outcomes: dict[str, dict[str, Any]] = {}
            for name in objectives:
                cell = (
                    outcomes_payload.get(name)
                    if isinstance(outcomes_payload, dict)
                    else None
                )
                if not isinstance(cell, dict):
                    cell = {"met": False, "evidence": [], "deferred": False}
                outcomes[name] = {
                    "met": bool(cell.get("met")),
                    "evidence": list(cell.get("evidence") or []),
                    "deferred": bool(cell.get("deferred")),
                }
            unmet = [
                name
                for name in objectives
                if not outcomes[name]["met"] and not outcomes[name]["deferred"]
            ]
            deferred_objectives = sorted(
                {name for name in objectives if outcomes[name]["deferred"]}
            )
            hosts.append(
                {
                    "host": host,
                    "outcomes": outcomes,
                    "unmet_objectives": unmet,
                    "deferred_objectives": deferred_objectives,
                    "deferrals": row.get("deferrals") or [],
                }
            )
    engagement_signals = (
        payload.get("engagement_signals") if isinstance(payload, dict) else None
    )
    return {
        "objectives": objectives,
        "hosts": hosts,
        "engagement_signals": engagement_signals if isinstance(engagement_signals, dict) else {},
    }


def filter_to_scope_literals(
    section: dict[str, Any],
    scope_literals: set[str],
) -> dict[str, Any]:
    """FU1 — fold wildcard-discovered hosts into a summary row."""
    if not scope_literals:
        return section

    literal_hosts: list[dict[str, Any]] = []
    discovered_hosts: list[dict[str, Any]] = []
    for row in section.get("hosts", []):
        host = str(row.get("host", "")).strip().lower()
        if host in scope_literals:
            literal_hosts.append(row)
        else:
            discovered_hosts.append(row)

    if not discovered_hosts:
        return section

    objectives = section.get("objectives", list(_PER_HOST_OBJECTIVES))
    unmet_counter: dict[str, int] = {obj: 0 for obj in objectives}
    hosts_with_unmet = 0
    hosts_with_deferral = 0
    for row in discovered_hosts:
        if row.get("unmet_objectives"):
            hosts_with_unmet += 1
        if row.get("deferrals"):
            hosts_with_deferral += 1
        for objective in row.get("unmet_objectives", []):
            unmet_counter[objective] = unmet_counter.get(objective, 0) + 1

    top_unmet = sorted(
        (
            (objective, count)
            for objective, count in unmet_counter.items()
            if count > 0
        ),
        key=lambda kv: (-kv[1], kv[0]),
    )[:3]

    summary = {
        "discovered_count": len(discovered_hosts),
        "hosts_with_unmet_count": hosts_with_unmet,
        "hosts_with_deferral_count": hosts_with_deferral,
        "top_unmet_objectives": [
            {"objective": objective, "host_count": count}
            for objective, count in top_unmet
        ],
    }
    return {
        **section,
        "hosts": literal_hosts,
        "discovered_summary": summary,
    }


def per_host_warning_lines(section: dict[str, Any]) -> list[str]:
    """Build human-readable per-objective warning lines."""
    warnings: list[str] = []
    for row in section.get("hosts", []):
        host = row.get("host", "")
        for objective in row.get("unmet_objectives", []):
            hint = _OBJECTIVE_DISPATCH_HINTS.get(
                objective,
                "dispatch the appropriate specialist or record a coverage_deferral",
            )
            try:
                rendered_hint = hint.format(host=host)
            except (KeyError, IndexError):
                rendered_hint = hint
            warnings.append(
                f"host {host} unmet objective {objective} — {rendered_hint}"
            )
    return warnings


def render_per_host_section(section: dict[str, Any], warnings: list[str]) -> list[str]:
    """Emit the human-readable per-host outcome table as lines."""
    lines: list[str] = []
    hosts = section.get("hosts", [])
    objectives = section.get("objectives", list(_PER_HOST_OBJECTIVES))
    discovered_summary = section.get("discovered_summary")
    lines.append("")
    lines.append("per-host coverage outcomes (C40 — WARN-only):")
    if not hosts and not discovered_summary:
        lines.append("  (no hosts with backend signal — recon dispatch is the next step)")
        return lines
    if hosts:
        lines.append("  objectives: " + ", ".join(objectives))
        for row in hosts:
            host = row.get("host", "")
            outcomes = row.get("outcomes", {})
            cells: list[str] = []
            for objective in objectives:
                cell = outcomes.get(objective) or {}
                if cell.get("deferred"):
                    marker = "D"
                elif cell.get("met"):
                    marker = "Y"
                else:
                    marker = "N"
                cells.append(f"{objective}={marker}")
            lines.append(f"  - {host}: {', '.join(cells)}")
    if discovered_summary:
        count = discovered_summary.get("discovered_count", 0)
        with_unmet = discovered_summary.get("hosts_with_unmet_count", 0)
        with_deferral = discovered_summary.get("hosts_with_deferral_count", 0)
        top_unmet = discovered_summary.get("top_unmet_objectives") or []
        top_unmet_str = (
            ", ".join(
                f"{entry['objective']} ({entry['host_count']})" for entry in top_unmet
            )
            or "—"
        )
        lines.append(
            f"  + {count} discovered host(s) from wildcard expansion: "
            f"{with_unmet} unmet, {with_deferral} with deferrals. "
            f"top unmet objectives: {top_unmet_str}. "
            "Pass --include-discovered for the full matrix."
        )
    if warnings:
        lines.append("per-host-warnings (WARN-only; does not block phase advance):")
        for line in warnings:
            lines.append(f"  ! {line}")
    return lines


# ---------------------------------------------------------------------------
# --auto-redispatch rendering
# ---------------------------------------------------------------------------
def render_redispatch_section(block: dict[str, Any]) -> list[str]:
    """Emit the human-readable --auto-redispatch recommendations as lines."""
    lines: list[str] = []
    recommendations = block.get("recommendations", [])
    suppressed = block.get("suppressed", [])
    notes = block.get("notes", [])
    lines.append("")
    lines.append("auto-redispatch recommendations (RECOMMENDATION-ONLY — nothing was dispatched):")
    if not recommendations and not suppressed and not notes:
        lines.append("  (no failing scope entries — nothing to recommend)")
        return lines
    for rec in recommendations:
        lines.append(
            f"  - {rec['scope_host']} [{rec['stage']} gap] "
            f"confidence={rec['confidence']} role={rec['role']}"
        )
        lines.append(f"      {rec['command']}")
        if rec.get("parallel_role"):
            lines.append(f"      note: run {rec['parallel_role']} in parallel for this stage")
        lines.append(f"      task: {rec['task_skeleton']}")
        lines.append(f"      why: {rec['reason']}")
    if suppressed:
        lines.append("  suppressed (prior dispatch already covers the gap):")
        for row in suppressed:
            lines.append(f"    - {row['reason']}")
    if notes:
        lines.append("  notes:")
        for note in notes:
            lines.append(f"    ! {note}")
    return lines


# ---------------------------------------------------------------------------
# W2 — the coverage ledger (measured + VISIBLE per-host coverage state)
# ---------------------------------------------------------------------------
# The ledger answers, per in-scope host: how many live routes, is it a real app,
# was a dedicated lane run, is there a RECORDED VERDICT, and therefore — at a
# glance — is it COVERED or an UNCOVERED gap. A host is "covered" ONLY with a
# recorded verdict (a finding); a mere completed dispatch (a shallow lane) does
# NOT clear it. Parking / pure-redirect / all-dead hosts are excluded; a
# WAF-fronted host with a low curl route count is surfaced for browser reprobe
# rather than silently dropped.

# Ledger coverage-state vocabulary (string constants, stable for consumers).
COVERAGE_STATE_COVERED = "covered"
COVERAGE_STATE_UNCOVERED = "uncovered"
COVERAGE_STATE_NEEDS_BROWSER_REPROBE = "needs_browser_reprobe"
COVERAGE_STATE_EXCLUDED = "excluded"


def _empty_route_stats() -> dict[str, Any]:
    return {
        "live_routes": 0,
        "total_routes": 0,
        "api_like": False,
        "auth_like": False,
        "graphql_like": False,
    }


def compute_real_app(
    *,
    route_count: int,
    api_auth_graphql: bool,
    has_finding: bool,
    threshold: int,
) -> tuple[bool, str]:
    """Decide whether a host is a real_app worth covering, with a reason.

    real_app = (>= threshold live routes) OR (exposes an API/auth/GraphQL
    surface) OR (already carries a finding). The OR-inclusion catches small
    high-value APIs under the blunt route threshold; the finding clause keeps a
    crown-jewel host that recon under-enumerated from being mislabeled parking.
    """
    if has_finding:
        return True, "finding recorded on host"
    if route_count >= threshold:
        return True, f">={threshold} live routes ({route_count})"
    if api_auth_graphql:
        return True, "exposes API/auth/GraphQL surface (under route threshold)"
    return False, f"<{threshold} live routes and no API/auth/GraphQL surface"


def compute_coverage_state(
    *,
    waf: bool,
    route_count: int,
    threshold: int,
    real_app: bool,
    has_recorded_verdict: bool,
) -> str:
    """The ledger state machine. ``covered`` wins (a verdict closes the host);
    a WAF host whose curl route count is below the threshold is surfaced for a
    browser reprobe (curl undercounts behind a WAF); a non-real_app host is
    excluded; everything else is an UNCOVERED gap."""
    if real_app and has_recorded_verdict:
        return COVERAGE_STATE_COVERED
    if waf and route_count < threshold:
        return COVERAGE_STATE_NEEDS_BROWSER_REPROBE
    if not real_app:
        return COVERAGE_STATE_EXCLUDED
    return COVERAGE_STATE_UNCOVERED


def dispatched_hosts_from_rows(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Map dispatch rows to ``{host: [roles]}`` (a "dedicated lane" per host)."""
    out: dict[str, list[str]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        host = host_from_token(str(row.get("scope_host") or ""))
        if not host:
            continue
        role = str(row.get("agent_role") or row.get("role") or "").strip()
        roles = out.setdefault(host, [])
        if role and role not in roles:
            roles.append(role)
    return out


def _host_waf_flag(per_host_row: dict[str, Any] | None) -> bool:
    if not per_host_row:
        return False
    cell = (per_host_row.get("outcomes") or {}).get("waf_tier") or {}
    return bool(cell.get("met")) or bool(cell.get("evidence"))


def build_coverage_ledger(
    *,
    scope_data: dict[str, Any],
    route_stats_by_host: dict[str, dict[str, Any]],
    per_host_payload: dict[str, Any],
    dispatched_hosts: dict[str, list[str]],
    route_threshold: int = 6,
) -> dict[str, Any]:
    """Assemble the per-host coverage ledger.

    Joins the backend work-buffer route stats with the backend per-host C40
    outcomes and the finding-VERDICT projection, scoped to in-scope hosts
    (out-of-scope carve-outs win). Hosts with at least one signal (routes,
    backend outcome row, verdict, or lane) become ledger rows; in-scope scope
    LITERALS that have no signal at all are surfaced separately as
    ``unprobed_hosts`` (recon never reached them) rather than silently dropped.
    """
    allow_entries = scope_entries(scope_data)
    deny_entries = out_of_scope_entries(scope_data)
    literal_hosts = _explicit_literal_scope_hosts(allow_entries)

    per_host_rows = {
        str(row.get("host")): row
        for row in (per_host_payload.get("hosts") or [])
        if isinstance(row, dict) and row.get("host")
    }
    finding_verdicts = per_host_payload.get("finding_verdicts")
    if not isinstance(finding_verdicts, dict):
        finding_verdicts = {}

    signal_hosts = (
        set(route_stats_by_host)
        | set(per_host_rows)
        | set(finding_verdicts)
        | set(dispatched_hosts)
    )

    rows: list[dict[str, Any]] = []
    summary = {
        "total": 0,
        "covered": 0,
        "uncovered": 0,
        "needs_browser_reprobe": 0,
        "excluded": 0,
        "real_app": 0,
        "unprobed": 0,
    }

    for host in sorted(signal_hosts):
        if not host_admitted(host, allow_entries, deny_entries):
            continue
        stats = route_stats_by_host.get(host) or _empty_route_stats()
        route_count = int(stats.get("live_routes", 0))
        total_routes = int(stats.get("total_routes", 0))
        api_auth_graphql = bool(
            stats.get("api_like") or stats.get("auth_like") or stats.get("graphql_like")
        )
        verdict = finding_verdicts.get(host) if isinstance(finding_verdicts.get(host), dict) else None
        has_recorded_verdict = bool(verdict and verdict.get("has_finding"))
        per_host_row = per_host_rows.get(host)
        waf = _host_waf_flag(per_host_row)
        lane_roles = sorted(dispatched_hosts.get(host, []))
        dedicated_lane = bool(lane_roles)

        real_app, real_app_reason = compute_real_app(
            route_count=route_count,
            api_auth_graphql=api_auth_graphql,
            has_finding=has_recorded_verdict,
            threshold=route_threshold,
        )
        state = compute_coverage_state(
            waf=waf,
            route_count=route_count,
            threshold=route_threshold,
            real_app=real_app,
            has_recorded_verdict=has_recorded_verdict,
        )

        rows.append(
            {
                "host": host,
                "scope_kind": "literal" if host in literal_hosts else "wildcard-discovered",
                "route_count": route_count,
                "total_routes": total_routes,
                "real_app": real_app,
                "real_app_reason": real_app_reason,
                "api_auth_graphql": api_auth_graphql,
                "waf": waf,
                "needs_browser_reprobe": state == COVERAGE_STATE_NEEDS_BROWSER_REPROBE,
                "dedicated_lane": dedicated_lane,
                "lane_roles": lane_roles,
                "has_recorded_verdict": has_recorded_verdict,
                "finding_verdict": verdict if has_recorded_verdict else None,
                "coverage_objectives": (per_host_row.get("outcomes") if per_host_row else None),
                "unmet_objectives": (per_host_row.get("unmet_objectives") if per_host_row else []),
                "coverage_state": state,
            }
        )
        summary["total"] += 1
        summary[state] += 1
        if real_app:
            summary["real_app"] += 1

    unprobed = sorted(
        host
        for host in literal_hosts
        if host not in signal_hosts and host_admitted(host, allow_entries, deny_entries)
    )
    summary["unprobed"] = len(unprobed)

    return {
        "route_threshold": route_threshold,
        "hosts": rows,
        "unprobed_hosts": unprobed,
        "summary": summary,
    }


_LEDGER_STATE_LABEL: dict[str, str] = {
    COVERAGE_STATE_COVERED: "COVERED",
    COVERAGE_STATE_UNCOVERED: "UNCOVERED",
    COVERAGE_STATE_NEEDS_BROWSER_REPROBE: "NEEDS-BROWSER-REPROBE",
    COVERAGE_STATE_EXCLUDED: "excluded",
}


def render_coverage_ledger_text(ledger: dict[str, Any]) -> list[str]:
    """Render the ledger as text. The uncovered gap is made obvious at a glance:
    a dedicated UNCOVERED block follows the table, then the WAF reprobe list and
    any unprobed scope literals."""
    lines: list[str] = []
    threshold = ledger.get("route_threshold", 6)
    summary = ledger.get("summary", {})
    rows = ledger.get("hosts", [])

    lines.append(
        f"coverage ledger (route-threshold={threshold} — BLUNT heuristic; "
        f"real_app = >={threshold} live routes OR API/auth/GraphQL surface OR a finding)"
    )
    lines.append(
        "  summary: "
        f"{summary.get('total', 0)} host(s) | "
        f"{summary.get('covered', 0)} covered | "
        f"{summary.get('uncovered', 0)} UNCOVERED | "
        f"{summary.get('needs_browser_reprobe', 0)} needs-browser-reprobe | "
        f"{summary.get('excluded', 0)} excluded | "
        f"{summary.get('unprobed', 0)} unprobed"
    )
    if not rows and not ledger.get("unprobed_hosts"):
        lines.append("  (no in-scope hosts with signal yet — run recon first)")
        return lines

    for row in rows:
        label = _LEDGER_STATE_LABEL.get(row["coverage_state"], row["coverage_state"])
        verdict = row.get("finding_verdict") or {}
        vshort = (
            f"finding({verdict.get('finding_count', 0)})"
            if row.get("has_recorded_verdict")
            else "-"
        )
        flags = []
        if row.get("waf"):
            flags.append("waf")
        if row.get("api_auth_graphql"):
            flags.append("api/auth")
        if row.get("dedicated_lane"):
            flags.append("lane")
        flag_str = f" [{','.join(flags)}]" if flags else ""
        lines.append(
            f"  - {row['host']}{flag_str}  routes={row['route_count']}"
            f"  real_app={'y' if row['real_app'] else 'n'}"
            f"  verdict={vshort}  => {label}"
        )

    uncovered = [r for r in rows if r["coverage_state"] == COVERAGE_STATE_UNCOVERED]
    if uncovered:
        lines.append("")
        lines.append(
            "UNCOVERED real_app host(s) — a recorded verdict is missing "
            "(a finding or an evidence-backed-negative decision; a completed "
            "dispatch does NOT count):"
        )
        for row in uncovered:
            lane = (
                f"lane={','.join(row['lane_roles'])}" if row.get("lane_roles") else "no lane"
            )
            lines.append(
                f"  ! {row['host']} ({row['route_count']} live routes, {lane}) "
                f"— {row['real_app_reason']}"
            )

    reprobe = [r for r in rows if r["coverage_state"] == COVERAGE_STATE_NEEDS_BROWSER_REPROBE]
    if reprobe:
        lines.append("")
        lines.append(
            "WAF-fronted host(s) with low curl route count — NEEDS BROWSER REPROBE "
            "(curl undercounts behind a WAF; not 'covered'):"
        )
        for row in reprobe:
            lines.append(f"  ! {row['host']} ({row['route_count']} curl routes)")

    unprobed = ledger.get("unprobed_hosts") or []
    if unprobed:
        lines.append("")
        lines.append(
            "unprobed in-scope literal(s) — recon recorded no signal at all "
            "(enumerate before judging coverage):"
        )
        for host in unprobed:
            lines.append(f"  ? {host}")

    return lines


# ---------------------------------------------------------------------------
# A1 — the by-family coverage grid (per application-unit × attack-family)
# ---------------------------------------------------------------------------
# The by-family grid is the finer-grained sibling of the per-host ledger: it
# projects, per deep-required application-unit, one cell PER expected attack-
# family — so a unit that is "covered" at the host level but has an untouched
# SQLi class is visibly a gap. The backend owns the projection
# (``coverage-readiness/by-family``); these renderers are CLI-side glue over the
# pinned payload shape:
#
#   {"units": [{"application_unit_id", "host", "port_class", "path_prefix",
#               "deep_required", "families": [{"family", "expected_reason",
#               "status", "probe_count", "covering_probe_count", "has_finding",
#               "finding_id"}]}],
#    "totals": {"units", "cells", "covered", "missing_block", "missing_warn",
#               "deferred", "with_finding"}}
#
# ``status`` ∈ covered | missing_block | missing_warn | deferred.

_FAMILY_LEDGER_STATUS_LABEL: dict[str, str] = {
    "covered": "COVERED",
    "missing_block": "MISSING-BLOCK",
    "missing_warn": "missing-warn",
    "deferred": "deferred",
}


def _family_cell_is_gap(fam: dict[str, Any]) -> bool:
    """A family cell is a coverage GAP when its status is a missing_* verdict, or
    (for any unrecognized status) when no covering probe has landed on it yet
    (``covering_probe_count == 0``). A ``covered`` cell is never a gap, and a
    ``deferred`` cell is a deliberate decision (like a per-host deferral), so it
    is not surfaced as an unaddressed gap either."""
    status = str(fam.get("status") or "")
    if status in ("covered", "deferred"):
        return False
    if status in ("missing_block", "missing_warn"):
        return True
    return int(fam.get("covering_probe_count") or 0) == 0


def _family_finding_flag(fam: dict[str, Any]) -> str:
    """Return a ``finding#<id>`` (or bare ``finding``) flag for a linked cell, else ``""``."""
    if not fam.get("has_finding"):
        return ""
    finding_id = fam.get("finding_id")
    return f"finding#{finding_id}" if finding_id is not None else "finding"


def render_family_ledger_text(payload: dict[str, Any]) -> list[str]:
    """Render the by-family coverage grid as text lines.

    One block per application-unit (header carries host / port_class /
    path_prefix / deep-required), then one line per expected family cell. A GAP
    cell (missing_block / missing_warn, or no covering probe) is marked ``GAP``;
    a covered cell shows its verdict plus ``covering/total covering`` probe
    counts; a finding-linked cell is flagged ``finding#<id>`` so the three read
    distinctly at a glance. The leading ``totals:`` line summarizes the grid.
    """
    if not isinstance(payload, dict):
        return ["coverage by-family: unexpected response from backend"]

    units = [u for u in (payload.get("units") or []) if isinstance(u, dict)]
    totals = payload.get("totals") if isinstance(payload.get("totals"), dict) else {}

    lines: list[str] = [
        "coverage by-family (per application-unit × attack-family — a GAP cell "
        "has no covering probe; a covered cell shows its verdict + probe counts):"
    ]
    lines.append(
        "  totals: "
        f"{totals.get('units', 0)} unit(s) | "
        f"{totals.get('cells', 0)} cell(s) | "
        f"{totals.get('covered', 0)} covered | "
        f"{totals.get('missing_block', 0)} missing-block | "
        f"{totals.get('missing_warn', 0)} missing-warn | "
        f"{totals.get('deferred', 0)} deferred | "
        f"{totals.get('with_finding', 0)} with finding"
    )
    if not units:
        lines.append("  (no application-units recorded yet)")
        return lines

    for unit in units:
        host = str(unit.get("host") or "")
        port_class = str(unit.get("port_class") or "")
        path_prefix = str(unit.get("path_prefix") or "")
        deep = "deep-required" if unit.get("deep_required") else "shallow-ok"
        unit_id = unit.get("application_unit_id")
        header = f"  - unit#{unit_id} {host}"
        if port_class:
            header += f" [{port_class}]"
        if path_prefix:
            header += f" {path_prefix}"
        header += f"  ({deep})"
        lines.append(header)

        families = [f for f in (unit.get("families") or []) if isinstance(f, dict)]
        if not families:
            lines.append("      (no expected families for this unit)")
            continue
        for fam in families:
            family = str(fam.get("family") or "")
            status = str(fam.get("status") or "")
            label = _FAMILY_LEDGER_STATUS_LABEL.get(status, status or "?")
            probe_count = int(fam.get("probe_count") or 0)
            covering = int(fam.get("covering_probe_count") or 0)
            marker = "GAP " if _family_cell_is_gap(fam) else "    "
            reason = str(fam.get("expected_reason") or "")
            reason_str = f" ({reason})" if reason else ""
            finding_flag = _family_finding_flag(fam)
            finding_str = f"  {finding_flag}" if finding_flag else ""
            lines.append(
                f"      {marker}{family}{reason_str}: {label} "
                f"[{covering}/{probe_count} covering]{finding_str}"
            )
    return lines


def render_dispatch_coverage_block(
    payload: dict[str, Any],
    *,
    host: str,
    path_prefix: str | None = None,
) -> list[str]:
    """Render a paste-ready ``COVERAGE:`` block for a specialist dispatch prompt.

    Filters the by-family grid CLIENT-SIDE to ``host`` (and ``path_prefix`` when
    given) and lists, per application-unit, which attack-families are already
    covered and which remain OPEN gaps — so a dispatch can hand the specialist
    the measured coverage picture plus an OPEN objective instead of a
    prescriptive technique cage. Reuses the by-family payload; adds no backend
    call. NOTE: ``host``/``path_prefix`` scope by application-unit here — this is
    deliberately NOT the surface-id sense of ``--surface`` on ``coverage --attempts``.
    """
    host_l = (host or "").strip().lower()
    prefix = (path_prefix or "").strip()
    units = [
        u
        for u in (payload.get("units") or [])
        if isinstance(u, dict) and str(u.get("host") or "").strip().lower() == host_l
    ]
    if prefix:
        units = [u for u in units if str(u.get("path_prefix") or "") == prefix]

    scope = f"{host_l}{prefix}"
    lines: list[str] = [
        f"COVERAGE: {scope} (coverage-driven dispatch context — hunt the OPEN "
        "gaps below and form your own hypotheses; this is a map, not a script):"
    ]
    if not units:
        lines.append(
            f"  (no recorded coverage expectation for {scope} yet — treat the "
            "whole surface as open and enumerate first)"
        )
        return lines

    for unit in units:
        pp = str(unit.get("path_prefix") or "")
        deep = "deep-required" if unit.get("deep_required") else "shallow-ok"
        covered_fams: list[str] = []
        deferred_fams: list[str] = []
        open_fams: list[str] = []
        for fam in unit.get("families") or []:
            if not isinstance(fam, dict):
                continue
            name = str(fam.get("family") or "")
            if _family_cell_is_gap(fam):
                open_fams.append(name)
            elif str(fam.get("status") or "") == "deferred":
                deferred_fams.append(name)
            else:
                flag = _family_finding_flag(fam)
                covered_fams.append(f"{name}({flag})" if flag else name)
        lines.append(f"  unit {host_l}{pp} [{deep}]")
        lines.append(
            f"    covered: {', '.join(covered_fams) if covered_fams else '(none)'}"
        )
        if deferred_fams:
            lines.append(f"    deferred: {', '.join(deferred_fams)}")
        lines.append(
            f"    OPEN gaps: {', '.join(open_fams) if open_fams else '(none)'}"
        )
    return lines


# Re-exports the consolidated CLI command and tests expect from this module.
__all__ = [
    "BUCKET_SKILLS",
    "render_surface_coverage",
    "render_report_readiness",
    "render_intel_readiness",
    "render_stage_audit",
    "build_scope_coverage_report",
    "build_redispatch_block",
    "fetch_prior_dispatches",
    "annotate_by_host_payload",
    "filter_to_scope_literals",
    "per_host_warning_lines",
    "render_scope_coverage_text",
    "render_per_host_section",
    "render_redispatch_section",
    "load_route_stats_by_host",
    "build_coverage_ledger",
    "compute_real_app",
    "compute_coverage_state",
    "dispatched_hosts_from_rows",
    "render_coverage_ledger_text",
    "render_family_ledger_text",
    "render_dispatch_coverage_block",
    "COVERAGE_STATE_COVERED",
    "COVERAGE_STATE_UNCOVERED",
    "COVERAGE_STATE_NEEDS_BROWSER_REPROBE",
    "COVERAGE_STATE_EXCLUDED",
]
