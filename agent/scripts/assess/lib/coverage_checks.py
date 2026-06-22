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
import sqlite3
from pathlib import Path
from typing import Any

from assess.lib.classify_buckets import BUCKET_SKILLS, classify_from_fields
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.scope import (
    classify_scope_entry,
    entry_matches_host,
    host_from_token,
    host_in_scope,
    host_is_vendor_saas,
    out_of_scope_entries,
)


# ===========================================================================
# check-coverage — surface-resolution gate (old check_coverage.py body)
# ===========================================================================
def render_surface_coverage(readiness: Any) -> tuple[bool, list[str], list[str]]:
    """Render the surface-coverage gate from a ``/coverage-readiness`` payload.

    Returns ``(ready, ok_lines, blocker_lines)``. ``ready`` is the gate verdict;
    ``blocker_lines`` enumerate uncovered / partially-covered / high-risk-deferred
    surfaces (the old ``check-coverage`` stderr block) and ``ok_lines`` carry the
    success line. The caller decides exit code + stream.
    """
    if not isinstance(readiness, dict):
        return False, [], ["check-coverage: unexpected response from backend"]

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
    db_path: Path,
    entry: dict[str, Any],
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, int]:
    """Tally untested/unconsumed work-item buckets for a scope entry's host(s).

    Mirrors the consumption gate's definition (S8): a row is unconsumed when it
    is ``pending`` with no ``terminal_reason``, OR stuck in ``processing``, OR in
    ``error`` — in every case ``type != 'host_root'``. Reuses the stored
    ``cluster_key`` (``gf:<bucket>``) when present, re-classifying otherwise.
    Returns ``{bucket_name: count}`` summed across matching hosts. A missing DB
    yields ``{}``.
    """
    if not db_path.is_file():
        return {}

    tally: dict[str, int] = {}
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            """
            SELECT url, url_path, query_params, body_params, path_params,
                   type, cluster_key
            FROM work_items
            WHERE type != 'host_root'
              AND (
                    (status = 'pending'
                       AND (terminal_reason IS NULL OR terminal_reason = ''))
                 OR status = 'processing'
                 OR status = 'error'
              )
            """
        )
        for row in cursor.fetchall():
            url = str(row[0] or "")
            host = _endpoint_host(url)
            if not host or not entry_matches_host(entry, host) or host_in_scope(host, deny_entries):
                continue
            bucket = _bucket_of_cluster_key(str(row[6] or ""))
            if not bucket:
                assignment = classify_from_fields(
                    case_type=str(row[5] or "unknown"),
                    url_path=str(row[1] or ""),
                    query_params=str(row[2] or "{}"),
                    body_params=str(row[3] or "{}"),
                    path_params=str(row[4] or "{}"),
                )
                bucket = _bucket_of_cluster_key(str(assignment.get("cluster_key") or ""))
            tally[bucket] = tally.get(bucket, 0) + 1
    finally:
        conn.close()
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
    db_path: Path,
    skills_root: Path | None,
    deny_entries: list[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a single recommendation dict for a failing scope entry+stage."""
    host = entry["host"]
    dropped_skills: list[str] = []

    if stage == "consumption":
        bucket_tally = _pending_buckets_for_host(db_path, entry, deny_entries)
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
    db_path: Path,
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
            entry=entry, stage=stage, db_path=db_path, skills_root=skills_root,
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
# cases.db work buffer
# ---------------------------------------------------------------------------
def _load_work_items_by_host(db_path: Path) -> dict[str, dict[str, int]]:
    """Return a ``{host: {status: count, ...}}`` rollup from the local DB.

    Tracks ``pending_without_terminal_reason`` so the consumption gate can
    distinguish "really pending" from "deferred by classify-work". ``host_root``
    crawl seeds are excluded from that count. A missing DB yields an empty map.
    """
    if not db_path.is_file():
        return {}

    rows: list[tuple[str, str, int]] = []
    rows_with_reason: list[tuple[str, str, int]] = []
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            """
            SELECT url, status, COUNT(*) AS total
            FROM work_items
            GROUP BY url, status
            """
        )
        rows = [(str(r[0] or ""), str(r[1] or ""), int(r[2] or 0)) for r in cursor.fetchall()]
        cursor = conn.execute(
            """
            SELECT url, COUNT(*) AS total
            FROM work_items
            WHERE status = 'pending' AND (terminal_reason IS NULL OR terminal_reason = '')
              AND type != 'host_root'
            GROUP BY url
            """
        )
        rows_with_reason = [(str(r[0] or ""), "pending_without_terminal_reason", int(r[1] or 0)) for r in cursor.fetchall()]
    finally:
        conn.close()

    agg: dict[str, dict[str, int]] = {}
    for url, status, count in rows + rows_with_reason:
        host = _endpoint_host(url)
        if not host:
            continue
        bucket = agg.setdefault(host, {})
        bucket[status] = bucket.get(status, 0) + count
    return agg


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


# Re-exports the consolidated CLI command and tests expect from this module.
__all__ = [
    "BUCKET_SKILLS",
    "render_surface_coverage",
    "render_report_readiness",
    "render_intel_readiness",
    "build_scope_coverage_report",
    "build_redispatch_block",
    "fetch_prior_dispatches",
    "annotate_by_host_payload",
    "filter_to_scope_literals",
    "per_host_warning_lines",
    "render_scope_coverage_text",
    "render_per_host_section",
    "render_redispatch_section",
]
