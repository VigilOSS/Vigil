"""vigil assess check-scope-coverage — per-scope-entry coverage audit.

This is a higher-level sibling of `check-coverage`: where that command audits
the backend's `assessment_surfaces` table for surface-level resolution,
`check-scope-coverage` walks every entry in `scope.json` (bare hosts,
wildcards, or http URLs) and reports coverage state across the enumeration,
collection, and consumption phases.

Unlike earlier revisions, this command does not re-parse raw command-run argv
to infer which enumeration/collection tool ran. Instead, coverage is read
directly from durable state the recon/collection specialists already produce:

- Backend `GET /engagements/{key}/assessment/services` — the live endpoints
  each scope entry resolves to. Wildcards require at least one live service
  under them; apex-only deployments satisfy that trivially.
- Backend `GET /engagements/{key}/assessment/surfaces` — recorded surface
  candidates keyed by host. Any surface under a scope entry's host proves
  collection produced something.
- Local `$DIR/cases.db` `work_items` grouped by status (pending / processing
  / done / skipped / error). Rows under a scope entry's host prove URL-level
  collection happened, and the pending/terminal_reason split drives the
  consumption gate.

The gate asks "did enumeration and collection produce evidence under this
scope entry?" not "did a specific tool binary run?". That shift is intentional:
the tool-binary question used to be answered by shell-parsing every stored
command run, which was fragile against wrappers, shell prefixes, and
file-driven target lists. The state we check instead is what downstream phases
actually consume, so a pass here means later phases have real data to work
with.

Scope-entry → host match heuristics:

- ``bare_host`` and ``url`` entries match hosts equal to the entry host.
- ``wildcard`` entries match the apex and any subdomain under it.

Exit codes:

- ``0`` — all required-stage gates clean (or no stage required).
- ``1`` — one or more scope entries fail the required stage gate, or a
  backend/CLI error prevented audit completion.
- ``2`` — invocation-time failure (missing scope.json, unparseable config).

The ``--require-stage`` flag gates only the exit code. All discovery still
happens regardless, so a ``--verbose`` run without a stage gate is still a
useful full-scope overview.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from assess.lib.classify_buckets import BUCKET_SKILLS, classify_from_fields
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.scope import (
    classify_scope_entry,
    entry_matches_host,
    host_from_token,
    host_is_vendor_saas,
)


def _explicit_literal_scope_hosts(entries: list[dict[str, Any]]) -> set[str]:
    """Hosts authored explicitly in ``scope.json`` (bare host or URL entry).

    Wildcard entries are excluded — those expand to subdomains the operator
    did not enumerate by hand, and a vendor-SaaS subdomain that appears
    under wildcard expansion is the genuinely ambiguous case the
    Vendor-SaaS scope checkpoint exists to resolve. An explicit literal
    (e.g. ``customer.my.salesforce.com`` typed directly into scope.json) is
    already the operator's in-scope decision; making the gate fire on it
    is theatre.
    """
    return {
        entry["host"]
        for entry in entries
        if entry.get("entry_kind") in ("bare_host", "url") and entry.get("host")
    }


def _vendor_saas_decided_hosts(client: AssessmentClient) -> set[str]:
    """Return the set of hosts that already carry a vendor-SaaS scope decision.

    Round 9: the Vendor-SaaS scope checkpoint records the user's choice in
    the orchestrator backend's ``assessment_dispatch_decisions`` table with
    ``kind='scope_decision'``. Hosts in that set are excluded from the
    phase-advance gate. A backend failure returns the empty set (the gate
    fires conservatively).

    Uses ``list_all_decisions`` (paginated) instead of ``list_decisions`` —
    the latter caps at the backend's 100-row default and would silently drop
    older decisions on long-running engagements, causing the phase gate to
    block transitions even when the operator already recorded the decision.
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


# Services count as "live" when the backend state is anything except
# `down`/`filtered`/`unreachable`. We prefer an allow list over a block list
# so new backend state values default to counting as live (they'd have to opt
# out explicitly), which keeps the audit optimistic during backend schema
# evolution.
_NON_LIVE_SERVICE_STATES: frozenset[str] = frozenset({"down", "filtered", "unreachable"})


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "check-scope-coverage",
        help="Audit coverage state per scope.json entry across enum/collect/consume phases",
    )
    p.add_argument(
        "--require-stage",
        dest="require_stage",
        choices=("enum", "collection", "consumption"),
        default=None,
        help=(
            "Gate the exit code on a stage. 'enum' requires every scope entry "
            "to have enumeration evidence (bare hosts satisfy this trivially; "
            "wildcards require at least one live service, surface, or work "
            "item under them). 'collection' additionally requires at least "
            "one surface or work item per entry. 'consumption' additionally "
            "requires pending==0 or every remaining pending item to carry "
            "terminal_reason."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the full JSON report to stdout instead of the human-readable summary",
    )
    p.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Dump per-entry detail rows even when the summary passes (default: compact)",
    )
    p.add_argument(
        "--strict-vendor-saas",
        dest="strict_vendor_saas",
        action="store_true",
        help=(
            "Fail the coverage gate on undecided vendor-SaaS discoveries. "
            "Without this flag, pending vendor-SaaS decisions are reported "
            "but do not block phase advance."
        ),
    )
    p.add_argument(
        "--by-host",
        dest="by_host",
        action="store_true",
        help=(
            "C40 — emit per-host outcome status (WAF tier, service inventory, "
            "directory-fuzz coverage, tech fingerprint, OSINT) for every host the "
            "engagement has signal for. Outcomes are read from intel / surface / "
            "service / decision tables; this gate NEVER queries assessment_command_runs. "
            "Unmet objectives WARN but do not block (use --force on transition-phase "
            "if needed). Record an explicit skip via "
            "`vigil assess agent decision --kind coverage_deferral --payload-json "
            "'{\"host\": \"...\", \"deferred_objectives\": [\"directory_fuzz\"], \"reason\": \"...\"}' "
            "--surfaced-to-user`."
        ),
    )
    p.add_argument(
        "--auto-redispatch",
        dest="auto_redispatch",
        action="store_true",
        help=(
            "For every scope entry that FAILS a --require-stage gate, emit a "
            "ready-to-run next-dispatch RECOMMENDATION (role + scope-host + "
            "dispatch-mode + skills) plus a task skeleton stating the coverage "
            "gap. This NEVER fires a dispatch — the interactive operator runs "
            "the printed `vigil assess agent start ...` line. Requires "
            "--require-stage (the stage that failed selects the role); a "
            "no-op note is emitted if no stage is set. Skill selection for a "
            "consumption gap is data-driven off the host's untested pending "
            "work-item buckets; ambiguous buckets yield a low-confidence "
            "shortlist. Recommendations whose (role, scope-host) already has an "
            "ACTIVE (in-progress) prior dispatch covering the gap are "
            "suppressed; a host whose only prior dispatch already terminated "
            "(completed/failed/aborted/blocked) is NOT suppressed so the needed "
            "retry is still recommended."
        ),
    )
    p.add_argument(
        "--max-recommendations",
        dest="max_recommendations",
        type=int,
        default=10,
        help=(
            "Cap the number of --auto-redispatch recommendations emitted "
            "(default 10). Failing entries past the cap are summarized as a "
            "single 'N more' note so a large wildcard fan-out does not bury the "
            "operator."
        ),
    )
    p.add_argument(
        "--include-discovered",
        dest="include_discovered",
        action="store_true",
        help=(
            "FU1 — render the per-host matrix for ALL hosts with backend signal, "
            "including those discovered under wildcard expansion. Default is "
            "scope.json explicit literals only (bare_host + url entries) plus a "
            "summary line for wildcard-discovered hosts. Pass this flag on "
            "wildcard-light engagements where every discovered subdomain is "
            "worth seeing in the matrix, or when debugging why a specific "
            "discovered host's outcomes aren't passing."
        ),
    )
    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# C40 — per-host outcome objectives + actionable dispatch hints
# ---------------------------------------------------------------------------


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
# them keeps a future role-file rename (e.g. recon-specialist -> web-recon-lead)
# from silently leaving stale references in the hint strings. The regression
# test in `test_check_scope_coverage_specialist_roster_exists` asserts each
# value here has a matching `agent/agents/<name>.md` file on disk, so a rename
# without a hint update fails the test suite.
_HINT_RECON_SPECIALIST = "recon-specialist"
_HINT_OSINT_ANALYST = "osint-analyst"


# Per-objective remediation hint. Operators read this when the gate WARNs so
# they know exactly what to dispatch (or what coverage_deferral to record) to
# clear the line.
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


# ---------------------------------------------------------------------------
# --auto-redispatch — turn a coverage gap into a ready-to-run RECOMMENDATION
# ---------------------------------------------------------------------------
#
# This command NEVER fires a dispatch. It prints the `vigil assess agent start`
# line the interactive operator runs by hand. The maps below mirror the
# operator phase model; `agent/operator-core.md` is the human source of truth
# (the "role default dispatch-mode" list near "Dispatch-Mode Declaration" and
# the Phase 1/2/3 specialist roster). Keep these in lockstep with that doc.

# stage gap -> base role. Mirrors the phase model: enum is recon's job,
# collection is the surface-collector's, consumption is the vulnerability
# analyst's. `_STAGE_PARALLEL_ROLE` records the role that runs in PARALLEL with
# the base role for a stage (recon-specialist + source-analyzer in Phase 1) so
# the recommendation can name it as a note without emitting a second command.
_STAGE_TO_ROLE: dict[str, str] = {
    "enum": "recon-specialist",
    "collection": "surface-collector",
    "consumption": "vulnerability-analyst",
}
_STAGE_PARALLEL_ROLE: dict[str, str] = {
    "enum": "source-analyzer",
}

# role -> default dispatch-mode. Mirrors the per-role defaults in
# operator-core.md ("If the operator omits the mode, the agent picks the safest
# default for its role"). `fuzzer` is included because a high-volume / fuzzing-
# shaped consumption gap swaps the base vulnerability-analyst for a fuzzer.
_ROLE_TO_MODE: dict[str, str] = {
    "recon-specialist": "hypothesis-driven",
    "source-analyzer": "item-iterating",
    "surface-collector": "item-iterating",
    "vulnerability-analyst": "item-iterating",
    "fuzzer": "variant-rotation",
}

# Fixed skills for the non-data-driven stages. Enum/collection gaps don't have a
# bucket tally to key off — the next move is always the same recon / collection
# skill set, so the mapping is fixed here (validated on disk like every other
# recommended skill).
_ENUM_SKILLS: tuple[str, ...] = ("web-recon", "subdomain-enumeration")
_COLLECTION_SKILLS: tuple[str, ...] = ("surface-collection", "gau-triage")

# Buckets whose dominant presence means "we can't confidently name one vuln
# class". These are generic / trust-delegation / environment buckets that don't
# map to a single testing skill (intentionally absent from BUCKET_SKILLS). When
# the dominant bucket is one of these, OR when the pending items split roughly
# evenly across >= 3 buckets, the recommendation degrades to a ranked
# shortlist flagged confidence=low rather than forcing one guess.
_AMBIGUOUS_BUCKETS: frozenset[str] = frozenset(
    {
        "interestingparams",
        "interestingext",
        "trust_surface",
        "debug_logic",
    }
)

# gap token (from _build_entry_report) -> stage name. A single entry can carry
# several gap tokens; the deepest failing stage is the one we recommend for
# (consumption implies enum+collection are listed too, but the operator's next
# move is the earliest unmet stage). Ordered earliest-first.
_GAP_TO_STAGE: tuple[tuple[str, str], ...] = (
    ("no-enum", "enum"),
    ("no-collection", "collection"),
    ("pending-work-remains", "consumption"),
)

# A high-volume consumption gap (many untested pending items concentrated on a
# single dominant bucket) is fuzzing-shaped: rotate payloads with the fuzzer
# rather than iterate items with the vulnerability-analyst. The threshold is a
# soft heuristic — operators can always re-pick the role.
_FUZZER_VOLUME_THRESHOLD = 100


def _bucket_of_cluster_key(cluster_key: str) -> str:
    """Map a stored ``cluster_key`` to its gf bucket name, or ``""``.

    classify_buckets stamps ``gf:<bucket>`` for matched rows; ``path:``,
    ``type:host_root``, and ``type:<inert>`` carry no vuln-class bucket.
    """
    key = (cluster_key or "").strip()
    if key.startswith("gf:"):
        return key[len("gf:"):]
    return ""


def _pending_buckets_for_host(
    db_path: Path,
    entry: dict[str, Any],
) -> dict[str, int]:
    """Tally untested pending work-item buckets for a scope entry's host(s).

    "Untested pending" mirrors the consumption gate's definition: ``status =
    'pending'`` AND no ``terminal_reason`` (classify-work has not deferred it)
    AND ``type != 'host_root'`` (crawl seeds are not consumable work). For each
    such row we reuse the stored ``cluster_key`` (``gf:<bucket>``) when present,
    falling back to re-classifying the row's fields via classify_buckets so the
    tally is correct even on a buffer that predates classify-work. Rows whose
    bucket is empty (``path:`` fallback, no gf match) are tallied under the
    empty-string key so the caller can still see "N unbucketed pending".

    Returns ``{bucket_name: count}`` summed across every host the entry matches
    (wildcards fold in all subdomains). A missing DB yields ``{}``.
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
            WHERE status = 'pending'
              AND (terminal_reason IS NULL OR terminal_reason = '')
              AND type != 'host_root'
            """
        )
        for row in cursor.fetchall():
            url = str(row[0] or "")
            host = _endpoint_host(url)
            if not host or not entry_matches_host(entry, host):
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

    A ``None``/missing skills root means we cannot verify — treat as resolving
    (don't drop a real skill just because the repo layout is unusual). The
    common case (root present) does the real path check so a typo'd or removed
    skill is dropped with a note rather than recommended.
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
    """Resolve ``agent/skills`` for skill validation, reusing contracts' logic.

    Imported lazily so the command stays importable in contexts where the
    contracts module's transitive imports are unavailable; a failure to import
    just disables on-disk validation (every skill is then kept).
    """
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
    """Pick role + skills + confidence for a consumption gap from the tally.

    Returns a dict with ``role``, ``skills`` (pre-validation), ``confidence``
    (``high`` / ``low``), ``dominant_bucket``, ``dominant_count``,
    ``pending_total``, and a human ``reason`` string. The ambiguity rules:

    - No bucketed pending at all (every pending row is ``path:``/unbucketed):
      ``confidence=low``, empty skills (nothing to test-skill on yet) — the
      operator likely needs more triage, not a vuln specialist.
    - Dominant bucket is generic/ambiguous (interestingparams, trust_surface,
      ...): ``confidence=low`` shortlist across the mapped buckets present.
    - Pending split roughly evenly across >= 3 distinct mapped buckets:
      ``confidence=low`` ranked shortlist (top buckets by count).
    - A single clearly-dominant mapped bucket: ``confidence=high``, that
      bucket's skill(s).
    """
    pending_total = sum(bucket_tally.values())
    # Buckets that actually map to a testing skill, ranked by count desc then
    # name for determinism.
    mapped = sorted(
        (
            (bucket, count)
            for bucket, count in bucket_tally.items()
            if bucket in BUCKET_SKILLS
        ),
        key=lambda kv: (-kv[1], kv[0]),
    )

    if not mapped:
        # Pending exists but nothing maps to a vuln class (all unbucketed /
        # ambiguous). Don't guess a testing skill.
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

    # "Roughly even across >= 3 buckets": at least three mapped buckets and the
    # runner-up is within ~half the leader (no single bucket dominates).
    split_evenly = distinct_mapped >= 3 and second_count * 2 >= top_count

    if split_evenly:
        # Ranked shortlist: each present mapped bucket's first skill, ordered.
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

    # Single dominant mapped bucket — high confidence. A high-volume single
    # bucket is fuzzing-shaped: swap to the fuzzer.
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
    """True when the single largest bucket is a generic/ambiguous one.

    Used to force a low-confidence shortlist when e.g. ``trust_surface`` or
    ``interestingparams`` is the most common pending bucket even though a
    smaller mapped bucket also exists.
    """
    if not bucket_tally:
        return False
    ranked = sorted(bucket_tally.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[0][0] in _AMBIGUOUS_BUCKETS


def _gap_stage_for_entry(entry: dict[str, Any]) -> str | None:
    """Return the earliest unmet stage for an entry, or ``None`` if clean.

    A failing entry can carry several gap tokens; the operator's next move is
    the earliest unmet stage (you must enumerate before you can collect before
    you can consume). ``no-live-hosts`` is informational and never selects a
    stage.
    """
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
) -> dict[str, Any]:
    """Build a single recommendation dict for a failing scope entry+stage."""
    host = entry["host"]
    dropped_skills: list[str] = []

    if stage == "consumption":
        bucket_tally = _pending_buckets_for_host(db_path, entry)
        selection = _consumption_skill_selection(bucket_tally)
        # An ambiguous-but-dominant generic bucket overrides a would-be
        # high-confidence pick: surface the shortlist of mapped buckets present.
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
    # consumption
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


def _build_recommendations(
    *,
    entries: list[dict[str, Any]],
    db_path: Path,
    skills_root: Path | None,
    prior_dispatches: list[dict[str, Any]] | None,
    dedup_degraded: bool,
    max_recommendations: int,
) -> dict[str, Any]:
    """Assemble the full --auto-redispatch recommendation block.

    Walks every entry with a failing stage gap, builds one recommendation each,
    suppresses any whose (role, scope_host) already has a prior dispatch
    covering the gap, and caps the surfaced list at ``max_recommendations``
    (summarizing the overflow). ``dedup_degraded`` records that the prior-
    dispatch fetch failed so the operator knows the suppression is best-effort.
    """
    prior_index = _index_prior_dispatches(prior_dispatches or [])
    recommendations: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    for entry in entries:
        stage = _gap_stage_for_entry(entry)
        if stage is None:
            continue
        rec = _build_recommendation(
            entry=entry, stage=stage, db_path=db_path, skills_root=skills_root
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
    # Define `cap` unconditionally so the overflow note's f-string can never hit
    # a NameError on a code path where `max_recommendations is None`. Clamp
    # negatives to 0 so a negative cap means "show none" (overflow is still
    # summarized) rather than silently disabling the cap.
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
    """Map ``(role, scope_host) -> agent_id`` for prior dispatch rows.

    A prior dispatch "covers the gap" when it shares the recommended role and
    scope-host. Role+host is the dedup key the design specifies — re-recommending
    a vulnerability-analyst against a host that already has one in flight is the
    duplicate we suppress. Empty role/host rows are skipped.
    """
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


# Dispatch lifecycle status values, mirrored from the backend
# ``_DISPATCH_STATUS`` / ``_DISPATCH_TERMINAL_STATUS`` literals in
# ``orchestrator/backend/app/api/assessment.py``. A dispatch is "active"
# (in-flight) only while ``in-progress``; the rest are terminal. Dedup must
# only suppress against ACTIVE dispatches — a host whose earlier dispatch
# already terminated (completed/failed/aborted/blocked) and STILL fails the
# gate needs a fresh retry recommended, not permanent suppression.
_DISPATCH_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "aborted", "blocked"}
)
_DISPATCH_ACTIVE_STATUSES: frozenset[str] = frozenset({"in-progress"})


def _fetch_prior_dispatches(
    client: AssessmentClient,
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch ACTIVE prior dispatches for dedup. Returns ``(rows, degraded)``.

    Reuses ``AssessmentClient.list_dispatches`` — the same method the
    ``vigil assess agent list`` path uses — but constrains the fetch to
    in-flight dispatches so dedup only suppresses against work that is still
    running. The backend ``GET /dispatches`` accepts a single ``status`` query
    param (exact match); ``in-progress`` is the only non-terminal status, so
    one server-side filter expresses "all active". A defensive client-side
    pass drops any terminal row the backend might still return (e.g. a future
    status the server filter doesn't know to exclude). A backend failure
    degrades gracefully: ``([], True)`` so the audit emits un-deduped
    recommendations with a note instead of crashing.
    """
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


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    scope_path = Path(cfg.engagement_dir) / "scope.json"
    if not scope_path.is_file():
        print(f"check-scope-coverage: scope.json not found at {scope_path}", file=sys.stderr)
        sys.exit(2)

    try:
        scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check-scope-coverage: unable to read scope.json: {exc}", file=sys.stderr)
        sys.exit(2)

    raw_hosts = scope_data.get("hosts") or []
    if not isinstance(raw_hosts, list):
        print("check-scope-coverage: scope.json `hosts` must be a list", file=sys.stderr)
        sys.exit(2)

    entries = [classify_scope_entry(h) for h in raw_hosts if isinstance(h, str) and h.strip()]
    entries = [e for e in entries if e is not None]

    scope_metadata = _extract_scope_metadata(scope_data)

    auto_redispatch = bool(getattr(args, "auto_redispatch", False))
    prior_dispatches: list[dict[str, Any]] = []
    dedup_degraded = False

    by_host_payload: dict[str, Any] | None = None
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            services = client.get("services")
        except AssessError as exc:
            print(f"check-scope-coverage: backend services fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        try:
            surfaces = client.get("surfaces")
        except AssessError as exc:
            print(f"check-scope-coverage: backend surfaces fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        decided_hosts = _vendor_saas_decided_hosts(client)
        if bool(getattr(args, "by_host", False)):
            try:
                by_host_payload = client.get("coverage-readiness/by-host")
            except AssessError as exc:
                print(
                    "check-scope-coverage: backend per-host coverage fetch failed: "
                    f"{exc}",
                    file=sys.stderr,
                )
                sys.exit(1)
        # Prior dispatches power --auto-redispatch dedup. Fetched here so it
        # rides the same keep-alive connection as services/surfaces. A backend
        # failure degrades gracefully (un-deduped + note) — never crashes the
        # audit.
        if auto_redispatch:
            prior_dispatches, dedup_degraded = _fetch_prior_dispatches(client)

    services_list = services if isinstance(services, list) else []
    surfaces_list = surfaces if isinstance(surfaces, list) else []

    db_path = Path(cfg.engagement_dir) / "cases.db"
    try:
        work_by_host = _load_work_items_by_host(db_path)
    except sqlite3.Error as exc:
        print(f"check-scope-coverage: unable to read work buffer: {exc}", file=sys.stderr)
        sys.exit(1)

    report_entries: list[dict[str, Any]] = []
    for entry in entries:
        report_entries.append(
            _build_entry_report(
                entry=entry,
                services=services_list,
                surfaces=surfaces_list,
                work_by_host=work_by_host,
                scope_metadata=scope_metadata,
                required_stage=args.require_stage,
            )
        )

    # Vendor-SaaS undecided hosts: any host known to services/surfaces/work
    # that matches a vendor-SaaS suffix and has no recorded scope_decision
    # blocks the gate. The user-facing checkpoint must record a decision
    # (in-scope, out-of-scope, partial-scope) before phase advance — UNLESS
    # the operator already authored the host as an explicit literal entry in
    # scope.json (a bare-host or url entry that resolves exactly to this
    # host). Wildcard-matched discoveries still gate; those are the genuinely
    # ambiguous case (the operator wrote ``*.example.test`` and a vendor
    # subdomain showed up under expansion). An explicit literal in scope.json
    # is already an unambiguous in-scope decision.
    explicit_literal_hosts = _explicit_literal_scope_hosts(entries)
    vendor_saas_pending = _vendor_saas_hosts_pending_decision(
        services=services_list,
        surfaces=surfaces_list,
        work_by_host=work_by_host,
        decided_hosts=decided_hosts | explicit_literal_hosts,
    )

    overall_gaps = _collect_overall_gaps(report_entries, args.require_stage)
    strict_vendor_saas = bool(getattr(args, "strict_vendor_saas", False))
    if vendor_saas_pending and args.require_stage is not None and strict_vendor_saas:
        for host, vendor in vendor_saas_pending:
            overall_gaps.append(
                f"vendor-saas: {host} (vendor={vendor}) has no scope_decision recorded "
                f"(record via `vigil assess agent decision --kind scope_decision --host {host} --vendor {vendor} --choice ...`)"
            )
    ready = not overall_gaps

    per_host_warnings: list[str] = []
    by_host_section: dict[str, Any] | None = None
    if by_host_payload is not None:
        by_host_section = _annotate_by_host_payload(by_host_payload)
        if not bool(getattr(args, "include_discovered", False)):
            by_host_section = _filter_to_scope_literals(
                by_host_section, explicit_literal_hosts
            )
        per_host_warnings = _per_host_warning_lines(by_host_section)

    report = {
        "engagement_key": cfg.engagement_key,
        "required_stage": args.require_stage,
        "entries": report_entries,
        "overall_gaps": overall_gaps,
        "vendor_saas_pending_decision": [
            {"host": host, "vendor": vendor} for host, vendor in vendor_saas_pending
        ],
        "strict_vendor_saas": strict_vendor_saas,
        "ready": ready,
    }
    if by_host_section is not None:
        report["per_host_coverage"] = by_host_section
        report["per_host_warnings"] = per_host_warnings

    redispatch_block: dict[str, Any] | None = None
    if auto_redispatch:
        if args.require_stage is None:
            # No stage gate -> no per-entry gaps -> nothing to recommend. Emit a
            # no-op block with a note rather than silently producing nothing.
            redispatch_block = {
                "recommendations": [],
                "suppressed": [],
                "overflow": 0,
                "notes": [
                    "--auto-redispatch is a no-op without --require-stage: a "
                    "stage gate is what marks entries as failing. Re-run with "
                    "--require-stage enum|collection|consumption."
                ],
            }
        else:
            skills_root = _agent_skills_root_for_recommendations()
            redispatch_block = _build_recommendations(
                entries=report_entries,
                db_path=db_path,
                skills_root=skills_root,
                prior_dispatches=prior_dispatches,
                dedup_degraded=dedup_degraded,
                max_recommendations=int(getattr(args, "max_recommendations", 10)),
            )
        report["redispatch"] = redispatch_block

    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_text(report, verbose=args.verbose)
        if by_host_section is not None:
            _render_per_host_section(by_host_section, per_host_warnings)
        if redispatch_block is not None:
            _render_redispatch_section(redispatch_block)

    if not ready:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Host extraction helpers
# ---------------------------------------------------------------------------


def _endpoint_host(endpoint: str) -> str:
    """Return the lowercased host portion of a service endpoint or surface
    target descriptor.

    Services store `endpoint` as either a bare host, a host:port, or a full
    URL. Surfaces store `target_descriptor` in the same shapes plus the
    occasional space-separated "<host> <path>" form. We unify them all to a
    lowercased host string for matching.
    """
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
) -> dict[str, Any]:
    live_hosts_set: set[str] = set()
    live_host_samples: list[str] = []
    total_services = 0

    for svc in services:
        endpoint_host = _endpoint_host(str(svc.get("endpoint") or ""))
        if not entry_matches_host(entry, endpoint_host):
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
        if not entry_matches_host(entry, host):
            continue
        surfaces_count += 1
        if host:
            surface_hosts.add(host)

    host_work = (
        _aggregate_wildcard_work(entry, work_by_host)
        if entry["entry_kind"] == "wildcard"
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

    # Enum evidence: what does the downstream state actually show under this
    # scope entry? "We expanded and something is there" is what enumeration
    # was supposed to produce; checking that is more honest than "did a tool
    # whose name we recognize run against it".
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
    # Informational: wildcard produced no live hosts even though *something*
    # (a surface or work item) gave us enum evidence. Useful signal for the
    # operator to review scope relevance; not a --require-stage enum failure.
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
        if not _consumption_satisfied(work_queued, entry_status):
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


def _aggregate_wildcard_work(
    entry: dict[str, Any],
    work_by_host: dict[str, dict[str, int]],
) -> dict[str, int]:
    """Sum per-host work counts for a wildcard entry.

    We can't pre-index the work map by wildcard because new subdomains come
    and go between runs — iterate every host key once per wildcard and fold
    in the matching counts. Cheap for the sizes we care about (< 1k hosts).
    """
    aggregate: dict[str, int] = {}
    for host, counts in work_by_host.items():
        if not entry_matches_host(entry, host):
            continue
        for key, val in counts.items():
            aggregate[key] = aggregate.get(key, 0) + int(val)
    return aggregate


def _consumption_satisfied(work_queued: dict[str, int], entry_status: str) -> bool:
    """Return True when the consumption gate is satisfied.

    A scope entry marked `status=deferred` in scope metadata is terminal —
    the operator decided to skip it, which is a valid terminal state that
    shouldn't block report-time readiness. Otherwise: pending==0 or every
    remaining pending item has terminal_reason set (= implicit consumption
    via classify-work's inert/skipped pipeline).
    """
    if entry_status == "deferred":
        return True
    if int(work_queued.get("pending", 0)) == 0:
        return True
    if int(work_queued.get("pending_without_terminal_reason", 0)) == 0:
        return True
    return False


# ---------------------------------------------------------------------------
# scope.json metadata helpers
# ---------------------------------------------------------------------------


def _extract_scope_metadata(scope_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Parse optional per-host status metadata from scope.json.

    Supported shapes (in priority order):

    - ``host_metadata``: a dict keyed by host string, value is a dict with
      at least a `status` field.
    - ``deferred_hosts``: a list of hosts to treat as status=deferred.

    New schemas can be added by extending this parser rather than adding a
    new CLI flag — the CLI treats the metadata as advisory.
    """
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

    The mapping also tracks ``pending_without_terminal_reason`` so the
    consumption gate can distinguish "really pending" from "pending but
    deferred by classify-work". A missing DB yields an empty map rather
    than an error — offline/local-only workflows should still render
    audits so operators can spot drift.
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
        # host_root rows are Phase-2 crawl SEEDS, not consumable work — web-discovery
        # crawls those hosts and the resulting endpoint rows are the real work. They
        # are intentionally pending with no terminal_reason, so excluding the seed
        # type here keeps them from permanently blocking the consumption gate.
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
    """Return ``[(host, vendor), ...]`` for vendor-SaaS hosts lacking a decision.

    Walks every host present in services / surfaces / work_items, classifies
    each via :func:`host_is_vendor_saas`, and excludes any host that already
    carries a ``scope_decision`` row in the orchestrator's
    ``assessment_dispatch_decisions`` table. Output is sorted by host string for
    deterministic output.
    """
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


def _render_text(report: dict[str, Any], *, verbose: bool) -> None:
    entries = report["entries"]
    ready = report["ready"]
    stage = report["required_stage"]
    header = f"scope-coverage: {'ok' if ready else 'blocked'}"
    if stage:
        header = f"{header} (stage={stage})"
    print(header)
    if not entries:
        print("  (no scope entries in scope.json `hosts`)")
        return

    if not verbose and ready:
        for entry in entries:
            live = entry["live_hosts"]
            samples = ", ".join(entry["live_host_samples"][:3]) if entry["live_host_samples"] else "-"
            print(
                f"  - {entry['scope_entry']} [{entry['entry_kind']}] live={live} "
                f"surfaces={entry['surfaces_count']} "
                f"enum={'y' if entry['enum_attempted'] else 'n'} "
                f"collect={'y' if entry['collection_attempted'] else 'n'} "
                f"pending={entry['work_queued']['pending']} samples={samples}"
            )
        return

    for entry in entries:
        print(
            f"  - {entry['scope_entry']} [{entry['entry_kind']}] host={entry['host']}"
        )
        print(
            f"      enum: attempted={entry['enum_attempted']} evidence={entry['enum_evidence']}"
        )
        print(
            f"      live_hosts={entry['live_hosts']} total_services={entry['total_services']} samples={entry['live_host_samples']}"
        )
        print(
            f"      collection: attempted={entry['collection_attempted']} evidence={entry['collection_evidence']} surfaces={entry['surfaces_count']}"
        )
        print(
            f"      work_queued={entry['work_queued']}"
        )
        if entry.get("status"):
            print(f"      status={entry['status']}")
        if entry["gaps"]:
            print(f"      gaps={entry['gaps']}")

    if report["overall_gaps"]:
        print("gaps:")
        for msg in report["overall_gaps"]:
            print(f"  - {msg}")

    vendor_saas_pending = report.get("vendor_saas_pending_decision") or []
    if vendor_saas_pending:
        print("vendor-saas-pending-decision:")
        for row in vendor_saas_pending:
            print(
                f"  - {row['host']} (vendor={row['vendor']}) — record a "
                f"scope_decision via `vigil assess agent decision "
                f"--kind scope_decision --host {row['host']} --vendor {row['vendor']} "
                f"--choice ...` before recon dispatch"
            )


# ---------------------------------------------------------------------------
# C40 — per-host outcome rendering helpers
# ---------------------------------------------------------------------------


def _annotate_by_host_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize the backend per-host payload into a stable rendering shape.

    Backwards-compatibility insurance: if the backend ever returns a missing
    objective (older API revision), the CLI still emits a deterministic row
    so the operator output doesn't go silent. Unknown objectives the backend
    returns are preserved verbatim.
    """
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


def _filter_to_scope_literals(
    section: dict[str, Any],
    scope_literals: set[str],
) -> dict[str, Any]:
    """FU1 — fold wildcard-discovered hosts into a summary row.

    The C40 projection returns every host with backend signal — on
    wildcard-heavy engagements (a scope.json entry like ``*.example.com``
    that recon expanded into hundreds of subdomains), the resulting
    matrix becomes unreadable. This filter keeps hosts that the operator
    explicitly authored in scope.json (bare_host + url entries) as full
    matrix rows, and folds everything else into ``discovered_summary``:
    counts of total / unmet / deferred discovered hosts plus the top
    three most-frequent unmet objectives.

    When ``scope_literals`` is empty (scope.json had no explicit literals,
    only wildcards), this function returns the section unchanged — the
    operator has no other anchor to filter against.

    Operators who want to see every discovered host can pass
    ``--include-discovered`` to bypass this filter at the run() level.
    """
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
        # Nothing was wildcard-discovered. Don't add a noise summary block.
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


def _per_host_warning_lines(section: dict[str, Any]) -> list[str]:
    """Build human-readable per-objective warning lines.

    Each line names a (host, unmet objective) pair plus the dispatch the
    operator should run to clear it. Deferred objectives are silent. The
    function never raises and never returns None — empty list ↔ no warnings.
    """
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


def _render_per_host_section(section: dict[str, Any], warnings: list[str]) -> None:
    """Emit the human-readable per-host outcome table after the main report."""
    hosts = section.get("hosts", [])
    objectives = section.get("objectives", list(_PER_HOST_OBJECTIVES))
    discovered_summary = section.get("discovered_summary")
    print("")
    print("per-host coverage outcomes (C40 — WARN-only):")
    if not hosts and not discovered_summary:
        print("  (no hosts with backend signal — recon dispatch is the next step)")
        return
    if hosts:
        print("  objectives: " + ", ".join(objectives))
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
            print(f"  - {host}: {', '.join(cells)}")
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
        print(
            f"  + {count} discovered host(s) from wildcard expansion: "
            f"{with_unmet} unmet, {with_deferral} with deferrals. "
            f"top unmet objectives: {top_unmet_str}. "
            "Pass --include-discovered for the full matrix."
        )
    if warnings:
        print("per-host-warnings (WARN-only; does not block phase advance):")
        for line in warnings:
            print(f"  ! {line}")


# ---------------------------------------------------------------------------
# --auto-redispatch rendering
# ---------------------------------------------------------------------------


def _render_redispatch_section(block: dict[str, Any]) -> None:
    """Emit the human-readable --auto-redispatch recommendations.

    RECOMMENDATION-ONLY: the ready-to-run command is printed for the operator
    to run by hand. This command never fires a dispatch.
    """
    recommendations = block.get("recommendations", [])
    suppressed = block.get("suppressed", [])
    notes = block.get("notes", [])
    print("")
    print("auto-redispatch recommendations (RECOMMENDATION-ONLY — nothing was dispatched):")
    if not recommendations and not suppressed and not notes:
        print("  (no failing scope entries — nothing to recommend)")
        return
    for rec in recommendations:
        print(
            f"  - {rec['scope_host']} [{rec['stage']} gap] "
            f"confidence={rec['confidence']} role={rec['role']}"
        )
        print(f"      {rec['command']}")
        if rec.get("parallel_role"):
            print(f"      note: run {rec['parallel_role']} in parallel for this stage")
        print(f"      task: {rec['task_skeleton']}")
        print(f"      why: {rec['reason']}")
    if suppressed:
        print("  suppressed (prior dispatch already covers the gap):")
        for row in suppressed:
            print(f"    - {row['reason']}")
    if notes:
        print("  notes:")
        for note in notes:
            print(f"    ! {note}")
