"""vigil assess check-phase-readiness — ONE phase-aware readiness command.

This command folds five former standalone commands into one phase-keyed surface (no
aliases, no back-compat shims):

  * ``check-coverage``         → the surface-resolution gate, relayed every phase
  * ``check-scope-coverage``   → the per-scope-entry stage gate (``--require-stage``
    enum/collection/consumption, ``--by-host``, ``--auto-redispatch``)
  * ``check-report-readiness`` → ``--phase report`` (terminal report gate)
  * ``check-exploit-gate``     → the exploit PROJECTION folded into ``--phase exploit``
  * ``check-intel-readiness``  → the intel-closure advisory folded into
    ``--phase recon|consume|report`` (``--strict`` preserved)

Per-phase composition (depth-gate §6):

  * ``recon``   → enum evidence (old ``--require-stage enum``) + intel advisory
  * ``collect`` → collection evidence (old ``--require-stage collection``)
  * ``consume`` → consumption evidence (old ``--require-stage consumption``,
    incl. ``--by-host``/``--auto-redispatch``) + the depth ledger + intel advisory
  * ``verify``  → findings/verification readiness + depth carry-over
  * ``exploit`` → unverified-high + variant-pass blockers (relayed coverage) +
    the EXPLOIT PROJECTION (``{exploit_policy, approved_targets}``)
  * ``report``  → report-readiness blockers + intel advisory

Flag semantics:
  * ``--depth``           — show the depth ledger detail (consume/verify).
  * ``--by-app-unit``     — render the depth ledger broken out per app unit.
  * ``--by-host``         — C40 per-host outcome table (recon/collect/consume).
  * ``--auto-redispatch`` — per-failing-entry next-dispatch RECOMMENDATIONS.
  * ``--include-intel``   — force-include the intel advisory even on a phase
    that does not fold it by default.
  * ``--strict-deep``     — gate on app-unit DETECTION (default OFF; detection is
    warm-first). Escalates an unsatisfied deep_required unit to a non-zero exit.
  * ``--strict``          — CI-style: exit 1 on ANY open advisory item — an open
    intel-closure item (preserves the old ``check-intel-readiness --strict``) OR
    an open recon-pipeline stage gap (P-1, see below). Does NOT imply
    ``--strict-deep``.
  * ``--json``            — emit the structured projection (the downstream contract).

P-1 (item 2.1) — recon-pipeline stage-completion audit. On the pipeline phases
(``recon``/``collect``) the backend folds a ``stage_audit`` block into the
phase-readiness payload: it diffs the command-run ledger
(``assessment_command_runs``) against a per-phase EXPECTED-STAGE checklist
(subdomain/dns → httpx → katana → gau → trufflehog; collect → nuclei) and flags
any stage that ``timed_out`` / produced ``partial_results`` / NEVER RAN. The gap
report is ADVISORY by default (WARN/report only); ``--strict`` escalates an open
stage gap to a non-zero exit. The EXPECTED-STAGE map lives backend-side in
``state_manager.phase_readiness.PHASE_EXPECTED_STAGES``.

The terminal ``report``/``complete`` hard block is INDEPENDENT of both ``--strict``
and ``--strict-deep`` — it lives on the ``transition-phase`` precondition and is
unaffected by this advisory command.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from assess.lib import coverage_checks as cc
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.exploit_targets import resolve_approved_target_slugs
from assess.lib.phases import CODE_PHASES, PHASE_INPUT_ALIASES, WEB_PHASES, canonical_phase
from assess.lib.scope import load_scope


# This command handles the WEB engagement phases, in the canonical spellings
# from `assess.lib.phases` — the same values `transition-phase` persists to
# scope.json and the audit enum tags command runs with. The short `consume`
# form callers may type is resolved at the argparse boundary by
# `canonical_phase`; it never reaches the branching below.
PHASES = WEB_PHASES

_PHASE_ALIASES = PHASE_INPUT_ALIASES

_CLI_PHASE_CHOICES = (*PHASES, *CODE_PHASES, "complete", *_PHASE_ALIASES)

_INTEL_PHASES = frozenset({"recon", "consume-test", "report"})

_PHASE_REQUIRE_STAGE: dict[str, str | None] = {
    "recon": "enum",
    "collect": "collection",
    "consume-test": "consumption",
    "verify": None,
    "exploit": None,
    "report": None,
}

# ``report`` is a depth phase for RENDERING only: it previews the depth ledger
# and the would-block set (coverage-grain unbundle / ADR 0012) so the terminal
# depth block is legible BEFORE `transition-phase report` runs it. The preview
# NEVER changes this advisory command's exit code — the hard block lives on the
# transition-phase precondition. (`complete` is not a phase of this command, so
# it is not listed; its block is previewed under `report`.)
_DEPTH_PHASES = frozenset({"consume-test", "verify", "report"})

_COVERAGE_PHASES = frozenset(
    {"recon", "collect", "consume-test", "verify", "exploit"}
)


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "check-phase-readiness",
        help=(
            "Phase-aware readiness: per-phase coverage/scope/depth/exploit/intel "
            "checks (consolidates check-coverage, check-scope-coverage, "
            "check-report-readiness, check-exploit-gate, check-intel-readiness)."
        ),
    )
    p.add_argument(
        "--phase",
        dest="phase",
        choices=_CLI_PHASE_CHOICES,
        required=True,
        help="Engagement phase to check readiness for (the `consume` short "
             "form resolves to the canonical `consume-test`).",
    )
    p.add_argument(
        "--depth",
        dest="depth",
        action="store_true",
        help="Show the depth-ledger detail (consume/verify phases).",
    )
    p.add_argument(
        "--by-app-unit",
        dest="by_app_unit",
        action="store_true",
        help="Render the depth ledger broken out per app unit (implies --depth).",
    )
    p.add_argument(
        "--by-host",
        dest="by_host",
        action="store_true",
        help=(
            "C40 — emit the per-host outcome table (WAF tier, service inventory, "
            "directory-fuzz, tech fingerprint, OSINT) for recon/collect/consume. "
            "Unmet objectives WARN but do not block."
        ),
    )
    p.add_argument(
        "--include-discovered",
        dest="include_discovered",
        action="store_true",
        help=(
            "Render the per-host matrix for ALL hosts with backend signal, "
            "including wildcard-discovered hosts (default: scope literals only, "
            "with a discovered-host summary)."
        ),
    )
    p.add_argument(
        "--auto-redispatch",
        dest="auto_redispatch",
        action="store_true",
        help=(
            "For every scope entry that FAILS the phase stage gate, emit a "
            "ready-to-run next-dispatch RECOMMENDATION (role + host context + "
            "dispatch-mode + skills). Never fires a dispatch. Only meaningful on "
            "phases with a stage gate (recon/collect/consume)."
        ),
    )
    p.add_argument(
        "--max-recommendations",
        dest="max_recommendations",
        type=int,
        default=10,
        help="Cap the number of --auto-redispatch recommendations (default 10).",
    )
    p.add_argument(
        "--strict-vendor-saas",
        dest="strict_vendor_saas",
        action="store_true",
        help=(
            "Fail the stage gate on undecided vendor-SaaS discoveries. Without "
            "this flag, pending vendor-SaaS decisions are reported but do not "
            "block phase advance."
        ),
    )
    p.add_argument(
        "--include-intel",
        dest="include_intel",
        action="store_true",
        help="Force-include the intel advisory even on a phase that omits it by default.",
    )
    p.add_argument(
        "--strict-deep",
        dest="strict_deep",
        action="store_true",
        help=(
            "Gate on app-unit DETECTION (default OFF — detection is warm-first). "
            "Exit non-zero when a deep_required app unit is depth-unsatisfied. "
            "Does NOT change what the terminal backstop blocks on."
        ),
    )
    p.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        help=(
            "CI-style: exit 1 on any open advisory item — an open intel-closure "
            "item (preserves the old check-intel-readiness --strict) OR an open "
            "recon-pipeline stage gap (timed_out/partial/never-ran). Does NOT "
            "imply --strict-deep."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the structured JSON projection instead of the human summary.",
    )
    p.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Dump per-scope-entry detail rows even when the stage gate passes.",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    phase = canonical_phase(args.phase)
    scope_path = Path(cfg.engagement_dir) / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8")) if scope_path.is_file() else {}
    engagement_type = scope.get("engagement_type", "web")
    if engagement_type not in {"code", "both"} and phase not in PHASES:
        print(
            f"check-phase-readiness: {phase} is a code phase, but this engagement has no code track",
            file=sys.stderr,
        )
        sys.exit(1)
    if engagement_type == "code" or phase in (*CODE_PHASES, "complete"):
        if phase in (*CODE_PHASES, "complete"):
            target = phase
        else:
            current = scope.get("code_phase" if engagement_type == "both" else "current_phase", "ingest")
            target = (
                (*CODE_PHASES, "complete")[CODE_PHASES.index(current) + 1]
                if current in CODE_PHASES else "classify-map"
            )
        print(
            "check-phase-readiness checks web phases; code readiness is owned by "
            f"`vigil assess code-coverage --require-transition-ready {target}`.",
            file=sys.stderr,
        )
        sys.exit(1)

    projection: dict[str, Any] = {"phase": phase, "engagement_key": cfg.engagement_key}
    text_lines: list[str] = (
        ["Web track readiness only. For code, use `vigil assess code-coverage "
         "--require-transition-ready <target-phase>`."]
        if engagement_type == "both" else []
    )
    exit_nonzero = False

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            backend = client.get(f"phase-readiness?phase={phase}")
        except AssessError as exc:
            print(f"check-phase-readiness: backend phase-readiness fetch failed: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        if not isinstance(backend, dict):
            print("check-phase-readiness: unexpected response from backend", file=sys.stderr)
            sys.exit(1)

        if phase == "report":
            exit_nonzero |= _run_report_phase(
                client, args, backend, projection, text_lines
            )
            _emit(args, projection, text_lines)
            if exit_nonzero:
                sys.exit(1)
            return

        coverage = backend.get("coverage")
        cov_ready, cov_ok, cov_blockers = cc.render_surface_coverage(coverage)
        projection["coverage"] = {"ready": cov_ready, "blockers": cov_blockers}
        if cov_ready:
            text_lines.extend(cov_ok)
        else:
            text_lines.extend(cov_blockers)
            if phase == "consume-test":
                exit_nonzero = True

        # P-1 (item 2.1) — recon-pipeline stage-completion audit. The backend
        # folds a ``stage_audit`` block into the phase-readiness payload for the
        # pipeline phases (recon/collect). It is ADVISORY by default (WARN/report
        # only); --strict escalates an open stage gap to a non-zero exit,
        # alongside the existing --strict intel-closure escalation below.
        stage_audit = backend.get("stage_audit")
        if isinstance(stage_audit, dict) and stage_audit.get("applicable"):
            stage_has_open, stage_lines = cc.render_stage_audit(stage_audit)
            projection["stage_audit"] = stage_audit
            projection["stage_audit_open_gaps"] = bool(stage_has_open)
            text_lines.extend(stage_lines)
            if args.strict and stage_has_open:
                exit_nonzero = True

        stage = _PHASE_REQUIRE_STAGE.get(phase)
        scope_report: dict[str, Any] | None = None
        if stage is not None:
            scope_report, stage_failed = _run_scope_gate(
                cfg, client, args, stage
            )
            projection["scope_coverage"] = scope_report
            text_lines.extend(cc.render_scope_coverage_text(scope_report, verbose=args.verbose))
            if stage_failed:
                exit_nonzero = True

            if args.auto_redispatch:
                redispatch_block = _run_redispatch(cfg, client, args, scope_report, stage)
                projection["redispatch"] = redispatch_block
                text_lines.extend(cc.render_redispatch_section(redispatch_block))

        if args.by_host:
            literals = set((scope_report or {}).get("explicit_literal_hosts") or [])
            if scope_report is None:
                literals = _scope_literals_from_disk(cfg)
            by_host_section, per_host_warnings = _run_by_host(client, args, literals)
            if by_host_section is not None:
                projection["per_host_coverage"] = by_host_section
                projection["per_host_warnings"] = per_host_warnings
                text_lines.extend(
                    cc.render_per_host_section(by_host_section, per_host_warnings)
                )

        if phase in _DEPTH_PHASES or args.depth or args.by_app_unit:
            ledger = backend.get("depth_ledger")
            if ledger is None:
                try:
                    ledger = client.get("application-units/depth-ledger")
                except AssessError:
                    ledger = {"skipped": True, "units": [], "summary": {}}
            projection["depth_ledger"] = ledger
            text_lines.extend(_render_depth_ledger(ledger, by_app_unit=args.by_app_unit))
            if args.strict_deep and _depth_unsatisfied(ledger):
                exit_nonzero = True

        if phase == "exploit":
            exploit_proj, exploit_lines, exploit_err = _exploit_projection(cfg)
            projection["exploit_policy"] = exploit_proj.get("exploit_policy")
            projection["approved_targets"] = exploit_proj.get("approved_targets")
            text_lines.extend(exploit_lines)
            if exploit_err:
                exit_nonzero = True

        if phase in _INTEL_PHASES or args.include_intel:
            intel = backend.get("intel")
            if intel is None:
                try:
                    intel = client.get_engagement("intel/readiness")
                except AssessError:
                    intel = None
            has_open, intel_lines = cc.render_intel_readiness(intel)
            projection["intel"] = intel if isinstance(intel, dict) else {}
            projection["intel_open_items"] = bool(has_open)
            text_lines.extend(intel_lines)
            if args.strict and has_open:
                exit_nonzero = True

    projection["ready"] = not exit_nonzero
    _emit(args, projection, text_lines)
    if exit_nonzero:
        sys.exit(1)


def _run_report_phase(
    client: AssessmentClient,
    args: argparse.Namespace,
    backend: dict[str, Any],
    projection: dict[str, Any],
    text_lines: list[str],
) -> bool:
    """Render the report-readiness gate + intel advisory. Returns exit_nonzero."""
    exit_nonzero = False
    readiness = backend.get("report_readiness")
    rr_ready, rr_ok, rr_blockers, rr_advisories = cc.render_report_readiness(readiness)
    projection["report_readiness"] = readiness if isinstance(readiness, dict) else {}
    if rr_ready:
        text_lines.extend(rr_ok)
    else:
        exit_nonzero = True
        text_lines.extend(rr_blockers)
    text_lines.extend(rr_advisories)

    # Depth-harness PREVIEW (see _DEPTH_PHASES above): surface the depth ledger,
    # incl. per-class `signal_classes_uncovered`, and the would-block set.
    if "report" in _DEPTH_PHASES:
        ledger = backend.get("depth_ledger")
        if ledger is None:
            try:
                ledger = client.get("application-units/depth-ledger")
            except AssessError:
                ledger = {"skipped": True, "units": [], "summary": {}}
        projection["depth_ledger"] = ledger
        text_lines.extend(
            _render_depth_ledger(ledger, by_app_unit=getattr(args, "by_app_unit", False))
        )

        would_block = None
        try:
            would_block = client.get("application-units/terminal-block")
        except AssessError:
            would_block = None
        if isinstance(would_block, dict):
            projection["depth_would_block"] = would_block
            text_lines.extend(_render_terminal_block_preview(would_block))

    intel = backend.get("intel")
    if intel is None:
        try:
            intel = client.get_engagement("intel/readiness")
        except AssessError:
            intel = None
    has_open, intel_lines = cc.render_intel_readiness(intel)
    projection["intel"] = intel if isinstance(intel, dict) else {}
    projection["intel_open_items"] = bool(has_open)
    text_lines.extend(intel_lines)
    if args.strict and has_open:
        exit_nonzero = True
    projection["ready"] = not exit_nonzero
    return exit_nonzero


def _run_scope_gate(
    cfg,
    client: AssessmentClient,
    args: argparse.Namespace,
    stage: str,
) -> tuple[dict[str, Any], bool]:
    """Run the per-scope-entry stage gate. Returns (report, stage_failed)."""
    scope_path = Path(cfg.engagement_dir) / "scope.json"
    if not scope_path.is_file():
        print(f"check-phase-readiness: scope.json not found at {scope_path}", file=sys.stderr)
        sys.exit(2)
    try:
        scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check-phase-readiness: unable to read scope.json: {exc}", file=sys.stderr)
        sys.exit(2)
    raw_hosts = scope_data.get("hosts") or []
    if not isinstance(raw_hosts, list):
        print("check-phase-readiness: scope.json `hosts` must be a list", file=sys.stderr)
        sys.exit(2)

    try:
        services = client.get("services")
    except AssessError as exc:
        print(f"check-phase-readiness: backend services fetch failed: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        surfaces = _get_all_pages(client, "surfaces")
    except AssessError as exc:
        print(f"check-phase-readiness: backend surfaces fetch failed: {exc}", file=sys.stderr)
        sys.exit(1)
    decided_hosts = cc._vendor_saas_decided_hosts(client)

    try:
        work_by_host = cc._load_work_items_by_host(client)
    except AssessError as exc:
        print(f"check-phase-readiness: unable to read work buffer: {exc}", file=sys.stderr)
        sys.exit(1)
    # The backend work buffer is the single store; "buffer present" now means the
    # buffer has any rows rather than a local cases.db existing on disk.
    buffer_present = bool(work_by_host)

    report = cc.build_scope_coverage_report(
        engagement_key=cfg.engagement_key,
        scope_data=scope_data,
        services=services if isinstance(services, list) else [],
        surfaces=surfaces if isinstance(surfaces, list) else [],
        work_by_host=work_by_host,
        decided_hosts=decided_hosts,
        required_stage=stage,
        buffer_present=buffer_present,
        strict_vendor_saas=bool(args.strict_vendor_saas),
    )
    return report, (not report["ready"])


def _get_all_pages(client: AssessmentClient, endpoint: str) -> Any:
    pager = getattr(client, "get_all_pages", None)
    if callable(pager):
        return pager(endpoint)
    return client.get(endpoint)


def _run_by_host(
    client: AssessmentClient,
    args: argparse.Namespace,
    literals: set[str],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Fetch + annotate the C40 per-host outcome projection."""
    try:
        payload = client.get("coverage-readiness/by-host")
    except AssessError as exc:
        print(f"check-phase-readiness: backend per-host coverage fetch failed: {exc}",
              file=sys.stderr)
        sys.exit(1)
    section = cc.annotate_by_host_payload(payload if isinstance(payload, dict) else {})
    if not args.include_discovered:
        section = cc.filter_to_scope_literals(section, literals)
    warnings = cc.per_host_warning_lines(section)
    return section, warnings


def _scope_literals_from_disk(cfg) -> set[str]:
    """Explicit literal scope hosts (bare_host/url entries) read from scope.json.

    Used for the per-host literal filter on phases with no stage gate, where the
    scope report (and thus its ``explicit_literal_hosts``) was not built.
    """
    from assess.lib.scope import classify_scope_entry

    scope_path = Path(cfg.engagement_dir) / "scope.json"
    if not scope_path.is_file():
        return set()
    try:
        data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    hosts = data.get("hosts") or []
    literals: set[str] = set()
    for raw in hosts if isinstance(hosts, list) else []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        entry = classify_scope_entry(raw)
        if entry and entry.get("entry_kind") in ("bare_host", "url") and entry.get("host"):
            literals.add(entry["host"])
    return literals


def _run_redispatch(
    cfg,
    client: AssessmentClient,
    args: argparse.Namespace,
    scope_report: dict[str, Any],
    stage: str | None,
) -> dict[str, Any]:
    """Build the --auto-redispatch recommendation block."""
    if stage is None:
        return {
            "recommendations": [],
            "suppressed": [],
            "overflow": 0,
            "notes": [
                "--auto-redispatch is a no-op without a stage gate (recon/collect/"
                "consume phases only)."
            ],
        }
    prior_dispatches, dedup_degraded = cc.fetch_prior_dispatches(client)
    skills_root = cc._agent_skills_root_for_recommendations()
    return cc.build_redispatch_block(
        entries=scope_report["entries"],
        client=client,
        skills_root=skills_root,
        prior_dispatches=prior_dispatches,
        dedup_degraded=dedup_degraded,
        max_recommendations=int(args.max_recommendations),
        deny_entries=cc.out_of_scope_entries(load_scope(cfg.engagement_dir)),
    )


def _exploit_projection(cfg) -> tuple[dict[str, Any], list[str], bool]:
    """Resolve the exploit projection from scope.json (old check-exploit-gate).

    Preserves the machine-readable projection AND the same text tokens
    specialists key off:
      * ``exploit_policy == "full_send"`` → prints ``full_send``;
      * a selected/approved policy → prints the comma-list of approved slugs,
        or ``*`` when none are explicitly recorded.
    Returns ``(projection, text_lines, error)`` where ``projection`` is
    ``{"exploit_policy": ..., "approved_targets": [...] | "*"}``.
    """
    scope = load_scope(cfg.engagement_dir)
    policy = str(scope.get("exploit_policy") or "pause")
    lines: list[str] = []

    try:
        approved_targets = resolve_approved_target_slugs(cfg, scope)
    except SystemExit as exc:
        lines.append(str(exc))
        return ({"exploit_policy": policy, "approved_targets": []}, lines, True)

    if policy == "full_send":
        lines.append("full_send")
        return ({"exploit_policy": policy, "approved_targets": "*"}, lines, False)

    if approved_targets:
        lines.append(",".join(approved_targets))
        return ({"exploit_policy": policy, "approved_targets": approved_targets}, lines, False)

    lines.append("*")
    return ({"exploit_policy": policy, "approved_targets": "*"}, lines, False)


def _depth_unsatisfied(ledger: Any) -> bool:
    """True when the ledger reports ≥1 depth-unsatisfied deep_required unit."""
    if not isinstance(ledger, dict) or ledger.get("skipped"):
        return False
    summary = ledger.get("summary") or {}
    return int(summary.get("depth_unsatisfied", 0) or 0) > 0


def _render_depth_ledger(ledger: Any, *, by_app_unit: bool) -> list[str]:
    """Render the EV-ranked depth ledger as human lines."""
    lines: list[str] = []
    lines.append("")
    if not isinstance(ledger, dict):
        lines.append("depth ledger: (unavailable)")
        return lines
    if ledger.get("skipped"):
        lines.append(f"depth ledger: skipped ({ledger.get('reason', 'web-only')})")
        return lines
    summary = ledger.get("summary") or {}
    deep = int(summary.get("deep_required", 0) or 0)
    satisfied = int(summary.get("depth_satisfied", 0) or 0)
    unsatisfied = int(summary.get("depth_unsatisfied", deep - satisfied) or 0)
    lines.append(
        f"depth ledger: {deep} deep_required unit(s), {satisfied} depth-satisfied, "
        f"{unsatisfied} unsatisfied (advisory, EV-ranked)"
    )
    units = ledger.get("units") or []
    if not units:
        lines.append("  (no deep_required app units scored yet)")
        return lines
    if by_app_unit:
        for u in units:
            unit = u.get("unit") or {}
            label = f"{unit.get('host', '?')}{unit.get('path_prefix', '/')}"
            tier = unit.get("depth_tier", "?")
            missing = [e.get("family") for e in (u.get("missing_block") or [])]
            warn = [e.get("family") for e in (u.get("missing_warn") or [])]
            verdict = "satisfied" if u.get("depth_satisfied") else "UNSATISFIED"
            lines.append(
                f"  - {label} [{tier}] ev={u.get('ev_rank', 0)} {verdict}"
            )
            if missing:
                lines.append(f"      missing (block): {', '.join(str(m) for m in missing)}")
            if warn:
                lines.append(f"      missing (warn):  {', '.join(str(m) for m in warn)}")
    else:
        top = [u for u in units if not u.get("depth_satisfied")][:5]
        for u in top:
            unit = u.get("unit") or {}
            label = f"{unit.get('host', '?')}{unit.get('path_prefix', '/')}"
            missing = [e.get("family") for e in (u.get("missing_block") or [])]
            lines.append(
                f"  ! {label} [{unit.get('depth_tier', '?')}] ev={u.get('ev_rank', 0)} "
                f"missing: {', '.join(str(m) for m in missing) or '(dispatch obligation)'}"
            )
        if not top:
            lines.append("  (all deep_required units depth-satisfied)")

    # Per-class signal gaps (coverage-grain unbundle / ADR 0012). Always surfaced
    # — including for units that are family-`depth_satisfied` — because a specific
    # BLOCK_HIGH class flagged via gf coverage_items can still be uncovered while
    # the family looks covered. For DECISIVE / high-confidence units this is a
    # deferred-terminal obligation (it will block `transition-phase report`); for
    # the rest it is advisory. WS3 Part D: previously --json only.
    flagged = [u for u in units if (u.get("signal_classes_uncovered") or [])]
    if flagged:
        lines.append(
            "  per-class signal gaps (BLOCK_HIGH class flagged, not class-tested):"
        )
        for u in flagged:
            unit = u.get("unit") or {}
            label = f"{unit.get('host', '?')}{unit.get('path_prefix', '/')}"
            classes = ", ".join(str(c) for c in u["signal_classes_uncovered"])
            decisive = (
                bool(u.get("decisive_surface"))
                or str(u.get("confidence") or "") == "high"
            )
            if decisive:
                lines.append(
                    f"    - {label}: {classes} — will block at report unless "
                    "covered or deferred"
                )
            else:
                lines.append(f"    - {label}: {classes} (advisory; per-class gap)")
    return lines


def _render_terminal_block_preview(result: Any) -> list[str]:
    """Render the terminal depth-block WOULD-BLOCK set as a phase-`report`
    preview (coverage-grain unbundle / ADR 0012).

    This is a legibility preview only — it lists the app units that WOULD block
    `transition-phase report`/`complete` and how to clear each. It NEVER changes
    this advisory command's exit code (the hard block is a transition-phase
    precondition). WEB-ONLY: a ``skipped`` result (code/blue) renders nothing.
    """
    lines: list[str] = []
    if not isinstance(result, dict) or result.get("skipped"):
        return lines
    blocking = result.get("blocking") or []
    deferral_count = int(result.get("deferral_count") or 0)
    lines.append("")
    if not blocking:
        lines.append(
            "depth backstop preview: no app unit would block the report/complete "
            f"transition ({deferral_count} depth_deferral(s) recorded)."
        )
        return lines
    lines.append(
        f"depth backstop preview: {len(blocking)} app unit(s) WOULD BLOCK the "
        "report/complete transition unless covered or deferred "
        f"({deferral_count} depth_deferral(s) recorded):"
    )
    for b in blocking:
        unit = b.get("unit") or {}
        label = f"{unit.get('host', '?')}{unit.get('path_prefix', '/')}"
        if b.get("block_grain") == "class":
            classes = ", ".join(
                str(c) for c in (b.get("uncovered_classes") or [])
            ) or "?"
            lines.append(
                f"  x {label} — uncovered BLOCK_HIGH class(es): {classes}"
            )
        else:
            fams = ", ".join(
                str(f) for f in (b.get("missing_block_families") or [])
            ) or "?"
            lines.append(
                f"  x {label} — untested/undeferred/untouched; missing family: {fams}"
            )
    lines.append(
        "  -> cover the class/family (tested/signal probe or evidence-bearing "
        "coverage-item), record a depth_deferral naming the class(es), or "
        "transition with --force --reason. Preview only; this command never blocks."
    )
    return lines


def _emit(args: argparse.Namespace, projection: dict[str, Any], text_lines: list[str]) -> None:
    if args.as_json:
        print(json.dumps(projection, ensure_ascii=False, indent=2))
    else:
        for line in text_lines:
            print(line)
