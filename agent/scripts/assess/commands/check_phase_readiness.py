"""vigil assess check-phase-readiness — ONE phase-aware readiness command.

Wave 6d (command consolidation, depth-gate §6 / master plan Wave 6) folds the
following five standalone commands into this one phase-keyed command (no
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

Flag semantics (master plan §6 "Consolidated-command flag semantics"):
  * ``--depth``           — show the depth ledger detail (consume/verify).
  * ``--by-app-unit``     — render the depth ledger broken out per app unit.
  * ``--by-host``         — C40 per-host outcome table (recon/collect/consume).
  * ``--auto-redispatch`` — per-failing-entry next-dispatch RECOMMENDATIONS.
  * ``--include-intel``   — force-include the intel advisory even on a phase
    that does not fold it by default.
  * ``--strict-deep``     — gate on app-unit DETECTION (default OFF; detection is
    warm-first). Escalates an unsatisfied deep_required unit to a non-zero exit.
  * ``--strict``          — CI-style: exit 1 on ANY open advisory item (preserves
    the old ``check-intel-readiness --strict``). Does NOT imply ``--strict-deep``.
  * ``--json``            — emit the structured projection (the downstream contract).

The terminal ``report``/``complete`` hard block is INDEPENDENT of both ``--strict``
and ``--strict-deep`` — it lives on the ``transition-phase`` precondition and is
unaffected by this advisory command.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from assess.lib import coverage_checks as cc
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.exploit_targets import resolve_approved_target_slugs
from assess.lib.scope import load_scope


PHASES = ("recon", "collect", "consume", "verify", "exploit", "report")

_PHASE_ALIASES = {"consume-test": "consume", "consume_test": "consume"}

_CLI_PHASE_CHOICES = (*PHASES, *_PHASE_ALIASES)

_INTEL_PHASES = frozenset({"recon", "consume", "report"})

_PHASE_REQUIRE_STAGE: dict[str, str | None] = {
    "recon": "enum",
    "collect": "collection",
    "consume": "consumption",
    "verify": None,
    "exploit": None,
    "report": None,
}

_DEPTH_PHASES = frozenset({"consume", "verify"})

_COVERAGE_PHASES = frozenset({"recon", "collect", "consume", "verify", "exploit"})


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
        help="Engagement phase to check readiness for (accepts the persisted "
             "consume-test alias for consume).",
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
            "ready-to-run next-dispatch RECOMMENDATION (role + scope-host + "
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
            "CI-style: exit 1 on any open advisory item (preserves the old "
            "check-intel-readiness --strict). Does NOT imply --strict-deep."
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
    phase = _PHASE_ALIASES.get(args.phase, args.phase)

    projection: dict[str, Any] = {"phase": phase, "engagement_key": cfg.engagement_key}
    text_lines: list[str] = []
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
            if phase == "consume":
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
        surfaces = client.get("surfaces")
    except AssessError as exc:
        print(f"check-phase-readiness: backend surfaces fetch failed: {exc}", file=sys.stderr)
        sys.exit(1)
    decided_hosts = cc._vendor_saas_decided_hosts(client)

    db_path = Path(cfg.engagement_dir) / "cases.db"
    buffer_present = db_path.is_file()
    try:
        work_by_host = cc._load_work_items_by_host(db_path)
    except sqlite3.Error as exc:
        print(f"check-phase-readiness: unable to read work buffer: {exc}", file=sys.stderr)
        sys.exit(1)

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
    db_path = Path(cfg.engagement_dir) / "cases.db"
    skills_root = cc._agent_skills_root_for_recommendations()
    return cc.build_redispatch_block(
        entries=scope_report["entries"],
        db_path=db_path,
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
    return lines


def _emit(args: argparse.Namespace, projection: dict[str, Any], text_lines: list[str]) -> None:
    if args.as_json:
        print(json.dumps(projection, ensure_ascii=False, indent=2))
    else:
        for line in text_lines:
            print(line)
