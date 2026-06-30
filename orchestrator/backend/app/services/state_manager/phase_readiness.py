"""Wave 6d — phase-keyed readiness assembly (command consolidation).

This module is the backend half of the consolidated ``check-phase-readiness``
CLI command. It exposes ONE entry point — :func:`phase_readiness` — that the API
serves at ``GET /engagements/{key}/assessment/phase-readiness?phase=…``. Per
phase it ASSEMBLES a result by CALLING the existing, unchanged state-manager
functions — it never re-implements their logic and never renames them:

  * ``coverage_readiness``  — surface-resolution gate (old ``check-coverage``)
  * ``per_host_coverage``   — C40 per-host outcome projection (old
                              ``check-scope-coverage --by-host``)
  * ``report_readiness``    — terminal report gate (old ``check-report-readiness``)
  * ``depth_ledger``        — the EV-ranked depth ledger (the consume heart)
  * ``intel_readiness``     — advisory intel-closure view (old
                              ``check-intel-readiness``)

Those function names (``coverage_readiness`` / ``report_readiness`` /
``per_host_coverage`` / ``depth_ledger`` / ``intel_readiness``) and the HTTP
routes that serve them are STABLE — the phase-transition gate, ``report_export``,
and the frontend bind to them. This module is purely ADDITIVE: it calls them
behind a new front door.

Phase composition (depth-gate §6 / master plan Wave 6):

  * ``recon``   → coverage gate + per-host outcomes + intel advisory
  * ``collect`` → coverage gate + per-host outcomes
  * ``consume`` → coverage gate + per-host outcomes + the depth ledger + intel
  * ``verify``  → coverage gate + the depth ledger (carry-over)
  * ``exploit`` → coverage gate (the exploit projection is resolved CLI-side
                  from scope.json, which the backend does not read here)
  * ``report``  → report-readiness blockers + intel advisory

DOCTRINE: this is a READ-ONLY assembly. It never mutates state, never raises to
block a transition, and the underlying terminal block stays where it lives
(``transition_phase`` precondition over ``terminal_depth_block``). The CLI maps
the assembled payload to exit codes; the backend only assembles.
"""
from __future__ import annotations

from typing import Any, NamedTuple

from ..events import _engagement_or_404
from . import _common
from .coverage import coverage_readiness, per_host_coverage
from .depth_ledger import depth_ledger
from .report_readiness import report_readiness

PHASES: tuple[str, ...] = ("recon", "collect", "consume", "verify", "exploit", "report")

PHASE_REQUIRE_STAGE: dict[str, str | None] = {
    "recon": "enum",
    "collect": "collection",
    "consume": "consumption",
    "verify": None,
    "exploit": None,
    "report": None,
}


# ── P-1 (item 2.1) — recon-pipeline stage-completion audit ───────────────────
#
# The durable-state gates (coverage / per-host / depth ledger) answer "is the
# state consistent" but NEVER diff the command-run ledger, so a phase can read
# GREEN while katana timed out (partial corpus) and gau never ran. This audit
# closes that gap: it reads ``assessment_command_runs`` (the ONE function in the
# assembly that does — per_host_coverage deliberately does not) and diffs the
# per-stage execution outcome against a per-phase EXPECTED-STAGE checklist.
#
# To add/retune a stage, edit ``_STAGE_SPECS`` (the tool→stage map) and
# ``PHASE_EXPECTED_STAGES`` (which stages each phase expects). A run's stage is
# derived from the persisted ``tool_bin`` (the discriminator the command-run
# service already extracts at write time) — never by re-parsing argv here.


class _StageSpec(NamedTuple):
    """One pipeline stage: its id, a human label, and the tool binaries that
    satisfy it. ``tool_bins`` are matched case-insensitively against a row's
    ``tool_bin`` (preferred) or route-collapsed ``tool_name``."""

    stage: str
    label: str
    tool_bins: frozenset[str]


_STAGE_SPECS: tuple[_StageSpec, ...] = (
    _StageSpec(
        "subdomain_enum",
        "subdomain/DNS enumeration",
        frozenset({"dnsx", "subfinder", "amass", "puredns", "shuffledns", "assetfinder", "findomain"}),
    ),
    _StageSpec("http_liveness", "httpx liveness probe", frozenset({"httpx", "httprobe"})),
    _StageSpec("crawl", "katana crawl", frozenset({"katana", "gospider", "hakrawler"})),
    _StageSpec(
        "historical_urls",
        "gau historical-URL mining",
        frozenset({"gau", "gauplus", "waybackurls", "waymore"}),
    ),
    _StageSpec("secret_mining", "trufflehog secret/JS mining", frozenset({"trufflehog", "gitleaks"})),
    _StageSpec("vuln_scan", "nuclei template scan", frozenset({"nuclei"})),
)

# Reverse lookups derived once from the specs above.
_STAGE_BY_ID: dict[str, _StageSpec] = {spec.stage: spec for spec in _STAGE_SPECS}
_TOOL_TO_STAGE: dict[str, str] = {
    tool: spec.stage for spec in _STAGE_SPECS for tool in spec.tool_bins
}

# Per-phase EXPECTED-STAGE checklist. A phase absent here gets no audit
# (``applicable=False``). recon owns the full discovery pipeline; collect owns
# the active template scan. Easy to extend: add a phase → ordered stage tuple.
PHASE_EXPECTED_STAGES: dict[str, tuple[str, ...]] = {
    "recon": ("subdomain_enum", "http_liveness", "crawl", "historical_urls", "secret_mining"),
    "collect": ("vuln_scan",),
}

# Bound the offending command-run id list reported per gap so a runaway retry
# loop cannot make the report unbounded.
_MAX_GAP_RUN_IDS = 5

# Pre-terminal command-run statuses — a stage whose only runs are still in
# flight is reported as a distinct ``in_progress`` disposition rather than a
# hard failure.
_PRE_TERMINAL_STATUSES = frozenset({"queued", "running"})


def stage_completion_audit(engagement_id: int, phase: str) -> dict[str, Any]:
    """Diff the command-run ledger against the phase's EXPECTED-STAGE checklist.

    Returns an operator-actionable gap report::

        {
          "applicable": bool,            # False when the phase has no checklist
          "phase": <phase>,
          "expected_stages": [stage_id, ...],
          "satisfied_stages": [stage_id, ...],   # ≥1 clean run recorded
          "gaps": [ {stage, label, disposition, command_run_ids, action,
                     detail}, ... ],
          "open_gap_count": int,
        }

    A stage is SATISFIED when ≥1 of its command runs terminated cleanly
    (``success`` and not ``timed_out`` and not ``partial_results``). Otherwise it
    is a GAP with the worst observed disposition:

      * ``never_ran``       — expected but no command run matched the stage
      * ``timed_out``       — a run hit its deadline (likely partial corpus)
      * ``partial_results`` — a run finished but truncated its output
      * ``in_progress``     — the only runs are still queued/running
      * ``failed``          — runs terminated non-success with none of the above

    READ-ONLY and ADVISORY: it never mutates state and never raises to block a
    transition. The CLI maps an open gap to a non-zero exit only under
    ``--strict``.
    """
    expected = PHASE_EXPECTED_STAGES.get(phase, ())
    if not expected:
        return {
            "applicable": False,
            "phase": phase,
            "expected_stages": [],
            "satisfied_stages": [],
            "gaps": [],
            "open_gap_count": 0,
        }

    engagement = _engagement_or_404(engagement_id)
    runs_by_stage = _pipeline_runs_by_stage(engagement.id)

    satisfied: list[str] = []
    gaps: list[dict[str, Any]] = []
    for stage_id in expected:
        spec = _STAGE_BY_ID[stage_id]
        runs = runs_by_stage.get(stage_id, [])
        if any(_run_is_clean_success(run) for run in runs):
            satisfied.append(stage_id)
            continue
        gaps.append(_build_stage_gap(spec, runs))

    return {
        "applicable": True,
        "phase": phase,
        "expected_stages": list(expected),
        "satisfied_stages": satisfied,
        "gaps": gaps,
        "open_gap_count": len(gaps),
    }


def _pipeline_runs_by_stage(engagement_id: int) -> dict[str, list[dict[str, Any]]]:
    """Group this engagement's pipeline-tool command runs by derived stage.

    Reads ``assessment_command_runs`` filtered to the pipeline tool set (bounded)
    and buckets each row under the stage its ``tool_bin``/``tool_name`` resolves
    to. This is the ONLY function in the phase-readiness assembly that reads the
    command-run ledger — per_host_coverage stays outcome-table-only by design.
    """
    tools = sorted(_TOOL_TO_STAGE)
    if not tools:
        return {}
    placeholders = ", ".join("?" for _ in tools)
    sql = (
        "SELECT id, tool_bin, tool_name, status, timed_out, partial_results, success "
        "FROM assessment_command_runs "
        "WHERE engagement_id = ? "
        f"AND (LOWER(tool_bin) IN ({placeholders}) OR LOWER(tool_name) IN ({placeholders})) "
        "ORDER BY id ASC"
    )
    params: list[Any] = [engagement_id, *tools, *tools]
    with _common.get_connection() as connection:
        rows = connection.execute(sql, tuple(params)).fetchall()

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        data = dict(row)
        stage_id = _stage_of_row(data)
        if stage_id is None:
            continue
        grouped.setdefault(stage_id, []).append(data)
    return grouped


def _stage_of_row(row: dict[str, Any]) -> str | None:
    """Resolve a command-run row to a pipeline stage id (or None).

    Prefers the persisted ``tool_bin`` discriminator and falls back to the
    route-collapsed ``tool_name``; matching is case-insensitive.
    """
    for key in ("tool_bin", "tool_name"):
        token = str(row.get(key) or "").strip().lower()
        if token in _TOOL_TO_STAGE:
            return _TOOL_TO_STAGE[token]
    return None


def _run_is_clean_success(row: dict[str, Any]) -> bool:
    """A run satisfies its stage only if it succeeded without timeout/truncation."""
    return (
        bool(int(row.get("success") or 0))
        and not int(row.get("timed_out") or 0)
        and not int(row.get("partial_results") or 0)
    )


def _build_stage_gap(spec: _StageSpec, runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Build one gap record for an EXPECTED stage that has no clean run."""
    if not runs:
        return {
            "stage": spec.stage,
            "label": spec.label,
            "disposition": "never_ran",
            "command_run_ids": [],
            "action": "re-run-or-accept",
            "detail": (
                f"{spec.label} is expected for this phase but no command run is "
                "recorded — re-run the stage or record an accept-with-reason deferral."
            ),
        }

    timed_out = [r for r in runs if int(r.get("timed_out") or 0)]
    partial = [r for r in runs if int(r.get("partial_results") or 0)]
    in_flight = [r for r in runs if str(r.get("status") or "").strip().lower() in _PRE_TERMINAL_STATUSES]
    if timed_out:
        disposition, offending = "timed_out", timed_out
        why = "timed out (likely a partial corpus)"
    elif partial:
        disposition, offending = "partial_results", partial
        why = "finished but truncated its output corpus"
    elif in_flight:
        disposition, offending = "in_progress", in_flight
        why = "is still in flight (queued/running)"
    else:
        disposition, offending = "failed", runs
        why = "terminated without a successful run"

    offending_ids = sorted(int(r["id"]) for r in offending)[:_MAX_GAP_RUN_IDS]
    return {
        "stage": spec.stage,
        "label": spec.label,
        "disposition": disposition,
        "command_run_ids": offending_ids,
        "action": "re-run-or-accept",
        "detail": (
            f"{spec.label} {why}; re-run the stage or record an "
            f"accept-with-reason deferral (offending run id(s): "
            f"{', '.join(str(i) for i in offending_ids) or 'n/a'})."
        ),
    }


def _intel_readiness(engagement_id: int) -> dict[str, Any]:
    """Call the intel-closure advisory (red-only) defensively.

    Imported lazily so this state-manager module does not create an import
    cycle with ``services.intel`` (which imports state-manager helpers). A
    backend without the intel service still assembles the rest of the payload.
    """
    try:
        from ..intel import intel_readiness as _intel
    except Exception:
        return {"applicable": False, "engagement_type": "unknown",
                "open_high_cves": [], "open_leads": [],
                "exploited_unlinked_cves": [], "dangling_links": []}
    return _intel(engagement_id)


def phase_readiness(engagement_id: int, phase: str) -> dict[str, Any]:
    """Assemble the per-phase readiness payload by calling the existing gates.

    The phase is normalized (``consume-test`` → ``consume``). An unknown phase
    raises ``ValueError`` (the API turns it into a 422). The returned payload
    always carries::

        {
          "phase": <normalized phase>,
          "engagement_key": <key>,
          "ready": bool,                 # phase-appropriate gate verdict
          "blockers": [ ... ],           # phase-appropriate blockers
          "require_stage": <stage|None>, # the old --require-stage mapping
          ... phase-specific structured payloads (see below) ...
        }

    Phase-specific keys:
      * recon/collect/consume → ``coverage`` (coverage_readiness),
        ``per_host_coverage`` (C40 projection)
      * recon/collect         → ``stage_audit`` (P-1 command-run stage-completion
        audit — the ONLY assembly member that reads the command-run ledger)
      * consume/verify        → ``depth_ledger``
      * recon/consume/report  → ``intel`` (intel_readiness advisory)
      * report                → ``report_readiness`` (the terminal report gate)
    """
    normalized = _normalize_phase(phase)
    engagement = _engagement_or_404(engagement_id)
    out: dict[str, Any] = {
        "phase": normalized,
        "engagement_key": getattr(engagement, "engagement_key", ""),
        "require_stage": PHASE_REQUIRE_STAGE.get(normalized),
    }

    if normalized == "report":
        rr = report_readiness(engagement_id)
        out["report_readiness"] = rr
        out["ready"] = bool(rr.get("ready", False))
        out["blockers"] = list(rr.get("blockers") or [])
        out["advisories"] = list(rr.get("advisories") or [])
        out["intel"] = _intel_readiness(engagement_id)
        return out

    coverage = coverage_readiness(engagement_id)
    out["coverage"] = coverage
    out["ready"] = bool(coverage.get("ready", False))
    out["blockers"] = list(coverage.get("blockers") or [])

    if normalized in ("recon", "collect", "consume"):
        out["per_host_coverage"] = per_host_coverage(engagement_id)

    # P-1: fold the command-run stage-completion audit into the phases that own
    # an EXPECTED-STAGE checklist (the recon/collect pipeline). Purely additive
    # and advisory — the CLI decides whether an open gap fails --strict.
    if normalized in PHASE_EXPECTED_STAGES:
        out["stage_audit"] = stage_completion_audit(engagement_id, normalized)

    if normalized in ("consume", "verify"):
        out["depth_ledger"] = depth_ledger(engagement_id)

    if normalized in ("recon", "consume"):
        out["intel"] = _intel_readiness(engagement_id)

    return out


def _normalize_phase(phase: str) -> str:
    raw = str(phase or "").strip().lower()
    if raw in ("consume-test", "consume_test"):
        raw = "consume"
    if raw not in PHASES:
        raise ValueError(
            f"unknown phase {phase!r}; expected one of {', '.join(PHASES)}"
        )
    return raw


__all__ = [
    "phase_readiness",
    "stage_completion_audit",
    "PHASES",
    "PHASE_REQUIRE_STAGE",
    "PHASE_EXPECTED_STAGES",
]
