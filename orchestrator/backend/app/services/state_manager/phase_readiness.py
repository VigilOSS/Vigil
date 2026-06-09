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

Those four function names (``coverage_readiness`` / ``report_readiness`` /
``per_host_coverage`` / ``depth_ledger``) and the HTTP routes that serve them
are STABLE — the phase-transition gate, ``report_export``, and the frontend bind
to them. This module is purely ADDITIVE: it calls them behind a new front door.

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

from typing import Any

from ..events import _engagement_or_404
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


__all__ = ["phase_readiness", "PHASES", "PHASE_REQUIRE_STAGE"]
