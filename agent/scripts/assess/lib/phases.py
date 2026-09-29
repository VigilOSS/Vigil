"""Canonical engagement-phase rosters — the ONE source of truth.

Vigil runs three independent engagement tracks, each with its own ordered phase
roster that terminates in the shared ``complete`` state:

- **web** (red / runtime): ``recon → collect → consume-test → verify → exploit
  → report``.
- **code** (white-box source analysis): ``ingest → classify-map → hunt →
  verify-variant → fuzz``. This is a deliberately DISTINCT vocabulary, not an
  alternate spelling of the web one.
- **blue** (incident response): ``intake → triage → investigate → verify →
  respond → report``.

New engagements persist each enabled phase in ``scope.json.tracks``. Legacy
engagements keep ``current_phase`` and optional ``code_phase`` until repaired.

Consumers must import from here rather than re-declaring a literal:

- ``kali_audit.ALLOWED_PHASES`` — the fail-closed ``--phase`` audit enum.
- ``contracts.CATALOG_PHASES`` — the per-phase command catalog.
- ``commands/transition_phase.py`` — the guarded scope.json transition orders.
- ``commands/check_phase_readiness.py`` — the per-phase readiness composition.

The backend readiness assembly
(``orchestrator/backend/app/services/state_manager/phase_readiness.py``) cannot
import this module at runtime — the backend does not depend on the agent tree —
so it declares a matching tuple, and the frontend waterfalls declare matching
TypeScript literals. ``orchestrator/backend/tests/test_phase_roster.py`` pins
every one of those copies against this module; add a phase here and that test
tells you which surfaces still need it.

Phase values are **persisted**: ``scope.json`` carries the current phase and
``assessment_command_runs.phase`` stores the audit tag as plain TEXT. Renaming a
value therefore orphans existing engagements and historical rows; extend the
roster instead, and route any short or legacy spelling through
``PHASE_INPUT_ALIASES`` so the second spelling stays at the input boundary and
never reaches stored state or branching logic.
"""
from __future__ import annotations


#: The one state every track terminates in. Not a working phase: no readiness
#: gate, no audit tag, no per-phase operator doc.
TERMINAL_PHASE = "complete"

#: Ordered web (red / runtime) working phases — the canonical spellings that
#: land in ``scope.json.current_phase`` and in ``assessment_command_runs.phase``.
WEB_PHASES: tuple[str, ...] = (
    "recon",
    "collect",
    "consume-test",
    "verify",
    "exploit",
    "report",
)

#: Ordered white-box code-analysis working phases (``scope.json.code_phase``).
CODE_PHASES: tuple[str, ...] = (
    "ingest",
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
)

#: Ordered blue incident-response working phases (``scope.json.current_phase``).
BLUE_PHASES: tuple[str, ...] = (
    "intake",
    "triage",
    "investigate",
    "verify",
    "respond",
    "report",
)

#: The full transition orders `vigil assess transition-phase` walks, terminal
#: state included.
WEB_TRANSITION_PHASES: tuple[str, ...] = (*WEB_PHASES, TERMINAL_PHASE)
CODE_TRANSITION_PHASES: tuple[str, ...] = (*CODE_PHASES, TERMINAL_PHASE)
BLUE_TRANSITION_PHASES: tuple[str, ...] = (*BLUE_PHASES, TERMINAL_PHASE)

#: Audit tags for code-track work — one per ``CODE_PHASES`` entry, in the same
#: order, derived by the rule ``code-<first word of the phase>``. The code track
#: carries its own phase names, so its command-run rows take a ``code-``-prefixed
#: vocabulary that cannot collide with a web phase, abbreviated where the phase
#: name is compound (``code-classify`` ← ``classify-map``, ``code-verify`` ←
#: ``verify-variant``). A new code phase therefore gets its tag for free; if two
#: phases ever share a first word the derived tags would collide, which
#: ``test_phase_roster.py`` fails on.
CODE_PHASE_AUDIT_TAGS: tuple[str, ...] = tuple(
    f"code-{phase.split('-')[0]}" for phase in CODE_PHASES
)

#: Half-phase tags for mid-engagement work between formal phase transitions.
#: The dispatching agent passes these explicitly when the snapshot in scope.json
#: does not match what the dispatch was actually authorized for.
HALF_PHASE_AUDIT_TAGS: tuple[str, ...] = ("recon-pivot", "exploit-recon")

#: The complete ``--phase`` vocabulary an audited command run may be tagged
#: with. Derived, never re-spelled, so the audit enum cannot drift from the web
#: roster it extends.
AUDIT_PHASE_TAGS: tuple[str, ...] = (
    *WEB_PHASES,
    *CODE_PHASE_AUDIT_TAGS,
    *HALF_PHASE_AUDIT_TAGS,
)

#: Spellings accepted on INPUT and resolved to a canonical roster value. These
#: exist because the readiness surfaces historically used the short ``consume``
#: form; they are a boundary convenience only — nothing stores or branches on
#: them. Never add an alias whose target is not already in a roster.
PHASE_INPUT_ALIASES: dict[str, str] = {
    "consume": "consume-test",
    "consume_test": "consume-test",
}


def canonical_phase(phase: str) -> str:
    """Normalize a caller-supplied phase token to its canonical spelling.

    Lower-cases, trims, and resolves ``PHASE_INPUT_ALIASES``. An unrecognized
    value is returned normalized but unchanged — validation belongs to the
    caller, which knows which roster applies.
    """
    key = (phase or "").strip().lower()
    return PHASE_INPUT_ALIASES.get(key, key)


__all__ = [
    "AUDIT_PHASE_TAGS",
    "BLUE_PHASES",
    "BLUE_TRANSITION_PHASES",
    "CODE_PHASES",
    "CODE_PHASE_AUDIT_TAGS",
    "CODE_TRANSITION_PHASES",
    "HALF_PHASE_AUDIT_TAGS",
    "PHASE_INPUT_ALIASES",
    "TERMINAL_PHASE",
    "WEB_PHASES",
    "WEB_TRANSITION_PHASES",
    "canonical_phase",
]
