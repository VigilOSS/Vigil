"""Single-source-of-truth drift tests for the engagement-phase rosters.

`agent/scripts/assess/lib/phases.py` is the ONE place the ordered phase rosters
for the three engagement tracks (web / code / blue), the terminal phase, the
audit-tag vocabulary, and the accepted input aliases are declared. Every other
surface either imports it or must match it value-for-value:

  * ``assess.lib.kali_audit.ALLOWED_PHASES`` — the fail-closed ``--phase`` enum
  * ``assess.lib.contracts.CATALOG_PHASES`` / ``_PHASE_FILTER_ALIASES``
  * ``assess.commands.transition_phase`` — the scope.json transition orders
  * ``assess.commands.check_phase_readiness.PHASES``
  * ``assess.commands.list_commands._PHASE_CHOICES``
  * ``app.services.state_manager.phase_readiness`` — the backend readiness
    assembly (the backend cannot import the agent tree at runtime, so it keeps
    its own tuple and this test is what stops the two from diverging)
  * ``orchestrator/frontend/src/components/PhaseWaterfall.tsx`` and
    ``CodeAnalysisTab.tsx`` — the display rosters, parsed out of the TSX
  * ``agent/phases/*.md`` — the per-phase operator doc filenames

Three rosters previously disagreed (the backend readiness tuple spelled the
consume phase ``consume``, the frontend waterfall dropped ``verify`` entirely,
and the audit enum was a hand-copied literal); these tests exist so that cannot
happen silently again. Host-side modules are imported by inserting the agent
scripts root on ``sys.path``, mirroring ``test_vuln_taxonomy.py``.
"""
from __future__ import annotations

import ast
import importlib
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_ROOT = _REPO_ROOT / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from assess.commands import check_phase_readiness, list_commands, transition_phase  # noqa: E402
from assess.lib import contracts, kali_audit, phases  # noqa: E402

pr_mod = importlib.import_module("app.services.state_manager.phase_readiness")

_FRONTEND_SRC = _REPO_ROOT / "orchestrator" / "frontend" / "src" / "components"


def _module_constant(path: Path, name: str) -> object:
    """Read one module-level literal out of a .py file without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        targets = (
            [node.target] if isinstance(node, ast.AnnAssign) else getattr(node, "targets", [])
        )
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"{path.name}: no module-level `{name}` assignment")


def _tsx_roster(path: Path, const_name: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the ``(keys, labels)`` of a ``const <name> = [ {key,label}, … ]``
    array literal in a .tsx file. Parsing the literal (rather than asserting on
    prose) is what lets a Python test pin a TypeScript roster."""
    source = path.read_text(encoding="utf-8")
    match = re.search(
        rf"const {const_name}[^=]*=\s*\[(.*?)\]\s*(?:as const)?\s*;",
        source,
        re.DOTALL,
    )
    assert match, f"{path.name}: no `const {const_name} = [...]` array literal found"
    body = match.group(1)
    entries = re.findall(r'\{\s*key:\s*"([^"]+)"\s*,\s*label:\s*"([^"]+)"\s*\}', body)
    assert entries, f"{path.name}: {const_name} entries are not `{{ key, label }}` objects"
    keys, labels = zip(*entries)
    return keys, labels


# ── The rosters themselves ───────────────────────────────────────────────────


def test_track_rosters_are_ordered_and_terminate_in_complete():
    for transition_roster, work_roster in (
        (phases.WEB_TRANSITION_PHASES, phases.WEB_PHASES),
        (phases.CODE_TRANSITION_PHASES, phases.CODE_PHASES),
        (phases.BLUE_TRANSITION_PHASES, phases.BLUE_PHASES),
    ):
        assert transition_roster == (*work_roster, phases.TERMINAL_PHASE)
        assert len(set(transition_roster)) == len(transition_roster)


def test_track_boundaries_are_explicit():
    """The web and code tracks are deliberately DISTINCT vocabularies; the blue
    track deliberately reuses two web names. Pin all three overlaps so a merge
    of two tracks (or an accidental rename into another track) is loud."""
    assert set(phases.WEB_PHASES) & set(phases.CODE_PHASES) == set()
    assert set(phases.BLUE_PHASES) & set(phases.WEB_PHASES) == {"verify", "report"}
    assert set(phases.BLUE_PHASES) & set(phases.CODE_PHASES) == set()
    # ``complete`` is the one name every track shares.
    assert (
        set(phases.WEB_TRANSITION_PHASES)
        & set(phases.CODE_TRANSITION_PHASES)
        & set(phases.BLUE_TRANSITION_PHASES)
        == {phases.TERMINAL_PHASE}
    )


def test_audit_tags_extend_the_web_roster_without_re_spelling_it():
    assert phases.AUDIT_PHASE_TAGS == (
        *phases.WEB_PHASES,
        *phases.CODE_PHASE_AUDIT_TAGS,
        *phases.HALF_PHASE_AUDIT_TAGS,
    )
    assert phases.TERMINAL_PHASE not in phases.AUDIT_PHASE_TAGS


def test_code_audit_tags_cover_every_code_phase_without_collision():
    """One `code-` tag per code phase, in phase order — otherwise a specialist
    working that phase has no legal `--phase` value and its commands vanish from
    `list-commands --phase` (exactly what had happened to `code-fuzz`). The
    derivation collapses a compound phase name to its first word, so two phases
    sharing a first word would silently produce one tag."""
    assert len(phases.CODE_PHASE_AUDIT_TAGS) == len(phases.CODE_PHASES)
    assert len(set(phases.CODE_PHASE_AUDIT_TAGS)) == len(phases.CODE_PHASES)
    for tag, phase in zip(phases.CODE_PHASE_AUDIT_TAGS, phases.CODE_PHASES):
        assert tag == f"code-{phase.split('-')[0]}"


def test_input_aliases_all_resolve_into_the_canonical_roster():
    for alias, canonical in phases.PHASE_INPUT_ALIASES.items():
        assert alias not in phases.AUDIT_PHASE_TAGS, (
            f"{alias!r} is an INPUT alias; it must never become a roster value"
        )
        assert canonical in phases.AUDIT_PHASE_TAGS
        assert phases.canonical_phase(alias) == canonical
    for tag in phases.AUDIT_PHASE_TAGS:
        assert phases.canonical_phase(tag) == tag
    assert phases.canonical_phase("  CONSUME  ") == "consume-test"


# ── Every other surface matches ──────────────────────────────────────────────


def test_kali_audit_enum_is_the_shared_roster():
    assert kali_audit.ALLOWED_PHASES == phases.AUDIT_PHASE_TAGS


def test_contract_catalog_and_its_alias_map_are_the_shared_roster():
    assert contracts.CATALOG_PHASES == phases.AUDIT_PHASE_TAGS
    assert contracts.canonical_phase is phases.canonical_phase
    for token in (*phases.AUDIT_PHASE_TAGS, *phases.PHASE_INPUT_ALIASES):
        assert contracts.canonical_phase(token) == phases.canonical_phase(token)


def test_every_command_contract_tags_only_real_phases():
    """A contract carrying a typo'd or retired phase tag is a SILENT coverage
    hole: `list-commands --phase <p>` simply never surfaces that command to the
    specialist working that phase. The catalog test only checks the reverse
    direction (every phase has commands), so pin this one here."""
    unknown = {
        (contract.name, tag)
        for contract in contracts.all_command_contracts()
        for tag in contract.phase
        if tag not in phases.AUDIT_PHASE_TAGS
    }
    assert not unknown, sorted(unknown)


def test_transition_phase_orders_are_the_shared_rosters():
    assert tuple(transition_phase.WEB_PHASES) == phases.WEB_TRANSITION_PHASES
    assert tuple(transition_phase.CODE_PHASES) == phases.CODE_TRANSITION_PHASES
    assert tuple(transition_phase.BLUE_PHASES) == phases.BLUE_TRANSITION_PHASES
    for roster, order in (
        (phases.WEB_TRANSITION_PHASES, transition_phase.WEB_TRANSITION_ORDER),
        (phases.CODE_TRANSITION_PHASES, transition_phase.CODE_TRANSITION_ORDER),
        (phases.BLUE_TRANSITION_PHASES, transition_phase.BLUE_TRANSITION_ORDER),
    ):
        assert order == {phase: i for i, phase in enumerate(roster)}


def test_check_phase_readiness_uses_the_shared_web_roster():
    assert check_phase_readiness.PHASES == phases.WEB_PHASES
    assert tuple(check_phase_readiness._PHASE_REQUIRE_STAGE) == phases.WEB_PHASES
    # Every CLI --phase choice is a roster value or a declared input alias.
    assert set(check_phase_readiness._CLI_PHASE_CHOICES) == set(phases.WEB_PHASES) | set(
        phases.PHASE_INPUT_ALIASES
    )
    for group in (
        check_phase_readiness._INTEL_PHASES,
        check_phase_readiness._DEPTH_PHASES,
        check_phase_readiness._COVERAGE_PHASES,
    ):
        assert group <= set(phases.WEB_PHASES), sorted(group - set(phases.WEB_PHASES))


def test_list_commands_phase_choices_are_the_roster_plus_aliases():
    assert set(list_commands._PHASE_CHOICES) == set(phases.AUDIT_PHASE_TAGS) | set(
        phases.PHASE_INPUT_ALIASES
    )


def test_code_readiness_targets_are_the_code_roster_after_ingest():
    """The code-analysis readiness surfaces ask "ready to ENTER phase X", so
    their vocabulary is the code transition order minus its entry phase — you
    cannot be ready to enter `ingest`. Pinned across the service constant, the
    API Literal, the TS union, and the eval harness so the four cannot drift."""
    from typing import get_args, get_type_hints

    expected = phases.CODE_TRANSITION_PHASES[1:]

    from app.api import code_analysis as code_api
    from app.services import code_analysis as code_svc

    assert code_svc._CODE_READINESS_PHASES == expected
    hints = get_type_hints(code_api.get_readiness)
    assert get_args(hints["target_phase"]) == expected

    api_ts = (
        _REPO_ROOT / "orchestrator" / "frontend" / "src" / "lib" / "api.ts"
    ).read_text(encoding="utf-8")
    union = re.search(
        r'export type CodeReadinessTarget\s*=\s*((?:\s*\|\s*"[^"]+")+)\s*;', api_ts
    )
    assert union, "CodeReadinessTarget union not found in api.ts"
    assert tuple(re.findall(r'"([^"]+)"', union.group(1))) == expected

    # The eval harness lives under the ROOT `tests/` tree, whose package name
    # collides with the backend's own `tests` package, so read its literal with
    # `ast` rather than importing it.
    harness = _module_constant(
        _REPO_ROOT / "tests" / "eval" / "harnesses" / "code_workflow" / "schema.py",
        "_EXPECTED_PHASES",
    )
    assert harness == expected


def test_backend_readiness_roster_matches_the_shared_web_roster():
    """The backend cannot import the agent tree at runtime, so it declares its
    own tuple — this assertion is the only thing keeping the two identical."""
    assert pr_mod.PHASES == phases.WEB_PHASES
    assert tuple(pr_mod.PHASE_REQUIRE_STAGE) == phases.WEB_PHASES
    assert set(pr_mod.PHASE_EXPECTED_STAGES) <= set(phases.WEB_PHASES)


@pytest.mark.parametrize("alias,canonical", sorted(phases.PHASE_INPUT_ALIASES.items()))
def test_backend_normalizes_every_declared_input_alias(alias, canonical):
    assert pr_mod._normalize_phase(alias) == canonical
    assert pr_mod._normalize_phase(alias.upper()) == canonical


def test_backend_rejects_a_non_roster_phase():
    with pytest.raises(ValueError):
        pr_mod._normalize_phase("athena")


# ── Display surfaces ─────────────────────────────────────────────────────────


def test_frontend_waterfall_renders_every_web_phase_with_a_label():
    keys, labels = _tsx_roster(_FRONTEND_SRC / "PhaseWaterfall.tsx", "PHASES")
    assert keys == phases.WEB_PHASES
    assert all(label.strip() for label in labels)
    # The stored value and the display label are separate: the label map is the
    # ONLY place a phase is spelled differently from its roster value.
    assert dict(zip(keys, labels))["consume-test"] != "consume-test"


def test_frontend_code_pipeline_renders_every_code_phase_with_a_label():
    keys, labels = _tsx_roster(_FRONTEND_SRC / "CodeAnalysisTab.tsx", "CODE_PHASES")
    assert keys == phases.CODE_PHASES
    assert all(label.strip() for label in labels)


def test_web_phase_docs_exist_one_per_roster_phase():
    """`agent/phases/phase-<n>-<slug>.md` filenames carry the phase name. This
    pins the FILENAME set (not prose), which is where the README's `test` /
    `athena` drift originally came from."""
    doc_dir = _REPO_ROOT / "agent" / "phases"
    web = {
        m.group(2): p.name
        for p in doc_dir.glob("phase-*.md")
        if (m := re.fullmatch(r"phase-(\d+)-(.+)\.md", p.name))
    }
    assert set(web) == set(phases.WEB_PHASES), (
        f"web phase docs {sorted(web)} != roster {list(phases.WEB_PHASES)}"
    )

    code = [
        m.group(2)
        for p in sorted(doc_dir.glob("code-phase-*.md"))
        if (m := re.fullmatch(r"code-phase-(\d+)-(.+)\.md", p.name))
    ]
    assert len(code) == len(phases.CODE_PHASES)
    for slug, phase in zip(code, phases.CODE_PHASES):
        # phase 0's doc is `ingest-index` — a doc slug may EXTEND its phase name
        # with a hyphenated qualifier, never replace it.
        assert slug == phase or slug.startswith(f"{phase}-"), (
            f"code phase doc slug {slug!r} does not name phase {phase!r}"
        )
