"""Every gap code ``code-dependencies`` can emit is documented in its contract.

A gap is the one value in the dependency picture that says "this was not
measured". An operator who meets an undocumented gap code has no way to tell a
bounded run from an unreadable file from a coordinate that needs a parent POM,
so the honest-absence vocabulary silently degrades into noise. The roster drifted
exactly that way once: sixteen emitted codes, seven documented in the contract,
eight in the skill, four in both, five described nowhere.

The emitted set is re-derived from the source on every run rather than restated
here, so a new ``AnalysisGap`` fails this test instead of quietly joining the
undocumented five. Two emission shapes exist and both are read:

* ``AnalysisGap(gap="<literal>")`` at the construction site, and
* the ``(imports, gap, detail)`` triple ``_artifact_imports`` returns, which the
  caller forwards into ``AnalysisGap(gap=gap)``.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from assess.lib import contracts
from assess.lib.dependency_manifests import AnalysisGap


_ASSESS_ROOT = Path(contracts.__file__).resolve().parents[1]
_GAP_SOURCES = (
    _ASSESS_ROOT / "lib" / "dependency_manifests.py",
    _ASSESS_ROOT / "lib" / "dependency_picture.py",
    _ASSESS_ROOT / "commands" / "code_dependencies.py",
)
# The one gap producer that returns its code instead of naming it at the
# AnalysisGap call site. Named explicitly so a rename fails loudly here rather
# than silently shrinking the emitted set this test compares against.
_INDIRECT_PRODUCER = ("code_dependencies.py", "_artifact_imports")


def _literal_gap_kwargs(tree: ast.AST) -> set[str]:
    codes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "gap" and isinstance(keyword.value, ast.Constant):
                if isinstance(keyword.value.value, str) and keyword.value.value:
                    codes.add(keyword.value.value)
    return codes


def _returned_gap_codes(tree: ast.AST, function_name: str) -> set[str]:
    """Gap codes returned as element 1 of ``(imports, gap, detail)``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            break
    else:
        pytest.fail(
            f"{function_name} is gone or renamed; this test's derivation of the "
            "emitted gap set no longer covers it — update _INDIRECT_PRODUCER"
        )
    codes: set[str] = set()
    for statement in ast.walk(node):
        if not isinstance(statement, ast.Return):
            continue
        value = statement.value
        if not isinstance(value, ast.Tuple) or len(value.elts) != 3:
            continue
        element = value.elts[1]
        if isinstance(element, ast.Constant) and isinstance(element.value, str) and element.value:
            codes.add(element.value)
    return codes


def _emitted_gap_codes() -> set[str]:
    codes: set[str] = set()
    for source in _GAP_SOURCES:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        codes |= _literal_gap_kwargs(tree)
        if source.name == _INDIRECT_PRODUCER[0]:
            codes |= _returned_gap_codes(tree, _INDIRECT_PRODUCER[1])
    return codes


def test_gap_sources_exist():
    # A moved module would otherwise make the emitted set empty and the drift
    # assertion below vacuously true.
    for source in _GAP_SOURCES:
        assert source.is_file(), source


def test_gap_sources_name_every_module_that_constructs_a_gap():
    # _GAP_SOURCES is a hand-written list, so a fourth module emitting gaps
    # would be swept by nothing and its codes would pass undocumented. The
    # roster is checked against the tree rather than trusted.
    constructing = {
        path.relative_to(_ASSESS_ROOT).as_posix()
        for path in _ASSESS_ROOT.rglob("*.py")
        if "tests/" not in path.relative_to(_ASSESS_ROOT).as_posix()
        and "AnalysisGap(" in path.read_text(encoding="utf-8")
    }
    rostered = {source.relative_to(_ASSESS_ROOT).as_posix() for source in _GAP_SOURCES}

    assert constructing == rostered, (
        "these modules construct an AnalysisGap outside the swept roster; add "
        "them to _GAP_SOURCES or this test proves nothing about their codes"
    )


def test_a_gap_cannot_be_constructed_positionally():
    # The sweep reads `gap="<literal>"` KEYWORDS, so `AnalysisGap(path, "code",
    # detail)` would emit a code this test can never see. Keyword-only
    # construction makes that spelling impossible rather than merely unusual.
    with pytest.raises(TypeError):
        AnalysisGap("manifest.json", "unparsed_ecosystem", "detail")  # type: ignore[misc]


def test_every_emitted_gap_code_is_documented():
    emitted = _emitted_gap_codes()
    documented = {code for code, _ in contracts.DEPENDENCY_ANALYSIS_GAPS}
    assert emitted, "derivation found no gap codes at all"
    assert emitted - documented == set(), (
        "these gap codes are emitted but documented nowhere; add them to "
        "contracts.DEPENDENCY_ANALYSIS_GAPS"
    )
    assert documented - emitted == set(), (
        "these gap codes are documented but no longer emitted; drop them from "
        "contracts.DEPENDENCY_ANALYSIS_GAPS"
    )


def test_documented_gap_codes_reach_the_rendered_contract():
    text = contracts.render_contract("code-dependencies")
    for code, meaning in contracts.DEPENDENCY_ANALYSIS_GAPS:
        assert code in text, f"{code} is in the roster but never rendered"
        assert meaning.strip(), f"{code} carries no meaning"
