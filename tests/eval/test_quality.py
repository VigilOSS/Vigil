"""Layer 2 — quality scoring.

A definition-driven scorer over captured engagement outputs (lists of finding
payloads). Each definition YAML file under ``tests/eval/definitions/`` names a
fixture (JSON array of finding payloads) and asserts constraints. Assertions
support two enforcement modes:

  strict — test FAILS if the assertion is not satisfied
  soft   — a warning is printed but the test does NOT fail

Supported assertion kinds:

  min_findings          — engagement must contain >= value findings
  max_findings          — engagement must contain <= value findings
  expected_cwes         — every listed CWE ID must appear in at least one
                          finding's details.cwe_id
  expected_severities   — every listed severity must appear in at least one
                          finding's severity field
  severity_distribution — for each severity key, optionally enforce:
                            min: <int>  (at least N findings with that severity)
                            max: <int>  (at most N findings with that severity)
  attacker_outcome_present — every finding's details.impact must be a non-empty
                             string (enforces the project's attacker-outcome
                             discipline)

Definition format: YAML (PyYAML 6.x is present in the backend venv).
Fixture format: JSON array of finding payloads.

The conftest inserts ``agent/scripts`` onto sys.path. No additional libraries
are added — all deps are already available in the backend venv.
"""
from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest
import yaml

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
_DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"

# Captured at import time so inline tests can temporarily redirect _FIXTURES_DIR
# regardless of the module's __name__ when run from different working directories.
_THIS_MODULE = sys.modules[__name__]


# ---------------------------------------------------------------------------
# Definition loader + scorer
# ---------------------------------------------------------------------------


def _load_definition(def_path: Path) -> dict[str, Any]:
    return yaml.safe_load(def_path.read_text(encoding="utf-8"))


def _load_fixture(fixture_name: str) -> list[dict[str, Any]]:
    path = _FIXTURES_DIR / fixture_name
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list), f"{fixture_name} must be a JSON array of findings"
    return data


def _score_assertion(
    assertion: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[str]:
    """Score one assertion against the finding set.

    Returns a list of failure messages (empty = pass).
    """
    kind = assertion.get("kind")
    value = assertion.get("value")
    failures: list[str] = []

    if kind == "min_findings":
        if len(findings) < int(value):
            failures.append(
                f"min_findings: got {len(findings)}, expected >= {value}"
            )

    elif kind == "max_findings":
        if len(findings) > int(value):
            failures.append(
                f"max_findings: got {len(findings)}, expected <= {value}"
            )

    elif kind == "expected_cwes":
        present = {
            f.get("details", {}).get("cwe_id", "")
            for f in findings
            if isinstance(f.get("details"), dict)
        }
        for cwe in value:
            if cwe not in present:
                failures.append(
                    f"expected_cwes: CWE '{cwe}' not found in any finding's "
                    f"details.cwe_id (found: {sorted(present)})"
                )

    elif kind == "expected_severities":
        present = {f.get("severity", "") for f in findings}
        for sev in value:
            if sev not in present:
                failures.append(
                    f"expected_severities: severity '{sev}' not found in any "
                    f"finding (found: {sorted(present)})"
                )

    elif kind == "severity_distribution":
        from collections import Counter
        sev_counts: Counter[str] = Counter(f.get("severity", "") for f in findings)
        for sev, constraints in value.items():
            count = sev_counts.get(sev, 0)
            if "min" in constraints and count < constraints["min"]:
                failures.append(
                    f"severity_distribution: severity '{sev}' has {count} "
                    f"findings, expected >= {constraints['min']}"
                )
            if "max" in constraints and count > constraints["max"]:
                failures.append(
                    f"severity_distribution: severity '{sev}' has {count} "
                    f"findings, expected <= {constraints['max']}"
                )

    elif kind == "attacker_outcome_present":
        for idx, finding in enumerate(findings):
            details = finding.get("details") or {}
            impact = details.get("impact", "")
            if not (isinstance(impact, str) and impact.strip()):
                title = finding.get("title", f"finding[{idx}]")
                failures.append(
                    f"attacker_outcome_present: finding '{title}' has an empty "
                    "or missing details.impact"
                )

    else:
        failures.append(f"Unknown assertion kind: {kind!r}")

    return failures


def _run_definition(def_path: Path) -> None:
    """Load a definition file and score all its assertions.

    Strict failures are collected and raised together.
    Soft failures are emitted as ``warnings.warn`` messages so they show up
    in the test output without failing the suite.
    """
    defn = _load_definition(def_path)
    fixture_name = defn["fixture"]
    findings = _load_fixture(fixture_name)
    assertions = defn.get("assertions", [])

    strict_failures: list[str] = []

    for assertion in assertions:
        mode = assertion.get("mode", "strict")
        failures = _score_assertion(assertion, findings)
        if not failures:
            continue
        for msg in failures:
            qualified = f"[{def_path.name} / {fixture_name}] {msg}"
            if mode == "strict":
                strict_failures.append(qualified)
            else:
                warnings.warn(f"SOFT ASSERTION: {qualified}", stacklevel=2)

    if strict_failures:
        raise AssertionError(
            "Quality assertion failures:\n"
            + "\n".join(f"  - {m}" for m in strict_failures)
        )


# ---------------------------------------------------------------------------
# Parametrized test: one test per definition file
# ---------------------------------------------------------------------------


def _definition_files() -> list[Path]:
    if not _DEFINITIONS_DIR.exists():
        return []
    return sorted(_DEFINITIONS_DIR.glob("*.yaml"))


@pytest.mark.parametrize(
    "def_path",
    _definition_files(),
    ids=[p.stem for p in _definition_files()],
)
def test_quality_definition(def_path: Path) -> None:
    """Score engagement output against its definition's assertions."""
    _run_definition(def_path)


# ---------------------------------------------------------------------------
# Direct unit tests for the scorer functions (guard against false-green)
# ---------------------------------------------------------------------------


def test_scorer_min_findings_fails_correctly():
    """Scorer correctly fails when finding count is below min_findings."""
    findings = [{"title": "A", "severity": "low", "details": {"impact": "x"}}]
    assertion = {"kind": "min_findings", "value": 3, "mode": "strict"}
    failures = _score_assertion(assertion, findings)
    assert failures, "Expected failure for min_findings=3 with 1 finding"
    assert "min_findings" in failures[0]


def test_scorer_attacker_outcome_fails_for_empty_impact():
    """Scorer catches a finding with empty details.impact."""
    findings = [
        {"title": "Good finding", "severity": "high", "details": {"impact": "RCE"}},
        {"title": "Bad finding", "severity": "medium", "details": {"impact": ""}},
    ]
    assertion = {"kind": "attacker_outcome_present", "mode": "strict"}
    failures = _score_assertion(assertion, findings)
    assert failures, "Expected failure for empty impact"
    assert "Bad finding" in failures[0]


def test_scorer_attacker_outcome_passes_when_all_impacts_present():
    """Scorer passes when every finding has a non-empty details.impact."""
    findings = [
        {"title": "F1", "severity": "high", "details": {"impact": "Data exfil"}},
        {"title": "F2", "severity": "low", "details": {"impact": "Session theft"}},
    ]
    assertion = {"kind": "attacker_outcome_present", "mode": "strict"}
    failures = _score_assertion(assertion, findings)
    assert failures == [], f"Unexpected failures: {failures}"


def test_scorer_expected_cwes_fails_for_missing_cwe():
    """Scorer flags a required CWE that does not appear in any finding."""
    findings = [
        {"title": "SQLi", "severity": "high", "details": {"cwe_id": "CWE-89", "impact": "x"}},
    ]
    assertion = {"kind": "expected_cwes", "value": ["CWE-89", "CWE-79"], "mode": "strict"}
    failures = _score_assertion(assertion, findings)
    assert any("CWE-79" in f for f in failures), (
        f"Expected CWE-79 missing error, got: {failures}"
    )


def test_scorer_severity_distribution_fails_when_count_below_min():
    """Scorer fails when a severity bucket is below its minimum."""
    findings = [
        {"title": "Low1", "severity": "low", "details": {"impact": "minor"}},
        {"title": "Low2", "severity": "low", "details": {"impact": "minor"}},
    ]
    assertion = {
        "kind": "severity_distribution",
        "value": {"critical": {"min": 1}},
        "mode": "strict",
    }
    failures = _score_assertion(assertion, findings)
    assert any("critical" in f for f in failures), (
        f"Expected critical severity_distribution failure, got: {failures}"
    )


# ---------------------------------------------------------------------------
# Soft-vs-strict routing tests — exercise the _run_definition dispatch path
# ---------------------------------------------------------------------------


def _make_def_path(tmp_path: Path, yaml_text: str, name: str = "inline_test.yaml") -> Path:
    """Write a YAML definition to tmp_path and return its path."""
    p = tmp_path / name
    p.write_text(yaml_text, encoding="utf-8")
    return p


def _make_fixture(tmp_path: Path, findings: list[dict], name: str = "inline_fixture.json") -> Path:
    """Write a JSON findings array to tmp_path and return its path."""
    p = tmp_path / name
    p.write_text(json.dumps(findings), encoding="utf-8")
    return p


def test_soft_assertion_miss_emits_warning_does_not_fail(tmp_path: Path) -> None:
    """A soft assertion that fails must emit a UserWarning and NOT raise.

    We point _FIXTURES_DIR at tmp_path so _load_fixture resolves our inline file.
    """
    # A finding that passes min_findings (strict) but fails expected_cwes (soft).
    findings = [
        {
            "title": "Only finding",
            "severity": "high",
            "details": {"cwe_id": "CWE-89", "impact": "SQL injection"},
        }
    ]
    fixture_name = "soft_miss_fixture.json"
    _make_fixture(tmp_path, findings, name=fixture_name)

    def_yaml = f"""\
fixture: {fixture_name}
assertions:
  - kind: min_findings
    value: 1
    mode: strict
  - kind: expected_cwes
    value:
      - CWE-79
    mode: soft
"""
    def_path = _make_def_path(tmp_path, def_yaml, name="soft_miss.yaml")

    # Temporarily redirect _FIXTURES_DIR in this module so _load_fixture
    # resolves our inline fixture file.
    orig_fixtures_dir = _THIS_MODULE._FIXTURES_DIR
    _THIS_MODULE._FIXTURES_DIR = tmp_path
    try:
        with pytest.warns(UserWarning, match="SOFT ASSERTION"):
            _run_definition(def_path)
    finally:
        _THIS_MODULE._FIXTURES_DIR = orig_fixtures_dir


def test_strict_assertion_miss_raises(tmp_path: Path) -> None:
    """A strict assertion that fails must raise AssertionError."""
    findings = [
        {
            "title": "Low severity finding",
            "severity": "low",
            "details": {"cwe_id": "CWE-89", "impact": "Minor"},
        }
    ]
    fixture_name = "strict_miss_fixture.json"
    _make_fixture(tmp_path, findings, name=fixture_name)

    def_yaml = f"""\
fixture: {fixture_name}
assertions:
  - kind: expected_cwes
    value:
      - CWE-200
    mode: strict
"""
    def_path = _make_def_path(tmp_path, def_yaml, name="strict_miss.yaml")

    orig_fixtures_dir = _THIS_MODULE._FIXTURES_DIR
    _THIS_MODULE._FIXTURES_DIR = tmp_path
    try:
        with pytest.raises(AssertionError, match="Quality assertion failures"):
            _run_definition(def_path)
    finally:
        _THIS_MODULE._FIXTURES_DIR = orig_fixtures_dir
