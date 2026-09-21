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
  white_box_finding_contract — require an exact set of code-finding identities,
                               canonical file locations, named proof fields,
                               an allowed evidence type, and one exact sealed
                               source identity

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

from assess.lib.schema_validation import collect_validation_errors, load_schema

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
_DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"
_FINDING_SCHEMA = load_schema("finding-record.schema.json")

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
    for index, finding in enumerate(data):
        errors = collect_validation_errors(
            finding,
            _FINDING_SCHEMA,
            path=f"{fixture_name}[{index}]",
        )
        assert not errors, (
            f"{fixture_name} contains an invalid finding at index {index}:\n"
            + "\n".join(f"  - {error}" for error in errors)
        )
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

    elif kind == "white_box_finding_contract":
        contract = value if isinstance(value, dict) else {}
        expected_rows = contract.get("expected_findings", [])
        expected_code_snapshot = contract.get("expected_code_snapshot")
        expected_snapshot_valid = (
            isinstance(expected_code_snapshot, dict)
            and type(expected_code_snapshot.get("repo_id")) is int
            and expected_code_snapshot["repo_id"] >= 1
            and type(expected_code_snapshot.get("repo_generation")) is int
            and expected_code_snapshot["repo_generation"] >= 1
            and isinstance(expected_code_snapshot.get("source_manifest_digest"), str)
            and len(expected_code_snapshot["source_manifest_digest"]) == 64
            and all(
                character in "0123456789abcdef"
                for character in expected_code_snapshot["source_manifest_digest"]
            )
        )
        if not expected_snapshot_valid:
            failures.append(
                "white_box_finding_contract: value must declare expected_code_snapshot "
                "with positive repo_id/repo_generation and a lowercase SHA-256 digest"
            )
        required_proof_fields = contract.get("required_proof_fields", [])
        allowed_evidence_types = set(contract.get("allowed_evidence_types", []))

        def identity(finding: dict[str, Any]) -> tuple[str, str, str]:
            details = finding.get("details")
            return (
                str(finding.get("defect_family", "")),
                str(finding.get("canonical_location", "")),
                str(details.get("cwe_id", "")) if isinstance(details, dict) else "",
            )

        expected_identities = sorted(
            (
                str(row.get("defect_family", "")),
                str(row.get("canonical_location", "")),
                str(row.get("cwe_id", "")),
            )
            for row in expected_rows
            if isinstance(row, dict)
        )
        actual_identities = sorted(identity(finding) for finding in findings)
        if actual_identities != expected_identities:
            failures.append(
                "white_box_finding_contract: exact finding identity mismatch; "
                f"expected {sorted(expected_identities)}, got {sorted(actual_identities)}"
            )

        for idx, finding in enumerate(findings):
            title = str(finding.get("title") or f"finding[{idx}]")
            location = finding.get("canonical_location")
            if not (
                isinstance(location, str)
                and location.startswith("file:")
                and location.rsplit(":", 1)[-1].isdigit()
                and bool(location.removeprefix("file:").rsplit(":", 1)[0])
            ):
                failures.append(
                    "white_box_finding_contract: finding "
                    f"'{title}' lacks a canonical file location in file:path:line form"
                )

            details = finding.get("details")
            details = details if isinstance(details, dict) else {}
            for field in required_proof_fields:
                proof = details.get(field)
                if not (isinstance(proof, str) and proof.strip()):
                    failures.append(
                        "white_box_finding_contract: finding "
                        f"'{title}' has empty or missing details.{field}"
                    )

            evidence_type = finding.get("evidence_type")
            if evidence_type not in allowed_evidence_types:
                failures.append(
                    "white_box_finding_contract: finding "
                    f"'{title}' evidence_type {evidence_type!r} is not one of "
                    f"{sorted(allowed_evidence_types)}"
                )

            provenance = finding.get("provenance")
            actual_code_snapshot = (
                provenance.get("code_snapshot")
                if isinstance(provenance, dict)
                else None
            )
            if expected_snapshot_valid and actual_code_snapshot != expected_code_snapshot:
                failures.append(
                    "white_box_finding_contract: finding "
                    f"'{title}' code snapshot mismatch; expected "
                    f"{expected_code_snapshot!r}, got {actual_code_snapshot!r}"
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
        if mode not in {"strict", "soft"}:
            raise AssertionError(
                f"[{def_path.name} / {fixture_name}] assertion mode must be "
                f"'strict' or 'soft', got {mode!r}"
            )
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


def test_quality_definition_roster_is_nonempty() -> None:
    assert _definition_files(), "quality eval must ship at least one definition"


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


def _white_box_contract() -> dict[str, Any]:
    return {
        "kind": "white_box_finding_contract",
        "value": {
            "expected_findings": [
                {
                    "defect_family": "buffer-overflow",
                    "canonical_location": "file:src/parser.c:41",
                    "cwe_id": "CWE-122",
                }
            ],
            "expected_code_snapshot": {
                "repo_id": 1,
                "repo_generation": 7,
                "source_manifest_digest": "a" * 64,
            },
            "required_proof_fields": [
                "entry_point",
                "sink",
                "taint_path",
                "guards_evaluated",
                "remediation",
            ],
            "allowed_evidence_types": ["code-inferred", "network-confirmed"],
        },
        "mode": "strict",
    }


def _white_box_finding() -> dict[str, Any]:
    return {
        "title": "Parser overflow",
        "defect_family": "buffer-overflow",
        "canonical_location": "file:src/parser.c:41",
        "evidence_type": "code-inferred",
        "provenance": {
            "code_snapshot": {
                "repo_id": 1,
                "repo_generation": 7,
                "source_manifest_digest": "a" * 64,
            }
        },
        "details": {
            "cwe_id": "CWE-122",
            "entry_point": "parse_packet",
            "sink": "memcpy",
            "taint_path": "packet -> length -> memcpy",
            "guards_evaluated": "No length guard",
            "remediation": "Reject oversized lengths",
        },
    }


def test_scorer_white_box_contract_accepts_exact_identity_and_complete_proof():
    failures = _score_assertion(_white_box_contract(), [_white_box_finding()])
    assert failures == [], f"Unexpected failures: {failures}"


def test_scorer_white_box_contract_rejects_identity_drift():
    finding = _white_box_finding()
    finding["details"]["cwe_id"] = "CWE-190"
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("exact finding identity" in failure for failure in failures), failures


def test_scorer_white_box_contract_rejects_noncanonical_file_location():
    finding = _white_box_finding()
    finding["canonical_location"] = "src/parser.c"
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("canonical file location" in failure for failure in failures), failures


def test_scorer_white_box_contract_rejects_missing_proof_field():
    finding = _white_box_finding()
    finding["details"]["taint_path"] = ""
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("details.taint_path" in failure for failure in failures), failures


def test_scorer_white_box_contract_rejects_untyped_evidence():
    finding = _white_box_finding()
    finding["evidence_type"] = None
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("evidence_type" in failure for failure in failures), failures


def test_scorer_white_box_contract_rejects_missing_snapshot_binding():
    finding = _white_box_finding()
    finding["provenance"] = {}
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("code snapshot mismatch" in failure for failure in failures), failures


def test_scorer_white_box_contract_rejects_snapshot_identity_drift():
    finding = _white_box_finding()
    finding["provenance"]["code_snapshot"]["repo_generation"] = 8
    failures = _score_assertion(_white_box_contract(), [finding])
    assert any("code snapshot mismatch" in failure for failure in failures), failures


def test_scorer_white_box_contract_requires_expected_snapshot_identity():
    contract = _white_box_contract()
    del contract["value"]["expected_code_snapshot"]

    failures = _score_assertion(contract, [_white_box_finding()])

    assert any("must declare expected_code_snapshot" in failure for failure in failures), failures


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


def _valid_fixture_finding(
    *, title: str = "Only finding", severity: str = "high", cwe_id: str = "CWE-89"
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "sql-injection",
        "root_cause_key": "",
        "auth_context": "anonymous",
        "canonical_location": "https://target.example/search",
        "summary": "SQL injection reaches the search query.",
        "evidence_ref": "",
        "notes": "",
        "details": {
            "cwe_id": cwe_id,
            "evidence": "A quote closes the query and changes the response.",
            "impact": "An attacker can read database rows.",
        },
    }


def test_soft_assertion_miss_emits_warning_does_not_fail(tmp_path: Path) -> None:
    """A soft assertion that fails must emit a UserWarning and NOT raise.

    We point _FIXTURES_DIR at tmp_path so _load_fixture resolves our inline file.
    """
    # A finding that passes min_findings (strict) but fails expected_cwes (soft).
    findings = [_valid_fixture_finding()]
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
    findings = [_valid_fixture_finding(title="Low severity finding", severity="low")]
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


def test_fixture_schema_is_validated_before_scoring(tmp_path: Path) -> None:
    fixture_name = "invalid_fixture.json"
    invalid = _valid_fixture_finding()
    del invalid["details"]["evidence"]
    _make_fixture(tmp_path, [invalid], name=fixture_name)
    def_path = _make_def_path(
        tmp_path,
        f"fixture: {fixture_name}\nassertions:\n  - kind: min_findings\n    value: 1\n",
        name="invalid_fixture.yaml",
    )

    orig_fixtures_dir = _THIS_MODULE._FIXTURES_DIR
    _THIS_MODULE._FIXTURES_DIR = tmp_path
    try:
        with pytest.raises(AssertionError, match="evidence"):
            _run_definition(def_path)
    finally:
        _THIS_MODULE._FIXTURES_DIR = orig_fixtures_dir


def test_assertion_mode_outside_strict_or_soft_is_rejected(tmp_path: Path) -> None:
    fixture_name = "valid_fixture.json"
    _make_fixture(tmp_path, [_valid_fixture_finding()], name=fixture_name)
    def_path = _make_def_path(
        tmp_path,
        (
            f"fixture: {fixture_name}\nassertions:\n"
            "  - kind: min_findings\n    value: 1\n    mode: warning\n"
        ),
        name="invalid_mode.yaml",
    )

    orig_fixtures_dir = _THIS_MODULE._FIXTURES_DIR
    _THIS_MODULE._FIXTURES_DIR = tmp_path
    try:
        with pytest.raises(AssertionError, match="strict.*soft.*warning"):
            _run_definition(def_path)
    finally:
        _THIS_MODULE._FIXTURES_DIR = orig_fixtures_dir
