"""Contract tests for ``vigil assess eval-capture`` (blueprint §7).

Deterministic, NO live LLM. Seeds an engagement + findings via the TestClient
(mirroring test_dispatch_handoffs_api.py:17-58), fetches the RAW serialized rows
through ``GET /findings`` (so ``details_json``/``provenance_json`` arrive as JSON
STRINGS plus the extra DB columns, exactly as in production), then drives the
capture module's pure functions. Asserts:

  (a) every emitted record validates against finding-record.schema.json,
      details/provenance are dicts, no details_json/id/created_at leak, links==[]
  (b) replay-green: the scaffolded fixture+definition pass the eval harness
      (monkeypatch test_quality _FIXTURES_DIR/_DEFINITIONS_DIR → tmp_path)
  (c) idempotency: re-capture is byte-identical
  (d) --check exits 0 unchanged, non-zero after mutating a seeded severity
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Put agent/scripts on sys.path so assess.* imports resolve (mirrors
# tests/eval/conftest.py and test_aith_cli.py).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_ROOT = _REPO_ROOT / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from assess.commands import eval_capture  # noqa: E402
from assess.lib.schema_validation import collect_validation_errors, load_schema  # noqa: E402

ENGAGEMENT_KEY = "2026-05-01-090000-evalcap"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


# ---------------------------------------------------------------------------
# Seed helpers (mirror test_dispatch_handoffs_api.py:17-58)
# ---------------------------------------------------------------------------


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://target.example",
                "hostname": "target.example",
                "created_at": "2026-05-01T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "target.example",
                "hosts": ["target.example"],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")
    return eng


def _schema_example_bodies() -> list[dict]:
    """The two finding-record schema examples (finding-record.schema.json:413-515).

    Used verbatim as POST bodies so the seed exercises the real backend write
    path (which splits ``details``/``provenance`` into ``*_json`` columns).
    """
    schema = load_schema("finding-record.schema.json")
    examples = [dict(ex) for ex in schema["examples"]]
    # Give each a distinct canonical slug (<PREFIX>-<>=3 digits>) so list
    # ordering + filters are exercisable.
    examples[0]["slug"] = "VA-001"
    examples[1]["slug"] = "VA-002"
    return examples


def _seed(client) -> list[dict]:
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    for body in _schema_example_bodies():
        created = client.post(f"{BASE}/findings", json=body)
        assert created.status_code == 201, created.text
    rows = client.get(f"{BASE}/findings")
    assert rows.status_code == 200, rows.text
    return rows.json()


def _default_args(**overrides) -> SimpleNamespace:
    """Build the argparse-shaped namespace the capture filters/run expect."""
    args = {
        "severity": None,
        "workflow_status": None,
        "verification_state": None,
        "verification_disposition": None,
        "source_name": None,
        "slug": None,
        "search": None,
        "strict": False,
        "check": False,
    }
    args.update(overrides)
    return SimpleNamespace(**args)


@pytest.fixture
def seeded_rows(client, isolate_settings) -> list[dict]:
    _write_engagement(isolate_settings["engagements_dir"])
    return _seed(client)


# ---------------------------------------------------------------------------
# (a) transform fidelity + validate-before-write guard
# ---------------------------------------------------------------------------


def test_raw_rows_carry_json_strings_and_db_columns(seeded_rows: list[dict]) -> None:
    """Precondition: the RAW serialized rows are NOT fixture-shaped.

    Guards against the test silently passing because the backend changed to
    pre-parse details. If this fails, the transform is no longer being
    exercised against the documented #1-risk shape.
    """
    assert len(seeded_rows) == 2
    row = seeded_rows[0]
    assert isinstance(row.get("details_json"), str), "details_json must be a JSON string on the raw row"
    assert isinstance(row.get("provenance_json"), str)
    assert "id" in row and "engagement_id" in row and "created_at" in row


def test_every_emitted_record_validates_and_is_clean(seeded_rows: list[dict]) -> None:
    records = eval_capture._capture_records(seeded_rows, _default_args())
    assert len(records) == 2

    schema = load_schema("finding-record.schema.json")
    leak_keys = {
        "id",
        "engagement_id",
        "details_json",
        "provenance_json",
        "merged_into_finding_id",
        "merged_into_slug",
        "last_seen_at",
        "created_at",
        "updated_at",
        "evidence_artifact_id",
        "slug",
    }
    for record in records:
        assert collect_validation_errors(record, schema) == [], record
        assert isinstance(record["details"], dict)
        assert isinstance(record["provenance"], dict)
        assert record["links"] == []
        assert leak_keys.isdisjoint(record.keys()), f"leaked DB columns: {leak_keys & record.keys()}"

    # The unconditional guard must accept a clean capture without raising.
    eval_capture._validate_or_die(records)


def test_pending_runtime_proof_disposition_captures_and_validates(
    client, isolate_settings
) -> None:
    """Regression (Codex P2): a finding verified to ``pending_runtime_proof``
    must survive the capture transform + validate-before-write guard.

    Phase 3 added ``pending_runtime_proof`` to the backend
    (FindingVerifyRequest + VerificationDisposition StrEnum + the DB column), so
    GET /findings now serializes that value on findings in the holding state. If
    finding-record.schema.json's ``verification_disposition`` enum omits it, the
    unconditional ``_validate_or_die`` guard rejects the captured row. This test
    drives the exact scenario: seed -> verify(pending_runtime_proof) -> GET ->
    capture -> validate, asserting the record carries the disposition, VALIDATES,
    and the guard does not raise.
    """
    _write_engagement(isolate_settings["engagements_dir"])
    rows = _seed(client)
    slug = rows[0]["slug"]

    verified = client.post(
        f"{BASE}/findings/{slug}/verify",
        json={
            "disposition": "pending_runtime_proof",
            "reason_text": "Static taint path confirmed; runtime proof outstanding.",
            "source_name": "verifier",
        },
    )
    assert verified.status_code == 200, verified.text

    # GET /findings is the exact production source eval-capture consumes. The
    # holding-state row must serialize the new disposition (state -> verified,
    # disposition sticks) — this is the value that previously failed validation.
    refreshed = client.get(f"{BASE}/findings")
    assert refreshed.status_code == 200, refreshed.text
    raw_rows = refreshed.json()
    holding = next(r for r in raw_rows if r["slug"] == slug)
    assert holding["verification_disposition"] == "pending_runtime_proof"
    assert holding["verification_state"] == "verified"

    records = eval_capture._capture_records(raw_rows, _default_args())
    captured = next(
        r for r in records if r["verification_disposition"] == "pending_runtime_proof"
    )

    schema = load_schema("finding-record.schema.json")
    assert collect_validation_errors(captured, schema) == [], captured
    # The exact failure Codex flagged: the unconditional guard must NOT raise on
    # a holding-state row now that the enum includes the new disposition.
    eval_capture._validate_or_die(records)


def test_validate_or_die_hard_fails_on_schema_violation() -> None:
    """The validate-before-write guard hard-fails (SystemExit) on any error.

    A record missing the required nested ``details.evidence`` must abort.
    """
    bad = {
        "title": "Broken finding",
        "severity": "high",
        "defect_family": "x",
        "canonical_location": "loc",
        "summary": "s",
        "evidence_ref": "",
        "notes": "",
        "workflow_status": "active",
        "verification_state": "unreviewed",
        "verification_disposition": "none",
        "root_cause_key": "",
        "auth_context": "anonymous",
        "details": {"impact": "x"},  # missing evidence/remediation/steps/cvss_*
        "provenance": {},
        "links": [],
    }
    with pytest.raises(SystemExit) as exc:
        eval_capture._validate_or_die([bad])
    assert "finding-record.schema.json" in str(exc.value)


def test_filters_subset_findings(seeded_rows: list[dict]) -> None:
    """list_findings-style filters select the matching subset before transform."""
    only_high_sqli = eval_capture._capture_records(seeded_rows, _default_args(slug="VA-001"))
    assert len(only_high_sqli) == 1
    assert only_high_sqli[0]["details"]["cwe_id"] == "CWE-89"


def test_empty_impact_warns_not_strict(seeded_rows: list[dict], capsys: pytest.CaptureFixture[str]) -> None:
    """G5: an empty details.impact warns by default and hard-fails with --strict."""
    records = eval_capture._capture_records(seeded_rows, _default_args())
    records[0]["details"]["impact"] = "   "  # whitespace-only → empty

    eval_capture._enforce_impact(records, strict=False)
    assert "attacker_outcome_present" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        eval_capture._enforce_impact(records, strict=True)


# ---------------------------------------------------------------------------
# (b) replay-green against the live eval harness
# ---------------------------------------------------------------------------


def test_capture_replays_green_in_eval_harness(
    seeded_rows: list[dict], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A captured fixture + scaffolded definition pass the real eval scorer.

    Imports tests/eval/test_quality.py, redirects its _FIXTURES_DIR to tmp_path
    (supported at test_quality.py:316-322) so _load_fixture resolves our inline
    fixture by name, and runs _run_definition(def_path) — which takes an
    explicit definition path — → must not raise AssertionError.
    """
    records = eval_capture._capture_records(seeded_rows, _default_args())

    fixture_name = "golden_evalcap.json"
    fixture_path = tmp_path / fixture_name
    fixture_path.write_text(eval_capture._dump_fixture(records), encoding="utf-8")

    def_text = eval_capture._scaffold_definition(records, fixture_name)
    def_path = tmp_path / "evalcap.yaml"
    def_path.write_text(def_text, encoding="utf-8")

    # Load the harness scorer from tests/eval.
    eval_dir = _REPO_ROOT / "tests" / "eval"
    sys.path.insert(0, str(eval_dir))
    try:
        test_quality = importlib.import_module("test_quality")
    finally:
        sys.path.remove(str(eval_dir))

    # Only _FIXTURES_DIR matters here: _run_definition(def_path) resolves the
    # definition from the explicit path we pass, then resolves the fixture by
    # name via _load_fixture (which reads _FIXTURES_DIR). _DEFINITIONS_DIR is
    # only consulted by the directory-glob discovery path, which this call does
    # not exercise, so it is intentionally left unpatched.
    monkeypatch.setattr(test_quality, "_FIXTURES_DIR", tmp_path)

    # No AssertionError == replay-green.
    test_quality._run_definition(def_path)

    # The scaffolded definition must carry the captured CWEs and counts.
    defn = test_quality._load_definition(def_path)
    assert defn["fixture"] == fixture_name
    kinds = {a["kind"] for a in defn["assertions"]}
    assert {"min_findings", "max_findings", "expected_cwes", "attacker_outcome_present"} <= kinds


# ---------------------------------------------------------------------------
# (c) idempotency — re-capture is byte-identical
# ---------------------------------------------------------------------------


def test_capture_is_byte_identical_on_recapture(seeded_rows: list[dict]) -> None:
    first = eval_capture._dump_fixture(eval_capture._capture_records(seeded_rows, _default_args()))
    # Re-fetch order from the backend is updated_at DESC (time-varying); the
    # capture re-sort must make a shuffled input produce identical bytes.
    shuffled = list(reversed(seeded_rows))
    second = eval_capture._dump_fixture(eval_capture._capture_records(shuffled, _default_args()))
    assert first == second
    assert first.endswith("\n")


def test_dump_matches_golden_formatting(seeded_rows: list[dict]) -> None:
    """Output uses indent=2 + ensure_ascii=False + trailing newline like the goldens."""
    text = eval_capture._dump_fixture(eval_capture._capture_records(seeded_rows, _default_args()))
    assert isinstance(json.loads(text), list)
    assert text.startswith("[\n")
    assert text.endswith("]\n")


# ---------------------------------------------------------------------------
# (d) --check diff — green unchanged, red after a severity mutation
# ---------------------------------------------------------------------------


def test_check_no_regression_when_unchanged(seeded_rows: list[dict]) -> None:
    records = eval_capture._capture_records(seeded_rows, _default_args())
    golden = json.loads(eval_capture._dump_fixture(records))
    assert eval_capture._diff_against_golden(records, golden) == []


def test_check_flags_severity_regression(seeded_rows: list[dict]) -> None:
    """Downgrading a seeded high finding shrinks the 'high' bucket → regression."""
    golden = eval_capture._capture_records(seeded_rows, _default_args())
    # Fresh capture where one finding regressed from high → low.
    fresh = json.loads(json.dumps(golden))  # deep copy
    high_idx = next(i for i, r in enumerate(fresh) if r["severity"] == "high")
    fresh[high_idx]["severity"] = "low"

    regressions = eval_capture._diff_against_golden(fresh, golden)
    assert any("severity 'high' regressed" in m for m in regressions)


def test_check_flags_dropped_cwe_and_count(seeded_rows: list[dict]) -> None:
    golden = eval_capture._capture_records(seeded_rows, _default_args())
    fresh = [golden[0]]  # dropped one finding (and its CWE)
    regressions = eval_capture._diff_against_golden(fresh, golden)
    assert any("finding count regressed" in m for m in regressions)
    assert any("CWE coverage regressed" in m for m in regressions)


def test_check_allows_more_coverage(seeded_rows: list[dict]) -> None:
    """A fresh capture with strictly MORE findings/CWEs is not a regression."""
    golden = eval_capture._capture_records(seeded_rows, _default_args())
    extra = json.loads(json.dumps(golden[0]))
    extra["details"]["cwe_id"] = "CWE-999"
    fresh = golden + [extra]
    assert eval_capture._diff_against_golden(fresh, golden) == []


def test_check_flags_newly_empty_impact(seeded_rows: list[dict]) -> None:
    golden = eval_capture._capture_records(seeded_rows, _default_args())
    fresh = json.loads(json.dumps(golden))
    fresh[0]["details"]["impact"] = ""
    regressions = eval_capture._diff_against_golden(fresh, golden)
    assert any("attacker_outcome regressed" in m for m in regressions)
