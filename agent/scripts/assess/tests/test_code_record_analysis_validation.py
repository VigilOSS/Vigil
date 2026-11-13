"""`code-record analysis` names every defect in a payload in one pass.

The client-side validator failed on the first missing key of the first bad
entry, so a hunter authoring one `cross_file_triggers` block paid one refused
invocation per missing key per entry — and nothing about the payload changes
between those runs, so every defect is knowable on the first read. The backend
validator (`_normalize_cross_file_triggers`) now reports them together; this is
the matching behaviour on the door the author actually types.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess.commands import code_record_analysis


def _args(path: Path, tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(analysis_json=str(path), engagement_dir=str(tmp_path))


def _payload(tmp_path: Path, **overrides) -> Path:
    item: dict[str, object] = {
        "queue_item_id": 101,
        "agent_name": "HUNT-1",
        "lease_token": "lease-101",
        "file_id": 7,
        "disposition": "clean",
    }
    item.update(overrides)
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps([item]), encoding="utf-8")
    return path


class _ForbiddenClient:
    def __init__(self, *_args, **_kwargs) -> None:
        raise AssertionError("a payload refusal must precede the client")


def test_every_malformed_trigger_key_is_named_in_one_invocation(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _payload(
        tmp_path,
        cross_file_triggers=[
            {"reason": "shared helper"},
            {"file_path": "src/helpers.py", "vuln_class": "ssrf"},
        ],
    )

    with pytest.raises(SystemExit) as exc:
        code_record_analysis.run(_args(path, tmp_path))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "cross_file_triggers entry 0 is missing file_path" in err
    assert "cross_file_triggers entry 0 is missing vuln_class" in err
    assert "cross_file_triggers entry 1 is missing reason" in err


def test_a_trigger_spelled_with_target_path_is_told_the_canonical_key(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _payload(
        tmp_path,
        cross_file_triggers=[
            {
                "target_path": "src/helpers.py",
                "vuln_class": "ssrf",
                "reason": "shared helper",
            }
        ],
    )

    with pytest.raises(SystemExit) as exc:
        code_record_analysis.run(_args(path, tmp_path))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "cross_file_triggers entry 0 is missing file_path" in err
    assert "target_path" in err
    assert "file_path" in err


def test_a_well_formed_trigger_block_still_passes_validation(monkeypatch, tmp_path):
    """The one-pass collector must not refuse a payload that is complete."""
    seen: list[dict] = []

    class _Client(StubClient):
        def post(self, _endpoint: str, payload: dict):
            seen.append(payload)
            return {
                "id": len(seen),
                "queue_item_id": payload["queue_item_id"],
                "agent_name": payload["agent_name"],
                "lease_token": payload["lease_token"],
                "disposition": payload["disposition"],
                "receipt_kind": payload.get("receipt_kind", "file"),
                "file_id": payload["file_id"],
                "callable_refs": [],
                "reviewed_spans": [],
                "receipt_binding_status": "source_span",
            }

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _Client)
    monkeypatch.setattr(
        code_record_analysis, "write_json_snapshot", lambda *_a, **_k: snapshot
    )
    monkeypatch.setattr(
        code_record_analysis,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        code_record_analysis,
        "_require_canonical_source_receipt_response",
        lambda *_a, **_k: None,
    )
    path = _payload(
        tmp_path,
        receipt_kind="file",
        reviewed_spans=[{"file_id": 7, "start_line": 1, "end_line": 40}],
        cross_file_triggers=[
            {
                "file_path": "src/helpers.py",
                "vuln_class": "ssrf",
                "reason": "shared helper forwards the caller's URL",
            }
        ],
    )

    code_record_analysis.run(_args(path, tmp_path))

    assert len(seen) == 1
    assert seen[0]["cross_file_triggers"][0]["file_path"] == "src/helpers.py"


def test_every_malformed_coverage_entry_is_named_in_one_invocation(
    monkeypatch, tmp_path, capsys
):
    """The same single-pass rule on the sibling collection in the same payload.

    `cwe_coverage` and `cross_file_triggers` are authored together in one file,
    so a validator that reports all of one and the first of the other still
    sends the author back for a second read.
    """
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _payload(
        tmp_path,
        cwe_coverage=[
            {"effort": 80},
            {"family": "ssrf", "effort": "lots"},
            {"family": "ssrf", "effort": 10},
        ],
    )

    with pytest.raises(SystemExit) as exc:
        code_record_analysis.run(_args(path, tmp_path))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "cwe_coverage entry 0 is missing family" in err
    assert "cwe_coverage entry 1 has a non-numeric effort" in err
    assert "duplicate family: ssrf" in err


def test_an_out_of_range_effort_and_an_unknown_confidence_are_named_together(
    monkeypatch, tmp_path, capsys
):
    """Effort is a 0-100 score and confidence one of high/medium/low; both are
    refused before the POST, in the same report as every other defect."""
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _payload(
        tmp_path,
        confidence="certain",
        cwe_coverage=[{"family": "ssrf", "effort": 150}, {"family": "sqli", "effort": -1}],
    )

    with pytest.raises(SystemExit) as exc:
        code_record_analysis.run(_args(path, tmp_path))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "cwe_coverage entry 0 effort 150 is outside 0-100" in err
    assert "cwe_coverage entry 1 effort -1 is outside 0-100" in err
    assert "confidence 'certain' must be one of: high, medium, low" in err


def test_a_supersede_correction_prints_the_families_recorded_at_effort_zero(
    monkeypatch, tmp_path, capsys
):
    """A correction that leaves required families out says so on stdout.

    The backend records each family a corrected critical/high closeout omits at
    effort 0 and returns `unreviewed_families_recorded`; `code-record analysis`
    prints one summary line per receipt, so that report must be one of them
    rather than living only in the response snapshot.
    """
    detail = (
        "The closeout of critical file src/app.py named no cwe_coverage entry "
        "for ssrf, so each is recorded at effort 0"
    )

    class _Client(StubClient):
        def get(self, endpoint: str):
            assert endpoint == "code/analysis-results?queue_item_id=101"
            return [{"id": 41, "queue_item_id": 101}]

        def post(self, _endpoint: str, payload: dict):
            return {
                "id": 42,
                "queue_item_id": payload["queue_item_id"],
                "agent_name": payload["agent_name"],
                "lease_token": payload["lease_token"],
                "disposition": payload["disposition"],
                "receipt_kind": payload.get("receipt_kind", "file"),
                "file_id": payload["file_id"],
                "supersedes": payload["supersedes"],
                "callable_refs": [],
                "reviewed_spans": [],
                "receipt_binding_status": "source_span",
                "unreviewed_families_recorded": {
                    "families": ["ssrf"],
                    "effort": 0,
                    "detail": detail,
                },
            }

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _Client)
    monkeypatch.setattr(
        code_record_analysis, "write_json_snapshot", lambda *_a, **_k: snapshot
    )
    monkeypatch.setattr(
        code_record_analysis,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        code_record_analysis,
        "_require_canonical_source_receipt_response",
        lambda *_a, **_k: None,
    )
    path = _payload(
        tmp_path,
        receipt_kind="file",
        reviewed_spans=[{"file_id": 7, "start_line": 1, "end_line": 40}],
    )

    code_record_analysis.run(
        SimpleNamespace(
            analysis_json=str(path), engagement_dir=str(tmp_path), supersede=101
        )
    )

    out = capsys.readouterr().out
    assert f"  {detail}\n" in out
