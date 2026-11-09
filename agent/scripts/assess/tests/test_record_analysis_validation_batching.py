"""`code-record analysis` validates the whole payload in one pass.

Every collection in a receipt is authored in the same file in the same sitting,
so reporting one collection's defects and stopping sends the author back for
another read of a payload that has not changed. The same holds across items: a
grouped submission is one array, and item 0's missing field must not hide item
7's. These cases drive the door the author actually types and assert that one
invocation names every defect, in input order, with the entry index, the named
field and the near-miss alias hint intact.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_record_analysis
from _fake_client import StubClient


def _args(path: Path, tmp_path: Path, **overrides) -> SimpleNamespace:
    return SimpleNamespace(
        analysis_json=str(path), engagement_dir=str(tmp_path), **overrides
    )


def _write(tmp_path: Path, items: list) -> Path:
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(items), encoding="utf-8")
    return path


def _item(index: int, **overrides) -> dict:
    item: dict[str, object] = {
        "queue_item_id": 100 + index,
        "agent_name": "code-vuln-hunter",
        "lease_token": f"lease-{100 + index}",
        "file_id": 7 + index,
        "disposition": "clean",
        "reviewed_spans": [{"file_id": 7 + index, "start_line": 1, "end_line": 40}],
    }
    item.update(overrides)
    return item


class _ForbiddenClient:
    def __init__(self, *_args, **_kwargs) -> None:
        raise AssertionError("a payload refusal must precede the client")


def _reported_item_indices(err: str) -> list[int]:
    return [int(match) for match in re.findall(r"^Item (\d+)\b", err, re.MULTILINE)]


def test_every_defect_across_every_item_and_collection_lands_in_one_run(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _write(
        tmp_path,
        [
            _item(
                0,
                cwe_coverage=[{"effort": 80}, {"family": "ssrf", "effort": "lots"}],
                cross_file_triggers=[
                    {
                        "file_path": "src/helpers.py",
                        "vuln": "ssrf",
                        "reason": "shared helper forwards the caller's URL",
                    }
                ],
            ),
            _item(
                1,
                disposition="vulnerable",
                reviewed_spans=[],
                callable_refs=[
                    {"file_id": 8, "name": "handle", "start_line": 10, "end_line": 20}
                ],
            ),
            _item(2, queue_item_id="one-oh-two"),
            {
                "queue_item_id": 103,
                "agent_name": "code-vuln-hunter",
                "disposition": "clean",
                "reviewed_spans": [{"file_id": 10, "start_line": 1, "end_line": 2}],
            },
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        code_record_analysis.run(_args(path, tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0 cwe_coverage entry 0 is missing family" in err
    assert "Item 0 cwe_coverage entry 1 has a non-numeric effort" in err
    assert "Item 0 cross_file_triggers entry 0 is missing vuln_class" in err
    # The near-miss hint is what makes a missing key a one-read fix.
    assert "the entry carries 'vuln'" in err
    assert "'vuln_class' is the one accepted spelling" in err
    assert "Item 1 callable_refs entry 0 is missing qualified_name" in err
    assert "Item 2 queue_item_id must be an integer" in err
    assert "Item 3 missing required fields: lease_token" in err
    assert _reported_item_indices(err) == sorted(_reported_item_indices(err))


def test_a_collection_of_the_wrong_type_is_collected_and_never_walked(
    monkeypatch, tmp_path, capsys
):
    """A payload that cannot be walked still reports every other item."""
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _write(
        tmp_path,
        [
            _item(0, cwe_coverage={"family": "ssrf"}),
            _item(1, cross_file_triggers="src/helpers.py"),
            _item(2, callable_refs={"name": "handle"}),
            "not-an-object",
            _item(4, supersedes=0),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        code_record_analysis.run(_args(path, tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0 cwe_coverage must be a JSON array" in err
    assert "Item 1 cross_file_triggers must be a JSON array" in err
    assert "Item 2 callable_refs and reviewed_spans must be JSON arrays" in err
    assert "Item 3 is not a JSON object" in err
    assert "Item 4 supersedes must be a positive integer analysis-result ID" in err


def test_every_malformed_anchor_in_a_receipt_is_named_in_one_invocation(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _write(
        tmp_path,
        [
            _item(
                0,
                disposition="vulnerable",
                reviewed_spans=[{"file_id": 0, "start_line": 1, "end_line": 2}],
                callable_refs=[
                    {
                        "file_id": 7,
                        "name": "a",
                        "qualified_name": "Handler.a",
                        "start_line": 0,
                        "end_line": 5,
                    },
                    {"file_id": 7, "name": "b", "start_line": 10, "end_line": 20},
                    {
                        "file_id": 7,
                        "name": "c",
                        "qualified_name": "Handler.c",
                        "start_line": 30,
                        "end_line": 10,
                    },
                ],
            )
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        code_record_analysis.run(_args(path, tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0 callable_refs entry 0 has an invalid file/span identity" in err
    assert "Item 0 callable_refs entry 1 is missing qualified_name" in err
    assert "Item 0 callable_refs entry 2 has an invalid file/span identity" in err
    assert "Item 0 reviewed_spans entry 0 has an invalid file/span identity" in err


def test_the_receipt_shape_refusals_all_reach_the_same_report(
    monkeypatch, tmp_path, capsys
):
    """Each refusal below is the only problem its item carries."""
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _write(
        tmp_path,
        [
            _item(0, receipt_kind="chain"),
            _item(1, disposition="vulnerable", empty_file_reviewed=True),
            _item(
                2,
                disposition="vulnerable",
                reviewed_spans=[],
                callable_refs=[
                    {
                        "file_id": 9,
                        "name": "run",
                        "qualified_name": "Handler.run",
                        "start_line": 1,
                        "line_end": 5,
                    }
                ],
            ),
            _item(3, reviewed_spans=["src/a.py"]),
            _item(4, file_id="seven"),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        code_record_analysis.run(_args(path, tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0 receipt_kind must be file or call_chain" in err
    assert "Item 1 empty_file_reviewed requires clean with no anchors" in err
    assert "Item 2 callable_refs entry 0 must use one complete line range spelling" in err
    assert "Item 3 reviewed_spans entry 0 must be a JSON object" in err
    assert "Item 4 file_id must be an integer when supplied" in err


def test_a_supersede_mismatch_is_reported_with_the_rest_of_the_payload(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_record_analysis, "AssessmentClient", _ForbiddenClient)
    path = _write(tmp_path, [_item(0, cwe_coverage=[{"effort": 80}]), _item(1)])

    with pytest.raises(SystemExit) as excinfo:
        code_record_analysis.run(_args(path, tmp_path, supersede=100))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0 cwe_coverage entry 0 is missing family" in err
    assert "Item 1 queue_item_id must match --supersede 100" in err


def test_an_index_spelled_line_range_is_still_normalized_before_the_post(
    monkeypatch, tmp_path
):
    """The validator rewrites `line_start`/`line_end`, and `run` submits that."""
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
                "callable_refs": [
                    {
                        **ref,
                        "file_path": "src/parser.py",
                        "callable_key": "a" * 64,
                    }
                    for ref in payload.get("callable_refs", [])
                ],
                "reviewed_spans": [],
                "receipt_binding_status": "structural",
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
    path = _write(
        tmp_path,
        [
            _item(
                0,
                disposition="vulnerable",
                reviewed_spans=[],
                callable_refs=[
                    {
                        "file_id": 7,
                        "name": "run",
                        "qualified_name": "Handler.run",
                        "line_start": 12,
                        "line_end": 18,
                    }
                ],
            )
        ],
    )

    code_record_analysis.run(_args(path, tmp_path))

    assert len(seen) == 1
    assert seen[0]["callable_refs"][0] == {
        "file_id": 7,
        "name": "run",
        "qualified_name": "Handler.run",
        "start_line": 12,
        "end_line": 18,
    }
