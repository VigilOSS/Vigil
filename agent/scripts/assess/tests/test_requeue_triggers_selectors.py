"""A15a/A15d (CLI half): one strict selector per input, honest exit status.

`requeue-triggers` used to dereference every array member as an object and read
only `file_path`: a `list-triggers` row (`id` + `target_file_path`) became an
empty selector the backend silently skipped, and a bare integer id raised
AttributeError. A response could report `total > 0` with every bucket zero.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


def _install_snapshot_stub(monkeypatch, tmp_path: Path) -> None:
    counter = iter(range(100))

    def fake_snapshot(*_args, **_kwargs):
        path = tmp_path / f"snapshot-{next(counter)}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(code_dispatch, "write_json_snapshot", fake_snapshot)


def _install_client(monkeypatch, response: dict) -> dict:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return response

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    return captured


def _response(**overrides) -> dict:
    payload = {
        "input_trigger_count": 0,
        "target_count": 0,
        "inserted": 0,
        "already_queued": 0,
        "already_completed": 0,
        "blocked": 0,
        "reopened_terminal_files": 0,
        "not_found": [],
        "ambiguous": [],
        "outcomes": [],
        "inputs": [],
    }
    payload.update(overrides)
    return payload


def _write(tmp_path: Path, payload) -> str:
    path = tmp_path / "triggers.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_list_trigger_rows_are_directly_consumable(monkeypatch, tmp_path, capsys):
    _install_snapshot_stub(monkeypatch, tmp_path)
    captured = _install_client(
        monkeypatch, _response(input_trigger_count=1, target_count=1, inserted=1)
    )
    # A verbatim `list-triggers` row: the trigger id plus every bookkeeping
    # column the backend owns.
    triggers_file = _write(
        tmp_path,
        [
            {
                "id": 12,
                "engagement_id": 3,
                "repo_id": 1,
                "repo_generation": 4,
                "source_queue_item_id": 88,
                "source_file_id": 7,
                "source_file_path": "src/parser.py",
                "target_file_id": None,
                "target_file_path": "src/helpers.py",
                "vuln_class": "web-app-injection",
                "reason": "shared parser helper",
                "status": "pending",
                "resolution_note": "",
                "created_at": "2026-09-15T10:00:00Z",
            }
        ],
    )

    code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert captured["endpoint"] == "code/analysis-queue/requeue"
    assert captured["payload"] == {
        "items": [
            {
                "trigger_id": 12,
                "reason": "shared parser helper",
                "trigger_context": {
                    "vuln_class": "web-app-injection",
                    "source": "cross_file_trigger",
                },
            }
        ]
    }


def test_analysis_result_trigger_shape_still_selects_by_path(
    monkeypatch, tmp_path, capsys
):
    _install_snapshot_stub(monkeypatch, tmp_path)
    captured = _install_client(
        monkeypatch, _response(input_trigger_count=1, target_count=1, inserted=1)
    )
    triggers_file = _write(
        tmp_path,
        {
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "repo_id": 2,
                    "reason": "shared parser helper",
                    "vuln_class": "web-app-injection",
                    "batch_theme": "helpers",
                    "guidance_hypotheses": ["Check the length guard."],
                    "operator_note": "keep the original hypothesis",
                }
            ]
        },
    )

    code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert captured["payload"]["items"] == [
        {
            "file_path": "src/helpers.py",
            "repo_id": 2,
            "reason": "shared parser helper",
            "batch_theme": "helpers",
            "guidance_hypotheses": ["Check the length guard."],
            "trigger_context": {
                "vuln_class": "web-app-injection",
                "source": "cross_file_trigger",
                "operator_note": "keep the original hypothesis",
            },
        }
    ]


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ([12], "must be a JSON object"),
        ([{"reason": "no selector"}], "needs file_id"),
        ([{"file_id": 3, "trigger_id": 4}], "exactly one"),
        ([{"file_id": "3"}], "positive integer"),
        ([{"file_id": 0}], "positive integer"),
    ],
)
def test_malformed_selectors_are_rejected_before_any_write(
    monkeypatch, tmp_path, capsys, payload, expected
):
    _install_snapshot_stub(monkeypatch, tmp_path)
    captured = _install_client(monkeypatch, _response())
    triggers_file = _write(tmp_path, payload)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert exc.value.code == 1
    assert captured == {}
    assert expected in capsys.readouterr().err


def test_blocked_target_exits_nonzero_with_its_reason(monkeypatch, tmp_path, capsys):
    _install_snapshot_stub(monkeypatch, tmp_path)
    _install_client(
        monkeypatch,
        _response(
            input_trigger_count=2,
            target_count=2,
            inserted=1,
            blocked=1,
            reopened_terminal_files=1,
            outcomes=[
                {
                    "file_id": 7,
                    "file_path": "src/parser.py",
                    "queue_item_id": None,
                    "outcome": "blocked",
                    "detail": "target file must be classified before requeue",
                },
                {
                    "file_id": 8,
                    "file_path": "src/helpers.py",
                    "queue_item_id": 31,
                    "outcome": "inserted",
                    "detail": "created the first trigger attempt",
                },
            ],
        ),
    )
    triggers_file = _write(
        tmp_path, [{"file_id": 7, "reason": "a"}, {"file_id": 8, "reason": "b"}]
    )

    with pytest.raises(SystemExit) as exc:
        code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "2 trigger input(s) across 2 target(s)" in captured.out
    assert "reopened 1 terminal file(s)" in captured.out
    assert "src/parser.py" in captured.err
    assert "must be classified" in captured.err


def test_unresolved_selectors_exit_nonzero(monkeypatch, tmp_path, capsys):
    _install_snapshot_stub(monkeypatch, tmp_path)
    _install_client(
        monkeypatch,
        _response(input_trigger_count=1, not_found=["src/nowhere.py"]),
    )
    triggers_file = _write(tmp_path, [{"file_path": "src/nowhere.py"}])

    with pytest.raises(SystemExit) as exc:
        code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert exc.value.code == 1
    assert "src/nowhere.py" in capsys.readouterr().err


def test_fully_applied_batch_exits_zero(monkeypatch, tmp_path, capsys):
    _install_snapshot_stub(monkeypatch, tmp_path)
    _install_client(
        monkeypatch,
        _response(input_trigger_count=1, target_count=1, already_queued=1),
    )
    triggers_file = _write(tmp_path, [{"file_id": 8, "reason": "b"}])

    code_dispatch._requeue_triggers(_config(tmp_path), triggers_file)

    assert "already-queued=1" in capsys.readouterr().out
