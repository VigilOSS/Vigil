"""`code-record classify` says what each tag or tier change moved.

A tag or tier change reopens no review: the backend recomputes what the file
owes, raises depth_floor triggers for families the review on record left below
the floor, retires the ones no longer owed and withdraws a directed attempt
left with nothing to carry (`obligation_changes`). A field the classification
left out keeps the stored value (`derived`). Both reach the operator; a large
pass prints a bounded sample, the omitted count and the read that lists the rest.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_classify
from _fake_client import StubClient


def _change(file_id: int) -> dict:
    return {
        "file_id": file_id,
        "file_path": f"src/acme_{file_id}.py",
        "previous_classification": "high",
        "classification": "critical",
        "required_families_added": ["auth-bypass"],
        "required_families_removed": ["ssrf"],
        "optional_families_added": [],
        "depth_floor_triggers": {"raised": [{"trigger_id": 100 + file_id, "family": "auth-bypass"}]},
        "depth_floor_triggers_retired": [200 + file_id],
        "depth_floor_triggers_retired_reasons": {str(200 + file_id): "family_no_longer_required"},
        "requeue_withdrawn": [{"queue_item_id": 300 + file_id}],
    }


class _Client(StubClient):
    def __init__(self, response: dict, files: list[dict] | None = None) -> None:
        self.response = response
        self.files = files or []
        self.posts: list[dict] = []

    def post(self, _endpoint: str, payload: dict, **_options) -> dict:
        self.posts.append(payload)
        count = len(payload["classifications"])
        return {**self.response, "updated": count, "total": count}

    def get(self, endpoint: str) -> dict:
        assert endpoint.startswith("code/files?")
        return {
            "total": len(self.files), "offset": 0, "count": len(self.files),
            "has_more": False, "items": self.files,
        }


def _classify(monkeypatch, tmp_path: Path, client: _Client, items: list[dict]) -> None:
    monkeypatch.setattr(code_classify, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(
        code_classify, "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    path = tmp_path / "classifications.json"
    path.write_text(json.dumps(items), encoding="utf-8")
    code_classify.run(
        SimpleNamespace(classifications_json=str(path), engagement_dir=str(tmp_path))
    )


def _medium(file_id: int) -> dict:
    return {"file_id": file_id, "classification": "medium", "analysis_priority": 40}


def test_each_files_obligation_change_is_printed(monkeypatch, tmp_path, capsys):
    client = _Client({"obligation_changes": [_change(1)]})

    _classify(monkeypatch, tmp_path, client, [_medium(1)])

    out = capsys.readouterr().out
    assert "Obligations recomputed on 1 file(s)" in out
    (line,) = [row for row in out.splitlines() if row.startswith("  src/acme_1.py:")]
    for fragment in (
        "tier high -> critical", "required +auth-bypass", "required -ssrf",
        "raised triggers 101 (auth-bypass)", "retired triggers 201 (family_no_longer_required)",
        "withdrew directed attempt(s) 301",
    ):
        assert fragment in line


def test_a_large_pass_prints_a_bounded_sample_and_the_full_list(monkeypatch, tmp_path, capsys):
    changes = [_change(file_id) for file_id in range(1, 31)]
    client = _Client({"obligation_changes": changes})

    _classify(monkeypatch, tmp_path, client, [_medium(file_id) for file_id in range(1, 31)])

    out = capsys.readouterr().out
    printed = [row for row in out.splitlines() if row.startswith("  src/acme_")]
    assert len(printed) == code_classify._OBLIGATION_CHANGE_SAMPLE
    assert "Obligations recomputed on 30 file(s)" in out
    assert "30 depth_floor trigger(s) raised, 30 retired" in out
    assert f"... {30 - code_classify._OBLIGATION_CHANGE_SAMPLE} more file(s) not shown" in out
    assert "activity-entries?q=code-record%20classify" in out


def test_kept_role_and_slot_types_are_named(monkeypatch, tmp_path, capsys):
    client = _Client({"derived": [
        {"file_id": 1, "file_path": "src/acme_1.py", "field": "role", "value": "parser"},
        {"file_id": 1, "file_path": "src/acme_1.py", "field": "slot_types",
         "value": ["NETWORK-INPUT"]},
    ]})

    _classify(monkeypatch, tmp_path, client, [_medium(1)])

    out = capsys.readouterr().out
    assert "Kept recorded role on 1 file(s)" in out and "src/acme_1.py: parser" in out
    assert "Kept recorded slot_types on 1 file(s)" in out
    assert "src/acme_1.py: NETWORK-INPUT" in out


def test_a_critical_item_without_slot_types_keeps_the_stored_ones(monkeypatch, tmp_path):
    client = _Client({}, files=[{"id": 1, "file_path": "src/acme_1.py",
                                 "slot_types": ["NETWORK-INPUT"]}])

    _classify(monkeypatch, tmp_path, client, [
        {"file_id": 1, "classification": "critical", "analysis_priority": 90,
         "context_tags": ["authentication"]},
    ])

    (posted,) = client.posts
    assert "slot_types" not in posted["classifications"][0]


def test_a_critical_item_with_no_slot_types_to_keep_is_refused_before_sending(
    monkeypatch, tmp_path, capsys
):
    client = _Client({}, files=[{"id": 1, "file_path": "src/acme_1.py", "slot_types": []}])

    with pytest.raises(SystemExit) as exited:
        _classify(monkeypatch, tmp_path, client, [
            {"file_id": 1, "classification": "critical", "analysis_priority": 90},
        ])

    assert exited.value.code == 1
    assert client.posts == []
    assert "records none to keep" in capsys.readouterr().err
