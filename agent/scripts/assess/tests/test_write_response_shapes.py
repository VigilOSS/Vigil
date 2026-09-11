from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import record_intel, supersede_intel, update_intel
from assess.lib.client import AssessError, AssessmentClient


class _MalformedIntelResponseClient:
    posts: list[tuple[str, dict]] = []

    def __init__(self, *_args):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post_engagement(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {}

    def post_event(self, _payload: dict) -> dict:
        raise AssertionError("a malformed write response must not emit a success event")


class _SuccessfulNoteClient:
    def __init__(self, *_args):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post_engagement(self, _endpoint: str, _payload: dict) -> dict:
        return {"id": 7, "title": "Durable note", "write_outcome": "updated"}

    def post_event(self, _payload: dict) -> dict:
        return {}


def test_intel_note_record_reports_create_or_update_outcome(tmp_path, monkeypatch, capsys):
    payload_file = tmp_path / "note.json"
    payload_file.write_text(json.dumps({"title": "Durable note"}), encoding="utf-8")
    monkeypatch.setattr(record_intel, "AssessmentClient", _SuccessfulNoteClient)
    monkeypatch.setattr(
        record_intel,
        "load_config",
        lambda _directory: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
        ),
    )

    record_intel.run(
        SimpleNamespace(
            intel_type="note",
            json_file=str(payload_file),
            dry_run=False,
            engagement_dir=str(tmp_path),
        )
    )

    assert "updated existing note" in capsys.readouterr().out


def test_intel_record_rejects_object_without_canonical_record_identity(
    tmp_path, monkeypatch, capsys
):
    payload_file = tmp_path / "note.json"
    payload_file.write_text(json.dumps({"title": "Durable note"}), encoding="utf-8")
    _MalformedIntelResponseClient.posts = []
    monkeypatch.setattr(record_intel, "AssessmentClient", _MalformedIntelResponseClient)
    monkeypatch.setattr(
        record_intel,
        "load_config",
        lambda _directory: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        record_intel.run(
            SimpleNamespace(
                intel_type="note",
                json_file=str(payload_file),
                dry_run=False,
                engagement_dir=str(tmp_path),
            )
        )

    assert exc.value.code == 1
    assert "canonical note record" in capsys.readouterr().err
    assert _MalformedIntelResponseClient.posts == [
        ("intel/notes", {"title": "Durable note"})
    ]


def test_intel_record_rejects_id_bound_to_a_different_natural_identity(
    tmp_path, monkeypatch, capsys
):
    payload_file = tmp_path / "note.json"
    payload_file.write_text(json.dumps({"title": "Requested note"}), encoding="utf-8")

    class _WrongNoteClient(_MalformedIntelResponseClient):
        def post_engagement(self, endpoint: str, payload: dict) -> dict:
            self.posts.append((endpoint, payload))
            return {"id": 7, "title": "Different note"}

    _WrongNoteClient.posts = []
    monkeypatch.setattr(record_intel, "AssessmentClient", _WrongNoteClient)
    monkeypatch.setattr(
        record_intel,
        "load_config",
        lambda _directory: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        record_intel.run(
            SimpleNamespace(
                intel_type="note",
                json_file=str(payload_file),
                dry_run=False,
                engagement_dir=str(tmp_path),
            )
        )

    assert exc.value.code == 1
    assert "canonical note record" in capsys.readouterr().err


@pytest.mark.parametrize(
    "response_body",
    ["not-json", '{"id":8,"title":"Durable note"}'],
)
def test_intel_update_rejects_an_unreadable_or_wrong_row_receipt(
    tmp_path, monkeypatch, response_body
):
    monkeypatch.setattr(
        AssessmentClient,
        "_request",
        lambda *_args, **_kwargs: (200, response_body),
    )
    monkeypatch.setattr(
        update_intel,
        "load_config",
        lambda _directory: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
        ),
    )

    with pytest.raises(AssessError, match="uncertain|durable result"):
        update_intel.run(
            SimpleNamespace(
                intel_type="note",
                intel_id=7,
                payload=None,
                inline_payload='{"source_name":"operator"}',
                engagement_dir=str(tmp_path),
            )
        )


@pytest.mark.parametrize(
    "response_body",
    [
        "not-json",
        '{"superseded":{"id":7,"superseded_by_id":8},"current":{"id":8}}',
        '{"superseded":{"id":7.0,"superseded_by_id":9},"current":{"id":9}}',
    ],
)
def test_intel_supersede_rejects_an_unreadable_or_wrong_canonical_receipt(
    tmp_path, monkeypatch, response_body
):
    monkeypatch.setattr(
        AssessmentClient,
        "_request",
        lambda *_args, **_kwargs: (201, response_body),
    )
    monkeypatch.setattr(
        supersede_intel,
        "load_config",
        lambda _directory: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
        ),
    )

    with pytest.raises(AssessError, match="uncertain|canonical"):
        supersede_intel.run(
            SimpleNamespace(
                intel_type="tech-component",
                intel_id=7,
                payload=None,
                inline_payload=None,
                to_existing_id=9,
                rationale="duplicate",
                engagement_dir=str(tmp_path),
            )
        )
