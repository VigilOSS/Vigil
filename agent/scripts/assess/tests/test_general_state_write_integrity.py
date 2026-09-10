from __future__ import annotations

from types import SimpleNamespace

import pytest

from assess.commands import app_unit, log_entry
from assess.lib.client import AssessError


class _Client:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.events: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, _endpoint: str, _payload: dict) -> dict:
        return self.response

    def patch(self, _endpoint: str, _payload: dict) -> dict:
        return self.response

    def post_engagement(self, _endpoint: str, _payload: dict) -> dict:
        return self.response

    def post_event(self, payload: dict) -> None:
        self.events.append(payload)


def _config(engagement_dir):
    return SimpleNamespace(
        base_url="http://backend",
        engagement_key="eng",
        engagement_dir=str(engagement_dir),
    )


def test_app_unit_score_requires_complete_summary_shape(monkeypatch, tmp_path):
    client = _Client({"skipped": False, "units": []})
    monkeypatch.setattr(app_unit, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(app_unit, "load_config", _config)

    with pytest.raises(AssessError, match="score application units") as exc:
        app_unit.run(
            SimpleNamespace(
                action="score",
                unit_id=None,
                reason="",
                as_json=False,
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_app_unit_patch_requires_addressed_id_and_override(monkeypatch, tmp_path):
    client = _Client({"id": 999, "override": "mark-deep"})
    monkeypatch.setattr(app_unit, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(app_unit, "load_config", _config)

    with pytest.raises(AssessError, match="update application unit") as exc:
        app_unit.run(
            SimpleNamespace(
                action="mark-deep",
                unit_id=7,
                reason="sensitive workflow",
                as_json=False,
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_log_entry_requires_canonical_activity_identity(monkeypatch, tmp_path, capsys):
    client = _Client(
        {
            "actor_kind": "agent",
            "actor_name": "analyst",
            "title": "checkpoint",
        }
    )
    monkeypatch.setattr(log_entry, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(log_entry, "load_config", _config)

    with pytest.raises(SystemExit) as exc:
        log_entry.run(
            SimpleNamespace(
                eng_dir=str(tmp_path),
                agent="analyst",
                title="checkpoint",
                action="reviewed",
                result="complete",
                metadata_inline=None,
                metadata_file=None,
            )
        )

    assert exc.value.code == 1
    assert "do not retry automatically" in capsys.readouterr().err
    assert client.events == []
