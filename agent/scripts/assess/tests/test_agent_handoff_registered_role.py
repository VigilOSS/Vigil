"""A handoff takes its role from the dispatch it belongs to.

The backend stores the dispatch's registered role on the handoff and reports a
substituted or absent role on the response's ``derived`` list. The CLI must
therefore create a first handoff that names no role, and surface what the
backend filled in.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from assess.commands.dispatch import agent as dispatch_agent


class _Client:
    def __init__(self) -> None:
        self.recorded: list[dict] = []

    def close(self) -> None:
        pass

    def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
        self.recorded.append(payload)
        derived = []
        if payload.get("agent_role") != "code-vuln-hunter":
            derived.append({
                "field": "agent_role", "value": "code-vuln-hunter", "derived_from": "dispatch",
                "detail": "stored the registered dispatch role 'code-vuln-hunter'; the handoff named none",
            })
        return {"id": 1, "agent_id": payload["agent_id"], "summary": payload["summary"],
                "agent_role": "code-vuln-hunter", "handoff_version": 1,
                "handoff_status": "checkpointed", "derived": derived}

    def get_handoff(self, agent_id: str):
        return None


def _run(monkeypatch, tmp_path, payload: dict) -> _Client:
    client = _Client()
    monkeypatch.setattr(dispatch_agent, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(
        dispatch_agent, "load_config",
        lambda *a, **k: SimpleNamespace(base_url="http://backend.invalid", engagement_key="key",
                                        engagement_dir=str(tmp_path)),
    )
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    dispatch_agent._record_handoff(
        SimpleNamespace(from_json=str(path), engagement_dir=str(tmp_path), agent_id=payload["agent_id"])
    )
    return client


def test_first_handoff_without_a_role_is_created_and_the_derived_role_is_named(
    monkeypatch, tmp_path, capsys
) -> None:
    client = _run(monkeypatch, tmp_path, {"agent_id": "acme-hunter-1", "summary": "Reviewed src/acme.c."})

    assert len(client.recorded) == 1
    err = capsys.readouterr().err
    assert "agent_role" in err
    assert "code-vuln-hunter" in err


def test_a_handoff_naming_its_registered_role_reports_nothing_derived(
    monkeypatch, tmp_path, capsys
) -> None:
    _run(monkeypatch, tmp_path, {"agent_id": "acme-hunter-1", "agent_role": "code-vuln-hunter",
                                 "summary": "Reviewed src/acme.c."})

    assert "derived" not in capsys.readouterr().err
