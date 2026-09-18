"""``agent handoff`` refuses an over-long summary before the POST.

The backend caps ``summary`` at 2000 characters on both ``HandoffCreate`` and
``HandoffUpdate``, so a specialist that writes a longer one used to learn about
it from an HTTP 422 after the request had already been built and sent. The
bound is mirrored client-side in ``_build_handoff_payload`` — the one point
every create payload and every partial-update patch passes through — so the
failure lands before the network, with the text still in the author's hands.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands.dispatch import agent as dispatch_agent


@pytest.fixture
def calls(monkeypatch, tmp_path):
    """Record every backend call the command makes; empty means no network."""
    recorded: list[tuple[str, object]] = []

    class _FakeClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def close(self) -> None:
            pass

        def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
            recorded.append(("record_handoff", payload))
            return {"id": 1, "agent_id": payload.get("agent_id")}

        def get_handoff(self, agent_id: str) -> dict:
            recorded.append(("get_handoff", agent_id))
            return {"agent_id": agent_id, "summary": "prior"}

        def update_handoff(self, agent_id: str, patch: dict) -> dict:
            recorded.append(("update_handoff", patch))
            return {"id": 2, "agent_id": agent_id}

    monkeypatch.setattr(
        dispatch_agent, "AssessmentClient", lambda *a, **k: _FakeClient()
    )
    monkeypatch.setattr(
        dispatch_agent,
        "load_config",
        lambda *a, **k: SimpleNamespace(
            base_url="http://backend.invalid",
            engagement_key="key",
            engagement_dir=str(tmp_path),
        ),
    )
    return recorded


def _args(tmp_path, payload: dict) -> SimpleNamespace:
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return SimpleNamespace(from_json=str(path), engagement_dir=str(tmp_path))


def test_over_long_summary_on_a_create_payload_fails_before_any_request(
    tmp_path, capsys, calls
):
    args = _args(
        tmp_path,
        {
            "agent_id": "recon-1",
            "agent_role": "recon-specialist",
            "summary": "x" * 2001,
        },
    )

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "2001" in err
    assert "2000" in err
    for field in ("coverage_gaps", "next_steps", "runtime_issues"):
        assert field in err
    assert calls == []


def test_over_long_summary_on_a_partial_update_fails_before_any_request(
    tmp_path, capsys, calls
):
    # No agent_role: the patch path, which would otherwise GET the existing
    # handoff before PATCHing the summary in.
    args = _args(tmp_path, {"agent_id": "recon-1", "summary": "y" * 2500})

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "2500" in err
    assert "2000" in err
    for field in ("coverage_gaps", "next_steps", "runtime_issues"):
        assert field in err
    assert calls == []


def test_summary_exactly_at_the_cap_is_sent_unchanged(tmp_path, calls):
    summary = "z" * 2000
    args = _args(
        tmp_path,
        {
            "agent_id": "recon-1",
            "agent_role": "recon-specialist",
            "summary": summary,
        },
    )

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["record_handoff"]
    assert calls[0][1]["summary"] == summary


def test_a_payload_without_a_summary_is_unaffected(tmp_path, calls):
    args = _args(tmp_path, {"agent_id": "recon-1", "handoff_status": "ready"})

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["get_handoff", "update_handoff"]
    assert calls[1][1] == {"handoff_status": "ready"}


def test_the_mirrored_cap_still_matches_the_backend_it_mirrors():
    """The KEEP-IN-SYNC comment, made executable.

    A mirrored bound that drifts UPWARD lets the 422 back; one that drifts
    DOWNWARD is worse — the CLI refuses the specialist's own valid text on a
    stale local rule and there is no backend error to explain it. The assess
    suite runs on the backend venv, so the authority is importable here.
    """
    from app.api.assessment import HandoffCreate, HandoffUpdate

    def declared_max_length(model, field: str) -> int | None:
        return next(
            (
                meta.max_length
                for meta in model.model_fields[field].metadata
                if getattr(meta, "max_length", None) is not None
            ),
            None,
        )

    assert declared_max_length(HandoffCreate, "summary") == (
        dispatch_agent._HANDOFF_SUMMARY_MAX_CHARS
    )
    assert declared_max_length(HandoffUpdate, "summary") == (
        dispatch_agent._HANDOFF_SUMMARY_MAX_CHARS
    )
