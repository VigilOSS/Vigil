import argparse
import json
import subprocess
from pathlib import Path

import pytest

from vigil_cli import blue


@pytest.mark.parametrize(
    "command_overrides",
    [
        {"finding_id": 22},
        {"intent": "containment proposal=99 action=revoke_session"},
        {"argv": ["gam", "user", "other@example.com", "signout"]},
    ],
)
def test_contain_rejects_command_run_not_bound_to_approved_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command_overrides: dict,
) -> None:
    monkeypatch.setattr(blue, "_resolve_blue_engagement", lambda *_args: tmp_path)
    monkeypatch.setattr(blue, "_read_scope", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(blue, "_fetch_containment_decision", lambda *_args: {
        "resolved": True,
        "payload": {"finding_slug": "FIND-001", "action": "revoke_session", "target": "user@example.com", "platform": "gws"},
    })
    command = {
        "route": "host_exec", "phase": "respond", "technique": "CONTAINMENT", "success": True,
        "finding_id": 11, "intent": "containment proposal=42 action=revoke_session",
        "argv": ["gam", "user", "user@example.com", "signout"],
    }
    monkeypatch.setattr(blue, "_fetch_command_run", lambda *_args: {**command, **command_overrides})
    monkeypatch.setattr(blue, "_fetch_containment_finding", lambda *_args: {"id": 11, "slug": "FIND-001"}, raising=False)
    monkeypatch.setattr(blue, "_run_assess", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("containment was recorded")))
    args = argparse.Namespace(engagement_key="project", select=False, finding_slug="FIND-001", proposal="42",
                              action=None, target=None, proof_artifact=None, command_run_id=73)

    with pytest.raises(SystemExit, match="command run id 73.*(finding|proposal|target)"):
        blue._cmd_contain(args, tmp_path)


def test_containment_command_run_accepts_matching_proof() -> None:
    blue._require_containment_command_run(
        {
            "route": "host_exec", "phase": "respond", "technique": "CONTAINMENT", "success": True,
            "finding_id": 11, "intent": "containment proposal=42 action=revoke_session",
            "argv": ["gam", "user", "user@example.com", "signout"],
        },
        73, finding_id=11, proposal_id=42, action="revoke_session", target="user@example.com",
    )


def test_contain_cannot_override_approved_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(blue, "_resolve_blue_engagement", lambda *_args: tmp_path)
    monkeypatch.setattr(blue, "_read_scope", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(blue, "_fetch_containment_decision", lambda *_args: {
        "resolved": True,
        "payload": {"finding_slug": "FIND-001", "action": "revoke_session", "target": "user@example.com"},
    })
    args = argparse.Namespace(engagement_key="project", select=False, finding_slug="FIND-001", proposal="42",
                              action=None, target="other@example.com", proof_artifact=None, command_run_id=73)

    with pytest.raises(SystemExit, match="approved target"):
        blue._cmd_contain(args, tmp_path)


def test_contain_records_matching_command_proof(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(blue, "_resolve_blue_engagement", lambda *_args: tmp_path)
    monkeypatch.setattr(blue, "_read_scope", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(blue, "_fetch_containment_decision", lambda *_args: {
        "resolved": True,
        "payload": {"finding_slug": "FIND-001", "action": "revoke_session", "target": "user@example.com"},
    })
    monkeypatch.setattr(blue, "_fetch_command_run", lambda *_args: {
        "route": "host_exec", "phase": "respond", "technique": "CONTAINMENT", "success": True,
        "finding_id": 11, "intent": "containment proposal=42 action=revoke_session",
        "argv": ["gam", "user", "user@example.com", "signout"],
    })
    monkeypatch.setattr(blue, "_fetch_containment_finding", lambda *_args: {"id": 11, "slug": "FIND-001"})
    recorded: list[list[str]] = []
    monkeypatch.setattr(blue, "_run_assess", lambda _root, _eng, argv, **_kwargs: recorded.append(argv) or 0)
    args = argparse.Namespace(engagement_key="project", select=False, finding_slug="FIND-001", proposal="42",
                              action=None, target=None, proof_artifact=None, command_run_id=73)

    blue._cmd_contain(args, tmp_path)

    assert [argv[:2] for argv in recorded] == [["log", "operator"], ["finding", "update"]]
    assert "contained" in recorded[1]


def test_containment_finding_lookup_requires_matching_slug(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(blue, "_build_assess_argv", lambda _root, _eng, argv: argv)
    monkeypatch.setattr(blue.subprocess, "run", lambda argv, **_kwargs: subprocess.CompletedProcess(
        argv, 0, json.dumps({"id": 11, "slug": "OTHER"}), ""))

    assert blue._fetch_containment_finding(tmp_path, tmp_path, "FIND-001") is None
