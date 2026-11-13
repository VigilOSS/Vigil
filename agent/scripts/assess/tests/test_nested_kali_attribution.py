"""A helper an audited run executes inherits that run's attribution (I-12).

An engagement helper (``./tools/login.sh``) that calls ``vigil assess kali exec``
without ``--agent-id`` used to be credited to ``operator`` even when the lane
that ran it was attributed. ``host-exec`` now hands the run's attribution to
its child through every env carrier the resolvers read, so the nested call
resolves to the same agent.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import host_exec
from assess.lib import kali_audit
from assess.lib.kali_audit import ATTRIBUTION_ENV_NAMES, _resolve_agent_name


class _Client:
    def __init__(self, *_a, **_k) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._run_uuid = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self) -> None:
        pass

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        self._run_uuid = payload.get("run_uuid") or self._run_uuid
        return {"id": 42}

    def patch(self, endpoint: str, payload: dict, **_kwargs) -> dict:
        response = dict(payload)
        response["completed_at"] = str(response.pop("ended_at")).replace("Z", "+00:00")
        response.pop("output_quiesced", None)
        response.update(id=42, run_uuid=self._run_uuid)
        return response


def _run_host_exec(monkeypatch, tmp_path: Path, *, agent_name: str | None, command: list[str]):
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": ["app.example.com"]}))
    client = _Client()
    monkeypatch.setattr(host_exec, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(
        host_exec,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://backend.invalid", engagement_key=tmp_path.name,
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(host_exec, "prepare_execution_command", lambda argv, **k: "anonymous")
    monkeypatch.setattr(host_exec, "emit_foreign_lane_recency", lambda *a, **k: None)
    seen: dict = {}

    def _fake_run_host_process(*_args, **kwargs):
        seen.update(kwargs)
        return 0, "ok\n", "", False

    monkeypatch.setattr(host_exec, "_run_host_process", _fake_run_host_process)
    args = SimpleNamespace(
        engagement_dir=str(tmp_path), from_json=None, technique="RECON", phase="recon",
        target_host="", scope_host="", cwd=str(tmp_path), timeout=30, audit_source="argv",
        allow_destructive=False, agent_name=agent_name, require_audit=False, finding=None,
        identity=None, identity_scope="", command=command, tool=command[0],
        intent="engagement login helper",
    )
    with pytest.raises(SystemExit) as exc_info:
        host_exec.run(args)
    assert exc_info.value.code == 0
    return client, seen


def test_host_exec_hands_its_attribution_to_the_child(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_NAME", raising=False)
    monkeypatch.setenv("VIGIL_AGENT_NAME", "stale-role")

    client, seen = _run_host_exec(
        monkeypatch, tmp_path, agent_name="sa-acme-1114w", command=["bash", "tools/login.sh"]
    )

    exported = dict(seen["env_pairs"])
    assert client.posts[0][1]["agent_name"] == "sa-acme-1114w"
    for name in ATTRIBUTION_ENV_NAMES:
        assert exported[name] == "sa-acme-1114w"


def test_a_nested_kali_exec_resolves_to_the_inherited_agent(monkeypatch):
    for name, value in kali_audit.attribution_env_pairs("sa-acme-1114w"):
        monkeypatch.setenv(name, value)

    assert _resolve_agent_name(None) == "sa-acme-1114w"
    # An explicit flag on the nested call still wins.
    assert _resolve_agent_name(None, agent_id="va-7f3") == "va-7f3"


def test_host_exec_records_a_script_run_as_unknown_target_traffic(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_NAME", raising=False)
    monkeypatch.delenv("VIGIL_AGENT_NAME", raising=False)

    client, _seen = _run_host_exec(
        monkeypatch, tmp_path, agent_name=None, command=["python3", "tools/login.py"]
    )

    notes = json.loads(client.posts[0][1]["notes"])
    assert notes["target_facing"] == "unknown"
