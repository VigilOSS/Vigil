from __future__ import annotations

import json
import hashlib

from assess.lib import config, instruction_identity


def test_config_resolves_release_assets_independently_of_engagement_paths(tmp_path, monkeypatch):
    application = tmp_path / "application"
    engagement = tmp_path / "workspace" / "engagements" / "acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}")
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(engagement.parent.parent))
    monkeypatch.setattr(config, "_verify_backend", lambda _: None)
    cfg = config.load_config(str(engagement))
    assert cfg.agent_root == str(application / "agent")
    assert cfg.engagement_dir == str(engagement)


def test_private_workspace_env_fallback_does_not_read_release_env(tmp_path, monkeypatch):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    application.mkdir()
    workspace.mkdir()
    (workspace / ".env").write_text("ORCHESTRATOR_BASE_URL=http://127.0.0.1:18345\n")
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "missing-config.json"))
    assert config.resolve_base_url("", str(application / "agent")) == "http://127.0.0.1:18345"


def test_instruction_identity_reads_release_provenance_and_exact_release_prompts(tmp_path, monkeypatch):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    agent = application / "agent"
    engagement = workspace / "engagements" / "acme"
    engagement.mkdir(parents=True)
    (agent / ".claude" / "agents").mkdir(parents=True)
    (agent / "AGENTS.md").write_text("matched operator")
    (agent / ".claude" / "agents" / "recon-specialist.md").write_text("matched specialist")
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "offensive", "tracks": {"web": {"phase": "recon"}}}))
    (application / "bundle.json").write_text(json.dumps({"version": "1.1.0", "content_sha256": "a" * 64,
        "files": {"agent/AGENTS.md": hashlib.sha256((agent / "AGENTS.md").read_bytes()).hexdigest(),
                  "agent/.claude/agents/recon-specialist.md": hashlib.sha256((agent / ".claude/agents/recon-specialist.md").read_bytes()).hexdigest()}}))
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    identity, warnings = instruction_identity.build_dispatch_instruction_identity(
        agent_root=agent, engagement_dir=engagement, agent_role="recon-specialist", client_name="claude",
    )
    assert identity["instruction_identity_status"] == "verified"
    assert identity["source_revision"] == "bundle:" + "a" * 64
    assert identity["instructions_stale"] is False
    assert not warnings
