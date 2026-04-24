from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root / "src"))

from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement


def _copy_agent_fixture(agent_root: Path, sandbox_root: Path, *, client: str) -> None:
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    shutil.copytree(agent_root / "agents", sandbox_root / "agents")
    shutil.copytree(agent_root / "rules", sandbox_root / "rules")
    shutil.copytree(agent_root / "skills", sandbox_root / "skills")
    shutil.copytree(agent_root / "references", sandbox_root / "references")
    if client in {"codex", "both"}:
        shutil.copytree(agent_root / ".codex", sandbox_root / ".codex")
        shutil.copy2(agent_root / "AGENTS.md", sandbox_root / "AGENTS.md")
    if client in {"claude", "both"}:
        shutil.copytree(agent_root / ".claude", sandbox_root / ".claude")
        shutil.copy2(agent_root / "CLAUDE.md", sandbox_root / "CLAUDE.md")
    shutil.copy2(agent_root / "SKILL.md", sandbox_root / "SKILL.md")


def test_aith_engagement_create_writes_explicit_web_scope(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
            hosts=["app.example.com", "admin.example.com"],
            auth_mode="manual",
            exploit_policy="selected",
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((created.path / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["exploit_policy"] == "selected"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_targets"] == []
    assert auth["mode"] == "manual"
    assert auth["state"] == "missing"
    assert auth["use_for_requests"] is True
    assert manifest["key"] == created.key
    assert manifest["target"] == "https://app.example.com"
    assert (created.path / "sessions" / "index.json").exists()
    assert (created.path / "start_codex.sh").exists()
    assert (created.path / "start_claude.sh").exists()
    assert (created.path / ".codex" / "config.toml").exists()


def test_aith_engagement_create_code_mode_with_local_repo(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")
    fake_repo = tmp_path / "my-cool-project"
    fake_repo.mkdir()
    (fake_repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="code",
            name="my-cool-project",
            repos=[str(fake_repo)],
            exploit_policy="pause",
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((created.path / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert scope["engagement_type"] == "code"
    assert scope["name"] == "my-cool-project"
    assert scope["repos"] == [{"path": str(fake_repo), "name": "my-cool-project"}]
    assert scope["hosts"] == []
    assert scope["current_phase"] == "ingest"
    assert scope["source_repos"] == []
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert manifest["name"] == "my-cool-project"
    assert (created.path / "source").is_dir()
    assert (created.path / "start_claude.sh").exists()
    assert not (created.path / "start_codex.sh").exists()


def test_aith_start_codex_exports_engagement_environment(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="codex")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=https://override.example.test/\n",
        encoding="utf-8",
    )

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "codex").write_text(
        "#!/usr/bin/env bash\n"
        "printf 'ENGAGEMENT_DIR=%s\\n' \"${ENGAGEMENT_DIR:-}\"\n"
        "printf 'AI_THREAT_HUNTING_AGENT_ROOT=%s\\n' \"${AI_THREAT_HUNTING_AGENT_ROOT:-}\"\n"
        "printf 'ORCHESTRATOR_BASE_URL=%s\\n' \"${ORCHESTRATOR_BASE_URL:-}\"\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "codex", 0o755)

    launch = subprocess.run(
        [str(created.path / "start_codex.sh")],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(created.path),
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
    )

    assert f"ENGAGEMENT_DIR={created.path}" in launch.stdout
    assert f"AI_THREAT_HUNTING_AGENT_ROOT={sandbox_root}" in launch.stdout
    assert "ORCHESTRATOR_BASE_URL=https://override.example.test" in launch.stdout
