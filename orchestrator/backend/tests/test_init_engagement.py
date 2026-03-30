from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def _copy_init_fixture_tree(agent_root: Path, sandbox_root: Path) -> None:
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    shutil.copytree(agent_root / "agents", sandbox_root / "agents")
    shutil.copytree(agent_root / "rules", sandbox_root / "rules")
    shutil.copytree(agent_root / "skills", sandbox_root / "skills")
    shutil.copytree(agent_root / "references", sandbox_root / "references")
    shutil.copytree(agent_root / ".codex", sandbox_root / ".codex")
    shutil.copytree(agent_root / ".claude", sandbox_root / ".claude")
    shutil.copy2(agent_root / "AGENTS.md", sandbox_root / "AGENTS.md")
    shutil.copy2(agent_root / "CLAUDE.md", sandbox_root / "CLAUDE.md")
    shutil.copy2(agent_root / "SKILL.md", sandbox_root / "SKILL.md")


def test_init_engagement_writes_explicit_scope_and_exploit_policy(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root)

    templates_target = sandbox_root / "scripts" / "templates"
    templates_target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(agent_root / "scripts" / "templates" / "intel.md", templates_target / "intel.md")

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
            "--scope-mode",
            "explicit_hosts",
            "--scope-hosts",
            "app.example.com,admin.example.com",
            "--out-of-scope-hosts",
            "beta.example.com",
            "--auth-mode",
            "manual",
            "--exploit-policy",
            "selected",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    scope = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((engagement_dir / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((engagement_dir / "engagement.json").read_text(encoding="utf-8"))
    active_key = (sandbox_root / "engagements" / ".active").read_text(encoding="utf-8").strip()
    orchestrator_env = (engagement_dir / ".orchestrator.env").read_text(encoding="utf-8")
    agents_wrapper = (engagement_dir / "AGENTS.md").read_text(encoding="utf-8")
    claude_wrapper = (engagement_dir / "CLAUDE.md").read_text(encoding="utf-8")

    assert scope["scope_mode"] == "explicit_hosts"
    assert scope["scope_hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["scope"] == ["app.example.com", "admin.example.com"]
    assert scope["out_of_scope_hosts"] == ["beta.example.com"]
    assert scope["exploit_policy"] == "selected"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_findings"] == []
    assert "parallelism" not in scope
    assert "confirm_mode" not in scope
    assert "scan_intensity" not in scope
    assert "engagement_name" not in scope
    assert "start_time" not in scope
    assert "phases_completed" not in scope
    assert "port" not in scope
    assert "target" not in scope
    assert auth["mode"] == "manual"
    assert auth["state"] == "missing"
    assert auth["use_for_requests"] is True
    assert auth["auth_context"] == "authenticated"
    assert (engagement_dir / "sessions" / "index.json").exists()
    assert (engagement_dir / "start_codex.sh").exists()
    assert (engagement_dir / "start_claude.sh").exists()
    assert manifest["key"] == engagement_dir.name
    assert manifest["target"] == "https://app.example.com"
    assert active_key == engagement_dir.name
    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000" in orchestrator_env

    expected_codex_paths = [
        sandbox_root / "AGENTS.md",
        sandbox_root / ".codex" / "agents",
        sandbox_root / "agents",
        sandbox_root / "rules",
        sandbox_root / "SKILL.md",
        sandbox_root / "skills",
        sandbox_root / "references",
        sandbox_root / "scripts",
    ]
    for path in expected_codex_paths:
        assert str(path) in agents_wrapper
        assert path.exists(), f"expected wrapper path to exist: {path}"

    expected_claude_paths = [
        sandbox_root / "CLAUDE.md",
        sandbox_root / ".claude" / "agents",
        sandbox_root / "agents",
        sandbox_root / "rules",
        sandbox_root / "SKILL.md",
        sandbox_root / "skills",
        sandbox_root / "references",
        sandbox_root / "scripts",
    ]
    for path in expected_claude_paths:
        assert str(path) in claude_wrapper
        assert path.exists(), f"expected wrapper path to exist: {path}"


def test_init_engagement_uses_safe_defaults_in_noninteractive_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root)

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    scope = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((engagement_dir / "auth.json").read_text(encoding="utf-8"))
    active_key = (sandbox_root / "engagements" / ".active").read_text(encoding="utf-8").strip()
    orchestrator_env = (engagement_dir / ".orchestrator.env").read_text(encoding="utf-8")

    assert scope["scope_mode"] == "host_only"
    assert scope["scope_hosts"] == ["app.example.com"]
    assert scope["out_of_scope_hosts"] == []
    assert scope["exploit_policy"] == "pause"
    assert "parallelism" not in scope
    assert "confirm_mode" not in scope
    assert "scan_intensity" not in scope
    assert "engagement_name" not in scope
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert auth["use_for_requests"] is False
    assert auth["auth_context"] == "anonymous"
    assert active_key == engagement_dir.name
    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000" in orchestrator_env


def test_init_engagement_accepts_proxy_capture_auth_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root)

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
            "--auth-mode",
            "proxy_capture",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    auth = json.loads((engagement_dir / "auth.json").read_text(encoding="utf-8"))

    assert auth["mode"] == "proxy_capture"
    assert auth["state"] == "missing"
    assert auth["use_for_requests"] is True
    assert auth["auth_context"] == "authenticated"


def test_init_engagement_uses_install_root_env_override_for_orchestrator_url(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    install_root = tmp_path / "install-root"
    sandbox_root = install_root / "agent"
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=https://orchestrator.example.test\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    orchestrator_env = (engagement_dir / ".orchestrator.env").read_text(encoding="utf-8")
    start_codex = (engagement_dir / "start_codex.sh").read_text(encoding="utf-8")

    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000" in orchestrator_env
    assert "load_orchestrator_env" in start_codex


def test_orchestrator_env_loader_prefers_install_root_env_over_engagement_default(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    install_root = tmp_path / "install-root"
    sandbox_root = install_root / "agent"
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=https://orchestrator.example.test\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    resolved = subprocess.run(
        [
            "bash",
            "-lc",
            (
                f'source "{sandbox_root / "scripts" / "lib" / "orchestrator_env.sh"}"; '
                f'load_orchestrator_env "{engagement_dir}"; '
                'printf "%s" "$ORCHESTRATOR_BASE_URL"'
            ),
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(engagement_dir),
    )

    assert resolved.stdout.strip() == "https://orchestrator.example.test"


def test_install_upgrade_preserves_agent_engagements(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_script = repo_root / "install.sh"
    install_root = tmp_path / "install-root"
    env = {
        **os.environ,
        "AI_THREAT_HUNTING_SKIP_PREREQ_CHECKS": "1",
        "AI_THREAT_HUNTING_SKIP_DOCKER_IMAGE_CHECKS": "1",
    }

    subprocess.run(
        ["bash", str(install_script), "codex", str(install_root)],
        text=True,
        capture_output=True,
        check=True,
        cwd=repo_root,
        env=env,
    )

    engagement_dir = install_root / "agent" / "engagements" / "existing-engagement"
    engagement_dir.mkdir(parents=True)
    marker = engagement_dir / "scope.json"
    marker.write_text('{"target":"https://app.example.com"}\n', encoding="utf-8")

    subprocess.run(
        ["bash", str(install_script), "codex", str(install_root)],
        text=True,
        capture_output=True,
        check=True,
        cwd=repo_root,
        env=env,
    )

    assert marker.exists()
