from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def _copy_init_fixture_tree(agent_root: Path, sandbox_root: Path, *, client: str) -> None:
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    shutil.copytree(agent_root / "agents", sandbox_root / "agents")
    shutil.copytree(agent_root / "rules", sandbox_root / "rules")
    shutil.copytree(agent_root / "skills", sandbox_root / "skills")
    shutil.copytree(agent_root / "references", sandbox_root / "references")
    if client == "codex":
        shutil.copytree(agent_root / ".codex", sandbox_root / ".codex")
        shutil.copy2(agent_root / "AGENTS.md", sandbox_root / "AGENTS.md")
    elif client == "claude":
        shutil.copytree(agent_root / ".claude", sandbox_root / ".claude")
        shutil.copy2(agent_root / "CLAUDE.md", sandbox_root / "CLAUDE.md")
    else:
        raise ValueError(f"unsupported client fixture: {client}")
    shutil.copy2(agent_root / "SKILL.md", sandbox_root / "SKILL.md")


def test_init_engagement_writes_explicit_scope_and_exploit_policy(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")

    templates_target = sandbox_root / "scripts" / "templates"
    templates_target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(agent_root / "scripts" / "templates" / "intel.md", templates_target / "intel.md")

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "https://app.example.com",
            "--hosts",
            "app.example.com,admin.example.com",
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
    orchestrator_env = (engagement_dir / ".orchestrator.env").read_text(encoding="utf-8")
    agents_wrapper = (engagement_dir / "AGENTS.md").read_text(encoding="utf-8")

    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["exploit_policy"] == "selected"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_targets"] == []
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
    assert not (engagement_dir / "start_claude.sh").exists()
    assert not (engagement_dir / "CLAUDE.md").exists()
    assert manifest["key"] == engagement_dir.name
    assert manifest["target"] == "https://app.example.com"
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

def test_init_engagement_uses_safe_defaults_in_noninteractive_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")

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
    orchestrator_env = (engagement_dir / ".orchestrator.env").read_text(encoding="utf-8")

    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com"]
    assert scope["exploit_policy"] == "pause"
    assert "parallelism" not in scope
    assert "confirm_mode" not in scope
    assert "scan_intensity" not in scope
    assert "engagement_name" not in scope
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert auth["use_for_requests"] is False
    assert auth["auth_context"] == "anonymous"
    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000" in orchestrator_env


def test_init_engagement_accepts_proxy_capture_auth_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")

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
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")
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


def test_orchestrator_env_loader_prefers_install_root_env_over_engagement_default(tmp_path: Path) -> None:
    """Verify that assess.py's config module resolves ORCHESTRATOR_BASE_URL from
    install-root .env before falling back to the engagement-dir default."""
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    install_root = tmp_path / "install-root"
    sandbox_root = install_root / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")
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

    # Use the Python config module to resolve the base URL (same path assess.py uses)
    resolved = subprocess.run(
        [
            "python3",
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(sandbox_root / 'scripts')!r}); "
                "from assess.lib.config import resolve_base_url; "
                f"print(resolve_base_url({str(engagement_dir)!r}, {str(sandbox_root)!r}))"
            ),
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(engagement_dir),
    )

    assert resolved.stdout.strip() == "https://orchestrator.example.test"


def test_init_engagement_writes_claude_only_launchers_for_claude_install(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="claude")

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
    claude_wrapper = (engagement_dir / "CLAUDE.md").read_text(encoding="utf-8")

    assert (engagement_dir / "start_claude.sh").exists()
    assert not (engagement_dir / "start_codex.sh").exists()
    assert (engagement_dir / "CLAUDE.md").exists()
    assert not (engagement_dir / "AGENTS.md").exists()
    assert str(sandbox_root / "CLAUDE.md") in claude_wrapper


def test_start_codex_exports_engagement_orchestrator_url(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    install_root = tmp_path / "install-root"
    sandbox_root = install_root / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="codex")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=https://override.example.test/\n",
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

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "codex").write_text(
        "#!/usr/bin/env bash\n"
        "printf 'ENGAGEMENT_DIR=%s\\n' \"${ENGAGEMENT_DIR:-}\"\n"
        "printf 'ORCHESTRATOR_BASE_URL=%s\\n' \"${ORCHESTRATOR_BASE_URL:-}\"\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "codex", 0o755)

    launch = subprocess.run(
        [str(engagement_dir / "start_codex.sh")],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(engagement_dir),
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
    )

    assert f"ENGAGEMENT_DIR={engagement_dir}" in launch.stdout
    assert "ORCHESTRATOR_BASE_URL=https://override.example.test" in launch.stdout


def test_init_engagement_code_mode_with_local_repo(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="claude")

    # Create a fake local repo directory for the --repo flag
    fake_repo = tmp_path / "my-cool-project"
    fake_repo.mkdir()
    (fake_repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "--type",
            "code",
            "--name",
            "my-cool-project",
            "--repo",
            str(fake_repo),
            "--exploit-policy",
            "pause",
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
    log_text = (engagement_dir / "log.md").read_text(encoding="utf-8")

    # Code-mode scope assertions
    assert scope["engagement_type"] == "code"
    assert scope["name"] == "my-cool-project"
    assert scope["repos"] == [{"path": str(fake_repo), "name": "my-cool-project"}]
    assert "repo" not in scope
    assert "repo_name" not in scope
    assert scope["hosts"] == []
    assert scope["current_phase"] == "ingest"
    assert scope["exploit_policy"] == "pause"
    assert scope["source_repos"] == []
    assert "hostname" not in scope

    # Auth forced to none
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert auth["use_for_requests"] is False

    # Engagement manifest has name and repos, not target/hostname
    assert manifest["name"] == "my-cool-project"
    assert manifest["repos"] == [{"path": str(fake_repo), "name": "my-cool-project"}]
    assert "repo" not in manifest
    assert "repo_name" not in manifest
    assert "target" not in manifest
    assert "hostname" not in manifest

    # Log reflects code analysis
    assert "Code Analysis" in log_text
    assert "Repositories" in log_text

    # source/ directory created for repo checkout
    assert (engagement_dir / "source").is_dir()

    # Standard directories still present
    assert (engagement_dir / "tools").is_dir()
    assert (engagement_dir / "scans").is_dir()
    assert (engagement_dir / "sessions").is_dir()


def test_init_engagement_code_mode_with_clone_url(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="claude")

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "--type",
            "code",
            "--name",
            "my-project",
            "--repo",
            "https://github.com/org/my-project.git",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    scope = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))
    manifest = json.loads((engagement_dir / "engagement.json").read_text(encoding="utf-8"))

    assert scope["engagement_type"] == "code"
    assert scope["name"] == "my-project"
    assert scope["repos"] == [{"path": "https://github.com/org/my-project.git", "name": "my-project"}]
    assert scope["current_phase"] == "ingest"
    assert scope["hosts"] == []
    assert manifest["name"] == "my-project"
    assert manifest["repos"] == [{"path": "https://github.com/org/my-project.git", "name": "my-project"}]

    # Directory name includes the engagement name
    assert "my-project" in engagement_dir.name


def test_init_engagement_code_mode_positional_name(tmp_path: Path) -> None:
    """--type code my-engagement (positional arg used as engagement name)."""
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    _copy_init_fixture_tree(agent_root, sandbox_root, client="claude")

    result = subprocess.run(
        [
            "bash",
            str(sandbox_root / "scripts" / "init_engagement.sh"),
            "--type",
            "code",
            "my-engagement",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    scope = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))

    assert scope["engagement_type"] == "code"
    assert scope["name"] == "my-engagement"
    assert scope["repos"] == []
    assert scope["current_phase"] == "ingest"
    assert "my-engagement" in engagement_dir.name


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
