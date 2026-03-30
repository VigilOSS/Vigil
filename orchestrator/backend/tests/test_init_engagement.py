from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def test_init_engagement_writes_explicit_scope_and_exploit_policy(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")

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
    assert manifest["key"] == engagement_dir.name
    assert manifest["target"] == "https://app.example.com"
    assert active_key == engagement_dir.name


def test_init_engagement_uses_safe_defaults_in_noninteractive_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")

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


def test_init_engagement_accepts_proxy_capture_auth_mode(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    agent_root = repo_root / "agent"
    sandbox_root = tmp_path / "agent"
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")

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
