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
            "--scan-intensity",
            "stealth",
            "--auth-mode",
            "manual",
            "--exploit-policy",
            "selected",
            "--engagement-name",
            "app-review",
        ],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(sandbox_root),
    )

    engagement_dir = Path(result.stdout.strip())
    scope = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))

    assert scope["scope_mode"] == "explicit_hosts"
    assert scope["scope_hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["scope"] == ["app.example.com", "admin.example.com"]
    assert scope["out_of_scope_hosts"] == ["beta.example.com"]
    assert scope["scan_intensity"] == "stealth"
    assert scope["auth_mode"] == "manual"
    assert scope["exploit_policy"] == "selected"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_findings"] == []
    assert scope["engagement_name"] == "app-review"
    assert (engagement_dir / "sessions" / "index.json").exists()


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

    assert scope["scope_mode"] == "host_only"
    assert scope["scope_hosts"] == ["app.example.com"]
    assert scope["out_of_scope_hosts"] == []
    assert scope["scan_intensity"] == "normal"
    assert scope["auth_mode"] == "none"
    assert scope["exploit_policy"] == "pause"
    assert scope["engagement_name"].startswith("app-example-com-")
