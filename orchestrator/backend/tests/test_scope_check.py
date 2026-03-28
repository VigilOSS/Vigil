from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def _run_scope_check(command: str, engagement_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[3]
    script = repo_root / "agent" / "scripts" / "hooks" / "scope-check.sh"
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "agent_type": "operator",
    }
    env = os.environ.copy()
    env["ENGAGEMENT_DIR"] = str(engagement_dir)
    return subprocess.run(
        ["bash", str(script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(repo_root / "agent"),
        env=env,
        check=False,
    )


def test_scope_check_allows_local_only_command(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check("jq -r '.target' scope.json", engagement_dir)

    assert result.returncode == 0


def test_scope_check_blocks_in_scope_host_side_target_command(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check("curl -I https://target.example/admin", engagement_dir)

    assert result.returncode == 2
    assert "kali mcp" in result.stderr.lower()


def test_scope_check_blocks_removed_host_side_helper_path(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check("source scripts/lib/container.sh && run_tool nmap -sV target.example", engagement_dir)

    assert result.returncode == 2
    assert "kali mcp" in result.stderr.lower()
