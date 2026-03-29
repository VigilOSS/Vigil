from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _run_auth_helper(repo_root: Path, engagement_dir: Path, command: str) -> subprocess.CompletedProcess[str]:
    auth_lib = repo_root / "agent" / "scripts" / "lib" / "auth.sh"
    shell_command = f'source "{auth_lib}" && {command} "{engagement_dir}"'
    return subprocess.run(
        ["bash", "-lc", shell_command],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(repo_root),
    )


def test_auth_runtime_snapshot_marks_expired_auth_as_warning_only(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "auth.json").write_text(
        json.dumps(
            {
                "mode": "manual",
                "state": "available",
                "use_for_requests": True,
                "auth_context": "authenticated",
                "expires_at": "2000-01-01T00:00:00Z",
                "cookies": {"session": "abc"},
                "headers": {"Authorization": "Bearer stale"},
            }
        ),
        encoding="utf-8",
    )

    result = _run_auth_helper(repo_root, engagement_dir, "auth_runtime_snapshot_json")
    payload = json.loads(result.stdout)

    assert payload["mode"] == "manual"
    assert payload["state"] == "expired"
    assert payload["active_use"] is False
    assert payload["auth_context"] == "anonymous"
    assert "expired" in payload["warning"].lower()


def test_auth_runtime_snapshot_emits_headers_for_available_auth(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "auth.json").write_text(
        json.dumps(
            {
                "mode": "auth_json",
                "state": "available",
                "use_for_requests": True,
                "auth_context": "tenant-admin",
                "cookies": {"session": "abc", "csrftoken": "def"},
                "headers": {"Authorization": "Bearer live-token"},
            }
        ),
        encoding="utf-8",
    )

    context = _run_auth_helper(repo_root, engagement_dir, "auth_active_context")
    assert context.stdout.strip() == "tenant-admin"

    auth_lib = repo_root / "agent" / "scripts" / "lib" / "auth.sh"
    shell_command = f'source "{auth_lib}" && auth_header_args_stream "{engagement_dir}"'
    result = subprocess.run(
        ["bash", "-lc", shell_command],
        capture_output=True,
        check=True,
        cwd=str(repo_root),
    )
    items = [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]

    assert "-H" in items
    assert any(item.startswith("Cookie: ") and "session=abc" in item for item in items)
    assert "Authorization: Bearer live-token" in items
