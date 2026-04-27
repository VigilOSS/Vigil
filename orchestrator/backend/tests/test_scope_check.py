from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


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

    result = _run_scope_check('python3 -c "print(1)" https://target.example/admin', engagement_dir)

    assert result.returncode == 2
    assert "aith assess kali" in result.stderr.lower()


def test_scope_check_blocks_removed_host_side_helper_path(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check("source scripts/lib/container.sh && run_tool nmap -sV target.example", engagement_dir)

    assert result.returncode == 2
    assert "aith assess kali" in result.stderr.lower()


def test_scope_check_blocks_when_scope_metadata_is_missing(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    result = _run_scope_check('python3 -c "print(1)" https://target.example/admin', engagement_dir)

    assert result.returncode == 2
    assert "scope metadata is missing" in result.stderr.lower()


def test_scope_check_blocks_explicitly_out_of_scope_host(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "target.example",
                "scope_mode": "wildcard",
                "scope_hosts": ["target.example", "*.target.example"],
                "out_of_scope_hosts": ["admin.target.example"],
            }
        ),
        encoding="utf-8",
    )

    result = _run_scope_check('python3 -c "print(1)" https://admin.target.example/panel', engagement_dir)

    assert result.returncode == 2
    assert "explicitly out of scope" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Strict apex-wildcard semantics — `aith assess filter-scope` regressions (1F.1)
# ---------------------------------------------------------------------------


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_filter_scope_module():
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = (
        Path(__file__).resolve().parents[3]
        / "agent"
        / "scripts"
        / "assess"
        / "commands"
        / "filter_scope.py"
    )
    spec = importlib.util.spec_from_file_location("test_filter_scope_apex_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_filter_scope(monkeypatch, engagement_dir: Path, lines: list[str], capsys):
    module = _load_filter_scope_module()
    input_file = engagement_dir / "input.txt"
    input_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",
        ),
    )
    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            input_file=str(input_file),
            output=None,
        )
    )
    return capsys.readouterr()


def test_apex_filter_with_wildcard_only(monkeypatch, tmp_path: Path, capsys) -> None:
    """Strict apex-wildcard: `filter-scope` rejects bare-apex URLs against `*.example.test`.

    The wildcard-only scope excludes the bare apex; apex URLs are dropped
    from output AND a warning is emitted on stderr telling the operator how
    to admit the apex if intended.
    """
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://example.test/",
            "https://example.test/login",
            "https://corp.example.test/api",
            "https://vendor-saas.example.test/api",
        ],
        capsys,
    )

    # Apex URLs are rejected; subdomains pass through.
    assert captured.out.splitlines() == [
        "https://corp.example.test/api",
        "https://vendor-saas.example.test/api",
    ]
    # Strict-semantics warning is emitted to stderr (deduped per apex host).
    assert "bare apex is excluded by strict semantics" in captured.err
    assert "example.test" in captured.err
    assert captured.err.count("WARN: https://example.test/") == 1


def test_apex_match_with_explicit_entry(monkeypatch, tmp_path: Path, capsys) -> None:
    """An explicit apex entry alongside the wildcard admits apex URLs.

    Operators opt in to apex coverage by listing the apex (bare-host or URL)
    in addition to the wildcard. With both present, both apex and subdomain
    URLs pass through filter-scope and no strict-semantics warning fires.
    """
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["example.test", "*.example.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://example.test/",
            "https://example.test/login",
            "https://corp.example.test/api",
        ],
        capsys,
    )

    assert captured.out.splitlines() == [
        "https://example.test/",
        "https://example.test/login",
        "https://corp.example.test/api",
    ]
    # No warning when the apex is explicitly listed.
    assert "bare apex is excluded by strict semantics" not in captured.err
