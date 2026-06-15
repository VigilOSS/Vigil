"""CR-7: subfinder provider-config.yaml generation from SUBFINDER_* env vars.

Covers the runtime-side generator that translates the non-empty SUBFINDER_*
container env vars into subfinder's native on-disk provider-config.yaml:
  - only non-empty keys are emitted (fail-open keyless)
  - multi-part keys (Censys, PassiveTotal) are ":"-joined
  - a half-configured multi-part source emits nothing (no malformed "id:" entry)
  - generate_subfinder_provider_config returns the emitted count / fails open

The script half runs the REAL POSIX-sh snippet in a temp HOME (no shell mocking)
so a schema regression is caught for real; the runner half uses a fake
docker.Runner so no container is required.

New, distinctly-named file (no edits to existing tests) per the workstream
isolation constraint.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from vigil_cli.docker import DockerResult  # noqa: E402
from vigil_cli.runtime import (  # noqa: E402
    _SUBFINDER_CONFIG_REL_PATH,
    _subfinder_provider_config_script,
    generate_subfinder_provider_config,
)


def _run_script(env: dict[str, str], home: Path) -> tuple[int, str]:
    """Execute the generated snippet under a clean env + temp HOME.

    Returns (emitted_count, file_contents). The snippet prints the count as its
    last stdout line.
    """
    script = _subfinder_provider_config_script()
    full_env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    full_env.update(env)
    proc = subprocess.run(
        ["sh", "-c", script],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    count = int(proc.stdout.strip().splitlines()[-1])
    cfg = home / _SUBFINDER_CONFIG_REL_PATH
    return count, (cfg.read_text() if cfg.is_file() else "")


def test_keyless_writes_empty_config_and_counts_zero(tmp_path: Path) -> None:
    count, contents = _run_script({}, tmp_path)
    assert count == 0
    assert contents == ""  # valid (empty) YAML — subfinder runs keyless
    # File is created (so subfinder finds a real path), just empty.
    assert (tmp_path / _SUBFINDER_CONFIG_REL_PATH).is_file()


def test_emits_only_non_empty_single_keys(tmp_path: Path) -> None:
    count, contents = _run_script(
        {
            "SUBFINDER_CHAOS_API_KEY": "chaos-abc",
            "SUBFINDER_GITHUB_TOKEN": "ghp_xyz",
            "SUBFINDER_SECURITYTRAILS_API_KEY": "",  # empty -> skipped
        },
        tmp_path,
    )
    assert count == 2
    assert 'chaos:\n  - "chaos-abc"\n' in contents
    assert 'github:\n  - "ghp_xyz"\n' in contents
    assert "securitytrails" not in contents


def test_multipart_censys_is_colon_joined(tmp_path: Path) -> None:
    count, contents = _run_script(
        {
            "SUBFINDER_CENSYS_API_ID": "cid",
            "SUBFINDER_CENSYS_API_SECRET": "csecret",
        },
        tmp_path,
    )
    assert count == 1
    assert 'censys:\n  - "cid:csecret"\n' in contents


def test_half_configured_multipart_emits_nothing(tmp_path: Path) -> None:
    # ID set but SECRET missing must NOT write a malformed "cid:" entry.
    count, contents = _run_script({"SUBFINDER_CENSYS_API_ID": "cid"}, tmp_path)
    assert count == 0
    assert "censys" not in contents


def test_passivetotal_multipart(tmp_path: Path) -> None:
    count, contents = _run_script(
        {
            "SUBFINDER_PASSIVETOTAL_USERNAME": "user@example.com",
            "SUBFINDER_PASSIVETOTAL_API_KEY": "pt-key",
        },
        tmp_path,
    )
    assert count == 1
    assert 'passivetotal:\n  - "user@example.com:pt-key"\n' in contents


def test_config_file_is_yaml_parseable_when_pyyaml_present(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    _run_script(
        {
            "SUBFINDER_CHAOS_API_KEY": "chaos-abc",
            "SUBFINDER_CENSYS_API_ID": "cid",
            "SUBFINDER_CENSYS_API_SECRET": "csecret",
        },
        tmp_path,
    )
    parsed = yaml.safe_load((tmp_path / _SUBFINDER_CONFIG_REL_PATH).read_text())
    assert parsed == {"chaos": ["chaos-abc"], "censys": ["cid:csecret"]}


# --- generator (runner) layer -------------------------------------------------


def _fake_runner(returncode: int, stdout: str = "", stderr: str = ""):
    calls: list[list[str]] = []

    def runner(argv, **kwargs):  # signature-compatible with docker.Runner
        calls.append(argv)
        return DockerResult(returncode, stdout, stderr)

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


def test_generate_returns_emitted_count() -> None:
    runner = _fake_runner(0, stdout="3\n")
    assert generate_subfinder_provider_config("vigil", runner=runner) == 3
    # Execs inside the named container with an sh -c script.
    argv = runner.calls[0]  # type: ignore[attr-defined]
    assert argv[:4] == ["docker", "exec", "vigil", "sh"]
    assert argv[4] == "-c"


def test_generate_zero_keys_warns_but_fails_open(capsys) -> None:
    runner = _fake_runner(0, stdout="0\n")
    assert generate_subfinder_provider_config("vigil", runner=runner) == 0
    err = capsys.readouterr().err
    assert "keyless" in err.lower()
    assert "WARN" in err


def test_generate_unreachable_probe_returns_none_and_warns(capsys) -> None:
    runner = _fake_runner(125, stderr="container not running")
    assert generate_subfinder_provider_config("vigil", runner=runner) is None
    assert "WARN" in capsys.readouterr().err


def test_generate_inconclusive_empty_stdout_is_silent(capsys) -> None:
    # A runner that returns rc=0 but no count line (e.g. did not actually run the
    # script) is inconclusive — must NOT emit the keyless WARN or claim "no keys".
    runner = _fake_runner(0, stdout="")
    assert generate_subfinder_provider_config("vigil", runner=runner) is None
    assert capsys.readouterr().err == ""


def test_generate_nonempty_reports_count(capsys) -> None:
    runner = _fake_runner(0, stdout="2\n")
    assert generate_subfinder_provider_config("vigil", runner=runner) == 2
    out = capsys.readouterr().err
    assert "2 keyed" in out
