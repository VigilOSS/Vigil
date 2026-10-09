from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_cli import config


def test_save_config_failed_replace_preserves_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.json"
    target.write_text('{"existing": "value"}\n', encoding="utf-8")

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("publication failed")

    monkeypatch.setattr(config.os, "replace", fail_replace)

    with pytest.raises(OSError, match="publication failed"):
        config.save_config({"replacement": "value"}, target)

    assert target.read_text(encoding="utf-8") == '{"existing": "value"}\n'
    assert not list(tmp_path.glob(".config.json.*.tmp"))


def test_set_config_waits_for_the_cross_process_mutation_lock(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text('{"existing": "value"}\n', encoding="utf-8")
    lock_path = tmp_path / ".config.json.lock"
    lock_path.touch()
    src_root = Path(__file__).resolve().parents[1] / "src"
    env = os.environ.copy()
    env[config.CONFIG_ENV] = str(target)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(src_root), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    child_code = (
        "from vigil_cli.config import set_config_value; "
        "print('ready', flush=True); "
        "set_config_value('child', 'written')"
    )

    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        process = subprocess.Popen(
            [sys.executable, "-c", child_code],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            assert process.stdout.readline().strip() == "ready"
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=0.2)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, (stdout, stderr)
    assert config.load_config(target) == {"child": "written", "existing": "value"}
