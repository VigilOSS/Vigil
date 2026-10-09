from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_sdist_builds_an_installable_wheel_with_a_working_cli(tmp_path: Path) -> None:
    """Prove the published path, not an editable checkout.

    Build an sdist, build the wheel from that archive, install it in an isolated
    environment, and invoke the console entrypoint from an unrelated directory.
    """
    uv = shutil.which("uv")
    assert uv is not None, "the repository test matrix requires uv"

    dist_dir = tmp_path / "dist"
    subprocess.run(
        [uv, "build", "--sdist", "--out-dir", str(dist_dir), str(REPO_ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    sdists = list(dist_dir.glob("vigil-*.tar.gz"))
    assert len(sdists) == 1

    # Build the wheel from the source archive, not the working tree, so ignored
    # build directories cannot make a missing package-data declaration pass.
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(dist_dir), str(sdists[0])],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(dist_dir.glob("vigil-*.whl"))
    assert len(wheels) == 1

    venv_dir = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", str(wheels[0])],
        check=True,
        capture_output=True,
        text=True,
    )

    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    version = subprocess.run(
        [str(python), "-I", "-c", "import vigil_cli; print(vigil_cli.__version__)"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert version.stdout.strip() == "1.0.0"

    executable = venv_dir / ("Scripts/vigil.exe" if os.name == "nt" else "bin/vigil")
    cli_version = subprocess.run(
        [str(executable), "--version"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "1.0.0" in cli_version.stdout
    help_result = subprocess.run(
        [str(executable), "--help"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "usage: vigil" in help_result.stdout.lower()
    assert "engagement" in help_result.stdout
