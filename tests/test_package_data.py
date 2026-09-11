from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_installed_wheel_can_list_and_render_generated_family(tmp_path: Path) -> None:
    """A wheel built from the sdist must carry the benchmark factory data."""
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
        [str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
        check=True,
        capture_output=True,
        text=True,
    )

    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    probe = """
import json
from pathlib import Path

from vigil_cli.bench import factory

families = factory.list_families()
manifest = factory.render("bola-rest-graph", 0, Path("rendered"))
required = [
    "Dockerfile",
    "app.py",
    "docker-compose.yml",
    "requirements.txt",
    "solve.py",
    ".oracle/dag.json",
    ".oracle/decoys.json",
]
missing = [name for name in required if not (manifest.source_dir / name).is_file()]
print(json.dumps({"families": families, "missing": missing}, sort_keys=True))
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [str(python), "-I", "-c", probe],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert "bola-rest-graph" in result["families"]
    assert result["missing"] == []
