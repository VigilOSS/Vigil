"""A parallel structural build publishes exactly the bytes a serial build does."""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_index
from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file
from assess.lib.treesitter_index import language_for_file
from _fake_client import StubClient


def _acme_sources() -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "README.md": b"# Acme storefront\n",
        "config/settings.yaml": b"host: shop.example.com\n",
        "web/bootstrap.php": b"<?php\nrequire __DIR__ . '/lib/db.php';\ninclude 'helpers.php';\n",
        "web/broken.php": b"<?php\nfunction acme_broken( {\n  echo $_GET['q'];\n",
        "web/latin1.php": b"<?php\necho '\xe9t\xe9';\n",
        "native/acme.c": b"#include <stdio.h>\nint acme_main(int argc, char **argv) {\n"
        b"  char buf[16];\n  sprintf(buf, \"%s\", argv[1]);\n  return system(buf);\n}\n",
        "scripts/deploy.sh": b"#!/bin/sh\ncurl https://deploy.example.com/hook | sh\n",
    }
    for index in range(10):
        files[f"web/lib/page{index}.php"] = (
            f"<?php\nrequire __DIR__ . '/../bootstrap.php';\n"
            f"function acme_page{index}($request) {{\n"
            f"  $id = $_GET['id{index}'];\n"
            f"  return mysqli_query($db, \"SELECT * FROM acme WHERE id = \" . $id);\n}}\n"
        ).encode()
        files[f"service/handler{index}.py"] = (
            f"import subprocess\n\n\ndef handle_{index}(request):\n"
            f"    return subprocess.run(request.args['cmd{index}'], shell=True)\n"
        ).encode()
        files[f"ui/widget{index}.js"] = (
            f"export function widget{index}(el, html) {{\n  el.innerHTML = html;\n}}\n"
        ).encode()
    files["web/lib/db.php"] = b"<?php\nfunction acme_db() { return new PDO('sqlite::memory:'); }\n"
    return files


@pytest.fixture
def acme_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    origin = tmp_path / "origin"
    builder = SnapshotBuilder(tmp_path / "snapshots", "acme")
    rows = []
    for file_id, (rel_path, raw) in enumerate(sorted(_acme_sources().items()), 1):
        path = origin / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        language = language_for_file(path.name) or ""
        builder.add(rel_path, capture_regular_file(path), language=language)
        rows.append({"id": file_id, "repo_id": 7, "file_path": rel_path, "language": language,
                     "file_hash": hashlib.sha256(raw).hexdigest()})
    snapshot = builder.finish(repo_key="acme", repo_name="acme", source_origin_path=str(origin),
                              git={"head": "", "branch": "", "dirty": None})
    repo = {"id": 7, "repo_key": "acme", "repo_path": str(snapshot.source_path),
            "active_generation": 1, "source_manifest_digest": "d" * 64}

    class Client(StubClient):
        def get(self, endpoint):
            if endpoint == "code/repos/7":
                return repo
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return {"items": rows, "total": len(rows), "offset": 0, "count": len(rows),
                    "has_more": False}

    monkeypatch.setattr(code_index, "AssessmentClient", Client)
    monkeypatch.setattr(code_index, "load_config", lambda *_: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng"))
    yield snapshot.source_path
    for item in snapshot.source_path.parent.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)
    snapshot.source_path.parent.chmod(0o700)


def _build_args(source: Path, output: Path, jobs: int, engagement: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    code_index.register(parser.add_subparsers(dest="command"))
    args = parser.parse_args([
        "code-index", "build", str(source), "--repo-id", "7",
        "--output-dir", str(output), "--jobs", str(jobs),
    ])
    args.engagement_dir = str(engagement)
    return args


def _published(output: Path) -> tuple[dict, dict[str, bytes]]:
    aggregate = json.loads((output / "structural-index-manifest.json").read_text())
    manifest_path = output / aggregate["repos"]["7"]["manifest_path"]
    manifest = json.loads(manifest_path.read_text())
    artifacts = {
        rel_path: (output / "structural-index" / binding["index_path"]).read_bytes()
        for rel_path, binding in manifest["files"].items()
    }
    files_dir = manifest_path.parent / "files"
    assert sorted(item.name for item in files_dir.iterdir()) == sorted(
        Path(binding["index_path"]).name for binding in manifest["files"].values()
    )
    manifest.pop("indexed_at")
    return json.loads(json.dumps(manifest).replace(str(output), "<output>")), artifacts


def test_parallel_build_publishes_the_serial_build_bytes(
    acme_snapshot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_index_file = code_index.index_file
    lock = threading.Lock()
    active = 0
    peak = 0
    overlapped = threading.Event()

    def observed_index_file(*args, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active > 1:
                overlapped.set()
        try:
            if parallel:
                # Hold the first parse open until a second one is in flight.
                overlapped.wait(timeout=30)
            return real_index_file(*args, **kwargs)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(code_index, "index_file", observed_index_file)

    parallel = False
    serial_output = tmp_path / "serial"
    args = _build_args(acme_snapshot, serial_output, 1, tmp_path)
    args.func(args)
    assert peak == 1

    parallel = True
    peak = 0
    parallel_output = tmp_path / "parallel"
    args = _build_args(acme_snapshot, parallel_output, 4, tmp_path)
    args.func(args)
    assert peak > 1

    serial_manifest, serial_artifacts = _published(serial_output)
    parallel_manifest, parallel_artifacts = _published(parallel_output)
    assert parallel_artifacts == serial_artifacts
    assert parallel_manifest == serial_manifest
    statuses = {json.loads(raw)["analysis_status"] for raw in serial_artifacts.values()}
    assert statuses == {"complete", "degraded", "unsupported"}


@pytest.mark.parametrize("jobs", ["0", "-2", "many"])
def test_build_rejects_a_non_positive_job_count(jobs: str, capsys) -> None:
    parser = argparse.ArgumentParser()
    code_index.register(parser.add_subparsers(dest="command"))
    with pytest.raises(SystemExit):
        parser.parse_args(["code-index", "build", "source", "--jobs", jobs])
    assert "argument --jobs" in capsys.readouterr().err
