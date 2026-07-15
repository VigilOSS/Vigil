from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def _run_extract(repo_root: Path, map_root: Path, output_root: Path, *extra: str):
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "agent" / "scripts" / "assess.py"),
            "code-sourcemap-extract",
            str(map_root),
            "--output-root",
            str(output_root),
            *extra,
        ],
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": str(repo_root / "src")},
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_sourcemap_extract_is_safe_deterministic_and_refreshes_immutably(tmp_path):
    repo_root = Path(__file__).resolve().parents[3]
    map_root = tmp_path / "maps"
    output_root = tmp_path / "extracted"
    map_root.mkdir()
    first_content = "export const first = 1;\n"
    duplicate_content = "export const second = 2;\n"
    (map_root / "app.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "file": "app.min.js",
                "sources": [
                    "src/app.ts",
                    "src/app.ts",
                    "src/app.ts",
                    "webpack:///./src/virtual.ts",
                    "../escape.ts",
                    "/absolute.ts",
                    "https://attacker.invalid/source.ts",
                    "missing.ts",
                ],
                "sourcesContent": [
                    first_content,
                    duplicate_content,
                    duplicate_content,
                    "export const virtual = true;\n",
                    "escape",
                    "absolute",
                    "url",
                    None,
                ],
            }
        ),
        encoding="utf-8",
    )
    (map_root / "missing.css.map").write_text(
        json.dumps({"version": 3, "sources": ["styles/main.scss"]}),
        encoding="utf-8",
    )
    (map_root / "indexed.js.map").write_text(
        json.dumps(
            {
                "version": 3,
                "sections": [
                    {
                        "offset": {"line": 0, "column": 0},
                        "map": {
                            "version": 3,
                            "sources": ["src/indexed.ts"],
                            "sourcesContent": ["export const indexed = true;\n"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (map_root / "malformed.js.map").write_text("{not-json", encoding="utf-8")

    first = _run_extract(repo_root, map_root, output_root)
    assert first.returncode == 0, first.stderr
    snapshots = sorted(path for path in output_root.iterdir() if path.is_dir())
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["snapshot_sha256"] == snapshot.name
    assert manifest["policy"] == {
        "extracted_sources_are_source_equivalents": True,
        "ingest_extracted_tree_only": True,
        "mapped_minified_artifacts_are_non_covering": True,
        "publish_via_code_ingest_only": True,
    }
    assert manifest["next_step"]["command"].startswith("vigil assess code-ingest ")
    assert "--include-minified" not in manifest["next_step"]["command"]
    assert (snapshot / "sources" / "src" / "app.ts").read_text(encoding="utf-8") == first_content
    duplicate_hash = hashlib.sha256(duplicate_content.encode()).hexdigest()[:12]
    assert (
        snapshot / "sources" / "src" / f"app__dup-{duplicate_hash}.ts"
    ).read_text(encoding="utf-8") == duplicate_content
    assert (
        snapshot / "sources" / "src" / "virtual.ts"
    ).read_text(encoding="utf-8") == "export const virtual = true;\n"
    assert len(list((snapshot / "sources" / "src").glob("app*.ts"))) == 2
    assert (
        snapshot / "sources" / "src" / "indexed.ts"
    ).read_text(encoding="utf-8") == "export const indexed = true;\n"

    records = manifest["records"]
    statuses = {(record["map_path"], record.get("source", "")): record["status"] for record in records}
    assert statuses[("app.js.map", "../escape.ts")] == "rejected_path"
    assert statuses[("app.js.map", "/absolute.ts")] == "rejected_path"
    assert statuses[("app.js.map", "https://attacker.invalid/source.ts")] == "rejected_path"
    assert statuses[("app.js.map", "missing.ts")] == "missing_content"
    assert statuses[("missing.css.map", "styles/main.scss")] == "missing_sources_content"
    assert statuses[("malformed.js.map", "")] == "malformed_map"
    assert not any(
        record["map_path"] == "indexed.js.map" and record["status"] == "missing_sources"
        for record in records
    )
    assert not (tmp_path / "escape.ts").exists()

    repeated = _run_extract(repo_root, map_root, output_root)
    assert repeated.returncode == 0, repeated.stderr
    assert "Reused immutable source-map snapshot" in repeated.stdout
    assert sorted(path for path in output_root.iterdir() if path.is_dir()) == snapshots

    payload = json.loads((map_root / "app.js.map").read_text(encoding="utf-8"))
    payload["sourcesContent"][0] = "export const first = 3;\n"
    (map_root / "app.js.map").write_text(json.dumps(payload), encoding="utf-8")
    changed_without_refresh = _run_extract(repo_root, map_root, output_root)
    assert changed_without_refresh.returncode != 0
    assert "--refresh" in changed_without_refresh.stderr
    refreshed = _run_extract(repo_root, map_root, output_root, "--refresh")
    assert refreshed.returncode == 0, refreshed.stderr
    refreshed_snapshots = sorted(path for path in output_root.iterdir() if path.is_dir())
    assert len(refreshed_snapshots) == 2
    assert (snapshot / "sources" / "src" / "app.ts").read_text(encoding="utf-8") == first_content
    refreshed_snapshot = next(path for path in refreshed_snapshots if path != snapshot)
    refreshed_manifest = json.loads(
        (refreshed_snapshot / "manifest.json").read_text(encoding="utf-8")
    )
    assert refreshed_manifest["snapshot_sha256"] != manifest["snapshot_sha256"]
    assert refreshed_manifest["next_step"]["repo_key"] == manifest["next_step"]["repo_key"]
