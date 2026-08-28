"""I-140 — `code-sourcemap-extract` must not hand off an empty tree.

Three defects are pinned here:

1. ``..`` in a map's ``sources`` was rejected on sight at ANY depth, so the most
   common Rollup/Vite/tsc shape extracted nothing. It now resolves against the
   map file's own directory (where the source-map format defines it) and only a
   path that climbs past the extracted tree root still fails closed.
2. The manifest's ``next_step`` was composed from the pre-rename ``.tmp-<uuid>``
   staging directory, so the printed handoff named a path that never existed
   after the run — on every run, successful or not.
3. A zero-extraction run printed a confident ``code-ingest`` handoff and exited
   0, turning "measured nothing" into a durable "this product has no source".
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_sourcemap_extract as extract


def _args(map_root: Path, output_root: Path, refresh: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        map_root=str(map_root),
        output_root=str(output_root),
        refresh=refresh,
        engagement_dir=None,
    )


def _write_map(path: Path, sources: list[str], contents: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 3, "sources": sources, "sourcesContent": contents}),
        encoding="utf-8",
    )


def _snapshot(output_root: Path) -> Path:
    snapshots = [path for path in output_root.iterdir() if path.is_dir()]
    assert len(snapshots) == 1, snapshots
    return snapshots[0]


def _manifest(snapshot: Path) -> dict:
    return json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))


def test_parent_segments_resolve_against_the_map_directory(tmp_path, capsys):
    """Any `..` depth the map's own location can absorb now extracts."""
    map_root = tmp_path / "maps"
    output_root = tmp_path / "out"
    _write_map(
        map_root / "static" / "js" / "chunks" / "app.js.map",
        ["../../../src/a.ts", "../shared/b.ts"],
        ["export const a = 1;\n", "export const b = 2;\n"],
    )

    extract.run(_args(map_root, output_root))

    snapshot = _snapshot(output_root)
    assert (snapshot / "sources" / "src" / "a.ts").read_text(encoding="utf-8") == (
        "export const a = 1;\n"
    )
    assert (
        snapshot / "sources" / "static" / "js" / "shared" / "b.ts"
    ).read_text(encoding="utf-8") == "export const b = 2;\n"
    out = capsys.readouterr().out
    assert "Extracted 2 source file(s) from 1 source map(s)" in out
    assert "extracted: 2" in out


def test_a_path_that_climbs_past_the_tree_root_is_still_rejected(tmp_path):
    map_root = tmp_path / "maps"
    output_root = tmp_path / "out"
    _write_map(
        map_root / "assets" / "app.js.map",
        ["../../../../../../etc/passwd", "../src/kept.ts"],
        ["root:x:0:0:\n", "export const kept = 1;\n"],
    )

    extract.run(_args(map_root, output_root))

    snapshot = _snapshot(output_root)
    statuses = {
        record.get("source"): record["status"] for record in _manifest(snapshot)["records"]
    }
    assert statuses["../../../../../../etc/passwd"] == "rejected_path"
    assert statuses["../src/kept.ts"] == "extracted"
    assert not (tmp_path / "etc").exists()
    assert not (snapshot / "sources" / "etc").exists()


@pytest.mark.parametrize(
    "source",
    [
        "/absolute.ts",
        "C:/windows/system32/drivers.ts",
        "//attacker.invalid/source.ts",
        "https://attacker.invalid/source.ts",
    ],
)
def test_absolute_and_remote_sources_stay_rejected(source):
    """The non-`..` rejections the traversal rewrite must not loosen."""
    assert extract._safe_source_path("", source, ("assets", "js")) is None


def test_webpack_sources_are_not_anchored_to_the_map_directory():
    """webpack:// identifiers are absolute in their bundle namespace."""
    resolved = extract._safe_source_path("", "webpack://app/./src/foo.js", ("assets",))
    assert resolved is not None
    assert resolved.as_posix() == "app/src/foo.js"
    # ...and one that climbs out of that namespace still fails closed.
    assert extract._safe_source_path("", "webpack:///../../etc/passwd", ("assets",)) is None


def test_zero_extraction_refuses_and_emits_no_ingest_handoff(tmp_path, capsys):
    map_root = tmp_path / "maps"
    output_root = tmp_path / "out"
    _write_map(
        map_root / "app.js.map",
        ["../../src/a.ts", "../../src/b.ts"],
        ["export const a = 1;\n", "export const b = 2;\n"],
    )

    with pytest.raises(SystemExit) as excinfo:
        extract.run(_args(map_root, output_root))
    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert "vigil assess code-ingest" not in captured.out
    assert "vigil assess code-ingest" not in captured.err
    assert "Extracted 0 source file(s) from 1 source map(s)" in captured.err
    assert "rejected_path: 2" in captured.err

    snapshot = _snapshot(output_root)
    manifest = _manifest(snapshot)
    assert "next_step" not in manifest


def test_handoff_names_the_published_snapshot_not_the_staging_directory(tmp_path, capsys):
    map_root = tmp_path / "maps"
    output_root = tmp_path / "out"
    _write_map(map_root / "app.js.map", ["src/a.ts"], ["export const a = 1;\n"])

    extract.run(_args(map_root, output_root))

    snapshot = _snapshot(output_root)
    manifest = _manifest(snapshot)
    repo_path = Path(manifest["next_step"]["repo_path"])
    assert repo_path == snapshot / "sources"
    assert repo_path.is_dir()
    assert ".tmp-" not in manifest["next_step"]["command"]
    printed = capsys.readouterr().out
    assert str(repo_path) in printed
    assert ".tmp-" not in printed


def test_reused_snapshot_recomposes_the_handoff_and_honours_the_zero_guard(
    tmp_path, capsys
):
    map_root = tmp_path / "maps"
    output_root = tmp_path / "out"
    _write_map(map_root / "app.js.map", ["src/a.ts"], ["export const a = 1;\n"])
    extract.run(_args(map_root, output_root))
    snapshot = _snapshot(output_root)
    capsys.readouterr()

    # A manifest written before the staging-path fix names a directory that no
    # longer exists; the reuse branch must recompose rather than replay it.
    manifest = _manifest(snapshot)
    manifest["next_step"]["command"] = "vigil assess code-ingest /out/.tmp-stale/sources"
    manifest["next_step"]["repo_path"] = "/out/.tmp-stale/sources"
    (snapshot / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    extract.run(_args(map_root, output_root))
    reused = capsys.readouterr().out
    assert "Reused immutable source-map snapshot" in reused
    assert ".tmp-stale" not in reused
    assert str(snapshot / "sources") in reused

    # And a stored zero-extraction manifest refuses on reuse too.
    manifest["records"] = [{"map_path": "app.js.map", "status": "rejected_path"}]
    (snapshot / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        extract.run(_args(map_root, output_root))
    assert excinfo.value.code == 1
    replayed = capsys.readouterr()
    assert "vigil assess code-ingest" not in replayed.out
    assert "rejected_path: 1" in replayed.err
