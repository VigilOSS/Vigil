"""A moved or cloned engagement keeps validating its sealed sources and structural index.

The content address and the per-file digests authenticate a sealed snapshot; the
directory it sits in is its location. Neither the sealed manifest nor the structural
index may tie validity to the absolute engagement path recorded when it was written,
and the backend's stored ``repo_path`` names a snapshot by identity, not location.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_index, code_index_sync
from assess.lib.code_snapshot import (
    SnapshotBuilder,
    capture_regular_file,
    validate_snapshot,
)
from _fake_client import StubClient

_RAW = b"def f(): pass\n"
_REPO_KEY = "acme-app"


def _artifact(source: bytes) -> dict:
    return {
        "language": "python", "total_lines": 1, "total_functions": 1,
        "total_exports": 0,
        "functions": [{"name": "f", "qualified_name": "f", "line_start": 1, "line_end": 1}],
        **{field: [] for field in (
            "entry_points", "security_sinks", "security_sources", "call_sites",
            "imports", "import_targets", "exports", "classes",
        )},
        "structural_index_available": True, "analysis_status": "complete",
        "analysis_mode": "tree_sitter", "degradation_reason": None,
        "source_size": len(source), "bytes_scanned": len(source),
        "unavailable_dimensions": [], "artifact_truncated": False,
        "truncated_dimensions": [],
        "signal_counts": {field: 0 for field in (
            "entry_points", "imports", "security_sinks", "security_sources",
        )},
    }


def _writable(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


def _rewrite_sealed_json(path: Path, update) -> None:
    """Rewrite one sealed JSON manifest in place, restoring its sealed modes."""
    path.parent.chmod(0o755)
    path.chmod(0o644)
    value = json.loads(path.read_text(encoding="utf-8"))
    update(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)
    path.parent.chmod(0o555)


class _Workspace:
    """An engagement sealed under ``before/`` that can be moved to ``after/``."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.before = tmp_path / "before" / "engagements" / "acme-eng"
        self.after = tmp_path / "after" / "engagements" / "acme-eng"
        self.engagement = self.before
        origin = tmp_path / "origin"
        origin.mkdir()
        builder = SnapshotBuilder(self.snapshots_root, _REPO_KEY)
        self.rows = []
        for file_id, rel_path in enumerate(("a.py", "b.py"), 1):
            path = origin / rel_path
            path.write_bytes(_RAW)
            builder.add(rel_path, capture_regular_file(path), language="python")
            self.rows.append({"id": file_id, "repo_id": 7, "file_path": rel_path,
                              "language": "python", "file_hash": hashlib.sha256(_RAW).hexdigest()})
        self.snapshot = builder.finish(
            repo_key=_REPO_KEY, repo_name="acme-app", source_origin_path=str(origin),
            git={"head": "", "branch": "", "dirty": None},
        )
        self.digest = self.snapshot.snapshot_digest
        # The backend keeps the absolute path it was registered with.
        self.repo = {"id": 7, "repo_key": _REPO_KEY, "repo_path": str(self.snapshot.source_path),
                     "active_generation": 1, "source_manifest_digest": "d" * 64}

    @property
    def snapshots_root(self) -> Path:
        return self.engagement / "tools" / "analysis-state" / "code-snapshots"

    @property
    def snapshot_root(self) -> Path:
        return self.snapshots_root / _REPO_KEY / self.digest

    @property
    def analysis_state(self) -> Path:
        return self.engagement / "tools" / "analysis-state"

    def move(self) -> None:
        os.rename(self.tmp_path / "before", self.tmp_path / "after")
        self.engagement = self.after

    def build_args(self) -> SimpleNamespace:
        return SimpleNamespace(
            repo_path=str(self.snapshot_root / "source"), repo_id=7, repo_key=_REPO_KEY,
            output_dir=str(self.analysis_state), file_list=None,
            engagement_dir=str(self.engagement),
        )

    def sync_args(self) -> SimpleNamespace:
        return SimpleNamespace(
            manifest=str(self.analysis_state / "structural-index-manifest.json"),
            index_dir=None, repo_id=None, repo_key=None, engagement_dir=str(self.engagement),
        )

    def structural_manifest(self) -> Path:
        top = json.loads((self.analysis_state / "structural-index-manifest.json").read_text())
        return self.analysis_state / top["repos"]["7"]["manifest_path"]


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    space = _Workspace(tmp_path)
    posts: list[dict] = []

    class Client(StubClient):
        def get(self, endpoint):
            if endpoint == "code/repos/7":
                return space.repo
            if endpoint == "code/repos":
                return [space.repo]
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return {"items": space.rows, "total": 2, "offset": 0, "count": 2, "has_more": False}

        def post(self, endpoint, payload, **_kwargs):
            assert endpoint == "code/files/bulk-structural-metadata"
            posts.append(payload)
            return {field: payload[field] for field in (
                "repo_id", "repo_generation", "source_manifest_digest",
                "structural_input_digest", "structural_index_schema",
            )} | {"updated": len(payload["updates"])}

    for module in (code_index, code_index_sync):
        monkeypatch.setattr(module, "AssessmentClient", Client)
        monkeypatch.setattr(
            module, "load_config",
            lambda flag=None: SimpleNamespace(
                base_url="http://example.test", engagement_key="eng", engagement_dir=flag,
            ),
        )
    monkeypatch.setattr(
        code_index, "index_file", lambda _path, _language, source, **_kwargs: _artifact(source)
    )
    space.posts = posts
    yield space
    _writable(tmp_path)


def test_a_snapshot_sealed_before_a_move_validates_after_it(workspace) -> None:
    workspace.move()

    manifest = validate_snapshot(workspace.snapshot_root, expected_digest=workspace.digest)

    assert manifest["snapshot_digest"] == workspace.digest


def test_a_legacy_absolute_binding_from_a_prior_layout_validates_after_the_move(workspace) -> None:
    legacy = (
        workspace.tmp_path / "old-install" / "agent" / "engagements" / "acme-eng" / "tools"
        / "analysis-state" / "code-snapshots" / _REPO_KEY / workspace.digest / "source"
    )
    _rewrite_sealed_json(
        workspace.snapshot_root / "manifest.json",
        lambda value: value.update(source_path=str(legacy)),
    )
    workspace.move()

    manifest = validate_snapshot(workspace.snapshot_root, expected_digest=workspace.digest)

    assert manifest["snapshot_digest"] == workspace.digest
    # Re-sealing identical content after the move reuses the legacy-bound seal.
    builder = SnapshotBuilder(workspace.snapshots_root, _REPO_KEY)
    for rel_path in ("a.py", "b.py"):
        builder.add(
            rel_path,
            capture_regular_file(workspace.tmp_path / "origin" / rel_path),
            language="python",
        )
    resealed = builder.finish(
        repo_key=_REPO_KEY, repo_name="acme-app",
        source_origin_path=str(workspace.tmp_path / "origin"),
        git={"head": "", "branch": "", "dirty": None},
    )
    assert (resealed.snapshot_digest, resealed.reused) == (workspace.digest, True)
    assert resealed.source_path == workspace.snapshot_root / "source"


def test_a_snapshot_root_relative_binding_validates_after_the_move(workspace) -> None:
    _rewrite_sealed_json(
        workspace.snapshot_root / "manifest.json",
        lambda value: value.update(source_path="source"),
    )
    workspace.move()

    manifest = validate_snapshot(workspace.snapshot_root, expected_digest=workspace.digest)

    assert manifest["source_path"] == "source"


@pytest.mark.parametrize(
    "binding",
    [
        "elsewhere",
        "../source",
        "/srv/acme/code-snapshots/other-app/{digest}/source",
        "/srv/acme/code-snapshots/acme-app/{other}/source",
        "/srv/acme/code-snapshots/acme-app/{digest}/manifest.json",
        "",
    ],
)
def test_a_binding_that_names_another_snapshot_is_refused(workspace, binding: str) -> None:
    value = binding.format(digest=workspace.digest, other="e" * 64)
    _rewrite_sealed_json(
        workspace.snapshot_root / "manifest.json",
        lambda manifest: manifest.update(source_path=value),
    )
    workspace.move()

    with pytest.raises(ValueError, match="source path binding"):
        validate_snapshot(workspace.snapshot_root, expected_digest=workspace.digest)


def test_a_tampered_snapshot_still_fails_after_the_move(workspace) -> None:
    workspace.move()
    sealed = workspace.snapshot_root / "source" / "a.py"
    sealed.parent.chmod(0o755)
    sealed.chmod(0o644)
    sealed.write_bytes(b"def f(): return 1\n")
    sealed.chmod(0o444)
    sealed.parent.chmod(0o555)

    with pytest.raises(ValueError, match="file mismatch"):
        validate_snapshot(workspace.snapshot_root, expected_digest=workspace.digest)
    # The manifest's own content address is unaffected by where it lives.
    _rewrite_sealed_json(
        workspace.snapshot_root / "manifest.json",
        lambda manifest: manifest["files"][0].update(size=999),
    )
    with pytest.raises(ValueError, match="content address mismatch"):
        validate_snapshot(workspace.snapshot_root, deep=False)


def test_index_built_before_a_move_syncs_after_it(workspace) -> None:
    code_index.run(workspace.build_args())
    workspace.move()

    code_index_sync.run(workspace.sync_args())

    assert [payload["repo_id"] for payload in workspace.posts] == [7]
    assert len(workspace.posts[0]["updates"]) == 2
    assert workspace.posts[0]["structural_index_manifest_path"] == str(
        workspace.structural_manifest().resolve()
    )


def test_rebuilding_after_a_move_reuses_the_generation_and_syncs(workspace) -> None:
    code_index.run(workspace.build_args())
    before = workspace.structural_manifest().relative_to(workspace.analysis_state)
    workspace.move()

    code_index.run(workspace.build_args())
    code_index_sync.run(workspace.sync_args())

    assert workspace.structural_manifest().relative_to(workspace.analysis_state) == before
    assert len(workspace.posts) == 1


def _make_structural_manifest_legacy(workspace) -> None:
    """Rewrite the built manifest with the absolute bindings earlier builds stored."""
    manifest_path = workspace.structural_manifest().resolve()
    source = (workspace.snapshot_root / "source").resolve()

    def legacy(value: dict) -> None:
        value["source_path"] = str(source)
        value["source_snapshot_manifest_path"] = str(source.parent / "manifest.json")
        value["manifest_path"] = str(manifest_path)

    _rewrite_sealed_json(manifest_path, legacy)


def test_a_legacy_absolute_structural_manifest_syncs_and_rebuilds_after_a_move(workspace) -> None:
    code_index.run(workspace.build_args())
    _make_structural_manifest_legacy(workspace)
    workspace.move()

    code_index_sync.run(workspace.sync_args())
    code_index.run(workspace.build_args())
    code_index_sync.run(workspace.sync_args())

    assert [payload["repo_id"] for payload in workspace.posts] == [7, 7]


@pytest.mark.parametrize("moved", [False, True])
def test_a_legacy_structural_manifest_with_a_foreign_manifest_path_is_refused(
    workspace, capsys, moved: bool,
) -> None:
    code_index.run(workspace.build_args())
    _make_structural_manifest_legacy(workspace)
    _rewrite_sealed_json(
        workspace.structural_manifest().resolve(),
        lambda value: value.update(manifest_path="/srv/acme/structural-index/9/1/manifest.json"),
    )
    if moved:
        workspace.move()

    with pytest.raises(SystemExit):
        code_index_sync.run(workspace.sync_args())

    error = capsys.readouterr().err
    assert "Cannot sync structural index" in error
    if not moved:
        # The recorded source still exists, so the manifest's own identity refuses it.
        assert "structural manifest path differs from its identity" in error
    assert workspace.posts == []


def test_sync_refuses_a_backend_repo_bound_to_another_snapshot(workspace, capsys) -> None:
    code_index.run(workspace.build_args())
    workspace.move()
    workspace.repo["repo_path"] = str(
        workspace.snapshots_root / _REPO_KEY / ("e" * 64) / "source"
    )

    with pytest.raises(SystemExit):
        code_index_sync.run(workspace.sync_args())

    assert "sealed source path differs from the backend" in capsys.readouterr().err
    assert workspace.posts == []


def test_build_refuses_a_backend_repo_bound_to_another_snapshot(workspace, capsys) -> None:
    workspace.move()
    workspace.repo["repo_path"] = str(
        workspace.snapshots_root / _REPO_KEY / ("e" * 64) / "source"
    )

    with pytest.raises(SystemExit):
        code_index.run(workspace.build_args())

    assert "backend repo path differs from snapshot" in capsys.readouterr().err


def test_build_without_a_repo_id_finds_the_moved_snapshot_by_identity(workspace) -> None:
    workspace.move()
    args = workspace.build_args()
    args.repo_id = None

    code_index.run(args)
    code_index_sync.run(workspace.sync_args())

    assert [payload["repo_id"] for payload in workspace.posts] == [7]


def _clone(workspace) -> Path:
    """Copy the engagement, leaving the original in place: the same snapshot identity twice."""
    import shutil

    shutil.copytree(workspace.tmp_path / "before", workspace.tmp_path / "after", symlinks=True)
    return workspace.after


def test_build_refuses_another_engagements_copy_of_the_same_snapshot(workspace, capsys) -> None:
    clone = _clone(workspace)
    args = workspace.build_args()
    args.engagement_dir = str(clone)

    with pytest.raises(SystemExit):
        code_index.run(args)

    assert "is not under this engagement's" in capsys.readouterr().err


def test_sync_refuses_another_engagements_copy_of_the_same_snapshot(workspace, capsys) -> None:
    code_index.run(workspace.build_args())
    clone = _clone(workspace)
    args = workspace.sync_args()
    args.engagement_dir = str(clone)

    with pytest.raises(SystemExit):
        code_index_sync.run(args)

    assert "is not under this engagement's" in capsys.readouterr().err
    assert workspace.posts == []
