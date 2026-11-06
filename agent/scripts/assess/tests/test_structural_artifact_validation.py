from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_index, code_index_sync
from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file
from assess.lib.code_structural_identity import (
    STRUCTURAL_INDEXER_INPUTS,
    bind_structural_inputs,
    structural_input_digest,
)
from assess.lib.code_structural_metadata import validated_structural_metadata
from assess.lib.treesitter_index import index_file


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


@pytest.mark.parametrize("defect", ["identity", "duplicate", "registry_shortfall"])
def test_build_rejects_artifact_shapes_sync_cannot_publish(defect: str) -> None:
    source = b"def f(): pass\n"
    artifact = _artifact(source)
    if defect == "identity":
        artifact["functions"][0]["qualified_name"] = " f "
    elif defect == "duplicate":
        artifact["functions"] *= 2
        artifact["total_functions"] = 2
    else:
        artifact["total_functions"] = 2
    with pytest.raises(ValueError):
        code_index._validate_analysis_artifact(artifact, rel_path="bad.py", source_size=len(source))


def test_a_zero_callable_file_measured_at_file_scope_is_publishable() -> None:
    """The `<top-level>` scope reads file scope, so a module-level script with
    no callable can report what it found under `complete`."""
    source = b"<?php\necho $_GET['q'];\n"
    artifact = _artifact(source)
    artifact.update({
        "language": "php", "functions": [], "total_functions": 0,
        "security_sinks": [{"kind": "xss_output", "line": 2, "function": "<top-level>",
                            "snippet": "echo $_GET['q'];", "vuln_classes": ["web-app-injection"]}],
        "security_sources": [{"kind": "http_request_input", "line": 2, "snippet": "$_GET['q']"}],
        "entry_points": [{"name": "<top-level>", "line": 2, "kind": "php_script", "annotation": "$_GET"}],
        "signal_counts": {"entry_points": 1, "imports": 0, "security_sinks": 1, "security_sources": 1},
    })
    code_index._validate_analysis_artifact(artifact, rel_path="page.php", source_size=len(source))
    metadata = validated_structural_metadata(artifact, rel_path="page.php", source_size=len(source))
    assert metadata["structural_analysis_status"] == "complete"


@pytest.mark.parametrize(
    ("segments", "valid"),
    [
        ([{"line_start": 2, "line_end": 2}], True),
        ([{"line_start": 2, "line_end": 2}, {"line_start": 2, "line_end": 3}], False),
        ([{"line_start": 1, "line_end": 2}], False),
        ([{"line_start": 3, "line_end": 9}], False),
    ],
)
def test_top_level_segments_are_ordered_in_file_and_clear_of_callables(
    segments: list[dict], valid: bool
) -> None:
    source = b"def f(): pass\nrun()\nrun()\n"
    artifact = _artifact(source)
    artifact.update({"total_lines": 3, "top_level_segments": segments})

    def validate() -> None:
        code_index._validate_analysis_artifact(artifact, rel_path="run.py", source_size=len(source))

    if valid:
        validate()
    else:
        with pytest.raises(ValueError):
            validate()


@pytest.mark.parametrize(
    ("status", "valid"),
    [
        ("resolved", True),
        ("constant_unresolved:ACME_ROOT", True),
        ("unclassified", True),
        ("constant_unresolved:", False),
        ("found", False),
    ],
)
def test_an_include_record_carries_a_known_status(status: str, valid: bool) -> None:
    source = b"<?php\nrequire __DIR__ . '/boot.php';\n"
    artifact = _artifact(source)
    artifact.update({
        "language": "php", "functions": [], "total_functions": 0,
        "imports": ["__DIR__ . '/boot.php'"],
        "import_targets": [{"raw": "__DIR__ . '/boot.php'", "resolved": "", "kind": "include",
                            "construct": "require", "line": 2, "status": status}],
        "signal_counts": {"entry_points": 0, "imports": 1, "security_sinks": 0, "security_sources": 0},
    })
    if valid:
        validated_structural_metadata(artifact, rel_path="index.php", source_size=len(source))
    else:
        with pytest.raises(ValueError):
            validated_structural_metadata(artifact, rel_path="index.php", source_size=len(source))


@pytest.mark.parametrize("language,extension", [("javascript", "js"), ("typescript", "ts"), ("typescript", "tsx")])
def test_block_comment_exports_are_empty_and_publishable(language: str, extension: str) -> None:
    source = b"\xef\xbb\xbf/*\r\nexport const Dead = 1;\r\nexport class Gone {}\r\nmodule.exports = Dead;\r\n*/\r\n"
    artifact = index_file(f"dead.{extension}", language, source)
    assert artifact["exports"] == []
    assert artifact["total_exports"] == 0
    assert artifact["analysis_status"] == "complete"
    validated_structural_metadata(artifact, rel_path=f"dead.{extension}", source_size=len(source))


def test_comment_export_filter_keeps_live_exports_and_source_positions() -> None:
    source = b"/* export const Dead = 0; */\n/*\nexport interface Gone {}\n*/ export const Live = 1;\nexport interface Public {} // export const Fake = 0;\nexport function f() { /* export const Hidden = 0; */ return Live; }\n"
    artifact = index_file("live.ts", "typescript", source)
    assert [(item["name"], item["line"]) for item in artifact["exports"]] == [("Live", 4), ("Public", 5), ("f", 6)]
    assert artifact["functions"][0]["line_start"] == 6
    code_index._validate_analysis_artifact(artifact, rel_path="live.ts", source_size=len(source))
    validated_structural_metadata(artifact, rel_path="live.ts", source_size=len(source))


@pytest.mark.parametrize("source", [b"export const value = 1;\n", b"export interface Public {}\n", b"export type Public = string;\n"])
def test_legitimate_noncallable_exports_remain_publishable(source: bytes) -> None:
    artifact = index_file("public.ts", "typescript", source)
    assert artifact["total_functions"] == 0
    assert artifact["total_exports"] == 1
    code_index._validate_analysis_artifact(artifact, rel_path="public.ts", source_size=len(source))
    validated_structural_metadata(artifact, rel_path="public.ts", source_size=len(source))


@pytest.fixture
def index_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    raw = b"def f(): pass\n"
    origin = tmp_path / "origin"
    origin.mkdir()
    builder = SnapshotBuilder(tmp_path / "snapshots", "demo")
    rows = []
    for file_id, rel_path in enumerate(("a.py", "b.py"), 1):
        path = origin / rel_path
        path.write_bytes(raw)
        builder.add(rel_path, capture_regular_file(path), language="python")
        rows.append({"id": file_id, "repo_id": 7, "file_path": rel_path,
                     "language": "python", "file_hash": hashlib.sha256(raw).hexdigest()})
    snapshot = builder.finish(repo_key="demo", repo_name="demo", source_origin_path=str(origin),
                              git={"head": "", "branch": "", "dirty": None})
    repo = {"id": 7, "repo_key": "demo", "repo_path": str(snapshot.source_path),
            "active_generation": 1, "source_manifest_digest": "d" * 64}

    class Client:
        def __init__(self, *_args):
            pass

        def get(self, endpoint):
            if endpoint == "code/repos/7":
                return repo
            if endpoint == "code/repos":
                return [repo]
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return {"items": rows, "total": 2, "offset": 0, "count": 2, "has_more": False}

        def post(self, *_args, **_kwargs):
            pytest.fail("invalid structural artifacts must not be published")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    for module in (code_index, code_index_sync):
        monkeypatch.setattr(module, "AssessmentClient", Client)
        monkeypatch.setattr(module, "load_config", lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"))
    monkeypatch.setattr(code_index, "index_file", lambda _path, _language, source, **_kwargs: _artifact(source))
    args = SimpleNamespace(repo_path=str(snapshot.source_path), repo_id=7, repo_key="demo",
                           output_dir=str(tmp_path / "analysis-state"), file_list=None, engagement_dir=str(tmp_path))
    yield args, repo, Client
    for path in snapshot.source_path.parent.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    snapshot.source_path.parent.chmod(0o700)


def test_build_publishes_every_invalid_artifact_degraded(index_project, monkeypatch, capsys) -> None:
    args, _repo, _client = index_project

    def invalid_index(_path, _language, source, **_kwargs):
        artifact = _artifact(source)
        artifact["functions"][0]["qualified_name"] = " f "
        return artifact

    monkeypatch.setattr(code_index, "index_file", invalid_index)
    code_index.run(args)

    error = capsys.readouterr().err
    assert error.count("a.py") == 1 and error.count("b.py") == 1
    manifest = json.loads(_current_manifest(args).read_text())
    assert manifest["degraded_file_paths"] == ["a.py", "b.py"]
    for binding in manifest["files"].values():
        artifact = json.loads(
            (Path(args.output_dir) / "structural-index" / binding["index_path"]).read_text()
        )
        assert artifact["analysis_mode"] == "streaming_security_fallback"
        assert artifact["degradation_reason"] == "invalid_structural_artifact"


def test_sync_publishes_every_invalid_artifact_degraded(index_project, monkeypatch, capsys) -> None:
    args, _repo, client_type = index_project
    code_index.run(args)
    output = Path(args.output_dir)
    top_path = output / "structural-index-manifest.json"
    top = json.loads(top_path.read_text())
    manifest_path = output / top["repos"]["7"]["manifest_path"]
    manifest = json.loads(manifest_path.read_text())
    for binding in manifest["files"].values():
        artifact_path = output / "structural-index" / binding["index_path"]
        artifact = json.loads(artifact_path.read_text())
        artifact["functions"][0]["qualified_name"] = " f "
        raw = json.dumps(artifact).encode()
        artifact_path.chmod(0o600)
        artifact_path.write_bytes(raw)
        binding["index_sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_path.chmod(0o600)
    manifest_path.write_text(json.dumps(manifest))
    (payload,) = _sync_posts(args, client_type, monkeypatch)
    assert payload["degraded_file_paths"] == ["a.py", "b.py"]
    assert {
        (update["structural_analysis_status"], update["structural_degradation_reason"])
        for update in payload["updates"]
    } == {("degraded", "invalid_structural_artifact")}
    assert all(update["callables"] == [] for update in payload["updates"])
    error = capsys.readouterr().err
    assert "a.py" in error and "b.py" in error


def test_sync_reports_failures_across_selected_repositories(index_project, monkeypatch, capsys) -> None:
    args, repo, _client = index_project
    manifests = [("7", {"repo_id": 7}), ("8", {"repo_id": 8})]
    monkeypatch.setattr(code_index_sync, "_load_manifest", lambda _path: {})
    monkeypatch.setattr(code_index_sync, "_resolve_per_repo_manifests", lambda *_args, **_kwargs: manifests)
    monkeypatch.setattr(code_index_sync, "_find_backend_repo", lambda *_args, **_kwargs: copy.deepcopy(repo))

    def invalid_payload(_client, _repo, manifest, _root):
        raise ValueError(f"bad artifact in repo {manifest['repo_id']}")

    monkeypatch.setattr(code_index_sync, "_prepare_repo_payload", invalid_payload)
    with pytest.raises(SystemExit):
        code_index_sync.run(SimpleNamespace(manifest=str(Path(args.output_dir) / "manifest.json"),
                                           index_dir=None, repo_id=None, repo_key=None, engagement_dir=args.engagement_dir))
    error = capsys.readouterr().err
    assert "bad artifact in repo 7" in error and "bad artifact in repo 8" in error


def test_corrected_build_and_sync_preserve_historical_v6_artifacts(index_project, monkeypatch) -> None:
    args, repo, client_type = index_project
    source = Path(args.repo_path)
    snapshot = json.loads((source.parent / "manifest.json").read_text())
    rows = client_type().get("code/files?limit=5000&offset=0&repo_id=7")["items"]
    identity = structural_input_digest(
        bind_structural_inputs(snapshot["files"], {row["file_path"]: row for row in rows}, repo_id=7),
        repo_id=7, repo_generation=1, source_manifest_digest=repo["source_manifest_digest"],
    )
    output = Path(args.output_dir)
    historical = output / "structural-index" / "7" / "1" / "v6" / repo["source_manifest_digest"] / identity
    historical.mkdir(parents=True)
    old_manifest = historical / "manifest.json"
    old_bytes = b'{"schema":"structural-index/v6","historical":true}\n'
    old_manifest.write_bytes(old_bytes)
    (historical / "files").mkdir()
    old_manifest.chmod(0o444)
    (historical / "files").chmod(0o555)
    historical.chmod(0o555)

    code_index.run(args)
    top_path = output / "structural-index-manifest.json"
    top = json.loads(top_path.read_text())
    current_manifest = output / top["repos"]["7"]["manifest_path"]
    assert json.loads(current_manifest.read_text())["schema"] == "structural-index/v7"
    assert "v7" in current_manifest.parts
    posts = []

    def post(_self, endpoint, payload, **_kwargs):
        assert endpoint == "code/files/bulk-structural-metadata"
        posts.append(payload)
        return {field: payload[field] for field in (
            "repo_id", "repo_generation", "source_manifest_digest",
            "structural_input_digest", "structural_index_schema",
        )} | {"updated": len(payload["updates"])}

    monkeypatch.setattr(client_type, "post", post)
    code_index_sync.run(SimpleNamespace(manifest=str(top_path), index_dir=None,
                                       repo_id=None, repo_key=None, engagement_dir=args.engagement_dir))
    assert len(posts) == 1
    assert posts[0]["structural_index_schema"] == "structural-index/v7"
    assert old_manifest.read_bytes() == old_bytes
    assert old_manifest.stat().st_mode & 0o777 == 0o444


@pytest.mark.parametrize("selection", [{"repo_id": 7}, {"repo_key": "demo"}])
def test_selected_v7_sync_coexists_with_unselected_v6_aggregate_pointer(
    index_project, monkeypatch, tmp_path, request, selection, capsys,
) -> None:
    args, repo, client_type = index_project
    raw = b"def f(): pass\n"
    origin = tmp_path / "other-origin"
    origin.mkdir()
    path = origin / "other.py"
    path.write_bytes(raw)
    builder = SnapshotBuilder(tmp_path / "snapshots", "other")
    builder.add("other.py", capture_regular_file(path), language="python")
    snapshot = builder.finish(repo_key="other", repo_name="other", source_origin_path=str(origin),
                              git={"head": "", "branch": "", "dirty": None})

    def make_writable():
        for item in snapshot.source_path.parent.rglob("*"):
            item.chmod(0o700 if item.is_dir() else 0o600)
        snapshot.source_path.parent.chmod(0o700)

    request.addfinalizer(make_writable)
    other_repo = {**repo, "id": 8, "repo_key": "other", "repo_path": str(snapshot.source_path)}
    original_get = client_type.get

    def get(self, endpoint):
        if endpoint == "code/repos":
            return [repo, other_repo]
        if endpoint == "code/repos/8":
            return other_repo
        if endpoint == "code/files?limit=5000&offset=0&repo_id=8":
            row = {"id": 3, "repo_id": 8, "file_path": "other.py", "language": "python",
                   "file_hash": hashlib.sha256(raw).hexdigest()}
            return {"items": [row], "total": 1, "offset": 0, "count": 1, "has_more": False}
        return original_get(self, endpoint)

    monkeypatch.setattr(client_type, "get", get)
    other_args = SimpleNamespace(**(vars(args) | {"repo_id": 8, "repo_key": "other", "repo_path": str(snapshot.source_path)}))
    with monkeypatch.context() as legacy:
        legacy.setattr(code_index, "STRUCTURAL_INDEX_SCHEMA", "structural-index/v6")
        legacy.setattr(code_index, "STRUCTURAL_INDEX_PATH_VERSION", "v6")
        code_index.run(args)
        code_index.run(other_args)
    output = Path(args.output_dir)
    top_path = output / "structural-index-manifest.json"
    old_pointer = json.loads(top_path.read_text())["repos"]["8"]
    historical_bytes = {item: item.read_bytes() for item in output.rglob("*.json") if "v6" in item.parts}
    assert len(historical_bytes) == 5  # Two manifests and three per-file artifacts.

    code_index.run(args)
    assert json.loads(top_path.read_text())["repos"]["8"] == old_pointer
    posts = []

    def post(_self, endpoint, payload, **_kwargs):
        assert endpoint == "code/files/bulk-structural-metadata"
        posts.append(payload)
        return {field: payload[field] for field in (
            "repo_id", "repo_generation", "source_manifest_digest",
            "structural_input_digest", "structural_index_schema",
        )} | {"updated": len(payload["updates"])}

    monkeypatch.setattr(client_type, "post", post)
    sync_args = SimpleNamespace(manifest=str(top_path), index_dir=None, repo_id=None,
                                repo_key=None, engagement_dir=args.engagement_dir)
    code_index_sync.run(SimpleNamespace(**(vars(sync_args) | selection)))
    assert [payload["repo_id"] for payload in posts] == [7]
    assert posts[0]["structural_index_schema"] == "structural-index/v7"
    capsys.readouterr()
    with pytest.raises(SystemExit):
        code_index_sync.run(SimpleNamespace(**(vars(sync_args) | {"repo_id": 8})))
    assert "repo 8 manifest is not structural-index/v7" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        code_index_sync.run(sync_args)
    assert "repo 8 manifest is not structural-index/v7" in capsys.readouterr().err
    assert len(posts) == 1
    assert {item: item.read_bytes() for item in historical_bytes} == historical_bytes


def test_build_reports_phases_and_sparse_monotonic_file_activity(
    index_project, monkeypatch, capsys
) -> None:
    args, _repo, _client = index_project
    # The fake clock advances inside each parse, so parses run one at a time.
    args.jobs = 1
    clock = [100.0]
    durations = iter([29.0, 2.0])
    monkeypatch.setattr(code_index, "monotonic", lambda: clock[0], raising=False)

    def timed_index(_path, _language, source, **_kwargs):
        clock[0] += next(durations)
        return _artifact(source)

    monkeypatch.setattr(code_index, "index_file", timed_index)
    code_index.run(args)

    captured = capsys.readouterr()
    notices = [line for line in captured.err.splitlines() if line.startswith("code-index:")]
    phases = [word for word in ("validation", "binding", "indexing", "publication")
              if any(word in line for line in notices)]
    assert phases == ["validation", "binding", "indexing", "publication"]
    assert [next(index for index, line in enumerate(notices) if word in line)
            for word in phases] == sorted(
        next(index for index, line in enumerate(notices) if word in line) for word in phases
    )
    activity = [line for line in notices if "activity" in line]
    assert len(activity) == 1
    for value in ("processed=2/2", "indexed=2", "errors=0", "elapsed=31s"):
        assert value in activity[0]
    assert captured.out == ""
    output = Path(args.output_dir)
    aggregate = json.loads((output / "structural-index-manifest.json").read_text())
    manifest = json.loads((output / aggregate["repos"]["7"]["manifest_path"]).read_text())
    assert manifest["indexed_files"] == 2
    assert set(manifest["files"]) == {"a.py", "b.py"}


def test_build_activity_counts_processed_errors_without_claiming_indexed_artifacts(
    index_project, monkeypatch, capsys
) -> None:
    args, _repo, _client = index_project
    args.jobs = 1
    clock = [100.0]
    monkeypatch.setattr(code_index, "monotonic", lambda: clock[0], raising=False)

    def invalid_index(_path, _language, source, **_kwargs):
        clock[0] += 31.0
        return _artifact(source) | {"language": "ruby"}

    monkeypatch.setattr(code_index, "index_file", invalid_index)
    with pytest.raises(SystemExit) as exc:
        code_index.run(args)

    assert exc.value.code == 1
    captured = capsys.readouterr()
    activity = [line for line in captured.err.splitlines() if "code-index:" in line and "activity" in line]
    assert len(activity) == 2
    for line, count in zip(activity, (1, 2), strict=True):
        assert f"processed={count}/2" in line
        assert "indexed=0" in line
        assert f"errors={count}" in line
    assert "invalid structural artifacts" in captured.err
    assert captured.out == ""


def _renamed_artifact(source: bytes) -> dict:
    artifact = _artifact(source)
    artifact["functions"][0].update(name="g", qualified_name="g")
    return artifact


def _sync_posts(args, client_type, monkeypatch) -> list[dict]:
    posts: list[dict] = []

    def post(_self, endpoint, payload, **_kwargs):
        assert endpoint == "code/files/bulk-structural-metadata"
        posts.append(payload)
        return {field: payload[field] for field in (
            "repo_id", "repo_generation", "source_manifest_digest",
            "structural_input_digest", "structural_index_schema",
        )} | {"updated": len(payload["updates"])}

    monkeypatch.setattr(client_type, "post", post)
    code_index_sync.run(SimpleNamespace(
        manifest=str(Path(args.output_dir) / "structural-index-manifest.json"), index_dir=None,
        repo_id=None, repo_key=None, engagement_dir=args.engagement_dir,
    ))
    return posts


def _current_manifest(args) -> Path:
    output = Path(args.output_dir)
    top = json.loads((output / "structural-index-manifest.json").read_text())
    return output / top["repos"]["7"]["manifest_path"]


def test_indexer_upgrade_rebuilds_unchanged_snapshot_beside_history_and_sync_publishes_it(
    index_project, monkeypatch,
) -> None:
    args, _repo, client_type = index_project
    monkeypatch.setattr(code_index, "structural_indexer_digest", lambda: "a" * 64)
    code_index.run(args)
    old_manifest = _current_manifest(args)
    old_bytes = {path: path.read_bytes() for path in old_manifest.parent.rglob("*.json")}

    monkeypatch.setattr(code_index, "structural_indexer_digest", lambda: "b" * 64)
    monkeypatch.setattr(code_index, "index_file", lambda _path, _language, source, **_kwargs: _renamed_artifact(source))
    code_index.run(args)

    new_manifest = _current_manifest(args)
    assert new_manifest != old_manifest
    assert {path: path.read_bytes() for path in old_bytes} == old_bytes
    assert old_manifest.stat().st_mode & 0o777 == 0o444
    built = json.loads(new_manifest.read_text())
    assert built["indexer_digest"] == "b" * 64
    assert built["structural_input_digest"] == json.loads(old_bytes[old_manifest])["structural_input_digest"]
    posts = _sync_posts(args, client_type, monkeypatch)
    assert [payload["structural_index_manifest_path"] for payload in posts] == [str(new_manifest)]
    assert {item["callables"][0]["qualified_name"] for item in posts[0]["updates"]} == {"g"}


def test_sync_of_an_index_another_indexer_built_names_the_rebuild(
    index_project, monkeypatch, capsys,
) -> None:
    """After an upgrade, sync without a rebuild republishes what the old indexer
    found; it says so and prints the build that refreshes it."""
    args, repo, client_type = index_project
    monkeypatch.setattr(code_index, "structural_indexer_digest", lambda: "a" * 64)
    code_index.run(args)
    capsys.readouterr()

    monkeypatch.setattr(code_index_sync, "structural_indexer_digest", lambda: "a" * 64)
    _sync_posts(args, client_type, monkeypatch)
    assert "different indexer" not in capsys.readouterr().err

    monkeypatch.setattr(code_index_sync, "structural_indexer_digest", lambda: "b" * 64)
    posts = _sync_posts(args, client_type, monkeypatch)
    err = capsys.readouterr().err
    assert len(posts) == 1
    assert "repo 7: this structural index was built by a different indexer" in err
    assert f"vigil assess code-index build --repo-id 7 {repo['repo_path']}" in err


def test_identical_rebuild_with_the_same_indexer_reuses_the_artifact(index_project) -> None:
    args, _repo, _client = index_project
    code_index.run(args)
    manifest = _current_manifest(args)
    first = {path: path.read_bytes() for path in Path(args.output_dir, "structural-index").rglob("*.json")}

    code_index.run(args)

    assert _current_manifest(args) == manifest
    assert {path: path.read_bytes() for path in Path(args.output_dir, "structural-index").rglob("*.json")} == first


def test_rebuild_with_the_same_indexer_and_different_output_is_refused(index_project, monkeypatch, capsys) -> None:
    args, _repo, _client = index_project
    code_index.run(args)
    manifest = _current_manifest(args)
    aggregate = (Path(args.output_dir) / "structural-index-manifest.json").read_bytes()

    monkeypatch.setattr(code_index, "index_file", lambda _path, _language, source, **_kwargs: _renamed_artifact(source))
    with pytest.raises(SystemExit) as exc:
        code_index.run(args)

    assert exc.value.code == 1
    assert "existing generation-scoped index conflicts with the requested build" in capsys.readouterr().err
    assert (Path(args.output_dir) / "structural-index-manifest.json").read_bytes() == aggregate
    assert len(list(Path(args.output_dir, "structural-index").rglob("manifest.json"))) == 1
    assert _current_manifest(args) == manifest


def test_structural_indexer_inputs_declare_every_assess_module_their_libraries_import() -> None:
    assess_root = Path(code_index.__file__).resolve().parents[1]
    imported: set[str] = set()
    for rel_path in STRUCTURAL_INDEXER_INPUTS:
        if not rel_path.startswith("lib/"):
            continue
        for node in ast.walk(ast.parse((assess_root / rel_path).read_text(encoding="utf-8"))):
            if not isinstance(node, ast.ImportFrom) or not (node.module or "").startswith("assess."):
                continue
            package = node.module.removeprefix("assess.").replace(".", "/")
            for alias in node.names:
                candidate = f"{package}/{alias.name}.py"
                imported.add(candidate if (assess_root / candidate).is_file() else f"{package}.py")
    assert imported <= set(STRUCTURAL_INDEXER_INPUTS)
