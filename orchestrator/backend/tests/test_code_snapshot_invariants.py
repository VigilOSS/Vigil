from __future__ import annotations

import codecs
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO_ROOT / "agent" / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from assess.lib.code_snapshot import (  # noqa: E402
    SOURCE_MANIFEST_SCHEMA,
    SnapshotBuilder,
    capture_regular_file,
    validate_repo_key,
    validate_snapshot,
)
from assess.lib import code_snapshot as producer_snapshot  # noqa: E402
from app import code_snapshot as backend_snapshot  # noqa: E402
from assess.lib.trusted_exec import (  # noqa: E402
    resolve_trusted_tool,
    trusted_environment,
)
from app.code_snapshot import (  # noqa: E402
    SnapshotAttestationError,
    attest_verified_snapshot,
)


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _restore_tree_writable(path: Path) -> None:
    if not path.exists():
        return
    for root, directories, files in os.walk(path, topdown=False, followlinks=False):
        for filename in files:
            file_path = Path(root) / filename
            if not file_path.is_symlink():
                os.chmod(file_path, 0o600, follow_symlinks=False)
        for dirname in directories:
            directory = Path(root) / dirname
            if not directory.is_symlink():
                os.chmod(directory, 0o700, follow_symlinks=False)
    os.chmod(path, 0o700, follow_symlinks=False)


def test_trusted_tool_rejects_source_owned_final_symlink_escape(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source_bin = source / "bin"
    source_bin.mkdir(parents=True)
    attacker = _make_executable(tmp_path / "attacker" / "git")
    (source_bin / "git").symlink_to(attacker)
    trusted = _make_executable(tmp_path / "trusted" / "git")

    resolved = resolve_trusted_tool(
        "git",
        source_root=source,
        path=f"{source_bin}{os.pathsep}{trusted.parent}",
    )

    assert resolved == str(trusted.resolve())


def test_trusted_tool_and_environment_reject_source_owned_path_symlink_escape(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    attacker_dir = tmp_path / "attacker"
    _make_executable(attacker_dir / "ctags")
    source_link = source / "linked-bin"
    source_link.symlink_to(attacker_dir, target_is_directory=True)
    trusted = _make_executable(tmp_path / "trusted" / "ctags")
    supplied_path = f"{source_link}{os.pathsep}{trusted.parent}"

    resolved = resolve_trusted_tool(
        "ctags",
        source_root=source,
        path=supplied_path,
    )
    environment = trusted_environment(source_root=source, path=supplied_path)

    assert resolved == str(trusted.resolve())
    assert environment["PATH"] == str(trusted.parent.resolve())


def test_validate_repo_key_enforces_portable_utf8_component_limit() -> None:
    assert validate_repo_key("a" * 255) == "a" * 255

    with pytest.raises(ValueError, match="repo_key"):
        validate_repo_key("a" * 256)
    with pytest.raises(ValueError, match="repo_key"):
        validate_repo_key("é" * 128)


def test_backend_attestation_rejects_non_object_manifest_rows_without_500(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    engagement_root = tmp_path / "engagement"
    digest = "a" * 64
    snapshot_root = (
        engagement_root
        / "tools"
        / "analysis-state"
        / "code-snapshots"
        / "malformed-repo"
        / digest
    )
    source = snapshot_root / "source"
    source.mkdir(parents=True)
    manifest = {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "repo_key": "malformed-repo",
        "repo_name": "Malformed repo",
        "source_origin_path": "/tmp/malformed-repo",
        "git": {"head": "", "branch": "", "dirty": None},
        "files": [1],
        "excluded_entries": [],
        "source_path": str(source),
        "snapshot_digest": digest,
    }
    manifest_path = snapshot_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o444)
    source.chmod(0o555)
    snapshot_root.chmod(0o555)
    request.addfinalizer(lambda: _restore_tree_writable(engagement_root))

    with pytest.raises(SnapshotAttestationError, match="file record"):
        attest_verified_snapshot(
            engagement_root=engagement_root,
            metadata={
                "repo_key": "malformed-repo",
                "name": "Malformed repo",
                "repo_path": str(source),
                "source_origin_path": "/tmp/malformed-repo",
                "source_kind": "directory",
                "snapshot_manifest_path": str(manifest_path),
                "snapshot_digest": digest,
                "commit_hash": "",
                "branch": "",
                "worktree_dirty": None,
            },
        )


def test_backend_attestation_rejects_deeply_nested_manifest_without_500(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    engagement_root = (tmp_path / "engagement").resolve()
    digest = "a" * 64
    snapshot_root = (
        engagement_root
        / "tools"
        / "analysis-state"
        / "code-snapshots"
        / "deep-manifest-repo"
        / digest
    )
    source = snapshot_root / "source"
    source.mkdir(parents=True)
    manifest_path = snapshot_root / "manifest.json"
    manifest_path.write_bytes(
        b'{"nested":' + (b"[" * 20_000) + b"0" + (b"]" * 20_000) + b"}"
    )
    manifest_path.chmod(0o444)
    source.chmod(0o555)
    snapshot_root.chmod(0o555)
    request.addfinalizer(lambda: _restore_tree_writable(engagement_root))

    with pytest.raises(SnapshotAttestationError, match="nesting exceeds"):
        attest_verified_snapshot(
            engagement_root=engagement_root,
            metadata={
                "repo_key": "deep-manifest-repo",
                "name": "Deep manifest repo",
                "repo_path": str(source),
                "source_origin_path": "/tmp/deep-manifest-repo",
                "source_kind": "directory",
                "snapshot_manifest_path": str(manifest_path),
                "snapshot_digest": digest,
                "commit_hash": "",
                "branch": "",
                "worktree_dirty": None,
            },
        )


def _build_backend_attestation_fixture(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    *,
    repo_key: str = "attested-repo",
    git: dict[str, object] | None = None,
    source_bytes: bytes = b"print('safe')\n",
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    engagement_root = (tmp_path / "engagement").resolve()
    origin = engagement_root / "tools" / "analysis-state" / "fixture-origin"
    source_file = origin / "src" / "main.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(source_bytes)
    captured = capture_regular_file(source_file)
    staged = {
        "src/main.py": {
            "file_path": "src/main.py",
            "language": "python",
            "loc": captured.loc,
            "file_hash": captured.sha256,
            "header_snippet": captured.header,
            "git_churn_score": 0,
            "has_past_cve_fix": False,
        }
    }
    builder = SnapshotBuilder(
        engagement_root / "tools" / "analysis-state" / "code-snapshots",
        repo_key,
    )
    builder.add("src/main.py", captured, language="python")
    provenance = git or {"head": "", "branch": "", "dirty": None}
    sealed = builder.finish(
        repo_key=repo_key,
        repo_name="Attested repo",
        source_origin_path="/tmp/attested-origin",
        git=provenance,
        excluded_entries=[],
    )
    request.addfinalizer(lambda: _restore_tree_writable(engagement_root))
    metadata: dict[str, object] = {
        "repo_key": repo_key,
        "name": "Attested repo",
        "repo_path": str(sealed.source_path),
        "source_origin_path": "/tmp/attested-origin",
        "source_kind": "git" if provenance["head"] else "directory",
        "snapshot_manifest_path": str(sealed.manifest_path),
        "snapshot_digest": sealed.snapshot_digest,
        "commit_hash": provenance["head"],
        "branch": provenance["branch"],
        "worktree_dirty": provenance["dirty"],
        "analyzable_files": 1,
        "total_files": 1,
        "total_loc": staged["src/main.py"]["loc"],
        "_engagement_root": engagement_root,
    }
    return metadata, staged


def test_backend_attestation_accepts_genuine_snapshot_builder_output(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")

    with attest_verified_snapshot(
        engagement_root=Path(str(engagement_root)),
        metadata=metadata,
    ) as attestation:
        attestation.assert_staged_inventory(staged, metadata)
        attestation.verify_unchanged()


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_backend_attestation_accepts_bom_encoded_source_without_transcoding(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    encoding: str,
) -> None:
    source_bytes = "print('safe')\r\nprint('😀')\r\n".encode(encoding)
    metadata, staged = _build_backend_attestation_fixture(
        tmp_path, request, source_bytes=source_bytes
    )
    engagement_root = metadata.pop("_engagement_root")

    with attest_verified_snapshot(
        engagement_root=Path(str(engagement_root)), metadata=metadata
    ) as attestation:
        attestation.assert_staged_inventory(staged, metadata)
        attestation.verify_unchanged()

    assert (Path(str(metadata["repo_path"])) / "src/main.py").read_bytes() == source_bytes


def _build_historical_snapshot(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    *,
    data: bytes,
    loc: int,
    schema: str = "code-source-manifest/v2",
) -> tuple[Path, dict[str, object], dict[str, dict[str, object]]]:
    engagement_root = (tmp_path / "engagement").resolve()
    payload = {
        "schema": schema,
        "repo_key": "historical",
        "repo_name": "Historical snapshot",
        "source_origin_path": "/tmp/historical",
        "git": {"head": "", "branch": "", "dirty": None},
        "files": [{
            "file_path": "source.txt",
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "loc": loc,
            "language": "text",
            "executable": False,
        }],
        "excluded_entries": [],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    snapshot = engagement_root / "tools/analysis-state/code-snapshots/historical" / digest
    source = snapshot / "source"
    source.mkdir(parents=True)
    (source / "source.txt").write_bytes(data)
    manifest_path = snapshot / "manifest.json"
    manifest_path.write_text(
        json.dumps({**payload, "source_path": str(source), "snapshot_digest": digest}),
        encoding="utf-8",
    )
    (source / "source.txt").chmod(0o444)
    manifest_path.chmod(0o444)
    source.chmod(0o555)
    snapshot.chmod(0o555)
    request.addfinalizer(lambda: _restore_tree_writable(engagement_root))
    metadata = {
        "repo_key": "historical",
        "name": "Historical snapshot",
        "repo_path": str(source),
        "source_origin_path": "/tmp/historical",
        "source_kind": "directory",
        "snapshot_manifest_path": str(manifest_path),
        "snapshot_digest": digest,
        "commit_hash": "",
        "branch": "",
        "worktree_dirty": None,
        "analyzable_files": 1,
        "total_files": 1,
        "total_loc": loc,
    }
    staged = {"source.txt": {
        "file_path": "source.txt",
        "file_hash": hashlib.sha256(data).hexdigest(),
        "loc": loc,
        "language": "text",
        "header_snippet": data.decode("utf-8", errors="replace"),
        "git_churn_score": 0,
        "has_past_cve_fix": False,
    }}
    return engagement_root, metadata, staged


@pytest.mark.parametrize("validator", ["producer", "backend"])
@pytest.mark.parametrize("chunk_size", [1, 7])
@pytest.mark.parametrize(
    ("data", "loc"),
    [
        (codecs.BOM_UTF8 + b"one\r\ntwo\r\n", 2),
        (codecs.BOM_UTF32_LE + "one\r\ntwo\r\n".encode("utf-32-le"), 5),
        (codecs.BOM_UTF32_BE + "one\r\ntwo\r\n".encode("utf-32-be"), 4),
        (codecs.BOM_UTF8, 1),
    ],
    ids=["utf8-bom-header", "utf32-le-raw-loc", "utf32-be-raw-loc", "bom-only"],
)
def test_historical_v2_snapshot_validates_without_rewriting_metadata(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
    loc: int,
    chunk_size: int,
    validator: str,
) -> None:
    engagement_root, metadata, staged = _build_historical_snapshot(
        tmp_path, request, data=data, loc=loc
    )
    manifest = Path(str(metadata["snapshot_manifest_path"]))
    manifest_bytes = manifest.read_bytes()
    monkeypatch.setattr(producer_snapshot, "_READ_CHUNK_SIZE", chunk_size)
    monkeypatch.setattr(backend_snapshot, "_READ_CHUNK_SIZE", chunk_size)

    if validator == "producer":
        validate_snapshot(manifest.parent, expected_digest=str(metadata["snapshot_digest"]))
    else:
        with attest_verified_snapshot(
            engagement_root=engagement_root, metadata=metadata
        ) as attestation:
            attestation.assert_staged_inventory(staged, metadata)
            attestation.verify_unchanged()

    assert manifest.read_bytes() == manifest_bytes
    assert (Path(str(metadata["repo_path"])) / "source.txt").read_bytes() == data


def test_new_snapshot_authenticates_v3_text_semantics(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _ = _build_backend_attestation_fixture(tmp_path, request)
    manifest = json.loads(Path(str(metadata["snapshot_manifest_path"])).read_text())
    assert manifest["schema"] == "code-source-manifest/v3"


@pytest.mark.parametrize("validator", ["producer", "backend"])
@pytest.mark.parametrize("schema", ["code-source-manifest/v1", "code-source-manifest/v99"])
def test_snapshot_rejects_authenticated_unknown_schema(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    validator: str,
    schema: str,
) -> None:
    engagement_root, metadata, _ = _build_historical_snapshot(
        tmp_path, request, data=b"one\n", loc=1, schema=schema
    )
    with pytest.raises(ValueError, match="unsupported"):
        if validator == "producer":
            validate_snapshot(Path(str(metadata["snapshot_manifest_path"])).parent)
        else:
            attest_verified_snapshot(engagement_root=engagement_root, metadata=metadata)


@pytest.mark.parametrize("validator", ["producer", "backend"])
def test_snapshot_schema_change_requires_new_content_address(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    validator: str,
) -> None:
    engagement_root, metadata, _ = _build_historical_snapshot(
        tmp_path, request, data=b"one\n", loc=1
    )
    manifest = Path(str(metadata["snapshot_manifest_path"]))
    payload = json.loads(manifest.read_text())
    payload["schema"] = "code-source-manifest/v3"
    manifest.chmod(0o644)
    manifest.write_text(json.dumps(payload))
    manifest.chmod(0o444)
    with pytest.raises(ValueError, match="content address mismatch"):
        if validator == "producer":
            validate_snapshot(manifest.parent)
        else:
            attest_verified_snapshot(engagement_root=engagement_root, metadata=metadata)


def test_backend_attestation_rejects_foreign_engagement_snapshot(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    metadata.pop("_engagement_root")
    foreign_engagement = (tmp_path / "foreign-engagement").resolve()
    foreign_engagement.mkdir()

    with pytest.raises(SnapshotAttestationError, match="engagement-owned"):
        attest_verified_snapshot(
            engagement_root=foreign_engagement,
            metadata=metadata,
        )


def test_backend_attestation_rejects_symlinked_snapshot_ancestor(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")
    repo_root = Path(str(metadata["snapshot_manifest_path"])).parent.parent
    relocated = repo_root.with_name(f"{repo_root.name}-relocated")
    repo_root.rename(relocated)
    repo_root.symlink_to(relocated, target_is_directory=True)

    with pytest.raises(SnapshotAttestationError):
        attest_verified_snapshot(
            engagement_root=Path(str(engagement_root)),
            metadata=metadata,
        )


def test_backend_attestation_rejects_request_git_provenance_drift(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(
        tmp_path,
        request,
        git={"head": "a" * 40, "branch": "main", "dirty": False},
    )
    engagement_root = metadata.pop("_engagement_root")
    metadata["branch"] = "attacker-controlled"

    with pytest.raises(SnapshotAttestationError, match="git provenance"):
        attest_verified_snapshot(
            engagement_root=Path(str(engagement_root)),
            metadata=metadata,
        )


def test_backend_attestation_rejects_manifest_content_address_drift(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")
    manifest_path = Path(str(metadata["snapshot_manifest_path"]))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["language"] = "ruby"
    manifest_path.chmod(0o644)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o444)

    with pytest.raises(SnapshotAttestationError, match="content address mismatch"):
        attest_verified_snapshot(
            engagement_root=Path(str(engagement_root)),
            metadata=metadata,
        )


def test_backend_attestation_rejects_actual_source_byte_drift(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")
    source_file = Path(str(metadata["repo_path"])) / "src" / "main.py"
    source_file.chmod(0o644)
    source_file.write_text("print('evil')\n", encoding="utf-8")
    source_file.chmod(0o444)

    with pytest.raises(SnapshotAttestationError, match="source_sha256 mismatch"):
        attest_verified_snapshot(
            engagement_root=Path(str(engagement_root)),
            metadata=metadata,
        )


def test_backend_attestation_rejects_staged_inventory_drift(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")
    staged["src/main.py"]["file_hash"] = "b" * 64

    with attest_verified_snapshot(
        engagement_root=Path(str(engagement_root)),
        metadata=metadata,
    ) as attestation:
        with pytest.raises(SnapshotAttestationError, match="file_hash"):
            attestation.assert_staged_inventory(staged, metadata)


def test_backend_attestation_maps_final_manifest_removal_to_attestation_error(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")

    with attest_verified_snapshot(
        engagement_root=Path(str(engagement_root)),
        metadata=metadata,
    ) as attestation:
        manifest_path = Path(str(metadata["snapshot_manifest_path"]))
        manifest_path.parent.chmod(0o755)
        manifest_path.unlink()
        manifest_path.parent.chmod(0o555)

        with pytest.raises(SnapshotAttestationError, match="changed after attestation"):
            attestation.verify_unchanged()


def test_backend_attestation_rechecks_lexical_path_after_pinned_tree_walk(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    metadata, _staged = _build_backend_attestation_fixture(tmp_path, request)
    engagement_root = metadata.pop("_engagement_root")

    with attest_verified_snapshot(
        engagement_root=Path(str(engagement_root)),
        metadata=metadata,
    ) as attestation:
        repo_root = attestation._snapshot_path.parent
        relocated = repo_root.with_name(f"{repo_root.name}-relocated")
        original_open = attestation._open_source_directory
        swapped = False

        def swap_path_then_open(raw: str = "") -> int:
            nonlocal swapped
            if not swapped:
                repo_root.rename(relocated)
                repo_root.symlink_to(relocated, target_is_directory=True)
                swapped = True
            return original_open(raw)

        attestation._open_source_directory = swap_path_then_open

        with pytest.raises(SnapshotAttestationError, match="path changed"):
            attestation.verify_unchanged()


def test_snapshot_builder_rejects_finish_key_that_differs_from_constructor(
    tmp_path: Path,
) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    source_file = origin / "main.py"
    source_file.write_text("print('safe')\n", encoding="utf-8")
    builder = SnapshotBuilder(tmp_path / "snapshots", "repo-a")
    builder.add("main.py", capture_regular_file(source_file), language="python")

    try:
        with pytest.raises(ValueError, match="repo_key"):
            builder.finish(
                repo_key="repo-b",
                repo_name="Repo B",
                source_origin_path=str(origin),
                git={"head": "", "branch": "", "dirty": None},
            )
    finally:
        builder.abort()


def _write_misbound_v2_snapshot(tmp_path: Path) -> Path:
    raw = b"print('safe')\n"
    files = [
        {
            "file_path": "main.py",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "loc": 1,
            "language": "python",
            "executable": False,
        }
    ]
    payload = {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "repo_key": "repo-b",
        "repo_name": "Repo B",
        "source_origin_path": str(tmp_path / "origin"),
        "git": {"head": "", "branch": "", "dirty": None},
        "files": files,
        "excluded_entries": [],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    root = tmp_path / "snapshots" / "repo-a" / digest
    source = root / "source"
    source.mkdir(parents=True)
    (source / "main.py").write_bytes(raw)
    manifest = {**payload, "source_path": str(source), "snapshot_digest": digest}
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (source / "main.py").chmod(0o444)
    (root / "manifest.json").chmod(0o444)
    source.chmod(0o555)
    root.chmod(0o555)
    return root


def test_validate_snapshot_rejects_v2_repo_key_parent_mismatch(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    root = _write_misbound_v2_snapshot(tmp_path)
    request.addfinalizer(lambda: _restore_tree_writable(tmp_path))

    with pytest.raises(ValueError, match="repo_key"):
        validate_snapshot(root)


def test_code_index_rejects_backend_repo_key_mismatch_before_artifact_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    from assess.commands import code_index

    origin = tmp_path / "origin"
    origin.mkdir()
    source_file = origin / "main.py"
    source_file.write_text("print('safe')\n", encoding="utf-8")
    builder = SnapshotBuilder(tmp_path / "snapshots", "snapshot-key")
    builder.add("main.py", capture_regular_file(source_file), language="python")
    sealed = builder.finish(
        repo_key="snapshot-key",
        repo_name="Snapshot",
        source_origin_path=str(origin),
        git={"head": "", "branch": "", "dirty": None},
    )
    request.addfinalizer(lambda: _restore_tree_writable(tmp_path))
    output = tmp_path / "analysis-state"

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str) -> dict[str, object]:
            assert endpoint == "code/repos/7"
            return {
                "id": 7,
                "repo_key": "backend-key",
                "repo_path": str(sealed.source_path),
                "active_generation": 4,
                "source_manifest_digest": "d" * 64,
            }

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(code_index, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_index,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    monkeypatch.setitem(sys.modules, "tree_sitter", SimpleNamespace())
    monkeypatch.setattr(
        code_index,
        "index_file",
        lambda *_args, **_kwargs: {
            "total_functions": 0,
            "entry_points": [],
            "security_sinks": [],
            "exports": [],
        },
    )

    with pytest.raises(SystemExit) as excinfo:
        code_index.run(
            SimpleNamespace(
                repo_path=str(sealed.source_path),
                repo_id=7,
                repo_key=None,
                repo_name=None,
                output_dir=str(output),
                file_list=None,
                engagement_dir=str(tmp_path),
            )
        )

    assert excinfo.value.code == 1
    assert not (output / "structural-index").exists()
