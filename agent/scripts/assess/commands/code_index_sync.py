"""vigil assess code-index sync — validate and CAS-publish structural metadata."""
from __future__ import annotations

import hashlib
import json
import shlex
import sys
from pathlib import Path
from typing import Any

from assess.lib.client import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    AssessmentClient,
    AssessError,
    require_write_result,
)
from assess.lib.code_snapshot import (
    MAX_JSON_ARTIFACT_BYTES,
    RootedSourceTree,
    read_bounded_regular_file,
    sealed_source_file_path,
    validate_snapshot,
)
from assess.lib.code_structural_identity import (
    STRUCTURAL_AGGREGATE_SCHEMA,
    STRUCTURAL_INDEX_PATH_VERSION,
    STRUCTURAL_INDEX_SCHEMA,
    bind_structural_inputs,
    fetch_backend_file_inventory,
    structural_indexer_digest,
    structural_input_digest,
)
from assess.lib.config import load_config
from assess.commands.code_index import _unsupported_index
from assess.lib.code_structural_metadata import (
    INVALID_ARTIFACT_REASON,
    invalid_artifact_notice,
    validated_callable_records,
    validated_structural_metadata,
)
from assess.lib.treesitter_streaming import StreamingSecurityScanner

# The bulk write is one all-or-none transaction per repo, so its server-side
# cost scales with the file count; widen the response budget past the 10s
# default the same way bulk artifact registration does.
_BULK_SYNC_SECONDS_PER_FILE = 0.02


def register_sync(subparsers) -> None:
    parser = subparsers.add_parser(
        "sync",
        help="Validate and sync generation-bound structural metadata",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Aggregate structural-index-manifest.json path",
    )
    parser.add_argument(
        "--index-dir",
        default=None,
        help="Structural-index root (default: sibling structural-index directory)",
    )
    parser.add_argument("--repo-id", default=None, type=int, help="Sync one backend repo ID")
    parser.add_argument("--repo-key", default=None, help="Sync one exact repo_key")
    parser.set_defaults(func=run)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            read_bounded_regular_file(
                path,
                max_bytes=MAX_JSON_ARTIFACT_BYTES,
                label="structural manifest",
            ).decode("utf-8")
        )
    except FileNotFoundError:
        print(f"Manifest not found: {path}", file=sys.stderr)
        print("Run code-index build first.", file=sys.stderr)
        sys.exit(1)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Cannot read structural manifest {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(value, dict):
        print(f"Structural manifest must contain an object: {path}", file=sys.stderr)
        sys.exit(1)
    return value


def _under(root: Path, path: Path, *, label: str) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes structural index root: {resolved}") from exc
    return resolved


def _resolve_per_repo_manifests(
    top: dict,
    top_path: Path,
    *,
    repo_id: int | None = None,
    repo_key: str | None = None,
) -> list[tuple[str, dict]]:
    if top.get("schema") != STRUCTURAL_AGGREGATE_SCHEMA or not isinstance(top.get("repos"), dict):
        raise ValueError(
            f"structural index aggregate must use {STRUCTURAL_AGGREGATE_SCHEMA}; rebuild with code-index"
        )
    output: list[tuple[str, dict]] = []
    for key, summary in top["repos"].items():
        if not isinstance(summary, dict):
            raise ValueError(f"aggregate repo {key!r} has no manifest_path")
        if repo_id is not None and summary.get("repo_id") != repo_id:
            continue
        if repo_key is not None and summary.get("repo_key") is not None and summary["repo_key"] != repo_key:
            continue
        if not summary.get("manifest_path"):
            raise ValueError(f"aggregate repo {key!r} has no manifest_path")
        manifest_path = _under(
            top_path.parent,
            top_path.parent / str(summary["manifest_path"]),
            label=f"repo {key} manifest",
        )
        manifest = _load_manifest(manifest_path)
        if repo_key is not None and manifest.get("repo_key") != repo_key:
            continue
        if manifest.get("schema") != STRUCTURAL_INDEX_SCHEMA:
            raise ValueError(f"repo {key} manifest is not {STRUCTURAL_INDEX_SCHEMA}")
        manifest["_resolved_manifest_path"] = str(manifest_path)
        for field in (
            "repo_id",
            "repo_generation",
            "source_manifest_digest",
            "structural_input_digest",
            "degraded_files",
            "degraded_file_paths",
            "artifact_truncated_files",
            "artifact_truncated_file_paths",
            "analysis_status_counts",
        ):
            if summary.get(field) != manifest.get(field):
                raise ValueError(
                    f"aggregate repo {key} {field} does not match its current manifest"
                )
        output.append((str(key), manifest))
    return output


def _find_backend_repo(repos: list[dict], *, repo_id: int) -> dict | None:
    matches = [repo for repo in repos if int(repo.get("id") or repo.get("repo_id") or 0) == repo_id]
    return matches[0] if len(matches) == 1 else None


def _read_index(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    try:
        raw = read_bounded_regular_file(
            path,
            max_bytes=MAX_JSON_ARTIFACT_BYTES,
            label="structural index artifact",
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid structural index artifact: {path}: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"structural index artifact hash mismatch: {path}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid structural index JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            f"structural index must contain an object: {path}"
        )
    return value


def _backend_files(client: AssessmentClient, repo_id: int) -> dict[str, dict]:
    return fetch_backend_file_inventory(client, repo_id)


def _invalid_artifact_fallback(
    source_tree: RootedSourceTree, rel_path: str, language: str, source_sha: str
) -> dict[str, Any]:
    """An all-byte streaming scan of the sealed source, for a file whose artifact is unpublishable."""
    scanner = StreamingSecurityScanner(rel_path, language)
    captured = source_tree.capture(rel_path, retain_spool=False, chunk_consumer=scanner.feed)
    if captured.sha256 != source_sha:
        raise ValueError(f"sealed source hash differs for {rel_path}")
    return scanner.finish(degradation_reason=INVALID_ARTIFACT_REASON)


def _bound_artifact(
    index_root: Path, manifest_path: Path, binding: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """The file's artifact, read at its identity path and bound to its manifest entry."""
    rel_path = expected["file_path"]
    index_path = _under(
        index_root,
        index_root / str(binding.get("index_path") or ""),
        label="file index",
    )
    if index_path.parent != manifest_path.parent / "files":
        raise ValueError(f"structural index path differs from its identity for {rel_path}")
    indexed = _read_index(index_path, expected_sha256=str(binding.get("index_sha256")))
    for field, value in expected.items():
        if indexed.get(field) != value:
            raise ValueError(f"structural index {field} differs for {rel_path}")
    for field in ("analysis_status", "analysis_mode", "artifact_truncated"):
        if binding.get(field) != indexed.get(field):
            raise ValueError(f"structural binding {field} mismatch for {rel_path}")
    return indexed


def _debt_summary(files: list[tuple[str, Any, Any]]) -> dict[str, Any]:
    """Coverage-debt totals over `(path, analysis status, artifact truncated)`."""
    counts = {"complete": 0, "degraded": 0, "unsupported": 0}
    for _path, status, _truncated in files:
        counts[str(status)] = counts.get(str(status), 0) + 1
    degraded = sorted(path for path, status, _truncated in files if status == "degraded")
    truncated = sorted(path for path, _status, flag in files if flag is True)
    return {
        "degraded_files": len(degraded),
        "degraded_file_paths": degraded,
        "artifact_truncated_files": len(truncated),
        "artifact_truncated_file_paths": truncated,
        "analysis_status_counts": counts,
    }


def _prepare_repo_payload(
    client: AssessmentClient,
    backend_repo: dict,
    manifest: dict,
    index_root: Path,
) -> dict[str, Any]:
    repo_id = int(manifest.get("repo_id") or 0)
    if manifest.get("schema") != STRUCTURAL_INDEX_SCHEMA:
        raise ValueError(f"repo {repo_id} manifest is not {STRUCTURAL_INDEX_SCHEMA}")
    generation = int(manifest.get("repo_generation") or 0)
    digest = str(manifest.get("source_manifest_digest") or "")
    backend_generation = int(backend_repo.get("active_generation") or 0)
    backend_digest = str(backend_repo.get("source_manifest_digest") or "")
    if generation < 1 or len(digest) != 64:
        raise ValueError(f"repo {repo_id} manifest has an invalid source binding")
    if backend_generation != generation or backend_digest != digest:
        raise ValueError(
            f"repo {repo_id} backend generation/digest differs from the structural manifest"
        )
    if manifest.get("repo_key") and backend_repo.get("repo_key") != manifest.get("repo_key"):
        raise ValueError(f"repo {repo_id} repo_key differs from the backend")
    source = Path(str(manifest.get("source_path") or "")).resolve()
    if Path(str(backend_repo.get("repo_path") or "")).resolve() != source:
        raise ValueError(f"repo {repo_id} sealed source path differs from the backend")
    files_manifest = manifest.get("files")
    if not isinstance(files_manifest, dict):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            f"repo {repo_id} current manifest files must be an object"
        )
    for rel_path in files_manifest:
        sealed_source_file_path(source, str(rel_path))
    snapshot_digest = str(manifest.get("snapshot_digest") or "")
    snapshot_manifest_path = Path(
        str(manifest.get("source_snapshot_manifest_path") or "")
    ).resolve()
    expected_snapshot_manifest = source.parent / "manifest.json"
    if snapshot_manifest_path != expected_snapshot_manifest or len(snapshot_digest) != 64:
        raise ValueError(f"repo {repo_id} structural manifest has an invalid snapshot binding")
    source_manifest = validate_snapshot(source.parent, expected_digest=snapshot_digest)
    if Path(str(source_manifest.get("source_path") or "")).resolve() != source:
        raise ValueError(f"repo {repo_id} source snapshot path binding is invalid")
    source_files = source_manifest.get("files")
    if not isinstance(source_files, list):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            f"repo {repo_id} source snapshot inventory is invalid"
        )
    source_by_path = {
        str(item.get("file_path") or ""): item
        for item in source_files
        if isinstance(item, dict) and item.get("file_path")
    }
    if set(files_manifest) != set(source_by_path):
        raise ValueError(f"repo {repo_id} structural manifest is not source-inventory complete")
    expected_lookup = {
        rel_path: str(binding.get("index_path") or "")
        for rel_path, binding in files_manifest.items()
        if isinstance(binding, dict)
    }
    if manifest.get("path_to_index") != expected_lookup:
        raise ValueError(f"repo {repo_id} path_to_index differs from its file bindings")

    backend_by_path = _backend_files(client, repo_id)
    bound_inputs = bind_structural_inputs(source_files, backend_by_path, repo_id=repo_id)
    expected_input_digest = structural_input_digest(
        bound_inputs,
        repo_id=repo_id,
        repo_generation=generation,
        source_manifest_digest=digest,
    )
    if manifest.get("structural_input_digest") != expected_input_digest:
        raise ValueError(
            f"repo {repo_id} structural input digest/language identity differs from the backend"
        )
    manifest_path = Path(str(manifest["_resolved_manifest_path"])).resolve()
    identity_root = index_root / str(repo_id) / str(generation) / STRUCTURAL_INDEX_PATH_VERSION / digest
    if "indexer_digest" in manifest:
        indexer_digest = manifest["indexer_digest"]
        if (
            not isinstance(indexer_digest, str)
            or len(indexer_digest) != 64
            or not set(indexer_digest) <= set("0123456789abcdef")
        ):
            raise ValueError(f"repo {repo_id} structural indexer digest is invalid")
        identity_root = identity_root / indexer_digest
    expected_manifest_path = identity_root / expected_input_digest / "manifest.json"
    if (
        _under(index_root, manifest_path, label=f"repo {repo_id} manifest")
        != expected_manifest_path.resolve()
        or Path(str(manifest.get("manifest_path") or "")).resolve() != manifest_path
    ):
        raise ValueError(f"repo {repo_id} structural manifest path differs from its identity")
    if manifest.get("indexer_digest") != structural_indexer_digest():
        # Publishing it is still valid; it just carries the old indexer's
        # findings (file-scope segments, sinks, entry points).
        print(
            f"code-index sync: WARNING — repo {repo_id}: this structural index was built by a "
            "different indexer than this install's. Run "
            f"`vigil assess code-index build --repo-id {repo_id} {shlex.quote(str(source))}`, "
            "then sync again, to publish what the current indexer reports.",
            file=sys.stderr,
        )
    updates: list[dict[str, Any]] = []
    built: list[tuple[str, Any, Any]] = []
    published: list[tuple[str, Any, Any]] = []
    invalid: list[str] = []
    errors: list[str] = []
    with RootedSourceTree(source) as source_tree:
        for rel_path in sorted(files_manifest):
            try:
                binding = files_manifest[rel_path]
                if not isinstance(binding, dict):
                    raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
                        f"repo {repo_id} file binding is invalid: {rel_path}"
                    )
                source_sha = str(binding.get("source_sha256") or "")
                index_sha = str(binding.get("index_sha256") or "")
                if len(source_sha) != 64 or len(index_sha) != 64:
                    raise ValueError(f"repo {repo_id} file binding hashes are invalid: {rel_path}")
                if source_by_path[rel_path].get("source_sha256") != source_sha:
                    raise ValueError(f"repo {repo_id} snapshot source hash differs for {rel_path}")
                backend_file = backend_by_path.get(rel_path)
                if backend_file is None:
                    raise ValueError(f"repo {repo_id} backend has no file row for {rel_path}")
                if backend_file.get("file_hash") != source_sha:
                    raise ValueError(f"repo {repo_id} backend source hash differs for {rel_path}")
                expected_language = str(bound_inputs[rel_path]["language"])
                if binding.get("language") != expected_language:
                    raise ValueError(
                        f"repo {repo_id} structural binding language differs from the backend for "
                        f"{rel_path}"
                    )
                captured_source = source_tree.capture(rel_path, retain_spool=False)
                if captured_source.sha256 != source_sha:
                    raise ValueError(f"repo {repo_id} sealed source hash differs for {rel_path}")
                file_id = int(backend_file.get("id") or 0)
                if file_id < 1:
                    raise ValueError(f"repo {repo_id} backend file has no ID for {rel_path}")
                built.append(
                    (rel_path, binding.get("analysis_status"), binding.get("artifact_truncated"))
                )
                source_size = int(source_by_path[rel_path].get("size") or 0)
                indexed = _bound_artifact(
                    index_root,
                    manifest_path,
                    binding,
                    {
                        "file_path": rel_path,
                        "repo_id": repo_id,
                        "repo_generation": generation,
                        "source_manifest_digest": digest,
                        "structural_input_digest": expected_input_digest,
                        "source_sha256": source_sha,
                        "language": expected_language,
                    },
                )
                try:
                    structural_metadata = validated_structural_metadata(
                        indexed, rel_path=rel_path, source_size=source_size
                    )
                    callable_records = validated_callable_records(
                        indexed, rel_path=rel_path, loc=captured_source.loc
                    )
                except ValueError as exc:
                    invalid.append(str(exc))
                    indexed = (
                        _unsupported_index(rel_path, expected_language, source_size=source_size)
                        if indexed.get("analysis_status") == "unsupported"
                        else _invalid_artifact_fallback(
                            source_tree, rel_path, expected_language, source_sha
                        )
                    )
                    structural_metadata = validated_structural_metadata(
                        indexed, rel_path=rel_path, source_size=source_size
                    )
                    callable_records = []
                published.append(
                    (rel_path, indexed["analysis_status"], indexed["artifact_truncated"])
                )
                updates.append(
                    {
                        "file_id": file_id,
                        "source_sha256": source_sha,
                        "indexed_language": expected_language,
                        "total_functions": int(indexed.get("total_functions", 0)),
                        "total_top_level_segments": len(
                            indexed.get("top_level_segments", [])
                        ),
                        "total_entry_points": int(indexed["signal_counts"]["entry_points"]),
                        "total_sinks": int(indexed["signal_counts"]["security_sinks"]),
                        "total_exports": int(indexed["total_exports"]),
                        "callables": callable_records,
                        **structural_metadata,
                    }
                )
            except (OSError, ValueError) as exc:
                errors.append(f"{rel_path}: {exc}")
        source_tree.verify_root_identity()
    if errors:
        raise ValueError("invalid structural artifacts:\n" + "\n".join(errors))
    if any(manifest.get(field) != value for field, value in _debt_summary(built).items()):
        raise ValueError(f"repo {repo_id} structural coverage-debt summary differs from files")
    if invalid:
        print(invalid_artifact_notice(f"code-index sync: repo {repo_id}", invalid), file=sys.stderr)

    return {
        "repo_id": repo_id,
        "repo_generation": generation,
        "source_manifest_digest": digest,
        "structural_index_schema": STRUCTURAL_INDEX_SCHEMA,
        "structural_input_digest": expected_input_digest,
        "structural_index_manifest_path": str(manifest_path),
        **_debt_summary(published),
        "updates": updates,
    }


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    manifest_value = getattr(args, "manifest", None)
    if manifest_value:
        manifest_path = Path(manifest_value).resolve()
    else:
        engagement = getattr(args, "engagement_dir", None) or getattr(cfg, "engagement_dir", None)
        if not engagement:
            print("Cannot determine engagement directory for structural sync", file=sys.stderr)
            sys.exit(1)
        manifest_path = (
            Path(engagement).resolve()
            / "tools"
            / "analysis-state"
            / "structural-index-manifest.json"
        )
    top = _load_manifest(manifest_path)
    index_root = (
        Path(args.index_dir).resolve()
        if getattr(args, "index_dir", None)
        else manifest_path.parent / "structural-index"
    )
    repo_id_filter = getattr(args, "repo_id", None)
    repo_key_filter = getattr(args, "repo_key", None)
    try:
        selected = _resolve_per_repo_manifests(
            top, manifest_path, repo_id=repo_id_filter, repo_key=repo_key_filter or None,
        )
    except ValueError as exc:
        print(f"Cannot sync structural index: {exc}", file=sys.stderr)
        sys.exit(1)

    if not selected:
        print("No structural manifest matched the selected repository", file=sys.stderr)
        sys.exit(1)

    # Validation is deliberately two-phase: no backend mutation occurs until
    # every selected repo and every selected file has passed all bindings.
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        repos = client.get("code/repos")
        if not isinstance(repos, list):
            print("Cannot sync structural index: backend repo response is invalid", file=sys.stderr)
            sys.exit(1)
        prepared: list[dict[str, Any]] = []
        errors: list[str] = []
        for _key, manifest in selected:
            try:
                repo_id = int(manifest.get("repo_id") or 0)
                backend = _find_backend_repo(repos, repo_id=repo_id)
                if backend is None:
                    raise ValueError(f"no unique backend repo matches repo_id {repo_id}")
                prepared.append(_prepare_repo_payload(client, backend, manifest, index_root))
            except (OSError, ValueError) as exc:
                errors.append(f"repo {_key}: {exc}")
        if errors:
            print("Cannot sync structural index:\n" + "\n".join(errors), file=sys.stderr)
            sys.exit(1)

        total_updated = 0
        total_skipped = 0
        for payload in prepared:
            result = client.post(
                "code/files/bulk-structural-metadata",
                payload,
                read_timeout=max(
                    DEFAULT_READ_TIMEOUT_SECONDS,
                    _BULK_SYNC_SECONDS_PER_FILE * len(payload["updates"]),
                ),
            )
            result = require_write_result(
                result,
                operation="sync structural metadata",
                expected={
                    "repo_id": payload["repo_id"],
                    "repo_generation": payload["repo_generation"],
                    "source_manifest_digest": payload["source_manifest_digest"],
                    "structural_input_digest": payload["structural_input_digest"],
                    "structural_index_schema": payload["structural_index_schema"],
                },
                nonnegative_counts=("updated",),
            )
            updated = result["updated"]
            if updated != len(payload["updates"]):
                raise AssessError(
                    "sync structural metadata: backend response count does not match "
                    "the submitted snapshot; the write may have committed, so inspect "
                    "durable state and do not retry automatically"
                )
            skipped = 0
            total_updated += updated
            total_skipped += skipped
            print(
                f"  sync repo_id={payload['repo_id']} generation={payload['repo_generation']}: "
                f"{updated} updated, {skipped} skipped",
                file=sys.stderr,
            )

    print(
        f"\nStructural metadata synced across {len(prepared)} repos: "
        f"{total_updated} files updated, {total_skipped} skipped",
        file=sys.stderr,
    )
