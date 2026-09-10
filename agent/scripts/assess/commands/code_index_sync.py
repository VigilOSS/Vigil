"""vigil assess code-index sync — validate and CAS-publish structural metadata."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from assess.lib.client import AssessmentClient, AssessError, require_write_result
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
    structural_input_digest,
)
from assess.lib.config import load_config
from assess.lib.treesitter_index import STREAMING_FALLBACK_BASELINE_UNAVAILABLE

STRUCTURAL_DIMENSIONS = {
    "call_sites",
    "classes",
    "dataflow",
    "entry_points",
    "exports",
    "functions",
    "imports",
    "security_sinks",
    "security_sources",
}
SIGNAL_DIMENSIONS = (
    "entry_points",
    "imports",
    "security_sinks",
    "security_sources",
)
STRUCTURAL_RECORD_FIELDS = (
    "functions",
    "entry_points",
    "security_sinks",
    "security_sources",
    "call_sites",
    "imports",
    "import_targets",
    "exports",
    "classes",
)
UNAVAILABLE_RECORD_FIELDS = {
    "functions": ("functions",),
    "entry_points": ("entry_points",),
    "security_sinks": ("security_sinks",),
    "security_sources": ("security_sources",),
    "call_sites": ("call_sites",),
    "imports": ("imports", "import_targets"),
    "exports": ("exports",),
    "classes": ("classes",),
}


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


def _resolve_per_repo_manifests(top: dict, top_path: Path) -> list[tuple[str, dict]]:
    if top.get("schema") != STRUCTURAL_AGGREGATE_SCHEMA or not isinstance(top.get("repos"), dict):
        raise ValueError(
            f"structural index aggregate must use {STRUCTURAL_AGGREGATE_SCHEMA}; rebuild with code-index"
        )
    output: list[tuple[str, dict]] = []
    for key, summary in top["repos"].items():
        if not isinstance(summary, dict) or not summary.get("manifest_path"):
            raise ValueError(f"aggregate repo {key!r} has no manifest_path")
        manifest_path = _under(
            top_path.parent,
            top_path.parent / str(summary["manifest_path"]),
            label=f"repo {key} manifest",
        )
        manifest = _load_manifest(manifest_path)
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


def _validated_structural_metadata(
    indexed: dict[str, Any],
    *,
    rel_path: str,
    source_size: int,
) -> dict[str, Any]:
    status = indexed.get("analysis_status")
    mode = indexed.get("analysis_mode")
    reason = indexed.get("degradation_reason")
    available = indexed.get("structural_index_available")
    unavailable = indexed.get("unavailable_dimensions")
    truncated = indexed.get("artifact_truncated")
    truncated_dimensions = indexed.get("truncated_dimensions")
    counts = indexed.get("signal_counts")
    if status not in {"complete", "degraded", "unsupported"}:
        raise ValueError(f"structural analysis status is invalid for {rel_path}")
    if mode not in {"tree_sitter", "lightweight_regex", "streaming_security_fallback", "none"}:
        raise ValueError(f"structural analysis mode is invalid for {rel_path}")
    if indexed.get("source_size") != source_size or indexed.get("bytes_scanned") != source_size:
        raise ValueError(f"structural scan byte accounting differs for {rel_path}")
    if not isinstance(available, bool) or not isinstance(truncated, bool):
        raise ValueError(f"structural availability/truncation is invalid for {rel_path}")
    if not isinstance(unavailable, list) or unavailable != sorted(set(unavailable)):
        raise ValueError(f"structural unavailable dimensions are invalid for {rel_path}")
    if not isinstance(truncated_dimensions, list) or truncated_dimensions != sorted(
        set(truncated_dimensions)
    ):
        raise ValueError(f"structural truncated dimensions are invalid for {rel_path}")
    if not set(unavailable).issubset(STRUCTURAL_DIMENSIONS) or not set(
        truncated_dimensions
    ).issubset(STRUCTURAL_DIMENSIONS):
        raise ValueError(f"structural dimensions are unsupported for {rel_path}")
    if truncated != bool(truncated_dimensions) or (truncated and status != "degraded"):
        raise ValueError(f"structural truncation debt is inconsistent for {rel_path}")
    if status == "complete" and (
        not available
        or mode not in {"tree_sitter", "lightweight_regex"}
        or reason
        or unavailable
        or truncated
    ):
        raise ValueError(f"complete structural analysis is inconsistent for {rel_path}")
    if status == "unsupported" and (
        available
        or mode != "none"
        or reason != "unsupported_language"
        or not unavailable
    ):
        raise ValueError(f"unsupported structural analysis is inconsistent for {rel_path}")
    if status == "degraded":
        if mode == "streaming_security_fallback":
            if (
                available
                or not reason
                or not STREAMING_FALLBACK_BASELINE_UNAVAILABLE.issubset(unavailable)
            ):
                raise ValueError(f"streaming fallback debt is incomplete for {rel_path}")
        elif not (
            mode in {"tree_sitter", "lightweight_regex"}
            and available
            and truncated
            and reason == "artifact_signal_limit"
            and not unavailable
        ):
            raise ValueError(f"bounded parser debt is inconsistent for {rel_path}")
    if not isinstance(counts, dict) or set(counts) != set(SIGNAL_DIMENSIONS) or any(
        not isinstance(counts.get(dimension), int) or int(counts[dimension]) < 0
        for dimension in SIGNAL_DIMENSIONS
    ):
        raise ValueError(f"structural signal counts are invalid for {rel_path}")
    for field in STRUCTURAL_RECORD_FIELDS:
        if not isinstance(indexed.get(field), list):
            raise ValueError(f"structural {field} records are invalid for {rel_path}")
    if not isinstance(indexed.get("total_functions"), int) or int(
        indexed["total_functions"]
    ) < 0:
        raise ValueError(f"structural function total is invalid for {rel_path}")
    if not isinstance(indexed.get("total_exports"), int) or int(indexed["total_exports"]) < 0:
        raise ValueError(f"structural export total is invalid for {rel_path}")
    if status == "unsupported" and (
        int(indexed["total_functions"]) != 0
        or int(indexed["total_exports"]) != 0
        or any(int(counts[dimension]) for dimension in SIGNAL_DIMENSIONS)
        or any(indexed[field] for field in STRUCTURAL_RECORD_FIELDS)
    ):
        raise ValueError(f"unsupported structural analysis contains signals for {rel_path}")
    retained_counts = {
        "entry_points": len(indexed["entry_points"]),
        "imports": max(len(indexed["imports"]), len(indexed["import_targets"])),
        "security_sinks": len(indexed["security_sinks"]),
        "security_sources": len(indexed["security_sources"]),
    }
    if any(int(counts[dimension]) < retained_counts[dimension] for dimension in SIGNAL_DIMENSIONS):
        raise ValueError(f"structural signal totals undercount retained records for {rel_path}")
    if int(indexed["total_exports"]) < len(indexed["exports"]):
        raise ValueError(f"structural export total undercounts retained records for {rel_path}")
    unavailable_signals = set(unavailable).intersection(SIGNAL_DIMENSIONS)
    if (
        any(int(counts[dimension]) for dimension in unavailable_signals)
        or ("functions" in unavailable and int(indexed["total_functions"]) != 0)
        or ("exports" in unavailable and int(indexed["total_exports"]) != 0)
        or any(
            any(indexed[field] for field in fields)
            for dimension, fields in UNAVAILABLE_RECORD_FIELDS.items()
            if dimension in unavailable
        )
    ):
        raise ValueError(f"unavailable structural dimension contains signals for {rel_path}")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 128):
        raise ValueError(f"structural degradation reason is invalid for {rel_path}")
    return {
        "structural_analysis_status": status,
        "structural_analysis_mode": mode,
        "structural_degradation_reason": reason,
        "structural_source_size": source_size,
        "structural_bytes_scanned": int(indexed["bytes_scanned"]),
        "structural_unavailable_dimensions": unavailable,
        "structural_artifact_truncated": truncated,
        "structural_truncated_dimensions": truncated_dimensions,
        "structural_signal_counts": counts,
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
    expected_manifest_path = (
        index_root
        / str(repo_id)
        / str(generation)
        / STRUCTURAL_INDEX_PATH_VERSION
        / digest
        / expected_input_digest
        / "manifest.json"
    )
    if (
        _under(index_root, manifest_path, label=f"repo {repo_id} manifest")
        != expected_manifest_path.resolve()
        or Path(str(manifest.get("manifest_path") or "")).resolve() != manifest_path
    ):
        raise ValueError(f"repo {repo_id} structural manifest path differs from its identity")
    updates: list[dict[str, Any]] = []
    degraded_paths: list[str] = []
    truncated_paths: list[str] = []
    status_counts = {"complete": 0, "degraded": 0, "unsupported": 0}
    with RootedSourceTree(source) as source_tree:
        for rel_path in sorted(files_manifest):
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
            index_path = _under(
                index_root,
                index_root / str(binding.get("index_path") or ""),
                label=f"repo {repo_id} file index",
            )
            if index_path.parent != manifest_path.parent / "files":
                raise ValueError(
                    f"repo {repo_id} structural index path differs from its identity for {rel_path}"
                )
            indexed = _read_index(index_path, expected_sha256=index_sha)
            expected_binding = {
                "file_path": rel_path,
                "repo_id": repo_id,
                "repo_generation": generation,
                "source_manifest_digest": digest,
                "structural_input_digest": expected_input_digest,
                "source_sha256": source_sha,
            }
            for field, expected in expected_binding.items():
                if indexed.get(field) != expected:
                    raise ValueError(f"repo {repo_id} structural index {field} mismatch for {rel_path}")
            if indexed.get("language") != expected_language:
                raise ValueError(
                    f"repo {repo_id} structural index language differs from the backend for "
                    f"{rel_path}"
                )
            source_size = int(source_by_path[rel_path].get("size") or 0)
            structural_metadata = _validated_structural_metadata(
                indexed,
                rel_path=rel_path,
                source_size=source_size,
            )
            for field in ("analysis_status", "analysis_mode", "artifact_truncated"):
                if binding.get(field) != indexed.get(field):
                    raise ValueError(
                        f"repo {repo_id} structural binding {field} mismatch for {rel_path}"
                    )
            status = str(indexed["analysis_status"])
            status_counts[status] += 1
            if status == "degraded":
                degraded_paths.append(rel_path)
            if indexed["artifact_truncated"]:
                truncated_paths.append(rel_path)
            file_id = int(backend_file.get("id") or 0)
            if file_id < 1:
                raise ValueError(f"repo {repo_id} backend file has no ID for {rel_path}")
            updates.append(
                {
                    "file_id": file_id,
                    "source_sha256": source_sha,
                    "indexed_language": expected_language,
                    "total_functions": int(indexed.get("total_functions", 0)),
                    "total_entry_points": int(indexed["signal_counts"]["entry_points"]),
                    "total_sinks": int(indexed["signal_counts"]["security_sinks"]),
                    "total_exports": int(indexed["total_exports"]),
                    **structural_metadata,
                }
            )
        source_tree.verify_root_identity()

    expected_degraded = sorted(degraded_paths)
    expected_truncated = sorted(truncated_paths)
    if (
        manifest.get("degraded_files") != len(expected_degraded)
        or manifest.get("degraded_file_paths") != expected_degraded
        or manifest.get("artifact_truncated_files") != len(expected_truncated)
        or manifest.get("artifact_truncated_file_paths") != expected_truncated
        or manifest.get("analysis_status_counts") != status_counts
    ):
        raise ValueError(f"repo {repo_id} structural coverage-debt summary differs from files")

    return {
        "repo_id": repo_id,
        "repo_generation": generation,
        "source_manifest_digest": digest,
        "structural_index_schema": STRUCTURAL_INDEX_SCHEMA,
        "structural_input_digest": expected_input_digest,
        "structural_index_manifest_path": str(manifest_path),
        "degraded_files": len(expected_degraded),
        "degraded_file_paths": expected_degraded,
        "artifact_truncated_files": len(expected_truncated),
        "artifact_truncated_file_paths": expected_truncated,
        "analysis_status_counts": status_counts,
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
    try:
        selected = _resolve_per_repo_manifests(top, manifest_path)
    except ValueError as exc:
        print(f"Cannot sync structural index: {exc}", file=sys.stderr)
        sys.exit(1)

    repo_id_filter = getattr(args, "repo_id", None)
    repo_key_filter = getattr(args, "repo_key", None)
    if repo_id_filter is not None:
        selected = [item for item in selected if int(item[1].get("repo_id") or 0) == repo_id_filter]
    if repo_key_filter:
        selected = [item for item in selected if item[1].get("repo_key") == repo_key_filter]
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
        try:
            for _key, manifest in selected:
                repo_id = int(manifest.get("repo_id") or 0)
                backend = _find_backend_repo(repos, repo_id=repo_id)
                if backend is None:
                    raise ValueError(f"no unique backend repo matches repo_id {repo_id}")
                prepared.append(_prepare_repo_payload(client, backend, manifest, index_root))
        except (OSError, ValueError) as exc:
            print(f"Cannot sync structural index: {exc}", file=sys.stderr)
            sys.exit(1)

        total_updated = 0
        total_skipped = 0
        for payload in prepared:
            result = client.post("code/files/bulk-structural-metadata", payload)
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
