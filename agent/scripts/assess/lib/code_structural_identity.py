"""Canonical backend-language identity for generation-bound structural indexes."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from assess.lib.code_languages import canonical_backend_language

STRUCTURAL_INPUT_IDENTITY_SCHEMA = "structural-input-identity/v1"
STRUCTURAL_INDEX_SCHEMA = "structural-index/v5"
STRUCTURAL_AGGREGATE_SCHEMA = "structural-index-aggregate/v4"
STRUCTURAL_INDEX_PATH_VERSION = "v5"


def fetch_backend_file_inventory(client: Any, repo_id: int) -> dict[str, dict[str, Any]]:
    """Fetch one complete, duplicate-free backend file inventory."""

    files: dict[str, dict[str, Any]] = {}
    page_size = 5000
    offset = 0
    while True:
        page = client.get(f"code/files?limit={page_size}&offset={offset}&repo_id={repo_id}")
        if not isinstance(page, list):
            raise ValueError(f"backend files response for repo {repo_id} is not an array")
        for item in page:
            if not isinstance(item, dict) or not item.get("file_path"):
                raise ValueError(f"backend files response for repo {repo_id} contains an invalid row")
            rel_path = str(item["file_path"])
            if rel_path in files:
                raise ValueError(f"backend repo {repo_id} contains duplicate path {rel_path}")
            files[rel_path] = item
        if len(page) < page_size:
            return files
        offset += page_size


def bind_structural_inputs(
    source_files: list[dict[str, Any]],
    backend_by_path: dict[str, dict[str, Any]],
    *,
    repo_id: int,
) -> dict[str, dict[str, Any]]:
    """Bind sealed source hashes to current canonical backend languages."""

    source_by_path: dict[str, dict[str, Any]] = {}
    for item in source_files:
        if not isinstance(item, dict) or not item.get("file_path"):
            raise ValueError(f"repo {repo_id} source snapshot inventory contains an invalid row")
        rel_path = str(item["file_path"])
        if rel_path in source_by_path:
            raise ValueError(f"repo {repo_id} source snapshot contains duplicate path {rel_path}")
        source_by_path[rel_path] = item
    if set(source_by_path) != set(backend_by_path):
        raise ValueError(f"repo {repo_id} backend/source file inventories differ")

    bound: dict[str, dict[str, Any]] = {}
    seen_ids: set[int] = set()
    for rel_path in sorted(source_by_path):
        source = source_by_path[rel_path]
        backend = backend_by_path[rel_path]
        file_id = backend.get("id")
        backend_repo_id = backend.get("repo_id")
        if not isinstance(file_id, int) or file_id < 1 or file_id in seen_ids:
            raise ValueError(f"repo {repo_id} backend file identity is invalid for {rel_path}")
        if not isinstance(backend_repo_id, int) or backend_repo_id != repo_id:
            raise ValueError(f"repo {repo_id} backend file repo binding differs for {rel_path}")
        seen_ids.add(file_id)
        source_sha = source.get("source_sha256")
        if not isinstance(source_sha, str) or len(source_sha) != 64:
            raise ValueError(f"repo {repo_id} snapshot source hash is invalid for {rel_path}")
        if backend.get("file_hash") != source_sha:
            raise ValueError(f"repo {repo_id} backend source hash differs for {rel_path}")
        try:
            language = canonical_backend_language(backend.get("language"))
        except ValueError as exc:
            raise ValueError(f"repo {repo_id} {exc} for {rel_path}") from exc
        bound[rel_path] = {
            "file_id": file_id,
            "file_path": rel_path,
            "source_sha256": source_sha,
            "language": language,
        }
    return bound


def structural_input_digest(
    bound: dict[str, dict[str, Any]],
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
) -> str:
    """Hash the complete parser-relevant identity using canonical JSON."""

    payload = {
        "schema": STRUCTURAL_INPUT_IDENTITY_SCHEMA,
        "repo_id": repo_id,
        "repo_generation": repo_generation,
        "source_manifest_digest": source_manifest_digest,
        "files": [
            {
                "file_path": rel_path,
                "source_sha256": str(bound[rel_path]["source_sha256"]),
                "language": str(bound[rel_path]["language"]),
            }
            for rel_path in sorted(bound)
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
