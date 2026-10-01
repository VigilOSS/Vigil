"""Canonical backend-language identity for generation-bound structural indexes."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from assess.lib.code_languages import canonical_backend_language

STRUCTURAL_INPUT_IDENTITY_SCHEMA = "structural-input-identity/v1"
STRUCTURAL_INDEX_SCHEMA = "structural-index/v7"
STRUCTURAL_AGGREGATE_SCHEMA = "structural-index-aggregate/v4"
STRUCTURAL_INDEX_PATH_VERSION = "v7"


def parse_code_file_page(
    value: Any,
    *,
    expected_offset: int,
    context: str,
) -> tuple[list[dict[str, Any]], int, bool]:
    """Validate the bounded ``code/files`` pagination envelope.

    Keeping this validation in one place prevents command-specific fallback
    behavior from silently accepting a truncated or internally inconsistent
    inventory.
    """

    if not isinstance(value, dict):
        raise ValueError(f"{context} is not a pagination envelope")
    required = {"total", "offset", "count", "has_more", "items"}
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"{context} is missing: {', '.join(missing)}")
    total = value["total"]
    offset = value["offset"]
    count = value["count"]
    has_more = value["has_more"]
    items = value["items"]
    if type(total) is not int or total < 0:
        raise ValueError(f"{context} total is invalid")
    if type(offset) is not int or offset != expected_offset:
        raise ValueError(f"{context} offset does not match the request")
    if type(count) is not int or count < 0:
        raise ValueError(f"{context} count is invalid")
    if type(has_more) is not bool:
        raise ValueError(f"{context} has_more is invalid")
    if not isinstance(items, list) or count != len(items):
        raise ValueError(f"{context} count does not match items")
    if total < offset + count:
        raise ValueError(f"{context} total is smaller than the returned page")
    if has_more != (offset + count < total):
        raise ValueError(f"{context} has_more is inconsistent with total")
    if has_more and count == 0:
        raise ValueError(f"{context} cannot advance past an empty page")
    if any(not isinstance(item, dict) for item in items):
        raise ValueError(f"{context} contains a non-object row")
    return items, total, has_more


def fetch_backend_file_inventory(client: Any, repo_id: int) -> dict[str, dict[str, Any]]:
    """Fetch one complete, duplicate-free backend file inventory."""

    files: dict[str, dict[str, Any]] = {}
    page_size = 5000
    offset = 0
    expected_total: int | None = None
    while True:
        page = client.get(f"code/files?limit={page_size}&offset={offset}&repo_id={repo_id}")
        items, total, has_more = parse_code_file_page(
            page,
            expected_offset=offset,
            context=f"backend files response for repo {repo_id}",
        )
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise ValueError(f"backend files total changed while paging repo {repo_id}")
        for item in items:
            if not item.get("file_path"):
                raise ValueError(f"backend files response for repo {repo_id} contains an invalid row")
            rel_path = str(item["file_path"])
            if rel_path in files:
                raise ValueError(f"backend repo {repo_id} contains duplicate path {rel_path}")
            files[rel_path] = item
        if not has_more:
            return files
        offset += len(items)


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
