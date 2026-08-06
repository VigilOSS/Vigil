"""Helpers for durable code-analysis audit artifacts under tools/analysis-state."""
from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_FILENAME = "artifact-manifest.json"
MANIFEST_LOCK_FILENAME = ".artifact-manifest.lock"
CANONICAL_ARTIFACT_RE = re.compile(
    r"^\d{8}T\d{6}(?:\d{6})?Z-([a-z0-9-]+)-([a-z0-9-]+)\.json$"
)


def analysis_state_dir(engagement_dir: str) -> Path:
    path = Path(engagement_dir) / "tools" / "analysis-state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "artifact"


def write_json_snapshot(
    engagement_dir: str,
    *,
    category: str,
    label: str,
    payload: Any,
    source_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Path:
    state_dir = analysis_state_dir(engagement_dir)
    stem = f"{_timestamp_slug()}-{slugify(category)}-{slugify(label)}"
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    for collision_index in range(10_000):
        suffix = "" if collision_index == 0 else f"-{collision_index + 1}"
        filename = f"{stem}{suffix}.json"
        path = state_dir / filename
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(serialized)
        except FileExistsError:
            continue
        break
    else:
        raise RuntimeError(f"Could not allocate a unique audit snapshot name for {stem}")
    rebuild_manifest(engagement_dir, extra_entries=[{
        "name": filename,
        "kind": category,
        "label": label,
        "source_path": source_path or "",
        "metadata": metadata or {},
    }])
    return path


def rebuild_manifest(engagement_dir: str, extra_entries: list[dict[str, Any]] | None = None) -> Path:
    state_dir = analysis_state_dir(engagement_dir)
    manifest_path = state_dir / MANIFEST_FILENAME
    lock_flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_fd = os.open(state_dir / MANIFEST_LOCK_FILENAME, lock_flags, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        existing_by_name: dict[str, dict[str, Any]] = {}
        try:
            manifest_stat = manifest_path.lstat()
        except FileNotFoundError:
            manifest_stat = None
        if manifest_stat is not None:
            if not stat.S_ISREG(manifest_stat.st_mode):
                raise RuntimeError(f"Unsafe artifact manifest node: {manifest_path}")
            try:
                existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Could not load artifact manifest: {exc}") from exc
            if not isinstance(existing_manifest, dict) or not isinstance(
                existing_manifest.get("entries"), list
            ):
                raise RuntimeError("Artifact manifest has an invalid shape")
            existing_by_name = {
                str(entry["name"]): entry
                for entry in existing_manifest["entries"]
                if isinstance(entry, dict) and entry.get("name")
            }

        extra_by_name = {
            entry["name"]: entry for entry in (extra_entries or []) if entry.get("name")
        }
        entries: list[dict[str, Any]] = []
        for path in sorted(state_dir.iterdir()):
            if not path.is_file() or path.name == MANIFEST_FILENAME:
                continue
            match = CANONICAL_ARTIFACT_RE.match(path.name)
            if match is None:
                continue
            entry = {**existing_by_name.get(path.name, {}), **extra_by_name.get(path.name, {})}
            path_stat = path.stat()
            entries.append({
                "name": path.name,
                "relative_path": str(path.relative_to(Path(engagement_dir))),
                "kind": entry.get("kind", match.group(1)),
                "label": entry.get("label", path.stem),
                "source_path": entry.get("source_path", ""),
                "size_bytes": path_stat.st_size,
                "modified_at": datetime.fromtimestamp(
                    path_stat.st_mtime, timezone.utc
                ).isoformat(),
                "metadata": entry.get("metadata", {}),
            })

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifact_count": len(entries),
            "entries": entries,
        }
        temp_fd, temp_name = tempfile.mkstemp(
            dir=state_dir, prefix=".artifact-manifest.", suffix=".tmp"
        )
        temp_path = Path(temp_name)
        try:
            os.fchmod(temp_fd, 0o644)
            with os.fdopen(temp_fd, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle, indent=2, sort_keys=True, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, manifest_path)
            directory_fd = os.open(state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temp_path.unlink(missing_ok=True)
        return manifest_path
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
