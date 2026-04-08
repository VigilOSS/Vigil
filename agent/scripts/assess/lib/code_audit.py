"""Helpers for durable code-analysis audit artifacts under tools/analysis-state."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_FILENAME = "artifact-manifest.json"
CANONICAL_ARTIFACT_RE = re.compile(r"^\d{8}T\d{6}Z-([a-z0-9-]+)-([a-z0-9-]+)\.json$")


def analysis_state_dir(engagement_dir: str) -> Path:
    path = Path(engagement_dir) / "tools" / "analysis-state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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
    filename = f"{_timestamp_slug()}-{slugify(category)}-{slugify(label)}.json"
    path = state_dir / filename
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
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

    extra_by_name = {entry["name"]: entry for entry in (extra_entries or []) if entry.get("name")}
    entries: list[dict[str, Any]] = []
    for path in sorted(state_dir.iterdir()):
        if not path.is_file() or path.name == MANIFEST_FILENAME:
            continue
        if not CANONICAL_ARTIFACT_RE.match(path.name):
            continue
        entry = extra_by_name.get(path.name, {})
        stat = path.stat()
        match = CANONICAL_ARTIFACT_RE.match(path.name)
        assert match is not None
        default_kind = match.group(1)
        entries.append({
            "name": path.name,
            "relative_path": str(path.relative_to(Path(engagement_dir))),
            "kind": entry.get("kind", default_kind),
            "label": entry.get("label", path.stem),
            "source_path": entry.get("source_path", ""),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "metadata": entry.get("metadata", {}),
        })

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact_count": len(entries),
        "entries": entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest_path
