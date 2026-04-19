from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, status

from .engagements import get_engagement_or_404


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    name: str
    relative_path: str
    media_type: str
    sensitive: bool
    exists: bool


@dataclass(frozen=True, slots=True)
class ArtifactContent:
    entry: ArtifactEntry
    content: str


ARTIFACT_SPECS = {
    "scope.json": ("scope.json", "application/json", False),
    "findings.md": ("findings.md", "text/markdown", False),
    "report.md": ("report.md", "text/markdown", False),
    "auth.json": ("auth.json", "application/json", True),
    "surfaces.jsonl": ("surfaces.jsonl", "text/plain", False),
    "engagement.json": ("engagement.json", "application/json", False),
}


def _artifact_entry(engagement_root: Path, name: str) -> ArtifactEntry:
    relative_path, media_type, sensitive = ARTIFACT_SPECS[name]
    return ArtifactEntry(
        name=name,
        relative_path=relative_path,
        media_type=media_type,
        sensitive=sensitive,
        exists=(engagement_root / relative_path).exists(),
    )


def list_artifacts_for_engagement(engagement_key: str) -> list[ArtifactEntry]:
    engagement = get_engagement_or_404(engagement_key)
    engagement_root = Path(engagement.engagement_root)
    return [_artifact_entry(engagement_root, name) for name in ARTIFACT_SPECS]


def read_artifact_for_engagement(engagement_key: str, name: str) -> ArtifactContent:
    if name not in ARTIFACT_SPECS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    engagement = get_engagement_or_404(engagement_key)
    engagement_root = Path(engagement.engagement_root)
    entry = _artifact_entry(engagement_root, name)
    artifact_path = engagement_root / entry.relative_path
    if not artifact_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    return ArtifactContent(entry=entry, content=artifact_path.read_text(encoding="utf-8"))
