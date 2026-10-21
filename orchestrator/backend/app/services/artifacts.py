from __future__ import annotations

import codecs
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import HTTPException, status

from . import artifact_index
from .state_manager import dispatches as dispatch_service
from .engagements import get_engagement_or_404

# Root documents the Files view serves. The viewer is a reading surface, not a
# package or integrity boundary, so it reads at most this many bytes and flags
# the rest as truncated instead of refusing the file (the full file stays in
# the engagement directory). The largest root document seen in practice is an
# export snapshot well under this bound.
ARTIFACT_VIEW_MAX_BYTES = 1024 * 1024

# ``vigil engagement create`` seeds ENGAGEMENT.md with this marker
# (src/vigil_cli/engagements.py ``_write_engagement_brief_stub``). Mirrors the
# check in agent/scripts/assess/lib/scope.py ``_require_program_brief_resolution``,
# which the backend cannot import: a stub is unfilled until the operator either
# replaces it or records a reasoned ``no_separate_program_brief`` decision.
_BRIEF_STUB_MARKER = re.compile(r"^> \*\*STUB\b", re.MULTILINE)
_BRIEF_NAME = "ENGAGEMENT.md"
_PROGRAM_BRIEF_DECISION_KIND = "program_brief"
_NO_SEPARATE_BRIEF_CHOICE = "no_separate_program_brief"
_DECISION_PAGE_SIZE = 500

ArtifactGroup = Literal["working", "snapshot"]
_EXPORT_SNAPSHOT_ROLE = "Export snapshot (DB is the source of truth)"


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    relative_path: str
    media_type: str
    group: ArtifactGroup
    role: str
    description: str


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    name: str
    relative_path: str
    media_type: str
    exists: bool
    group: ArtifactGroup
    role: str
    description: str
    size_bytes: int | None
    modified_at: str | None
    is_stub: bool
    stub_waiver: str


@dataclass(frozen=True, slots=True)
class ArtifactContent:
    entry: ArtifactEntry
    content: str
    truncated: bool
    returned_bytes: int


# Priority order: the working documents an operator or agent reads first, then
# configuration and export snapshots of backend state. Generated client
# wrappers (AGENTS.md, CLAUDE.md, start scripts) and ad-hoc operator files are
# deliberately not listed.
ARTIFACT_SPECS: dict[str, ArtifactSpec] = {
    "ENGAGEMENT.md": ArtifactSpec(
        "ENGAGEMENT.md",
        "text/markdown",
        "working",
        "Program brief",
        "Rules of engagement and program brief. Agents must read it before any target traffic.",
    ),
    "RESUME.md": ArtifactSpec(
        "RESUME.md",
        "text/markdown",
        "working",
        "Handoff",
        "Where the last session stopped and what to pick up next.",
    ),
    "COMPACT.md": ArtifactSpec(
        "COMPACT.md",
        "text/markdown",
        "working",
        "Context memory",
        "Working memory an agent saved before its context was compacted.",
    ),
    "ISSUES-AND-ENHANCEMENTS.md": ArtifactSpec(
        "ISSUES-AND-ENHANCEMENTS.md",
        "text/markdown",
        "working",
        "Issues log",
        "Reusable product, prompt, and tooling lessons noticed during the engagement. Not a findings log.",
    ),
    "RULES.md": ArtifactSpec(
        "RULES.md",
        "text/markdown",
        "working",
        "Program brief (legacy name)",
        "Older name for the program brief. Agents still read it as the brief when ENGAGEMENT.md is absent.",
    ),
    "report.md": ArtifactSpec(
        "report.md",
        "text/markdown",
        "working",
        "Incident report",
        "Report scaffold that blue (incident) engagements render into.",
    ),
    "scope.json": ArtifactSpec(
        "scope.json",
        "application/json",
        "snapshot",
        "Scope and policy",
        "Scope hosts, exploit policy, and the current phase.",
    ),
    "capture-policy.json": ArtifactSpec(
        "capture-policy.json",
        "application/json",
        "snapshot",
        "Capture policy",
        "Which HTTP request and response bodies the proxy records, and the size limit.",
    ),
    "engagement.json": ArtifactSpec(
        "engagement.json",
        "application/json",
        "snapshot",
        "Engagement record",
        "Engagement metadata written at creation; the page header shows the same fields.",
    ),
    "findings.md": ArtifactSpec(
        "findings.md",
        "text/markdown",
        "snapshot",
        _EXPORT_SNAPSHOT_ROLE,
        "Point-in-time findings export. The Findings view shows current state.",
    ),
    "surfaces.jsonl": ArtifactSpec(
        "surfaces.jsonl",
        "text/plain",
        "snapshot",
        _EXPORT_SNAPSHOT_ROLE,
        "Point-in-time attack-surface export, one JSON record per line. The Surfaces view shows current state.",
    ),
}


def _engagement_root(engagement) -> Path:
    return Path(engagement.engagement_root).expanduser().resolve()


def _iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_root_document(root: Path, relative_path: str) -> int | None:
    """Open a root document without following symlinks (None when absent)."""
    return artifact_index._open_registered_artifact(root, relative_path)


def _read_bounded(descriptor: int, max_bytes: int) -> tuple[os.stat_result, bytes, bool]:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="engagement file must be a regular file",
        )
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    truncated = len(data) > max_bytes
    return info, data[:max_bytes], truncated


def _decode(data: bytes, *, truncated: bool) -> str:
    """Strict UTF-8; a truncated read drops only an incomplete trailing character."""
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        return decoder.decode(data, final=not truncated)
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="engagement file is not valid UTF-8 text",
        ) from exc


def _brief_stub_waiver(engagement_id: int) -> str:
    """Reason of the newest reasoned no-separate-brief decision, else ""."""
    offset = 0
    while True:
        page = dispatch_service.list_decisions(
            engagement_id,
            kind=_PROGRAM_BRIEF_DECISION_KIND,
            limit=_DECISION_PAGE_SIZE,
            offset=offset,
        )
        for row in page:
            payload = row.get("payload")
            if not isinstance(payload, dict) or payload.get("choice") != _NO_SEPARATE_BRIEF_CHOICE:
                continue
            reason = str(payload.get("reason") or "")
            if reason.strip():
                return reason
        if len(page) < _DECISION_PAGE_SIZE:
            return ""
        offset += _DECISION_PAGE_SIZE


def _artifact_entry(
    engagement,
    root: Path,
    name: str,
    *,
    info: os.stat_result | None,
    text: str | None,
) -> ArtifactEntry:
    spec = ARTIFACT_SPECS[name]
    is_stub = bool(name == _BRIEF_NAME and text is not None and _BRIEF_STUB_MARKER.search(text))
    return ArtifactEntry(
        name=name,
        relative_path=spec.relative_path,
        media_type=spec.media_type,
        exists=info is not None or (root / spec.relative_path).is_symlink(),
        group=spec.group,
        role=spec.role,
        description=spec.description,
        size_bytes=info.st_size if info is not None else None,
        modified_at=_iso_utc(info.st_mtime) if info is not None else None,
        is_stub=is_stub,
        stub_waiver=_brief_stub_waiver(engagement.id) if is_stub else "",
    )


def _list_entry(engagement, root: Path, name: str) -> ArtifactEntry:
    spec = ARTIFACT_SPECS[name]
    try:
        descriptor = _open_root_document(root, spec.relative_path)
    except HTTPException:
        # A symlinked root document is never followed; it is listed as present
        # but unreadable, and reading it returns the refusal.
        descriptor = None
    if descriptor is None:
        return _artifact_entry(engagement, root, name, info=None, text=None)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            # A directory (or other non-file) under a document's name is not
            # that document; reading it returns the regular-file refusal.
            return _artifact_entry(engagement, root, name, info=None, text=None)
        text: str | None = None
        if name == _BRIEF_NAME:
            _, data, _ = _read_bounded(descriptor, ARTIFACT_VIEW_MAX_BYTES)
            text = data.decode("utf-8", errors="replace")
        return _artifact_entry(engagement, root, name, info=info, text=text)
    finally:
        os.close(descriptor)


def list_artifacts_for_engagement(engagement_key: str) -> list[ArtifactEntry]:
    engagement = get_engagement_or_404(engagement_key)
    root = _engagement_root(engagement)
    return [_list_entry(engagement, root, name) for name in ARTIFACT_SPECS]


def read_artifact_for_engagement(engagement_key: str, name: str) -> ArtifactContent:
    if name not in ARTIFACT_SPECS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")

    engagement = get_engagement_or_404(engagement_key)
    root = _engagement_root(engagement)
    descriptor = _open_root_document(root, ARTIFACT_SPECS[name].relative_path)
    if descriptor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    try:
        info, data, truncated = _read_bounded(descriptor, ARTIFACT_VIEW_MAX_BYTES)
    finally:
        os.close(descriptor)
    content = _decode(data, truncated=truncated)
    entry = _artifact_entry(engagement, root, name, info=info, text=content)
    return ArtifactContent(
        entry=entry,
        content=content,
        truncated=truncated,
        returned_bytes=len(content.encode("utf-8")),
    )
