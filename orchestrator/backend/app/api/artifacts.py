from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

from ..services.artifacts import ArtifactEntry, list_artifacts_for_engagement, read_artifact_for_engagement

router = APIRouter(prefix="/engagements/{engagement_key}/artifacts", tags=["artifacts"])


class ArtifactResponse(BaseModel):
    name: str
    relative_path: str
    media_type: str
    exists: bool
    # "working" documents lead the list; "snapshot" covers config and exports.
    group: Literal["working", "snapshot"]
    role: str
    description: str
    # File size and last modification (ISO-8601 UTC); null when the file is
    # absent or cannot be opened without following a symlink.
    size_bytes: int | None
    modified_at: str | None
    # ENGAGEMENT.md still carries the generated STUB marker.
    is_stub: bool
    # Reason from the operator's ``no_separate_program_brief`` decision when a
    # stub brief was deliberately left unfilled; "" otherwise.
    stub_waiver: str


class ArtifactContentResponse(ArtifactResponse):
    content: str
    # The read stops at the view limit; ``returned_bytes`` of ``size_bytes``
    # are in ``content`` when ``truncated`` is true.
    truncated: bool
    returned_bytes: int


def _artifact_response_payload(artifact: ArtifactEntry) -> dict:
    return {
        "name": artifact.name,
        "relative_path": artifact.relative_path,
        "media_type": artifact.media_type,
        "exists": artifact.exists,
        "group": artifact.group,
        "role": artifact.role,
        "description": artifact.description,
        "size_bytes": artifact.size_bytes,
        "modified_at": artifact.modified_at,
        "is_stub": artifact.is_stub,
        "stub_waiver": artifact.stub_waiver,
    }


@router.get("", response_model=list[ArtifactResponse])
def list_artifacts(engagement_key: str) -> list[ArtifactResponse]:
    artifacts = list_artifacts_for_engagement(engagement_key)
    return [ArtifactResponse(**_artifact_response_payload(artifact)) for artifact in artifacts]


@router.get("/{artifact_name}", response_model=ArtifactContentResponse)
def read_artifact(engagement_key: str, artifact_name: str) -> ArtifactContentResponse:
    artifact = read_artifact_for_engagement(engagement_key, artifact_name)
    return ArtifactContentResponse(
        content=artifact.content,
        truncated=artifact.truncated,
        returned_bytes=artifact.returned_bytes,
        **_artifact_response_payload(artifact.entry),
    )
