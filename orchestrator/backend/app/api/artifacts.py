from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ..services.artifacts import list_artifacts_for_engagement, read_artifact_for_engagement

router = APIRouter(prefix="/engagements/{engagement_key}/artifacts", tags=["artifacts"])


class ArtifactResponse(BaseModel):
    name: str
    relative_path: str
    media_type: str
    sensitive: bool
    exists: bool


class ArtifactContentResponse(ArtifactResponse):
    content: str


def _artifact_response_payload(artifact) -> dict:
    return {
        "name": artifact.name,
        "relative_path": artifact.relative_path,
        "media_type": artifact.media_type,
        "sensitive": artifact.sensitive,
        "exists": artifact.exists,
    }


@router.get("", response_model=list[ArtifactResponse])
def list_artifacts(engagement_key: str) -> list[ArtifactResponse]:
    artifacts = list_artifacts_for_engagement(engagement_key)
    return [ArtifactResponse(**_artifact_response_payload(artifact)) for artifact in artifacts]


@router.get("/{artifact_name}", response_model=ArtifactContentResponse)
def read_artifact(engagement_key: str, artifact_name: str) -> ArtifactContentResponse:
    artifact = read_artifact_for_engagement(engagement_key, artifact_name)
    return ArtifactContentResponse(content=artifact.content, **_artifact_response_payload(artifact.entry))
