from __future__ import annotations

import functools
from typing import Annotated, Literal

import anyio
from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from ..services import sent_reply_versions, submission_versions
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster


router = APIRouter(
    prefix="/engagements/{engagement_key}/assessment/submissions",
    tags=["assessment-submissions"],
)


async def _broadcast(
    engagement_key: str, record_type: str, payload: dict
) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "assessment.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


class SubmissionExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: Literal["bugcrowd", "hackerone", "direct"]
    submission_path: str = Field(min_length=1, max_length=2048)
    context_path: str = Field(min_length=1, max_length=2048)
    attachment_ids: list[int] = Field(default_factory=list, max_length=1000)
    actor_surface: Literal["vigil-assess", "web-ui"]


class SubmissionRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_surface: Literal["vigil-assess", "web-ui"]
    orphan_after: str = Field(default="", max_length=2048)
    orphan_limit: int = Field(
        default=submission_versions.DEFAULT_SUBMISSION_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_SUBMISSION_PAGE_LIMIT,
    )
    failed_version_offset: int = Field(default=0, ge=0)
    failed_version_limit: int = Field(
        default=submission_versions.DEFAULT_SUBMISSION_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_SUBMISSION_PAGE_LIMIT,
    )


class SentReplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_row_version: int = Field(ge=1)
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=4096)


@router.get("")
async def list_submission_findings(
    engagement_key: str,
    finding_offset: int = Query(default=0, ge=0),
    finding_limit: int = Query(
        default=submission_versions.DEFAULT_SUBMISSION_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_SUBMISSION_PAGE_LIMIT,
    ),
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        functools.partial(
            submission_versions.list_submissions,
            engagement.id,
            limit=finding_limit,
            offset=finding_offset,
        )
    )


@router.get("/{finding_slug}")
async def get_submission_detail(
    engagement_key: str,
    finding_slug: str,
    attachment_id: list[int] | None = Query(default=None),
    attachment_offset: int = Query(default=0, ge=0),
    attachment_limit: int = Query(
        default=submission_versions.DEFAULT_ATTACHMENT_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_ATTACHMENT_PAGE_LIMIT,
    ),
    version_offset: int = Query(default=0, ge=0),
    version_limit: int = Query(
        default=submission_versions.DEFAULT_SUBMISSION_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_SUBMISSION_PAGE_LIMIT,
    ),
    pending_version_offset: int = Query(default=0, ge=0),
    pending_version_limit: int = Query(
        default=submission_versions.DEFAULT_SUBMISSION_PAGE_LIMIT,
        ge=1,
        le=submission_versions.MAX_SUBMISSION_PAGE_LIMIT,
    ),
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        functools.partial(
            submission_versions.submission_detail,
            engagement.id,
            finding_slug,
            attachment_ids=attachment_id or [],
            attachment_offset=attachment_offset,
            attachment_limit=attachment_limit,
            version_offset=version_offset,
            version_limit=version_limit,
            pending_version_offset=pending_version_offset,
            pending_version_limit=pending_version_limit,
        )
    )


@router.post("/{finding_slug}/exports", status_code=status.HTTP_201_CREATED)
async def export_submission_version(
    engagement_key: str,
    finding_slug: str,
    request: SubmissionExportRequest,
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    result = await anyio.to_thread.run_sync(
        functools.partial(
            submission_versions.export_version,
            engagement.id,
            finding_slug,
            platform=request.platform,
            submission_path=request.submission_path,
            context_path=request.context_path,
            attachment_ids=request.attachment_ids,
            actor_surface=request.actor_surface,
        )
    )
    await _broadcast(engagement_key, "submission_version", result)
    return result


@router.post(
    "/{finding_slug}/replies/{reply_sequence}/send",
    status_code=status.HTTP_201_CREATED,
)
async def send_reply(
    engagement_key: str,
    finding_slug: str,
    reply_sequence: Annotated[int, Path(ge=1)],
    request: SentReplyRequest,
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    result = await anyio.to_thread.run_sync(
        functools.partial(
            sent_reply_versions.send_reply,
            engagement.id,
            finding_slug,
            reply_sequence,
            expected_row_version=request.expected_row_version,
            actor=request.actor,
            reason=request.reason,
        )
    )
    await _broadcast(engagement_key, "sent_reply", result)
    return result


@router.get("/{finding_slug}/replies/{reply_sequence}/sent")
async def get_sent_reply(
    engagement_key: str,
    finding_slug: str,
    reply_sequence: Annotated[int, Path(ge=1)],
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    metadata, _data = await anyio.to_thread.run_sync(
        sent_reply_versions.read_sent_reply,
        engagement.id,
        finding_slug,
        reply_sequence,
    )
    return metadata


@router.get("/{finding_slug}/replies/{reply_sequence}/sent/download")
async def download_sent_reply(
    engagement_key: str,
    finding_slug: str,
    reply_sequence: Annotated[int, Path(ge=1)],
) -> Response:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    metadata, data = await anyio.to_thread.run_sync(
        sent_reply_versions.read_sent_reply,
        engagement.id,
        finding_slug,
        reply_sequence,
    )
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "legacy sent reply bytes are unavailable; Vigil will not "
                "reconstruct them from mutable finding content"
            ),
        )
    return Response(
        content=data,
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="reply-{metadata["reply_sequence"]}.md"'
            )
        },
    )


@router.get("/{finding_slug}/versions/{version_number}/download")
async def download_submission_version(
    engagement_key: str,
    finding_slug: str,
    version_number: int,
) -> Response:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    data, media_type, filename = await anyio.to_thread.run_sync(
        submission_versions.read_version,
        engagement.id,
        finding_slug,
        version_number,
    )
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/recover")
async def recover_submission_exports(
    engagement_key: str,
    request: SubmissionRecoveryRequest,
) -> dict:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    result = await anyio.to_thread.run_sync(
        functools.partial(
            submission_versions.recover_exports,
            engagement.id,
            actor_surface=request.actor_surface,
            orphan_after=request.orphan_after,
            orphan_limit=request.orphan_limit,
            failed_version_offset=request.failed_version_offset,
            failed_version_limit=request.failed_version_limit,
        )
    )
    await _broadcast(engagement_key, "submission_recovery", result)
    return result
