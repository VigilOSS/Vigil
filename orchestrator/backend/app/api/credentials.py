"""Engagement credentials API (centralized auth store — replaces auth.json).

The mitmproxy addon (capture), the ``vigil auth`` CLI, and the assess runtime
all read/write credentials through these endpoints instead of a per-engagement
``auth.json`` file. The named-identity model is preserved: an engagement holds N
identities and one is active.

Credential material is sensitive (live session cookies/tokens); these routes are
served only on the trusted localhost backend, same as the rest of the API.
"""
from __future__ import annotations

from typing import Any

import anyio
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..services import credentials as creds_service
from ..services.engagements import get_engagement_or_404

router = APIRouter(
    prefix="/engagements/{engagement_key}/credentials", tags=["credentials"]
)


class CredentialUpsertRequest(BaseModel):
    # extra="allow" so an operator can import a session with fields we don't
    # model (custom token shapes, vendor-specific keys). Unknown fields flow
    # into raw_json verbatim and round-trip on read — nothing is silently
    # dropped at the API boundary.
    model_config = ConfigDict(extra="allow")

    mode: str = Field(default="manual", max_length=64)
    state: str | None = Field(default=None, max_length=64)
    use_for_requests: bool = True
    auth_context: str = Field(default="authenticated", min_length=1, max_length=128)
    cookies: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, Any] = Field(default_factory=dict)
    tokens: dict[str, Any] = Field(default_factory=dict)
    host_cookies: list[Any] = Field(default_factory=list)
    notes: str = Field(default="", max_length=8192)
    expires_at: str | None = None
    make_active: bool = False


class CredentialCaptureRequest(BaseModel):
    identity_name: str = Field(default="default", min_length=1, max_length=128)
    host: str = Field(default="", max_length=512)
    scope_host: str = Field(default="", max_length=512)
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)


@router.get("")
async def list_identities(engagement_key: str) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        creds_service.load_identities, engagement.id
    )


@router.get("/resolve")
async def resolve_identity(
    engagement_key: str, identity: str | None = Query(default=None)
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    name, material = await anyio.to_thread.run_sync(
        creds_service.resolve_identity, engagement.id, identity
    )
    return {"identity_name": name, "material": material}


@router.post("/capture")
async def capture(
    engagement_key: str, request: CredentialCaptureRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        lambda: creds_service.capture_material(
            engagement.id,
            request.identity_name,
            host=request.host,
            cookies=request.cookies,
            headers=request.headers,
            tokens=request.tokens,
            scope_host=request.scope_host,
        )
    )


@router.get("/{identity_name}")
async def get_identity(engagement_key: str, identity_name: str) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    material = await anyio.to_thread.run_sync(
        lambda: creds_service.resolve_identity(engagement.id, identity_name)[1]
    )
    if not material:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_name}",
        )
    return material


@router.put("/{identity_name}")
async def put_identity(
    engagement_key: str, identity_name: str, request: CredentialUpsertRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        lambda: creds_service.upsert_material(
            engagement.id,
            identity_name,
            request.model_dump(),
            make_active=request.make_active,
        )
    )


@router.post("/{identity_name}/activate")
async def activate_identity(
    engagement_key: str, identity_name: str
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    ok = await anyio.to_thread.run_sync(
        creds_service.set_active, engagement.id, identity_name
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_name}",
        )
    return {"active_identity": identity_name}


@router.delete("/{identity_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_identity(engagement_key: str, identity_name: str) -> None:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    await anyio.to_thread.run_sync(
        creds_service.clear, engagement.id, identity_name
    )


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_all(engagement_key: str) -> None:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    await anyio.to_thread.run_sync(creds_service.clear, engagement.id, None)
