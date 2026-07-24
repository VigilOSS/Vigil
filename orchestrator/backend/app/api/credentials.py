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

from .. import db
from ..services import credentials as creds_service
from ..services.engagements import get_engagement_or_404

# Verdicts accepted by the per-session liveness-persist route. Mirrors the
# ``{live, dead, unknown}`` vocabulary the CLI liveness classifier emits and
# ``db.set_liveness`` reconciles state against; ``stale`` is set by the age
# backstop sweep, never by a probe, so it is not an accepted probe verdict here.
_LIVENESS_VERDICTS = frozenset({"live", "dead", "unknown"})

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
    principal_id: str = Field(default="", max_length=256)
    mfa_factor: str = Field(default="", max_length=64)
    make_active: bool = False


class LivenessPersistRequest(BaseModel):
    # An LLM-owned per-session liveness verdict (WS4). ``verdict`` is one of
    # {live, dead, unknown}; ``probed_at`` is the ISO-8601 probe time (or null to
    # let the store record without a timestamp). Persisted through
    # ``db.set_liveness``, which reconciles ``state`` (dead->dead, live->available
    # clearing a stale flag, unknown->state untouched — never a false verdict).
    verdict: str = Field(..., min_length=1, max_length=32)
    probed_at: str | None = Field(default=None, max_length=64)
    scope_key: str = Field(default="", max_length=512)
    ttl_seconds: int = Field(default=900, ge=1, le=86400)
    source: str = Field(default="probe", max_length=64)
    reason: str = Field(default="", max_length=1024)


class CredentialAliasRequest(BaseModel):
    principal_id: str = Field(..., min_length=1, max_length=256)
    scope_key: str = Field(default="", max_length=512)


class CredentialCaptureRequest(BaseModel):
    # identity_name is DERIVED server-side from the capture's session-anchor
    # material (see credentials.derive_capture_identity); any value posted here
    # is ignored. Kept as an optional field only for backward-compatible request
    # bodies from older addon builds.
    identity_name: str | None = Field(default=None, max_length=128)
    host: str = Field(default="", max_length=512)
    scope_host: str = Field(default="", max_length=512)
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)


@router.get("")
async def list_identities(
    engagement_key: str,
    host: str | None = Query(default=None),
    include_dead: bool = Query(default=False),
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    return await anyio.to_thread.run_sync(
        lambda: creds_service.load_identities(
            engagement.id, host=host, include_dead=include_dead
        )
    )


@router.get("/resolve")
async def resolve_identity(
    engagement_key: str,
    identity: str | None = Query(default=None),
    scope: str = Query(default=""),
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    name, material = await anyio.to_thread.run_sync(
        lambda: creds_service.resolve_identity(engagement.id, identity, scope_key=scope)
    )
    return {"identity_name": name, "material": material}


@router.put("/aliases/{alias}")
async def put_alias(
    engagement_key: str, alias: str, request: CredentialAliasRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    await anyio.to_thread.run_sync(
        lambda: db.set_credential_alias(
            engagement.id, alias, request.principal_id, request.scope_key
        )
    )
    return {
        "alias": alias,
        "principal_id": request.principal_id,
        "scope_key": request.scope_key,
    }


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


@router.post("/{identity_name}/quarantine")
async def quarantine_identity(
    engagement_key: str, identity_name: str
) -> dict[str, Any]:
    """Disable request replay while preserving the credential as evidence."""
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    material = await anyio.to_thread.run_sync(
        db.quarantine_credential, engagement.id, identity_name
    )
    if material is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_name}",
        )
    return material


@router.post("/{identity_name}/liveness")
async def persist_liveness(
    engagement_key: str, identity_name: str, request: LivenessPersistRequest
) -> dict[str, Any]:
    """Record an LLM-owned liveness-probe verdict for one stored identity (WS4).

    The CLI probe (``vigil assess auth-status --probe --identity`` / operator
    ``vigil auth status --probe --identity``) classifies a session with the
    identity's ``material.liveness`` signature, then persists the verdict here so
    a proven-dead session is hidden from the default list and a ``live`` probe
    clears an age-backstop ``stale`` mark. Only a probe sets ``dead`` — never age.
    Returns the updated material; 404 when the identity does not exist.
    """
    verdict = request.verdict.strip().lower()
    if verdict not in _LIVENESS_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"verdict must be one of {sorted(_LIVENESS_VERDICTS)}",
        )
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    material = await anyio.to_thread.run_sync(
        lambda: db.record_credential_liveness(
            engagement.id,
            identity_name,
            scope_key=request.scope_key,
            verdict=verdict,
            observed_at=request.probed_at or "",
            ttl_seconds=request.ttl_seconds,
            source=request.source,
            reason=request.reason,
        )
    )
    # The singleton columns are a legacy unscoped projection. A dead verdict for
    # one app scope must not kill the same principal's capability everywhere.
    if material is not None and not request.scope_key:
        authoritative = next(
            (
                row
                for row in material.get("liveness_observations", [])
                if row.get("scope_key") == ""
            ),
            None,
        )
        if authoritative is not None:
            material = await anyio.to_thread.run_sync(
                lambda: db.set_liveness(
                    engagement.id,
                    identity_name,
                    str(authoritative["verdict"]),
                    str(authoritative["observed_at"]),
                )
            )
    if material is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity not found: {identity_name}",
        )
    return material


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
