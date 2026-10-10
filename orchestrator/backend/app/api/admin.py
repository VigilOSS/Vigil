"""Admin / introspection endpoints.

These exist for the host-side `vigil` CLI to detect install-root drift between
the running orchestrator and a freshly created engagement directory. When the
operator runs ``vigil --root /custom/path engagement create ...``, the new
engagement lands under ``/custom/path/agent/engagements/...`` but the running
orchestrator was started against a *different* install root and cannot see
the new directory through ``sync_engagements()``. Without an introspection
hook the mismatch is silent: the CLI's first ``vigil assess`` call eventually
hits the 404 warning in ``agent/scripts/assess/lib/config.py``, by which
point recon data has already been written to a stale or missing engagement.

The CLI calls ``GET /admin/install-root`` immediately after creating the
engagement, compares the value to its own resolved install root, and aborts
with a recovery message when they diverge. ``POST /admin/sync-engagements``
forces a fresh ``maybe_sync_engagements(force=True)`` so a matching
orchestrator picks up the new directory without waiting for the next sync
trigger.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from .. import db
from ..config import settings
from ..services.engagements import engagements_root, maybe_sync_engagements

router = APIRouter(prefix="/admin", tags=["admin"])


class InstallRootResponse(BaseModel):
    install_root: str
    engagements_root: str


class SyncEngagementsResponse(BaseModel):
    synced: bool
    install_root: str
    engagement_count: int


@router.get("/install-root", response_model=InstallRootResponse)
def get_install_root() -> InstallRootResponse:
    """Return the install root the orchestrator was started against.

    The CLI compares this to its own resolved install root before declaring
    a freshly created engagement reachable. A mismatch means the engagement
    directory is invisible to ``sync_engagements()`` and any data the CLI
    writes will be routed to a stale or non-existent engagement row.
    """
    return InstallRootResponse(
        install_root=str(settings.install_dir),
        engagements_root=str(engagements_root()),
    )


@router.post("/sync-engagements", response_model=SyncEngagementsResponse)
def post_sync_engagements() -> SyncEngagementsResponse:
    """Force a re-scan of the configured engagements root.

    Called by ``vigil engagement create`` immediately after writing the new
    engagement directory so the running backend picks it up without waiting
    for the next implicit sync trigger. Only useful when the orchestrator's
    install root already matches the engagement's install root — the orch
    cannot point at a different directory at runtime, so a true install-root
    mismatch must be caught earlier via ``GET /admin/install-root``.
    """
    maybe_sync_engagements(force=True)
    return SyncEngagementsResponse(
        synced=True,
        install_root=str(settings.install_dir),
        engagement_count=len(db.list_engagements()),
    )
