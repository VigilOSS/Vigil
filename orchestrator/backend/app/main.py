import functools
import logging
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from anyio import to_thread
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from .api.activity import router as activity_router
from .api.admin import router as admin_router
from .api.artifacts import router as artifacts_router
from .api.assessment import router as assessment_router
from .api.code_analysis import router as code_analysis_router
from .api.credentials import router as credentials_router
from .api.dashboard import router as dashboard_router
from .api.engagements import router as engagements_router
from .api.events import router as events_router
from .api.intel import router as intel_router
from .api.report_export import router as report_export_router
from .config import settings
from .db import database_readiness_flags, get_connection, init_db
from .services.backup import start_scheduler as start_backup_scheduler, stop_scheduler as stop_backup_scheduler
from .services.engagements import get_engagement_or_404, maybe_sync_engagements
from .ws import broadcaster

logger = logging.getLogger(__name__)

_BACKEND_PROCESS_STARTED_AT = time.time()
_BACKEND_SOURCE_ROOT = Path(__file__).resolve().parent


_FRONTEND_MISSING_HELP = (
    "Frontend build not found at "
    f"{settings.frontend_dist_dir}. The backend was started without first "
    "building the frontend (likely a direct `uv run uvicorn ...` instead of "
    "`vigil up` or `vigil orchestrator start`). Run `vigil orchestrator build` "
    "to build the install-side frontend in place, then refresh."
)


def _backend_runtime_snapshot() -> dict[str, object]:
    newer_files: list[str] = []
    newest_mtime = 0.0
    for path in _BACKEND_SOURCE_ROOT.rglob("*.py"):
        try:
            modified_at = path.stat().st_mtime
        except OSError:
            continue
        newest_mtime = max(newest_mtime, modified_at)
        if modified_at > _BACKEND_PROCESS_STARTED_AT:
            newer_files.append(path.relative_to(_BACKEND_SOURCE_ROOT).as_posix())
    return {
        "source_root": str(_BACKEND_SOURCE_ROOT),
        "process_started_at": datetime.fromtimestamp(
            _BACKEND_PROCESS_STARTED_AT,
            tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "newest_source_mtime": (
            datetime.fromtimestamp(newest_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if newest_mtime
            else None
        ),
        "restart_required": bool(newer_files),
        "newer_source_files": sorted(newer_files)[:20],
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    # E1: async write handlers off-load their synchronous SQLite work to the
    # anyio worker threadpool (the same pool FastAPI uses for plain-`def`
    # reads). SQLite has a single writer and short CPU-heavy row materialization
    # bursts; allowing dozens of workers to pile into it makes the process hit
    # multi-core saturation and starves health checks. Keep the default
    # conservative and env-tunable for larger machines.
    to_thread.current_default_thread_limiter().total_tokens = int(
        os.environ.get("VIGIL_BACKEND_THREADPOOL", "16")
    )
    init_db()
    maybe_sync_engagements(force=True)
    start_backup_scheduler()
    if not settings.frontend_dist_dir.exists():
        logger.warning(_FRONTEND_MISSING_HELP)
    try:
        yield
    finally:
        stop_backup_scheduler()


app = FastAPI(title=settings.app_name, lifespan=lifespan)


@app.exception_handler(sqlite3.OperationalError)
async def sqlite_operational_error(
    _request: Request, exc: sqlite3.OperationalError
) -> JSONResponse:
    """Expose contention as retryable service pressure, not a blank 500."""
    if "locked" in str(exc).lower():
        logger.warning("SQLite contention exhausted busy timeout: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"detail": "database write contention; retry shortly"},
            headers={"Retry-After": "1"},
        )
    logger.exception("SQLite operational failure", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "database operation failed"},
    )


app.include_router(admin_router)
app.include_router(dashboard_router)
app.include_router(engagements_router)
app.include_router(credentials_router)
app.include_router(events_router)
app.include_router(artifacts_router)
app.include_router(assessment_router)
app.include_router(report_export_router)
app.include_router(code_analysis_router)
app.include_router(intel_router)
app.include_router(activity_router)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "app": settings.app_name}


@app.get("/readyz", response_model=None)
def readyz() -> JSONResponse | dict[str, object]:
    with get_connection() as connection:
        connection.execute("SELECT 1").fetchone()
        schema_flags = database_readiness_flags(connection)
    payload: dict[str, object] = {
        "status": "ready",
        "app": settings.app_name,
        "database_connected": True,
        "backend_runtime": _backend_runtime_snapshot(),
    }
    payload.update(schema_flags)
    if not all(schema_flags.values()):
        payload["status"] = "not_ready"
        return JSONResponse(status_code=503, content=payload)
    return payload


@app.websocket("/ws/engagements/{engagement_key}")
async def engagement_stream(websocket: WebSocket, engagement_key: str) -> None:
    get_engagement_or_404(engagement_key)
    await broadcaster.connect(engagement_key, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(engagement_key, websocket)


@functools.lru_cache(maxsize=1)
def _engagement_api_segments() -> frozenset[str]:
    """Path segments an API router owns under ``/engagements/{key}/``.

    Derived from the app's own route table rather than hand-listed: the router
    registrations ARE the list, so adding a router can never silently re-open the
    SPA fallback over a new API family.
    """

    segments: set[str] = set()
    for route in app.routes:
        parts = str(getattr(route, "path", "")).strip("/").split("/")
        if (
            len(parts) >= 3
            and parts[0] == "engagements"
            and parts[1].startswith("{")
            and not parts[2].startswith("{")
        ):
            segments.add(parts[2])
    return frozenset(segments)


def _is_unmatched_api_path(full_path: str) -> bool:
    """Would an API client reasonably have expected a route here?

    The SPA catch-all answered 200 + index.html for EVERY unmatched path, so a
    misspelt endpoint was indistinguishable from a working one that returned an
    HTML-shaped body — exit 0, no error, no route. UI deep links live in the same
    namespace (``/engagements/<key>/findings`` is a real page), so the split is by
    the API families the routers actually claim, never by the ``engagements/``
    prefix alone.
    """

    parts = full_path.strip("/").split("/")
    if not parts or not parts[0]:
        return False
    if parts[0] == "api":
        return True
    return (
        len(parts) >= 3
        and parts[0] == "engagements"
        and parts[2] in _engagement_api_segments()
    )


@app.get("/{full_path:path}")
def frontend_app(full_path: str):
    if _is_unmatched_api_path(full_path):
        return JSONResponse(
            status_code=404,
            content={
                "detail": (
                    f"no API route matches '/{full_path.strip('/')}'. Check the "
                    "route name — path separators are slashes, not hyphens "
                    "(e.g. 'code/files', not 'code-files')."
                )
            },
        )

    if not settings.frontend_dist_dir.exists():
        return JSONResponse(
            status_code=503,
            content={"detail": _FRONTEND_MISSING_HELP, "fix": "vigil orchestrator build"},
        )

    requested_path = settings.frontend_dist_dir / full_path
    if full_path and requested_path.is_file() and requested_path.is_relative_to(settings.frontend_dist_dir):
        return FileResponse(requested_path)

    index_path = settings.frontend_dist_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    return JSONResponse(
        status_code=503,
        content={"detail": _FRONTEND_MISSING_HELP, "fix": "vigil orchestrator build"},
    )
