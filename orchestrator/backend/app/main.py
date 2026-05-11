import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from .api.activity import router as activity_router
from .api.admin import router as admin_router
from .api.artifacts import router as artifacts_router
from .api.assessment import router as assessment_router
from .api.code_analysis import router as code_analysis_router
from .api.engagements import router as engagements_router
from .api.events import router as events_router
from .api.intel import router as intel_router
from .config import settings
from .db import database_readiness_flags, get_connection, init_db
from .services.backup import start_scheduler as start_backup_scheduler, stop_scheduler as stop_backup_scheduler
from .services.engagements import get_engagement_or_404, maybe_sync_engagements
from .ws import broadcaster

logger = logging.getLogger(__name__)


_FRONTEND_MISSING_HELP = (
    "Frontend build not found at "
    f"{settings.frontend_dist_dir}. The backend was started without first "
    "building the frontend (likely a direct `uv run uvicorn ...` instead of "
    "`aith up` or `aith orchestrator start`). Run `aith orchestrator build` "
    "to build the install-side frontend in place, then refresh."
)


@asynccontextmanager
async def lifespan(app: FastAPI):
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
app.include_router(admin_router)
app.include_router(engagements_router)
app.include_router(events_router)
app.include_router(artifacts_router)
app.include_router(assessment_router)
app.include_router(code_analysis_router)
app.include_router(intel_router)
app.include_router(activity_router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
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


@app.get("/{full_path:path}")
def frontend_app(full_path: str):
    if not settings.frontend_dist_dir.exists():
        return JSONResponse(
            status_code=503,
            content={"detail": _FRONTEND_MISSING_HELP, "fix": "aith orchestrator build"},
        )

    requested_path = settings.frontend_dist_dir / full_path
    if full_path and requested_path.is_file() and requested_path.is_relative_to(settings.frontend_dist_dir):
        return FileResponse(requested_path)

    index_path = settings.frontend_dist_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    return JSONResponse(
        status_code=503,
        content={"detail": _FRONTEND_MISSING_HELP, "fix": "aith orchestrator build"},
    )
