from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from .api.artifacts import router as artifacts_router
from .api.assessment import router as assessment_router
from .api.code_analysis import router as code_analysis_router
from .api.engagements import router as engagements_router
from .api.events import router as events_router
from .config import settings
from .db import init_db
from .services.engagements import get_engagement_or_404, maybe_sync_engagements
from .ws import broadcaster


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    maybe_sync_engagements(force=True)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(engagements_router)
app.include_router(events_router)
app.include_router(artifacts_router)
app.include_router(assessment_router)
app.include_router(code_analysis_router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "app": settings.app_name}


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
        return {"detail": "frontend build not found"}

    requested_path = settings.frontend_dist_dir / full_path
    if full_path and requested_path.is_file() and requested_path.is_relative_to(settings.frontend_dist_dir):
        return FileResponse(requested_path)

    index_path = settings.frontend_dist_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    return {"detail": "frontend build not found"}
