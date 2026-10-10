import functools
import hashlib
import logging
import os
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from importlib.machinery import PathFinder
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
from .api.remediation import router as remediation_router
from .api.submissions import router as submissions_router
from .config import settings
from .db import database_readiness_flags, get_connection, init_db
from .services.backup import start_scheduler as start_backup_scheduler, stop_scheduler as stop_backup_scheduler
from .services.engagements import get_engagement_or_404, maybe_sync_engagements
from .ws import broadcaster, websocket_origin_allowed

logger = logging.getLogger(__name__)

_BACKEND_PROCESS_STARTED_AT = time.time()
_BACKEND_SOURCE_ROOT = Path(__file__).resolve().parent
_BACKEND_PACKAGE_ROOT = _BACKEND_SOURCE_ROOT.parent
# Pinned at import, not read per request: the install root a process was
# launched against cannot change while it runs, and re-reading `settings` would
# let a later override make the snapshot and the check disagree about which
# files they are even talking about.
_BACKEND_INSTALL_ROOT = settings.install_dir.expanduser().resolve()
_BACKEND_APPLICATION_ROOT = settings.application_dir.expanduser().resolve()

# Files the backend is built from that are NOT under `app/`. A new dependency
# lands here and nowhere else, which is precisely the change that cannot work
# without a restart — and precisely the one the previous `app/**.py` mtime scan
# could not see.
_BACKEND_DEPENDENCY_MANIFESTS = ("pyproject.toml", "uv.lock")

# Build artifacts and caches that live inside a source tree but are not source.
# `vigil_cli.image_freshness` owns the canonical set for the CLI side; the
# backend is a separate uv project that cannot import it, so it carries the
# subset that can appear under `app/`. `__pycache__` is the load-bearing entry:
# every import rewrites bytecode next to the module it came from.
_NOT_SOURCE_NAMES = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".DS_Store"})

# Stands in for a file on one side of a comparison but not the other, so a
# deletion and an addition are both a difference rather than an omission.
_ABSENT = "<absent>"


def _is_source_file(path: Path) -> bool:
    if path.suffix == ".pyc":
        return False
    return not any(part in _NOT_SOURCE_NAMES for part in path.parts)


def _file_digest(path: Path) -> str:
    """sha256 of a file's CONTENT, or a marker for one that is gone.

    An absent file gets its own marker rather than being dropped, so DELETING a
    module the running process imported reads as a required restart instead of
    silently vanishing from the comparison.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "<absent>"


def _declared_backend_inputs() -> dict[str, str]:
    """Content digests of the backend's own declared build inputs.

    Labels are relative to the backend package root, so `app/db.py` and
    `uv.lock` share one namespace and a reader of `/readyz` can tell at a glance
    which half of the backend moved.
    """
    inputs: dict[str, str] = {}
    for path in sorted(_BACKEND_SOURCE_ROOT.rglob("*")):
        if not path.is_file() or not _is_source_file(path):
            continue
        inputs[path.relative_to(_BACKEND_PACKAGE_ROOT).as_posix()] = _file_digest(path)
    for name in _BACKEND_DEPENDENCY_MANIFESTS:
        inputs[name] = _file_digest(_BACKEND_PACKAGE_ROOT / name)
    return inputs


def _loaded_cross_tree_inputs() -> dict[str, str]:
    """Content digests of every module this process imported from outside `app/`.

    `services/state_manager/taxonomy_bridge` puts `agent/scripts` on `sys.path`
    and imports `assess.lib.vuln_taxonomy` at module import time, so a file under
    `agent/` really is running inside this process — "`agent/**` is only prompts,
    no restart needed" is not universally true. No path table would stay right
    through the next such import; `sys.modules` is the only source that cannot
    go stale, and it costs one dict walk.
    """
    inputs: dict[str, str] = {}
    for module in list(sys.modules.values()):
        raw = getattr(module, "__file__", None)
        if not raw:
            continue
        try:
            path = Path(raw).resolve()
        except (OSError, ValueError):
            continue
        if not path.is_relative_to(_BACKEND_APPLICATION_ROOT):
            continue
        if path.is_relative_to(_BACKEND_SOURCE_ROOT) or not _is_source_file(path):
            continue
        inputs[path.relative_to(_BACKEND_APPLICATION_ROOT).as_posix()] = _file_digest(path)
    return inputs


def _inputs_sha256(inputs: dict[str, str]) -> str:
    """One stable digest over a label -> content-digest map."""
    rolling = hashlib.sha256()
    for label in sorted(inputs):
        rolling.update(label.encode("utf-8"))
        rolling.update(b"\0")
        rolling.update(inputs[label].encode("utf-8"))
        rolling.update(b"\0")
    return rolling.hexdigest()


# The snapshot of what this process is actually running, taken once at import —
# after every router/service import above, so `sys.modules` is already populated.
_BACKEND_STARTUP_INPUTS = {**_declared_backend_inputs(), **_loaded_cross_tree_inputs()}

# label -> digest of the bytes that were on disk when the module was imported.
# Written by `_ImportDigestRecorder` under `_LAZY_BASELINE_LOCK`; the lock also
# guards the read, because `/readyz` is a plain `def` and FastAPI therefore runs
# concurrent probes in the threadpool while imports may still be happening.
_LAZY_INPUT_BASELINE: dict[str, str] = {}
_LAZY_BASELINE_LOCK = threading.Lock()


class _ImportDigestRecorder:
    """Digest every install-root source file at the moment it is imported.

    `_BACKEND_STARTUP_INPUTS` is fixed at import time, so a cross-tree module
    imported LATER — the depth ledger reaching `assess.lib.vuln_taxonomy`
    through `taxonomy_bridge` is the real case — is in neither the startup map
    nor the declared set. Excluding it from the comparison is right exactly
    once: at first load it was read from the current disk state. It is wrong
    forever after, because the process then HOLDS those bytes while an install
    replaces the file, and a label in neither set is never compared again — the
    drift stays invisible for the life of the process.

    The honest baseline is the content the import actually read, and the only
    moment that content is knowable is the import itself. Reconstructing it
    afterwards cannot work: an mtime says when a file was last written, never
    what the reader got, and `vigil install` rewrites every managed file
    unconditionally, so a "rewritten since startup" rule would report a restart
    after every byte-identical install — the exact false positive this whole
    area exists to eliminate.

    So the recorder sits in ``sys.meta_path`` immediately ahead of
    ``PathFinder``, delegates the actual search to it, and digests the resolved
    origin on the way past. Builtin and frozen imports are still handled by the
    finders ahead of it, and nothing about import semantics changes: the spec
    returned is the one ``PathFinder`` produced.
    """

    @staticmethod
    def find_spec(fullname, path=None, target=None):  # type: ignore[no-untyped-def]
        spec = _ImportDigestRecorder._delegate(fullname, path, target)
        origin = getattr(spec, "origin", None)
        if not origin:
            return spec
        try:
            resolved = Path(origin).resolve()
        except (OSError, ValueError):
            return spec
        if not resolved.is_relative_to(_BACKEND_APPLICATION_ROOT) or not _is_source_file(resolved):
            return spec
        label = resolved.relative_to(_BACKEND_APPLICATION_ROOT).as_posix()
        with _LAZY_BASELINE_LOCK:
            if label in _LAZY_INPUT_BASELINE:
                return spec
            _LAZY_INPUT_BASELINE[label] = _file_digest(resolved)
        return spec

    @staticmethod
    def _delegate(fullname, path, target):  # type: ignore[no-untyped-def]
        """Hand the search to every finder that sits after this one.

        Calling ``PathFinder`` directly would be shorter, and wrong the moment
        anything installs a finder between the two — that finder would be
        skipped for every import, because this one always answers first. Walking
        the tail of ``sys.meta_path`` keeps the resolution order exactly what it
        would be if this recorder were not installed at all.
        """
        try:
            start = sys.meta_path.index(_ImportDigestRecorder) + 1
        except ValueError:  # pragma: no cover — removed from meta_path
            start = 0
        for finder in sys.meta_path[start:]:
            found = getattr(finder, "find_spec", None)
            if found is None:
                continue
            spec = found(fullname, path, target)
            if spec is not None:
                return spec
        return None


def _install_import_digest_recorder() -> None:
    """Put the recorder directly ahead of ``PathFinder``, once."""
    if any(finder is _ImportDigestRecorder for finder in sys.meta_path):
        return
    for index, finder in enumerate(sys.meta_path):
        if finder is PathFinder:
            sys.meta_path.insert(index, _ImportDigestRecorder)  # type: ignore[arg-type]
            return
    sys.meta_path.append(_ImportDigestRecorder)  # type: ignore[arg-type]


# Installed here, directly after the startup snapshot: everything imported so
# far is already in `_BACKEND_STARTUP_INPUTS`, and everything imported from now
# on is what the recorder exists to catch.
_install_import_digest_recorder()


def _lazy_input_baseline(loaded: dict[str, str]) -> dict[str, str]:
    """Import-time digests for the post-startup modules the recorder vouched for.

    These are the labels the comparison gains: each one is compared against the
    bytes its import actually read, so a later install that replaces the file
    registers as drift instead of disappearing into a set nothing compares.
    """
    with _LAZY_BASELINE_LOCK:
        recorded = dict(_LAZY_INPUT_BASELINE)
    return {
        label: recorded[label]
        for label in loaded
        if label not in _BACKEND_STARTUP_INPUTS and label in recorded
    }


def _unvouched_lazy_inputs(loaded: dict[str, str]) -> list[str]:
    """Post-startup modules the recorder never saw, reported but never gated on.

    A module reaches this list only by being imported through a loader that
    bypasses ``PathFinder`` — pytest's assertion rewriter is the one that
    actually occurs, and a deployed backend has none. Nothing on disk can say
    what such a loader read, so the label is surfaced for an operator rather
    than counted as drift: manufacturing `restart_required` from a condition
    that cannot arise in production would resurrect exactly the always-wrong
    notice this whole area exists to remove.
    """
    with _LAZY_BASELINE_LOCK:
        recorded = frozenset(_LAZY_INPUT_BASELINE)
    return sorted(
        label
        for label in loaded
        if label not in _BACKEND_STARTUP_INPUTS and label not in recorded
    )


def _aligned_backend_inputs(
    startup: dict[str, str], current: dict[str, str], declared: frozenset[str]
) -> tuple[dict[str, str], dict[str, str]]:
    """The startup and current input maps over one comparable set of labels.

    Pure alignment: the comparable set is `startup ∪ declared`, and the caller
    decides what `startup` contains. `_backend_runtime_snapshot` passes the
    process-start snapshot MERGED with `_lazy_input_baseline`, so a cross-tree
    module imported after startup — the depth ledger reaching
    `assess.lib.vuln_taxonomy` through `taxonomy_bridge` is the real case — is
    in the set and is compared against the bytes its import actually read. It
    used to be in neither set, which read as "current by construction" and was
    true only until the next install replaced the file underneath the running
    process.

    Everything that IS in the set is compared both ways, so a DELETED module the
    process still holds, and a NEW file under `app/` the process has not got,
    both register — each as `<absent>` on one side.
    """
    labels = startup.keys() | declared
    return (
        {label: startup.get(label, _ABSENT) for label in labels},
        {label: current.get(label, _ABSENT) for label in labels},
    )


_FRONTEND_MISSING_HELP = (
    "Frontend build not found at "
    f"{settings.frontend_dist_dir}. The backend was started without first "
    "building the frontend (likely a direct `uv run uvicorn ...` instead of "
    "`vigil up` or `vigil orchestrator start`). Run `vigil orchestrator build` "
    "to build the install-side frontend in place, then refresh."
)


def _backend_runtime_snapshot() -> dict[str, object]:
    """Does the code on disk still match the code this process is running?

    Content, never mtime. `vigil install` rewrites every managed file
    unconditionally (no content comparison anywhere in its copy path), so every
    install bumped the mtime of every backend `.py` and the previous
    high-water mark answered `restart_required: true` with twenty files listed
    for a byte-identical backend. An operator who is told to restart after every
    install stops reading the field, which costs exactly the one install that
    needed it.

    Both digests are published so the answer is auditable from outside without
    a second implementation of the input set having to agree with this one.
    """
    declared = _declared_backend_inputs()
    loaded = _loaded_cross_tree_inputs()
    startup, current = _aligned_backend_inputs(
        {**_BACKEND_STARTUP_INPUTS, **_lazy_input_baseline(loaded)},
        {**declared, **loaded},
        frozenset(declared),
    )
    changed = sorted(label for label in startup if startup[label] != current[label])
    # Named apart from the rest because the claim is different: these are not
    # known to have changed, they are known not to be provable either way.
    unestablished = _unvouched_lazy_inputs(loaded)
    return {
        "source_root": str(_BACKEND_SOURCE_ROOT),
        "install_root": str(_BACKEND_INSTALL_ROOT),
        "application_root": str(_BACKEND_APPLICATION_ROOT),
        "process_started_at": datetime.fromtimestamp(
            _BACKEND_PROCESS_STARTED_AT,
            tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "startup_inputs_sha256": _inputs_sha256(startup),
        "current_inputs_sha256": _inputs_sha256(current),
        "restart_required": bool(changed),
        "changed_inputs": changed[:20],
        "changed_input_count": len(changed),
        "unestablished_inputs": unestablished[:20],
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
app.include_router(remediation_router)
app.include_router(credentials_router)
app.include_router(events_router)
app.include_router(artifacts_router)
app.include_router(submissions_router)
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
    if not websocket_origin_allowed(
        websocket.headers.get("origin"), settings.orchestrator_public_url
    ):
        await websocket.close(code=1008, reason="untrusted websocket origin")
        return
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

    def registered_routes(routes):
        for route in routes:
            nested_router = getattr(route, "original_router", None)
            if nested_router is not None:
                yield from registered_routes(nested_router.routes)
            else:
                yield route

    segments: set[str] = set()
    for route in registered_routes(app.routes):
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

    frontend_root = settings.frontend_dist_dir.resolve()
    requested_path = (frontend_root / full_path).resolve()
    if full_path and requested_path.is_relative_to(frontend_root) and requested_path.is_file():
        return FileResponse(requested_path)

    index_path = frontend_root / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    return JSONResponse(
        status_code=503,
        content={"detail": _FRONTEND_MISSING_HELP, "fix": "vigil orchestrator build"},
    )
