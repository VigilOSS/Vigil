from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field

from ..services import code_analysis
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(
    prefix="/engagements/{engagement_key}/assessment/code",
    tags=["code-analysis"],
)


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class CodeRepoCreateRequest(BaseModel):
    repo_key: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    language: str = Field(default="", max_length=64)
    repo_path: str = Field(min_length=1, max_length=4096)
    total_files: int = Field(default=0, ge=0)
    analyzable_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)
    commit_hash: str = Field(default="", max_length=64)
    branch: str = Field(default="", max_length=256)
    git_churn: dict[str, Any] = Field(default_factory=dict)


class CodeFileRecord(BaseModel):
    file_path: str = Field(min_length=1, max_length=4096)
    language: str = Field(default="", max_length=64)
    loc: int = Field(default=0, ge=0)
    file_hash: str = Field(default="", max_length=128)
    header_snippet: str = Field(default="", max_length=8192)
    git_churn_score: int = Field(default=0, ge=0)
    has_past_cve_fix: bool = False


class CodeFilesBulkCreateRequest(BaseModel):
    repo_id: int
    files: list[CodeFileRecord]


class CodeFileClassification(BaseModel):
    file_id: int
    classification: str = Field(min_length=1, max_length=32)  # critical/high/medium/low/skip
    role: str = Field(default="", max_length=128)
    slot_types: list[str] = Field(default_factory=list)
    analysis_priority: int = Field(default=50, ge=0, le=100)


class CodeFilesBulkClassifyRequest(BaseModel):
    classifications: list[CodeFileClassification]


class CodeModuleRecord(BaseModel):
    module_key: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=4096)
    trust_boundary: str = Field(default="", max_length=1024)
    files: list[str] = Field(default_factory=list)
    file_ids: list[int] = Field(default_factory=list)


class CodeModulesBulkCreateRequest(BaseModel):
    repo_id: int
    modules: list[CodeModuleRecord]


class CodeContextRecord(BaseModel):
    file_id: int
    function_name: str = Field(min_length=1, max_length=512)
    start_line: int = Field(default=0, ge=0)
    end_line: int = Field(default=0, ge=0)
    slot_types: list[str] = Field(default_factory=list)
    call_chain: dict[str, Any] = Field(default_factory=dict)
    data_flow: dict[str, Any] = Field(default_factory=dict)
    cross_refs: list[dict[str, Any]] = Field(default_factory=list)
    guard_annotations: list[dict[str, Any]] = Field(default_factory=list)
    sink_annotations: list[dict[str, Any]] = Field(default_factory=list)
    context_text: str = Field(default="", max_length=100000)


class CodeContextsBulkCreateRequest(BaseModel):
    contexts: list[CodeContextRecord]


class QueueItemRecord(BaseModel):
    context_id: int
    file_id: int
    priority: int = Field(default=50, ge=0, le=100)


class QueueItemsBulkCreateRequest(BaseModel):
    items: list[QueueItemRecord]


class QueueFetchRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=100)
    agent_name: str = Field(min_length=1, max_length=128)


class QueueCompleteRequest(BaseModel):
    item_ids: list[int]
    disposition: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=20000)


class QueueErrorRequest(BaseModel):
    item_ids: list[int]
    notes: str = Field(default="", max_length=20000)


class QueueNeedsContextRequest(BaseModel):
    item_ids: list[int]
    expansion_request: dict[str, Any] = Field(default_factory=dict)


class QueueResetStaleRequest(BaseModel):
    minutes: int = Field(default=10, ge=1, le=1440)


class AnalysisResultRecord(BaseModel):
    queue_item_id: int
    context_id: int | None = None
    file_id: int
    agent_name: str = Field(default="", max_length=128)
    function_name: str = Field(default="", max_length=512)
    hypothesis: str = Field(default="", max_length=20000)
    evidence: str = Field(default="", max_length=20000)
    disposition: str = Field(min_length=1, max_length=64)
    confidence: str = Field(default="medium", max_length=32)
    finding_slug: str = Field(default="", max_length=256)
    cwe_id: str = Field(default="", max_length=32)
    slot_type: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=20000)


class ThreatModelRecordRequest(BaseModel):
    repo_id: int
    threat_model: dict[str, Any]


# ---------------------------------------------------------------------------
# Broadcast helper
# ---------------------------------------------------------------------------

async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "code_analysis.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


# ---------------------------------------------------------------------------
# Repository endpoints
# ---------------------------------------------------------------------------

@router.post("/repos", status_code=status.HTTP_201_CREATED)
async def create_repo(engagement_key: str, request: CodeRepoCreateRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.create_code_repo(engagement.id, **request.model_dump())
    await _broadcast(engagement.key, "repo", record)
    return record


@router.get("/repos")
def list_repos(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_repos(engagement.id)


@router.get("/repos/{repo_id}")
def get_repo(engagement_key: str, repo_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_code_repo(engagement.id, repo_id)


# ---------------------------------------------------------------------------
# File endpoints
# ---------------------------------------------------------------------------

@router.post("/files", status_code=status.HTTP_201_CREATED)
async def bulk_create_files(engagement_key: str, request: CodeFilesBulkCreateRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.bulk_create_code_files(
        engagement.id,
        repo_id=request.repo_id,
        files=[f.model_dump() for f in request.files],
    )
    await _broadcast(engagement.key, "files", record)
    return record


@router.get("/files")
def list_files(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
    module_id: int | None = Query(default=None),
    classification: str | None = Query(default=None),
    analysis_status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_files(
        engagement.id,
        repo_id=repo_id,
        module_id=module_id,
        classification=classification,
        analysis_status=analysis_status,
        limit=limit,
    )


@router.get("/files/{file_id}")
def get_file(engagement_key: str, file_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_code_file(engagement.id, file_id)


@router.post("/files/bulk-classify")
async def bulk_classify_files(engagement_key: str, request: CodeFilesBulkClassifyRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.bulk_classify_code_files(
        engagement.id,
        classifications=[c.model_dump() for c in request.classifications],
    )
    await _broadcast(engagement.key, "file_classification", record)
    return record


@router.patch("/files/{file_id}")
async def update_file(engagement_key: str, file_id: int, request: dict[str, Any]) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.update_code_file(engagement.id, file_id, **request)
    await _broadcast(engagement.key, "file", record)
    return record


# ---------------------------------------------------------------------------
# Module endpoints
# ---------------------------------------------------------------------------

@router.post("/modules", status_code=status.HTTP_201_CREATED)
async def bulk_create_modules(engagement_key: str, request: CodeModulesBulkCreateRequest) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    records = code_analysis.bulk_create_code_modules(
        engagement.id,
        repo_id=request.repo_id,
        modules=[m.model_dump() for m in request.modules],
    )
    await _broadcast(engagement.key, "modules", {"count": len(records)})
    return records


@router.get("/modules")
def list_modules(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_modules(engagement.id, repo_id=repo_id)


# ---------------------------------------------------------------------------
# Context endpoints
# ---------------------------------------------------------------------------

@router.post("/contexts", status_code=status.HTTP_201_CREATED)
async def bulk_create_contexts(engagement_key: str, request: CodeContextsBulkCreateRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.bulk_create_code_contexts(
        engagement.id,
        contexts=[c.model_dump() for c in request.contexts],
    )
    await _broadcast(engagement.key, "contexts", record)
    return record


@router.get("/contexts")
def list_contexts(
    engagement_key: str,
    file_id: int | None = Query(default=None),
    analysis_status: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_contexts(
        engagement.id,
        file_id=file_id,
        analysis_status=analysis_status,
    )


@router.patch("/contexts/{context_id}")
async def update_context(engagement_key: str, context_id: int, request: dict[str, Any]) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.update_code_context(engagement.id, context_id, **request)
    await _broadcast(engagement.key, "context", record)
    return record


# ---------------------------------------------------------------------------
# Analysis queue endpoints
# ---------------------------------------------------------------------------

@router.post("/analysis-queue", status_code=status.HTTP_201_CREATED)
async def bulk_create_queue_items(engagement_key: str, request: QueueItemsBulkCreateRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.bulk_create_queue_items(
        engagement.id,
        items=[i.model_dump() for i in request.items],
    )
    await _broadcast(engagement.key, "analysis_queue", record)
    return record


@router.get("/analysis-queue/stats")
def get_queue_stats(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.queue_stats(engagement.id)


@router.post("/analysis-queue/fetch")
async def fetch_queue_items(engagement_key: str, request: QueueFetchRequest) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    records = code_analysis.fetch_queue_items(
        engagement.id,
        limit=request.limit,
        agent_name=request.agent_name,
    )
    await _broadcast(engagement.key, "queue_fetch", {"count": len(records)})
    return records


@router.post("/analysis-queue/done")
async def complete_queue_items(engagement_key: str, request: QueueCompleteRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.complete_queue_items(
        engagement.id,
        item_ids=request.item_ids,
        disposition=request.disposition,
        notes=request.notes,
    )
    await _broadcast(engagement.key, "queue_done", record)
    return record


@router.post("/analysis-queue/error")
async def error_queue_items(engagement_key: str, request: QueueErrorRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.error_queue_items(
        engagement.id,
        item_ids=request.item_ids,
        notes=request.notes,
    )
    await _broadcast(engagement.key, "queue_error", record)
    return record


@router.post("/analysis-queue/needs-context")
async def needs_context_queue_items(engagement_key: str, request: QueueNeedsContextRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.needs_context_queue_items(
        engagement.id,
        item_ids=request.item_ids,
        expansion_request=request.expansion_request,
    )
    await _broadcast(engagement.key, "queue_needs_context", record)
    return record


@router.post("/analysis-queue/reset-stale")
async def reset_stale_queue_items(engagement_key: str, request: QueueResetStaleRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.reset_stale_queue_items(
        engagement.id,
        minutes=request.minutes,
    )
    await _broadcast(engagement.key, "queue_reset_stale", record)
    return record


# ---------------------------------------------------------------------------
# Analysis results endpoints
# ---------------------------------------------------------------------------

@router.post("/analysis-results", status_code=status.HTTP_201_CREATED)
async def create_analysis_result(engagement_key: str, request: AnalysisResultRecord) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.create_analysis_result(engagement.id, request.model_dump())
    await _broadcast(engagement.key, "analysis_result", record)
    return record


@router.get("/analysis-results")
def list_analysis_results(
    engagement_key: str,
    file_id: int | None = Query(default=None),
    disposition: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_analysis_results(
        engagement.id,
        file_id=file_id,
        disposition=disposition,
    )


# ---------------------------------------------------------------------------
# Threat model endpoints
# ---------------------------------------------------------------------------

@router.post("/threat-model")
async def create_threat_model(engagement_key: str, request: ThreatModelRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.record_threat_model(
        engagement.id,
        repo_id=request.repo_id,
        threat_model=request.threat_model,
    )
    await _broadcast(engagement.key, "threat_model", record)
    return record


@router.get("/threat-model/{repo_id}")
def get_threat_model(engagement_key: str, repo_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_threat_model(engagement.id, repo_id)


# ---------------------------------------------------------------------------
# Coverage endpoint
# ---------------------------------------------------------------------------

@router.get("/coverage")
def get_coverage(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.code_coverage_summary(engagement.id, repo_id=repo_id)
