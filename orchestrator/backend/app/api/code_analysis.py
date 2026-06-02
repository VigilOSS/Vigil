from __future__ import annotations

from typing import Any, Literal, TypeAlias

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..services import activity as activity_service
from ..services import code_analysis
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(
    prefix="/engagements/{engagement_key}/assessment/code",
    tags=["code-analysis"],
)


CodeSlotType: TypeAlias = Literal[
    "NETWORK-INPUT",
    "URL-COMPONENT",
    "CMD-ARGUMENT",
    "FILE-CONTENT",
    "ENV-VARIABLE",
    "CALLBACK-DATA",
    "PROTOCOL-FIELD",
    "SERIALIZED-DATA",
]


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
    model_config = ConfigDict(extra="forbid")

    file_id: int
    classification: str = Field(min_length=1, max_length=32)  # critical/high/medium/low/skip
    role: str = Field(default="", max_length=128)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    language: str | None = Field(default=None, max_length=64)
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


class QueueItemRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: int
    priority: int = Field(default=50, ge=0, le=100)
    batch_theme: str = Field(default="", max_length=256)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    guidance_hypotheses: list[str] = Field(default_factory=list)


class QueueItemsBulkCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[QueueItemRecord]


class QueueFetchRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=100)
    agent_name: str = Field(min_length=1, max_length=128)


class QueueCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item_ids: list[int] = Field(min_length=1, max_length=1)
    disposition: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=20000)
    cwe_coverage: list[dict[str, Any]] = Field(default_factory=list)
    # C50: structured reason when disposition='skipped'. Required at the
    # service layer when skipping; ignored for other dispositions.
    skip_reason: str = Field(default="", max_length=512)


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
    file_id: int | None = None
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
    audit_metadata: dict[str, Any] = Field(default_factory=dict)
    cwe_coverage: list[dict[str, Any]] = Field(default_factory=list)
    cross_file_triggers: list[dict[str, Any]] = Field(default_factory=list)


class RequeueItemRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: Any | None = None
    file_path: str = Field(default="", max_length=4096)
    repo_id: Any | None = None
    priority: int = Field(default=50, ge=0, le=100)
    batch_theme: str = Field(default="", max_length=256)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    guidance_hypotheses: list[str] = Field(default_factory=list)
    reason: str = Field(default="", max_length=20000)
    trigger_context: dict[str, Any] = Field(default_factory=dict)


class RequeueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RequeueItemRecord]


TriggerResolutionStatus: TypeAlias = Literal[
    "external_context_unavailable",
    "source_equivalent_analyzed",
    "not_applicable",
]


class TriggerResolutionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_id: int | None = None
    id: int | None = None
    file_path: str = Field(default="", max_length=4096)
    target_file_path: str = Field(default="", max_length=4096)
    repo_id: int | None = None
    vuln_class: str = Field(default="", max_length=128)


class TriggerResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TriggerResolutionItem] = Field(min_length=1)
    resolution_status: TriggerResolutionStatus
    resolution_note: str = Field(min_length=1, max_length=20000)


class StructuralMetadataItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: int
    total_functions: int = Field(ge=0)
    total_entry_points: int = Field(ge=0)
    total_sinks: int = Field(ge=0)
    total_exports: int = Field(ge=0)


class BulkStructuralMetadataRequest(BaseModel):
    updates: list[StructuralMetadataItem]


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


def _audit_code_mutation(
    engagement_id: int,
    *,
    title: str,
    action: str,
    actor_name: str = "vigil-assess",
    result: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        activity_service.record_activity_entry(
            engagement_id,
            actor_kind="system",
            actor_name=actor_name or "vigil-assess",
            title=title,
            action=action,
            result=result,
            metadata=metadata or {},
        )
    except Exception:
        return


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


@router.patch("/repos/{repo_id}")
async def update_repo(engagement_key: str, repo_id: int, request: dict[str, Any]) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.update_code_repo(engagement.id, repo_id, **request)
    await _broadcast(engagement.key, "repo", record)
    return record


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
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_files(
        engagement.id,
        repo_id=repo_id,
        module_id=module_id,
        classification=classification,
        analysis_status=analysis_status,
        search=search,
        limit=limit,
        offset=offset,
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


@router.post("/files/bulk-structural-metadata")
async def bulk_structural_metadata(
    engagement_key: str,
    request: BulkStructuralMetadataRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.bulk_update_structural_metadata(
        engagement.id,
        updates=[u.model_dump() for u in request.updates],
    )
    await _broadcast(engagement.key, "structural_metadata", record)
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
        cwe_coverage=request.cwe_coverage,
        skip_reason=request.skip_reason,
    )
    _audit_code_mutation(
        engagement.id,
        title="code-dispatch done",
        action=f"item_ids={request.item_ids} disposition={request.disposition}",
        result=request.notes,
        metadata={"item_ids": request.item_ids, "disposition": request.disposition},
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


@router.post("/analysis-queue/requeue", status_code=status.HTTP_201_CREATED)
async def requeue_triggered_files(engagement_key: str, request: RequeueRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.requeue_triggered_files(
        engagement.id,
        items=[item.model_dump() for item in request.items],
    )
    _audit_code_mutation(
        engagement.id,
        title="code-dispatch requeue-triggers",
        action=f"count={len(request.items)}",
        metadata={"count": len(request.items)},
    )
    await _broadcast(engagement.key, "queue_requeue", record)
    return record


@router.get("/triggers")
def list_code_triggers(
    engagement_key: str,
    status_filter: str | None = Query(default=None, alias="status"),
    repo_id: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_triggers(
        engagement.id,
        status_filter=status_filter,
        repo_id=repo_id,
    )


@router.post("/triggers/resolve")
async def resolve_code_triggers(engagement_key: str, request: TriggerResolveRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.resolve_code_triggers(
        engagement.id,
        items=[item.model_dump() for item in request.items],
        resolution_status=request.resolution_status,
        resolution_note=request.resolution_note,
    )
    _audit_code_mutation(
        engagement.id,
        title="code-dispatch resolve-triggers",
        action=f"status={request.resolution_status} count={len(request.items)}",
        result=request.resolution_note,
        metadata={"count": len(request.items), "resolution_status": request.resolution_status},
    )
    await _broadcast(engagement.key, "triggers_resolve", record)
    return record


# ---------------------------------------------------------------------------
# Analysis results endpoints
# ---------------------------------------------------------------------------

@router.post("/analysis-results", status_code=status.HTTP_201_CREATED)
async def create_analysis_result(engagement_key: str, request: AnalysisResultRecord) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = code_analysis.create_analysis_result(engagement.id, request.model_dump())
    _audit_code_mutation(
        engagement.id,
        title="code-record-analysis",
        action=f"file_id={record['file_id']} function={request.function_name or '(file)'}",
        actor_name=request.agent_name,
        result=request.disposition,
        metadata={
            "file_id": record["file_id"],
            "queue_item_id": request.queue_item_id,
            "finding_slug": request.finding_slug,
            "disposition": request.disposition,
        },
    )
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
    detail: str | None = Query(default=None),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    if detail == "cwe":
        return code_analysis.code_coverage_cwe_detail(engagement.id, repo_id=repo_id)
    return code_analysis.code_coverage_summary(engagement.id, repo_id=repo_id)
