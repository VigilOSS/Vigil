from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from ..services import state_manager
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(prefix="/engagements/{engagement_key}/assessment", tags=["assessment"])


class RequestObservationIngestRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    method: str = Field(default="GET", min_length=1, max_length=16)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    content_type_family: str = Field(default="unknown", min_length=1, max_length=64)
    query_schema: dict[str, Any] = Field(default_factory=dict)
    body_schema: dict[str, Any] = Field(default_factory=dict)
    path_schema: dict[str, Any] = Field(default_factory=dict)
    cookie_schema: dict[str, Any] = Field(default_factory=dict)
    header_schema: dict[str, Any] = Field(default_factory=dict)
    path_template: str = Field(default="", max_length=1024)
    discovery_source: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    response_status: int | None = None
    evidence_ref: str = Field(default="", max_length=1024)
    observation_payload: dict[str, Any] = Field(default_factory=dict)
    target_identity: str | None = Field(default=None, max_length=256)
    target_kind: str = Field(default="host", min_length=1, max_length=64)
    target_notes: str = Field(default="", max_length=4096)
    target_ip_address: str | None = Field(default=None, max_length=64)
    target_hostname: str | None = Field(default=None, max_length=256)
    banner: str = Field(default="", max_length=4096)
    coverage_candidates: list[dict[str, Any]] = Field(default_factory=list)
    auto_generate_coverage: bool = True


class ProbeRunRecordRequest(BaseModel):
    request_variant_id: int | None = None
    service_id: int | None = None
    coverage_item_id: int | None = None
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    input_slot: str = Field(default="unknown", min_length=1, max_length=64)
    attack_family: str = Field(min_length=1, max_length=64)
    payload_family: str = Field(default="", max_length=128)
    payload_value: str = Field(default="", max_length=16384)
    tool_name: str = Field(min_length=1, max_length=128)
    agent_name: str = Field(default="", max_length=128)
    result_status: str = Field(default="tested", min_length=1, max_length=64)
    observed_http_status: int | None = None
    signal_type: str = Field(default="", max_length=128)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)


class SurfaceRecordRequest(BaseModel):
    surface_type: str = Field(min_length=1, max_length=128)
    target_descriptor: str = Field(min_length=1, max_length=1024)
    source_name: str = Field(default="", max_length=128)
    rationale: str = Field(default="", max_length=4096)
    evidence_ref: str = Field(default="", max_length=1024)
    status: str = Field(default="discovered", min_length=1, max_length=64)


class FindingLinkRequest(BaseModel):
    link_kind: str = Field(default="related", min_length=1, max_length=64)
    target_kind: str = Field(min_length=1, max_length=64)
    target_id: int | None = None
    target_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class FindingRecordRequest(BaseModel):
    slug: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    severity: str = Field(default="info", min_length=1, max_length=32)
    status: str = Field(default="draft", min_length=1, max_length=32)
    defect_family: str = Field(default="", max_length=128)
    root_cause_key: str = Field(default="", max_length=256)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    canonical_location: str = Field(default="", max_length=1024)
    summary: str = Field(default="", max_length=4096)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=20000)
    source_name: str = Field(default="", max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    request_variant_id: int | None = None
    service_id: int | None = None
    surface_id: int | None = None
    links: list[FindingLinkRequest] = Field(default_factory=list)


async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "assessment.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


@router.get("/summary")
def get_assessment_summary(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.assessment_summary(engagement.id)


@router.get("/targets")
def get_targets(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_targets(engagement.id)


@router.get("/services")
def get_services(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_services(engagement.id)


@router.get("/request-variants")
def get_request_variants(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_request_variants(engagement.id)


@router.get("/request-observations")
def get_request_observations(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_request_observations(engagement.id)


@router.get("/coverage-items")
def get_coverage_items(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_coverage_items(engagement.id)


@router.get("/probe-runs")
def get_probe_runs(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_probe_runs(engagement.id)


@router.get("/surfaces")
def get_surfaces(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surfaces(engagement.id)


@router.get("/findings")
def get_findings(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_findings(engagement.id)


@router.get("/finding-links")
def get_finding_links(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_links(engagement.id)


@router.get("/attack-chains")
def get_attack_chains(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_attack_chains(engagement.id)


@router.get("/attack-chain-links")
def get_attack_chain_links(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_attack_chain_links(engagement.id)


@router.post("/request-observations", status_code=status.HTTP_201_CREATED)
async def create_request_observation(engagement_key: str, request: RequestObservationIngestRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.ingest_request_observation(engagement.id, **request.model_dump())
    await _broadcast(engagement.key, "request_observation", record)
    return record


@router.post("/probe-runs", status_code=status.HTTP_201_CREATED)
async def create_probe_run(engagement_key: str, request: ProbeRunRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_probe_run(engagement.id, **request.model_dump())
    await _broadcast(engagement.key, "probe_run", record)
    return record


@router.post("/surfaces", status_code=status.HTTP_201_CREATED)
async def create_surface(engagement_key: str, request: SurfaceRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_surface(
        engagement.id,
        surface_type=request.surface_type,
        target_descriptor=request.target_descriptor,
        source_name=request.source_name,
        rationale=request.rationale,
        evidence_ref=request.evidence_ref,
        status_value=request.status,
    )
    await _broadcast(engagement.key, "surface", record)
    return record


@router.post("/findings", status_code=status.HTTP_201_CREATED)
async def create_finding(engagement_key: str, request: FindingRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.create_finding(
        engagement.id,
        slug=request.slug,
        title=request.title,
        severity=request.severity,
        status_value=request.status,
        defect_family=request.defect_family,
        root_cause_key=request.root_cause_key,
        auth_context=request.auth_context,
        canonical_location=request.canonical_location,
        summary=request.summary,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        source_name=request.source_name,
        details=request.details,
        provenance=request.provenance,
        request_variant_id=request.request_variant_id,
        service_id=request.service_id,
        surface_id=request.surface_id,
        links=[item.model_dump() for item in request.links],
    )
    await _broadcast(engagement.key, "finding", record)
    return record
