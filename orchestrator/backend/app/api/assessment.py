from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from ..security import CurrentUser
from ..services.assessment import (
    assessment_summary,
    list_surfaces,
    record_coverage_item,
    record_probe_run,
    record_request_variant,
    record_service,
    record_surface,
    record_target,
)
from ..ws import broadcaster

router = APIRouter(prefix="/projects/{project_id}/runs/{run_id}/assessment", tags=["assessment"])


class TargetRecordRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=256)
    kind: str = Field(default="host", min_length=1, max_length=64)
    host: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=256)
    notes: str = Field(default="", max_length=4096)
    discovered_by: str = Field(default="", max_length=128)


class ServiceRecordRequest(BaseModel):
    endpoint: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="tcp", min_length=1, max_length=32)
    port: int | None = None
    service: str = Field(default="", max_length=128)
    state: str = Field(default="discovered", min_length=1, max_length=64)
    coverage_status: str = Field(default="pending", min_length=1, max_length=64)
    banner: str = Field(default="", max_length=4096)
    notes: str = Field(default="", max_length=4096)
    discovered_by: str = Field(default="", max_length=128)
    target_identity: str | None = Field(default=None, max_length=256)


class RequestVariantRecordRequest(BaseModel):
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


class CoverageItemRecordRequest(BaseModel):
    request_variant_id: int | None = None
    service_id: int | None = None
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    input_slot: str = Field(min_length=1, max_length=64)
    attack_family: str = Field(min_length=1, max_length=64)
    status: str = Field(default="pending", min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)


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


async def _broadcast(project_id: int, run_id: int, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        project_id,
        run_id,
        {
            "type": "assessment.updated",
            "project_id": project_id,
            "run_id": run_id,
            "record_type": record_type,
            "payload": payload,
        },
    )


@router.get("/summary")
def get_assessment_summary(project_id: int, run_id: int, current_user: CurrentUser) -> dict[str, Any]:
    return assessment_summary(project_id, run_id, current_user)


@router.get("/surfaces")
def get_surfaces(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return list_surfaces(project_id, run_id, current_user)


@router.post("/targets", status_code=status.HTTP_201_CREATED)
async def create_target(project_id: int, run_id: int, request: TargetRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = record_target(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "target", record)
    return record


@router.post("/services", status_code=status.HTTP_201_CREATED)
async def create_service(project_id: int, run_id: int, request: ServiceRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = record_service(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "service", record)
    return record


@router.post("/request-variants", status_code=status.HTTP_201_CREATED)
async def create_request_variant(
    project_id: int,
    run_id: int,
    request: RequestVariantRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = record_request_variant(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "request_variant", record)
    return record


@router.post("/coverage-items", status_code=status.HTTP_201_CREATED)
async def create_coverage_item(
    project_id: int,
    run_id: int,
    request: CoverageItemRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = record_coverage_item(
        project_id,
        run_id,
        current_user,
        request_variant_id=request.request_variant_id,
        service_id=request.service_id,
        auth_context=request.auth_context,
        input_slot=request.input_slot,
        attack_family=request.attack_family,
        status_value=request.status,
        notes=request.notes,
    )
    await _broadcast(project_id, run_id, "coverage_item", record)
    return record


@router.post("/probe-runs", status_code=status.HTTP_201_CREATED)
async def create_probe_run(
    project_id: int,
    run_id: int,
    request: ProbeRunRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = record_probe_run(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "probe_run", record)
    return record


@router.post("/surfaces", status_code=status.HTTP_201_CREATED)
async def create_surface(project_id: int, run_id: int, request: SurfaceRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = record_surface(
        project_id,
        run_id,
        current_user,
        surface_type=request.surface_type,
        target_descriptor=request.target_descriptor,
        source_name=request.source_name,
        rationale=request.rationale,
        evidence_ref=request.evidence_ref,
        status_value=request.status,
    )
    await _broadcast(project_id, run_id, "surface", record)
    return record
