from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from ..security import CurrentUser
from ..services.assessment import assessment_summary
from ..services import state_manager
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


class RequestObservationIngestRequest(RequestVariantRecordRequest):
    target_identity: str | None = Field(default=None, max_length=256)
    target_kind: str = Field(default="host", min_length=1, max_length=64)
    target_notes: str = Field(default="", max_length=4096)
    target_ip_address: str | None = Field(default=None, max_length=64)
    target_hostname: str | None = Field(default=None, max_length=256)
    banner: str = Field(default="", max_length=4096)
    coverage_candidates: list[dict[str, Any]] = Field(default_factory=list)
    auto_generate_coverage: bool = True


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


class FindingMergeRequest(BaseModel):
    source_slug: str = Field(min_length=1, max_length=256)
    target_slug: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="", max_length=4096)
    source_name: str = Field(default="", max_length=128)


class AttackChainLinkRequest(BaseModel):
    relation: str = Field(default="step", min_length=1, max_length=64)
    entity_kind: str = Field(min_length=1, max_length=64)
    entity_id: int | None = None
    entity_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class AttackChainRecordRequest(BaseModel):
    chain_key: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    status: str = Field(default="draft", min_length=1, max_length=64)
    severity: str = Field(default="info", min_length=1, max_length=32)
    narrative: str = Field(default="", max_length=12000)
    evidence_ref: str = Field(default="", max_length=1024)
    provenance: dict[str, Any] = Field(default_factory=dict)
    links: list[AttackChainLinkRequest] = Field(default_factory=list)


class CredentialRecordRequest(BaseModel):
    credential_key: str = Field(min_length=1, max_length=256)
    kind: str = Field(default="password", min_length=1, max_length=64)
    principal: str = Field(default="", max_length=256)
    secret_locator: str = Field(default="", max_length=1024)
    source_name: str = Field(default="", max_length=128)
    status: str = Field(default="discovered", min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CredentialTestRecordRequest(BaseModel):
    credential_id: int
    service_id: int | None = None
    target_ref: str = Field(default="", max_length=1024)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    outcome: str = Field(default="untested", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)


class AccessRecordRequest(BaseModel):
    access_key: str = Field(min_length=1, max_length=256)
    credential_id: int | None = None
    service_id: int | None = None
    principal: str = Field(default="", max_length=256)
    access_level: str = Field(default="", max_length=128)
    target_ref: str = Field(default="", max_length=1024)
    status: str = Field(default="active", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class PivotRecordRequest(BaseModel):
    pivot_key: str = Field(min_length=1, max_length=256)
    access_record_id: int | None = None
    source_ref: str = Field(default="", max_length=1024)
    destination_ref: str = Field(default="", max_length=1024)
    technique: str = Field(default="", max_length=256)
    status: str = Field(default="draft", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class TunnelRecordRequest(BaseModel):
    tunnel_key: str = Field(min_length=1, max_length=256)
    pivot_id: int | None = None
    tunnel_type: str = Field(default="", max_length=128)
    source_endpoint: str = Field(default="", max_length=1024)
    destination_endpoint: str = Field(default="", max_length=1024)
    status: str = Field(default="draft", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class BlockedTechniqueRecordRequest(BaseModel):
    technique_key: str = Field(min_length=1, max_length=256)
    technique: str = Field(min_length=1, max_length=256)
    target_kind: str = Field(default="", max_length=128)
    target_ref: str = Field(default="", max_length=1024)
    reason: str = Field(default="", max_length=4096)
    retry_state: str = Field(default="pending", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


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


@router.get("/targets")
def get_targets(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_targets(project_id, run_id, current_user)


@router.get("/services")
def get_services(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_services(project_id, run_id, current_user)


@router.get("/request-variants")
def get_request_variants(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_request_variants(project_id, run_id, current_user)


@router.get("/request-observations")
def get_request_observations(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_request_observations(project_id, run_id, current_user)


@router.get("/coverage-items")
def get_coverage_items(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_coverage_items(project_id, run_id, current_user)


@router.get("/probe-runs")
def get_probe_runs(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_probe_runs(project_id, run_id, current_user)


@router.get("/surfaces")
def get_surfaces(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_surfaces(project_id, run_id, current_user)


@router.get("/findings")
def get_findings(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_findings(project_id, run_id, current_user)


@router.get("/finding-links")
def get_finding_links(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_finding_links(project_id, run_id, current_user)


@router.get("/attack-chains")
def get_attack_chains(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_attack_chains(project_id, run_id, current_user)


@router.get("/attack-chain-links")
def get_attack_chain_links(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_attack_chain_links(project_id, run_id, current_user)


@router.get("/credentials")
def get_credentials(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_credentials(project_id, run_id, current_user)


@router.get("/credential-tests")
def get_credential_tests(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_credential_tests(project_id, run_id, current_user)


@router.get("/access-records")
def get_access_records(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_access_records(project_id, run_id, current_user)


@router.get("/pivots")
def get_pivots(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_pivots(project_id, run_id, current_user)


@router.get("/tunnels")
def get_tunnels(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_tunnels(project_id, run_id, current_user)


@router.get("/blocked-techniques")
def get_blocked_techniques(project_id: int, run_id: int, current_user: CurrentUser) -> list[dict[str, Any]]:
    return state_manager.list_blocked_techniques(project_id, run_id, current_user)


@router.post("/targets", status_code=status.HTTP_201_CREATED)
async def create_target(project_id: int, run_id: int, request: TargetRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_target(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "target", record)
    return record


@router.post("/services", status_code=status.HTTP_201_CREATED)
async def create_service(project_id: int, run_id: int, request: ServiceRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_service(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "service", record)
    return record


@router.post("/request-variants", status_code=status.HTTP_201_CREATED)
async def create_request_variant(
    project_id: int,
    run_id: int,
    request: RequestVariantRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.record_request_variant(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "request_variant", record)
    return record


@router.post("/request-observations", status_code=status.HTTP_201_CREATED)
async def create_request_observation(
    project_id: int,
    run_id: int,
    request: RequestObservationIngestRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.ingest_request_observation(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "request_observation", record)
    return record


@router.post("/coverage-items", status_code=status.HTTP_201_CREATED)
async def create_coverage_item(
    project_id: int,
    run_id: int,
    request: CoverageItemRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.record_coverage_item(
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
    record = state_manager.record_probe_run(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "probe_run", record)
    return record


@router.post("/surfaces", status_code=status.HTTP_201_CREATED)
async def create_surface(project_id: int, run_id: int, request: SurfaceRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_surface(
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


@router.post("/findings", status_code=status.HTTP_201_CREATED)
async def create_finding(project_id: int, run_id: int, request: FindingRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.create_finding(
        project_id,
        run_id,
        current_user,
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
    await _broadcast(project_id, run_id, "finding", record)
    return record


@router.put("/findings/{finding_slug}")
async def put_finding(
    project_id: int,
    run_id: int,
    finding_slug: str,
    request: FindingRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.update_finding(
        project_id,
        run_id,
        current_user,
        slug=finding_slug,
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
    )
    await _broadcast(project_id, run_id, "finding", record)
    return record


@router.post("/findings/merge")
async def post_merge_findings(project_id: int, run_id: int, request: FindingMergeRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.merge_findings(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "finding_merge", record)
    return record


@router.post("/finding-links", status_code=status.HTTP_201_CREATED)
async def create_finding_link(
    project_id: int,
    run_id: int,
    finding_slug: str,
    request: FindingLinkRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.create_finding_link(
        project_id,
        run_id,
        current_user,
        finding_slug=finding_slug,
        link_kind=request.link_kind,
        target_kind=request.target_kind,
        target_id=request.target_id,
        target_ref=request.target_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "finding_link", record)
    return record


@router.post("/attack-chains", status_code=status.HTTP_201_CREATED)
async def create_attack_chain(project_id: int, run_id: int, request: AttackChainRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.create_attack_chain(
        project_id,
        run_id,
        current_user,
        chain_key=request.chain_key,
        title=request.title,
        status_value=request.status,
        severity=request.severity,
        narrative=request.narrative,
        evidence_ref=request.evidence_ref,
        provenance=request.provenance,
        links=[item.model_dump() for item in request.links],
    )
    await _broadcast(project_id, run_id, "attack_chain", record)
    return record


@router.post("/attack-chain-links", status_code=status.HTTP_201_CREATED)
async def create_attack_chain_link(
    project_id: int,
    run_id: int,
    chain_key: str,
    request: AttackChainLinkRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.create_attack_chain_link(
        project_id,
        run_id,
        current_user,
        chain_key=chain_key,
        relation=request.relation,
        entity_kind=request.entity_kind,
        entity_id=request.entity_id,
        entity_ref=request.entity_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "attack_chain_link", record)
    return record


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def create_credential(project_id: int, run_id: int, request: CredentialRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_credential(
        project_id,
        run_id,
        current_user,
        credential_key=request.credential_key,
        kind=request.kind,
        principal=request.principal,
        secret_locator=request.secret_locator,
        source_name=request.source_name,
        status_value=request.status,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "credential", record)
    return record


@router.post("/credential-tests", status_code=status.HTTP_201_CREATED)
async def create_credential_test(
    project_id: int,
    run_id: int,
    request: CredentialTestRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.record_credential_test(project_id, run_id, current_user, **request.model_dump())
    await _broadcast(project_id, run_id, "credential_test", record)
    return record


@router.post("/access-records", status_code=status.HTTP_201_CREATED)
async def create_access_record(project_id: int, run_id: int, request: AccessRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_access_record(
        project_id,
        run_id,
        current_user,
        access_key=request.access_key,
        credential_id=request.credential_id,
        service_id=request.service_id,
        principal=request.principal,
        access_level=request.access_level,
        target_ref=request.target_ref,
        status_value=request.status,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "access_record", record)
    return record


@router.post("/pivots", status_code=status.HTTP_201_CREATED)
async def create_pivot(project_id: int, run_id: int, request: PivotRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_pivot(
        project_id,
        run_id,
        current_user,
        pivot_key=request.pivot_key,
        access_record_id=request.access_record_id,
        source_ref=request.source_ref,
        destination_ref=request.destination_ref,
        technique=request.technique,
        status_value=request.status,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "pivot", record)
    return record


@router.post("/tunnels", status_code=status.HTTP_201_CREATED)
async def create_tunnel(project_id: int, run_id: int, request: TunnelRecordRequest, current_user: CurrentUser) -> dict[str, Any]:
    record = state_manager.record_tunnel(
        project_id,
        run_id,
        current_user,
        tunnel_key=request.tunnel_key,
        pivot_id=request.pivot_id,
        tunnel_type=request.tunnel_type,
        source_endpoint=request.source_endpoint,
        destination_endpoint=request.destination_endpoint,
        status_value=request.status,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "tunnel", record)
    return record


@router.post("/blocked-techniques", status_code=status.HTTP_201_CREATED)
async def create_blocked_technique(
    project_id: int,
    run_id: int,
    request: BlockedTechniqueRecordRequest,
    current_user: CurrentUser,
) -> dict[str, Any]:
    record = state_manager.record_blocked_technique(
        project_id,
        run_id,
        current_user,
        technique_key=request.technique_key,
        technique=request.technique,
        target_kind=request.target_kind,
        target_ref=request.target_ref,
        reason=request.reason,
        retry_state=request.retry_state,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(project_id, run_id, "blocked_technique", record)
    return record
