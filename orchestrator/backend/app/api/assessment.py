from __future__ import annotations

import hashlib
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

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


class CommandRunRecordRequest(BaseModel):
    command: str = Field(min_length=1, max_length=65536)
    argv: list[str] | None = None
    tool_name: str = Field(min_length=1, max_length=128)
    route: str = Field(default="", max_length=256)
    agent_name: str = Field(min_length=1, max_length=128)
    phase: str = Field(min_length=1, max_length=64)
    return_code: int | None = None
    timed_out: bool = False
    success: bool | None = None
    started_at: str = Field(min_length=1, max_length=64)
    completed_at: str = Field(min_length=1, max_length=64)
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    command_hash: str = Field(default="", max_length=128)
    stdout_sha256: str = Field(default="", max_length=128)
    stderr_sha256: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    engagement_artifact_dir: str | None = Field(default=None, max_length=1024)
    run_uuid: str | None = Field(default=None, max_length=64)
    audit_source: Literal["header", "env_fallback", "mixed"] = "header"


class SurfaceRecordRequest(BaseModel):
    surface_type: Literal[
        "account_recovery",
        "api_documentation",
        "auth_entry",
        "dynamic_render",
        "file_handling",
        "object_reference",
        "privileged_write",
        "workflow_token",
    ]
    target_descriptor: str = Field(min_length=1, max_length=1024)
    source_name: str = Field(default="", max_length=128)
    rationale: str = Field(default="", max_length=4096)
    evidence_ref: str = Field(default="", max_length=1024)
    status: Literal["covered", "deferred", "discovered", "not_applicable"] = "discovered"


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
    status: str = Field(default="active", min_length=1, max_length=32)
    severity: str = Field(default="info", min_length=1, max_length=32)
    narrative: str = Field(default="", max_length=20000)
    evidence_ref: str = Field(default="", max_length=1024)
    provenance: dict[str, Any] = Field(default_factory=dict)
    links: list[AttackChainLinkRequest] = Field(default_factory=list)


class CredentialRecordRequest(BaseModel):
    credential_key: str = Field(min_length=1, max_length=256)
    kind: str = Field(min_length=1, max_length=64)
    principal: str = Field(min_length=1, max_length=256)
    secret: str = Field(default="", max_length=1024, description="The credential secret value (password, token, key)")
    source_name: str = Field(default="", max_length=128)
    status: str = Field(default="discovered", min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CredentialTestRecordRequest(BaseModel):
    credential_id: int
    service_id: int | None = None
    target_ref: str = Field(min_length=1, max_length=1024)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)


class AccessRecordRequest(BaseModel):
    access_key: str = Field(min_length=1, max_length=256)
    credential_id: int | None = None
    service_id: int | None = None
    principal: str = Field(min_length=1, max_length=256)
    access_level: str = Field(min_length=1, max_length=64)
    target_ref: str = Field(min_length=1, max_length=1024)
    status: str = Field(default="active", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CoverageItemUpdateRequest(BaseModel):
    status: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)


class BlockedTechniqueRecordRequest(BaseModel):
    technique_key: str = Field(min_length=1, max_length=256)
    technique: str = Field(min_length=1, max_length=256)
    target_kind: str = Field(min_length=1, max_length=64)
    target_ref: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=1, max_length=4096)
    retry_state: str = Field(default="no_retry", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class FindingLinkRequest(BaseModel):
    link_kind: str = Field(default="related", min_length=1, max_length=64)
    target_kind: str = Field(min_length=1, max_length=64)
    target_id: int | None = None
    target_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class MergeFindingsRequest(BaseModel):
    source_slug: str = Field(min_length=1, max_length=256)
    target_slug: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=4096)
    source_name: str = Field(default="operator", min_length=1, max_length=128)


class FindingRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    severity: str = Field(default="info", min_length=1, max_length=32)
    workflow_status: str = Field(default="active", min_length=1, max_length=32)
    verification_state: str = Field(default="unreviewed", min_length=1, max_length=32)
    verification_disposition: str = Field(default="none", min_length=1, max_length=32)
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


class FindingPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    severity: str | None = Field(default=None, min_length=1, max_length=32)
    workflow_status: str | None = Field(default=None, min_length=1, max_length=32)
    defect_family: str | None = Field(default=None, max_length=128)
    root_cause_key: str | None = Field(default=None, max_length=256)
    auth_context: str | None = Field(default=None, min_length=1, max_length=128)
    canonical_location: str | None = Field(default=None, max_length=1024)
    summary: str | None = Field(default=None, max_length=4096)
    evidence_ref: str | None = Field(default=None, max_length=1024)
    notes: str | None = Field(default=None, max_length=20000)
    source_name: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(default="", max_length=4096)
    artifact_ref: str = Field(default="", max_length=1024)


class FindingVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: Literal["confirmed", "downgraded", "false_positive", "disputed"]
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(min_length=1, max_length=4096)
    new_severity: str | None = Field(default=None, min_length=1, max_length=32)
    evidence_ref: str = Field(default="", max_length=1024)
    artifact_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=20000)
    source_name: str = Field(default="", max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


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


@router.get("/exploit-candidates")
def get_exploit_candidates(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_exploit_candidates(engagement.id)


@router.get("/coverage-readiness")
def get_coverage_readiness(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.coverage_readiness(engagement.id)


@router.get("/report-readiness")
def get_report_readiness(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.report_readiness(engagement.id)


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


@router.get("/command-runs")
def get_command_runs(
    engagement_key: str,
    q: str = "",
    agent_name: str = "",
    phase: str = "",
    tool_name: str = "",
    tool_bin: str = "",
    audit_source: str = "",
    success: bool | None = Query(default=None),
    timed_out: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_command_runs(
        engagement.id,
        q=q,
        agent_name=agent_name,
        phase=phase,
        tool_name=tool_name,
        tool_bin=tool_bin,
        audit_source=audit_source,
        success=success,
        timed_out=timed_out,
        limit=limit,
        offset=offset,
        include_output=include_output,
    )


@router.get("/command-runs/{command_run_id}")
def get_command_run(engagement_key: str, command_run_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_command_run(engagement.id, command_run_id)


@router.get("/surfaces")
def get_surfaces(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surfaces(engagement.id)


@router.get("/findings")
def get_findings(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_findings(engagement.id)


@router.get("/findings/{finding_slug}/transitions")
def get_finding_transitions(engagement_key: str, finding_slug: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_transitions(engagement.id, slug=finding_slug)


@router.get("/report-findings")
def get_report_findings(engagement_key: str, mode: Literal["draft", "final"] = "draft") -> list[dict[str, Any]]:
    """Findings formatted for report generation.

    Sorted by severity (critical first), excludes merged and false-positive
    findings, and extracts CVSS, remediation, CWE, and steps-to-reproduce from
    the details blob.
    Each finding includes a ``report_id`` (e.g. ``FINDING-001``) for sequential
    report numbering and a ``slug`` field so the original backend ID remains
    available for cross-referencing.
    """
    engagement = get_engagement_or_404(engagement_key)
    if mode == "final":
        readiness = state_manager.report_readiness(engagement.id)
        if not readiness["ready"]:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=readiness)
    return state_manager.list_report_findings(engagement.id, mode=mode)


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


@router.get("/credentials")
def get_credentials(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_credentials(engagement.id)


@router.get("/credential-tests")
def get_credential_tests(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_credential_tests(engagement.id)


@router.get("/access-records")
def get_access_records(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_access_records(engagement.id)


@router.get("/pivots")
def get_pivots(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_pivots(engagement.id)


@router.get("/tunnels")
def get_tunnels(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_tunnels(engagement.id)


@router.get("/blocked-techniques")
def get_blocked_techniques(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_blocked_techniques(engagement.id)


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


@router.post("/command-runs", status_code=status.HTTP_201_CREATED)
async def create_command_run(engagement_key: str, request: CommandRunRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    payload = request.model_dump()
    if not payload.get("command_hash"):
        payload["command_hash"] = hashlib.sha256(
            payload["command"].encode("utf-8", errors="replace")
        ).hexdigest()
    record = state_manager.record_command_run(engagement.id, **payload)
    await _broadcast(engagement.key, "command_run", record)
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


@router.post("/findings/merge")
async def merge_findings_endpoint(engagement_key: str, request: MergeFindingsRequest) -> dict[str, Any]:
    """Merge a source finding into a target finding.

    The source finding's status becomes 'merged' and its evidence, notes, and
    links are folded into the target.  The stronger severity and status win.
    """
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.merge_findings(
        engagement.id,
        source_slug=request.source_slug,
        target_slug=request.target_slug,
        reason=request.reason,
        source_name=request.source_name,
    )
    await _broadcast(engagement.key, "finding_merge", record)
    return record


@router.post("/findings", status_code=status.HTTP_201_CREATED)
async def create_finding(engagement_key: str, request: FindingRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.create_finding(
        engagement.id,
        slug=request.slug,
        title=request.title,
        severity=request.severity,
        workflow_status=request.workflow_status,
        verification_state=request.verification_state,
        verification_disposition=request.verification_disposition,
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


@router.patch("/findings/{finding_slug}")
async def patch_finding(
    engagement_key: str,
    finding_slug: str,
    request: FindingPatchRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.patch_finding(
        engagement.id,
        slug=finding_slug,
        title=request.title,
        severity=request.severity,
        workflow_status=request.workflow_status,
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
        transition_reason_code=request.reason_code,
        transition_reason_text=request.reason_text,
        transition_artifact_ref=request.artifact_ref,
    )
    await _broadcast(engagement.key, "finding_patch", record)
    return record


@router.post("/findings/{finding_slug}/verify")
async def verify_finding(
    engagement_key: str,
    finding_slug: str,
    request: FindingVerifyRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.verify_finding(
        engagement.id,
        slug=finding_slug,
        disposition=request.disposition,
        reason_code=request.reason_code,
        reason_text=request.reason_text,
        source_name=request.source_name,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
        details=request.details,
        provenance=request.provenance,
        artifact_ref=request.artifact_ref,
        new_severity=request.new_severity,
    )
    await _broadcast(engagement.key, "finding_verify", record)
    return record


@router.post("/attack-chains", status_code=status.HTTP_201_CREATED)
async def create_attack_chain(engagement_key: str, request: AttackChainRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.create_attack_chain(
        engagement.id,
        chain_key=request.chain_key,
        title=request.title,
        status_value=request.status,
        severity=request.severity,
        narrative=request.narrative,
        evidence_ref=request.evidence_ref,
        provenance=request.provenance,
        links=[item.model_dump() for item in request.links],
    )
    await _broadcast(engagement.key, "attack_chain", record)
    return record


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def create_credential(engagement_key: str, request: CredentialRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_credential(
        engagement.id,
        credential_key=request.credential_key,
        kind=request.kind,
        principal=request.principal,
        secret=request.secret,
        source_name=request.source_name,
        status_value=request.status,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "credential", record)
    return record


@router.post("/credential-tests", status_code=status.HTTP_201_CREATED)
async def create_credential_test(engagement_key: str, request: CredentialTestRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_credential_test(
        engagement.id,
        credential_id=request.credential_id,
        service_id=request.service_id,
        target_ref=request.target_ref,
        auth_context=request.auth_context,
        outcome=request.outcome,
        evidence_ref=request.evidence_ref,
        notes=request.notes,
    )
    await _broadcast(engagement.key, "credential_test", record)
    return record


@router.post("/access-records", status_code=status.HTTP_201_CREATED)
async def create_access_record(engagement_key: str, request: AccessRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_access_record(
        engagement.id,
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
    await _broadcast(engagement.key, "access_record", record)
    return record


@router.patch("/coverage-items/{coverage_item_id}")
async def update_coverage_item(engagement_key: str, coverage_item_id: int, request: CoverageItemUpdateRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_coverage_item_status(
        engagement.id,
        coverage_item_id=coverage_item_id,
        status_value=request.status,
        notes=request.notes,
    )
    await _broadcast(engagement.key, "coverage_item", record)
    return record


@router.post("/blocked-techniques", status_code=status.HTTP_201_CREATED)
async def create_blocked_technique(engagement_key: str, request: BlockedTechniqueRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_blocked_technique(
        engagement.id,
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
    await _broadcast(engagement.key, "blocked_technique", record)
    return record
