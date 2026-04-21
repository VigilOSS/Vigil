"""Per-engagement intel ingestion + query API.

Real bodies for plan §1d. Every POST mirrors the pydantic-request →
service-helper → ``_broadcast`` pattern in ``api/assessment.py``. Every
list endpoint is a thin passthrough to ``services.intel``; search hits
``intel_search_fts`` via the shadow ``intel_search_index`` table.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status

from ..services import intel as intel_service
from ..services import state_manager
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster
from .intel_schemas import (
    BreachRecordRequest,
    CveRecordRequest,
    DnsRecordRequest,
    DomainRecordRequest,
    EmailRecordRequest,
    IntelByUrlResponse,
    IntelSummaryResponse,
    NoteRecordRequest,
    OrgFactRecordRequest,
    PersonRecordRequest,
    SocialProfileRecordRequest,
    TechComponentRecordRequest,
)


router = APIRouter(prefix="/engagements/{engagement_key}/intel", tags=["intel"])


async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "intel.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


# ── Reader endpoints ───────────────────────────────────────


@router.get("/summary", response_model=IntelSummaryResponse)
def get_intel_summary(engagement_key: str) -> IntelSummaryResponse:
    engagement = get_engagement_or_404(engagement_key)
    counts = intel_service.intel_summary(engagement.id)
    return IntelSummaryResponse(counts=counts)


@router.get("/search")
def search_intel(
    engagement_key: str,
    q: str = Query(default="", max_length=1024),
    entity_type: str = Query(default="", max_length=64),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.intel_search(
        engagement.id,
        q,
        entity_type=entity_type,
        limit=limit,
        offset=offset,
    )


@router.get("/by-url", response_model=IntelByUrlResponse)
def get_intel_by_url(
    engagement_key: str,
    url: str = Query(min_length=1, max_length=2048),
) -> IntelByUrlResponse:
    engagement = get_engagement_or_404(engagement_key)
    merged = intel_service.intel_by_url(engagement.id, url)
    return IntelByUrlResponse(**merged)


@router.get("/credentials")
def list_intel_credentials(engagement_key: str) -> list[dict[str, Any]]:
    """Alias over ``assessment_credentials`` so the intel pane stays uniform."""
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_credentials(engagement.id)


@router.get("/tech-components")
def list_tech_components(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_tech_components(engagement.id)


@router.get("/people")
def list_people(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_people(engagement.id)


@router.get("/emails")
def list_emails(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_emails(engagement.id)


@router.get("/domains")
def list_domains(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_domains(engagement.id)


@router.get("/cves")
def list_cves(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_cves(engagement.id)


@router.get("/dns-records")
def list_dns_records(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_dns_records(engagement.id)


@router.get("/social-profiles")
def list_social_profiles(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_social_profiles(engagement.id)


@router.get("/breach-records")
def list_breach_records(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_breach_records(engagement.id)


@router.get("/org-facts")
def list_org_facts(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_org_facts(engagement.id)


@router.get("/notes")
def list_notes(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_notes(engagement.id)


# ── POST endpoints ─────────────────────────────────────────


@router.post("/tech-components", status_code=status.HTTP_201_CREATED)
async def create_tech_component(
    engagement_key: str, request: TechComponentRecordRequest
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_tech_component(
        engagement.id,
        component=request.component,
        version=request.version,
        source_name=request.source_name,
        confidence=request.confidence,
        evidence_ref=request.evidence_ref,
        first_seen_at=request.first_seen_at,
        last_seen_at=request.last_seen_at,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "tech_component", record)
    return record


@router.post("/people", status_code=status.HTTP_201_CREATED)
async def create_person(engagement_key: str, request: PersonRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_person(
        engagement.id,
        name=request.name,
        role=request.role,
        organization=request.organization,
        email=request.email,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "person", record)
    return record


@router.post("/emails", status_code=status.HTTP_201_CREATED)
async def create_email(engagement_key: str, request: EmailRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_email(
        engagement.id,
        address=request.address,
        role_hint=request.role_hint,
        linked_person_id=request.linked_person_id,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "email", record)
    return record


@router.post("/domains", status_code=status.HTTP_201_CREATED)
async def create_domain(engagement_key: str, request: DomainRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_domain(
        engagement.id,
        identity=request.identity,
        kind=request.kind,
        value=request.value,
        source_name=request.source_name,
        live_status=request.live_status,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "domain", record)
    return record


@router.post("/cves", status_code=status.HTTP_201_CREATED)
async def create_cve(engagement_key: str, request: CveRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_cve(
        engagement.id,
        cve_id=request.cve_id,
        affected_component=request.affected_component,
        affected_version_range=request.affected_version_range,
        cvss_score=request.cvss_score,
        cvss_vector=request.cvss_vector,
        cwe_id=request.cwe_id,
        poc_available=request.poc_available,
        source_name=request.source_name,
        validation_status=request.validation_status,
        linked_finding_slug=request.linked_finding_slug,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "cve", record)
    return record


@router.post("/dns-records", status_code=status.HTTP_201_CREATED)
async def create_dns_record(engagement_key: str, request: DnsRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_dns_record(
        engagement.id,
        record_type=request.record_type,
        name=request.name,
        value=request.value,
        first_seen=request.first_seen,
        last_seen=request.last_seen,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "dns_record", record)
    return record


@router.post("/social-profiles", status_code=status.HTTP_201_CREATED)
async def create_social_profile(
    engagement_key: str, request: SocialProfileRecordRequest
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_social_profile(
        engagement.id,
        subject_kind=request.subject_kind,
        subject_ref=request.subject_ref,
        platform=request.platform,
        handle=request.handle,
        url=request.url,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "social_profile", record)
    return record


@router.post("/breach-records", status_code=status.HTTP_201_CREATED)
async def create_breach_record(
    engagement_key: str, request: BreachRecordRequest
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_breach_record(
        engagement.id,
        subject=request.subject,
        breach_name=request.breach_name,
        breach_date=request.breach_date,
        data_types=request.data_types,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "breach_record", record)
    return record


@router.post("/org-facts", status_code=status.HTTP_201_CREATED)
async def create_org_fact(engagement_key: str, request: OrgFactRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_org_fact(
        engagement.id,
        fact_key=request.fact_key,
        fact_value=request.fact_value,
        source_name=request.source_name,
        notes=request.notes,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "org_fact", record)
    return record


@router.post("/notes", status_code=status.HTTP_201_CREATED)
async def create_note(engagement_key: str, request: NoteRecordRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = intel_service.record_note(
        engagement.id,
        title=request.title,
        body_markdown=request.body_markdown,
        source_agent=request.source_agent,
        tags=request.tags,
        source_name=request.source_name,
        provenance=request.provenance,
    )
    await _broadcast(engagement.key, "note", record)
    return record
