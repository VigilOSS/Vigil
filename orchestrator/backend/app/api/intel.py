"""Per-engagement intel ingestion + query API.

Real bodies for plan §1d. Every POST mirrors the pydantic-request →
service-helper → ``_broadcast`` pattern in ``api/assessment.py``. Every
list endpoint is a thin passthrough to ``services.intel``; search hits
``intel_search_fts`` via the shadow ``intel_search_index`` table.
"""
from __future__ import annotations

import functools
from typing import Any, Literal

import anyio
from fastapi import APIRouter, HTTPException, Query, status

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
    IntelSupersedeRequest,
    IntelUpdateRequest,
    NoteRecordRequest,
    OrgFactRecordRequest,
    PersonRecordRequest,
    SocialProfileRecordRequest,
    TechComponentRecordRequest,
)


# Map URL plural segment -> CLI/type slug used by services.intel helpers.
_INTEL_TYPE_BY_PLURAL: dict[str, str] = {
    "tech-components": "tech-component",
    "people": "person",
    "emails": "email",
    "domains": "domain",
    "cves": "cve",
    "dns-records": "dns-record",
    "social-profiles": "social-profile",
    "breach-records": "breach-record",
    "org-facts": "org-fact",
    "notes": "note",
}


router = APIRouter(prefix="/engagements/{engagement_key}/intel", tags=["intel"])
DEFAULT_INTEL_LIST_LIMIT = 100
MAX_INTEL_LIST_LIMIT = 500


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


@router.get("/readiness")
def get_intel_readiness(engagement_key: str) -> dict[str, Any]:
    """Advisory (non-gating) intel-closure view — open CVEs/leads + dangling
    finding links. Red engagements only; blue returns applicable=False."""
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.intel_readiness(engagement.id)


@router.get("/search")
def search_intel(
    engagement_key: str,
    q: str = Query(default="", max_length=1024),
    entity_type: str = Query(default="", max_length=64),
    lead_status: Literal["open", "in_progress", "resolved", "ruled_out"] | None = Query(
        default=None
    ),
    provenance: str = Query(default="", max_length=1024),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.intel_search(
        engagement.id,
        q,
        entity_type=entity_type,
        lead_status=lead_status,
        provenance=provenance,
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


@router.get("/resolve")
def resolve_intel_ids(
    engagement_key: str,
    ids: list[str] = Query(min_length=1, max_length=100),
) -> list[dict[str, Any]]:
    """Resolve untyped finding intel ids without guessing across entity tables."""
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.resolve_intel_ids(engagement.id, ids)


@router.get("/credentials")
def list_intel_credentials(
    engagement_key: str,
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    """Alias over ``assessment_credentials`` so the intel pane stays uniform."""
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_credentials(engagement.id, limit=limit, offset=offset)


@router.get("/tech-components")
def list_tech_components(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_tech_components(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/people")
def list_people(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_people(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/emails")
def list_emails(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_emails(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/domains")
def list_domains(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_domains(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/cves")
def list_cves(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_cves(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/dns-records")
def list_dns_records(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_dns_records(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/social-profiles")
def list_social_profiles(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_social_profiles(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/breach-records")
def list_breach_records(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_breach_records(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/org-facts")
def list_org_facts(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_org_facts(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


@router.get("/notes")
def list_notes(
    engagement_key: str,
    include_superseded: bool = Query(default=True),
    limit: int = Query(default=DEFAULT_INTEL_LIST_LIMIT, ge=1, le=MAX_INTEL_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return intel_service.list_notes(
        engagement.id, include_superseded=include_superseded, limit=limit, offset=offset
    )


# ── POST endpoints ─────────────────────────────────────────


@router.post("/tech-components", status_code=status.HTTP_201_CREATED)
async def create_tech_component(
    engagement_key: str, request: TechComponentRecordRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_tech_component,
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
    )
    await _broadcast(engagement.key, "tech_component", record)
    return record


@router.post("/people", status_code=status.HTTP_201_CREATED)
async def create_person(engagement_key: str, request: PersonRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_person,
            engagement.id,
            name=request.name,
            role=request.role,
            organization=request.organization,
            email=request.email,
            source_name=request.source_name,
            notes=request.notes,
            provenance=request.provenance,
        )
    )
    await _broadcast(engagement.key, "person", record)
    return record


@router.post("/emails", status_code=status.HTTP_201_CREATED)
async def create_email(engagement_key: str, request: EmailRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_email,
            engagement.id,
            address=request.address,
            role_hint=request.role_hint,
            linked_person_id=request.linked_person_id,
            source_name=request.source_name,
            notes=request.notes,
            provenance=request.provenance,
        )
    )
    await _broadcast(engagement.key, "email", record)
    return record


@router.post("/domains", status_code=status.HTTP_201_CREATED)
async def create_domain(engagement_key: str, request: DomainRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_domain,
            engagement.id,
            identity=request.identity,
            kind=request.kind,
            value=request.value,
            source_name=request.source_name,
            live_status=request.live_status,
            notes=request.notes,
            provenance=request.provenance,
        )
    )
    await _broadcast(engagement.key, "domain", record)
    return record


@router.post("/cves", status_code=status.HTTP_201_CREATED)
async def create_cve(engagement_key: str, request: CveRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_cve,
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
            details=request.details,
            provenance=request.provenance,
        )
    )
    await _broadcast(engagement.key, "cve", record)
    return record


@router.post("/dns-records", status_code=status.HTTP_201_CREATED)
async def create_dns_record(engagement_key: str, request: DnsRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_dns_record,
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
    )
    await _broadcast(engagement.key, "dns_record", record)
    return record


@router.post("/social-profiles", status_code=status.HTTP_201_CREATED)
async def create_social_profile(
    engagement_key: str, request: SocialProfileRecordRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_social_profile,
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
    )
    await _broadcast(engagement.key, "social_profile", record)
    return record


@router.post("/breach-records", status_code=status.HTTP_201_CREATED)
async def create_breach_record(
    engagement_key: str, request: BreachRecordRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_breach_record,
            engagement.id,
            subject=request.subject,
            breach_name=request.breach_name,
            breach_date=request.breach_date,
            data_types=request.data_types,
            source_name=request.source_name,
            notes=request.notes,
            provenance=request.provenance,
        )
    )
    await _broadcast(engagement.key, "breach_record", record)
    return record


@router.post("/org-facts", status_code=status.HTTP_201_CREATED)
async def create_org_fact(engagement_key: str, request: OrgFactRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_org_fact,
            engagement.id,
            fact_key=request.fact_key,
            fact_value=request.fact_value,
            source_name=request.source_name,
            notes=request.notes,
            provenance=(
                request.provenance
                if "provenance" in request.model_fields_set
                else None
            ),
            authored_by=request.authored_by,
            scope=request.scope,
            validity_context=request.validity_context,
        )
    )
    await _broadcast(engagement.key, "org_fact", record)
    return record


@router.post("/notes", status_code=status.HTTP_201_CREATED)
async def create_note(engagement_key: str, request: NoteRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.record_note,
            engagement.id,
            **request.model_dump(exclude_unset=True),
        )
    )
    await _broadcast(engagement.key, "note", record)
    return record


# ── PATCH + supersede ──────────────────────────────────────


def _resolve_intel_plural(intel_type_plural: str) -> str:
    intel_type = _INTEL_TYPE_BY_PLURAL.get(intel_type_plural)
    if not intel_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown intel type segment '{intel_type_plural}'",
        )
    return intel_type


# DECLARATION ORDER IS LOAD-BEARING: FastAPI matches in declaration order, so this
# parameterised GET must stay AFTER every literal-path GET above (``/summary``,
# ``/search``, ``/credentials``, ``/notes``, ...) or it would shadow them.
@router.get("/{intel_type_plural}/{intel_id}")
async def get_intel_record(
    engagement_key: str,
    intel_type_plural: str,
    intel_id: int,
) -> dict[str, Any]:
    """Read one intel row by id.

    Three distinct 404s, matching the PATCH on the same path template: engagement
    not found, unknown intel type segment, and intel id not found.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    intel_type = _resolve_intel_plural(intel_type_plural)
    return await anyio.to_thread.run_sync(
        functools.partial(intel_service.get_intel_row, engagement.id, intel_type, intel_id)
    )


@router.patch("/{intel_type_plural}/{intel_id}")
async def patch_intel_record(
    engagement_key: str,
    intel_type_plural: str,
    intel_id: int,
    request: IntelUpdateRequest,
) -> dict[str, Any]:
    """In-place patch on an intel row by id.

    The body shape is ``{"payload": {...}}`` so the agent CLI can stream a
    raw JSON object as ``payload`` without conflating it with route-level
    metadata. Field-level validation lives in the service helper.

    Three distinct 404s are possible: engagement not found, unknown intel
    type segment, and intel id not found. Each returns a different ``detail``
    so callers can disambiguate without parsing the URL back out of the
    request.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    intel_type = _resolve_intel_plural(intel_type_plural)
    record = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.update_intel, engagement.id, intel_type, intel_id, request.payload
        )
    )
    await _broadcast(engagement.key, intel_type.replace("-", "_"), record)
    return record


@router.post("/{intel_type_plural}/{intel_id}/supersede", status_code=status.HTTP_201_CREATED)
async def supersede_intel_record(
    engagement_key: str,
    intel_type_plural: str,
    intel_id: int,
    request: IntelSupersedeRequest,
) -> dict[str, Any]:
    """Insert a replacement intel row and mark the old row as superseded.

    Returns ``{"superseded": {...}, "current": {...}}`` so callers can render
    both rows side-by-side without a second fetch.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    intel_type = _resolve_intel_plural(intel_type_plural)
    result = await anyio.to_thread.run_sync(
        functools.partial(
            intel_service.supersede_intel,
            engagement.id,
            intel_type,
            intel_id,
            request.payload,
            rationale=request.rationale,
            to_existing_id=request.to_existing_id,
        )
    )
    await _broadcast(engagement.key, intel_type.replace("-", "_"), result.get("current", {}))
    return result
