"""Pydantic request/response models for the per-engagement intel API.

One request model per POST endpoint in plan §1d, plus shared response models.
Field min/max lengths and defaults mirror the style of
``orchestrator/backend/app/api/assessment.py`` — these schemas are the
single source of truth that ``agent/schemas/intel-*.schema.json`` and the
``orchestrator/frontend/src/lib/api.ts`` TS types track.

All inbound payloads use ``ConfigDict(extra="forbid")`` so stray fields from
older agent prompts surface immediately instead of being silently dropped.
Response shapes are plain ``BaseModel`` classes; downstream route handlers
return dicts the state_manager helpers produce and FastAPI serialises them
against the declared ``response_model`` when a handler opts in.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ── Request models ─────────────────────────────────────────


class _IntelRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TechComponentRecordRequest(_IntelRequestBase):
    component: str = Field(min_length=1, max_length=256)
    version: str = Field(default="", max_length=128)
    source_name: str = Field(default="", max_length=128)
    confidence: Literal["low", "medium", "high", "confirmed", ""] = ""
    evidence_ref: str = Field(default="", max_length=1024)
    first_seen_at: str = Field(default="", max_length=64)
    last_seen_at: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class PersonRecordRequest(_IntelRequestBase):
    name: str = Field(min_length=1, max_length=256)
    role: str = Field(default="", max_length=256)
    organization: str = Field(default="", max_length=256)
    email: str = Field(default="", max_length=320)
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class EmailRecordRequest(_IntelRequestBase):
    address: str = Field(min_length=3, max_length=320)
    role_hint: str = Field(default="", max_length=128)
    linked_person_id: int | None = None
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class DomainRecordRequest(_IntelRequestBase):
    identity: str = Field(min_length=1, max_length=512)
    kind: Literal[
        "subdomain",
        "ip",
        "asn",
        "nameserver",
        "mx",
        "ptr",
        "domain",
    ] = "subdomain"
    value: str = Field(default="", max_length=1024)
    source_name: str = Field(default="", max_length=128)
    live_status: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class CveRecordRequest(_IntelRequestBase):
    cve_id: str = Field(min_length=3, max_length=64)
    affected_component: str = Field(default="", max_length=256)
    affected_version_range: str = Field(default="", max_length=256)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str = Field(default="", max_length=256)
    cwe_id: str = Field(default="", max_length=64)
    poc_available: bool = False
    source_name: str = Field(default="", max_length=128)
    validation_status: Literal[
        "unverified",
        "version_match",
        "poc_available_unverified",
        "attempted_blocked",
        "exploited",
        "ruled_out",
    ] = "unverified"
    linked_finding_slug: str = Field(default="", max_length=256)
    notes: str = Field(default="", max_length=4096)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def _details_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Light-weight upper bound on the details payload — keeps an
        # accidental dump (e.g., a full PoC scrape) from filling the column.
        block_reason = value.get("block_reason") if isinstance(value, dict) else None
        if block_reason is not None:
            if not isinstance(block_reason, str):
                raise ValueError("details.block_reason must be a string")
            if len(block_reason) > 500:
                raise ValueError("details.block_reason exceeds 500 characters")
        return value

    @model_validator(mode="after")
    def _enforce_attempted_blocked_requires_block_reason(self) -> "CveRecordRequest":
        if self.validation_status == "attempted_blocked":
            block_reason = (self.details or {}).get("block_reason")
            if not isinstance(block_reason, str) or not block_reason.strip():
                raise ValueError(
                    "details.block_reason is required when validation_status='attempted_blocked'"
                )
        return self


class DnsRecordRequest(_IntelRequestBase):
    record_type: str = Field(min_length=1, max_length=16)
    name: str = Field(min_length=1, max_length=512)
    value: str = Field(default="", max_length=4096)
    first_seen: str = Field(default="", max_length=64)
    last_seen: str = Field(default="", max_length=64)
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class SocialProfileRecordRequest(_IntelRequestBase):
    subject_kind: Literal["person", "org"]
    subject_ref: str = Field(default="", max_length=512)
    platform: str = Field(min_length=1, max_length=128)
    handle: str = Field(default="", max_length=256)
    url: str = Field(default="", max_length=2048)
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class BreachRecordRequest(_IntelRequestBase):
    subject: str = Field(min_length=1, max_length=512)
    breach_name: str = Field(min_length=1, max_length=256)
    breach_date: str = Field(default="", max_length=64)
    data_types: str = Field(default="", max_length=1024)
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class OrgFactRecordRequest(_IntelRequestBase):
    fact_key: str = Field(min_length=1, max_length=128)
    fact_value: str = Field(default="", max_length=4096)
    source_name: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)


class NoteRecordRequest(_IntelRequestBase):
    title: str = Field(min_length=1, max_length=512)
    body_markdown: str = Field(default="", max_length=65536)
    source_agent: str = Field(default="", max_length=128)
    tags: list[str] = Field(default_factory=list)
    source_name: str = Field(default="", max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)


class ActivityEntryRecordRequest(_IntelRequestBase):
    occurred_at: str = Field(default="", max_length=64)
    actor_kind: Literal["operator", "agent", "hook", "system"] = "operator"
    actor_name: str = Field(default="", max_length=128)
    title: str = Field(default="", max_length=512)
    action: str = Field(default="", max_length=4096)
    result: str = Field(default="", max_length=4096)
    artifact_ref: str = Field(default="", max_length=1024)
    body_markdown: str = Field(default="", max_length=65536)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Response models ────────────────────────────────────────


class _IntelResponseBase(BaseModel):
    """Shared fields every intel_* row carries on the wire."""

    id: int
    engagement_id: int
    source_name: str = ""
    notes: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    superseded_by_id: int | None = None
    superseded_at: str | None = None
    # Leaf of the ``superseded_by_id`` chain. Equal to ``id`` when the row
    # is the current canonical record; the backend walks the chain server-
    # side so the frontend can render the latest entity in one hop.
    canonical_id: int | None = None
    created_at: str
    updated_at: str


# ── Update + supersede request models ──────────────────────


class IntelUpdateRequest(BaseModel):
    """Generic patch payload for ``PATCH /intel/{type}/{id}``.

    The route receives a flat dict and the service helper validates the
    field set against the per-type updatable column whitelist. Using a
    permissive ``dict`` here keeps the patch contract uniform across the
    ten intel types — the per-type request models above are POST shapes,
    not PATCH shapes.
    """

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(default_factory=dict)


class IntelSupersedeRequest(BaseModel):
    """Replacement payload for ``POST /intel/{type}/{id}/supersede``."""

    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=4096)


class TechComponentRecord(_IntelResponseBase):
    component: str
    version: str = ""
    confidence: str = ""
    evidence_ref: str = ""
    first_seen_at: str = ""
    last_seen_at: str = ""


class PersonRecord(_IntelResponseBase):
    name: str
    role: str = ""
    organization: str = ""
    email: str = ""


class EmailRecord(_IntelResponseBase):
    address: str
    role_hint: str = ""
    linked_person_id: int | None = None


class DomainRecord(_IntelResponseBase):
    identity: str
    kind: str
    value: str = ""
    live_status: str = ""


class CveRecord(_IntelResponseBase):
    cve_id: str
    affected_component: str = ""
    affected_version_range: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe_id: str = ""
    poc_available: bool = False
    validation_status: str = "unverified"
    linked_finding_slug: str = ""


class DnsRecord(_IntelResponseBase):
    record_type: str
    name: str
    value: str = ""
    first_seen: str = ""
    last_seen: str = ""


class SocialProfileRecord(_IntelResponseBase):
    subject_kind: str
    subject_ref: str = ""
    platform: str
    handle: str = ""
    url: str = ""


class BreachRecord(_IntelResponseBase):
    subject: str
    breach_name: str
    breach_date: str = ""
    data_types: str = ""


class OrgFactRecord(_IntelResponseBase):
    fact_key: str
    fact_value: str = ""


class NoteRecord(_IntelResponseBase):
    title: str
    body_markdown: str = ""
    source_agent: str = ""
    tags: list[str] = Field(default_factory=list)


class ActivityEntryRecord(BaseModel):
    id: int
    engagement_id: int
    occurred_at: str
    actor_kind: str
    actor_name: str
    title: str
    action: str
    result: str
    artifact_ref: str
    body_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class IntelSearchHit(BaseModel):
    """Row returned by ``GET /intel/search``.

    ``entity_type`` names the underlying intel_* table (e.g. ``tech_component``,
    ``person``) so the frontend can route clicks back into the right drawer.
    ``source_id`` is the row id in that table; ``record`` carries the full
    resolved payload state_manager hydrates on demand.
    """

    entity_type: str
    source_id: int
    key: str
    body: str
    source_name: str
    rank: float | None = None
    record: dict[str, Any] = Field(default_factory=dict)


class IntelSummaryResponse(BaseModel):
    counts: dict[str, int]


class IntelByUrlResponse(BaseModel):
    """Merged view returned by ``GET /intel/by-url``.

    Matches ``intel_domains.identity``, ``assessment_services.endpoint``,
    ``assessment_surfaces.target_descriptor``, and
    ``assessment_request_variants.host`` for a single URL argument.
    """

    domains: list[DomainRecord] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    surfaces: list[dict[str, Any]] = Field(default_factory=list)
    request_variants: list[dict[str, Any]] = Field(default_factory=list)


class ListIntelResponse(BaseModel):
    """Generic envelope for list endpoints that need paging or counts.

    Service layer returns plain lists today, but this wrapper lets B1 add
    pagination metadata (``total``, ``offset``, ``limit``) without a breaking
    frontend refactor.
    """

    entity_type: str
    total: int
    items: list[dict[str, Any]]


class ListActivityEntriesResponse(BaseModel):
    total: int
    items: list[ActivityEntryRecord]
