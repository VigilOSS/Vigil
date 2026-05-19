from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models.engagement import Engagement
from ..services import activity as activity_service
from ..services import assessment_memory
from ..services import artifact_index
from ..services import state_manager
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(prefix="/engagements/{engagement_key}/assessment", tags=["assessment"])

_ALLOWED_PHASES: frozenset[str] = frozenset(
    {
        "recon",
        "collect",
        "consume-test",
        "verify",
        "exploit",
        "report",
        "code-ingest",
        "code-classify",
        "code-hunt",
        "code-verify",
        # Half-phase tags for mid-engagement work between formal phase
        # transitions. The dispatching agent passes these explicitly when
        # the snapshot in scope.json does not match what the dispatch was
        # actually authorized for.
        "recon-pivot",
        "exploit-recon",
    }
)


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
    # phase is required-from-input. Wave-1 cutover removes the env-var
    # fallback that the patched MCP server used; the dispatching agent must
    # pass --phase explicitly because scope.json.current_phase is operator
    # state that does not reflect what the dispatch was authorized for.
    phase: str = Field(min_length=1, max_length=64)
    return_code: int | None = None
    timed_out: bool = False
    success: bool | None = None
    started_at: str = Field(min_length=1, max_length=64)
    # Pre-exec POST (status="running") sends completed_at="" — the command
    # hasn't completed yet. Finalize PATCH supplies the real value.
    # Historically this was set to started_at to satisfy a NOT NULL/min_length
    # constraint, which made in-flight rows look "completed at the same
    # instant they started" and broke orphan-sweep heuristics. The model
    # validator below requires a non-empty completed_at on terminal status.
    completed_at: str = Field(default="", max_length=64)
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
    # Command-metadata fields. Soft validation — matches the audit_source
    # precedent of plain TEXT storage. Technique/probe_kind are intentionally
    # not Literal-typed so new enum members don't require a backend redeploy;
    # the runtime logs a warning on unknown values and stores them verbatim.
    # Intent is trimmed to 200 chars server-side in record_command_run;
    # max_length here is a generous upper bound for transport.
    technique: str | None = Field(default=None, max_length=128)
    intent: str | None = Field(default=None, max_length=4096)
    probe_kind: str | None = Field(default=None, max_length=64)
    destructive: bool | None = None
    # Wave-1 cutover fields. New CLI pre-exec writes pass status=running
    # explicitly. Legacy one-shot posts may omit status while carrying terminal
    # fields; the service layer infers the terminal status in that case.
    status: Literal["queued", "running", "completed", "failed", "timed_out", "killed", "lost"] | None = None
    stdout_path: str | None = Field(default=None, max_length=1024)
    stderr_path: str | None = Field(default=None, max_length=1024)
    peak_rss_bytes: int | None = Field(default=None, ge=0)
    cpu_user_seconds: float | None = Field(default=None, ge=0)
    cpu_system_seconds: float | None = Field(default=None, ge=0)
    working_dir: str | None = Field(default=None, max_length=1024)
    scope_version: str | None = Field(default=None, max_length=128)
    auth_context: str | None = Field(default=None, max_length=128)
    # C30: parsed target host extracted from argv by the kali wrapper for
    # high-traffic verbs (httpx, nuclei, ffuf, sqlmap). Empty for unhandled
    # verbs; the existing FTS `--q` search still matches those rows.
    target_host: str = Field(default="", max_length=512)
    timeout_seconds_requested: int | None = Field(default=None, ge=0)
    force: bool = False

    @model_validator(mode="after")
    def _require_completed_at_for_terminal(self) -> "CommandRunRecordRequest":
        """Empty completed_at is only valid for in-flight rows (status="running"
        or "queued"). Any terminal status must supply a real timestamp so the
        audit row reflects when the command actually finished."""
        terminal = {"completed", "failed", "timed_out", "killed", "lost"}
        if (self.status or "completed") in terminal and not (self.completed_at or "").strip():
            raise ValueError(
                f"completed_at is required when status='{self.status}'; "
                "send the real terminal timestamp, not an empty string"
            )
        return self


class CommandRunFinalize(BaseModel):
    """PATCH payload for the new pre-exec/finalize lifecycle. Applied via
    state_manager.finalize_command_run(id, ...) after the subprocess exits.

    Accepting ``running`` here is a deliberate idempotency hatch: a no-op
    refresh of an in-flight row is allowed (B4) so an operator can re-PATCH
    metadata without flipping lifecycle state. The terminal-only check that
    used to live at this layer now belongs to ``finalize_command_run`` so
    duplicate terminal PATCHes can be detected and rejected with 409 instead
    of silently overwriting the first finalize."""

    status: Literal[
        "running",
        "completed",
        "failed",
        "timed_out",
        "killed",
        "lost",
    ]
    return_code: int | None = None
    ended_at: datetime
    duration_ms: int | None = Field(default=None, ge=0)
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    timed_out: bool = False
    partial_results: bool = False
    peak_rss_bytes: int | None = Field(default=None, ge=0)
    cpu_user_seconds: float | None = Field(default=None, ge=0)
    cpu_system_seconds: float | None = Field(default=None, ge=0)


class ArtifactRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=2048)
    kind: str = Field(default="", max_length=128)
    media_type: str = Field(default="", max_length=128)
    sensitive: bool = False
    producer_agent_id: str | None = Field(default=None, max_length=256)
    producer_agent_role: str | None = Field(default=None, max_length=128)
    producer_command_run_id: int | None = Field(default=None, ge=1)
    related_finding_slug: str | None = Field(default=None, max_length=256)
    related_chain_key: str | None = Field(default=None, max_length=256)
    related_surface_id: int | None = Field(default=None, ge=1)
    related_request_variant_id: int | None = Field(default=None, ge=1)


class JobCreate(BaseModel):
    """Request body for POST /jobs — opens an assessment_jobs row.

    parent_command_run_id links the synchronous audit row that initiated the
    dtach worker. status defaults to queued; the CLI bumps it to running
    immediately after dtach attaches.
    """

    parent_command_run_id: int | None = Field(default=None, ge=1)
    status: Literal["queued", "running", "completed", "failed", "killed", "lost", "stop_failed"] = "queued"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    exit_code: int | None = None
    dtach_socket_path: str | None = Field(default=None, max_length=1024)
    stdout_path: str | None = Field(default=None, max_length=1024)
    stderr_path: str | None = Field(default=None, max_length=1024)
    audit_metadata: dict[str, Any] | None = None


class JobUpdate(BaseModel):
    status: Literal["queued", "running", "completed", "failed", "killed", "lost", "stop_failed"] | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    exit_code: int | None = None
    dtach_socket_path: str | None = Field(default=None, max_length=1024)
    stdout_path: str | None = Field(default=None, max_length=1024)
    stderr_path: str | None = Field(default=None, max_length=1024)
    audit_metadata: dict[str, Any] | None = None


class JobRecord(BaseModel):
    """Durable job payload contract. agent/schemas/job.schema.json mirrors
    this shape so the CLI validator and the backend speak the same fields."""

    model_config = ConfigDict(extra="forbid")

    id: int
    engagement_id: int
    parent_command_run_id: int | None = None
    status: Literal["queued", "running", "completed", "failed", "killed", "lost", "stop_failed"]
    started_at: datetime | None = None
    ended_at: datetime | None = None
    exit_code: int | None = None
    dtach_socket_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    audit_metadata: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


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


class SurfaceUpdateRequest(BaseModel):
    """Patch shape for ``PATCH /assessment/surfaces/{id}``.

    Every field is optional so callers can update only what changed. The
    service helper rejects requests where every field is ``None`` so a
    no-op call surfaces as 400 instead of silently mutating updated_at.
    ``source_name`` and ``evidence_ref`` reject empty strings (use ``null``
    to leave the field unchanged) so a deliberate empty does not silently
    drop on the backend.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["covered", "deferred", "discovered", "not_applicable", "partially-covered"] | None = None
    rationale: str | None = Field(default=None, max_length=4096)
    source_name: str | None = Field(default=None, min_length=1, max_length=128)
    evidence_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    followup_condition: str | None = Field(default=None, max_length=500)


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


class RootCauseLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_cause_slug: str = Field(min_length=1, max_length=256)
    sibling_order: int | None = Field(default=None, ge=1)
    root_cause_effect: Literal["eliminates_finding", "eliminates_attack_path"] = "eliminates_finding"
    note: str = Field(default="", max_length=4096)
    source_name: str = Field(default="operator", min_length=1, max_length=128)
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
    # C44: evidence_type categorizes confirmation mode so report-writer can
    # sort/downrate without re-parsing details. Nullable; agents that don't
    # set it leave NULL (legacy behavior preserved).
    evidence_type: Literal[
        "network-confirmed", "code-inferred", "theoretical", "informational"
    ] | None = None
    request_variant_id: int | None = None
    service_id: int | None = None
    surface_id: int | None = None
    links: list[FindingLinkRequest] = Field(default_factory=list)

    @model_validator(mode="after")
    def _root_cause_links_use_helper(self) -> "FindingRecordRequest":
        if any(link.link_kind == state_manager.ROOT_CAUSE_LINK_KIND for link in self.links):
            raise ValueError("root_cause links must be created with link-finding / PUT /findings/{slug}/root-cause")
        return self


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
    # C44: allow retroactive labeling via aith assess update-finding.
    evidence_type: Literal[
        "network-confirmed", "code-inferred", "theoretical", "informational"
    ] | None = None
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


def _audit_assessment_mutation(
    engagement_id: int,
    *,
    title: str,
    action: str,
    actor_name: str = "aith-assess",
    result: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Best-effort activity row for backend state writes made by assess helpers."""
    try:
        activity_service.record_activity_entry(
            engagement_id,
            actor_kind="system",
            actor_name=actor_name or "aith-assess",
            title=title,
            action=action,
            result=result,
            metadata=metadata or {},
        )
    except Exception:
        # Activity visibility must never make the underlying assessment write fail.
        return


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


def _scope_hosts_for(engagement: Engagement) -> list[str]:
    """Read the raw scope.json `hosts` entries for the engagement.

    Returned verbatim (no classification) so the frontend can render the
    P1#3 scope-literals-only toggle and still see wildcard entries for
    context. Best-effort — a missing or malformed scope.json yields an
    empty list, not an error, because the per-host coverage projection
    must continue to render.
    """
    scope_path = Path(engagement.engagement_root) / "scope.json"
    if not scope_path.is_file():
        return []
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    hosts = scope.get("hosts") or []
    if not isinstance(hosts, list):
        return []
    return [entry for entry in hosts if isinstance(entry, str) and entry.strip()]


@router.get("/coverage-readiness/by-host")
def get_per_host_coverage(engagement_key: str) -> dict[str, Any]:
    """C40 outcome-based per-host coverage projection.

    Surfaces the WAF / service-inventory / directory-fuzz / nikto-trigger /
    OSINT outcome status for every host the engagement has signal for, plus
    active ``coverage_deferral`` decision rows. The CLI consumes this via
    ``aith assess check-scope-coverage --by-host``; the frontend Readiness
    panel (C58) renders the same shape.

    P1#3: also embeds ``scope_hosts`` (the raw scope.json hosts list) so
    the frontend can partition rows into scope literals vs wildcard
    discoveries without a second fetch.
    """
    engagement = get_engagement_or_404(engagement_key)
    payload = dict(state_manager.per_host_coverage(engagement.id))
    payload["scope_hosts"] = _scope_hosts_for(engagement)
    return payload


@router.get("/report-readiness")
def get_report_readiness(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    readiness = state_manager.report_readiness(engagement.id)
    # C58 — the Readiness panel renders per-host coverage outcomes alongside
    # the Definition-of-Done blockers, so include the C40 projection in the
    # same payload the frontend already fetches. The CLI keeps using
    # ``/coverage-readiness/by-host`` directly; this is purely an additive
    # extension for the UI consumer.
    readiness = dict(readiness)
    try:
        per_host = dict(state_manager.per_host_coverage(engagement.id))
        per_host["scope_hosts"] = _scope_hosts_for(engagement)
        readiness["per_host_coverage"] = per_host
    except Exception:  # pragma: no cover — defensive; never block the call
        readiness["per_host_coverage"] = {
            "objectives": [],
            "hosts": [],
            "engagement_signals": {},
            "scope_hosts": [],
        }
    return readiness


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
    target_host: str = "",
    audit_source: str = "",
    success: bool | None = Query(default=None),
    timed_out: bool | None = Query(default=None),
    # Command-metadata filter axes. Technique + probe_kind are plain str
    # (matching the audit_source precedent) so new enum values don't force
    # a backend redeploy. intent_q runs a FTS5 scoped match against the
    # intent column; destructive coerces True→1, False→0 on the WHERE.
    technique: str | None = None,
    probe_kind: str | None = None,
    destructive: bool | None = Query(default=None),
    intent_q: str | None = None,
    sort: Literal["", "relevance", "recent", "distant"] = "",
    show_matches: bool = False,
    exact: bool = False,
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
        target_host=target_host,
        audit_source=audit_source,
        success=success,
        timed_out=timed_out,
        technique=technique or "",
        probe_kind=probe_kind or "",
        destructive=destructive,
        intent_q=intent_q or "",
        sort=sort,
        exact=exact,
        show_matches=show_matches,
        limit=limit,
        offset=offset,
        include_output=include_output,
    )


@router.get("/resume-brief")
def get_resume_brief(
    engagement_key: str,
    q: str = "",
    finding: str = "",
    agent_id: str = "",
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return assessment_memory.build_resume_brief(
        engagement.id,
        q=q,
        finding=finding,
        agent_id=agent_id,
    )


@router.get("/command-runs/{command_run_id}")
def get_command_run(engagement_key: str, command_run_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_command_run(engagement.id, command_run_id)


@router.post("/artifacts", status_code=status.HTTP_201_CREATED)
async def register_artifact(engagement_key: str, request: ArtifactRegisterRequest) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = artifact_index.register_artifact(
        engagement.id,
        path=request.path,
        kind=request.kind,
        media_type=request.media_type,
        sensitive=request.sensitive,
        producer_agent_id=request.producer_agent_id,
        producer_agent_role=request.producer_agent_role,
        producer_command_run_id=request.producer_command_run_id,
        related_finding_slug=request.related_finding_slug,
        related_chain_key=request.related_chain_key,
        related_surface_id=request.related_surface_id,
        related_request_variant_id=request.related_request_variant_id,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="artifact register",
        action=str(record.get("relative_path") or request.path),
        actor_name=request.producer_agent_role or request.producer_agent_id or "operator",
        result=record.get("kind", ""),
        metadata={"artifact_id": record.get("id"), "relative_path": record.get("relative_path")},
    )
    await _broadcast(engagement.key, "artifact", record)
    return record


@router.post("/artifacts/sync")
async def sync_artifacts(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    result = artifact_index.sync_artifacts(engagement.id)
    _audit_assessment_mutation(
        engagement.id,
        title="artifact sync",
        action="sync engagement artifact index",
        actor_name="operator",
        result=f"present={result.get('present', 0)} missing={result.get('missing', 0)}",
        metadata=result,
    )
    await _broadcast(engagement.key, "artifact_sync", result)
    return result


@router.get("/artifacts/search")
def search_artifacts(
    engagement_key: str,
    q: str = "",
    finding: str = "",
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return artifact_index.search_artifacts(
        engagement.id,
        query=q,
        finding=finding,
        limit=limit,
        offset=offset,
    )


@router.get("/artifacts/{artifact_id}")
def get_indexed_artifact(engagement_key: str, artifact_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return artifact_index.get_artifact(engagement.id, artifact_id)


@router.get("/surfaces")
def get_surfaces(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surfaces(engagement.id)


@router.get("/findings")
def get_findings(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_findings(engagement.id)


@router.get("/findings/{finding_slug}")
def get_finding(engagement_key: str, finding_slug: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_finding(engagement.id, finding_slug)


@router.get("/findings/{finding_slug}/transitions")
def get_finding_transitions(engagement_key: str, finding_slug: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_transitions(engagement.id, slug=finding_slug)


@router.get("/report-findings")
def get_report_findings(
    engagement_key: str,
    mode: Literal["draft", "final"] = "draft",
) -> Any:
    """Grouped findings formatted for report generation.

    Sorted by severity (critical first), excludes merged and false-positive
    findings, and extracts CVSS, remediation, CWE, and steps-to-reproduce from
    the details blob.
    Root and sibling findings include a ``report_id`` (e.g. ``001``) for sequential
    report numbering and a ``slug`` field so the original backend ID remains
    available for cross-referencing.
    """
    engagement = get_engagement_or_404(engagement_key)
    if mode == "final":
        readiness = state_manager.report_readiness(engagement.id)
        if not readiness["ready"]:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=readiness)
    return state_manager.list_report_finding_groups(engagement.id, mode=mode)


@router.get("/finding-links")
def get_finding_links(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_links(engagement.id)


@router.get("/finding-groups")
def get_finding_groups(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_groups(engagement.id)


@router.get("/finding-groups/{root_slug}")
def get_finding_group(engagement_key: str, root_slug: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    groups = state_manager.list_finding_groups(engagement.id, root_slug=root_slug)
    if not groups:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding group not found")
    return groups[0]


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
async def create_command_run(
    engagement_key: str,
    request: CommandRunRecordRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    payload = request.model_dump()
    if not payload.get("command_hash"):
        payload["command_hash"] = hashlib.sha256(
            payload["command"].encode("utf-8", errors="replace")
        ).hexdigest()
    record = state_manager.record_command_run(engagement.id, **payload)
    await _broadcast(engagement.key, "command_run", record)
    return record


@router.patch("/command-runs/{command_run_id}")
async def patch_command_run(
    engagement_key: str,
    command_run_id: int,
    request: CommandRunFinalize,
) -> dict[str, Any]:
    """Finalize a pre-exec command-run row written with status=running."""
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.finalize_command_run(
        engagement.id,
        command_run_id=int(command_run_id),
        status_value=request.status,
        return_code=request.return_code,
        ended_at=request.ended_at.isoformat(),
        duration_ms=request.duration_ms,
        stdout_preview=request.stdout_preview,
        stderr_preview=request.stderr_preview,
        timed_out=request.timed_out,
        partial_results=request.partial_results,
        peak_rss_bytes=request.peak_rss_bytes,
        cpu_user_seconds=request.cpu_user_seconds,
        cpu_system_seconds=request.cpu_system_seconds,
    )
    if not record.get("noop"):
        await _broadcast(engagement.key, "command_run", record)
    return record


@router.post("/jobs", status_code=status.HTTP_201_CREATED)
async def create_job(
    engagement_key: str,
    request: JobCreate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_job(
        engagement.id,
        parent_command_run_id=request.parent_command_run_id,
        status_value=request.status,
        started_at=request.started_at.isoformat() if request.started_at else None,
        ended_at=request.ended_at.isoformat() if request.ended_at else None,
        exit_code=request.exit_code,
        dtach_socket_path=request.dtach_socket_path,
        stdout_path=request.stdout_path,
        stderr_path=request.stderr_path,
        audit_metadata=request.audit_metadata,
    )
    await _broadcast(engagement.key, "job", record)
    return record


@router.get("/jobs")
def get_jobs(
    engagement_key: str,
    status_value: str | None = Query(default=None, alias="status"),
    parent_command_run_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_jobs(
        engagement.id,
        status_value=status_value or "",
        parent_command_run_id=parent_command_run_id,
        limit=limit,
        offset=offset,
    )


@router.get("/jobs/{job_id}")
def get_job(engagement_key: str, job_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_job(engagement.id, int(job_id))


@router.patch("/jobs/{job_id}")
async def patch_job(
    engagement_key: str,
    job_id: int,
    request: JobUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_job(
        engagement.id,
        job_id=int(job_id),
        status_value=request.status,
        started_at=request.started_at.isoformat() if request.started_at else None,
        ended_at=request.ended_at.isoformat() if request.ended_at else None,
        exit_code=request.exit_code,
        dtach_socket_path=request.dtach_socket_path,
        stdout_path=request.stdout_path,
        stderr_path=request.stderr_path,
        audit_metadata=request.audit_metadata,
    )
    await _broadcast(engagement.key, "job", record)
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


@router.patch("/surfaces/{surface_id}")
async def update_surface_endpoint(
    engagement_key: str,
    surface_id: int,
    request: SurfaceUpdateRequest,
) -> dict[str, Any]:
    """Patch an assessment_surfaces row by id.

    The dedicated by-id PATCH lets the operator resolve a discovered surface
    to ``covered``, ``not_applicable``, or ``deferred`` without re-deriving
    the (surface_type, target_descriptor) UPSERT key. ``aith assess
    resolve-surface`` is the helper that drives this endpoint.
    """
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_surface(
        engagement.id,
        surface_id,
        status_value=request.status,
        rationale=request.rationale,
        source_name=request.source_name,
        evidence_ref=request.evidence_ref,
        followup_condition=request.followup_condition,
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
    _audit_assessment_mutation(
        engagement.id,
        title="merge-findings",
        action=f"{request.source_slug} -> {request.target_slug}",
        actor_name=request.source_name,
        result=request.reason or "",
        metadata={"source_slug": request.source_slug, "target_slug": request.target_slug},
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
        evidence_type=request.evidence_type,
        request_variant_id=request.request_variant_id,
        service_id=request.service_id,
        surface_id=request.surface_id,
        links=[item.model_dump() for item in request.links],
    )
    _audit_assessment_mutation(
        engagement.id,
        title="record-finding",
        action=f"finding={record.get('slug', request.slug)} severity={record.get('severity', request.severity)}",
        actor_name=request.source_name,
        result=record.get("workflow_status", request.workflow_status) or "",
        metadata={"finding_slug": record.get("slug", request.slug), "source_name": request.source_name},
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
        evidence_type=request.evidence_type,
        transition_reason_code=request.reason_code,
        transition_reason_text=request.reason_text,
        transition_artifact_ref=request.artifact_ref,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="update-finding",
        action=f"finding={finding_slug}",
        actor_name=request.source_name,
        result=request.reason_code or request.reason_text or "",
        metadata={"finding_slug": finding_slug},
    )
    await _broadcast(engagement.key, "finding_patch", record)
    return record


@router.put("/findings/{finding_slug}/root-cause")
async def set_finding_root_cause(
    engagement_key: str,
    finding_slug: str,
    request: RootCauseLinkRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.set_root_cause_link(
        engagement.id,
        finding_slug=finding_slug,
        root_cause_slug=request.root_cause_slug,
        sibling_order=request.sibling_order,
        root_cause_effect=request.root_cause_effect,
        note=request.note,
        source_name=request.source_name,
        provenance=request.provenance,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="link-finding",
        action=f"finding={finding_slug} root_cause={request.root_cause_slug}",
        actor_name=request.source_name,
        result=request.root_cause_effect,
        metadata={"finding_slug": finding_slug, "root_cause_slug": request.root_cause_slug},
    )
    await _broadcast(engagement.key, "finding_root_cause", record)
    return record


@router.delete("/findings/{finding_slug}/root-cause")
async def clear_finding_root_cause(engagement_key: str, finding_slug: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.clear_root_cause_link(engagement.id, finding_slug=finding_slug)
    _audit_assessment_mutation(
        engagement.id,
        title="unlink-finding",
        action=f"finding={finding_slug} root_cause=clear",
        actor_name="operator",
        result=str(record.get("cleared", 0)),
        metadata={"finding_slug": finding_slug},
    )
    await _broadcast(engagement.key, "finding_root_cause", record)
    return record


@router.post("/findings/{finding_slug}/links")
async def create_finding_link(
    engagement_key: str,
    finding_slug: str,
    request: FindingLinkRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    if request.link_kind == state_manager.ROOT_CAUSE_LINK_KIND:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="use PUT /findings/{slug}/root-cause for root-cause links",
        )
    record = state_manager.create_finding_link(
        engagement.id,
        finding_slug=finding_slug,
        link_kind=request.link_kind,
        target_kind=request.target_kind,
        target_id=request.target_id,
        target_ref=request.target_ref,
        notes=request.notes,
        provenance=request.provenance,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="finding-link",
        action=f"finding={finding_slug} link={request.link_kind}:{request.target_kind}:{request.target_ref}",
        actor_name="operator",
        result="linked",
        metadata={"finding_slug": finding_slug, "link_id": record.get("id")},
    )
    await _broadcast(engagement.key, "finding_link", record)
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
    _audit_assessment_mutation(
        engagement.id,
        title="verify-finding",
        action=f"finding={finding_slug} disposition={request.disposition}",
        actor_name=request.source_name,
        result=request.reason_code or request.reason_text or request.disposition,
        metadata={"finding_slug": finding_slug, "disposition": request.disposition},
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


# ── Round 9: dispatch / handoff / decision endpoints ──────────────────────


_DISPATCH_STATUS = Literal["in-progress", "completed", "failed", "aborted", "blocked"]
_DISPATCH_MODE = Literal[
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
    "swarm",
]
_REASONING = Literal["low", "medium", "high", "xhigh", "max"]
_CONFIDENCE = Literal["low", "medium", "high"]
_HANDOFF_STATUS = Literal["checkpointed", "ready", "blocked", "superseded"]


# Roles exempt from declaring `skills` on dispatch. The operator coordinates
# phases rather than executing a single skill, so requiring an explicit skill
# list on operator dispatches would be misleading. Every other specialist role
# must declare which skills it loaded so the dispatch row is a truthful audit
# of the specialist context. Mirrors `_DISPATCH_ROLES_WITHOUT_SKILLS` in
# `agent/scripts/assess/lib/contracts.py`; keep the two in sync.
_DISPATCH_ROLES_WITHOUT_SKILLS: frozenset[str] = frozenset({"operator"})


class DispatchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    agent_role: str = Field(min_length=1, max_length=128)
    task: str | None = Field(default=None, max_length=4096)
    scope_host: str | None = Field(default=None, max_length=512)
    dispatched_at: str | None = Field(default=None, max_length=64)
    status: _DISPATCH_STATUS = "in-progress"
    model: str | None = Field(default=None, max_length=128)
    reasoning: _REASONING | None = None
    requested_model: str | None = Field(default=None, max_length=128)
    actual_model: str | None = Field(default=None, max_length=128)
    requested_reasoning: _REASONING | None = None
    actual_reasoning: _REASONING | None = None
    dispatch_mode: _DISPATCH_MODE | None = None
    finding_slugs: list[str] | None = None
    skills: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def _enforce_skills_for_specialists(self) -> "DispatchCreate":
        """Specialist dispatches must declare which skills the agent loaded.

        The dispatch row is the audit surface for "what context did this
        specialist actually carry"; without a skill list it loses the
        provenance report-writer relies on. Operators are exempt because
        they coordinate phases rather than executing a single skill.
        """
        role = (self.agent_role or "").strip()
        if role.lower() in _DISPATCH_ROLES_WITHOUT_SKILLS:
            return self
        skills = (self.skills or "").strip()
        if not skills:
            raise ValueError(
                f"skills is required for role '{role}'; "
                "list at least one skill name from `aith assess list-skills`"
            )
        return self


class DispatchUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: _DISPATCH_STATUS | None = None
    completed_at: str | None = Field(default=None, max_length=64)
    finding_slugs: list[str] | None = None


class HandoffCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    agent_role: str = Field(min_length=1, max_length=128)
    phase: str | None = Field(default=None, max_length=64)
    summary: str = Field(min_length=1, max_length=2000)
    confidence: _CONFIDENCE | None = None
    finding_slugs: list[str] | None = None
    coverage_gaps: list[dict[str, Any]] | None = None
    next_steps: list[dict[str, Any]] | None = None
    runtime_issues: list[dict[str, Any]] | None = None
    working_artifacts: list[dict[str, Any]] | None = None
    open_questions: list[str] | None = None
    recommended_next_agent: str | None = Field(default=None, max_length=128)
    handoff_status: _HANDOFF_STATUS = "checkpointed"
    closed_dispatch_status: _DISPATCH_STATUS | None = None
    extras: dict[str, Any] | None = None


class HandoffUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str | None = Field(default=None, min_length=1, max_length=2000)
    phase: str | None = Field(default=None, max_length=64)
    confidence: _CONFIDENCE | None = None
    finding_slugs: list[str] | None = None
    coverage_gaps: list[dict[str, Any]] | None = None
    next_steps: list[dict[str, Any]] | None = None
    runtime_issues: list[dict[str, Any]] | None = None
    working_artifacts: list[dict[str, Any]] | None = None
    open_questions: list[str] | None = None
    recommended_next_agent: str | None = Field(default=None, max_length=128)
    handoff_status: _HANDOFF_STATUS | None = None
    closed_dispatch_status: _DISPATCH_STATUS | None = None
    extras: dict[str, Any] | None = None


_COVERAGE_DEFERRAL_OBJECTIVES = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "nikto_trigger",
    "osint",
)


class CoverageDeferralPayload(BaseModel):
    """Strict shape for ``kind='coverage_deferral'`` decision rows.

    Per the C40 design, the gate at ``per_host_coverage()`` consults this
    payload to decide whether a host has explicitly skipped a sub-objective.
    A malformed payload silently breaks the gate (the host appears unmet
    despite the operator's intent to defer), so kind-aware validation
    catches the bad shape at POST time rather than at gate-eval time.

    Free-form ``extras`` are allowed for context (timestamp, ticket link,
    etc.); only the load-bearing fields are constrained.
    """

    model_config = ConfigDict(extra="allow")

    deferred_objectives: list[
        Literal[
            "waf_tier",
            "service_inventory",
            "directory_fuzz",
            "nikto_trigger",
            "osint",
        ]
    ] = Field(
        min_length=1,
        description="One or more sub-objectives the operator is explicitly skipping for the host.",
    )
    reason: str = Field(
        min_length=1,
        description="Why the deferral was approved. Read by report-writer + audit views.",
    )
    host: str | None = Field(default=None, min_length=1)
    target: str | None = Field(default=None, min_length=1)
    hostname: str | None = Field(default=None, min_length=1)
    hosts: list[str] | None = Field(default=None)
    approved_by: str | None = Field(default=None, min_length=1)
    # Engagement-wide deferrals (e.g., "OSINT is out of scope for this whole
    # engagement") satisfy the named objectives for EVERY host with signal,
    # so operators don't have to duplicate the same deferral per host on
    # wildcard/large engagements. Mutually exclusive with the host fields:
    # an engagement-wide flag plus a host field is almost always an operator
    # mistake (which one wins?), so reject the ambiguous shape outright.
    engagement_wide: bool | None = Field(default=None)

    @model_validator(mode="after")
    def _require_host_or_engagement_wide(self) -> "CoverageDeferralPayload":
        has_host = any(
            [self.host, self.target, self.hostname, self.hosts and any(self.hosts)]
        )
        if not has_host and not self.engagement_wide:
            raise ValueError(
                "coverage_deferral payload requires one of: "
                "host, target, hostname, hosts[] (non-empty), or "
                "engagement_wide=true"
            )
        if has_host and self.engagement_wide:
            raise ValueError(
                "coverage_deferral payload cannot mix host fields with "
                "engagement_wide=true; pick one or the other"
            )
        if self.hosts is not None:
            for entry in self.hosts:
                if not isinstance(entry, str) or not entry.strip():
                    raise ValueError(
                        "coverage_deferral payload `hosts` entries must be non-empty strings"
                    )
        return self


class DecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # ``kind`` is intentionally NOT a Literal — operators may add new
    # checkpoint kinds (scope_decision, egress_decision, dispatch_blocked,
    # license_decision, ...) without a backend redeploy. The CLI helper layer
    # validates the well-known shapes; the table just stores the bytes.
    #
    # The exception is kinds whose payload is consumed by a backend gate
    # (currently: ``coverage_deferral`` → ``per_host_coverage()``). For those,
    # validate the payload shape at POST time so malformed payloads can't
    # silently neuter the gate that depends on them.
    kind: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    surfaced_to_user: bool = False

    @model_validator(mode="after")
    def _validate_known_kind_payload(self) -> "DecisionCreate":
        if self.kind == "coverage_deferral":
            CoverageDeferralPayload.model_validate(self.payload)
        return self


class DecisionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: bool | None = None
    resolution: dict[str, Any] | None = None
    surfaced_to_user: bool | None = None


@router.post("/dispatches", status_code=status.HTTP_201_CREATED)
async def create_dispatch(engagement_key: str, request: DispatchCreate) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_dispatch(
        engagement.id,
        agent_id=request.agent_id,
        agent_role=request.agent_role,
        task=request.task,
        scope_host=request.scope_host,
        dispatched_at=request.dispatched_at,
        status_value=request.status,
        model=request.model,
        reasoning=request.reasoning,
        requested_model=request.requested_model,
        actual_model=request.actual_model,
        requested_reasoning=request.requested_reasoning,
        actual_reasoning=request.actual_reasoning,
        dispatch_mode=request.dispatch_mode,
        finding_slugs=request.finding_slugs,
        skills=request.skills,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent start",
        action=f"agent_id={request.agent_id} role={request.agent_role}",
        actor_name=request.agent_role,
        result=request.status,
        metadata={"agent_id": request.agent_id, "agent_role": request.agent_role},
    )
    await _broadcast(engagement.key, "dispatch", record)
    return record


@router.get("/dispatches")
def get_dispatches(
    engagement_key: str,
    role: str = "",
    status_value: str = Query(default="", alias="status"),
    since: str = "",
    task_q: str = "",
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_dispatches(
        engagement.id,
        role=role,
        status_value=status_value,
        since=since,
        task_q=task_q,
        limit=limit,
    )


@router.get("/dispatches/{agent_id}")
def get_dispatch_endpoint(engagement_key: str, agent_id: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_dispatch(engagement.id, agent_id)


@router.patch("/dispatches/{agent_id}")
async def patch_dispatch(
    engagement_key: str,
    agent_id: str,
    request: DispatchUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_dispatch(
        engagement.id,
        agent_id=agent_id,
        status_value=request.status,
        completed_at=request.completed_at,
        finding_slugs=request.finding_slugs,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent done",
        action=f"agent_id={agent_id}",
        actor_name=agent_id,
        result=request.status or "",
        metadata={"agent_id": agent_id, "finding_slugs": request.finding_slugs or []},
    )
    await _broadcast(engagement.key, "dispatch", record)
    return record


@router.post("/dispatch-handoffs", status_code=status.HTTP_201_CREATED)
async def create_handoff(engagement_key: str, request: HandoffCreate) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_handoff(
        engagement.id,
        agent_id=request.agent_id,
        agent_role=request.agent_role,
        summary=request.summary,
        phase=request.phase,
        confidence=request.confidence,
        finding_slugs=request.finding_slugs,
        coverage_gaps=request.coverage_gaps,
        next_steps=request.next_steps,
        runtime_issues=request.runtime_issues,
        working_artifacts=request.working_artifacts,
        open_questions=request.open_questions,
        recommended_next_agent=request.recommended_next_agent,
        handoff_status=request.handoff_status,
        closed_dispatch_status=request.closed_dispatch_status,
        extras=request.extras,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent handoff",
        action=f"agent_id={request.agent_id} role={request.agent_role}",
        actor_name=request.agent_role,
        result=request.summary,
        metadata={"agent_id": request.agent_id, "agent_role": request.agent_role},
    )
    await _broadcast(engagement.key, "dispatch_handoff", record)
    return record


@router.get("/dispatch-handoffs")
def get_handoffs(
    engagement_key: str,
    role: str = "",
    since: str = "",
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_handoffs(
        engagement.id,
        role=role,
        since=since,
        limit=limit,
    )


@router.get("/dispatch-handoffs/{agent_id}")
def get_handoff_endpoint(engagement_key: str, agent_id: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_handoff(engagement.id, agent_id)


@router.patch("/dispatch-handoffs/{agent_id}")
async def patch_handoff(
    engagement_key: str,
    agent_id: str,
    request: HandoffUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_handoff(
        engagement.id,
        agent_id=agent_id,
        summary=request.summary,
        phase=request.phase,
        confidence=request.confidence,
        finding_slugs=request.finding_slugs,
        coverage_gaps=request.coverage_gaps,
        next_steps=request.next_steps,
        runtime_issues=request.runtime_issues,
        working_artifacts=request.working_artifacts,
        open_questions=request.open_questions,
        recommended_next_agent=request.recommended_next_agent,
        handoff_status=request.handoff_status,
        closed_dispatch_status=request.closed_dispatch_status,
        extras=request.extras,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent handoff",
        action=f"agent_id={agent_id}",
        actor_name=agent_id,
        result=request.summary or "",
        metadata={"agent_id": agent_id},
    )
    await _broadcast(engagement.key, "dispatch_handoff", record)
    return record


@router.post("/dispatch-decisions", status_code=status.HTTP_201_CREATED)
async def create_decision(engagement_key: str, request: DecisionCreate) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.record_decision(
        engagement.id,
        kind=request.kind,
        payload=request.payload,
        surfaced_to_user=request.surfaced_to_user,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent decision",
        action=f"kind={request.kind}",
        result="surfaced_to_user" if request.surfaced_to_user else "",
        metadata={"kind": request.kind, "surfaced_to_user": request.surfaced_to_user},
    )
    await _broadcast(engagement.key, "dispatch_decision", record)
    return record


@router.get("/dispatch-decisions")
def get_decisions(
    engagement_key: str,
    kind: str = "",
    resolved: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_decisions(
        engagement.id,
        kind=kind,
        resolved=resolved,
        limit=limit,
        offset=offset,
    )


@router.patch("/dispatch-decisions/{decision_id}")
async def patch_decision(
    engagement_key: str,
    decision_id: int,
    request: DecisionUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.update_decision(
        engagement.id,
        decision_id=int(decision_id),
        resolved=request.resolved,
        resolution=request.resolution,
        surfaced_to_user=request.surfaced_to_user,
    )
    _audit_assessment_mutation(
        engagement.id,
        title="agent decision",
        action=f"decision_id={decision_id}",
        result="resolved" if request.resolved else "",
        metadata={"decision_id": int(decision_id)},
    )
    await _broadcast(engagement.key, "dispatch_decision", record)
    return record
