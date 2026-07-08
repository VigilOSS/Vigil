from __future__ import annotations

import functools
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import anyio
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..models.engagement import Engagement
from ..services import activity as activity_service
from ..services import assessment_memory
from ..services import artifact_index
from ..services import state_manager
from ..services.state_manager.coverage import (
    DEFAULT_PROBE_RUN_LIMIT,
    DEFAULT_COVERAGE_ITEM_LIMIT,
    DEFAULT_REQUEST_OBSERVATION_LIMIT,
    DEFAULT_REQUEST_VARIANT_LIMIT,
    DEFAULT_SURFACE_LIMIT,
    MAX_ASSESSMENT_LIST_LIMIT,
    MAX_PROBE_RUN_LIST_LIMIT,
    MAX_REQUEST_LIST_LIMIT,
    SurfaceStatus,
)
from ..services.state_manager.http_flows import (
    DEFAULT_HTTP_FLOW_LIMIT,
    MAX_HTTP_FLOW_LIST_LIMIT,
)
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(prefix="/engagements/{engagement_key}/assessment", tags=["assessment"])

COMMAND_FINALIZE_PREVIEW_MAX_CHARS = 65_536
MAX_BULK_ASSESSMENT_WRITE_ITEMS = 500

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


class WorkItemInput(BaseModel):
    """Optional per-observation work-buffer derivation block. Permissive (every
    field defaulted, extra keys ignored) so a well-formed observation can NEVER
    422 — the same silent-loss-avoidance invariant as HttpFlowIngestRequest.
    When present, the backend derives one ``assessment_work_items`` row in the
    same transaction as the observation/variant/coverage-item; when absent
    (``None``), no buffered row is created. Classification fields
    (type/priority/cluster/…) are producer-computed facts — the backend stores
    them, it never re-runs the classifier."""

    model_config = ConfigDict(extra="ignore")

    case_type: str = Field(default="unknown", max_length=64)
    queue_key: str = Field(default="", max_length=512)
    source: str = Field(default="", max_length=128)
    status: str = Field(default="pending", max_length=32)
    url: str = ""
    url_path: str = ""
    query_params: Any = ""
    body_params: Any = ""
    path_params: Any = ""
    cookie_params: Any = ""
    headers: Any = ""
    body: str | None = None
    content_type: str = Field(default="", max_length=256)
    content_length: int = 0
    request_body_truncated: bool = False
    response_status: int = 0
    response_headers: Any = ""
    response_size: int = 0
    response_snippet: str | None = None
    response_truncated: bool = False
    params_key_sig: str = Field(default="", max_length=256)
    priority_score: int = 0
    priority_reason: str = ""
    cluster_key: str = ""
    terminal_reason: str = ""
    classifier_version: str = ""
    signals: str = ""
    selected_by: str = ""
    triage_rationale: str = ""
    live_status: str = ""


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
    # Optional producer-supplied work-buffer derivation block. When present the
    # backend derives one work item in the same ingest transaction (ADR 0013).
    work_item: WorkItemInput | None = None


class RequestObservationBulkIngestRequest(BaseModel):
    items: list[RequestObservationIngestRequest] = Field(
        min_length=1,
        max_length=MAX_BULK_ASSESSMENT_WRITE_ITEMS,
    )


class WorkItemBulkInput(BaseModel):
    """Direct work-buffer write for rows with no request-variant (out-of-scope /
    egress skips, arjun/dns/gau-only producers, ``requeue``, the cases.db
    migration tool). Permissive/defaulted so a well-formed producer never 422s.
    ``queue_key`` + ``url`` are the minimum for a row to be stored."""

    model_config = ConfigDict(extra="ignore")

    queue_key: str = Field(default="", max_length=512)
    request_variant_id: int | None = None
    service_id: int | None = None
    coverage_item_id: int | None = None
    auth_context: str = Field(default="anonymous", max_length=128)
    method: str = Field(default="GET", max_length=16)
    url: str = ""
    url_path: str = ""
    host: str = Field(default="", max_length=512)
    query_params: Any = "{}"
    body_params: Any = "{}"
    path_params: Any = "{}"
    cookie_params: Any = "{}"
    headers: Any = ""
    body: str | None = None
    content_type: str = Field(default="", max_length=256)
    content_length: int = 0
    request_body_truncated: bool = False
    response_status: int = 0
    response_headers: Any = ""
    response_size: int = 0
    response_snippet: str | None = None
    response_truncated: bool = False
    type: str = Field(default="unknown", max_length=64)
    source: str = Field(default="", max_length=128)
    status: str = Field(default="pending", max_length=32)
    params_key_sig: str = Field(default="", max_length=256)
    priority_score: int = 0
    priority_reason: str | None = None
    cluster_key: str | None = None
    terminal_reason: str | None = None
    classifier_version: str | None = None
    signals: str | None = None
    selected_by: str | None = None
    triage_rationale: str | None = None
    live_status: str | None = None


class WorkItemBulkIngestRequest(BaseModel):
    items: list[WorkItemBulkInput] = Field(
        min_length=1,
        max_length=MAX_BULK_ASSESSMENT_WRITE_ITEMS,
    )


class WorkItemFetchRequest(BaseModel):
    type: str = Field(default="", max_length=64)
    limit: int = Field(default=1, ge=1, le=1000)
    agent: str = Field(default="", max_length=128)


class WorkItemPriorityFetchRequest(BaseModel):
    limit: int = Field(default=1, ge=1, le=1000)
    agent: str = Field(default="auto", max_length=128)


class WorkItemIdsRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


class WorkItemDeferItemsRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)
    reason: str = Field(default="", max_length=1024)


class WorkItemDeferClusterRequest(BaseModel):
    cluster_key: str = Field(default="", max_length=512)
    reason: str = Field(default="", max_length=1024)


class WorkItemUpdate(BaseModel):
    """One by-id field update for the classify-work maintenance path. Only the
    fields present are written (extra keys ignored); ``id`` is required."""

    model_config = ConfigDict(extra="ignore")

    id: int
    type: str | None = None
    status: str | None = None
    queue_key: str | None = None
    priority_score: int | None = None
    priority_reason: str | None = None
    cluster_key: str | None = None
    terminal_reason: str | None = None
    classifier_version: str | None = None


class WorkItemUpdateRequest(BaseModel):
    updates: list[WorkItemUpdate] = Field(min_length=1, max_length=MAX_BULK_ASSESSMENT_WRITE_ITEMS)


class WorkItemResetStaleRequest(BaseModel):
    minutes: int = Field(default=30, ge=0, le=100000)


class WorkItemRetryErrorsRequest(BaseModel):
    max_retries: int = Field(default=3, ge=0, le=1000)


class HttpFlowIngestRequest(BaseModel):
    """Full-flow metadata the mitmproxy addon POSTs per captured flow.

    DELIBERATELY permissive: every field is optional with a default so a
    well-formed flow can NEVER 422 (a 422 here would re-create the
    silent-capture-loss class of bug). ``flow_uid`` is the addon-supplied stable
    per-flow id; if omitted the service synthesizes one. Unknown extra keys are
    ignored, not rejected.
    """

    flow_uid: str = Field(default="", max_length=256)
    method: str = Field(default="", max_length=16)
    scheme: str = Field(default="", max_length=16)
    host: str = Field(default="", max_length=512)
    port: int | None = None
    # No max_length on url/path: a live flow can legitimately carry a very long
    # URL/query, and the ingest invariant is to NEVER 422 a well-formed flow (that
    # would re-introduce the silent-capture-loss class). The DB columns are
    # unbounded TEXT and the only writer is the trusted local addon.
    url: str = ""
    path: str = ""
    response_status: int | None = None
    request_content_type: str = Field(default="", max_length=256)
    response_content_type: str = Field(default="", max_length=256)
    content_type_family: str = Field(default="unknown", max_length=64)
    auth_context: str = Field(default="anonymous", max_length=128)
    request_body_sha256: str = Field(default="", max_length=128)
    response_body_sha256: str = Field(default="", max_length=128)
    request_body_bytes: int = 0
    response_body_bytes: int = 0
    request_body_truncated: bool = False
    response_body_truncated: bool = False
    request_body_artifact_path: str | None = Field(default=None, max_length=1024)
    response_body_artifact_path: str | None = Field(default=None, max_length=1024)
    request_headers: dict[str, Any] = Field(default_factory=dict)
    response_headers: dict[str, Any] = Field(default_factory=dict)
    redaction_status: str = Field(default="none", max_length=64)
    host_mismatch: bool = False
    url_authority: str = Field(default="", max_length=512)
    host_header: str = Field(default="", max_length=512)
    sni: str = Field(default="", max_length=512)
    timing_ms: int | None = None
    started_at: str | None = Field(default=None, max_length=64)
    request_variant_id: int | None = None
    # Optional engagement-local JSONL flow-index sidecar the addon writes; the
    # ingest route registers it in assessment_artifacts (kind='http_flow_index').
    index_artifact_path: str | None = Field(default=None, max_length=1024)


class CapturePolicyUpdateRequest(BaseModel):
    """PUT body for the per-engagement capture policy. Fields left unset retain
    their current stored value (partial update)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    capture_request_bodies: bool | None = None
    capture_response_bodies: bool | None = None
    max_body_bytes: int | None = Field(default=None, ge=0, le=1_073_741_824)
    content_type_allow: list[str] | None = None
    content_type_deny: list[str] | None = None
    redaction_profile: str | None = Field(default=None, max_length=64)


class ProbeRunRecordRequest(BaseModel):
    request_variant_id: int | None = None
    service_id: int | None = None
    coverage_item_id: int | None = None
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    # 128 (not 64) so the `slot:name` probe convention survives intact — a
    # prefixed input name like `header:X-Forwarded-Host` or a nested
    # `body:data.attributes.owner.id` would truncate at 64.
    input_slot: str = Field(default="unknown", min_length=1, max_length=128)
    attack_family: str = Field(min_length=1, max_length=64)
    payload_family: str = Field(default="", max_length=128)
    payload_value: str = Field(default="", max_length=16384)
    tool_name: str = Field(min_length=1, max_length=128)
    agent_name: str = Field(default="", max_length=128)
    result_status: Literal[
        "tested", "signal", "attempted", "blocked", "error", "no-signal"
    ] = "tested"
    observed_http_status: int | None = None
    signal_type: str = Field(default="", max_length=128)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    target_host: str = Field(default="", max_length=256)
    target_path: str = Field(default="", max_length=2048)
    target_port: int | None = None
    # Free-text lens/mindset the probe ran under. Part of the probe_key so the
    # same target under a different lens is a distinct attempt, not a dedup hit.
    # Light-normalized (stripped) server-side; NOT hard-enumerated.
    lens: str = Field(default="", max_length=128)
    # Optional attempt→finding linkage. Validated to belong to the engagement
    # (404 otherwise) and COALESCE-backfilled on a re-run of the same probe.
    finding_id: int | None = None


class CoverageItemRecordRequest(BaseModel):
    """Create/upsert a class-typed coverage item (Wave 5 / 2b).

    Wires the previously-dead ``record_coverage_item``. The gf-bucket bridge
    (``ingest_endpoints``) POSTs one of these per matched gf bucket with the
    canonical ``attack_family`` so the depth ledger sees a class-typed coverage
    obligation per endpoint, not just the generic baseline.
    """

    request_variant_id: int | None = None
    service_id: int | None = None
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    # Coarse in practice (endpoint|query|body|path|cookie|header|service), but
    # kept aligned with ProbeRunRecordRequest.input_slot at 128 so the two fields
    # for the same concept cannot drift apart.
    input_slot: str = Field(default="endpoint", min_length=1, max_length=128)
    attack_family: str = Field(min_length=1, max_length=64)
    status_value: str = Field(default="pending", min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)


class CoverageItemBulkRecordRequest(BaseModel):
    items: list[CoverageItemRecordRequest] = Field(
        min_length=1,
        max_length=MAX_BULK_ASSESSMENT_WRITE_ITEMS,
    )


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
    audit_source: Literal["header", "env_fallback", "mixed", "stdin", "argv"] = "header"
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
    # Optional link to the finding this command produced/supports. Validated to
    # belong to the engagement (404 otherwise); nullable + back-compat default.
    finding_id: int | None = None
    force: bool = False

    @model_validator(mode="after")
    def _require_completed_at_for_terminal(self) -> "CommandRunRecordRequest":
        """Empty completed_at is only valid for in-flight rows (status="running"
        or "queued"). Any terminal status must supply a real timestamp so the
        audit row reflects when the command actually finished."""
        terminal = state_manager.COMMAND_RUN_TERMINAL_STATUSES
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
    stdout_preview: str | None = Field(default=None, max_length=COMMAND_FINALIZE_PREVIEW_MAX_CHARS)
    stderr_preview: str | None = Field(default=None, max_length=COMMAND_FINALIZE_PREVIEW_MAX_CHARS)
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
        "misconfiguration",
        "informational",
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

    # ``SurfaceStatus`` is the canonical backend vocabulary (state_manager.coverage).
    # The create model (SurfaceRecordRequest) keeps a narrower Literal that omits
    # ``partially-covered`` deliberately — that status is only reachable via update.
    status: SurfaceStatus | None = None
    rationale: str | None = Field(default=None, max_length=4096)
    source_name: str | None = Field(default=None, min_length=1, max_length=128)
    evidence_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    followup_condition: str | None = Field(default=None, max_length=500)


class SurfaceRequestVariantLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    surface_id: int = Field(ge=1)
    request_variant_id: int = Field(ge=1)
    relation: str = Field(default="", max_length=128)
    evidence_ref: str = Field(default="", max_length=1024)


class OobProbeRecordRequest(BaseModel):
    """Record an OAST probe minted by ``vigil oob mint``.

    The ``nonce`` is the unique random subdomain label that doubles as the
    correlation token routed through the shared interactsh/frp transport.
    Metadata (target_url / param / technique / probe_kind / request_hash)
    describes the payload so a later blind callback auto-maps back to it.
    """

    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=1, max_length=256)
    target_url: str = Field(default="", max_length=4096)
    param: str = Field(default="", max_length=512)
    technique: str = Field(default="", max_length=128)
    probe_kind: str = Field(default="", max_length=64)
    request_hash: str = Field(default="", max_length=128)
    oob_domain: str = Field(default="", max_length=256)
    notes: str = Field(default="", max_length=4096)
    status: Literal["pending", "fired", "confirmed", "expired", "ignored"] = "pending"


class OobInteractionRecordRequest(BaseModel):
    """Correlate a single observed OAST callback to its probe by ``nonce``.

    Driven by ``vigil oob poll`` after it parses the interactsh-client log.
    An unknown nonce is not an error — the backend reports ``matched=False``
    so the poller can surface it under "unmatched interactions".
    """

    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="", max_length=32)
    remote_address: str = Field(default="", max_length=256)
    query_type: str = Field(default="", max_length=32)
    raw_request: str = Field(default="", max_length=20000)
    observed_at: str = Field(default="", max_length=64)


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
    secret: str = Field(default="", max_length=8192, description="Literal secret value (password, token, key material). Redact if policy prohibits storage; record 'REDACTED' and describe in notes.")
    source_name: str = Field(default="", max_length=128)
    status: str = Field(default="discovered", min_length=1, max_length=64)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)
    identity: str = Field(default="", max_length=128)


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

    @model_validator(mode="after")
    def _require_rationale_for_resolved(self) -> "CoverageItemUpdateRequest":
        resolved_positive = {"covered", "not_applicable", "done", "n/a", "not-applicable"}
        if (self.status or "").strip().lower() in resolved_positive and not (
            self.notes and self.notes.strip()
        ):
            raise ValueError(
                "a non-empty rationale (notes) is required to mark a coverage "
                "item 'covered' or 'not_applicable'"
            )
        return self


class BlockedTechniqueRecordRequest(BaseModel):
    technique_key: str = Field(min_length=1, max_length=256)
    technique: str = Field(min_length=1, max_length=256)
    target_kind: str = Field(min_length=1, max_length=64)
    target_ref: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=1, max_length=4096)
    # Align the API default with the SQL column default (db.py: assessment_
    # blocked_techniques.retry_state DEFAULT 'pending'). Both are free TEXT with
    # no CHECK; a mismatched default (was "no_retry") meant a create that omitted
    # retry_state landed a different value depending on whether it went through
    # the Pydantic model or a raw INSERT. Soft vocab: pending|retryable|no_retry.
    retry_state: str = Field(default="pending", min_length=1, max_length=64)
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


def _reject_invalid_submission_status(value: str | None) -> None:
    """HTTP enforcement seam for submission_status.

    References the canonical ``state_manager.SUBMISSION_STATUSES`` set (owned in
    the state-manager layer) so the vocabulary has a single backend source of
    truth. ``None`` is allowed (means "unset" — default 'none' on create,
    preserve on patch). Raises in a Pydantic validator → HTTP 422 at the API.
    """
    if value is not None and value not in state_manager.SUBMISSION_STATUSES:
        allowed = ", ".join(sorted(state_manager.SUBMISSION_STATUSES))
        raise ValueError(f"submission_status must be one of: {allowed}")


class FindingRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    # Default aligned to the CLI + record-finding contract (both `medium`): a
    # not-yet-triaged finding is presumed real, not informational. `info` was the
    # lone outlier here and produced a schema default that contradicted the CLI;
    # since severity feeds report-inclusion, defaulting low risked silently
    # under-rating untriaged findings. Only affects requests that OMIT severity;
    # stored rows keep their own value (DB-read compat unaffected).
    severity: str = Field(default="medium", min_length=1, max_length=32)
    workflow_status: str = Field(default="active", min_length=1, max_length=32)
    verification_state: str = Field(default="unreviewed", min_length=1, max_length=32)
    verification_disposition: str = Field(default="none", min_length=1, max_length=32)
    defect_family: str = Field(default="", max_length=128)
    root_cause_key: str = Field(default="", max_length=256)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    canonical_location: str = Field(default="", max_length=4096)
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
    # External submission-tracking axis, ORTHOGONAL to workflow_status. Nullable
    # with default None: a true create lands the 'none' default server-side, and
    # a re-record upsert that omits it preserves the stored value (so external
    # submission tracking is never clobbered by an unrelated record). Validated
    # against the canonical state_manager.SUBMISSION_STATUSES set below.
    submission_status: str | None = Field(default=None, min_length=1, max_length=32)
    request_variant_id: int | None = None
    service_id: int | None = None
    surface_id: int | None = None
    links: list[FindingLinkRequest] = Field(default_factory=list)
    # D4 (kill re-mint override): control flag, NOT a stored column. When true it
    # skips the killed-finding re-mint guard so an intentional distinct re-mint of
    # a finding that only coincidentally shares an endpoint + technique with a prior
    # false_positive still lands. Plumbed from `record-finding --allow-remint/--force`.
    allow_remint: bool = Field(default=False)

    @model_validator(mode="after")
    def _root_cause_links_use_helper(self) -> "FindingRecordRequest":
        if any(link.link_kind == state_manager.ROOT_CAUSE_LINK_KIND for link in self.links):
            raise ValueError("root_cause links must be created with link-finding / PUT /findings/{slug}/root-cause")
        return self

    @model_validator(mode="after")
    def _validate_submission_status(self) -> "FindingRecordRequest":
        _reject_invalid_submission_status(self.submission_status)
        return self


class FindingPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=512)
    severity: str | None = Field(default=None, min_length=1, max_length=32)
    workflow_status: str | None = Field(default=None, min_length=1, max_length=32)
    defect_family: str | None = Field(default=None, max_length=128)
    root_cause_key: str | None = Field(default=None, max_length=256)
    auth_context: str | None = Field(default=None, min_length=1, max_length=128)
    canonical_location: str | None = Field(default=None, max_length=4096)
    summary: str | None = Field(default=None, max_length=4096)
    evidence_ref: str | None = Field(default=None, max_length=1024)
    notes: str | None = Field(default=None, max_length=20000)
    # "append" (default) keeps the historical checkpoint behavior; "replace"
    # overwrites notes so stale/contradicted internal text can be scrubbed.
    notes_mode: Literal["append", "replace"] = "append"
    source_name: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] | None = None
    # CR-31: "merge" (default) accretes detail keys across checkpoints; "replace"
    # overwrites the whole details object so cross-contaminated/stale keys can be
    # fully removed (merge cannot delete keys). Requires details to be present.
    details_mode: Literal["merge", "replace"] = "merge"
    provenance: dict[str, Any] | None = None
    # C44: allow retroactive labeling via vigil assess update-finding.
    evidence_type: Literal[
        "network-confirmed", "code-inferred", "theoretical", "informational"
    ] | None = None
    # Optional on patch: None preserves the stored submission_status (the
    # workflow axis can move without disturbing the submission axis). Validated
    # against the canonical state_manager.SUBMISSION_STATUSES set.
    submission_status: str | None = Field(default=None, min_length=1, max_length=32)
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(default="", max_length=4096)
    artifact_ref: str = Field(default="", max_length=1024)

    @model_validator(mode="after")
    def _validate_submission_status(self) -> "FindingPatchRequest":
        _reject_invalid_submission_status(self.submission_status)
        return self

    @model_validator(mode="after")
    def _require_notes_when_replacing(self) -> "FindingPatchRequest":
        if self.notes_mode == "replace" and self.notes is None:
            raise ValueError("notes_mode='replace' requires notes")
        return self

    @model_validator(mode="after")
    def _require_details_when_replacing(self) -> "FindingPatchRequest":
        # details_mode='replace' overwrites the column; without a details payload
        # it would silently null it. Reject (mirrors the notes_mode guard).
        if self.details_mode == "replace" and self.details is None:
            raise ValueError("details_mode='replace' requires details")
        return self


class FindingVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: Literal["confirmed", "downgraded", "pending_runtime_proof", "blocked", "false_positive", "disputed"]
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(min_length=1, max_length=4096)
    new_severity: str | None = Field(default=None, min_length=1, max_length=32)
    evidence_ref: str = Field(default="", max_length=1024)
    artifact_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=20000)
    source_name: str = Field(default="", max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


_SUMMARY_AFFECTING_RECORD_TYPES = frozenset(
    {
        "access_record",
        "artifact",
        "artifact_refresh",
        "artifact_scratch",
        "artifact_scratch_bulk",
        "attack_chain",
        "blocked_technique",
        "coverage_item",
        "coverage_item_bulk",
        "credential",
        "credential_test",
        "dispatch",
        "dispatch_decision",
        "dispatch_handoff",
        "finding",
        "finding_link",
        "finding_merge",
        "finding_patch",
        "finding_root_cause",
        "finding_verify",
        "host_liveness",
        "probe_run",
        "request_observation",
        "request_observation_bulk",
        "surface",
    }
)


async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    if record_type in _SUMMARY_AFFECTING_RECORD_TYPES:
        raw_engagement_id = payload.get("engagement_id")
        if isinstance(raw_engagement_id, int):
            state_manager.clear_assessment_summary_cache(raw_engagement_id)
        else:
            state_manager.clear_assessment_summary_cache()
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
    actor_name: str = "vigil-assess",
    result: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Best-effort activity row for backend state writes made by assess helpers."""
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
    ``vigil assess check-phase-readiness --phase recon|collect|consume --by-host``;
    the frontend Readiness panel (C58) renders the same shape.

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


@router.get("/phase-readiness")
def get_phase_readiness(engagement_key: str, phase: str) -> dict[str, Any]:
    """Wave 6d — consolidated phase-keyed readiness (depth-gate §6).

    The backend half of ``vigil assess check-phase-readiness --phase <phase>``.
    ASSEMBLES the per-phase result by CALLING the existing, unchanged gates
    (``coverage_readiness`` / ``per_host_coverage`` / ``report_readiness`` /
    ``depth_ledger`` / intel ``intel_readiness``) — those function names and the
    routes that serve them are stable; this is purely an additive front door.

    Read-only and ADVISORY: it never mutates state and never refuses a
    transition (the terminal depth block lives on the ``transition-phase``
    report/complete precondition). An unknown ``phase`` is a 422.
    """
    engagement = get_engagement_or_404(engagement_key)
    try:
        return state_manager.phase_readiness(engagement.id, phase)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/targets")
def get_targets(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_targets(engagement.id)


@router.get("/services")
def get_services(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_services(engagement.id)


class HostLivenessRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=512)
    status_code: int | None = None
    scheme: str = Field(default="", max_length=16)
    final_url: str = Field(default="", max_length=2048)
    host_ip: str = Field(default="", max_length=256)
    tech: str = Field(default="", max_length=4096)
    title: str = Field(default="", max_length=1024)
    webserver: str = Field(default="", max_length=256)
    tls: str = Field(default="", max_length=8192)
    failed: bool = False
    # The caller (ingest-httpx) supplies an already-classified stored verdict.
    # 'stale' is NOT accepted here — it is a read-time overlay, never stored.
    reachability_class: Literal["live", "dead", "blackholed", "unknown"] = "unknown"
    probed_at: str | None = Field(default=None, max_length=64)
    source: str = Field(default="httpx", max_length=64)
    source_run_id: int | None = None
    source_run_uuid: str = Field(default="", max_length=128)


class HostLivenessUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rows: list[HostLivenessRow] = Field(default_factory=list)


@router.get("/host-liveness")
def get_host_liveness(
    engagement_key: str,
    host: str = "",
    fresh_only: bool = False,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    hosts = [h.strip() for h in host.split(",") if h.strip()] if host else None
    return state_manager.host_liveness(engagement.id, hosts=hosts, fresh_only=fresh_only)


@router.post("/host-liveness")
def post_host_liveness(
    engagement_key: str,
    request: HostLivenessUpsertRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    result = state_manager.upsert_host_liveness(
        engagement.id, [row.model_dump() for row in request.rows]
    )
    state_manager.clear_assessment_summary_cache(engagement.id)
    return result


@router.get("/request-variants")
def get_request_variants(
    engagement_key: str,
    limit: int = Query(default=DEFAULT_REQUEST_VARIANT_LIMIT, ge=1, le=MAX_REQUEST_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_request_variants(engagement.id, limit=limit, offset=offset)


@router.get("/request-observations")
def get_request_observations(
    engagement_key: str,
    limit: int = Query(default=DEFAULT_REQUEST_OBSERVATION_LIMIT, ge=1, le=MAX_REQUEST_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_request_observations(engagement.id, limit=limit, offset=offset)


@router.get("/coverage-items")
def get_coverage_items(
    engagement_key: str,
    limit: int = Query(default=DEFAULT_COVERAGE_ITEM_LIMIT, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_coverage_items(engagement.id, limit=limit, offset=offset)


@router.get("/probe-runs")
def get_probe_runs(
    engagement_key: str,
    attack_family: str = "",
    target_host: str = "",
    target_path: str = "",
    auth_context: str = "",
    result_status: str = "",
    limit: int = Query(default=DEFAULT_PROBE_RUN_LIMIT, ge=1, le=MAX_PROBE_RUN_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_probe_runs(
        engagement.id,
        attack_family=attack_family,
        target_host=target_host,
        target_path=target_path,
        auth_context=auth_context,
        result_status=result_status,
        limit=limit,
        offset=offset,
    )


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
    route: str = "",
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
    require_all: bool = False,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    if exact and require_all:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="exact and require_all are mutually exclusive",
        )
    return state_manager.list_command_runs(
        engagement.id,
        q=q,
        agent_name=agent_name,
        phase=phase,
        tool_name=tool_name,
        tool_bin=tool_bin,
        target_host=target_host,
        audit_source=audit_source,
        route=route,
        success=success,
        timed_out=timed_out,
        technique=technique or "",
        probe_kind=probe_kind or "",
        destructive=destructive,
        intent_q=intent_q or "",
        sort=sort,
        exact=exact,
        require_all=require_all,
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
    max_age_hours: float | None = Query(default=None, gt=0, le=24 * 30),
    since: str = "",
    per_input_limit: int = Query(
        default=assessment_memory._PER_INPUT_ROW_LIMIT, ge=0, le=100000
    ),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return assessment_memory.build_resume_brief(
        engagement.id,
        q=q,
        finding=finding,
        agent_id=agent_id,
        max_age_hours=max_age_hours,
        since=since,
        per_input_limit=per_input_limit,
    )


@router.get("/command-runs/{command_run_id}")
def get_command_run(engagement_key: str, command_run_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_command_run(engagement.id, command_run_id)


@router.post("/artifacts", status_code=status.HTTP_201_CREATED)
async def register_artifact(engagement_key: str, request: ArtifactRegisterRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.register_artifact,
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
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="artifact register",
            action=str(record.get("relative_path") or request.path),
            actor_name=request.producer_agent_role or request.producer_agent_id or "operator",
            result=record.get("kind", ""),
            metadata={"artifact_id": record.get("id"), "relative_path": record.get("relative_path")},
        )
    )
    await _broadcast(engagement.key, "artifact", record)
    return record


@router.post("/artifacts/refresh")
async def refresh_artifacts(engagement_key: str) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    result = await anyio.to_thread.run_sync(
        functools.partial(artifact_index.refresh_artifacts, engagement.id)
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="artifact refresh",
            action="refresh",
            actor_name="operator",
            result=f"refreshed={result.get('refreshed', 0)} missing={result.get('missing', 0)}",
            metadata=result,
        )
    )
    await _broadcast(engagement.key, "artifact_refresh", result)
    return result


@router.get("/artifacts/search")
def search_artifacts(
    engagement_key: str,
    q: str = "",
    finding: str = "",
    kind: str = "",
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return artifact_index.search_artifacts(
        engagement.id,
        query=q,
        finding=finding,
        kind=kind,
        limit=limit,
        offset=offset,
    )


@router.get("/artifacts/{artifact_id}")
def get_indexed_artifact(engagement_key: str, artifact_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return artifact_index.get_artifact(engagement.id, artifact_id)


class ArtifactScratchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str | None = Field(default=None, max_length=2048)
    scratch: bool = True


@router.post("/artifacts/{artifact_id}/scratch")
async def mark_artifact_scratch(
    engagement_key: str,
    artifact_id: int,
    request: ArtifactScratchRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    row = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.set_scratch_flag,
            engagement.id,
            artifact_id=artifact_id,
            scratch=request.scratch,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="artifact mark-scratch" if request.scratch else "artifact unmark-scratch",
            action=str(row.get("relative_path") or ""),
            actor_name="operator",
            result="scratch=1" if request.scratch else "scratch=0",
            metadata={"artifact_id": row.get("id"), "relative_path": row.get("relative_path")},
        )
    )
    await _broadcast(engagement.key, "artifact_scratch", row)
    return row


@router.post("/artifacts/scratch-by-path")
async def mark_artifact_scratch_by_path(
    engagement_key: str,
    request: ArtifactScratchRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    if not (request.path or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="path is required")
    row = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.set_scratch_flag,
            engagement.id,
            path=request.path or "",
            scratch=request.scratch,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="artifact mark-scratch" if request.scratch else "artifact unmark-scratch",
            action=str(row.get("relative_path") or request.path or ""),
            actor_name="operator",
            result="scratch=1" if request.scratch else "scratch=0",
            metadata={"artifact_id": row.get("id"), "relative_path": row.get("relative_path")},
        )
    )
    await _broadcast(engagement.key, "artifact_scratch", row)
    return row


class ArtifactScratchBulkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prefix: str = Field(min_length=1, max_length=2048)
    scratch: bool = True


@router.post("/artifacts/scratch-under")
async def mark_artifacts_scratch_under(
    engagement_key: str,
    request: ArtifactScratchBulkRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    result = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.set_scratch_under_prefix,
            engagement.id,
            prefix=request.prefix,
            scratch=request.scratch,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="artifact mark-scratch (bulk)" if request.scratch else "artifact unmark-scratch (bulk)",
            action=f"prefix={request.prefix}",
            actor_name="operator",
            result=f"matched={result.get('matched', 0)} scratch={'1' if request.scratch else '0'}",
            metadata={"prefix": result.get("prefix"), "matched": result.get("matched", 0)},
        )
    )
    await _broadcast(engagement.key, "artifact_scratch_bulk", result)
    return result


@router.get("/surfaces")
def get_surfaces(
    engagement_key: str,
    limit: int = Query(default=DEFAULT_SURFACE_LIMIT, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surfaces(engagement.id, limit=limit, offset=offset)


@router.get("/oob-probes")
def get_oob_probes(
    engagement_key: str,
    status_filter: str | None = Query(default=None, alias="status"),
) -> list[dict[str, Any]]:
    """List OAST probes for the engagement (newest first).

    Each row carries an ``interaction_count`` and ``last_interaction_at`` so
    ``vigil oob poll`` can render matched probe↔callback pairs without a
    second round-trip per probe.
    """
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_oob_probes(engagement.id, status_value=status_filter)


@router.get("/oob-probes/{nonce}")
def get_oob_probe(engagement_key: str, nonce: str) -> dict[str, Any]:
    """Fetch one OAST probe by nonce with its full interaction history."""
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_oob_probe_by_nonce(engagement.id, nonce)


@router.get("/findings")
def get_findings(
    engagement_key: str,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_state: str | None = None,
    verification_disposition: str | None = None,
    auth_context: str | None = None,
    source_name: str | None = None,
    slug: str | None = None,
    search: str | None = None,
    holding: bool = False,
    limit: int | None = Query(default=None, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_findings(
        engagement.id,
        severity=severity,
        workflow_status=workflow_status,
        verification_state=verification_state,
        verification_disposition=verification_disposition,
        auth_context=auth_context,
        source_name=source_name,
        slug=slug,
        search=search,
        holding=holding,
        limit=limit,
        offset=offset,
    )


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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.ingest_request_observation, engagement.id, **request.model_dump())
    )
    await _broadcast(engagement.key, "request_observation", record)
    return record


@router.post("/request-observations/bulk", status_code=status.HTTP_201_CREATED)
async def create_request_observations_bulk(
    engagement_key: str,
    request: RequestObservationBulkIngestRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    result = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.ingest_request_observations_bulk,
            engagement.id,
            [item.model_dump() for item in request.items],
        )
    )
    await _broadcast(
        engagement.key,
        "request_observation_bulk",
        {"engagement_id": engagement.id, "count": result["count"]},
    )
    return result


# ---------------------------------------------------------------------------
# Work buffer (assessment_work_items) — the transient triage/dispatch queue.
# Folds the former per-engagement cases.db work_items into the backend ledger
# (ADR 0013). Reads are plain GET; the mutation/claim verbs are POST and offload
# the sync SQLite work to the threadpool like the other write handlers.
# ---------------------------------------------------------------------------
@router.get("/work-items")
def get_work_items(
    engagement_key: str,
    type: str = "",
    status: str = "",
    limit: int = Query(default=5000, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    if type:
        return state_manager.peek_work_items(engagement.id, type_val=type, limit=limit)
    return state_manager.list_work_items(engagement.id, status=(status or None), limit=limit, offset=offset)


@router.get("/work-items/stats")
def get_work_item_stats(engagement_key: str, by: str = "status") -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.work_buffer_stats(engagement.id, by=by)


@router.post("/work-items/bulk", status_code=status.HTTP_201_CREATED)
async def create_work_items_bulk(engagement_key: str, request: WorkItemBulkIngestRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_work_items_bulk,
            engagement.id,
            [item.model_dump() for item in request.items],
        )
    )


@router.post("/work-items/fetch")
async def fetch_work_items_endpoint(engagement_key: str, request: WorkItemFetchRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.fetch_work_items,
            engagement.id,
            type_val=request.type,
            limit=request.limit,
            agent=request.agent,
        )
    )


@router.post("/work-items/fetch-by-priority")
async def fetch_work_items_by_priority_endpoint(
    engagement_key: str, request: WorkItemPriorityFetchRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.fetch_work_items_by_priority,
            engagement.id,
            limit=request.limit,
            agent=request.agent,
        )
    )


@router.post("/work-items/done")
async def work_items_done(engagement_key: str, request: WorkItemIdsRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.mark_work_items_done, engagement.id, request.ids)
    )


@router.post("/work-items/error")
async def work_items_error(engagement_key: str, request: WorkItemIdsRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.mark_work_items_error, engagement.id, request.ids)
    )


@router.post("/work-items/defer")
async def work_items_defer(engagement_key: str, request: WorkItemDeferItemsRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.defer_work_items, engagement.id, ids=request.ids, reason=request.reason)
    )


@router.post("/work-items/defer-cluster")
async def work_items_defer_cluster(engagement_key: str, request: WorkItemDeferClusterRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.defer_work_item_cluster,
            engagement.id,
            cluster_key=request.cluster_key,
            reason=request.reason,
        )
    )


@router.post("/work-items/mark-manual")
async def work_items_mark_manual(engagement_key: str, request: WorkItemIdsRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.mark_work_items_manual, engagement.id, request.ids)
    )


@router.post("/work-items/update")
async def work_items_update(engagement_key: str, request: WorkItemUpdateRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.apply_work_item_updates,
            engagement.id,
            [u.model_dump(exclude_unset=True) for u in request.updates],
        )
    )


@router.post("/work-items/reset-stale")
async def work_items_reset_stale(engagement_key: str, request: WorkItemResetStaleRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.reset_stale_work_items, engagement.id, minutes=request.minutes)
    )


@router.post("/work-items/retry-errors")
async def work_items_retry_errors(engagement_key: str, request: WorkItemRetryErrorsRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(state_manager.retry_error_work_items, engagement.id, max_retries=request.max_retries)
    )


def _register_http_flow_artifacts(engagement_id: int, request: HttpFlowIngestRequest) -> None:
    """Register the addon-reported body/index sidecars in assessment_artifacts.

    Best-effort: an artifact-registry failure must never fail the flow ingest
    (silent-data-loss > redaction). ``register_artifact`` hashes/sizes the file
    if present and records present=0 otherwise — the backend never has to READ
    the sidecar here."""
    registrations = (
        (request.request_body_artifact_path, "http_flow_body"),
        (request.response_body_artifact_path, "http_flow_body"),
        (request.index_artifact_path, "http_flow_index"),
    )
    for path_value, kind in registrations:
        if not path_value:
            continue
        try:
            artifact_index.register_artifact(engagement_id, path=path_value, kind=kind)
        except Exception:
            continue


@router.get("/http-flows")
def get_http_flows(
    engagement_key: str,
    host: str = "",
    method: str = "",
    response_status: int | None = None,
    content_type_family: str = "",
    auth_context: str = "",
    truncated: bool | None = None,
    q: str = "",
    limit: int = Query(default=DEFAULT_HTTP_FLOW_LIMIT, ge=1, le=MAX_HTTP_FLOW_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_http_flows(
        engagement.id,
        host=host,
        method=method,
        response_status=response_status,
        content_type_family=content_type_family,
        auth_context=auth_context,
        truncated=truncated,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/http-flows/export-har")
def export_http_flows_har(
    engagement_key: str,
    host: str = "",
    method: str = "",
    response_status: int | None = None,
    content_type_family: str = "",
    auth_context: str = "",
    truncated: bool | None = None,
    q: str = "",
    limit: int = Query(default=MAX_HTTP_FLOW_LIST_LIMIT, ge=1, le=MAX_HTTP_FLOW_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Build a HAR 1.2 log from the filtered flows. Body sidecars under the
    engagement root are inlined into postData/content when present (size-capped);
    Vigil routing/auth/truncation metadata rides on each entry's ``_vigil`` field."""
    engagement = get_engagement_or_404(engagement_key)
    flows = state_manager.list_http_flows(
        engagement.id,
        host=host,
        method=method,
        response_status=response_status,
        content_type_family=content_type_family,
        auth_context=auth_context,
        truncated=truncated,
        q=q,
        limit=limit,
        offset=offset,
    )
    root = Path(engagement.engagement_root).resolve()
    return state_manager.har_from_flows(flows, root=root)


@router.get("/http-flows/{flow_uid}")
def get_http_flow_detail(engagement_key: str, flow_uid: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = state_manager.get_http_flow(engagement.id, flow_uid)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="http flow not found")
    return record


@router.post("/http-flows", status_code=status.HTTP_201_CREATED)
async def create_http_flow(engagement_key: str, request: HttpFlowIngestRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    fields = request.model_dump(exclude={"index_artifact_path"})
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.insert_http_flow, engagement.id, **fields)
    )
    await anyio.to_thread.run_sync(
        functools.partial(_register_http_flow_artifacts, engagement.id, request)
    )
    await _broadcast(engagement.key, "http_flow", record)
    return record


class HarImportRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    log: dict[str, Any] = Field(default_factory=dict)


@router.post("/http-flows/import-har", status_code=status.HTTP_201_CREATED)
async def import_http_flows_har(engagement_key: str, request: HarImportRequest) -> dict[str, Any]:
    """Parse a HAR log and insert each entry as a full-flow record. Round-trips
    an export from this engagement: export-har then import-har reconstructs the
    flow metadata (flow_uid/auth/truncation/routing) from each entry's ``_vigil``
    field."""
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    har_payload = {"log": request.log}
    root = Path(engagement.engagement_root).resolve()
    flow_kwargs_list = await anyio.to_thread.run_sync(
        functools.partial(state_manager.flows_from_har, har_payload, root=root)
    )

    def _insert_all() -> list[dict[str, Any]]:
        return [
            state_manager.insert_http_flow(engagement.id, **kwargs)
            for kwargs in flow_kwargs_list
        ]

    records = await anyio.to_thread.run_sync(_insert_all)
    result = {"engagement_id": engagement.id, "count": len(records), "flows": records}
    await _broadcast(
        engagement.key,
        "http_flow_import",
        {"engagement_id": engagement.id, "count": len(records)},
    )
    return result


@router.get("/capture-policy")
def get_capture_policy(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_capture_policy(engagement.id)


@router.put("/capture-policy")
async def put_capture_policy(
    engagement_key: str, request: CapturePolicyUpdateRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.set_capture_policy,
            engagement.id,
            **request.model_dump(exclude_unset=True),
        )
    )
    await _broadcast(engagement.key, "capture_policy", {**record, "engagement_id": engagement.id})
    return record


@router.post("/probe-runs", status_code=status.HTTP_201_CREATED)
async def create_probe_run(engagement_key: str, request: ProbeRunRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.record_probe_run, engagement.id, **request.model_dump())
    )
    await _broadcast(engagement.key, "probe_run", record)
    return record


@router.post("/coverage-items", status_code=status.HTTP_201_CREATED)
async def create_coverage_item(engagement_key: str, request: CoverageItemRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.record_coverage_item, engagement.id, **request.model_dump())
    )
    await _broadcast(engagement.key, "coverage_item", record)
    return record


@router.post("/coverage-items/bulk", status_code=status.HTTP_201_CREATED)
async def create_coverage_items_bulk(
    engagement_key: str,
    request: CoverageItemBulkRecordRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    result = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_coverage_items_bulk,
            engagement.id,
            [item.model_dump() for item in request.items],
        )
    )
    await _broadcast(
        engagement.key,
        "coverage_item_bulk",
        {"engagement_id": engagement.id, "count": result["count"]},
    )
    return result


@router.post("/command-runs", status_code=status.HTTP_201_CREATED)
async def create_command_run(
    engagement_key: str,
    request: CommandRunRecordRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    payload = request.model_dump()
    if not payload.get("command_hash"):
        payload["command_hash"] = hashlib.sha256(
            payload["command"].encode("utf-8", errors="replace")
        ).hexdigest()
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.record_command_run, engagement.id, **payload)
    )
    await _broadcast(engagement.key, "command_run", record)
    return record


class HostExecRecord(CommandRunRecordRequest):
    """Audit payload for ``vigil assess host-exec``.

    Reuses ``CommandRunRecordRequest`` for full field parity with the kali
    route — the host-exec wrapper is just a different execution surface, not
    a different audit shape. The dedicated route exists so the server can
    force ``route='host_exec'`` regardless of client input, giving downstream
    queries a single discriminator between kali-container rows and
    host-machine rows.
    """


@router.post("/command-runs/host-exec", status_code=status.HTTP_201_CREATED)
async def record_host_exec(
    engagement_key: str,
    request: HostExecRecord,
) -> dict[str, Any]:
    """Audited host-machine command execution (gam, gcloud, az, splunk, jq, ...).

    Forces ``route='host_exec'`` server-side so the audit marker is reliable
    regardless of what the CLI sent. Otherwise identical to ``POST
    /command-runs``: the same retention, dedup, and artifact-spill logic in
    ``state_manager.record_command_run()`` applies.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    payload = request.model_dump()
    payload["route"] = "host_exec"  # canonical marker, never trust client input
    if not payload.get("command_hash"):
        payload["command_hash"] = hashlib.sha256(
            payload["command"].encode("utf-8", errors="replace")
        ).hexdigest()
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.record_command_run, engagement.id, **payload)
    )
    await _broadcast(engagement.key, "command_run", record)
    return record


@router.patch("/command-runs/{command_run_id}")
async def patch_command_run(
    engagement_key: str,
    command_run_id: int,
    request: CommandRunFinalize,
) -> dict[str, Any]:
    """Finalize a pre-exec command-run row written with status=running."""
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.finalize_command_run,
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
    )
    if not record.get("noop"):
        await _broadcast(engagement.key, "command_run", record)
    return record


@router.post("/jobs", status_code=status.HTTP_201_CREATED)
async def create_job(
    engagement_key: str,
    request: JobCreate,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_job,
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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_job,
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
    )
    await _broadcast(engagement.key, "job", record)
    return record


@router.post("/oob-probes", status_code=status.HTTP_201_CREATED)
async def create_oob_probe(engagement_key: str, request: OobProbeRecordRequest) -> dict[str, Any]:
    """Record an OAST probe (called by ``vigil oob mint``).

    Idempotent on ``nonce`` — re-minting the same nonce returns the existing
    row rather than erroring, so a retried CLI call is safe.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_oob_probe,
            engagement.id,
            nonce=request.nonce,
            target_url=request.target_url,
            param=request.param,
            technique=request.technique,
            probe_kind=request.probe_kind,
            request_hash=request.request_hash,
            oob_domain=request.oob_domain,
            notes=request.notes,
            status_value=request.status,
        )
    )
    await _broadcast(engagement.key, "oob_probe", record)
    return record


@router.post("/oob-probes/interactions")
async def record_oob_interaction(engagement_key: str, request: OobInteractionRecordRequest) -> dict[str, Any]:
    """Correlate one observed OAST callback to its probe by nonce (``vigil oob poll``).

    Returns ``{matched, duplicate, probe, interaction}``. An unknown nonce
    yields ``matched=False`` with HTTP 200 so the poller can collect stray
    callbacks under an "unmatched interactions" section instead of aborting.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    result = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.correlate_oob_interaction,
            engagement.id,
            nonce=request.nonce,
            protocol=request.protocol,
            remote_address=request.remote_address,
            query_type=request.query_type,
            raw_request=request.raw_request,
            observed_at=request.observed_at,
        )
    )
    if result.get("matched") and result.get("probe") and not result.get("duplicate"):
        await _broadcast(engagement.key, "oob_probe", result["probe"])
    return result


@router.post("/surfaces", status_code=status.HTTP_201_CREATED)
async def create_surface(engagement_key: str, request: SurfaceRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_surface,
            engagement.id,
            surface_type=request.surface_type,
            target_descriptor=request.target_descriptor,
            source_name=request.source_name,
            rationale=request.rationale,
            evidence_ref=request.evidence_ref,
            status_value=request.status,
        )
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
    the (surface_type, target_descriptor) UPSERT key. ``vigil assess
    resolve-surface`` is the helper that drives this endpoint.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_surface,
            engagement.id,
            surface_id,
            status_value=request.status,
            rationale=request.rationale,
            source_name=request.source_name,
            evidence_ref=request.evidence_ref,
            followup_condition=request.followup_condition,
        )
    )
    await _broadcast(engagement.key, "surface", record)
    return record


@router.post("/surface-request-variant-links", status_code=status.HTTP_201_CREATED)
async def create_surface_request_variant_link_endpoint(
    engagement_key: str,
    request: SurfaceRequestVariantLinkRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_surface_request_variant_link,
            engagement.id,
            surface_id=request.surface_id,
            request_variant_id=request.request_variant_id,
            relation=request.relation,
            evidence_ref=request.evidence_ref,
        )
    )
    await _broadcast(engagement.key, "surface_request_variant_link", record)
    return record


@router.get("/surface-request-variant-links/by-surface/{surface_id}")
def get_surface_request_variant_links_by_surface(
    engagement_key: str,
    surface_id: int,
    limit: int = Query(default=DEFAULT_SURFACE_LIMIT, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surface_request_variant_links_by_surface(
        engagement.id, surface_id, limit=limit, offset=offset
    )


@router.get("/surface-request-variant-links/by-request-variant/{request_variant_id}")
def get_surface_request_variant_links_by_variant(
    engagement_key: str,
    request_variant_id: int,
    limit: int = Query(default=DEFAULT_SURFACE_LIMIT, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_surface_request_variant_links_by_variant(
        engagement.id, request_variant_id, limit=limit, offset=offset
    )


class AppUnitOverrideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    override: Literal["mark-deep", "clear-deep"] | None = None
    reason: str | None = Field(default=None, max_length=2048)


@router.get("/application-units")
def get_application_units(engagement_key: str) -> list[dict[str, Any]]:
    """List scored app units (depth-gate §5.2). Read-only; advisory."""
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_application_units(engagement.id)


@router.get("/application-units/depth-ledger")
def get_depth_ledger(engagement_key: str) -> dict[str, Any]:
    """Read-only, ADVISORY depth ledger (depth-gate §5.3, Wave 6c).

    Per ``deep_required`` app unit: Expected vuln classes (each gated by an
    executable §5.3 predicate), Covered, missing block/warn classes, active
    depth deferrals, the structured dedicated-dispatch verdict, a per-unit
    ``depth_satisfied`` verdict, and an EV rank. EV-ranked, highest first.

    Mid-engagement this is ADVISORY ONLY — it never blocks a transition and the
    endpoint never returns non-2xx for missing depth (the terminal block is a
    later wave). WEB-ONLY: code/blue engagements get a skipped result.
    """
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.depth_ledger(engagement.id)


@router.get("/application-units/terminal-block")
def get_terminal_depth_block(engagement_key: str) -> dict[str, Any]:
    """The ONE hard block (Wave 7, S17 resolution; master plan §1A).

    Read-only. Returns the units that BLOCK the terminal ``report``/``complete``
    edge on the WEB track: the union of high-confidence ``deep_required`` units
    AND units carrying a decisive risk surface, intersected with
    unsatisfied + undeferred + UNTOUCHED. Under-observed / touched-but-unfinished
    units are LISTED in ``warned_under_observed`` (never block). ``deferral_count``
    makes the recorded-deferral rate visible.

    The endpoint itself NEVER returns non-2xx for missing depth — it is the
    ``transition-phase`` report/complete precondition that turns a non-empty
    ``blocking`` list into the hard transition block. WEB-ONLY: code/blue get
    ``skipped=True`` with empty ``blocking`` (reuses the ledger's web-only skip).
    """
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.terminal_depth_block(engagement.id)


@router.post("/application-units/score")
def score_application_units_endpoint(engagement_key: str) -> dict[str, Any]:
    """Run prefix discovery + the depth scorer (idempotent). WEB-ONLY guard
    inside the scorer makes this a no-op for code/blue engagements.

    Plain ``def`` (no broadcast / no await): FastAPI runs it in the threadpool
    so the synchronous DB scoring work never blocks the event loop (E1)."""
    engagement = get_engagement_or_404(engagement_key)
    result = state_manager.score_application_units(engagement.id)
    return result


@router.patch("/application-units/{unit_id}")
def update_application_unit_override(
    engagement_key: str,
    unit_id: int,
    request: AppUnitOverrideRequest,
) -> dict[str, Any]:
    """Set/clear the manual mark-deep/clear-deep override on an app unit.

    Driven by ``vigil assess app-unit mark-deep|clear-deep``. The override is
    durable and always wins over the scorer (depth-gate §5.2).

    Plain ``def`` (no broadcast / no await): FastAPI runs it in the threadpool
    so the synchronous DB write never blocks the event loop (E1).
    """
    engagement = get_engagement_or_404(engagement_key)
    try:
        record = state_manager.set_app_unit_override(
            engagement.id, unit_id, override=request.override, reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return record


@router.post("/findings/merge")
async def merge_findings_endpoint(engagement_key: str, request: MergeFindingsRequest) -> dict[str, Any]:
    """Merge a source finding into a target finding.

    The source finding's status becomes 'merged' and its evidence, notes, and
    links are folded into the target.  The stronger severity and status win.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.merge_findings,
            engagement.id,
            source_slug=request.source_slug,
            target_slug=request.target_slug,
            reason=request.reason,
            source_name=request.source_name,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="merge-findings",
            action=f"{request.source_slug} -> {request.target_slug}",
            actor_name=request.source_name,
            result=request.reason or "",
            metadata={"source_slug": request.source_slug, "target_slug": request.target_slug},
        )
    )
    await _broadcast(engagement.key, "finding_merge", record)
    return record


@router.post("/findings", status_code=status.HTTP_201_CREATED)
async def create_finding(engagement_key: str, request: FindingRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_finding,
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
            submission_status=request.submission_status,
            request_variant_id=request.request_variant_id,
            service_id=request.service_id,
            surface_id=request.surface_id,
            links=[item.model_dump() for item in request.links],
            allow_remint=request.allow_remint,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="record-finding",
            action=f"finding={record.get('slug', request.slug)} severity={record.get('severity', request.severity)}",
            actor_name=request.source_name,
            result=record.get("workflow_status", request.workflow_status) or "",
            metadata={"finding_slug": record.get("slug", request.slug), "source_name": request.source_name},
        )
    )
    await _broadcast(engagement.key, "finding", record)
    return record


@router.patch("/findings/{finding_slug}")
async def patch_finding(
    engagement_key: str,
    finding_slug: str,
    request: FindingPatchRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.patch_finding,
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
            notes_mode=request.notes_mode,
            source_name=request.source_name,
            details=request.details,
            details_mode=request.details_mode,
            provenance=request.provenance,
            evidence_type=request.evidence_type,
            submission_status=request.submission_status,
            transition_reason_code=request.reason_code,
            transition_reason_text=request.reason_text,
            transition_artifact_ref=request.artifact_ref,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="update-finding",
            action=f"finding={finding_slug}",
            actor_name=request.source_name,
            result=request.reason_code or request.reason_text or "",
            metadata={"finding_slug": finding_slug},
        )
    )
    await _broadcast(engagement.key, "finding_patch", record)
    return record


@router.put("/findings/{finding_slug}/root-cause")
async def set_finding_root_cause(
    engagement_key: str,
    finding_slug: str,
    request: RootCauseLinkRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.set_root_cause_link,
            engagement.id,
            finding_slug=finding_slug,
            root_cause_slug=request.root_cause_slug,
            sibling_order=request.sibling_order,
            root_cause_effect=request.root_cause_effect,
            note=request.note,
            source_name=request.source_name,
            provenance=request.provenance,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="link-finding",
            action=f"finding={finding_slug} root_cause={request.root_cause_slug}",
            actor_name=request.source_name,
            result=request.root_cause_effect,
            metadata={"finding_slug": finding_slug, "root_cause_slug": request.root_cause_slug},
        )
    )
    await _broadcast(engagement.key, "finding_root_cause", record)
    return record


@router.delete("/findings/{finding_slug}/root-cause")
async def clear_finding_root_cause(engagement_key: str, finding_slug: str) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(state_manager.clear_root_cause_link, engagement.id, finding_slug=finding_slug)
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="unlink-finding",
            action=f"finding={finding_slug} root_cause=clear",
            actor_name="operator",
            result=str(record.get("cleared", 0)),
            metadata={"finding_slug": finding_slug},
        )
    )
    await _broadcast(engagement.key, "finding_root_cause", record)
    return record


@router.post("/findings/{finding_slug}/links")
async def create_finding_link(
    engagement_key: str,
    finding_slug: str,
    request: FindingLinkRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    if request.link_kind == state_manager.ROOT_CAUSE_LINK_KIND:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="use PUT /findings/{slug}/root-cause for root-cause links",
        )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_finding_link,
            engagement.id,
            finding_slug=finding_slug,
            link_kind=request.link_kind,
            target_kind=request.target_kind,
            target_id=request.target_id,
            target_ref=request.target_ref,
            notes=request.notes,
            provenance=request.provenance,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-link",
            action=f"finding={finding_slug} link={request.link_kind}:{request.target_kind}:{request.target_ref}",
            actor_name="operator",
            result="linked",
            metadata={"finding_slug": finding_slug, "link_id": record.get("id")},
        )
    )
    await _broadcast(engagement.key, "finding_link", record)
    return record


@router.post("/findings/{finding_slug}/verify")
async def verify_finding(
    engagement_key: str,
    finding_slug: str,
    request: FindingVerifyRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.verify_finding,
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
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="verify-finding",
            action=f"finding={finding_slug} disposition={request.disposition}",
            actor_name=request.source_name,
            result=request.reason_code or request.reason_text or request.disposition,
            metadata={"finding_slug": finding_slug, "disposition": request.disposition},
        )
    )
    await _broadcast(engagement.key, "finding_verify", record)
    return record


@router.post("/attack-chains", status_code=status.HTTP_201_CREATED)
async def create_attack_chain(engagement_key: str, request: AttackChainRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_attack_chain,
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
    )
    await _broadcast(engagement.key, "attack_chain", record)
    return record


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def create_credential(engagement_key: str, request: CredentialRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_credential,
            engagement.id,
            credential_key=request.credential_key,
            kind=request.kind,
            principal=request.principal,
            secret=request.secret,
            source_name=request.source_name,
            status_value=request.status,
            notes=request.notes,
            provenance=request.provenance,
            identity=request.identity,
        )
    )
    await _broadcast(engagement.key, "credential", record)
    return record


@router.post("/credential-tests", status_code=status.HTTP_201_CREATED)
async def create_credential_test(engagement_key: str, request: CredentialTestRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_credential_test,
            engagement.id,
            credential_id=request.credential_id,
            service_id=request.service_id,
            target_ref=request.target_ref,
            auth_context=request.auth_context,
            outcome=request.outcome,
            evidence_ref=request.evidence_ref,
            notes=request.notes,
        )
    )
    await _broadcast(engagement.key, "credential_test", record)
    return record


@router.post("/access-records", status_code=status.HTTP_201_CREATED)
async def create_access_record(engagement_key: str, request: AccessRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_access_record,
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
    )
    await _broadcast(engagement.key, "access_record", record)
    return record


@router.patch("/coverage-items/{coverage_item_id}")
async def update_coverage_item(engagement_key: str, coverage_item_id: int, request: CoverageItemUpdateRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_coverage_item_status,
            engagement.id,
            coverage_item_id=coverage_item_id,
            status_value=request.status,
            notes=request.notes,
        )
    )
    await _broadcast(engagement.key, "coverage_item", record)
    return record


@router.post("/blocked-techniques", status_code=status.HTTP_201_CREATED)
async def create_blocked_technique(engagement_key: str, request: BlockedTechniqueRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_blocked_technique,
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
    )
    await _broadcast(engagement.key, "blocked_technique", record)
    return record


# ── Round 9: dispatch / handoff / decision endpoints ──────────────────────


_DISPATCH_STATUS = Literal["in-progress", "completed", "failed", "aborted", "blocked"]
_DISPATCH_TERMINAL_STATUS = Literal["completed", "failed", "aborted", "blocked"]
_KNOWN_DISPATCH_MODES: tuple[str, ...] = (
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
    "swarm",
)
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
    dispatch_mode: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Dispatch execution mode (free text). Advisory known modes: "
            + ", ".join(_KNOWN_DISPATCH_MODES)
        ),
    )
    finding_slugs: list[str] | None = None
    skills: str | None = Field(default=None, max_length=4096)
    tier: Literal["L1", "L2", "L3", "L4"] | None = None
    scope_path_prefix: str | None = Field(default=None, max_length=512)
    vuln_classes: str | None = Field(default=None, max_length=2048)
    identity: str | None = Field(default=None, max_length=128)
    allow_no_skills: bool = False

    @model_validator(mode="after")
    def _enforce_skills_for_specialists(self) -> "DispatchCreate":
        """Specialist dispatches must declare which skills the agent loaded.

        The dispatch row is the audit surface for "what context did this
        specialist actually carry"; without a skill list it loses the
        provenance report-writer relies on. Operators are exempt because
        they coordinate phases rather than executing a single skill. L2-2 /
        L3-6: `allow_no_skills=true` provides an explicit escape for ad-hoc
        roles so the recording path is not hard-blocked on a self-attested
        signal — per the harness-not-gate doctrine, prefer a loud WARN +
        proceed over a 422.
        """
        role = (self.agent_role or "").strip()
        if role.lower() in _DISPATCH_ROLES_WITHOUT_SKILLS:
            return self
        if self.allow_no_skills:
            return self
        skills = (self.skills or "").strip()
        if not skills:
            raise ValueError(
                f"skills is required for role '{role}'; "
                "list at least one skill name from `vigil assess list-skills` "
                "(or set allow_no_skills=true for an ad-hoc role)"
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
    closed_dispatch_status: _DISPATCH_TERMINAL_STATUS | None = None
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
    closed_dispatch_status: _DISPATCH_TERMINAL_STATUS | None = None
    extras: dict[str, Any] | None = None


_COVERAGE_DEFERRAL_OBJECTIVES = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "tech_fingerprint",
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
            "tech_fingerprint",
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

    # Objectives that legitimately apply to an entire engagement (a
    # program-wide scope rule, vendor-confirmed CDN/WAF, OSINT carve-out).
    # `service_inventory` and `tech_fingerprint` are intentionally per-host —
    # an engagement-wide deferral on those would silence every host's
    # gate signal without a per-host justification, which is the failure
    # mode the audit ledger is designed to prevent.
    _ENGAGEMENT_WIDE_ALLOWED_OBJECTIVES: tuple[str, ...] = (
        "osint",
        "waf_tier",
        "directory_fuzz",
    )

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
        if self.engagement_wide:
            disallowed = [
                obj
                for obj in self.deferred_objectives
                if obj not in self._ENGAGEMENT_WIDE_ALLOWED_OBJECTIVES
            ]
            if disallowed:
                raise ValueError(
                    "engagement_wide=true is only allowed for objectives "
                    f"{list(self._ENGAGEMENT_WIDE_ALLOWED_OBJECTIVES)}; "
                    f"{disallowed} are per-host signals and require an explicit "
                    "host / hosts[] field. If a program-wide rule really blocks "
                    "one of those, file a per-host deferral with the rationale."
                )
        return self


class ContainmentProposalPayload(BaseModel):
    """Strict shape for ``kind='containment_proposal'`` decision rows.

    Mirrors ``agent/schemas/containment-proposal.schema.json`` so the JSONL
    writer (``vigil assess record-proposal``) and the backend dispatch-decisions
    row written by ``vigil blue propose-contain`` enforce the same contract.
    Without this, a malformed proposal still records a row but is unsafe to
    approve+execute later (e.g. ``vigil assess approve-proposal`` flips
    ``resolved=true``, then ``vigil blue contain`` reads garbage from the
    payload). Catching shape errors at POST time keeps the approval ledger
    trustworthy.

    Extra fields are rejected so typos like ``actoin`` surface immediately.
    """

    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    platform: Literal["gws", "m365", "aws", "okta", "edr", "network", "generic"]
    rollback: str = Field(min_length=1)
    blast_radius: Literal["single-user", "multi-user", "multi-tenant", "cross-platform"]
    note: str | None = Field(default=None)
    finding_slug: str | None = Field(default=None)


class DepthDeferralPayload(BaseModel):
    """Strict shape for ``kind='depth_deferral'`` decision rows (depth-gate §5.3).

    Mirrors ``CoverageDeferralPayload``: the depth ledger consults active
    ``depth_deferral`` rows to decide whether an Expected vuln-class for an app
    unit has been EXPLICITLY skipped-with-reason. A malformed payload would
    silently fail to match (the class stays unmet), so the shape is validated at
    POST time. The deferral is bounded + visible: a recorded, surfaced decision,
    never a silent skip.

    Scope: either a specific ``(host, path_prefix)`` app boundary, OR
    ``engagement_wide=true`` (a program-wide carve-out for the listed classes).
    Each entry of ``vuln_classes`` is a canonical class token (from
    ``vuln_taxonomy``); the ledger resolves it to its family.
    """

    model_config = ConfigDict(extra="allow")

    vuln_classes: list[str] = Field(
        min_length=1,
        description="One or more canonical vuln classes the operator is "
                    "explicitly skipping for the app unit.",
    )
    reason: str = Field(
        min_length=1,
        description="Why the depth deferral was approved. Read by the ledger + audit views.",
    )
    host: str | None = Field(default=None, min_length=1)
    path_prefix: str | None = Field(default=None, min_length=1)
    engagement_wide: bool | None = Field(default=None)
    approved_by: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _require_host_or_engagement_wide(self) -> "DepthDeferralPayload":
        has_host = bool(self.host)
        if not has_host and not self.engagement_wide:
            raise ValueError(
                "depth_deferral payload requires a `host` (with optional "
                "`path_prefix`) or `engagement_wide=true`"
            )
        if has_host and self.engagement_wide:
            raise ValueError(
                "depth_deferral payload cannot mix `host` with "
                "`engagement_wide=true`; pick one or the other"
            )
        for cls in self.vuln_classes:
            if not isinstance(cls, str) or not cls.strip():
                raise ValueError(
                    "depth_deferral payload `vuln_classes` entries must be "
                    "non-empty strings"
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
    # (currently: ``coverage_deferral`` → ``per_host_coverage()``) OR by a
    # downstream approve+execute flow (``containment_proposal`` →
    # ``vigil blue contain``). For those, validate the payload shape at POST
    # time so malformed payloads can't silently neuter the gate that depends
    # on them, or get blindly approved and executed later.
    kind: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    surfaced_to_user: bool = False

    @model_validator(mode="after")
    def _validate_known_kind_payload(self) -> "DecisionCreate":
        if self.kind == "coverage_deferral":
            CoverageDeferralPayload.model_validate(self.payload)
        elif self.kind == "depth_deferral":
            try:
                DepthDeferralPayload.model_validate(self.payload)
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"depth_deferral payload invalid: {exc}",
                ) from exc
        elif self.kind == "containment_proposal":
            try:
                ContainmentProposalPayload.model_validate(self.payload)
            except Exception as exc:
                # Surface as 422 with the underlying detail so operators see
                # which field is invalid (matches the JSONL-side error from
                # ``vigil assess record-proposal``).
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"containment_proposal payload invalid: {exc}",
                ) from exc
        return self


class DecisionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: bool | None = None
    resolution: dict[str, Any] | None = None
    surfaced_to_user: bool | None = None


@router.post("/dispatches", status_code=status.HTTP_201_CREATED)
async def create_dispatch(engagement_key: str, request: DispatchCreate) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_dispatch,
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
            tier=request.tier,
            scope_path_prefix=request.scope_path_prefix,
            vuln_classes=request.vuln_classes,
            identity=request.identity,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent start",
            action=f"agent_id={request.agent_id} role={request.agent_role}",
            actor_name=request.agent_role,
            result=request.status,
            metadata={"agent_id": request.agent_id, "agent_role": request.agent_role},
        )
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
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_dispatches(
        engagement.id,
        role=role,
        status_value=status_value,
        since=since,
        task_q=task_q,
        limit=limit,
        offset=offset,
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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_dispatch,
            engagement.id,
            agent_id=agent_id,
            status_value=request.status,
            completed_at=request.completed_at,
            finding_slugs=request.finding_slugs,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent done",
            action=f"agent_id={agent_id}",
            actor_name=agent_id,
            result=request.status or "",
            metadata={"agent_id": agent_id, "finding_slugs": request.finding_slugs or []},
        )
    )
    await _broadcast(engagement.key, "dispatch", record)
    return record


@router.post("/dispatch-handoffs", status_code=status.HTTP_201_CREATED)
async def create_handoff(engagement_key: str, request: HandoffCreate) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_handoff,
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
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent handoff",
            action=f"agent_id={request.agent_id} role={request.agent_role}",
            actor_name=request.agent_role,
            result=request.summary,
            metadata={"agent_id": request.agent_id, "agent_role": request.agent_role},
        )
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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_handoff,
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
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent handoff",
            action=f"agent_id={agent_id}",
            actor_name=agent_id,
            result=request.summary or "",
            metadata={"agent_id": agent_id},
        )
    )
    await _broadcast(engagement.key, "dispatch_handoff", record)
    return record


@router.post("/dispatch-decisions", status_code=status.HTTP_201_CREATED)
async def create_decision(engagement_key: str, request: DecisionCreate) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_decision,
            engagement.id,
            kind=request.kind,
            payload=request.payload,
            surfaced_to_user=request.surfaced_to_user,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent decision",
            action=f"kind={request.kind}",
            result="surfaced_to_user" if request.surfaced_to_user else "",
            metadata={"kind": request.kind, "surfaced_to_user": request.surfaced_to_user},
        )
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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_decision,
            engagement.id,
            decision_id=int(decision_id),
            resolved=request.resolved,
            resolution=request.resolution,
            surfaced_to_user=request.surfaced_to_user,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent decision",
            action=f"decision_id={decision_id}",
            result="resolved" if request.resolved else "",
            metadata={"decision_id": int(decision_id)},
        )
    )
    await _broadcast(engagement.key, "dispatch_decision", record)
    return record
