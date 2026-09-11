from __future__ import annotations

import functools
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..models.engagement import Engagement
from ..retry_state import RETRY_STATES
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
    list_attempts,
)
# by_family_coverage lives in the depth_ledger submodule (it reuses the ledger's
# per-unit scope/expected/covered helpers); the package re-exports the
# ``depth_ledger`` FUNCTION under that name, shadowing the submodule attribute, so
# it is imported directly from the submodule rather than via ``state_manager``.
from ..services.state_manager.depth_ledger import by_family_coverage
from ..services.state_manager.http_flows import (
    CapturePolicyMirrorError,
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


class WorkItemUnitFetchRequest(BaseModel):
    unit_id: int | None = Field(default=None, ge=1)
    path: str = Field(default="", max_length=1024)
    work_class: str = Field(default="", max_length=64)
    limit: int | None = Field(default=None, ge=1, le=1000)
    agent: str = Field(default="auto", max_length=128)


class WorkItemIdsRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)


class WorkItemDeferItemsRequest(BaseModel):
    ids: list[int] = Field(default_factory=list)
    reason: str = Field(default="", max_length=1024)
    dry_run: bool = False


class WorkItemDeferClusterRequest(BaseModel):
    cluster_key: str = Field(default="", max_length=512)
    reason: str = Field(default="", max_length=1024)
    dry_run: bool = False


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
    triage_rationale: str | None = Field(default=None, max_length=4096)


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
    request_body_capture_status: str = Field(default="unknown", max_length=64)
    response_body_capture_status: str = Field(default="unknown", max_length=64)
    request_body_capture_error: str = Field(default="", max_length=1000)
    response_body_capture_error: str = Field(default="", max_length=1000)
    request_body_artifact_path: str | None = Field(default=None, max_length=1024)
    response_body_artifact_path: str | None = Field(default=None, max_length=1024)
    request_headers: dict[str, Any] = Field(default_factory=dict)
    response_headers: dict[str, Any] = Field(default_factory=dict)
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
    # A signal must name the application-level observation that distinguishes a
    # true positive from a status/size lookalike. The service demotes a signal
    # with no assertion to an inconclusive attempt, including for direct callers.
    outcome_assertion: str = Field(default="", max_length=1024)
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
    # 1b — work-buffer drain OVERRIDE. A covering probe carrying a
    # ``coverage_item_id`` drains its FK-linked work-items BY DEFAULT; passing an
    # explicit id list narrows the drain to exactly these ids instead (and fires
    # regardless of the covering gate). Marked ``done`` in the SAME transaction as
    # the probe insert so "remaining work" bucket counts and recorded probes can
    # never disagree. Unknown ids are silently skipped (mirrors POST
    # /work-items/done); an empty list keeps the default derivation.
    work_item_ids: list[int] = Field(default_factory=list)
    # 1b — surface advance OVERRIDE. A covering probe carrying a
    # ``request_variant_id`` advances its FK-linked (discovered) surface(s) to
    # ``partially-covered`` BY DEFAULT; passing an explicit surface id advances
    # exactly that surface instead (and fires regardless of the covering gate).
    resolve_surface_id: int | None = None
    # 1b — suppress the whole default FK-derived cascade (both the work-item drain
    # and the surface advance). Recording still writes the probe row; it just
    # leaves the buffer and surfaces untouched.
    no_drain: bool = False


class CoverageItemRecordRequest(BaseModel):
    """Create or update a class-typed coverage item.

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
    # phase is required from input; the command-run contract has no env-var
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
    # Command-run lifecycle fields. CLI pre-exec writes pass status=running
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

    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "running",
        "completed",
        "failed",
        "timed_out",
        "killed",
        "lost",
    ]
    return_code: int | None = Field(default=None, ge=-(2**31), le=2**31 - 1)
    ended_at: datetime
    duration_ms: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stdout_preview: str | None = Field(default=None, max_length=COMMAND_FINALIZE_PREVIEW_MAX_CHARS)
    stderr_preview: str | None = Field(default=None, max_length=COMMAND_FINALIZE_PREVIEW_MAX_CHARS)
    # Byte truth measured by the wrapper from the output file it owns. The
    # previews above are truncated, so they cannot supply it, and only the
    # ``host_exec`` lane spills through the backend's own retention machinery —
    # for every other route these are the sole source of a real byte count.
    stdout_bytes: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stderr_bytes: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stdout_sha256: str | None = Field(default=None, max_length=64)
    stderr_sha256: str | None = Field(default=None, max_length=64)
    timed_out: bool = False
    partial_results: bool = False
    peak_rss_bytes: int | None = Field(default=None, ge=0, le=2**63 - 1)
    cpu_user_seconds: float | None = Field(
        default=None, ge=0, le=10**12, allow_inf_nan=False
    )
    cpu_system_seconds: float | None = Field(
        default=None, ge=0, le=10**12, allow_inf_nan=False
    )
    output_quiesced: bool = True


class ArtifactRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=2048)
    kind: str = Field(default="", max_length=128)
    media_type: str = Field(default="", max_length=128)
    producer_agent_id: str | None = Field(default=None, max_length=256)
    producer_agent_role: str | None = Field(default=None, max_length=128)
    producer_command_run_id: int | None = Field(default=None, ge=1)
    related_finding_slug: str | None = Field(default=None, max_length=256)
    related_chain_key: str | None = Field(default=None, max_length=256)
    related_surface_id: int | None = Field(default=None, ge=1)
    related_request_variant_id: int | None = Field(default=None, ge=1)


class JobCreate(BaseModel):
    """Request body for POST /jobs — opens an assessment_jobs row.

    parent_command_run_id links the pre-exec command audit owned by the async
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
    client_name: str = Field(min_length=1, max_length=128, pattern=r".*\S.*")
    client_payload_host: str = Field(min_length=1, max_length=256, pattern=r".*\S.*")
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
    client_name: str = Field(min_length=1, max_length=128, pattern=r".*\S.*")
    client_payload_host: str = Field(min_length=1, max_length=256, pattern=r".*\S.*")


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
    secret: str = Field(
        default="",
        max_length=8192,
        description="Literal secret value (password, token, or key material), preserved verbatim.",
    )
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
    retry_state: str = Field(default="pending", min_length=1, max_length=64)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)
    revalidation_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("retry_state")
    @classmethod
    def validate_retry_state(cls, value: str) -> str:
        if value not in RETRY_STATES:
            raise ValueError(
                "retry_state must be one of " + ", ".join(RETRY_STATES)
            )
        return value


class FindingLinkRequest(BaseModel):
    link_kind: str = Field(default="related", min_length=1, max_length=64)
    target_kind: str = Field(min_length=1, max_length=64)
    target_id: int | None = None
    target_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=4096)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_one_target_selector(self) -> FindingLinkRequest:
        has_id = self.target_id is not None
        has_ref = bool(self.target_ref.strip())
        if has_id == has_ref:
            raise ValueError("provide exactly one of target_id or target_ref")
        return self


class FindingLinkPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: str | None = Field(default=None, min_length=1, max_length=64)
    target_id: int | None = None
    target_ref: str | None = Field(default=None, max_length=1024)
    notes: str | None = Field(default=None, max_length=4096)
    provenance: dict[str, Any] | None = None
    retired: bool | None = None

    @model_validator(mode="after")
    def validate_patch(self) -> FindingLinkPatchRequest:
        provided = self.model_fields_set
        if not provided:
            raise ValueError("finding link patch requires at least one field")
        if {"target_id", "target_ref"} <= provided:
            raise ValueError("provide only one of target_id or target_ref")
        if "target_kind" in provided and not (
            {"target_id", "target_ref"} & provided
        ):
            raise ValueError("changing target_kind requires a target selector")
        return self


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
    expected_source_row_version: int | None = Field(default=None, ge=1)
    expected_target_row_version: int | None = Field(default=None, ge=1)


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


class CodeSnapshotProvenance(BaseModel):
    """Immutable identity of the verified source snapshot behind a code finding."""

    model_config = ConfigDict(extra="forbid")

    repo_id: int = Field(
        ge=1,
        description="code_repos.id for the source snapshot reviewed for this finding.",
    )
    repo_generation: int = Field(
        ge=1,
        description="The repository active_generation reviewed for this finding.",
    )
    source_manifest_digest: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="The repository source_manifest_digest reviewed for this finding.",
    )


class FindingProvenance(BaseModel):
    """Typed reserved provenance with forward-compatible producer metadata."""

    model_config = ConfigDict(extra="allow")

    code_snapshot: CodeSnapshotProvenance | None = None


class FindingRunCandidatePromotion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: int = Field(ge=1)
    candidate_id: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=8192)
    proof_receipt_ids: list[int] = Field(min_length=1, max_length=1000)


class FindingRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str | None = Field(default=None, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    # Default aligned to the CLI + finding-record contract (both `medium`): a
    # not-yet-triaged finding is presumed real, not informational. `info` was the
    # lone outlier here and produced a schema default that contradicted the CLI;
    # since severity feeds report-inclusion, defaulting low risked silently
    # under-rating untriaged findings. Only affects requests that OMIT severity;
    # stored rows keep their own value (DB-read compat unaffected).
    severity: str = Field(default="medium", min_length=1, max_length=32)
    workflow_status: str = Field(default="active", min_length=1, max_length=32)
    verification_status: Literal["unreviewed"] = "unreviewed"
    defect_family: str = Field(default="", max_length=128)
    root_cause_key: str = Field(default="", max_length=256)
    auth_context: str = Field(default="anonymous", min_length=1, max_length=128)
    canonical_location: str = Field(default="", max_length=4096)
    summary: str = Field(default="", max_length=4096)
    evidence_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=state_manager.FINDING_NOTES_MAX_LENGTH)
    source_name: str = Field(default="", max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: FindingProvenance = Field(default_factory=FindingProvenance)
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
    # The submission axis's IDENTITY. Required by the model validator below on a
    # NEW transition into a non-'none' status; nullable so an untouched legacy row
    # stays writable and a plain re-record never has to restate it.
    submission_platform: str | None = Field(default=None, max_length=64)
    submission_ref: str | None = Field(default=None, max_length=256)
    submission_url: str | None = Field(default=None, max_length=2048)
    request_variant_id: int | None = None
    service_id: int | None = None
    surface_id: int | None = None
    links: list[FindingLinkRequest] = Field(default_factory=list)
    run_candidate: FindingRunCandidatePromotion | None = None
    # D4 (kill re-mint override): control flag, NOT a stored column. When true it
    # skips the killed-finding re-mint guard so an intentional distinct re-mint of
    # a finding that only coincidentally shares an endpoint + technique with a prior
    # false_positive still lands. Plumbed from `finding record --allow-remint/--force`.
    allow_remint: bool = Field(default=False)

    @field_validator("canonical_location")
    @classmethod
    def _normalize_canonical_location(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _root_cause_links_use_helper(self) -> "FindingRecordRequest":
        if any(link.link_kind == state_manager.ROOT_CAUSE_LINK_KIND for link in self.links):
            raise ValueError("root_cause links must be created with `finding link` / PUT /findings/{slug}/root-cause")
        return self

    @model_validator(mode="after")
    def _validate_submission_status(self) -> "FindingRecordRequest":
        _reject_invalid_submission_status(self.submission_status)
        return self

    @model_validator(mode="after")
    def _require_code_snapshot_for_file_finding(self) -> FindingRecordRequest:
        if self.canonical_location.startswith("file:") and self.provenance.code_snapshot is None:
            raise ValueError(
                "file findings require provenance.code_snapshot bound to the current verified repository snapshot"
            )
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
    # The replace/rotate ceiling is deliberately HIGHER than the append cap: the
    # column grew unbounded for years, so the repair write is the one that has to
    # be able to carry a whole over-cap field. An append is bounded where it
    # actually grows, in ``_common._append_notes``.
    notes: str | None = Field(
        default=None, max_length=state_manager.FINDING_NOTES_REPLACE_MAX_LENGTH
    )
    # "append" (default) keeps the historical checkpoint behavior; "replace"
    # overwrites notes so stale/contradicted internal text can be scrubbed;
    # "rotate" banks the accumulated notes on the transition ledger and leaves a
    # pointer behind — the exit for a row already past the append cap.
    notes_mode: Literal["append", "replace", "rotate"] = "append"
    source_name: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] | None = None
    # CR-31: "merge" (default) accretes detail KEYS across checkpoints but
    # REPLACES a repeated key's whole value; "replace" overwrites the whole
    # details object so cross-contaminated/stale keys can be fully removed (merge
    # cannot delete keys); "append" is the non-destructive sibling of merge —
    # lists concatenate, objects deep-merge, and a scalar is refused rather than
    # silently concatenated. "replace" requires details to be present.
    details_mode: Literal["merge", "replace", "append"] = "merge"
    provenance: dict[str, Any] | None = None
    # Allow retroactive labeling via vigil assess finding update.
    evidence_type: Literal[
        "network-confirmed", "code-inferred", "theoretical", "informational"
    ] | None = None
    # Optional on patch: None preserves the stored submission_status (the
    # workflow axis can move without disturbing the submission axis). Validated
    # against the canonical state_manager.SUBMISSION_STATUSES set.
    submission_status: str | None = Field(default=None, min_length=1, max_length=32)
    submission_platform: str | None = Field(default=None, max_length=64)
    submission_ref: str | None = Field(default=None, max_length=256)
    submission_url: str | None = Field(default=None, max_length=2048)
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(default="", max_length=4096)
    artifact_ref: str = Field(default="", max_length=1024)
    expected_row_version: int | None = Field(default=None, ge=1)

    @field_validator("canonical_location")
    @classmethod
    def _normalize_canonical_location(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None

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
    def _bound_appended_notes(self) -> "FindingPatchRequest":
        # The raised ceiling exists for the repair write only. An append still
        # has to respect the cap the accumulator is bounded at, or the delta
        # alone could exceed what the column may hold.
        if (
            self.notes_mode == "append"
            and self.notes is not None
            and len(self.notes) > state_manager.FINDING_NOTES_MAX_LENGTH
        ):
            raise ValueError(
                "appended notes must be at most "
                f"{state_manager.FINDING_NOTES_MAX_LENGTH} characters; "
                "use notes_mode='replace' or 'rotate' to rewrite the whole field"
            )
        return self

    @model_validator(mode="after")
    def _require_details_when_replacing(self) -> "FindingPatchRequest":
        # details_mode='replace' overwrites the column; without a details payload
        # it would silently null it. Reject (mirrors the notes_mode guard).
        if self.details_mode == "replace" and self.details is None:
            raise ValueError("details_mode='replace' requires details")
        return self

    @model_validator(mode="after")
    def _require_cas_when_replacing(self) -> "FindingPatchRequest":
        if (
            self.notes_mode in {"replace", "rotate"}
            or self.details_mode == "replace"
        ) and self.expected_row_version is None:
            raise ValueError(
                "replacement modes require expected_row_version"
            )
        return self

    @model_validator(mode="after")
    def _require_mutation(self) -> "FindingPatchRequest":
        scalar_values = (
            self.title,
            self.severity,
            self.workflow_status,
            self.defect_family,
            self.root_cause_key,
            self.auth_context,
            self.canonical_location,
            self.summary,
            self.evidence_ref,
            self.source_name,
            self.evidence_type,
            self.submission_status,
            self.submission_platform,
            self.submission_ref,
            self.submission_url,
        )
        has_scalar_mutation = any(value not in (None, "") for value in scalar_values)
        has_notes_mutation = self.notes_mode == "rotate" or (
            self.notes is not None
            and (self.notes != "" or self.notes_mode == "replace")
        )
        has_details_mutation = self.details is not None and (
            self.details != {} or self.details_mode == "replace"
        )
        has_provenance_mutation = self.provenance not in (None, {})
        if not any(
            (
                has_scalar_mutation,
                has_notes_mutation,
                has_details_mutation,
                has_provenance_mutation,
            )
        ):
            raise ValueError(
                "finding patch requires at least one field that updates the finding; "
                "concurrency, mode, and transition-metadata controls do not update a "
                "finding by themselves, and empty merge values are no-ops"
            )
        return self

    @model_validator(mode="after")
    def _protect_code_snapshot_binding(self) -> FindingPatchRequest:
        if self.provenance is not None and "code_snapshot" in self.provenance:
            raise ValueError(
                "provenance.code_snapshot is reserved and cannot be changed by a generic finding patch"
            )
        return self


class FindingCounterCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str = Field(min_length=1, max_length=4096)
    expected_result: str = Field(min_length=1, max_length=4096)
    observed_result: str = Field(min_length=1, max_length=4096)
    falsified_claim: str = Field(min_length=1, max_length=4096)
    completed: bool
    proof_receipt_ids: list[int] = Field(min_length=1)


class FindingSeverityVarianceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    normal_band: Literal["info", "low", "medium", "high", "critical"]
    chosen_severity: Literal["info", "low", "medium", "high", "critical"]
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=4096)
    proof_receipt_id: int = Field(ge=1)


class FindingVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification_status: Literal[
        "confirmed",
        "downgraded",
        "pending_runtime_proof",
        "blocked",
        "false_positive",
        "disputed",
    ]
    reason_code: str = Field(default="", max_length=128)
    reason_text: str = Field(min_length=1, max_length=4096)
    new_severity: str | None = Field(default=None, min_length=1, max_length=32)
    evidence_ref: str = Field(default="", max_length=1024)
    artifact_ref: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=state_manager.FINDING_NOTES_MAX_LENGTH)
    source_name: str = Field(default="", max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    provenance: FindingProvenance = Field(default_factory=FindingProvenance)
    proof_receipt_ids: list[int] = Field(default_factory=list)
    counter_check: FindingCounterCheckRequest | None = None
    severity_variance: FindingSeverityVarianceRequest | None = None


class AssessmentRunSourceGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_key: str = Field(min_length=1, max_length=512)
    generation: int | None = Field(default=None, ge=0)
    manifest_digest: str | None = Field(default=None, min_length=64, max_length=64)
    inventory_commitment_version: Literal["v1"] | None = None
    inventory_count: int | None = Field(default=None, ge=0)
    inventory_digest: str | None = Field(default=None, min_length=64, max_length=64)


class AssessmentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_uuid: str = Field(min_length=1, max_length=128)
    run_kind: Literal["code", "web", "blue", "shared"]
    run_purpose: Literal["proof", "scan"] = "proof"
    producer_dispatch_agent_id: str = Field(min_length=1, max_length=128)
    target_identity: dict[str, Any] = Field(default_factory=dict)
    source_generations: list[AssessmentRunSourceGenerationRequest] = Field(
        default_factory=list
    )
    exclusions: list[dict[str, Any]] = Field(default_factory=list)
    resumed_from_run_id: int | None = Field(default=None, ge=1)


class AssessmentRunTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "running", "partial", "completed", "failed", "interrupted", "canceled"
    ]
    reason: str = Field(default="", max_length=4096)


class AssessmentRunSourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_key: str = Field(min_length=1, max_length=512)
    declared_root: str = Field(min_length=1, max_length=4096)
    path: str = Field(min_length=1, max_length=4096)
    content_sha256: str = Field(min_length=64, max_length=64)
    byte_size: int = Field(ge=0)
    line_count: int = Field(ge=0)
    encoding: str = Field(min_length=1, max_length=64)
    inventory_status: Literal["included", "excluded", "missing"]
    exclusion_reason: str = Field(default="", max_length=4096)
    parser_status: Literal["parsed", "failed", "not_applicable"]
    parser_error: str = Field(default="", max_length=4096)


class AssessmentRunSourcesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[AssessmentRunSourceRequest] = Field(min_length=1, max_length=10000)


class AssessmentRunSourceReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: int = Field(ge=1)
    dispatch_agent_id: str = Field(min_length=1, max_length=128)
    attempt: int = Field(ge=1)
    byte_start: int = Field(ge=0)
    byte_end: int = Field(ge=0)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    proof_receipt_id: int | None = Field(default=None, ge=1)


class AssessmentRunObligationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_key: str = Field(min_length=1, max_length=1024)
    obligation_kind: str = Field(min_length=1, max_length=128)
    object_type: str = Field(min_length=1, max_length=128)
    object_key: str = Field(min_length=1, max_length=4096)
    hard: bool = True
    status: Literal["open", "resolved", "blocked", "deferred", "accepted_gap"] = "open"
    resolution: str = Field(default="", max_length=8192)
    proof_receipt_ids: list[int] = Field(default_factory=list, max_length=1000)


class AssessmentRunObligationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["resolved", "blocked", "deferred", "accepted_gap"]
    resolution: str = Field(min_length=1, max_length=8192)
    proof_receipt_ids: list[int] = Field(default_factory=list, max_length=1000)


class AssessmentRunCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_key: str = Field(min_length=1, max_length=1024)
    target_key: str = Field(min_length=1, max_length=512)
    source_id: int | None = Field(default=None, ge=1)
    source_anchor: str = Field(min_length=1, max_length=4096)
    vulnerability_family: str = Field(min_length=1, max_length=128)
    hypothesis: str = Field(min_length=1, max_length=8192)
    originating_result_id: int | None = Field(default=None, ge=1)
    dispatch_agent_id: str = Field(min_length=1, max_length=128)
    proof_receipt_ids: list[int] = Field(default_factory=list, max_length=1000)
    state: Literal["open"] = "open"
    finding_slug: str = Field(default="", max_length=128)


class AssessmentRunCandidateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["promoted", "rejected", "duplicate", "deferred"]
    reason: str = Field(min_length=1, max_length=8192)
    proof_receipt_ids: list[int] = Field(default_factory=list, max_length=1000)
    finding_slug: str = Field(default="", max_length=128)


class AssessmentRunToolSignalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_key: str = Field(min_length=1, max_length=1024)
    signal_kind: Literal[
        "sanitizer_violation", "reproducible_crash", "attributed_oob_callback"
    ]
    dispatch_agent_id: str = Field(min_length=1, max_length=128)
    target_key: str = Field(min_length=1, max_length=512)
    source_id: int | None = Field(default=None, ge=1)
    source_anchor: str = Field(min_length=1, max_length=4096)
    vulnerability_family: str = Field(min_length=1, max_length=128)
    hypothesis: str = Field(min_length=1, max_length=8192)
    observed_signature: str = Field(min_length=1, max_length=8192)
    exact_input_sha256: str = Field(default="", max_length=64)
    command_run_id: int | None = Field(default=None, ge=1)
    proof_receipt_ids: list[int] = Field(min_length=1, max_length=1000)


class AssessmentRunDiscoveryPassRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_key: str = Field(min_length=1, max_length=1024)
    dispatch_agent_id: str = Field(min_length=1, max_length=128)
    frontier_identity_sha256: str = Field(min_length=64, max_length=64)
    terminal_reason: Literal[
        "frontier_exhausted", "no_new_candidates", "cap_reached", "interrupted", "failed"
    ]
    candidate_identity_keys: list[
        Annotated[str, Field(min_length=1, max_length=1024)]
    ] = Field(default_factory=list, max_length=10000)
    proof_receipt_ids: list[int] = Field(min_length=1, max_length=1000)


class AssessmentRunCodeReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_kind: Literal["variant_check", "fuzz_decision", "fuzz_campaign"]
    receipt_id: int = Field(ge=1)
    target_key: str = Field(min_length=1, max_length=512)
    obligation_id: int = Field(ge=1)
    candidate_ids: list[int] = Field(default_factory=list, max_length=1000)
    signal_ids: list[int] = Field(default_factory=list, max_length=1000)
    proof_receipt_ids: list[int] = Field(min_length=1, max_length=1000)


class AssessmentRunComparisonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_run_id: int | None = Field(default=None, ge=1)


class ProofReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: int = Field(ge=1)
    evidence_kind: Literal[
        "source_observation",
        "command",
        "http_exchange",
        "browser_action",
        "oob_event",
        "artifact",
    ]
    expected_result: str = Field(default="", max_length=4096)
    observed_result: str = Field(default="", max_length=4096)
    artifact_id: int | None = Field(default=None, ge=1)
    source_read_id: int | None = Field(default=None, ge=1)
    command_run_id: int | None = Field(default=None, ge=1)
    evidence_sha256: str = Field(default="", max_length=64)
    evidence_health: Literal["healthy", "missing", "stale", "tombstoned"] = "healthy"
    tombstone_reason: str = Field(default="", max_length=1024)


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


@router.get("/coverage-readiness/by-family")
def get_by_family_coverage(engagement_key: str) -> dict[str, Any]:
    """A1 — engagement-wide (application-unit × vuln-family) coverage grid.

    Complements ``/coverage-readiness/by-host`` (per-host recon outcomes) with a
    per-unit, per-family view: every application unit (INCLUDING non-deep_required
    ones) and, for each, one cell per vuln family in ``union(expected, probed)``
    tagged covered / missing_block / missing_warn / deferred with its probe and
    finding-linkage stats. Read-only/advisory — operators use it to SEE
    never-probed gaps vs probed-and-walled vs finding-linked before a phase exit.
    """
    engagement = get_engagement_or_404(engagement_key)
    with state_manager.get_connection() as connection:
        return by_family_coverage(connection, engagement.id)


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
    """Consolidated phase-keyed readiness.

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
    status: str = "",
    attack_family: str = "",
    input_slot: str = "",
    auth_context: str = "",
    target_host: str = "",
    request_variant_id: int | None = Query(default=None, ge=1),
    service_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=DEFAULT_COVERAGE_ITEM_LIMIT, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_coverage_items(
        engagement.id,
        status=status,
        attack_family=attack_family,
        input_slot=input_slot,
        auth_context=auth_context,
        target_host=target_host,
        request_variant_id=request_variant_id,
        service_id=service_id,
        limit=limit,
        offset=offset,
    )


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


@router.get("/attempts")
def get_attempts(
    engagement_key: str,
    finding: str = "",
    surface_id: int | None = None,
    target_host: str = "",
    attack_family: str = "",
    result_status: str = "",
    lens: str = "",
    limit: int = Query(default=DEFAULT_PROBE_RUN_LIMIT, ge=1, le=MAX_PROBE_RUN_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """A4a — finding-joined, surface-aware read of recorded probe attempts.

    A "what has actually been tried against this finding/surface/host, and did it
    land" view so a specialist does not re-run an already-walled probe. Additive to
    ``GET /probe-runs`` (unchanged): each attempt carries the linked finding's
    slug/title/severity (null when unlinked). ``finding`` is a finding SLUG
    (resolved server-side); ``surface_id`` matches BOTH FK-linked probes and probes
    whose target host/path is contained by the surface descriptor.
    """
    engagement = get_engagement_or_404(engagement_key)
    return list_attempts(
        engagement.id,
        finding=finding,
        surface_id=surface_id,
        target_host=target_host,
        attack_family=attack_family,
        result_status=result_status,
        lens=lens,
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
    auth_context: str = "",
    audit_source: str = "",
    route: str = "",
    success: bool | None = Query(default=None),
    timed_out: bool | None = Query(default=None),
    output_attention: bool = False,
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
    limit: int = Query(default=100, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
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
        auth_context=auth_context,
        audit_source=audit_source,
        route=route,
        success=success,
        timed_out=timed_out,
        output_attention=output_attention,
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


@router.get("/command-runs/foreign-lane-recency")
def get_foreign_lane_command_recency(
    engagement_key: str,
    agent_name: str = "",
) -> dict[str, int | str | None]:
    """One-row all-history coordination context for target-facing commands."""
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.foreign_lane_target_facing_recency(
        engagement.id, current_agent=agent_name
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


@router.post("/artifacts/{artifact_id}/refresh")
async def refresh_one_artifact(
    engagement_key: str, artifact_id: int
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    result = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.refresh_artifacts,
            engagement.id,
            artifact_id=artifact_id,
        )
    )
    await _broadcast(engagement.key, "artifact_refresh", result)
    return result


@router.delete("/artifacts/{artifact_id}/finding-link")
async def clear_artifact_finding_link(
    engagement_key: str, artifact_id: int
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    row = await anyio.to_thread.run_sync(
        functools.partial(
            artifact_index.clear_finding_link,
            engagement.id,
            artifact_id=artifact_id,
        )
    )
    await _broadcast(engagement.key, "artifact", row)
    return row


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
    verification_status: str | None = None,
    auth_context: str | None = None,
    source_name: str | None = None,
    slug: str | None = None,
    search: str | None = None,
    holding: bool = False,
    limit: int | None = Query(default=None, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_findings(
        engagement.id,
        severity=severity,
        workflow_status=workflow_status,
        verification_status=verification_status,
        auth_context=auth_context,
        source_name=source_name,
        slug=slug,
        search=search,
        holding=holding,
        limit=limit,
        offset=offset,
    )


@router.post("/assessment-runs", status_code=status.HTTP_201_CREATED)
async def create_assessment_run(
    engagement_key: str, request: AssessmentRunRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_assessment_run,
            engagement.id,
            run_uuid=request.run_uuid,
            run_kind=request.run_kind,
            run_purpose=request.run_purpose,
            producer_dispatch_agent_id=request.producer_dispatch_agent_id,
            target_identity=request.target_identity,
            source_generations=[
                generation.model_dump(exclude_none=True)
                for generation in request.source_generations
            ],
            exclusions=request.exclusions,
            resumed_from_run_id=request.resumed_from_run_id,
        )
    )
    await _broadcast(engagement.key, "assessment_run", record)
    return record


@router.get("/assessment-runs")
def get_assessment_runs(
    engagement_key: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_assessment_runs(
        engagement.id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}")
def get_assessment_run(engagement_key: str, run_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_assessment_run(engagement.id, run_id)


@router.patch("/assessment-runs/{run_id}")
async def transition_assessment_run(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunTransitionRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.transition_assessment_run,
            engagement.id,
            run_id=run_id,
            status_value=request.status,
            reason=request.reason,
        )
    )
    await _broadcast(engagement.key, "assessment_run", record)
    return record


@router.post("/assessment-runs/{run_id}/sources", status_code=status.HTTP_201_CREATED)
def record_assessment_run_sources(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunSourcesRequest,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_sources(
        engagement.id,
        run_id=run_id,
        sources=[source.model_dump() for source in request.sources],
    )


@router.get("/assessment-runs/{run_id}/sources")
def get_assessment_run_sources(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_sources(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.post(
    "/assessment-runs/{run_id}/source-reads", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_source_read(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunSourceReadRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_source_read(
        engagement.id,
        run_id=run_id,
        source_id=request.source_id,
        dispatch_agent_id=request.dispatch_agent_id,
        attempt=request.attempt,
        byte_start=request.byte_start,
        byte_end=request.byte_end,
        line_start=request.line_start,
        line_end=request.line_end,
        proof_receipt_id=request.proof_receipt_id,
    )


@router.get("/assessment-runs/{run_id}/source-reads")
def get_assessment_run_source_reads(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_source_reads(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/dispatches")
def get_assessment_run_dispatches(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_dispatches(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/proof-receipts")
def get_assessment_run_proof_receipts(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_proof_receipts(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/commands")
def get_assessment_run_commands(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_command_receipts(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/observed-events")
def get_assessment_run_observed_events(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_observed_events(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/decision-history")
def get_assessment_run_decision_history(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_decision_history(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.post(
    "/assessment-runs/{run_id}/obligations", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_obligation(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunObligationRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_obligation(
        engagement.id,
        run_id=run_id,
        identity_key=request.identity_key,
        obligation_kind=request.obligation_kind,
        object_type=request.object_type,
        object_key=request.object_key,
        hard=request.hard,
        status_value=request.status,
        resolution=request.resolution,
        proof_receipt_ids=request.proof_receipt_ids,
    )


@router.get("/assessment-runs/{run_id}/obligations")
def get_assessment_run_obligations(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_obligations(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.patch("/assessment-runs/{run_id}/obligations/{obligation_id}")
def update_assessment_run_obligation(
    engagement_key: str,
    run_id: int,
    obligation_id: int,
    request: AssessmentRunObligationUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.update_run_obligation(
        engagement.id,
        run_id=run_id,
        obligation_id=obligation_id,
        status_value=request.status,
        resolution=request.resolution,
        proof_receipt_ids=request.proof_receipt_ids,
    )


@router.get("/assessment-runs/{run_id}/obligations/{obligation_id}/history")
def get_assessment_run_obligation_history(
    engagement_key: str,
    run_id: int,
    obligation_id: int,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_obligation_history(
        engagement.id, run_id=run_id, obligation_id=obligation_id
    )


@router.post(
    "/assessment-runs/{run_id}/candidates", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_candidate(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunCandidateRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_candidate(
        engagement.id,
        run_id=run_id,
        identity_key=request.identity_key,
        target_key=request.target_key,
        source_id=request.source_id,
        source_anchor=request.source_anchor,
        vulnerability_family=request.vulnerability_family,
        hypothesis=request.hypothesis,
        originating_result_id=request.originating_result_id,
        dispatch_agent_id=request.dispatch_agent_id,
        proof_receipt_ids=request.proof_receipt_ids,
        state_value=request.state,
        finding_slug=request.finding_slug,
    )


@router.get("/assessment-runs/{run_id}/candidates")
def get_assessment_run_candidates(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_candidates(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.patch("/assessment-runs/{run_id}/candidates/{candidate_id}")
def update_assessment_run_candidate(
    engagement_key: str,
    run_id: int,
    candidate_id: int,
    request: AssessmentRunCandidateUpdate,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.update_run_candidate(
        engagement.id,
        run_id=run_id,
        candidate_id=candidate_id,
        state_value=request.state,
        reason=request.reason,
        proof_receipt_ids=request.proof_receipt_ids,
        finding_slug=request.finding_slug,
    )


@router.get("/assessment-runs/{run_id}/candidates/{candidate_id}/history")
def get_assessment_run_candidate_history(
    engagement_key: str,
    run_id: int,
    candidate_id: int,
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_candidate_history(
        engagement.id, run_id=run_id, candidate_id=candidate_id
    )


@router.post(
    "/assessment-runs/{run_id}/tool-signals", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_tool_signal(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunToolSignalRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_tool_signal(
        engagement.id,
        run_id=run_id,
        identity_key=request.identity_key,
        signal_kind=request.signal_kind,
        dispatch_agent_id=request.dispatch_agent_id,
        target_key=request.target_key,
        source_id=request.source_id,
        source_anchor=request.source_anchor,
        vulnerability_family=request.vulnerability_family,
        hypothesis=request.hypothesis,
        observed_signature=request.observed_signature,
        exact_input_sha256=request.exact_input_sha256,
        command_run_id=request.command_run_id,
        proof_receipt_ids=request.proof_receipt_ids,
    )


@router.get("/assessment-runs/{run_id}/tool-signals")
def get_assessment_run_tool_signals(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_tool_signals(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.post(
    "/assessment-runs/{run_id}/discovery-passes",
    status_code=status.HTTP_201_CREATED,
)
def record_assessment_run_discovery_pass(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunDiscoveryPassRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_discovery_pass(
        engagement.id,
        run_id=run_id,
        identity_key=request.identity_key,
        dispatch_agent_id=request.dispatch_agent_id,
        frontier_identity_sha256=request.frontier_identity_sha256,
        terminal_reason=request.terminal_reason,
        candidate_identity_keys=request.candidate_identity_keys,
        proof_receipt_ids=request.proof_receipt_ids,
    )


@router.get("/assessment-runs/{run_id}/discovery-passes")
def get_assessment_run_discovery_passes(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_discovery_passes(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.post(
    "/assessment-runs/{run_id}/code-receipts", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_code_receipt(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunCodeReceiptRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_run_code_receipt_link(
        engagement.id,
        run_id=run_id,
        receipt_kind=request.receipt_kind,
        receipt_id=request.receipt_id,
        target_key=request.target_key,
        obligation_id=request.obligation_id,
        candidate_ids=request.candidate_ids,
        signal_ids=request.signal_ids,
        proof_receipt_ids=request.proof_receipt_ids,
    )


@router.get("/assessment-runs/{run_id}/code-receipts")
def get_assessment_run_code_receipts(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_code_receipt_links(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.get("/assessment-runs/{run_id}/comparison")
def compare_assessment_run(
    engagement_key: str,
    run_id: int,
    baseline_run_id: int | None = Query(default=None, ge=1),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.compare_assessment_runs(
        engagement.id, run_id=run_id, baseline_run_id=baseline_run_id
    )


@router.post(
    "/assessment-runs/{run_id}/comparisons", status_code=status.HTTP_201_CREATED
)
def record_assessment_run_comparison(
    engagement_key: str,
    run_id: int,
    request: AssessmentRunComparisonRequest,
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.record_assessment_run_comparison(
        engagement.id,
        run_id=run_id,
        baseline_run_id=request.baseline_run_id,
    )


@router.get("/assessment-runs/{run_id}/comparisons")
def get_assessment_run_comparisons(
    engagement_key: str,
    run_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_run_comparisons(
        engagement.id, run_id=run_id, limit=limit, offset=offset
    )


@router.post("/proof-receipts", status_code=status.HTTP_201_CREATED)
async def create_proof_receipt(
    engagement_key: str, request: ProofReceiptRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.create_proof_receipt,
            engagement.id,
            run_id=request.run_id,
            evidence_kind=request.evidence_kind,
            expected_result=request.expected_result,
            observed_result=request.observed_result,
            artifact_id=request.artifact_id,
            source_read_id=request.source_read_id,
            command_run_id=request.command_run_id,
            evidence_sha256=request.evidence_sha256,
            evidence_health=request.evidence_health,
            tombstone_reason=request.tombstone_reason,
        )
    )
    await _broadcast(engagement.key, "proof_receipt", record)
    return record


@router.get("/proof-receipts")
def get_proof_receipts(
    engagement_key: str,
    finding_slug: str = "",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_proof_receipts(
        engagement.id,
        finding_slug=finding_slug,
        limit=limit,
        offset=offset,
    )


@router.get("/proof-receipts/{receipt_id}")
def get_proof_receipt(engagement_key: str, receipt_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_proof_receipt(engagement.id, receipt_id)


@router.get("/findings/{finding_slug}")
def get_finding(engagement_key: str, finding_slug: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_finding(engagement.id, finding_slug)


@router.get("/findings/{finding_slug}/transitions")
def get_finding_transitions(
    engagement_key: str,
    finding_slug: str,
    limit: int = Query(default=100, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_finding_transitions(
        engagement.id,
        slug=finding_slug,
        limit=limit,
        offset=offset,
    )


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


@router.get("/blocked-techniques/history")
def get_blocked_technique_history(
    engagement_key: str,
    technique_key: str = Query(default="", max_length=256),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_blocked_technique_history(
        engagement.id, technique_key=technique_key, limit=limit
    )


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
def get_work_item_stats(
    engagement_key: str, by: str = "status", status: str = ""
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.work_buffer_stats(
        engagement.id, by=by, status_value=status
    )


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


@router.post("/work-items/fetch-by-unit")
async def fetch_work_items_by_unit_endpoint(
    engagement_key: str, request: WorkItemUnitFetchRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.fetch_work_items_by_unit,
            engagement.id,
            unit_id=request.unit_id,
            path=request.path,
            work_class=request.work_class,
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
        functools.partial(
            state_manager.defer_work_items,
            engagement.id,
            ids=request.ids,
            reason=request.reason,
            dry_run=request.dry_run,
        )
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
            dry_run=request.dry_run,
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
    try:
        record = await anyio.to_thread.run_sync(
            functools.partial(
                state_manager.set_capture_policy,
                engagement.id,
                **request.model_dump(exclude_unset=True),
            )
        )
    except CapturePolicyMirrorError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": "capture policy saved, but its filesystem mirror was not updated",
                "database_updated": True,
                "filesystem_mirror_updated": False,
                "error": str(exc),
                "policy": exc.record,
            },
        ) from exc
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
    if request.route == "host_exec":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "route='host_exec' is reserved for the bounded "
                "/command-runs/host-exec contract"
            ),
        )
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
    """Bounded ingress for host pre-exec rows and policy refusals.

    Full host output belongs in descriptor-backed spill files, never this POST.
    The ordinary command-run endpoint intentionally keeps its one-shot inline
    contract for Kali and legacy tool writers.
    """

    model_config = ConfigDict(extra="forbid")

    host_record_kind: Literal["pre_exec", "policy_refusal"] = "pre_exec"
    argv: list[str] = Field(min_length=1, max_length=256)
    stdout: str = Field(default="", max_length=65_536)
    stderr: str = Field(default="", max_length=65_536)
    stdout_spill_device: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stdout_spill_inode: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stderr_spill_device: int | None = Field(default=None, ge=0, le=2**63 - 1)
    stderr_spill_inode: int | None = Field(default=None, ge=0, le=2**63 - 1)
    timeout_seconds_requested: int | None = Field(
        default=None, ge=0, le=2**63 - 1
    )
    finding_id: int | None = Field(default=None, ge=1, le=2**63 - 1)

    @model_validator(mode="after")
    def _validate_host_record_shape(self) -> "HostExecRecord":
        if any(len(arg.encode("utf-8", errors="replace")) > 4096 for arg in self.argv):
            raise ValueError("host-exec argv entries must be at most 4096 bytes")
        canonical_command = " ".join(self.argv)
        if len(canonical_command.encode("utf-8", errors="replace")) > 65_536:
            raise ValueError("host-exec argv must be at most 65536 bytes in total")
        if self.command != canonical_command:
            raise ValueError("host-exec command must exactly match argv joined by spaces")
        if self.timed_out or self.duration_ms != 0:
            raise ValueError("host-exec ingress timing fields must be empty")
        if any(
            value is not None
            for value in (
                self.peak_rss_bytes,
                self.cpu_user_seconds,
                self.cpu_system_seconds,
            )
        ):
            raise ValueError("host-exec ingress resource fields must be empty")
        if self.command_hash or self.stdout_sha256 or self.stderr_sha256:
            raise ValueError("host-exec ingress hash fields are server-owned")
        if self.engagement_artifact_dir is not None or self.force:
            raise ValueError("host-exec ingress storage and dedup fields are server-owned")
        if self.host_record_kind == "pre_exec":
            if self.status != "running":
                raise ValueError("host-exec pre_exec records must use status='running'")
            if self.return_code is not None or self.success is not None or self.completed_at:
                raise ValueError("host-exec pre_exec records cannot contain terminal fields")
            if self.stdout or self.stderr:
                raise ValueError("host-exec pre_exec output must be written to spill files")
            if not self.stdout_path or not self.stderr_path:
                raise ValueError("host-exec pre_exec records require stdout_path and stderr_path")
            if any(
                value is None
                for value in (
                    self.stdout_spill_device,
                    self.stdout_spill_inode,
                    self.stderr_spill_device,
                    self.stderr_spill_inode,
                )
            ):
                raise ValueError("host-exec pre_exec records require spill identity claims")
        else:
            if (
                self.status != "failed"
                or self.success is not False
                or self.return_code is not None
            ):
                raise ValueError("host-exec policy_refusal records must be failed")
            if self.stdout or self.stdout_path or self.stderr_path:
                raise ValueError("host-exec policy_refusal records cannot claim output spills")
            if any(
                value is not None
                for value in (
                    self.stdout_spill_device,
                    self.stdout_spill_inode,
                    self.stderr_spill_device,
                    self.stderr_spill_inode,
                )
            ):
                raise ValueError("host-exec policy_refusal records cannot claim spill identity")
        return self


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
    payload.pop("host_record_kind")
    payload["route"] = "host_exec"  # canonical marker, never trust client input
    if not payload.get("command_hash"):
        payload["command_hash"] = hashlib.sha256(
            payload["command"].encode("utf-8", errors="replace")
        ).hexdigest()
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.record_command_run,
            engagement.id,
            _host_exec_contract=True,
            **payload,
        )
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
            stdout_bytes=request.stdout_bytes,
            stderr_bytes=request.stderr_bytes,
            stdout_sha256=request.stdout_sha256,
            stderr_sha256=request.stderr_sha256,
            timed_out=request.timed_out,
            output_quiesced=request.output_quiesced,
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
            client_name=request.client_name,
            client_payload_host=request.client_payload_host,
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
            client_name=request.client_name,
            client_payload_host=request.client_payload_host,
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
    """Read-only, advisory depth ledger.

    Per ``deep_required`` app unit: Expected vuln classes (each gated by an
    executable §5.3 predicate), Covered, missing block/warn classes, active
    depth deferrals, the structured dedicated-dispatch verdict, a per-unit
    ``depth_satisfied`` verdict, and an EV rank. EV-ranked, highest first.

    Mid-engagement this is ADVISORY ONLY — it never blocks a transition and the
    endpoint never returns non-2xx for missing depth. The terminal backstop is a
    separate projection. WEB-ONLY: code/blue engagements get a skipped result.
    """
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.depth_ledger(engagement.id)


@router.get("/application-units/terminal-block")
def get_terminal_depth_block(engagement_key: str) -> dict[str, Any]:
    """The one terminal depth blocker.

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
            expected_source_row_version=request.expected_source_row_version,
            expected_target_row_version=request.expected_target_row_version,
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
            verification_status=request.verification_status,
            defect_family=request.defect_family,
            root_cause_key=request.root_cause_key,
            auth_context=request.auth_context,
            canonical_location=request.canonical_location,
            summary=request.summary,
            evidence_ref=request.evidence_ref,
            notes=request.notes,
            source_name=request.source_name,
            details=request.details,
            provenance=request.provenance.model_dump(exclude_none=True),
            evidence_type=request.evidence_type,
            submission_status=request.submission_status,
            submission_platform=request.submission_platform,
            submission_ref=request.submission_ref,
            submission_url=request.submission_url,
            request_variant_id=request.request_variant_id,
            service_id=request.service_id,
            surface_id=request.surface_id,
            links=[item.model_dump() for item in request.links],
            allow_remint=request.allow_remint,
            run_candidate=(
                request.run_candidate.model_dump()
                if request.run_candidate is not None
                else None
            ),
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-record",
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
            submission_platform=request.submission_platform,
            submission_ref=request.submission_ref,
            submission_url=request.submission_url,
            transition_reason_code=request.reason_code,
            transition_reason_text=request.reason_text,
            transition_artifact_ref=request.artifact_ref,
            expected_row_version=request.expected_row_version,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-update",
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
            title="finding-link",
            action=f"finding={finding_slug} root_cause={request.root_cause_slug}",
            actor_name=request.source_name,
            result=request.root_cause_effect,
            metadata={"finding_slug": finding_slug, "root_cause_slug": request.root_cause_slug},
        )
    )
    await _broadcast(engagement.key, "finding_root_cause", record)
    return record


class FindingRelocateRequest(BaseModel):
    """Audited crossing of the file/non-file canonical-location boundary.

    Deliberately a DEDICATED route rather than a loosening of the generic patch:
    the generic guard exists so a non-file finding cannot acquire ``file:``
    semantics through an unreviewed metadata patch, and it stays exactly as strict.
    """

    model_config = ConfigDict(extra="forbid")

    canonical_location: str = Field(min_length=1, max_length=4096)
    reason_text: str = Field(min_length=1, max_length=4096)
    source_name: str = Field(default="operator", min_length=1, max_length=128)
    expected_row_version: int = Field(ge=1)
    provenance: FindingProvenance = Field(default_factory=FindingProvenance)

    @field_validator("canonical_location")
    @classmethod
    def _normalize_canonical_location(cls, value: str) -> str:
        return value.strip()


class FindingAuthorRepairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=4096)
    expected_row_version: int = Field(ge=1)


@router.put("/findings/{finding_slug}/author")
async def repair_finding_author(
    engagement_key: str,
    finding_slug: str,
    request: FindingAuthorRepairRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.repair_finding_author,
            engagement.id,
            slug=finding_slug,
            agent_id=request.agent_id,
            actor=request.actor,
            reason=request.reason,
            expected_row_version=request.expected_row_version,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-author-repair",
            action=f"finding={finding_slug} agent_id={request.agent_id}",
            actor_name=request.actor,
            result=request.reason,
            metadata={"finding_slug": finding_slug, "agent_id": request.agent_id},
        )
    )
    await _broadcast(engagement.key, "finding_patch", record)
    return record


@router.put("/findings/{finding_slug}/canonical-location")
async def relocate_finding(
    engagement_key: str,
    finding_slug: str,
    request: FindingRelocateRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.relocate_finding,
            engagement.id,
            slug=finding_slug,
            canonical_location=request.canonical_location,
            reason_text=request.reason_text,
            source_name=request.source_name,
            expected_row_version=request.expected_row_version,
            provenance=request.provenance.model_dump(exclude_none=True),
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-relocate",
            action=f"finding={finding_slug} to={request.canonical_location}",
            actor_name=request.source_name,
            result=request.reason_text,
            metadata={"finding_slug": finding_slug},
        )
    )
    await _broadcast(engagement.key, "finding_patch", record)
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


@router.patch("/findings/{finding_slug}/links/{link_id}")
async def update_finding_link(
    engagement_key: str,
    finding_slug: str,
    link_id: int,
    request: FindingLinkPatchRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            state_manager.update_finding_link,
            engagement.id,
            finding_slug=finding_slug,
            link_id=link_id,
            **request.model_dump(),
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-link-update",
            action=f"finding={finding_slug} link_id={link_id}",
            actor_name="operator",
            result="retired" if request.retired else "updated",
            metadata={"finding_slug": finding_slug, "link_id": link_id},
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
            verification_status=request.verification_status,
            reason_code=request.reason_code,
            reason_text=request.reason_text,
            source_name=request.source_name,
            evidence_ref=request.evidence_ref,
            notes=request.notes,
            details=request.details,
            provenance=request.provenance.model_dump(exclude_none=True),
            artifact_ref=request.artifact_ref,
            new_severity=request.new_severity,
            proof_receipt_ids=request.proof_receipt_ids,
            counter_check=(
                request.counter_check.model_dump()
                if request.counter_check is not None
                else None
            ),
            severity_variance=(
                request.severity_variance.model_dump()
                if request.severity_variance is not None
                else None
            ),
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="finding-verify",
            action=f"finding={finding_slug} verification_status={request.verification_status}",
            actor_name=request.source_name,
            result=request.reason_code or request.reason_text or request.verification_status,
            metadata={
                "finding_slug": finding_slug,
                "verification_status": request.verification_status,
            },
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
            revalidation_context=request.revalidation_context,
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
    application_unit_id: int | None = Field(default=None, gt=0)
    dispatched_at: str | None = Field(default=None, max_length=64)
    status: _DISPATCH_STATUS = "in-progress"
    requested_model: str | None = Field(default=None, max_length=128)
    requested_reasoning: _REASONING | None = None
    client_name: Literal["claude", "codex", "goose", "kimi", "opencode", "unknown"] = (
        "unknown"
    )
    requested_client: Literal["claude", "codex", "goose", "kimi", "opencode", "unknown"] = "unknown"
    launcher_effective_client: Literal["claude", "codex", "goose", "kimi", "opencode", "unknown"] = "unknown"
    # Provider observation is deliberately closed to caller attestation until a
    # supported client exposes a stable, client-owned signal at this boundary.
    provider_observed_client: Literal["unknown"] = "unknown"
    source_revision: str = Field(default="unknown", max_length=128)
    operator_instruction_path: str | None = Field(default=None, max_length=1024)
    operator_instruction_sha256: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    specialist_instruction_path: str | None = Field(default=None, max_length=1024)
    specialist_instruction_sha256: str | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    instruction_identity_status: Literal["verified", "incomplete"] = "incomplete"
    instructions_stale: bool | None = None
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
    vuln_classes: str | None = Field(default=None, max_length=2048)
    identity: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _validate_instruction_identity(self) -> DispatchCreate:
        if self.launcher_effective_client == "unknown" and self.client_name != "unknown":
            self.launcher_effective_client = self.client_name
        elif self.client_name == "unknown" and self.launcher_effective_client != "unknown":
            self.client_name = self.launcher_effective_client
        elif self.client_name != self.launcher_effective_client:
            raise ValueError(
                "client_name is a compatibility projection and must equal "
                "launcher_effective_client"
            )
        if self.instruction_identity_status == "verified":
            complete = all(
                (
                    self.client_name != "unknown",
                    self.operator_instruction_path,
                    self.operator_instruction_sha256,
                    self.specialist_instruction_path,
                    self.specialist_instruction_sha256,
                )
            )
            if not complete:
                raise ValueError(
                    "verified instruction identity requires a known client plus both "
                    "installed instruction paths and SHA-256 fingerprints"
                )
        elif self.instructions_stale is not None:
            raise ValueError(
                "instructions_stale is only known for a verified instruction identity"
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


class BlindTriageVerdictPayload(BaseModel):
    """Fields the report gate consumes from a blind-triage decision."""

    model_config = ConfigDict(extra="allow")

    finding_slug: str = Field(min_length=1)
    verdict: Literal[
        "Accept@P1",
        "Accept@P2",
        "Accept@P3",
        "Accept@P4",
        "Accept@P5",
        "Need-More-Info",
        "Not-Applicable-Informational",
        "Out-of-Scope",
        "Duplicate",
    ]


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
        elif self.kind == "blind_triage_verdict":
            BlindTriageVerdictPayload.model_validate(self.payload)
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
            application_unit_id=request.application_unit_id,
            dispatched_at=request.dispatched_at,
            status_value=request.status,
            requested_model=request.requested_model,
            actual_model="unknown",
            requested_reasoning=request.requested_reasoning,
            actual_reasoning="unknown",
            client_name=request.client_name,
            requested_client=request.requested_client,
            launcher_effective_client=request.launcher_effective_client,
            provider_observed_client=request.provider_observed_client,
            source_revision=request.source_revision,
            operator_instruction_path=request.operator_instruction_path,
            operator_instruction_sha256=request.operator_instruction_sha256,
            specialist_instruction_path=request.specialist_instruction_path,
            specialist_instruction_sha256=request.specialist_instruction_sha256,
            instruction_identity_status=request.instruction_identity_status,
            instructions_stale=request.instructions_stale,
            dispatch_mode=request.dispatch_mode,
            finding_slugs=request.finding_slugs,
            skills=request.skills,
            tier=request.tier,
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
    limit: int = Query(default=100, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
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
            result=str(record.get("status") or ""),
            metadata={
                "agent_id": agent_id,
                "finding_slugs": record.get("finding_slugs") or [],
            },
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
    limit: int = Query(default=100, ge=1, le=MAX_ASSESSMENT_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_handoffs(
        engagement.id,
        role=role,
        since=since,
        limit=limit,
        offset=offset,
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


# Declared AFTER the literal-path ``GET /dispatch-decisions`` above so the
# parameterised route cannot shadow the list.
@router.get("/dispatch-decisions/{decision_id}")
def get_decision(engagement_key: str, decision_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_decision(engagement.id, decision_id=int(decision_id))


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
