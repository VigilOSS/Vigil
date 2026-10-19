"""Operator coordination routes for assessment dispatches and checkpoints."""
from __future__ import annotations

import functools
from typing import Any, Literal

import anyio
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..services import operator_checkpoints, state_manager
from ..services.engagements import get_engagement_or_404
from ..services.state_manager.coverage import MAX_ASSESSMENT_LIST_LIMIT
from ..services.state_manager.dispatches import (
    list_dispatch_client_bindings,
    record_dispatch_client_binding,
)
from .assessment import _audit_assessment_mutation, _broadcast


router = APIRouter()


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
# A dispatch can omit client identity, while a client binding cannot.
_LAUNCHED_CLIENT = Literal["claude", "codex", "goose", "kimi", "opencode", "pi"]
_DISPATCH_CLIENT = Literal["claude", "codex", "goose", "kimi", "opencode", "pi", "unknown"]
_MIXED_ASSESSMENT_ROLES = frozenset({"exploit-developer", "source-analyzer"})
_CODE_ASSESSMENT_ROLES = frozenset({
    'code-architect', 'code-fuzz-engineer', 'code-variant-hunter',
    'code-vuln-hunter', 'code-vuln-verifier',
})


class DispatchPromptPacket(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal["dispatch-prompt/v1"] = Field(alias="schema")
    context: dict[str, Any]
    rendered_prompt: str = Field(min_length=1)


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
    client_name: _DISPATCH_CLIENT = "unknown"
    requested_client: _DISPATCH_CLIENT = "unknown"
    launcher_effective_client: _DISPATCH_CLIENT = "unknown"
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
    instruction_identity_status: Literal["installed", "verified", "incomplete"] = "incomplete"
    instructions_stale: bool | None = None
    dispatch_mode: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Dispatch execution mode (free text). Advisory known modes: "
            + ", ".join(_KNOWN_DISPATCH_MODES)
        ),
    )
    assessment_mode: Literal["code", "web"] | None = None
    finding_slugs: list[str] | None = None
    skills: str | None = Field(default=None, max_length=4096)
    tier: Literal["L1", "L2", "L3", "L4"] | None = None
    vuln_classes: str | None = Field(default=None, max_length=2048)
    identity: str | None = Field(default=None, max_length=128)
    prompt_packet: DispatchPromptPacket | None = None
    continued_from_dispatch_id: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _validate_instruction_identity(self) -> DispatchCreate:
        if self.agent_role in _CODE_ASSESSMENT_ROLES:
            if self.assessment_mode == 'web':
                raise ValueError('Code-only specialist dispatches require assessment_mode=code')
            self.assessment_mode = 'code'
        if self.launcher_effective_client == "unknown" and self.client_name != "unknown":
            self.launcher_effective_client = self.client_name
        elif self.client_name == "unknown" and self.launcher_effective_client != "unknown":
            self.client_name = self.launcher_effective_client
        elif self.client_name != self.launcher_effective_client:
            raise ValueError(
                "client_name is a compatibility projection and must equal "
                "launcher_effective_client"
            )
        if self.instruction_identity_status in {"installed", "verified"}:
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
                    "installed instruction identity requires a known client plus both "
                    "installed instruction paths and SHA-256 fingerprints"
                )
        elif self.instructions_stale is not None:
            raise ValueError(
                "instructions_stale is only known for a fingerprinted instruction identity"
            )
        return self


class DispatchUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: _DISPATCH_STATUS | None = None
    completed_at: str | None = Field(default=None, max_length=64)
    finding_slugs: list[str] | None = None


class DispatchClientBindingCreate(BaseModel):
    """Which live client session a dispatch is running as, asserted post-launch.

    Every field is the OPERATOR'S claim: they read the handle out of their client
    and typed it here. Nothing in this request is observed by a launcher or a
    provider, which is why each field says ``asserted_`` and why there is no way
    to supply ``provider_observed_handle`` — that stays closed to caller
    attestation exactly like ``DispatchCreate.provider_observed_client``, so the
    row reports an unmeasured handle instead of an unearned one.
    """

    model_config = ConfigDict(extra="forbid")

    asserted_client: _LAUNCHED_CLIENT
    # The scope the handle is unique within — a working directory, a workspace,
    # a host. A bare session id is ambiguous across clients and machines, so the
    # namespace is required rather than optional: an unlocatable handle cannot be
    # used to reach the session, which is the whole purpose of binding one.
    asserted_session_namespace: str = Field(min_length=1, max_length=512)
    asserted_client_handle: str = Field(min_length=1, max_length=256)
    note: str | None = Field(default=None, max_length=1024)

    @field_validator(
        "asserted_session_namespace", "asserted_client_handle", mode="after"
    )
    @classmethod
    def _reject_blank_identity(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed


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
    """Fields the report gate consumes from an attributed blind review."""

    model_config = ConfigDict(extra="allow")

    finding_slug: str = Field(min_length=1)
    packet_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_dispatch_agent_id: str = Field(min_length=1)
    writer_dispatch_agent_id: str = Field(min_length=1)
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


class ReproRehearsalPayload(BaseModel):
    """A testing dispatch's result for the current authored reproduction."""

    model_config = ConfigDict(extra="forbid")

    finding_slug: str = Field(min_length=1)
    verdict: Literal["followed", "failed", "equivalent"]
    proof_mode: Literal["live", "source", "fuzz"]
    verifier_dispatch_agent_id: str = Field(min_length=1)
    runs_checked: list[int] = Field(default_factory=list)
    observed_outcome: str = ""
    failed_step: str = ""
    prior_decision_id: int | None = Field(default=None, gt=0)
    reason: str = ""


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
        elif self.kind == "repro_rehearsal":
            ReproRehearsalPayload.model_validate(self.payload)
        return self


class DecisionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: bool | None = None
    resolution: dict[str, Any] | None = None
    surfaced_to_user: bool | None = None


@router.post("/dispatches", status_code=status.HTTP_201_CREATED)
async def create_dispatch(engagement_key: str, request: DispatchCreate) -> dict[str, Any]:
    if request.agent_role in _MIXED_ASSESSMENT_ROLES and request.assessment_mode is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{request.agent_role} dispatches require assessment_mode=code|web",
        )
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
            launcher_effective_model=None,
            launcher_effective_reasoning=None,
            launcher_effective_source=None,
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
            assessment_mode=request.assessment_mode,
            finding_slugs=request.finding_slugs,
            skills=request.skills,
            tier=request.tier,
            vuln_classes=request.vuln_classes,
            identity=request.identity,
            prompt_packet=(request.prompt_packet.model_dump() if request.prompt_packet else None),
            continued_from_dispatch_id=request.continued_from_dispatch_id,
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


@router.get("/dispatches/{agent_id}/prompt-packet")
def get_dispatch_prompt_packet_endpoint(engagement_key: str, agent_id: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.get_dispatch_prompt_packet(engagement.id, agent_id)


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


@router.post(
    "/dispatches/{agent_id}/client-bindings", status_code=status.HTTP_201_CREATED
)
async def create_dispatch_client_binding(
    engagement_key: str,
    agent_id: str,
    request: DispatchClientBindingCreate,
) -> dict[str, Any]:
    """Bind a dispatch to the client session the operator actually launched.

    Deliberately a separate POST rather than a field on ``create_dispatch``: the
    handle does not exist when the dispatch row is written, so requiring it there
    would either block the dispatch or invite a fabricated value.
    """
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            record_dispatch_client_binding,
            engagement.id,
            agent_id=agent_id,
            asserted_client=request.asserted_client,
            asserted_session_namespace=request.asserted_session_namespace,
            asserted_client_handle=request.asserted_client_handle,
            note=request.note,
        )
    )
    binding = record["binding"]
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="agent bind-client-handle",
            action=(
                f"agent_id={agent_id} client={binding['asserted_client']} "
                f"handle={binding['asserted_client_handle']}"
            ),
            actor_name=agent_id,
            result=f"binding_version={binding['binding_version']}",
            metadata={
                "agent_id": agent_id,
                "binding_version": binding["binding_version"],
                "asserted_client": binding["asserted_client"],
                "asserted_session_namespace": binding["asserted_session_namespace"],
                "asserted_client_handle": binding["asserted_client_handle"],
                "superseded_binding_id": (record["superseded"] or {}).get("id"),
            },
        )
    )
    # Broadcast the DISPATCH row, not the binding: what changed for every reader
    # is which session that dispatch is now reachable at, and the dispatch row
    # carries the current binding.
    dispatch_row = await anyio.to_thread.run_sync(
        functools.partial(state_manager.get_dispatch, engagement.id, agent_id)
    )
    await _broadcast(engagement.key, "dispatch", dispatch_row)
    return record


@router.get("/dispatches/{agent_id}/client-bindings")
def get_dispatch_client_bindings(
    engagement_key: str, agent_id: str
) -> list[dict[str, Any]]:
    """The dispatch's full, append-only binding history, oldest version first."""
    engagement = get_engagement_or_404(engagement_key)
    return list_dispatch_client_bindings(engagement.id, agent_id)


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


# The operator's own checkpoint. Deliberately NO ``current_phase`` or
# ``code_phase`` field: both track phases are server-derived at write time, so a
# caller cannot assert a phase the engagement is not in — on either of its two
# independent tracks. The list caps and the note cap are validation bounds —
# over-long input is REFUSED with a clear error, never silently truncated.
class OperatorCheckpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_note: str = Field(
        min_length=1,
        max_length=operator_checkpoints.MAX_INTENT_NOTE_CHARS,
        description=(
            "UNVERIFIED operator intent: what you were about to do and why. This "
            "is the only free-text field on a checkpoint and is never a finding, "
            "a measurement, or evidence about the target."
        ),
    )
    finding_slugs: list[str] = Field(
        default_factory=list, max_length=operator_checkpoints.MAX_REFERENCES
    )
    dispatch_agent_ids: list[str] = Field(
        default_factory=list, max_length=operator_checkpoints.MAX_REFERENCES
    )
    command_run_ids: list[int] = Field(
        default_factory=list, max_length=operator_checkpoints.MAX_REFERENCES
    )
    artifact_ids: list[int] = Field(
        default_factory=list, max_length=operator_checkpoints.MAX_REFERENCES
    )

    @field_validator("intent_note")
    @classmethod
    def _intent_note_must_say_something(cls, value: str) -> str:
        """Refuse a note that is only whitespace; keep a real one byte-for-byte.

        ``min_length=1`` accepts `"   "` and `"\n"`, which a shell expansion of
        an unset variable produces easily. Recording one is not a harmless
        no-op: every write supersedes the previous row, so the blank becomes
        the CURRENT checkpoint and resume hydration — which reads the current
        one — stops showing the operator's real save-my-place note. The whole
        point of the record is to survive a context boundary, so losing it to
        an empty write is the one failure it cannot have.

        Only the check strips. The stored text stays verbatim, because the
        renderers are deliberately lossless about operator-authored content.
        """
        if not value.strip():
            raise ValueError(
                "intent_note cannot be blank: record what you were about to do "
                "and why. A whitespace-only note would supersede the last "
                "checkpoint and leave resume with nothing to rehydrate from."
            )
        return value


@router.post("/operator-checkpoints", status_code=status.HTTP_201_CREATED)
async def create_operator_checkpoint(
    engagement_key: str, request: OperatorCheckpointCreate
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            operator_checkpoints.record_checkpoint,
            engagement.id,
            intent_note=request.intent_note,
            finding_slugs=list(request.finding_slugs),
            dispatch_agent_ids=list(request.dispatch_agent_ids),
            command_run_ids=list(request.command_run_ids),
            artifact_ids=list(request.artifact_ids),
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_assessment_mutation,
            engagement.id,
            title="operator checkpoint",
            action=f"checkpoint_version={record['checkpoint_version']}",
            result=record["current_phase"],
            metadata={
                "checkpoint_version": record["checkpoint_version"],
                "source": record["source"],
            },
        )
    )
    await _broadcast(engagement.key, "operator_checkpoint", record)
    return record


@router.get("/operator-checkpoints")
def get_operator_checkpoints(
    engagement_key: str,
    include_superseded: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return operator_checkpoints.list_checkpoints(
        engagement.id,
        include_superseded=include_superseded,
        limit=limit,
        offset=offset,
    )
