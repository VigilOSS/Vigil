"""Operator coordination routes for assessment dispatches and checkpoints."""
from __future__ import annotations

import difflib
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from ..services import operator_checkpoints, state_manager
from ..services.code_analysis import FAMILY_EXCLUSION_DECISION_KIND, family_exclusion_problems
from ..services.engagements import get_engagement_or_404
from ..services.state_manager.coverage import MAX_ASSESSMENT_LIST_LIMIT
from ..services.state_manager.coverage_readiness import PER_HOST_OBJECTIVES
from ..services.state_manager.dispatches import (
    HANDOFF_SUMMARY_MAX_CHARS,
    list_dispatch_client_bindings,
    record_dispatch_client_binding,
)
from .assessment import (
    ASSESSMENT_PREFIX,
    _audit_assessment_mutation,
    _broadcast,
    _offload,
    folded_vocabulary,
)
from .query_params import DeclaredQueryParamsRoute


# Registered by the app at its full path (not included under the assessment
# router's prefix), so engagement_key is a path param of every route here.
router = APIRouter(
    prefix=ASSESSMENT_PREFIX, tags=["assessment"], route_class=DeclaredQueryParamsRoute
)


_DISPATCH_STATUS = folded_vocabulary(
    Literal["in-progress", "completed", "failed", "aborted", "blocked"]
)
_DISPATCH_TERMINAL_STATUS = folded_vocabulary(
    Literal["completed", "failed", "aborted", "blocked"]
)
_KNOWN_DISPATCH_MODES: tuple[str, ...] = (
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
    "swarm",
)
_REASONING = Literal["low", "medium", "high", "xhigh", "max"]
_CONFIDENCE = Literal["low", "medium", "high"]
_HANDOFF_STATUS = folded_vocabulary(Literal["checkpointed", "ready", "blocked", "superseded"])
# A dispatch can omit client identity, while a client binding cannot.
_LAUNCHED_CLIENT = Literal["claude", "codex", "goose", "kimi", "opencode", "zcode", "pi"]
_DISPATCH_CLIENT = Literal["claude", "codex", "goose", "kimi", "opencode", "zcode", "pi", "unknown"]
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
    # Optional: the handoff records the dispatch's registered role. When absent it
    # is filled from the dispatch and named on the response's ``derived`` list; a
    # different role contradicts the dispatch ``agent_id`` names and is refused (409).
    agent_role: str | None = Field(default=None, min_length=1, max_length=128)
    phase: str | None = Field(default=None, max_length=64)
    summary: str = Field(min_length=1, max_length=HANDOFF_SUMMARY_MAX_CHARS)
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

    expected_handoff_version: int | None = Field(default=None, ge=1)

    summary: str | None = Field(default=None, min_length=1, max_length=HANDOFF_SUMMARY_MAX_CHARS)
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

    # Exactly the objectives ``per_host_coverage`` evaluates: a deferral of
    # anything else would be stored and then read by no gate.
    deferred_objectives: list[Literal[PER_HOST_OBJECTIVES]] = Field(  # type: ignore[valid-type]
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

    Mirrors ``agent/schemas/containment-proposal.schema.json`` so the schema a
    specialist writes against and the dispatch-decisions row the backend stores
    enforce the same contract. ``vigil blue propose-contain`` is the only writer;
    it records that row by running
    ``vigil assess agent decision --kind containment_proposal``, which POSTs here.
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

    @field_validator("verdict", mode="before")
    @classmethod
    def _canonical_verdict_case(cls, value: Any) -> Any:
        # The verdict vocabulary is mixed-case by convention (`Accept@P2`); the
        # case a caller types it in carries no meaning, so it folds to the
        # canonical spelling the report gate compares against.
        if isinstance(value, str):
            return _BLIND_TRIAGE_VERDICTS_BY_FOLD.get(value.strip().casefold(), value)
        return value


_BLIND_TRIAGE_VERDICTS_BY_FOLD = {
    verdict.casefold(): verdict
    for verdict in BlindTriageVerdictPayload.model_fields["verdict"].annotation.__args__
}


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

    @field_validator("verdict", "proof_mode", mode="before")
    @classmethod
    def _lowercase_vocabulary(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value


def _literal_values(model: type[BaseModel], field: str) -> list[str]:
    info = model.model_fields.get(field)
    if info is None or getattr(info.annotation, "__origin__", None) is not Literal:
        return []
    return [str(value) for value in info.annotation.__args__]


def _validated_kind_payload(
    kind: str,
    model: type[BaseModel],
    payload: dict[str, Any],
    *,
    literal_notes: dict[str, str] | None = None,
) -> None:
    """Validate a gated kind's payload, naming each failing ``payload.<field>``.

    A raw validation error inside ``DecisionCreate`` reports ``body.<field>``,
    which points at the request instead of the payload, and an unknown key as
    "Extra inputs are not permitted" with no hint of the field meant.
    ``literal_notes`` adds, for a value refused from a field's vocabulary,
    where a value outside it belongs.
    """
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        problems = []
        for error in exc.errors():
            path = ".".join(str(part) for part in ("payload", *error["loc"]))
            if error["type"] == "extra_forbidden":
                field = str(error["loc"][-1])
                close = difflib.get_close_matches(field, sorted(model.model_fields), n=1, cutoff=0.6)
                problems.append(
                    f"{path} is not a {kind} field"
                    + (f" (did you mean payload.{close[0]}?)" if close else "")
                )
            elif error["type"] == "literal_error":
                allowed = str(error["ctx"]["expected"]).replace("'", "").replace(" or ", ", ")
                # A before-validator may have folded the word; quote it as sent.
                sent = (
                    payload[error["loc"][0]]
                    if len(error["loc"]) == 1 and error["loc"][0] in payload
                    else error["input"]
                )
                note = (literal_notes or {}).get(str(error["loc"][0]))
                problems.append(
                    f"{path} must be one of: {allowed} (got {sent!r})"
                    + (f"; {note}" if note else "")
                )
            elif error["type"] == "missing" and _literal_values(model, str(error["loc"][-1])):
                allowed = ", ".join(_literal_values(model, str(error["loc"][-1])))
                problems.append(f"{path} is required, one of: {allowed}")
            else:
                problems.append(f"{path}: {error['msg']}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"{kind} payload invalid: " + "; ".join(problems)
                + f". Fields: {', '.join(model.model_fields)}"
                " (`vigil assess contract agent decision`)"
            ),
        ) from exc


# Where a deferral of work that no per-host objective covers belongs: an ungated
# kind the vocabulary accepts as written, read by audit views and no gate.
_NON_OBJECTIVE_DEFERRAL_NOTE = (
    "a coverage_deferral closes only these readiness objectives. Record a deferred "
    "step that is not one of them (authenticated recon, a skipped scan) as an "
    "ungated decision, e.g. `vigil assess agent decision --kind phase_step_deferral "
    "--payload-json '{\"hosts\": [...], \"step\": \"<step>\", \"reason\": \"<why>\"}' "
    "--surfaced-to-user`, which no gate reads"
)


# Decision kinds a backend gate or a downstream approve+execute flow reads. A
# row recorded under another spelling of one of these would satisfy nothing and
# leave the gate open. A spelling equal to a gated kind once case and separators
# are folded is stored under that kind (named on the response's ``derived``); a
# misspelling within the near-miss distance is refused with the kind it meant.
GATED_DECISION_KINDS = frozenset(
    {
        "blind_triage_verdict",
        "claim_equivalence",
        "containment_proposal",
        "coverage_completeness_deferral",
        "coverage_deferral",
        "depth_deferral",
        "repro_rehearsal",
        "report_qc_verdict",
        "severity_variance",
        "submission_qc_verdict",
        "vuln_family_exclusion",
    }
)
# Kinds that satisfy no gate, mapped to the gated kind that does their job. The
# kind and its near misses are refused naming that kind, so a caller is led to a
# kind that is accepted; stored rows of these kinds stay readable data.
UNGATED_KIND_REPLACEMENTS: dict[str, str] = {
    "pass1_qa_verdict": "submission_qc_verdict",
}
_NEAR_MISS_EDIT_DISTANCE = 2


def _folded_kind(kind: str) -> str:
    return "".join(char for char in kind.casefold() if char.isalnum())


def _edit_distance(left: str, right: str) -> int:
    """Optimal-string-alignment distance: a transposition counts as one edit."""
    rows = [list(range(len(right) + 1))]
    for i, left_char in enumerate(left, start=1):
        row = [i] + [0] * len(right)
        for j, right_char in enumerate(right, start=1):
            row[j] = min(
                rows[-1][j] + 1,
                row[j - 1] + 1,
                rows[-1][j - 1] + (left_char != right_char),
            )
            if (
                i > 1 and j > 1
                and left_char == right[j - 2] and left[i - 2] == right_char
            ):
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def _nearest_kind(kind: str, candidates) -> str | None:
    """The candidate ``kind`` spells within the near-miss distance, if any."""
    folded = _folded_kind(kind)
    distance, canonical = min(
        (_edit_distance(folded, _folded_kind(candidate)), candidate)
        for candidate in candidates
    )
    return canonical if distance <= _NEAR_MISS_EDIT_DISTANCE else None


def _gated_kind_spelled(kind: str) -> str | None:
    """The gated kind ``kind`` names once case and separators are folded."""
    folded = _folded_kind(kind)
    return next(
        (candidate for candidate in GATED_DECISION_KINDS if _folded_kind(candidate) == folded),
        None,
    )


def _gated_kind_near_miss(kind: str) -> str | None:
    """The gated kind ``kind`` misspells, or None for a gated or unrelated kind."""
    if _gated_kind_spelled(kind) is not None:
        return None
    return _nearest_kind(kind, GATED_DECISION_KINDS)


def _ungated_kind_replacement(kind: str) -> str | None:
    """The gated kind that does the job of the ungated kind ``kind`` names or misspells."""
    ungated = _nearest_kind(kind, UNGATED_KIND_REPLACEMENTS)
    return UNGATED_KIND_REPLACEMENTS[ungated] if ungated is not None else None


class DecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # ``kind`` is intentionally NOT a Literal — operators may add new
    # checkpoint kinds (scope_decision, egress_decision, dispatch_blocked,
    # license_decision, ...) without a backend redeploy, and the table stores
    # the payload of an unrecognised kind as sent.
    #
    # The exceptions are the GATED_DECISION_KINDS. Another case or separator
    # spelling of one is stored under the canonical kind, a misspelling is
    # refused rather than stored under a name no gate reads, and a gated kind
    # whose gate depends on the payload shape has it validated at POST time —
    # here, or by its state-manager recorder — so a malformed payload cannot
    # silently neuter that gate or be blindly approved and executed later. The
    # CLI sends every kind's payload unchanged and relies on this validation.
    kind: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    surfaced_to_user: bool = False
    supersedes: int | None = Field(
        default=None,
        gt=0,
        description=(
            "Id of an earlier decision of the same kind in this engagement that this row "
            "replaces. The earlier row is stamped superseded_by_id and every gate reads "
            "only current rows; it stays readable by id."
        ),
    )
    # What the POST stored in place of what was sent, for the response's
    # ``derived`` list.
    _derived: list[dict[str, Any]] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _validate_known_kind_payload(self) -> "DecisionCreate":
        replacement = _ungated_kind_replacement(self.kind)
        if replacement is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"decision kind {self.kind!r} satisfies no gate and is not recorded; "
                    f"record the review as `--kind {replacement}` from a dispatch "
                    "separate from the writer (payload shape: `vigil assess "
                    "contract agent decision`)"
                ),
            )
        canonical = _gated_kind_near_miss(self.kind)
        if canonical is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"decision kind {self.kind!r} is not a gated kind; did you mean "
                    f"'{canonical}'? A row under any other name satisfies no gate. "
                    f"Record it with `--kind {canonical}`"
                ),
            )
        spelled = _gated_kind_spelled(self.kind)
        if spelled is not None and spelled != self.kind:
            self._derived.append({
                "field": "kind",
                "value": spelled,
                "derived_from": "kind",
                "detail": f"stored the gated kind {spelled!r} for the spelling {self.kind!r}",
            })
            self.kind = spelled
        if self.kind == "coverage_deferral":
            _validated_kind_payload(
                self.kind,
                CoverageDeferralPayload,
                self.payload,
                literal_notes={"deferred_objectives": _NON_OBJECTIVE_DEFERRAL_NOTE},
            )
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
                # which field is invalid. `vigil blue propose-contain` writes
                # this row through `vigil assess agent decision`, which relays
                # the detail to stderr and exits non-zero, so the operator is
                # told which field to fix rather than handed a proposal id.
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"containment_proposal payload invalid: {exc}",
                ) from exc
        elif self.kind == "blind_triage_verdict":
            _validated_kind_payload(self.kind, BlindTriageVerdictPayload, self.payload)
            self.payload = {
                **self.payload,
                "verdict": BlindTriageVerdictPayload.model_validate(self.payload).verdict,
            }
        elif self.kind == FAMILY_EXCLUSION_DECISION_KIND:
            problems = family_exclusion_problems(self.payload, surfaced_to_user=self.surfaced_to_user)
            if problems:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=(
                        f"{FAMILY_EXCLUSION_DECISION_KIND} not recorded: " + "; ".join(problems)
                        + '. Payload: {"vuln_classes": [<canonical review families>], '
                        '"ruling": "<the ruling verbatim and where it is recorded>"}'
                    ),
                )
        elif self.kind == "repro_rehearsal":
            _validated_kind_payload(self.kind, ReproRehearsalPayload, self.payload)
            folded = ReproRehearsalPayload.model_validate(self.payload)
            self.payload = {
                **self.payload, "verdict": folded.verdict, "proof_mode": folded.proof_mode,
            }
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
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
        prompt_packet=request.prompt_packet.model_dump() if request.prompt_packet else None,
        continued_from_dispatch_id=request.continued_from_dispatch_id,
    )
    await _offload(
        _audit_assessment_mutation,
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
        state_manager.update_dispatch,
        engagement.id,
        agent_id=agent_id,
        status_value=request.status,
        completed_at=request.completed_at,
        finding_slugs=request.finding_slugs,
    )
    await _offload(
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
    await _broadcast(engagement.key, "dispatch", record)
    return record


@router.post(
    "/dispatches/{agent_id}/client-bindings", status_code=status.HTTP_201_CREATED
)
async def create_dispatch_client_binding(
    engagement_key: str,
    agent_id: str,
    request: DispatchClientBindingCreate,
    response: Response,
) -> dict[str, Any]:
    """Bind a dispatch to the client session the operator actually launched.

    Deliberately a separate POST rather than a field on ``create_dispatch``: the
    handle does not exist when the dispatch row is written, so requiring it there
    would either block the dispatch or invite a fabricated value.
    """
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
        record_dispatch_client_binding,
        engagement.id,
        agent_id=agent_id,
        asserted_client=request.asserted_client,
        asserted_session_namespace=request.asserted_session_namespace,
        asserted_client_handle=request.asserted_client_handle,
        note=request.note,
    )
    if record["already_bound"]:
        # Nothing was written: the dispatch already holds exactly this binding.
        response.status_code = status.HTTP_200_OK
        return record
    binding = record["binding"]
    await _offload(
        _audit_assessment_mutation,
        engagement.id,
        title="agent bind-client-handle",
        action=f"agent_id={agent_id} client={binding['asserted_client']} "
            f"handle={binding['asserted_client_handle']}",
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
    # Broadcast the DISPATCH row, not the binding: what changed for every reader
    # is which session that dispatch is now reachable at, and the dispatch row
    # carries the current binding.
    dispatch_row = await _offload(state_manager.get_dispatch, engagement.id, agent_id)
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
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
    await _offload(
        _audit_assessment_mutation,
        engagement.id,
        title="agent handoff",
        action=f"agent_id={request.agent_id} role={record['agent_role']}",
        actor_name=record["agent_role"],
        result=request.summary,
        metadata={"agent_id": request.agent_id, "agent_role": record["agent_role"]},
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
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
        expected_handoff_version=request.expected_handoff_version,
    )
    await _offload(
        _audit_assessment_mutation,
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
        state_manager.record_decision,
        engagement.id,
        kind=request.kind,
        payload=request.payload,
        surfaced_to_user=request.surfaced_to_user,
        supersedes=request.supersedes,
    )
    await _offload(
        _audit_assessment_mutation,
        engagement.id,
        title="agent decision",
        action=f"kind={request.kind}",
        result="surfaced_to_user" if request.surfaced_to_user else "",
        metadata={
            "kind": request.kind,
            "surfaced_to_user": request.surfaced_to_user,
            "supersedes": request.supersedes,
        },
    )
    await _broadcast(engagement.key, "dispatch_decision", record)
    return {**record, "derived": list(request._derived)}


@router.get("/dispatch-decisions")
def get_decisions(
    engagement_key: str,
    kind: str = "",
    resolved: bool | None = Query(default=None),
    include_superseded: bool = Query(
        default=False,
        description="Also list rows a later decision superseded (history); gates never read them.",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return state_manager.list_decisions(
        engagement.id,
        kind=kind,
        resolved=resolved,
        include_superseded=include_superseded,
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
        state_manager.update_decision,
        engagement.id,
        decision_id=int(decision_id),
        resolved=request.resolved,
        resolution=request.resolution,
        surfaced_to_user=request.surfaced_to_user,
    )
    await _offload(
        _audit_assessment_mutation,
        engagement.id,
        title="agent decision",
        action=f"decision_id={decision_id}",
        result="resolved" if request.resolved else "",
        metadata={"decision_id": int(decision_id)},
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
    engagement = await _offload(get_engagement_or_404, engagement_key)
    record = await _offload(
        operator_checkpoints.record_checkpoint,
        engagement.id,
        intent_note=request.intent_note,
        finding_slugs=list(request.finding_slugs),
        dispatch_agent_ids=list(request.dispatch_agent_ids),
        command_run_ids=list(request.command_run_ids),
        artifact_ids=list(request.artifact_ids),
    )
    await _offload(
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
