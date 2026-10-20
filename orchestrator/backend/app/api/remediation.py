from __future__ import annotations

from typing import Any, Literal
from pathlib import PurePosixPath

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, field_validator, model_validator

from ..services import remediation

router = APIRouter(prefix="/engagements/{engagement_key}/remediation", tags=["remediation"])


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_-]*$")
    source_key: str | None = Field(default=None, min_length=1)
    external_provider: str | None = Field(default=None, min_length=1)
    external_key: str | None = Field(default=None, min_length=1)
    title: str = Field(min_length=1)
    snapshot: dict[str, Any]
    finding_ids: list[PositiveInt] = Field(default_factory=list)

    @model_validator(mode="after")
    def source_and_identity(self):
        if self.source_key is None and self.source_type not in {"manual", "report"}:
            raise ValueError("Source key is required for this provider")
        _paired_external(self.external_provider, self.external_key)
        return self


def _paired_external(provider: str | None, key: str | None) -> None:
    if (provider is None) != (key is None) or any(
        value is not None and not value.strip() for value in (provider, key)
    ):
        raise ValueError("External provider and key must both be nonempty or both null")


class CaseIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_external_provider: str | None
    expected_external_key: str | None
    external_provider: str | None
    external_key: str | None

    @model_validator(mode="after")
    def paired_identity(self):
        _paired_external(self.expected_external_provider, self.expected_external_key)
        _paired_external(self.external_provider, self.external_key)
        return self


class BranchFinalization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_branch: str = Field(min_length=1)
    new_branch: str = Field(min_length=1)
    revision: str = Field(min_length=1)


class PublicationIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_digest: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    branch: str = Field(min_length=1)


class CasePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1)
    finding_ids: list[PositiveInt] = Field(default_factory=list)
    worktree_path: str | None = None
    worktree_branch: str | None = Field(default=None, min_length=1)
    worktree_revision: str | None = None
    base_branch: str | None = Field(default=None, min_length=1)
    base_revision: str | None = Field(default=None, min_length=1)

    @field_validator("worktree_branch")
    @classmethod
    def nonempty_worktree_branch(cls, value: str | None) -> str:
        if value is None or not value.strip():
            raise ValueError("Worktree branch must be nonempty")
        return value


class VerificationRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1)
    methods: list[str] = Field(min_length=1)
    outcome: str = Field(default="passed", min_length=1)
    revision: Literal["current"] = "current"
    execution: Literal["executed", "reasoned"] = "executed"
    rationale: str = ""
    shared_environment: str | None = Field(default=None, min_length=1)
    runtime_identity_required: bool = False
    browser_purpose: Literal["happy-path", "bad-path", "other"] | None = None
    legitimate_use_control: bool = False
    fix_paths: list[str] = Field(default_factory=list)

    @field_validator("fix_paths")
    @classmethod
    def repository_fix_files(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not path or path == "." or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts or str(PurePosixPath(path)) != path for path in value
        ):
            raise ValueError("fix_paths must name distinct repository-relative files")
        return sorted(value)

    @field_validator("methods")
    @classmethod
    def nonempty_methods(cls, value: list[str]) -> list[str]:
        if any(not method.strip() for method in value):
            raise ValueError("Verification methods must be nonempty")
        return value

    @model_validator(mode="after")
    def validate_browser_control(self):
        if self.kind == "red-test" and (
            self.execution != "executed" or self.outcome != "failed_as_expected" or not self.fix_paths
            or self.shared_environment or self.runtime_identity_required
        ):
            raise ValueError("Red tests require local executed expected failure and explicit fix_paths")
        if self.kind != "red-test" and self.fix_paths:
            raise ValueError("Only red-test requirements name fix_paths")
        methods = {method.casefold() for method in self.methods}
        browser = methods & {"stagehand", "browse"}
        if self.browser_purpose is not None and (not browser or methods - {"stagehand", "browse"}):
            raise ValueError("Browser purpose requires only browser methods")
        if browser and (self.execution != "executed" or self.revision != "current" or self.outcome != "passed"):
            raise ValueError("Browser verification requires executed passing evidence at the current revision")
        if self.legitimate_use_control:
            if self.execution != "executed" or self.revision != "current" or self.outcome != "passed" or not self.rationale.strip():
                raise ValueError("Legitimate-use controls require a rationale and executed passing evidence at the current revision")
            if browser and self.browser_purpose in {"bad-path", "other"}:
                raise ValueError("A browser legitimate-use control requires happy-path purpose")
        return self


class PlanPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verification_plan: str
    requirements: list[VerificationRequirement] | None = Field(default=None, min_length=1)
    alternatives_reason: str = ""

    @field_validator("verification_plan")
    @classmethod
    def nonempty_plan(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Verification plan must be nonempty")
        return value

    @model_validator(mode="after")
    def explain_alternatives(self):
        if self.requirements is not None and not self.alternatives_reason.strip():
            raise ValueError("Explicit verification requirements need an alternatives reason")
        if self.requirements is not None and any(
            {method.casefold() for method in requirement.methods} & {"stagehand", "browse"}
            for requirement in self.requirements
        ) and not any(
            requirement.legitimate_use_control
            or (set(method.casefold() for method in requirement.methods) <= {"stagehand", "browse"}
                and requirement.browser_purpose in {None, "happy-path"})
            for requirement in self.requirements
        ):
            raise ValueError("Browser verification needs a legitimate-use control in the plan")
        return self


class EnvironmentAcquire(BaseModel):
    model_config = ConfigDict(extra="forbid")
    environment: str = Field(min_length=1)
    case_id: PositiveInt
    revision: str = Field(min_length=1)
    actor: str = Field(min_length=1)


class EnvironmentRelease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    environment: str = Field(min_length=1)
    case_id: PositiveInt
    token: str = Field(min_length=1)
    actor: str = Field(min_length=1)


class EnvironmentConfirm(EnvironmentRelease):
    observed_revision: str = Field(min_length=1)


class FindingCaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    remediation_engagement_key: str = Field(min_length=1)
    title: str | None = Field(default=None, min_length=1)


@router.get("/findings/{finding_slug}/cases")
def finding_cases(engagement_key: str, finding_slug: str):
    return remediation.finding_cases(engagement_key, finding_slug)


@router.post("/findings/{finding_slug}/cases", status_code=status.HTTP_201_CREATED)
def create_finding_case(engagement_key: str, finding_slug: str, body: FindingCaseCreate):
    return remediation.create_from_finding(engagement_key, finding_slug, body.remediation_engagement_key, body.title)


class EvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1)
    method: str = Field(min_length=1)
    environment: Literal["local", "development", "test", "production", "not_applicable"]
    command: str = ""
    observed: str = Field(min_length=1)
    proved: str = Field(min_length=1)
    outcome: str | None = None
    artifact_path: str | None = None
    revision: str | None = None
    execution: Literal["executed", "reasoned", "unavailable"] = "executed"
    executed_revision: str | None = None
    executed_directory: str | None = None
    shared_environment: str | None = None
    environment_token: str | None = None
    scratch_proof: dict[str, Any] | None = None


class ApprovalCreate(BaseModel):
    reviewer: str = Field(min_length=1)
    expected_review_digest: str = Field(min_length=64, max_length=64)
    approval_method: Literal["ui", "cli_instruction"]
    owner_instruction: str | None = None


class BaselinePatch(BaseModel):
    outcome: Literal["runtime_reproduced", "code_test_confirmed", "unreproduced"]
    method: str = Field(min_length=1)
    proved: str = Field(min_length=1)
    owner_decision: Literal["proceed", "pause"] | None = None
    owner_actor: str | None = None
    owner_reason: str | None = None


class ReleasePlanPatch(BaseModel):
    production_canary_decision: Literal["required", "not_required", "defer"]
    production_canary_rationale: str = Field(min_length=1)
    safe_procedure: str = ""
    monitoring: str = Field(min_length=1)


class TransitionCreate(BaseModel):
    status: str
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class DeploymentCreate(BaseModel):
    workflow: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    environment: Literal["development"]
    expected_revision: str = Field(min_length=1)
    observed_revision: str = Field(min_length=1)
    actor: str = Field(min_length=1)


class HumanVerificationCreate(BaseModel):
    actor: str = Field(min_length=1)
    result: Literal["passed", "failed", "blocked"]
    observed_revision: str = Field(min_length=1)
    notes: str


@router.get("/cases")
def list_cases(engagement_key: str):
    return remediation.list_cases(engagement_key)


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(engagement_key: str, body: CaseCreate):
    return remediation.create_case(engagement_key, body.model_dump())


@router.post("/cases/{case_id}/identity")
def update_identity(engagement_key: str, case_id: int, body: CaseIdentity):
    return remediation.update_identity(engagement_key, case_id, body.model_dump())


@router.post("/cases/{case_id}/finalize-branch")
def finalize_branch(engagement_key: str, case_id: int, body: BranchFinalization):
    return remediation.finalize_branch(engagement_key, case_id, body.model_dump())


@router.post("/cases/{case_id}/publication-intent")
def publication_intent(engagement_key: str, case_id: int, body: PublicationIntent):
    return remediation.publication_intent(engagement_key, case_id, body.model_dump())


@router.post("/cases/{case_id}/resolve-source")
def resolve_source(engagement_key: str, case_id: int, body: CaseCreate):
    return remediation.resolve_source(engagement_key, case_id, body.model_dump())


@router.post("/environments/acquire", status_code=status.HTTP_201_CREATED)
def acquire_environment(engagement_key: str, body: EnvironmentAcquire):
    return remediation.acquire_environment(engagement_key, body.model_dump())


@router.post("/environments/release")
def release_environment(engagement_key: str, body: EnvironmentRelease):
    return remediation.release_environment(engagement_key, body.model_dump())


@router.post("/environments/confirm")
def confirm_environment(engagement_key: str, body: EnvironmentConfirm):
    return remediation.confirm_environment(engagement_key, body.model_dump())


@router.get("/cases/{case_id}")
def get_case(engagement_key: str, case_id: int,
             evidence_limit: int | None = Query(default=None, ge=1, le=100),
             history_limit: int | None = Query(default=None, ge=1, le=100)):
    return remediation.get_case(engagement_key, case_id, evidence_limit=evidence_limit, history_limit=history_limit)


@router.get("/cases/{case_id}/evidence")
def list_evidence(engagement_key: str, case_id: int,
                  limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    return remediation.case_records(engagement_key, case_id, "evidence", limit=limit, offset=offset)


@router.get("/cases/{case_id}/history")
def list_history(engagement_key: str, case_id: int,
                 limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    return remediation.case_records(engagement_key, case_id, "history", limit=limit, offset=offset)


@router.get("/cases/{case_id}/evidence/{evidence_id}")
def get_evidence(engagement_key: str, case_id: int, evidence_id: int):
    return remediation.evidence_record(engagement_key, case_id, evidence_id)


@router.get("/cases/{case_id}/diff")
def get_case_diff(engagement_key: str, case_id: int):
    return remediation.review_diff(engagement_key, case_id)


@router.patch("/cases/{case_id}")
def patch_case(engagement_key: str, case_id: int, body: CasePatch):
    return remediation.patch_case(engagement_key, case_id, body.model_dump(exclude_unset=True))


@router.patch("/cases/{case_id}/verification-plan")
def patch_plan(engagement_key: str, case_id: int, body: PlanPatch):
    data = body.model_dump()
    if "requirements" not in body.model_fields_set:
        data.pop("requirements")
    return remediation.patch_verification_plan(engagement_key, case_id, data)


@router.patch("/cases/{case_id}/baseline")
def patch_baseline(engagement_key: str, case_id: int, body: BaselinePatch):
    return remediation.patch_baseline(engagement_key, case_id, body.model_dump())


@router.patch("/cases/{case_id}/release-plan")
def patch_release_plan(engagement_key: str, case_id: int, body: ReleasePlanPatch):
    return remediation.patch_release_plan(engagement_key, case_id, body.model_dump())


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def create_evidence(engagement_key: str, case_id: int, body: EvidenceCreate):
    return remediation.add_evidence(engagement_key, case_id, body.model_dump())


@router.get("/cases/{case_id}/evidence/{evidence_id}/file")
def evidence_file(engagement_key: str, case_id: int, evidence_id: int):
    path, source = remediation.artifact_file(engagement_key, case_id, evidence_id)
    media_type = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif"}.get(path.suffix.lower(), "application/octet-stream")
    def chunks():
        try:
            while chunk := source.read(1024 * 1024):
                yield chunk
        finally:
            source.close()
    return StreamingResponse(chunks(), media_type=media_type)


@router.post("/cases/{case_id}/approve", status_code=status.HTTP_201_CREATED)
def approve_case(engagement_key: str, case_id: int, body: ApprovalCreate):
    if body.approval_method == "cli_instruction" and not (body.owner_instruction or "").strip():
        raise HTTPException(400, "CLI approval requires exact case-owner instruction")
    return remediation.approve(
        engagement_key, case_id, body.reviewer, body.expected_review_digest,
        body.approval_method, body.owner_instruction,
    )


@router.post("/cases/{case_id}/transition")
def transition_case(engagement_key: str, case_id: int, body: TransitionCreate):
    return remediation.transition(engagement_key, case_id, body.status, body.actor, body.reason)


@router.post("/cases/{case_id}/deployment", status_code=status.HTTP_201_CREATED)
def record_deployment(engagement_key: str, case_id: int, body: DeploymentCreate):
    return remediation.deployment(engagement_key, case_id, body.model_dump())


@router.post("/cases/{case_id}/human-verification", status_code=status.HTTP_201_CREATED)
def record_human_verification(engagement_key: str, case_id: int, body: HumanVerificationCreate):
    return remediation.human_verification(engagement_key, case_id, body.model_dump())
