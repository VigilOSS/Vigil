from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from ..services import remediation

router = APIRouter(prefix="/engagements/{engagement_key}/remediation", tags=["remediation"])


class CaseCreate(BaseModel):
    source_type: Literal["jira", "bounty"]
    source_key: str = Field(min_length=1)
    title: str = Field(min_length=1)
    snapshot: dict[str, Any]
    linked_finding_engagement_key: str | None = None
    linked_finding_slug: str | None = None


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1)
    linked_finding_slug: str | None = None
    linked_finding_engagement_key: str | None = None
    worktree_path: str | None = None
    worktree_branch: str | None = Field(default=None, min_length=1)
    worktree_revision: str | None = None

    @field_validator("worktree_branch")
    @classmethod
    def nonempty_worktree_branch(cls, value: str | None) -> str:
        if value is None or not value.strip():
            raise ValueError("Worktree branch must be nonempty")
        return value


class PlanPatch(BaseModel):
    verification_plan: str


class EvidenceCreate(BaseModel):
    kind: str = Field(min_length=1)
    method: str = Field(min_length=1)
    environment: Literal["local", "development", "test", "production", "not_applicable"]
    command: str = ""
    observed: str = Field(min_length=1)
    proved: str = Field(min_length=1)
    outcome: str | None = None
    artifact_path: str | None = None
    revision: str | None = None


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
    coralogix_monitoring: str = Field(min_length=1)


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


@router.get("/cases/{case_id}")
def get_case(engagement_key: str, case_id: int):
    return remediation.get_case(engagement_key, case_id)


@router.get("/cases/{case_id}/diff")
def get_case_diff(engagement_key: str, case_id: int):
    return remediation.review_diff(engagement_key, case_id)


@router.patch("/cases/{case_id}")
def patch_case(engagement_key: str, case_id: int, body: CasePatch):
    return remediation.patch_case(engagement_key, case_id, body.model_dump(exclude_unset=True))


@router.patch("/cases/{case_id}/verification-plan")
def patch_plan(engagement_key: str, case_id: int, body: PlanPatch):
    return remediation.patch_case(engagement_key, case_id, {"verification_plan": body.verification_plan})


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
