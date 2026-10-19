"""Proof-work preparation, atomic dispatch claims, and explicit reconciliation."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..services.engagements import get_engagement_or_404
from ..services.state_manager import proof_work
from .assessment_operator import DispatchCreate

router = APIRouter()


class ProofWorkPrepare(BaseModel):
    model_config = ConfigDict(extra='forbid')
    finding_slug: str = Field(min_length=1)
    route: Literal['code', 'web']
    objective: str = Field(min_length=1, max_length=4096)
    target_hosts: list[str] = Field(default_factory=list)


class ProofWorkApproval(BaseModel):
    model_config = ConfigDict(extra='forbid')
    approved: bool
    actor: Literal['operator', 'ui']
    human_confirmation: str | None = Field(default=None, max_length=2000)
    reason: str | None = Field(default=None, max_length=8192)

    @model_validator(mode='after')
    def require_decision_context(self):
        value = self.human_confirmation if self.approved else self.reason
        if not value or not value.strip():
            raise ValueError('Approval requires human_confirmation; revocation requires reason')
        return self


class ProofWorkUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    agent_id: str = Field(min_length=1)
    status: Literal['claimed', 'blocked', 'finished']
    blocker: str = Field(default='', max_length=8192)
    run_id: int | None = Field(default=None, gt=0)


@router.get('/proof-work')
def list_work(engagement_key: str):
    return proof_work.list_proof_work(get_engagement_or_404(engagement_key).id)


@router.post('/proof-work', status_code=201)
def prepare(engagement_key: str, request: ProofWorkPrepare):
    return proof_work.prepare_proof_work(get_engagement_or_404(engagement_key).id, **request.model_dump())


@router.get('/proof-work/{work_id}')
def get_work(engagement_key: str, work_id: int):
    return proof_work.get_proof_work(get_engagement_or_404(engagement_key).id, work_id)


@router.post('/proof-work/{work_id}/claim')
def claim(engagement_key: str, work_id: int, request: DispatchCreate):
    return proof_work.claim_proof_work(get_engagement_or_404(engagement_key).id, work_id,
                                      dispatch=request.model_dump())


@router.post('/proof-work/{work_id}/approval')
def approve(engagement_key: str, work_id: int, request: ProofWorkApproval):
    return proof_work.approve_proof_work(get_engagement_or_404(engagement_key).id, work_id,
                                        **request.model_dump())


@router.patch('/proof-work/{work_id}')
def update(engagement_key: str, work_id: int, request: ProofWorkUpdate):
    return proof_work.update_proof_work(get_engagement_or_404(engagement_key).id, work_id, **request.model_dump())


@router.post('/proof-work/{work_id}/reconcile')
def reconcile(engagement_key: str, work_id: int):
    return proof_work.reconcile_proof_work(get_engagement_or_404(engagement_key).id, work_id)


class ProofWorkRelease(BaseModel):
    model_config = ConfigDict(extra='forbid')
    reason: str = Field(min_length=1, max_length=8192)


@router.post('/proof-work/{work_id}/release')
def release(engagement_key: str, work_id: int, request: ProofWorkRelease):
    return proof_work.release_proof_work(get_engagement_or_404(engagement_key).id, work_id,
                                        reason=request.reason)
