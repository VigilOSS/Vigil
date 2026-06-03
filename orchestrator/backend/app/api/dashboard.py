"""Cross-engagement dashboard summary API.

A single read-only aggregate that powers the landing-page dashboard. The
projection itself lives in ``app.services.dashboard``; this router is a thin
HTTP/Pydantic seam over it. No mutations, no per-engagement fan-out.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..services.dashboard import dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class EngagementCounts(BaseModel):
    total: int
    by_status: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    by_phase: dict[str, int] = Field(default_factory=dict)


class FindingTotals(BaseModel):
    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)


class DashboardEngagement(BaseModel):
    key: str
    target: str
    status: str
    current_phase: str
    engagement_type: str | None = None
    customer: str | None = None
    updated_at: str
    finding_count: int
    finding_severities: dict[str, int] = Field(default_factory=dict)


class DashboardActivity(BaseModel):
    id: int
    engagement_key: str
    actor_kind: str
    actor_name: str
    title: str
    action: str
    result: str
    occurred_at: str
    created_at: str


class DashboardSummaryResponse(BaseModel):
    engagement_counts: EngagementCounts
    finding_totals: FindingTotals
    engagements: list[DashboardEngagement] = Field(default_factory=list)
    recent_activity: list[DashboardActivity] = Field(default_factory=list)


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary() -> DashboardSummaryResponse:
    return DashboardSummaryResponse(**dashboard_summary())
