"""Correctness-sensitive phase gates must never accept partial audit reads."""

from __future__ import annotations

import pytest

from assess.commands import transition_phase


class _MalformedArtifactPageClient:
    def get(self, endpoint: str):
        if endpoint == "artifacts/search?limit=1000&offset=0":
            return [
                {
                    "id": index + 1,
                    "kind": "ir_closeout" if index == 0 else "other",
                    "relative_path": "reports/closeout.md" if index == 0 else "other.txt",
                }
                for index in range(1000)
            ]
        if endpoint == "artifacts/search?limit=1000&offset=1000":
            return {"unexpected": "object page"}
        if endpoint == "findings":
            return []
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def test_blue_complete_gate_blocks_when_later_artifact_page_is_malformed() -> None:
    blockers = transition_phase._blue_check_report_to_complete(
        _MalformedArtifactPageClient()
    )

    assert any(
        blocker["kind"] == "backend_query_failed"
        and "artifacts" in blocker["detail"]
        for blocker in blockers
    )


class _WebPrerequisiteClient:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses

    def get(self, endpoint: str):
        response = self.responses[endpoint]
        if isinstance(response, Exception):
            raise response
        return response

    def get_all_pages(self, endpoint: str):
        response = self.responses[endpoint]
        if isinstance(response, Exception):
            raise response
        return response


@pytest.mark.parametrize(
    ("target_phase", "check_name"),
    [("verify", "verify findings"), ("exploit", "exploit findings")],
)
def test_web_finding_precondition_fails_closed_on_malformed_response(
    target_phase: str,
    check_name: str,
) -> None:
    client = _WebPrerequisiteClient(
        {
            "findings": {"unexpected": "object"},
            "work-items?status=pending": [],
        }
    )

    blockers = transition_phase._check_web_preconditions(target_phase, client)

    assert blockers == [
        {
            "kind": "precondition_check_failed",
            "detail": f"{check_name} check failed: backend returned a non-list response",
        }
    ]


@pytest.mark.parametrize(
    "response",
    [
        ["unexpected", "list"],
        {"skipped": "false"},
        {
            "skipped": False,
            "blocking": [{"unit": "not-an-object"}],
            "warned_under_observed": [],
            "deferral_count": 0,
        },
    ],
)
def test_terminal_depth_precondition_fails_closed_on_malformed_response(
    response: object,
) -> None:
    blockers = transition_phase._depth_backstop_blockers(
        _WebPrerequisiteClient({"application-units/terminal-block": response})
    )

    assert len(blockers) == 1
    assert blockers[0]["kind"] == "precondition_check_failed"
    assert "terminal depth backstop check failed" in blockers[0]["detail"]


@pytest.mark.parametrize(
    "decision_response",
    [RuntimeError("decision backend unavailable"), {"unexpected": "object"}],
    ids=["unavailable", "malformed"],
)
def test_blind_triage_precondition_fails_closed_on_bad_decision_response(
    decision_response: object,
) -> None:
    client = _WebPrerequisiteClient(
        {
            "findings": [
                {
                    "slug": "VA-1",
                    "severity": "high",
                    "workflow_status": "active",
                    "verification_status": "confirmed",
                }
            ],
            "dispatch-decisions?kind=blind_triage_verdict&limit=1000": decision_response,
        }
    )

    blockers = transition_phase._blind_triage_blockers(client)

    assert len(blockers) == 1
    assert blockers[0]["kind"] == "precondition_check_failed"
    assert "blind-triage decisions check failed" in blockers[0]["detail"]


@pytest.mark.parametrize(
    "dispatch_response",
    [RuntimeError("dispatch backend unavailable"), {"unexpected": "object"}],
    ids=["unavailable", "malformed"],
)
def test_chain_construction_precondition_fails_closed_on_bad_dispatch_response(
    dispatch_response: object,
) -> None:
    client = _WebPrerequisiteClient(
        {
            "findings": [
                {
                    "slug": f"VA-{index}",
                    "severity": "high",
                    "verification_status": "confirmed",
                    "workflow_status": "active",
                }
                for index in (1, 2)
            ],
            "dispatches?role=exploit-developer&status=completed&limit=1000": dispatch_response,
        }
    )

    blockers = transition_phase._chain_construction_blockers(client)

    assert len(blockers) == 1
    assert blockers[0]["kind"] == "precondition_check_failed"
    assert "chain-construction dispatches check failed" in blockers[0]["detail"]
