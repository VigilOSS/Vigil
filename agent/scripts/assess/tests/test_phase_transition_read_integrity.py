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


def test_exploit_finding_precondition_fails_closed_on_malformed_response() -> None:
    client = _WebPrerequisiteClient({"findings?view=list": {"unexpected": "object"}})

    blockers = transition_phase._check_web_preconditions("exploit", client)

    assert blockers == [
        {
            "kind": "precondition_check_failed",
            "detail": "exploit findings check failed: backend returned a non-list response",
        }
    ]


_CLEAN_STAGE_AUDIT = {"stage_audit": {"applicable": True, "expected_stages": [], "gaps": []}}


@pytest.mark.parametrize(
    ("target_phase", "responses", "check_name"),
    [
        ("collect", {"services": RuntimeError("services backend unavailable"),
                     "phase-readiness?phase=recon": _CLEAN_STAGE_AUDIT},
         "collect services"),
        ("consume-test",
         {"work-items?status=pending": RuntimeError("work buffer unavailable"),
          "phase-readiness?phase=collect": _CLEAN_STAGE_AUDIT},
         "consume-test work buffer"),
        ("collect", {"services": [{"id": 1}],
                     "phase-readiness?phase=recon": RuntimeError("readiness unavailable")},
         "recon stage-completion audit"),
        ("verify",
         {"findings?view=list": {"unexpected": "object"}, "work-items?status=pending": []},
         "verify findings"),
        ("verify",
         {"findings?view=list": [{"slug": "VA-1", "workflow_status": "active"}],
          "work-items?status=pending": RuntimeError("work buffer unavailable")},
         "verify consumption"),
    ],
    ids=["collect", "consume-test", "collect-stage-audit", "verify-findings",
         "verify-consumption"],
)
def test_an_advisory_check_whose_read_fails_is_an_advisory_naming_the_failure(
    target_phase: str, responses: dict, check_name: str
) -> None:
    """These empty-state checks never block, so a failed read cannot block either;
    the advisory says the check was not evaluated."""
    blockers = transition_phase._check_web_preconditions(
        target_phase, _WebPrerequisiteClient(responses)
    )

    assert len(blockers) == 1
    [item] = blockers
    assert item["kind"] == "precondition_check_failed"
    assert item["severity"] == "advisory"
    assert item["detail"].startswith(f"{check_name} check failed: ")
    assert "not evaluated" in item["detail"]


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
            "findings?view=list": [
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


_TWO_CONFIRMED_HIGHS = [
    {
        "slug": f"VA-{index}",
        "severity": "high",
        "verification_status": "confirmed",
        "workflow_status": "active",
    }
    for index in (1, 2)
]


@pytest.mark.parametrize(
    "dispatch_response",
    [RuntimeError("dispatch backend unavailable"), {"unexpected": "object"}],
    ids=["unavailable", "malformed"],
)
def test_chain_construction_advisory_survives_a_bad_dispatch_response(
    dispatch_response: object,
) -> None:
    client = _WebPrerequisiteClient(
        {
            "findings?view=list": _TWO_CONFIRMED_HIGHS,
            "attack-chain-links": [],
            "dispatches?role=exploit-developer&status=completed&limit=1000": dispatch_response,
        }
    )

    blockers = transition_phase._chain_construction_blockers(client)

    assert len(blockers) == 1
    assert blockers[0]["kind"] == "chain_construction_unchained"
    assert blockers[0]["severity"] == "advisory"
    assert "VA-1, VA-2" in blockers[0]["detail"]
    assert "an unknown number of (read failed:" in blockers[0]["detail"]


@pytest.mark.parametrize(
    "links_response",
    [RuntimeError("chain backend unavailable"), {"unexpected": "object"}],
    ids=["unavailable", "malformed"],
)
def test_chain_construction_advisory_reports_a_bad_chain_link_read(
    links_response: object,
) -> None:
    client = _WebPrerequisiteClient(
        {"findings?view=list": _TWO_CONFIRMED_HIGHS, "attack-chain-links": links_response}
    )

    blockers = transition_phase._chain_construction_blockers(client)

    assert len(blockers) == 1
    assert blockers[0]["kind"] == "precondition_check_failed"
    assert blockers[0]["severity"] == "advisory"
    assert "chain-construction links check failed" in blockers[0]["detail"]


def test_variant_pass_gate_reads_every_analyst_dispatch_page() -> None:
    slug = "VA-7"
    analyst_filler = [
        {"agent_role": "vulnerability-analyst", "status": "completed",
         "dispatch_mode": "standard", "finding_slugs": []}
        for _ in range(1000)
    ]
    late_variant_pass = {
        "agent_role": "vulnerability-analyst", "status": "completed",
        "dispatch_mode": "variant-rotation", "finding_slugs": [slug],
    }
    client = _WebPrerequisiteClient(
        {
            "findings?view=list": [
                {"slug": slug, "severity": "high", "verification_status": "confirmed",
                 "workflow_status": "active"},
            ],
            "work-items?status=pending": [],
            "dispatches?role=vulnerability-analyst&limit=1000&offset=0": analyst_filler,
            "dispatches?role=vulnerability-analyst&limit=1000&offset=1000": [late_variant_pass],
        }
    )

    blockers = transition_phase._check_web_preconditions("exploit", client)

    assert blockers == []


def test_variant_pass_gate_fails_closed_on_a_malformed_later_page() -> None:
    client = _WebPrerequisiteClient(
        {
            "findings?view=list": [
                {"slug": "VA-7", "severity": "high", "verification_status": "confirmed",
                 "workflow_status": "active"},
            ],
            "work-items?status=pending": [],
            "dispatches?role=vulnerability-analyst&limit=1000&offset=0": [
                {"agent_role": "vulnerability-analyst", "status": "completed"}
                for _ in range(1000)
            ],
            "dispatches?role=vulnerability-analyst&limit=1000&offset=1000": {"page": "object"},
        }
    )

    blockers = transition_phase._check_web_preconditions("exploit", client)

    assert blockers == [
        {
            "kind": "precondition_check_failed",
            "detail": "exploit variant dispatches check failed: backend returned a non-list response",
        }
    ]
