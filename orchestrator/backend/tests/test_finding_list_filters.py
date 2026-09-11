"""Enum-typed filters on ``GET /assessment/findings``.

A SQL equality filter on a value that is not in its enum returns the same thing a
genuinely empty engagement returns: ``[]`` with a 200. That ambiguity is not
cosmetic here — ``finding list --verification-state verified`` (the retired
two-axis spelling) read as "no confirmed findings to exploit" while confirmed
findings sat in the table, and the operator had no signal that the question was
malformed rather than the answer empty.

These tests pin BOTH enforcement seams, mirroring ``test_submission_status.py``:
the backend rejects an unknown filter value with a 400 that names the vocabulary,
and the CLI's ``choices`` refuse it one step earlier with argparse exit 2. The
cross-package vocabulary pin lives here because the backend venv is the one
interpreter that can import both packages.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from app.api.assessment import FindingVerifyRequest  # noqa: E402
from app.services.state_manager._common import (  # noqa: E402
    SEVERITY_RANK,
    VERIFICATION_STATUSES as BACKEND_VERIFICATION_STATUSES,
    WORKFLOW_STATUSES as BACKEND_WORKFLOW_STATUSES,
)

ENGAGEMENT_KEY = "2026-06-30-120000-listfilters"
AUTHOR_AGENT_ID = "LIST-FILTER-FIXTURE-AUTHOR"


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "List Filters", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record finding-list fixture rows",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _finding_payload(slug: str = "VA-001", **over) -> dict:
    payload = {
        "slug": slug,
        "title": "IDOR in /api/users/{id} allows anon read of any user PII",
        "severity": "high",
        "workflow_status": "active",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "canonical_location": "https://app.example/api/users",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        "provenance": {
            "agent_id": AUTHOR_AGENT_ID,
            "agent_name": "vulnerability-analyst",
        },
    }
    payload.update(over)
    return payload


# ──────────────────────────────────────────────────────────────────────────
# Vocabulary sync across the two packages
# ──────────────────────────────────────────────────────────────────────────


def test_cli_and_backend_verification_vocabulary_stay_in_sync():
    from assess.lib.contracts import VERIFICATION_STATUSES as CLI_VERIFICATION_STATUSES

    assert set(CLI_VERIFICATION_STATUSES) == {
        str(status) for status in BACKEND_VERIFICATION_STATUSES
    }
    # The retired two-axis composite. `confirmed` replaced it; a prompt or CLI
    # that reintroduces `verified` is naming a value no seam accepts.
    assert "verified" not in CLI_VERIFICATION_STATUSES


def test_cli_verify_transition_targets_match_the_backend_request_literal():
    from assess.lib.contracts import VERIFICATION_TRANSITION_STATUSES

    backend_targets = set(
        FindingVerifyRequest.model_fields["verification_status"].annotation.__args__
    )
    assert set(VERIFICATION_TRANSITION_STATUSES) == backend_targets
    # `unreviewed` is the state a finding is RECORDED in, never a verifier's decision.
    assert "unreviewed" not in VERIFICATION_TRANSITION_STATUSES


# ──────────────────────────────────────────────────────────────────────────
# Backend HTTP enforcement
# ──────────────────────────────────────────────────────────────────────────


def test_valid_verification_status_filter_returns_the_matching_row(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    listing = client.get(f"{_base()}/findings", params={"verification_status": "unreviewed"})
    assert listing.status_code == 200, listing.text
    assert [row["slug"] for row in listing.json()] == ["VA-001"]

    empty = client.get(f"{_base()}/findings", params={"verification_status": "confirmed"})
    assert empty.status_code == 200, empty.text
    assert empty.json() == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        # The exact spelling PR #45 stranded in the prompt layer.
        ("verification_status", "verified"),
        ("verification_status", "not_a_status"),
        ("workflow_status", "verified"),
        ("severity", "sev1"),
    ],
)
def test_unknown_enum_filter_is_a_400_not_an_empty_list(
    client, isolate_settings, field, value
):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.get(f"{_base()}/findings", params={field: value})
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    assert f"invalid {field} filter" in detail
    # The error names the vocabulary so one round-trip is enough to self-correct.
    assert "allowed:" in detail


@pytest.mark.parametrize(
    ("field", "allowed"),
    [
        ("verification_status", BACKEND_VERIFICATION_STATUSES),
        ("workflow_status", BACKEND_WORKFLOW_STATUSES),
        ("severity", SEVERITY_RANK),
    ],
)
def test_every_enum_member_is_accepted_as_a_filter(client, isolate_settings, field, allowed):
    _seed(client, isolate_settings)
    for member in allowed:
        resp = client.get(f"{_base()}/findings", params={field: str(member)})
        assert resp.status_code == 200, f"{field}={member}: {resp.text}"


def test_enum_filter_matching_stays_case_insensitive(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.get(f"{_base()}/findings", params={"workflow_status": "ACTIVE"})
    assert resp.status_code == 200, resp.text
    assert [row["slug"] for row in resp.json()] == ["VA-001"]


def test_blank_enum_filter_is_treated_as_absent(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.get(f"{_base()}/findings", params={"verification_status": "  "})
    assert resp.status_code == 200, resp.text
    assert [row["slug"] for row in resp.json()] == ["VA-001"]


# ──────────────────────────────────────────────────────────────────────────
# CLI boundary — the same value dies one step earlier
# ──────────────────────────────────────────────────────────────────────────


def test_finding_list_cli_rejects_the_retired_verified_value():
    from assess.commands import list_findings

    parser = argparse.ArgumentParser()
    list_findings.register(parser.add_subparsers(dest="command"))

    assert parser.parse_args(["list", "--verification-status", "confirmed"]).verification_status == "confirmed"
    with pytest.raises(SystemExit) as exit_info:
        parser.parse_args(["list", "--verification-status", "verified"])
    assert exit_info.value.code == 2
