"""Write-time integrity gates on the finding severity and CVSS axes.

Two defects the report gate could only observe after the fact:

1. ``finding verify --new-severity`` was consumed ONLY by the ``downgraded``
   branch. Under any other disposition the flag was accepted, silently dropped,
   and answered 200 — a verifier who believed they had re-banded a finding got
   the old band back.
2. Nothing held ``details.cvss_score`` to ``details.cvss_vector`` on write. The
   report-readiness blocker caught the drift, but only for findings that reached
   ``verified`` + ``confirmed``/``downgraded``, and only at report time.
"""
from __future__ import annotations

import json

import pytest

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation

ENGAGEMENT_KEY = "2026-08-25-090000-cvss-gates"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"

# Both pairs are internally consistent — the gate under test rejects anything else.
_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
_HIGH_SCORE = 7.5
_INFO_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "CVSS gates", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    author = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "CVSS-AUTHOR",
            "agent_role": "vulnerability-analyst",
            "task": "Record CVSS fixture findings.",
        },
    )
    assert author.status_code == 201, author.text


def _record(client, slug: str, **overrides):
    payload = {
        "slug": slug,
        "title": f"Finding {slug}",
        "severity": "high",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "canonical_location": f"https://app.example/{slug.lower()}",
        "summary": "Summary",
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": "CVSS-AUTHOR"},
        "details": {
            "evidence": "proof",
            "impact": "impact",
            "cvss_score": _HIGH_SCORE,
            "cvss_vector": _HIGH_VECTOR,
        },
    }
    payload.update(overrides)
    return client.post(f"{BASE}/findings", json=payload)


def _verify(client, slug: str, **overrides):
    payload = {
        "verification_status": "confirmed",
        "reason_text": "reproduced end to end",
        "source_name": "verifier",
    }
    payload.update(overrides)
    if payload["verification_status"] == "downgraded":
        agent_id = f"VERIFY-{slug}"
        dispatch = client.post(
            f"{BASE}/dispatches",
            json={
                "agent_id": agent_id,
                "agent_role": "fixture-verifier",
                "task": f"Independently verify {slug}",
            },
        )
        assert dispatch.status_code == 201, dispatch.text
        run = client.post(
            f"{BASE}/assessment-runs",
            json={
                "run_uuid": f"cvss-gate-{slug}",
                "run_kind": "shared",
                "producer_dispatch_agent_id": agent_id,
            },
        )
        assert run.status_code == 201, run.text
        linked = client.post(
            f"{BASE}/findings/{slug}/links",
            json={
                "link_kind": "proof_run", "target_kind": "assessment_run",
                "target_id": run.json()["id"],
            },
        )
        assert linked.status_code == 200, linked.text
        receipt = post_artifact_backed_source_observation(
            client,
            f"{BASE}/proof-receipts",
            json={
                "run_id": run.json()["id"],
                "evidence_kind": "source_observation",
                "expected_result": "the finding severity survives independent review",
                "observed_result": "the independent review supports a lower severity",
            },
        )
        assert receipt.status_code == 201, receipt.text
        completed = client.patch(
            f"{BASE}/assessment-runs/{run.json()['id']}",
            json={"status": "completed"},
        )
        assert completed.status_code == 200, completed.text
        receipt_id = receipt.json()["id"]
        payload["proof_receipt_ids"] = [receipt_id]
        payload["confirm_check"] = completed_confirm_check(receipt_id)
        payload["severity_variance"] = {
            "normal_band": "high",
            "chosen_severity": payload["new_severity"],
            "actor": "fixture-verifier",
            "reason": "The fixture exercises an attributed downgrade from the CVSS band.",
            "proof_receipt_id": receipt_id,
        }
    return client.post(f"{BASE}/findings/{slug}/verify", json=payload)


# --------------------------------------------------------------------------- #
# new_severity outside the downgraded disposition
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "disposition",
    ["confirmed", "pending_runtime_proof", "blocked", "false_positive", "disputed"],
)
def test_verify_rejects_new_severity_outside_downgraded(
    client, isolate_settings, disposition
):
    _seed(client, isolate_settings)
    assert _record(client, "VA-001").status_code == 201

    response = _verify(
        client,
        "VA-001",
        verification_status=disposition,
        new_severity="low",
        details={"kill_reason": "not exploitable", "kill_check": 3, "block_reason": "no account"},
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "new_severity" in detail
    # The rejection must name the verb that DOES re-band a finding.
    assert "finding update VA-001 --severity low" in detail

    # And the severity is untouched, not half-applied.
    assert client.get(f"{BASE}/findings/VA-001").json()["severity"] == "high"


def test_verify_downgraded_still_consumes_new_severity(client, isolate_settings):
    _seed(client, isolate_settings)
    assert _record(client, "VA-002").status_code == 201

    response = _verify(
        client,
        "VA-002",
        verification_status="downgraded",
        new_severity="medium",
    )

    assert response.status_code == 200, response.text
    assert client.get(f"{BASE}/findings/VA-002").json()["severity"] == "medium"


# --------------------------------------------------------------------------- #
# cvss_score <-> cvss_vector agreement, at write time
# --------------------------------------------------------------------------- #


def test_record_rejects_a_score_that_disagrees_with_its_vector(client, isolate_settings):
    _seed(client, isolate_settings)

    response = _record(
        client,
        "VA-010",
        details={"evidence": "e", "impact": "i", "cvss_score": 9.8, "cvss_vector": _HIGH_VECTOR},
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "9.8" in detail and "7.5" in detail


def test_record_rejects_an_unparseable_vector(client, isolate_settings):
    _seed(client, isolate_settings)

    response = _record(
        client,
        "VA-011",
        details={"evidence": "e", "impact": "i", "cvss_vector": "CVSS:3.1/AV:N"},
    )

    assert response.status_code == 400, response.text
    assert "CVSS:3.1/AV:N" in response.json()["detail"]


def test_patch_scores_a_partial_update_against_the_stored_vector(
    client, isolate_settings
):
    """A patch supplying only the score is judged on the EFFECTIVE merged pair."""
    _seed(client, isolate_settings)
    assert _record(client, "VA-012").status_code == 201

    bad = client.patch(f"{BASE}/findings/VA-012", json={"details": {"cvss_score": 3.2}})
    assert bad.status_code == 400, bad.text
    assert "7.5" in bad.json()["detail"]

    good = client.patch(
        f"{BASE}/findings/VA-012",
        json={"details": {"cvss_score": 0.0, "cvss_vector": _INFO_VECTOR}},
    )
    assert good.status_code == 200, good.text
    stored = client.get(f"{BASE}/findings/VA-012").json()["details"]
    assert stored["cvss_score"] == 0.0
    assert stored["cvss_vector"] == _INFO_VECTOR


def test_a_legacy_mismatch_never_traps_an_unrelated_patch(client, isolate_settings):
    """A row written before this gate existed stays editable.

    Validating a write that touches neither CVSS key would make the stored
    mismatch reject every later edit — including the one that fixes it.
    """
    _seed(client, isolate_settings)
    assert _record(client, "VA-013").status_code == 201
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT details_json FROM assessment_findings WHERE slug = ?", ("VA-013",)
        ).fetchone()
        details = json.loads(row[0])
        details["cvss_score"] = 2.0
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps(details), "VA-013"),
        )

    untouched = client.patch(f"{BASE}/findings/VA-013", json={"summary": "revised"})
    assert untouched.status_code == 200, untouched.text

    repaired = client.patch(
        f"{BASE}/findings/VA-013",
        json={"details": {"cvss_score": _HIGH_SCORE, "cvss_vector": _HIGH_VECTOR}},
    )
    assert repaired.status_code == 200, repaired.text


@pytest.mark.parametrize("empty", [None, "", [], {}], ids=["null", "blank", "list", "dict"])
def test_an_empty_cvss_key_is_not_an_authoring_write(client, isolate_settings, empty):
    """A merge-mode patch drops empty incoming values, so a CVSS key carrying
    one changes nothing — and must not be judged as if it did.

    Otherwise a payload file that spells a key out as null would be rejected on
    the strength of stored data the caller never touched, over a write that was
    a no-op for the pair.
    """
    _seed(client, isolate_settings)
    assert _record(client, "VA-015").status_code == 201
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT details_json FROM assessment_findings WHERE slug = ?", ("VA-015",)
        ).fetchone()
        details = json.loads(row[0])
        details["cvss_score"] = 2.0
        connection.execute(
            "UPDATE assessment_findings SET details_json = ? WHERE slug = ?",
            (json.dumps(details), "VA-015"),
        )

    response = client.patch(
        f"{BASE}/findings/VA-015",
        json={"details": {"cvss_score": empty, "impact": "still exploitable"}},
    )

    assert response.status_code == 200, response.text
    stored = client.get(f"{BASE}/findings/VA-015").json()["details"]
    assert stored["impact"] == "still exploitable"
    # The no-op stayed a no-op: the stored (bad) score is untouched, not nulled.
    assert stored["cvss_score"] == 2.0


def test_a_replace_patch_still_judges_an_empty_cvss_key(client, isolate_settings):
    """``details_mode='replace'`` stores the payload verbatim, so an empty CVSS
    value DOES land — and is judged. The empty-value carve-out above is a
    property of the merge write, not a blanket exemption."""
    _seed(client, isolate_settings)
    assert _record(client, "VA-016").status_code == 201

    response = client.patch(
        f"{BASE}/findings/VA-016",
        json={
            "details": {"cvss_score": "", "cvss_vector": _HIGH_VECTOR},
            "details_mode": "replace",
            "expected_row_version": 1,
        },
    )

    assert response.status_code == 400, response.text
    # The details-schema check is the outer gate and answers first with the same
    # verdict the CVSS-pair check would give; both name the offending value.
    assert "details.cvss_score must be of type number, got ''" in response.json()["detail"]


def test_an_info_finding_is_representable_end_to_end(client, isolate_settings):
    """cvss_score 0.0 is the ONLY score in the `info` band; it must be storable
    and must not trip the severity<->CVSS or vector<->score readiness blockers."""
    _seed(client, isolate_settings)

    created = _record(
        client,
        "VA-014",
        severity="info",
        verification_status="unreviewed",
        details={
            "evidence": "e",
            "impact": "i",
            "remediation": "note it",
            "steps_to_reproduce": ["observe the banner"],
            "cvss_score": 0.0,
            "cvss_vector": _INFO_VECTOR,
        },
    )
    assert created.status_code == 201, created.text

    blockers = client.get(f"{BASE}/report-readiness").json()["blockers"]
    assert not [
        blocker
        for blocker in blockers
        if blocker.get("slug") == "VA-014"
        and blocker["kind"] in {"severity_cvss_mismatch", "cvss_vector_score_mismatch"}
    ], blockers
