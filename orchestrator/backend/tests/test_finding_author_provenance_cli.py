"""`finding record` must be able to mint a terminally-verifiable finding.

The backend refuses every terminal verification transition
(``confirmed`` / ``downgraded`` / ``false_positive``) whose finding carries no
``provenance.agent_id`` resolving to a dispatch distinct from the verifier's
(``state_manager/proofs.py``). ``FindingProvenance`` is ``extra="allow"``, so a
raw HTTP POST could always carry that key — but the generated CLI schema
declared ``provenance`` with ``additionalProperties: false`` and no
``agent_id``, and ``finding record`` validates against that schema and exits
before the POST. Every finding minted through the documented CLI path was
therefore pinned at ``unreviewed`` forever, with a green backend suite.

This module covers the whole path in one place, because no single layer shows
the defect: the generated schema must admit the key, the CLI must carry the
authoring dispatch id into it, and the finding that comes out the other end must
actually reach ``confirmed``.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

import pytest

from tests.test_engagements_api import write_engagement
from tests.proof_fixtures import completed_confirm_check
from app import db as db_module

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

record_finding = importlib.import_module("assess.commands.record_finding")
finding_ids = importlib.import_module("assess.lib.findings")
assess_cli = importlib.import_module("assess.cli")
schema_validation = importlib.import_module("assess.lib.schema_validation")


ENGAGEMENT_KEY = "2026-09-11-author-provenance"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
AUTHOR_DISPATCH = "HUNT-RUN-1"
VERIFIER_DISPATCH = "VERIFY-RUN-1"


def test_blue_alert_triage_role_has_a_canonical_finding_prefix() -> None:
    assert finding_ids.finding_prefix_for_agent("alert-triage-specialist") == "AT"


def test_finding_bind_author_is_a_documented_cli_action(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        assess_cli.main(["finding", "bind-author", "--help"])
    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    assert "--agent-id" in help_text
    assert "--expected-row-version" in help_text


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (
        (AUTHOR_DISPATCH, "vulnerability-analyst"),
        (VERIFIER_DISPATCH, "code-vuln-verifier"),
    ):
        response = client.post(
            f"{BASE}/dispatches",
            json={"agent_id": agent_id, "agent_role": role, "task": role},
        )
        assert response.status_code == 201, response.text


def _cli_payload(slug: str, *, dispatch_agent_id: str) -> dict:
    """Return exactly what ``finding record`` would POST for one finding."""

    return record_finding._normalize_payload(
        {
            "title": f"{slug} allows cross-tenant read",
            "severity": "high",
            "defect_family": "access-control",
            "root_cause_key": "missing-object-authz",
            "canonical_location": f"https://app.example/api/{slug}",
            "summary": "An object reference is not bound to the caller's tenant.",
            "details": {
                "evidence": "response returned another tenant's record",
                "impact": "cross-tenant disclosure of customer records",
            },
        },
        agent_name="vulnerability-analyst",
        candidate_slug=slug,
        dispatch_agent_id=dispatch_agent_id,
    )


def _verifier_receipt(client, suffix: str, finding_slug: str) -> int:
    """Return a healthy command receipt owned by the independent verifier."""

    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"verify-run-{suffix}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": VERIFIER_DISPATCH,
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/{finding_slug}/links",
        json={"link_kind": "proof_run", "target_kind": "assessment_run", "target_id": run.json()["id"]},
    )
    assert linked.status_code == 200, linked.text
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": f"verify-command-{suffix}",
            "agent_name": VERIFIER_DISPATCH,
            "command": "replay the cross-tenant request as the verifier",
            "tool_name": "curl",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-09-11T12:00:00Z",
            "completed_at": "2026-09-11T12:00:01Z",
            "stdout": "HTTP/1.1 200 OK\nanother tenant's record\n",
        },
    )
    assert command.status_code == 201, command.text
    receipt = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "expected_result": "the request is refused for a foreign tenant",
            "observed_result": "the foreign tenant's record is returned",
        },
    )
    assert receipt.status_code == 201, receipt.text
    sealed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}", json={"status": "completed"}
    )
    assert sealed.status_code == 200, sealed.text
    return int(receipt.json()["id"])


def _seed_legacy_finding(slug: str, *, agent_id: str = "") -> int:
    """Insert a historical row with missing or unresolvable author provenance."""

    with db_module.get_connection() as connection:
        engagement = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()
        assert engagement is not None
        cursor = connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status, verification_status,
                defect_family, root_cause_key, auth_context, canonical_location,
                source_name, summary, details_json, provenance_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(engagement["id"]),
                slug,
                f"{slug} legacy authorless finding",
                "high",
                "active",
                "unreviewed",
                "access-control",
                f"legacy-{slug.lower()}",
                "anonymous",
                f"https://app.example/api/{slug}",
                "vulnerability-analyst",
                "Imported from a database created before author dispatch provenance.",
                json.dumps({"evidence": "legacy evidence", "impact": "legacy impact"}),
                json.dumps({"agent_id": agent_id}) if agent_id else "{}",
            ),
        )
        finding_id = int(cursor.lastrowid)
    return finding_id


def test_generated_finding_schema_admits_the_authoring_dispatch_id() -> None:
    """The CLI validator is the layer that used to reject the key outright."""

    schema = schema_validation.load_schema("finding-record.schema.json")
    provenance = schema["properties"]["provenance"]
    assert provenance["additionalProperties"] is False
    assert "agent_id" in provenance["properties"]

    payload = _cli_payload("VA-001", dispatch_agent_id=AUTHOR_DISPATCH)
    assert payload["provenance"]["agent_id"] == AUTHOR_DISPATCH
    assert schema_validation.collect_validation_errors(payload, schema) == []


def test_record_finding_carries_only_an_explicit_authoring_dispatch_id() -> None:
    """A role name is not a dispatch id, so it must never stand in for one."""

    without_carrier = _cli_payload("VA-002", dispatch_agent_id="")
    assert "agent_id" not in without_carrier["provenance"]
    assert without_carrier["provenance"]["agent_name"] == "vulnerability-analyst"

    explicit = record_finding._normalize_payload(
        {"title": "t", "provenance": {"agent_id": "PAYLOAD-OWNED"}},
        agent_name="vulnerability-analyst",
        candidate_slug="VA-003",
        dispatch_agent_id=AUTHOR_DISPATCH,
    )
    assert explicit["provenance"]["agent_id"] == "PAYLOAD-OWNED"


def test_record_finding_registers_the_agent_id_carrier() -> None:
    parser = argparse.ArgumentParser()
    record_finding.register(parser.add_subparsers(dest="verb"))
    carried = parser.parse_args(
        ["record", "vulnerability-analyst", "f.json", "--agent-id", AUTHOR_DISPATCH]
    )
    assert carried.agent_id == AUTHOR_DISPATCH
    omitted = parser.parse_args(["record", "vulnerability-analyst", "f.json"])
    assert omitted.agent_id == ""


def test_record_finding_cli_refuses_missing_or_unresolvable_author(
    monkeypatch, capsys
) -> None:
    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, path):
            if path == f"dispatches/{AUTHOR_DISPATCH}":
                return {"agent_id": AUTHOR_DISPATCH}
            raise record_finding.AssessError("HTTP 404\nmissing dispatch")

    monkeypatch.setattr(record_finding, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit, match="1"):
        record_finding._require_authoring_dispatch(
            _cli_payload("VA-004", dispatch_agent_id=""),
            existing=None,
            base_url="http://backend",
            engagement_key=ENGAGEMENT_KEY,
        )
    assert "--agent-id" in capsys.readouterr().err

    with pytest.raises(SystemExit, match="1"):
        record_finding._require_authoring_dispatch(
            _cli_payload("VA-005", dispatch_agent_id="NOT-A-DISPATCH"),
            existing=None,
            base_url="http://backend",
            engagement_key=ENGAGEMENT_KEY,
        )
    assert "does not resolve to a dispatch" in capsys.readouterr().err

    record_finding._require_authoring_dispatch(
        _cli_payload("VA-006", dispatch_agent_id=AUTHOR_DISPATCH),
        existing=None,
        base_url="http://backend",
        engagement_key=ENGAGEMENT_KEY,
    )


def test_record_finding_cli_update_uses_but_does_not_rebind_stored_author(
    monkeypatch,
) -> None:
    seen: list[str] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, path):
            seen.append(path)
            return {"agent_id": AUTHOR_DISPATCH}

    monkeypatch.setattr(record_finding, "AssessmentClient", FakeClient)
    payload = _cli_payload("VA-007", dispatch_agent_id="")
    existing = {"provenance": {"agent_id": AUTHOR_DISPATCH}}

    record_finding._require_authoring_dispatch(
        payload,
        existing=existing,
        base_url="http://backend",
        engagement_key=ENGAGEMENT_KEY,
    )

    assert "agent_id" not in payload["provenance"]
    assert seen == [f"dispatches/{AUTHOR_DISPATCH}"]


def test_cli_recorded_finding_reaches_confirmed(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    recorded = client.post(
        f"{BASE}/findings", json=_cli_payload("VA-010", dispatch_agent_id=AUTHOR_DISPATCH)
    )
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["finding"]["provenance"]["agent_id"] == AUTHOR_DISPATCH

    receipt_id = _verifier_receipt(client, "va-010", "VA-010")
    confirmed = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent verifier replayed the cross-tenant read",
            "proof_receipt_ids": [receipt_id],
            "confirm_check": completed_confirm_check(receipt_id),
        },
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["finding"]["verification_status"] == "confirmed"


def test_new_finding_without_the_carrier_is_refused(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    recorded = client.post(
        f"{BASE}/findings", json=_cli_payload("VA-011", dispatch_agent_id="")
    )
    assert recorded.status_code == 400, recorded.text
    assert "provenance.agent_id" in recorded.json()["detail"]


def test_new_finding_with_unknown_author_dispatch_is_refused(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    recorded = client.post(
        f"{BASE}/findings",
        json=_cli_payload("VA-014", dispatch_agent_id="NOT-A-DISPATCH"),
    )
    assert recorded.status_code == 400, recorded.text
    assert "does not resolve to a dispatch" in recorded.json()["detail"]


def test_rerecord_omits_author_and_preserves_original_immutable_binding(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    first = client.post(
        f"{BASE}/findings",
        json=_cli_payload("VA-015", dispatch_agent_id=AUTHOR_DISPATCH),
    )
    assert first.status_code == 201, first.text
    rerecord = _cli_payload("VA-015", dispatch_agent_id="")
    rerecord["summary"] = "More evidence, same finding and original author."

    updated = client.post(f"{BASE}/findings", json=rerecord)

    assert updated.status_code == 201, updated.text
    assert updated.json()["finding"]["summary"] == rerecord["summary"]
    assert (
        updated.json()["finding"]["provenance"]["agent_id"] == AUTHOR_DISPATCH
    )


def test_authorless_finding_can_be_bound_once_with_an_audited_repair(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _seed_legacy_finding("VA-012")
    recorded = client.get(f"{BASE}/findings/VA-012")
    assert recorded.status_code == 200, recorded.text
    row_version = recorded.json()["row_version"]

    rerecord = client.post(
        f"{BASE}/findings",
        json=_cli_payload("VA-012", dispatch_agent_id=AUTHOR_DISPATCH),
    )
    assert rerecord.status_code == 400, rerecord.text
    assert "bind-author" in rerecord.json()["detail"]

    repaired = client.put(
        f"{BASE}/findings/VA-012/author",
        json={
            "agent_id": AUTHOR_DISPATCH,
            "actor": "operator",
            "reason": "Recovered from the authoring dispatch handoff.",
            "expected_row_version": row_version,
        },
    )
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["finding"]["provenance"]["agent_id"] == AUTHOR_DISPATCH
    transition = repaired.json()["transition"]
    assert transition["action"] == "author_provenance_repaired"
    assert transition["actor"] == "operator"
    assert transition["metadata_json"]

    second = client.put(
        f"{BASE}/findings/VA-012/author",
        json={
            "agent_id": VERIFIER_DISPATCH,
            "actor": "operator",
            "reason": "Attempt to rewrite a valid author.",
            "expected_row_version": repaired.json()["finding"]["row_version"],
        },
    )
    assert second.status_code == 409, second.text
    assert "already has immutable" in second.json()["detail"]


def test_unresolvable_legacy_author_can_be_replaced_once_with_full_audit(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    old_agent_id = "MISSING-HISTORICAL-DISPATCH"
    _seed_legacy_finding("VA-016", agent_id=old_agent_id)
    recorded = client.get(f"{BASE}/findings/VA-016")
    assert recorded.status_code == 200, recorded.text
    rerecord = client.post(
        f"{BASE}/findings",
        json=_cli_payload("VA-016", dispatch_agent_id=AUTHOR_DISPATCH),
    )
    assert rerecord.status_code == 400, rerecord.text
    assert "bind-author" in rerecord.json()["detail"]

    repaired = client.put(
        f"{BASE}/findings/VA-016/author",
        json={
            "agent_id": AUTHOR_DISPATCH,
            "actor": "operator",
            "reason": "The imported dispatch id was not engagement-local.",
            "expected_row_version": recorded.json()["row_version"],
        },
    )

    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["finding"]["provenance"]["agent_id"] == AUTHOR_DISPATCH
    transition = repaired.json()["transition"]
    assert transition["action"] == "author_provenance_repaired"
    assert transition["reason_text"] == "The imported dispatch id was not engagement-local."
    metadata = json.loads(transition["metadata_json"])
    assert metadata["old_agent_id"] == old_agent_id
    assert metadata["new_agent_id"] == AUTHOR_DISPATCH
    assert metadata["repair_kind"] == "unresolvable_author"


def test_author_repair_rejects_an_unknown_dispatch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _seed_legacy_finding("VA-013")
    recorded = client.get(f"{BASE}/findings/VA-013")
    assert recorded.status_code == 200, recorded.text
    refused = client.put(
        f"{BASE}/findings/VA-013/author",
        json={
            "agent_id": "MISSING-DISPATCH",
            "actor": "operator",
            "reason": "This should not bind.",
            "expected_row_version": recorded.json()["row_version"],
        },
    )
    assert refused.status_code == 400, refused.text
    assert "does not resolve to a dispatch" in refused.json()["detail"]


@pytest.mark.parametrize(
    ("field", "slug"),
    (("actor", "VA-017"), ("reason", "VA-018")),
)
def test_author_repair_rejects_whitespace_only_audit_fields(
    client, isolate_settings, field: str, slug: str
) -> None:
    _seed(client, isolate_settings)
    _seed_legacy_finding(slug)
    recorded = client.get(f"{BASE}/findings/{slug}")
    payload = {
        "agent_id": AUTHOR_DISPATCH,
        "actor": "operator",
        "reason": "Recovered from the dispatch ledger.",
        "expected_row_version": recorded.json()["row_version"],
    }
    payload[field] = "   \t"

    refused = client.put(f"{BASE}/findings/{slug}/author", json=payload)

    assert refused.status_code == 400, refused.text
    assert field in refused.json()["detail"]
    unchanged = client.get(f"{BASE}/findings/{slug}").json()
    assert unchanged["provenance"] == {}


@pytest.mark.parametrize(("slug", "agent_id"), [("VA-021", VERIFIER_DISPATCH)])
def test_terminal_verification_still_requires_an_independent_resolvable_author(
    client, isolate_settings, slug, agent_id
) -> None:
    """Admitting the key must not weaken what the key is checked against."""

    _seed(client, isolate_settings)
    recorded = client.post(
        f"{BASE}/findings", json=_cli_payload(slug, dispatch_agent_id=agent_id)
    )
    assert recorded.status_code == 201, recorded.text

    refused = client.post(
        f"{BASE}/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent verifier replayed the cross-tenant read",
            "proof_receipt_ids": [_verifier_receipt(client, slug.lower(), slug)],
        },
    )
    assert refused.status_code == 400, refused.text
    assert "independent verifier" in refused.json()["detail"]
