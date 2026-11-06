"""What a reportable finding's evidence and its verdict actually rest on.

Two report-readiness gates read the same question from opposite ends:

* A source-derived code finding cites a file and a line inside the generation
  its binding seals; its proof receipts are source observations over those
  exact bytes. There is no separate engagement artifact to index, so demanding
  an ``evidence_ref`` could only be satisfied by attaching something unrelated.
  The ``finding_repro_runs_missing`` advisory already exempts exactly this
  shape.
* An operator-authority verdict rests on out-of-snapshot evidence and names no
  proof receipt at all. ADR 0019 lets the operator weaken a gate over their own
  engagement; readiness must never let that verdict read as dispatch-verified.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex

import pytest

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation
from tests.test_finding_code_snapshot_provenance import (
    _ENGAGEMENT_KEY,
    _advance_repo,
    _dispatch,
    _finding_payload,
    _info_severity_variance,
    _record,
    _seed_repo,
    _verification_receipt,
    _verify,
)

BASE = f"/engagements/{_ENGAGEMENT_KEY}/assessment"


def _readiness(client) -> dict:
    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    return response.json()


def _kinds(items) -> list[str]:
    return [str(item["kind"]) for item in items]


def _slugs_for(items, kind: str) -> list[str]:
    return [str(item.get("slug", "")) for item in items if item["kind"] == kind]


def _engagement_id() -> int:
    with db_module.get_connection() as connection:
        return int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (_ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )


def _recorded(
    client,
    isolate_settings,
    slug: str,
    *,
    location: str = "file:src/parser.c:41",
    bind: bool = True,
    quality: str = "verified",
    **payload_overrides,
) -> dict[str, object]:
    binding = _seed_repo(client, isolate_settings, quality=quality)
    author = f"hunter-{slug.lower()}"
    _dispatch(client, author)
    payload = _finding_payload(
        slug,
        binding if bind else None,
        location=location,
        author_agent_id=author,
    )
    payload.update(payload_overrides)
    recorded = _record(client, payload)
    assert recorded.status_code == 201, recorded.text
    _dispatch(client, f"cvv-{slug.lower()}", role="code-vuln-verifier")
    return binding


def _intel_note(client, title: str) -> int:
    response = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/intel/notes",
        json={
            "title": title,
            "body_markdown": "Deployment config read outside the sealed snapshot.",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _intel_tech_component(client, component: str) -> int:
    response = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/intel/tech-components",
        json={
            "component": component,
            "source_name": "operator",
            "confidence": "high",
            "notes": "Vendor build read outside the sealed snapshot.",
        },
    )
    assert response.status_code in (200, 201), response.text
    return int(response.json()["id"])


# The ten intel tables allocate ids independently, so the type is half the
# citation: ``intel get`` takes it as a required positional and the same number
# names a different row in every table.
_INTEL_FIXTURES = {
    "note": lambda client, slug: _intel_note(client, f"Acme deployment config settles {slug}"),
    "tech-component": lambda client, slug: _intel_tech_component(
        client, f"acme-gateway-build-for-{slug}"
    ),
}


# ── Source-bound evidence owes no engagement artifact ────────────────────────


def test_a_source_bound_finding_owes_no_evidence_ref(client, isolate_settings):
    _recorded(client, isolate_settings, "VA-501")

    body = _readiness(client)

    assert "finding_missing_evidence_ref" not in _kinds(body["blockers"]), body


def test_a_source_bound_finding_may_cite_the_sealed_file_as_its_evidence(
    client, isolate_settings
):
    """A ``file:line`` evidence citation is not an unindexed engagement artifact.

    The historical shape: an evidence_ref naming the reviewed source, with no
    artifact row behind it because none was ever written to disk.
    """
    _recorded(client, isolate_settings, "VA-502")
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET evidence_ref = 'src/parser.c:41', evidence_artifact_id = NULL
            WHERE engagement_id = ? AND slug = 'VA-502'
            """,
            (_engagement_id(),),
        )

    body = _readiness(client)

    assert "finding_evidence_unindexed" not in _kinds(body["blockers"]), body


def test_a_non_source_finding_still_owes_an_evidence_ref(client, isolate_settings):
    _recorded(
        client,
        isolate_settings,
        "VA-503",
        location="https://acme.example/api/parse",
        bind=False,
    )

    body = _readiness(client)

    assert _slugs_for(body["blockers"], "finding_missing_evidence_ref") == ["VA-503"]


def test_a_file_finding_off_the_current_snapshot_still_owes_an_evidence_ref(
    client, isolate_settings
):
    """The exemption is paid for by a CURRENT binding, not by the ``file:`` form.

    Once the repository moves on, the finding cites bytes nothing seals any
    more, so its citation is not evidence and the artifact obligation stands.
    """
    binding = _recorded(client, isolate_settings, "VA-504")
    _advance_repo(binding)

    body = _readiness(client)

    assert _slugs_for(body["blockers"], "finding_missing_evidence_ref") == ["VA-504"]


# ── An operator-authority verdict is visible in readiness ────────────────────


def _operator_authority_downgrade(
    client, slug: str, binding: dict[str, object], *, intel_type: str = "note"
):
    intel_id = _INTEL_FIXTURES[intel_type](client, slug)
    response = _verify(
        client,
        slug,
        {
            "verification_status": "downgraded",
            "reason_code": "operator_authority",
            "reason_text": "The deployment config disables the affected route.",
            "source_name": "operator",
            "new_severity": "info",
            "operator_authority": True,
            "operator_authority_intel_id": intel_id,
            "provenance": {"code_snapshot": binding},
        },
    )
    assert response.status_code == 200, response.text
    return intel_id


def test_readiness_names_a_verdict_that_rests_on_operator_authority(
    client, isolate_settings
):
    binding = _recorded(
        client, isolate_settings, "VA-505", severity="low", evidence_ref="findings.md"
    )
    intel_id = _operator_authority_downgrade(client, "VA-505", binding)

    body = _readiness(client)

    advisory = next(
        item
        for item in body["advisories"]
        if item["kind"] == "finding_operator_authority_verdict"
    )
    assert advisory["slug"] == "VA-505"
    assert advisory["intel_id"] == intel_id
    assert advisory["severity"] == "advisory"
    assert str(intel_id) in advisory["detail"]
    # ADR 0019 permits the waiver, so surfacing it must not gate the report.
    assert "finding_operator_authority_verdict" not in _kinds(body["blockers"])


def test_a_dispatch_verified_verdict_raises_no_operator_authority_advisory(
    client, isolate_settings
):
    _recorded(
        client, isolate_settings, "VA-506", severity="low", evidence_ref="findings.md"
    )
    receipt = _verification_receipt(client, "cvv-va-506", "VA-506")
    confirmed = _verify(
        client,
        "VA-506",
        {
            "verification_status": "confirmed",
            "reason_text": "Independent review confirms the defect.",
            "source_name": "code-vuln-verifier",
            "proof_receipt_ids": [receipt],
            "confirm_check": completed_confirm_check(receipt),
            "severity_variance": {
                **_info_severity_variance(receipt),
                "normal_band": "high",
                "chosen_severity": "low",
            },
        },
    )
    assert confirmed.status_code == 200, confirmed.text

    body = _readiness(client)

    assert "finding_operator_authority_verdict" not in _kinds(body["advisories"])


def test_authority_band_divergence_is_attributed_without_a_receipt_variance(
    client, isolate_settings
):
    binding = _recorded(client, isolate_settings, "VA-511", severity="high")
    _operator_authority_downgrade(client, "VA-511", binding)

    body = _readiness(client)
    assert "severity_cvss_mismatch" not in _kinds(body["blockers"])
    divergence = next(item for item in body["advisories"]
                      if item["kind"] == "severity_cvss_band_divergence")
    assert divergence["slug"] == "VA-511"
    assert "operator" in divergence["detail"].lower()


def test_current_receipts_follow_the_decision_and_survive_kept_edits(
    client, isolate_settings
):
    _recorded(client, isolate_settings, "VA-512", severity="high")
    receipt = _verification_receipt(client, "cvv-va-512", "VA-512")
    confirmed = _verify(client, "VA-512", {
        "verification_status": "confirmed", "reason_text": "Independent confirmation.",
        "source_name": "code-vuln-verifier", "proof_receipt_ids": [receipt],
        "confirm_check": completed_confirm_check(receipt),
    })
    assert confirmed.status_code == 200, confirmed.text
    patched = client.patch(f"{BASE}/findings/VA-512", json={"notes": "Presentation note."})
    assert patched.status_code == 200, patched.text
    detail = client.get(f"{BASE}/findings/VA-512").json()
    assert [row["id"] for row in detail["proof_receipts"]] == [receipt]

    intel_id = _intel_note(client, "Acme operator independently confirms deployment")
    attested = _verify(client, "VA-512", {
        "verification_status": "confirmed", "reason_text": "Deployment confirms impact.",
        "source_name": "operator", "operator_authority": True,
        "operator_authority_intel_id": intel_id,
    })
    assert attested.status_code == 200, attested.text
    detail = client.get(f"{BASE}/findings/VA-512").json()
    assert detail["proof_receipts"] == []
    assert detail["verification_audit"]["proof_receipt_total"] == 1
    fresh_run = client.post(f"{BASE}/assessment-runs", json={
        "run_uuid": "acme-fresh-confirmation", "run_kind": "code",
        "producer_dispatch_agent_id": "cvv-va-512",
    })
    assert fresh_run.status_code == 201, fresh_run.text
    run_id = fresh_run.json()["id"]
    linked = client.post(f"{BASE}/findings/VA-512/links", json={
        "link_kind": "proof_run", "target_kind": "assessment_run", "target_id": run_id,
    })
    assert linked.status_code == 200, linked.text
    fresh = post_artifact_backed_source_observation(client, f"{BASE}/proof-receipts", json={
        "run_id": run_id, "evidence_kind": "source_observation",
        "expected_result": "The path is unaffected.", "observed_result": "The defect remains.",
    })
    assert fresh.status_code == 201, fresh.text
    fresh_receipt = fresh.json()["id"]
    assert client.patch(f"{BASE}/assessment-runs/{run_id}", json={"status": "completed"}).status_code == 200
    reverified = _verify(client, "VA-512", {
        "verification_status": "confirmed", "reason_text": "Proof-backed confirmation restored.",
        "source_name": "code-vuln-verifier", "proof_receipt_ids": [fresh_receipt],
        "confirm_check": completed_confirm_check(fresh_receipt),
    })
    assert reverified.status_code == 200, reverified.text
    detail = client.get(f"{BASE}/findings/VA-512").json()
    assert [row["id"] for row in detail["proof_receipts"]] == [fresh_receipt]
    assert detail["verification_audit"]["operator_authority"] is None


def test_authority_band_attribution_does_not_waive_cvss_arithmetic(
    client, isolate_settings
):
    binding = _recorded(client, isolate_settings, "VA-514", severity="high")
    _operator_authority_downgrade(client, "VA-514", binding)
    # Historical stored score/vector disagreement still owes a correction.
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET details_json = json_set(details_json, '$.cvss_score', 1) "
            "WHERE engagement_id = ? AND slug = ?", (_engagement_id(), "VA-514"),
        )
    assert "cvss_vector_score_mismatch" in _kinds(_readiness(client)["blockers"])


def test_authority_transition_summary_identifies_its_evidence_before_expansion(
    client, isolate_settings
):
    binding = _recorded(client, isolate_settings, "VA-513", severity="high")
    intel_id = _operator_authority_downgrade(client, "VA-513", binding)
    summaries = client.get(f"{BASE}/findings/VA-513/transitions?projection=summary").json()
    decision = next(row for row in summaries if row["action"] == "verified_downgraded")
    assert decision["operator_authority"]["intel_id"] == intel_id
    assert decision["operator_authority"]["intel_type"] == "note"


# ── Every command a readiness item prints must parse ─────────────────────────
#
# A message naming a verb spelling the CLI does not register is worse than no
# message: the reader runs it, argparse refuses, and the item's whole purpose
# (sending them to the intel row the verdict rests on) is lost.


def _assess_parser() -> argparse.ArgumentParser:
    """The real grouped parser for the verbs these readiness items print."""
    from assess import cli as assess_cli
    from assess.commands import get_intel, list_intel, update_finding

    parser = argparse.ArgumentParser(prog="vigil assess")
    sub = parser.add_subparsers(dest="command")
    assess_cli._register_subcommand_group(
        sub,
        name="intel",
        help_text="Structured intel.",
        dest="intel_action",
        leaf_modules=(get_intel, list_intel),
    )
    assess_cli._register_subcommand_group(
        sub,
        name="finding",
        help_text="Finding lifecycle.",
        dest="finding_action",
        leaf_modules=(update_finding,),
    )
    return parser


_PRINTED_COMMAND_RE = re.compile(r"`vigil assess ([^`]+)`")


def _printed_commands(detail: str) -> list[list[str]]:
    return [
        shlex.split(command)
        for command in _PRINTED_COMMAND_RE.findall(detail)
    ]


def _authority_advisory(client) -> dict:
    return next(
        item
        for item in _readiness(client)["advisories"]
        if item["kind"] == "finding_operator_authority_verdict"
    )


@pytest.mark.parametrize("intel_type", sorted(_INTEL_FIXTURES))
def test_the_operator_authority_advisory_names_the_table_holding_the_evidence(
    client, isolate_settings, intel_type: str
):
    """``intel get`` takes the type as a required positional over ten tables.

    Each table allocates its own ids, so a command naming the wrong one sends
    the reader to an unrelated row or to nothing at all — and the whole purpose
    of the advisory is sending them to the evidence the verdict rests on.
    """
    slug = f"VA-{507 if intel_type == 'note' else 508}"
    binding = _recorded(
        client, isolate_settings, slug, severity="low", evidence_ref="findings.md"
    )
    intel_id = _operator_authority_downgrade(
        client, slug, binding, intel_type=intel_type
    )

    advisory = _authority_advisory(client)
    assert advisory["intel_type"] == intel_type
    commands = _printed_commands(advisory["detail"])

    assert commands, advisory["detail"]
    parser = _assess_parser()
    for argv in commands:
        parsed = parser.parse_args(argv)
        assert parsed.command == "intel"
        assert parsed.intel_type == intel_type
        assert parsed.intel_id == intel_id


def test_the_advisory_command_survives_a_later_row_reusing_the_same_id(
    client, isolate_settings
):
    """The stakes: the same number is a live row in more than one table.

    The citation resolves to exactly one live row when it is recorded, but
    nothing stops a later note from landing on that same id in its own table. A
    command that assumed a table would then open a record the operator never
    cited and present it as the evidence behind a terminal verdict.
    """
    binding = _recorded(
        client, isolate_settings, "VA-509", severity="low", evidence_ref="findings.md"
    )
    intel_id = _operator_authority_downgrade(
        client, "VA-509", binding, intel_type="tech-component"
    )
    collision = _intel_note(client, "An unrelated note that landed on the same id")
    assert collision == intel_id, "fixture needs the two tables to collide"

    advisory = _authority_advisory(client)
    parser = _assess_parser()

    for argv in _printed_commands(advisory["detail"]):
        parsed = parser.parse_args(argv)
        assert parsed.intel_type == "tech-component"
        assert parsed.intel_id == intel_id


def test_the_advisory_still_names_a_typeless_stamp_without_guessing_a_table(
    client, isolate_settings
):
    """A stamp with no type recorded is named, and no table is invented for it.

    Every stamp this release writes carries the resolved type, but
    ``provenance_json`` is free-form and the advisory is the surface that exists
    so the waiver cannot hide. Printing a type-shaped command over a stamp that
    names no table would resolve against whichever table was guessed, which is
    the defect this item exists to prevent.
    """
    binding = _recorded(
        client, isolate_settings, "VA-510", severity="low", evidence_ref="findings.md"
    )
    intel_id = _operator_authority_downgrade(client, "VA-510", binding)
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT provenance_json FROM assessment_findings WHERE slug = ?",
            ("VA-510",),
        ).fetchone()
        stored = json.loads(row["provenance_json"])
        stored["operator_authority"].pop("intel_type")
        connection.execute(
            "UPDATE assessment_findings SET provenance_json = ? WHERE slug = ?",
            (json.dumps(stored), "VA-510"),
        )

    advisory = _authority_advisory(client)

    assert advisory["slug"] == "VA-510"
    assert advisory["intel_id"] == intel_id
    assert advisory["intel_type"] is None
    assert str(intel_id) in advisory["detail"]
    assert "The deployment config disables the affected route." in advisory["detail"]
    commands = _printed_commands(advisory["detail"])
    assert commands, advisory["detail"]
    parser = _assess_parser()
    intel_commands = [
        parser.parse_args(argv)
        for argv in commands
        if parser.parse_args(argv).command == "intel"
    ]
    assert intel_commands, commands
    for parsed in intel_commands:
        # The type-independent read: it names every table and its row count, so
        # the reader can find id N without the advisory guessing which one.
        assert parsed.intel_action == "list"
        assert parsed.intel_type is None
