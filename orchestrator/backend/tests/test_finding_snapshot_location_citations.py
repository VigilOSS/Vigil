"""A ``file:`` finding must cite a file, and a line inside it, in its sealed snapshot.

The binding proves which generation the author reviewed; the location says where
in it. Both are checked when a write asserts them, after the path is normalized
and before the write can move a verdict.
"""
from __future__ import annotations

import pytest

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_code_snapshot_provenance import (
    _ENGAGEMENT_KEY,
    _SEEDED_FILE_LOC,
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


@pytest.fixture
def binding(client, isolate_settings):
    """The sealed snapshot binding the citation cases below assert against.

    Requested last by each test so the repo is seeded after that test's other
    fixtures, exactly where the per-test ``_seed_repo(...)`` call used to run.
    """
    return _seed_repo(client, isolate_settings)


def _confirmed(client, isolate_settings, slug: str) -> dict[str, object]:
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, f"hunter-{slug.lower()}")
    recorded = _record(
        client,
        _finding_payload(slug, binding, author_agent_id=f"hunter-{slug.lower()}"),
    )
    assert recorded.status_code == 201, recorded.text
    _dispatch(client, f"cvv-{slug.lower()}", role="code-vuln-verifier")
    receipt = _verification_receipt(client, f"cvv-{slug.lower()}", slug)
    verified = _verify(
        client,
        slug,
        {
            "verification_status": "confirmed",
            "reason_text": "Independent source review confirms the copy.",
            "source_name": "code-vuln-verifier",
            "proof_receipt_ids": [receipt],
            "confirm_check": completed_confirm_check(receipt),
            "severity_variance": _info_severity_variance(receipt),
        },
    )
    assert verified.status_code == 200, verified.text
    return binding


def _state(client, slug: str) -> tuple[str, str, int, int]:
    finding = client.get(f"{BASE}/findings/{slug}").json()
    transitions = client.get(f"{BASE}/findings/{slug}/transitions").json()
    return (
        finding["verification_status"],
        finding["canonical_location"],
        int(finding["row_version"]),
        len(transitions),
    )


def test_record_refuses_a_path_absent_from_the_bound_generation(client, binding):
    response = _record(
        client, _finding_payload("VA-301", binding, location="file:src/parsr.c:41")
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert (
        f"'src/parsr.c' is not a file in generation 3 of repository {binding['repo_id']}"
        in detail
    )
    assert "closest admitted path: 'src/parser.c'" in detail
    assert client.get(f"{BASE}/findings/VA-301").status_code == 404


def test_record_refuses_a_line_past_the_end_of_the_file(client, binding):
    response = _record(
        client, _finding_payload("VA-302", binding, location="file:src/parser.c:99999")
    )

    assert response.status_code == 400, response.text
    assert (
        f"line 99999 is outside src/parser.c ({_SEEDED_FILE_LOC} lines)"
        in response.json()["detail"]
    )


@pytest.mark.parametrize(
    "location",
    [
        "file:src/parser.c:null",
        "file:src/parser.c:41:7",
        "file:src/parser.c",
        "file:src/parser.c:40-44",
    ],
)
def test_record_accepts_lineless_column_and_range_forms(client, location, binding):
    response = _record(client, _finding_payload("VA-303", binding, location=location))

    assert response.status_code == 201, response.text
    assert response.json()["finding"]["canonical_location"] == location


def test_record_refuses_a_range_that_runs_past_the_file(client, binding):
    response = _record(
        client,
        _finding_payload(
            "VA-304", binding, location=f"file:src/parser.c:190-{_SEEDED_FILE_LOC + 1}"
        ),
    )

    assert response.status_code == 400, response.text
    assert f"line {_SEEDED_FILE_LOC + 1} is outside src/parser.c" in response.json()["detail"]


def test_an_idempotent_replay_of_a_bad_citation_is_refused(client, binding):
    payload = _finding_payload("VA-305", binding)
    assert _record(client, payload).status_code == 201
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET canonical_location = 'file:src/gone.c:41' "
            "WHERE slug = 'VA-305'"
        )

    replay = _record(client, _finding_payload("VA-305", binding, location="file:src/gone.c:41"))

    assert replay.status_code == 400, replay.text
    assert "'src/gone.c' is not a file in generation 3" in replay.json()["detail"]
    # The stored row itself is left as it was.
    assert client.get(f"{BASE}/findings/VA-305").json()["canonical_location"] == (
        "file:src/gone.c:41"
    )


def test_an_empty_generation_roster_is_refused_with_its_own_message(client, binding):
    with db_module.get_connection() as connection:
        connection.execute("DELETE FROM code_source_generation_files")

    response = _record(client, _finding_payload("VA-306", binding))

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert f"generation 3 of repository {binding['repo_id']} has no files" in detail
    assert "is not a file" not in detail


@pytest.mark.parametrize(
    "location, expected",
    [
        ("file:src/missing.c:41", "'src/missing.c' is not a file in generation 3"),
        ("file:src/parser.c:9999", f"line 9999 is outside src/parser.c ({_SEEDED_FILE_LOC} lines)"),
    ],
)
def test_a_location_patch_outside_the_snapshot_is_refused_and_keeps_the_verdict(
    client, isolate_settings, location, expected
):
    _confirmed(client, isolate_settings, "VA-307")
    before = _state(client, "VA-307")
    assert before[0] == "confirmed"

    patched = client.patch(
        f"{BASE}/findings/VA-307", json={"canonical_location": location}
    )

    assert patched.status_code == 400, patched.text
    assert expected in patched.json()["detail"]
    assert _state(client, "VA-307") == before


@pytest.mark.parametrize(
    "location, expected",
    [
        ("file:src/missing.c:41", "'src/missing.c' is not a file in generation 3"),
        ("file:src/parser.c:9999", "line 9999 is outside src/parser.c"),
    ],
)
def test_a_relocation_outside_the_snapshot_is_refused_and_keeps_the_verdict(
    client, isolate_settings, location, expected
):
    _confirmed(client, isolate_settings, "VA-308")
    before = _state(client, "VA-308")

    relocated = client.put(
        f"{BASE}/findings/VA-308/canonical-location",
        json={
            "canonical_location": location,
            "reason_text": "Source review moved the defect.",
            "source_name": "code-vuln-verifier",
            "expected_row_version": before[2],
        },
    )

    assert relocated.status_code == 400, relocated.text
    assert expected in relocated.json()["detail"]
    assert _state(client, "VA-308") == before


def test_relocation_from_a_web_location_into_a_missing_file_is_refused(client, binding):
    assert _record(
        client, _finding_payload("VA-309", None, location="https://example.com/api/x")
    ).status_code == 201
    row_version = client.get(f"{BASE}/findings/VA-309").json()["row_version"]

    relocated = client.put(
        f"{BASE}/findings/VA-309/canonical-location",
        json={
            "canonical_location": "file:src/missing.c:3",
            "reason_text": "Source review located the defect.",
            "source_name": "code-vuln-verifier",
            "expected_row_version": row_version,
            "provenance": {"code_snapshot": binding},
        },
    )

    assert relocated.status_code == 400, relocated.text
    assert "'src/missing.c' is not a file in generation 3" in relocated.json()["detail"]
    assert client.get(f"{BASE}/findings/VA-309").json()["canonical_location"] == (
        "https://example.com/api/x"
    )


def test_a_rebind_to_a_generation_that_dropped_the_file_is_refused(client, binding):
    _dispatch(client, "hunter-310")
    assert _record(
        client, _finding_payload("VA-310", binding, author_agent_id="hunter-310")
    ).status_code == 201
    current = _advance_repo(binding, dropped_paths=("src/parser.c",))
    _dispatch(client, "cvv-310", role="code-vuln-verifier")
    receipt = _verification_receipt(client, "cvv-310", "VA-310")
    before = _state(client, "VA-310")

    rebound = _verify(
        client,
        "VA-310",
        {
            "verification_status": "confirmed",
            "reason_text": "Re-reviewed the current dataflow.",
            "source_name": "code-vuln-verifier",
            "provenance": {"code_snapshot": current},
            "proof_receipt_ids": [receipt],
            "confirm_check": completed_confirm_check(receipt),
            "severity_variance": _info_severity_variance(receipt),
        },
    )

    assert rebound.status_code == 400, rebound.text
    assert (
        f"'src/parser.c' is not a file in generation 4 of repository {binding['repo_id']}"
        in rebound.json()["detail"]
    )
    assert _state(client, "VA-310") == before


def test_web_findings_are_not_resolved_against_the_snapshot(client, binding):
    recorded = _record(
        client,
        _finding_payload("VA-311", binding, location="https://example.com/src/missing.c"),
    )
    assert recorded.status_code == 201, recorded.text
    patched = client.patch(
        f"{BASE}/findings/VA-311",
        json={"canonical_location": "https://example.com/src/missing.c?line=99999"},
    )

    assert patched.status_code == 200, patched.text
