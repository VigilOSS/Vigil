"""Which evidence a finding's reproduction rests on: source receipts or runtime runs.

A source-derived code finding is reproduced by reading the cited source, so its
current verification receipts are all ``source_observation`` and no command run
stands behind its steps. Asking it for ``details.repro_runs`` could only be
answered by attaching an unrelated run.
"""
from __future__ import annotations

from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_code_snapshot_provenance import (
    _ENGAGEMENT_KEY,
    _dispatch,
    _finding_payload,
    _info_severity_variance,
    _record,
    _seed_repo,
    _verification_receipt,
    _verify,
)

BASE = f"/engagements/{_ENGAGEMENT_KEY}/assessment"


def _confirm(client, slug: str, receipt: int) -> None:
    verified = _verify(
        client,
        slug,
        {
            "verification_status": "confirmed",
            "reason_text": "Independent review confirms the defect.",
            "source_name": "code-vuln-verifier",
            "proof_receipt_ids": [receipt],
            "confirm_check": completed_confirm_check(receipt),
            "severity_variance": _info_severity_variance(receipt),
        },
    )
    assert verified.status_code == 200, verified.text


def _recorded(client, isolate_settings, slug: str, *, location: str = "file:src/parser.c:41"):
    binding = _seed_repo(client, isolate_settings)
    author = f"hunter-{slug.lower()}"
    _dispatch(client, author)
    recorded = _record(
        client,
        _finding_payload(
            slug,
            binding if location.startswith("file:") else None,
            location=location,
            author_agent_id=author,
        ),
    )
    assert recorded.status_code == 201, recorded.text
    _dispatch(client, f"cvv-{slug.lower()}", role="code-vuln-verifier")


def _command_receipt(client, slug: str) -> int:
    verifier = f"cvv-{slug.lower()}"
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"runtime-{slug.lower()}", "run_kind": "shared",
            "producer_dispatch_agent_id": verifier,
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
    command = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": f"runtime-command-{slug.lower()}",
            "command": "./parser oversized.dat", "tool_name": "parser",
            "agent_name": verifier, "phase": "verify",
            "status": "completed", "return_code": 1,
            "started_at": "2026-09-25T12:00:00Z",
            "completed_at": "2026-09-25T12:00:01Z",
            "stdout": "AddressSanitizer: heap-buffer-overflow",
        },
    )
    assert command.status_code == 201, command.text
    proof = client.post(
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"], "evidence_kind": "command",
            "command_run_id": command.json()["id"],
            "observed_result": "AddressSanitizer reported the overflow",
        },
    )
    assert proof.status_code == 201, proof.text
    assert client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}", json={"status": "completed"}
    ).status_code == 200
    return int(proof.json()["id"])


def _repro_advisories(client) -> list[str]:
    body = client.get(f"{BASE}/report-readiness").json()
    return [
        advisory["slug"]
        for advisory in body["advisories"]
        if advisory.get("kind") == "finding_repro_runs_missing"
    ]


def _rehearse_from_source(client, slug: str):
    _dispatch(client, f"cold-{slug.lower()}", role="code-vuln-verifier")
    return client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "repro_rehearsal", "payload": {
            "finding_slug": slug, "verdict": "followed", "proof_mode": "source",
            "verifier_dispatch_agent_id": f"cold-{slug.lower()}",
            "observed_outcome": "The cited copy takes the attacker length unchecked.",
        }},
    )


def test_a_source_only_confirmed_file_finding_has_source_basis_and_no_advisory(
    client, isolate_settings
):
    _recorded(client, isolate_settings, "VA-401")
    _confirm(client, "VA-401", _verification_receipt(client, "cvv-va-401", "VA-401"))

    finding = client.get(f"{BASE}/findings/VA-401").json()

    assert finding["reproduction_basis"] == "source"
    assert "VA-401" not in _repro_advisories(client)
    assert _rehearse_from_source(client, "VA-401").status_code == 201


def test_a_file_finding_with_a_command_receipt_keeps_the_advisory(
    client, isolate_settings
):
    _recorded(client, isolate_settings, "VA-402")
    _confirm(client, "VA-402", _command_receipt(client, "VA-402"))

    finding = client.get(f"{BASE}/findings/VA-402").json()

    assert finding["reproduction_basis"] == "runtime"
    assert "VA-402" in _repro_advisories(client)
    refused = _rehearse_from_source(client, "VA-402")
    assert refused.status_code == 422, refused.text
    assert "source_observation" in refused.json()["detail"]


def test_a_web_finding_with_only_source_receipts_keeps_the_advisory(
    client, isolate_settings
):
    _recorded(client, isolate_settings, "VA-403", location="https://example.com/api/parse")
    _confirm(client, "VA-403", _verification_receipt(client, "cvv-va-403", "VA-403"))

    finding = client.get(f"{BASE}/findings/VA-403").json()

    assert finding["reproduction_basis"] == "runtime"
    assert "VA-403" in _repro_advisories(client)


def test_an_unverified_file_finding_has_runtime_basis(client, isolate_settings):
    _recorded(client, isolate_settings, "VA-404")

    assert client.get(f"{BASE}/findings/VA-404").json()["reproduction_basis"] == "runtime"
