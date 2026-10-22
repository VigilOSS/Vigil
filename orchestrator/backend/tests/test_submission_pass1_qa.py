from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from tests.test_report_export import ENGAGEMENT_KEY
from tests.test_submission_versions_api import (
    BASE,
    _seed_reportable_finding,
    _triage_dispatches,
    _write_workspace,
)


def _setup(client, isolate_settings):
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding, reviewed=False)
    identities = _triage_dispatches(client, finding["slug"])
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (root / "ENGAGEMENT.md").write_text("# Program facts\n", encoding="utf-8")
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    packet = importlib.import_module(
        "assess.commands.export_triage_packet"
    ).build_packet(root, finding["slug"])
    return (
        finding,
        root,
        {
            "finding_slug": finding["slug"],
            "packet_id": packet["packet_id"],
            "auditor_dispatch_agent_id": identities["writer_dispatch_agent_id"],
            "verdict": "pass",
            "reason": "Checked preconditions, claims, reproduction, and selected evidence after editing",
        },
    )


def test_pass1_qa_records_editing_writer_and_exposes_current_package_without_replacing_blind_review(
    client, isolate_settings
):
    finding, root, payload = _setup(client, isolate_settings)
    response = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "pass1_qa_verdict", "payload": payload},
    )
    assert response.status_code == 201, response.text
    detail = client.get(f"{BASE}/submissions/{finding['slug']}").json()
    qa = detail["pass1_qa"]
    assert qa["status"] == "current"
    assert qa["auditor_dispatch_agent_id"] == payload["auditor_dispatch_agent_id"]
    assert qa["packet_id"] == payload["packet_id"]
    assert not detail["readiness"]["final_ready"]
    assert not detail["blind_triage"]["accepted"]
    (root / f"submissions/{finding['slug']}/submission-body.md").write_text(
        "Changed outgoing report", encoding="utf-8"
    )
    stale = client.get(f"{BASE}/submissions/{finding['slug']}").json()["pass1_qa"]
    assert stale["status"] == "stale"
    assert stale["issue"]


@pytest.mark.parametrize("invalid", ["unknown-dispatch", "", None])
def test_pass1_qa_requires_recorded_auditor_dispatch(client, isolate_settings, invalid):
    _, _, payload = _setup(client, isolate_settings)
    payload["auditor_dispatch_agent_id"] = invalid
    response = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "pass1_qa_verdict", "payload": payload},
    )
    assert response.status_code == 422, response.text


def test_latest_blocked_qa_supersedes_pass_and_missing_is_explicit(
    client, isolate_settings
):
    finding, _, payload = _setup(client, isolate_settings)
    assert (
        client.get(f"{BASE}/submissions/{finding['slug']}").json()["pass1_qa"]["status"]
        == "missing"
    )
    for verdict in ["pass", "blocked"]:
        response = client.post(
            f"{BASE}/dispatch-decisions",
            json={
                "kind": "pass1_qa_verdict",
                "payload": {**payload, "verdict": verdict},
            },
        )
        assert response.status_code == 201, response.text
    assert (
        client.get(f"{BASE}/submissions/{finding['slug']}").json()["pass1_qa"]["status"]
        == "blocked"
    )


def test_pass1_qa_tracks_current_attachment_selection_not_only_its_own_packet(
    client, isolate_settings
):
    from tests.test_submission_versions_api import _approve_packet, _register_file

    finding, _, payload = _setup(client, isolate_settings)
    assert (
        client.post(
            f"{BASE}/dispatch-decisions",
            json={"kind": "pass1_qa_verdict", "payload": payload},
        ).status_code
        == 201
    )
    attachment = _register_file(
        client,
        isolate_settings,
        "evidence/additional.txt",
        b"additional checked evidence",
    )
    _approve_packet(client, isolate_settings, finding["slug"], [attachment])
    detail = client.get(f"{BASE}/submissions/{finding['slug']}").json()
    assert detail["default_attachment_ids"] == [attachment["id"]]
    assert detail["pass1_qa"]["status"] == "stale"
    assert "attachments" in detail["pass1_qa"]["issue"]
    selected = client.get(
        f"{BASE}/submissions/{finding['slug']}/readiness?attachment_id={attachment['id']}"
    ).json()
    assert selected["pass1_qa"]["status"] == "stale"
    original = client.get(f"{BASE}/submissions/{finding['slug']}/readiness").json()
    assert original["pass1_qa"]["status"] == "current"


@pytest.mark.parametrize("changed_input", ["platform", "brief", "missing_brief"])
def test_pass1_qa_stales_when_recipient_context_changes(
    client, isolate_settings, changed_input
):
    finding, root, payload = _setup(client, isolate_settings)
    assert (
        client.post(
            f"{BASE}/dispatch-decisions",
            json={"kind": "pass1_qa_verdict", "payload": payload},
        ).status_code
        == 201
    )
    if changed_input == "platform":
        context_path = root / f"submissions/{finding['slug']}/submission-context.json"
        context = json.loads(context_path.read_text())
        context["platform"] = "direct"
        context_path.write_text(json.dumps(context), encoding="utf-8")
    elif changed_input == "brief":
        (root / "ENGAGEMENT.md").write_text(
            "# Updated recipient requirements\n", encoding="utf-8"
        )
    else:
        (root / "ENGAGEMENT.md").unlink()
    response = client.get(f"{BASE}/submissions/{finding['slug']}")
    assert response.status_code == 200, response.text
    qa = response.json()["pass1_qa"]
    assert qa["status"] == "stale"
    assert qa["issue"]
