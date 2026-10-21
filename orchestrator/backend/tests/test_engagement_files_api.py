from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.services import artifacts as artifacts_service

ENGAGEMENT_KEY = "2026-03-30-120000-acme-files"
FILES_URL = f"/engagements/{ENGAGEMENT_KEY}/artifacts"
ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
STUB_BRIEF = (
    "# Engagement Program Brief\n\n"
    "> **STUB — fill this in per engagement, or delete it if this engagement has\n"
    "> no program brief.**\n\n## Scope\n\n<!-- In-scope assets. -->\n"
)


def _write_engagement(engagements_dir: Path) -> Path:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps({"key": ENGAGEMENT_KEY, "target": "https://acme.example", "created_at": "2026-03-30T12:00:00Z"}),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "acme.example", "scope_hosts": ["acme.example"], "status": "in_progress"}),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    return engagement_dir


@pytest.fixture
def engagement_dir(client, isolate_settings) -> Path:
    root = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    return root


def _by_name(client) -> dict[str, dict]:
    response = client.get(FILES_URL)
    assert response.status_code == 200, response.text
    return {entry["name"]: entry for entry in response.json()}


def test_files_list_leads_with_working_documents_in_priority_order(client, engagement_dir):
    response = client.get(FILES_URL)
    assert response.status_code == 200, response.text
    entries = response.json()
    names = [entry["name"] for entry in entries]
    working = [entry["name"] for entry in entries if entry["group"] == "working"]
    snapshots = [entry["name"] for entry in entries if entry["group"] == "snapshot"]

    assert working[:6] == [
        "ENGAGEMENT.md",
        "RESUME.md",
        "COMPACT.md",
        "ISSUES-AND-ENHANCEMENTS.md",
        "RULES.md",
        "report.md",
    ]
    assert set(snapshots) == {"scope.json", "capture-policy.json", "engagement.json", "findings.md", "surfaces.jsonl"}
    # Working documents precede snapshots so the list reads in priority order.
    assert names == working + snapshots
    for entry in entries:
        assert entry["role"].strip()
        assert entry["description"].strip()
    by_name = {entry["name"]: entry for entry in entries}
    for snapshot in ("findings.md", "surfaces.jsonl"):
        assert by_name[snapshot]["role"] == "Export snapshot (DB is the source of truth)"


def test_files_list_reports_size_and_utc_modified_time_only_for_present_files(client, engagement_dir):
    (engagement_dir / "RESUME.md").write_text("# Resume\n\nNext: re-run the Acme login check.\n", encoding="utf-8")

    entries = _by_name(client)

    resume = entries["RESUME.md"]
    assert resume["exists"] is True
    assert resume["size_bytes"] == (engagement_dir / "RESUME.md").stat().st_size
    assert ISO_Z.match(resume["modified_at"])
    missing = entries["COMPACT.md"]
    assert missing["exists"] is False
    assert missing["size_bytes"] is None
    assert missing["modified_at"] is None


def test_files_read_returns_exact_bytes_for_files_under_the_view_limit(client, engagement_dir):
    text = "# Resume\n\nAuthorization: Bearer acme-token-123\n"
    (engagement_dir / "RESUME.md").write_text(text, encoding="utf-8")

    response = client.get(f"{FILES_URL}/RESUME.md")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["content"] == text
    assert body["truncated"] is False
    assert body["size_bytes"] == len(text.encode("utf-8"))
    assert body["returned_bytes"] == len(text.encode("utf-8"))
    assert ISO_Z.match(body["modified_at"])


def test_files_read_is_bounded_and_flags_truncation(client, engagement_dir, monkeypatch):
    monkeypatch.setattr(artifacts_service, "ARTIFACT_VIEW_MAX_BYTES", 16)
    text = "0123456789abcdefTAIL-BEYOND-LIMIT\n"
    (engagement_dir / "RESUME.md").write_text(text, encoding="utf-8")

    body = client.get(f"{FILES_URL}/RESUME.md").json()

    assert body["truncated"] is True
    assert body["content"] == "0123456789abcdef"
    assert body["returned_bytes"] == 16
    assert body["size_bytes"] == len(text.encode("utf-8"))


def test_files_read_truncation_never_splits_a_multibyte_character(client, engagement_dir, monkeypatch):
    monkeypatch.setattr(artifacts_service, "ARTIFACT_VIEW_MAX_BYTES", 5)
    # "é" is two bytes; the limit falls inside the second "é".
    (engagement_dir / "RESUME.md").write_text("abééz", encoding="utf-8")

    body = client.get(f"{FILES_URL}/RESUME.md").json()

    assert body["truncated"] is True
    assert body["content"] == "abé"
    assert body["returned_bytes"] == 4


def test_files_flag_an_unfilled_engagement_brief_stub(client, engagement_dir):
    (engagement_dir / "ENGAGEMENT.md").write_text(STUB_BRIEF, encoding="utf-8")

    brief = _by_name(client)["ENGAGEMENT.md"]
    assert brief["is_stub"] is True
    assert brief["stub_waiver"] == ""
    assert client.get(f"{FILES_URL}/ENGAGEMENT.md").json()["is_stub"] is True

    (engagement_dir / "ENGAGEMENT.md").write_text(
        "# Engagement Program Brief\n\n## Scope\n\nOnly acme.example.\n",
        encoding="utf-8",
    )
    assert _by_name(client)["ENGAGEMENT.md"]["is_stub"] is False


def test_files_report_the_operator_no_separate_brief_waiver_for_a_stub(client, engagement_dir):
    (engagement_dir / "ENGAGEMENT.md").write_text(STUB_BRIEF, encoding="utf-8")
    reason = "Operator confirmed the Acme lab has no separate program brief."
    decision = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatch-decisions",
        json={"kind": "program_brief", "payload": {"choice": "no_separate_program_brief", "reason": reason}},
    )
    assert decision.status_code == 201, decision.text

    brief = _by_name(client)["ENGAGEMENT.md"]

    assert brief["is_stub"] is True
    assert brief["stub_waiver"] == reason


def test_files_ignore_a_waiver_decision_without_a_reason(client, engagement_dir):
    (engagement_dir / "ENGAGEMENT.md").write_text(STUB_BRIEF, encoding="utf-8")
    decision = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatch-decisions",
        json={"kind": "program_brief", "payload": {"choice": "no_separate_program_brief", "reason": "  "}},
    )
    assert decision.status_code == 201, decision.text

    assert _by_name(client)["ENGAGEMENT.md"]["stub_waiver"] == ""


def test_files_do_not_follow_a_symlinked_root_document(client, engagement_dir, tmp_path):
    outside = tmp_path / "outside-secret.md"
    outside.write_text("outside the engagement\n", encoding="utf-8")
    (engagement_dir / "RESUME.md").symlink_to(outside)

    response = client.get(f"{FILES_URL}/RESUME.md")

    assert response.status_code == 409
    assert "outside the engagement" not in response.text
    assert _by_name(client)["RESUME.md"]["size_bytes"] is None


def test_files_reject_names_outside_the_declared_list(client, engagement_dir):
    (engagement_dir / "AGENTS.md").write_text("# generated wrapper\n", encoding="utf-8")

    assert client.get(f"{FILES_URL}/AGENTS.md").status_code == 404
    assert "AGENTS.md" not in _by_name(client)


def test_files_refuse_non_utf8_content_instead_of_failing(client, engagement_dir):
    (engagement_dir / "RESUME.md").write_bytes(b"# Resume\n\xff\xfe binary tail\n")

    response = client.get(f"{FILES_URL}/RESUME.md")

    assert response.status_code == 409
    assert "UTF-8" in response.json()["detail"]


def test_files_do_not_list_a_directory_as_a_present_document(client, engagement_dir):
    (engagement_dir / "RESUME.md").mkdir()

    resume = _by_name(client)["RESUME.md"]

    assert (resume["exists"], resume["size_bytes"], resume["modified_at"]) == (False, None, None)
    assert client.get(f"{FILES_URL}/RESUME.md").status_code == 409
