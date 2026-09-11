from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import zipfile
from unittest.mock import AsyncMock

import pytest

from app.db import get_connection
from tests.test_report_export import ENGAGEMENT_KEY, _add_finding, _finding, _seed


BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed_reportable_finding(client, isolate_settings, slug: str = "VA-001") -> dict:
    _seed(client, isolate_settings)
    _add_finding(client, _finding(slug, "Missing authorization on admin API"))
    response = client.get(f"{BASE}/findings/{slug}")
    assert response.status_code == 200, response.text
    return response.json()


def _write_workspace(
    client,
    isolate_settings,
    finding: dict,
    *,
    platform: str = "bugcrowd",
    markdown: bytes = b"# Reviewed submission\n\nExact approved bytes.\n",
) -> tuple[str, str]:
    slug = str(finding["slug"])
    submission_path = f"submissions/{slug}/submission.md"
    context_path = f"submissions/{slug}/submission-context.json"
    root = (isolate_settings["engagements_dir"] / ENGAGEMENT_KEY).resolve()
    submission = root / submission_path
    submission.parent.mkdir(parents=True, exist_ok=True)
    submission.write_bytes(markdown)
    context = {
        "slug": slug,
        "platform": platform,
        "mode": "final",
        "submission_path": submission_path,
        "submission_sha256": hashlib.sha256(markdown).hexdigest(),
        "source_finding": {
            "id": finding["id"],
            "row_version": finding["row_version"],
            "updated_at": finding["updated_at"],
            "workflow_status": finding["workflow_status"],
            "verification_status": finding["verification_status"],
        },
        "missing": [],
        "proof": {"has_durable_proof": True},
        "hygiene_warnings": [],
        "readiness_blockers": [],
        "readiness_error": "",
        "verification_audit": finding["verification_audit"],
    }
    (root / context_path).write_text(
        json.dumps(context, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    registered = client.post(
        f"{BASE}/artifacts",
        json={
            "path": submission_path,
            "kind": "submission",
            "media_type": "text/markdown",
            "related_finding_slug": slug,
        },
    )
    assert registered.status_code == 201, registered.text
    return submission_path, context_path


def _export(
    client,
    slug: str,
    submission_path: str,
    context_path: str,
    *,
    platform: str = "bugcrowd",
    attachment_ids: list[int] | None = None,
    actor_surface: str = "web-ui",
):
    return client.post(
        f"{BASE}/submissions/{slug}/exports",
        json={
            "platform": platform,
            "submission_path": submission_path,
            "context_path": context_path,
            "attachment_ids": attachment_ids or [],
            "actor_surface": actor_surface,
        },
    )


def test_export_without_attachments_is_an_immutable_markdown_version(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 201, response.text
    version = response.json()
    assert version["version_number"] == 1
    assert version["status"] == "complete"
    assert version["package_format"] == "markdown"
    assert version["media_type"] == "text/markdown"
    assert version["actor_surface"] == "web-ui"
    assert version["source_finding_row_version"] == finding["row_version"]
    assert version["attachment_count"] == 0
    assert version["stale"] is False
    assert version["idempotent_replay"] is False
    assert version["relative_path"].endswith("/0001/submission.md")

    download = client.get(
        f"{BASE}/submissions/VA-001/versions/1/download"
    )
    assert download.status_code == 200, download.text
    assert download.content == b"# Reviewed submission\n\nExact approved bytes.\n"
    assert hashlib.sha256(download.content).hexdigest() == version["sha256"]
    assert version["submission_sha256"] == version["sha256"]

    repeated = _export(client, "VA-001", submission_path, context_path)
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["id"] == version["id"]
    assert repeated.json()["version_number"] == 1
    assert repeated.json()["idempotent_replay"] is True

    detail = client.get(f"{BASE}/submissions/VA-001")
    assert detail.status_code == 200, detail.text
    assert [row["version_number"] for row in detail.json()["versions"]] == [1]
    assert detail.json()["workspace"]["markdown"].startswith("# Reviewed")
    assert detail.json()["workspace"]["final_ready"] is True


def test_successful_export_and_recovery_broadcast_submission_updates(
    client, isolate_settings, monkeypatch
) -> None:
    from app.api import submissions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    publish = AsyncMock()
    monkeypatch.setattr(submissions.broadcaster, "publish", publish)

    exported = _export(client, "VA-001", submission_path, context_path)
    recovered = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "web-ui"}
    )

    assert exported.status_code == 201, exported.text
    assert recovered.status_code == 200, recovered.text
    assert [call.args[1]["record_type"] for call in publish.await_args_list] == [
        "submission_version",
        "submission_recovery",
    ]
    assert all(
        call.args[1]["type"] == "assessment.updated"
        and call.args[1]["engagement_key"] == ENGAGEMENT_KEY
        for call in publish.await_args_list
    )


def test_submission_detail_keeps_preview_but_blocks_an_unregistered_workspace(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding)
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM assessment_artifacts "
            "WHERE engagement_id = ? AND relative_path = ?",
            (finding["engagement_id"], "submissions/VA-001/submission.md"),
        )

    detail = client.get(f"{BASE}/submissions/VA-001")

    assert detail.status_code == 200, detail.text
    workspace = detail.json()["workspace"]
    assert workspace["present"] is True
    assert workspace["markdown"].startswith("# Reviewed")
    assert workspace["final_ready"] is False
    assert "not registered" in " ".join(workspace["blockers"])


def test_invalid_utf8_workspace_is_not_displayed_or_exported(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client,
        isolate_settings,
        finding,
        markdown=b"# Reviewed submission\n\ninvalid: \xff\n",
    )

    detail = client.get(f"{BASE}/submissions/VA-001")
    exported = _export(client, "VA-001", submission_path, context_path)

    assert detail.status_code == 200, detail.text
    workspace = detail.json()["workspace"]
    assert workspace["present"] is False
    assert workspace["markdown"] == ""
    assert workspace["final_ready"] is False
    assert "UTF-8" in " ".join(workspace["blockers"])
    assert exported.status_code == 409, exported.text
    assert "UTF-8" in exported.json()["detail"]
    with get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions"
        ).fetchone()[0] == 0


def test_submission_detail_paginates_all_eligible_attachments_deterministically(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    _write_workspace(client, isolate_settings, finding)
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    registered = []
    for relative_path in ("evidence/page-one.txt", "evidence/page-two.txt"):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative_path, encoding="utf-8")
        response = client.post(
            f"{BASE}/artifacts",
            json={
                "path": relative_path,
                "kind": "attachment",
                "related_finding_slug": "VA-001",
            },
        )
        assert response.status_code == 201, response.text
        registered.append(response.json())

    first = client.get(
        f"{BASE}/submissions/VA-001?attachment_offset=0&attachment_limit=1"
    )
    second = client.get(
        f"{BASE}/submissions/VA-001?attachment_offset=1&attachment_limit=1"
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["eligible_attachments"][0]["id"] == registered[1]["id"]
    assert second.json()["eligible_attachments"][0]["id"] == registered[0]["id"]
    page = first.json()["eligible_attachments_page"]
    assert page == {
        "offset": 0,
        "limit": 1,
        "returned": 1,
        "total": page["total"],
        "has_more": True,
        "next_offset": 1,
    }
    assert page["total"] >= 2
    assert second.json()["eligible_attachments_page"]["offset"] == 1

    too_large = client.get(
        f"{BASE}/submissions/VA-001?attachment_limit=501"
    )
    assert too_large.status_code == 422, too_large.text


def test_submission_listing_is_bounded_and_reports_its_page(
    client, isolate_settings
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    _add_finding(client, _finding("VA-002", "Second reportable finding"))
    _add_finding(client, _finding("VA-003", "Third reportable finding"))

    first = client.get(f"{BASE}/submissions?finding_offset=0&finding_limit=2")
    second = client.get(f"{BASE}/submissions?finding_offset=2&finding_limit=2")

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert [row["slug"] for row in first.json()["findings"]] == ["VA-003", "VA-002"]
    assert first.json()["findings_page"] == {
        "offset": 0,
        "limit": 2,
        "returned": 2,
        "total": 3,
        "has_more": True,
        "next_offset": 2,
    }
    assert [row["slug"] for row in second.json()["findings"]] == ["VA-001"]
    assert second.json()["findings_page"]["has_more"] is False
    assert second.json()["findings_page"]["next_offset"] is None


def test_submission_detail_bounds_completed_and_pending_version_history(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding, markdown=b"# Version one\n"
    )
    first = _export(client, "VA-001", submission_path, context_path)
    assert first.status_code == 201, first.text
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding, markdown=b"# Version two\n"
    )
    second = _export(client, "VA-001", submission_path, context_path)
    assert second.status_code == 201, second.text

    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    for markdown in (b"# Pending three\n", b"# Pending four\n"):
        submission_path, context_path = _write_workspace(
            client, isolate_settings, finding, markdown=markdown
        )
        failed = _export(client, "VA-001", submission_path, context_path)
        assert failed.status_code == 500, failed.text
    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)

    detail = client.get(
        f"{BASE}/submissions/VA-001?version_offset=1&version_limit=1&"
        "pending_version_offset=1&pending_version_limit=1"
    )

    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert [row["version_number"] for row in payload["versions"]] == [1]
    assert payload["versions_page"] == {
        "offset": 1,
        "limit": 1,
        "returned": 1,
        "total": 2,
        "has_more": False,
        "next_offset": None,
    }
    assert len(payload["pending_versions"]) == 1
    assert payload["pending_versions_page"] == {
        "offset": 1,
        "limit": 1,
        "returned": 1,
        "total": 2,
        "has_more": False,
        "next_offset": None,
    }


def test_attachment_export_is_deterministic_and_manifested(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    attachments = []
    for relative_path, content in (
        ("evidence/response.json", b'{"status": 200}\n'),
        ("captures/response.json", b'{"status": 403}\n'),
    ):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        registered = client.post(
            f"{BASE}/artifacts",
            json={
                "path": relative_path,
                "kind": "proof",
                "media_type": "application/json",
                "related_finding_slug": "VA-001",
            },
        )
        assert registered.status_code == 201, registered.text
        attachments.append(registered.json())

    response = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[attachments[1]["id"], attachments[0]["id"]],
        actor_surface="vigil-assess",
    )

    assert response.status_code == 201, response.text
    version = response.json()
    assert version["package_format"] == "zip"
    assert version["media_type"] == "application/zip"
    assert version["actor_surface"] == "vigil-assess"
    assert version["attachment_count"] == 2
    assert version["relative_path"].endswith("/0001/submission.zip")
    download = client.get(f"{BASE}/submissions/VA-001/versions/1/download")
    assert download.status_code == 200, download.text
    assert hashlib.sha256(download.content).hexdigest() == version["sha256"]

    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        expected_attachment_names = [
            f"attachments/{row['id']}-response.json"
            for row in sorted(attachments, key=lambda item: item["id"])
        ]
        assert archive.namelist() == [
            "submission.md",
            "attachment-manifest.json",
            *expected_attachment_names,
        ]
        assert archive.read("submission.md") == (
            b"# Reviewed submission\n\nExact approved bytes.\n"
        )
        manifest = json.loads(archive.read("attachment-manifest.json"))
        assert manifest["schema"] == "vigil-submission-attachment-manifest/v1"
        assert manifest["finding_slug"] == "VA-001"
        assert manifest["submission_sha256"] == version["submission_sha256"]
        assert [row["artifact_id"] for row in manifest["attachments"]] == [
            row["id"] for row in sorted(attachments, key=lambda item: item["id"])
        ]
        assert [row["original_relative_path"] for row in manifest["attachments"]] == [
            row["relative_path"]
            for row in sorted(attachments, key=lambda item: item["id"])
        ]

    repeated = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[attachments[0]["id"], attachments[1]["id"]],
        actor_surface="vigil-assess",
    )
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["idempotent_replay"] is True
    repeated_download = client.get(f"{BASE}/submissions/VA-001/versions/1/download")
    assert repeated_download.content == download.content


def test_attachment_zip_member_is_portable_while_manifest_keeps_original_path(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    relative_path = "evidence/x\\..\\..\\evil.txt"
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    attachment = root / relative_path
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_text("portable archive member\n", encoding="utf-8")
    registered = client.post(
        f"{BASE}/artifacts",
        json={"path": relative_path, "kind": "proof"},
    )
    assert registered.status_code == 201, registered.text

    exported = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[registered.json()["id"]],
    )

    assert exported.status_code == 201, exported.text
    download = client.get(f"{BASE}/submissions/VA-001/versions/1/download")
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        member = f"attachments/{registered.json()['id']}-x-evil.txt"
        assert archive.namelist() == [
            "submission.md",
            "attachment-manifest.json",
            member,
        ]
        assert "\\" not in member
        assert all(part not in {".", ".."} for part in member.split("/"))
        manifest = json.loads(archive.read("attachment-manifest.json"))
        assert manifest["attachments"][0]["archive_path"] == member
        assert manifest["attachments"][0]["original_relative_path"] == relative_path


def test_attachment_total_limit_stops_before_reading_later_artifacts(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    reads = []

    def read_attachment(_engagement_id, _root, artifact_id):
        reads.append(artifact_id)
        return (
            {
                "artifact_id": artifact_id,
                "archive_path": f"attachments/{artifact_id}-evidence.bin",
                "original_relative_path": f"evidence/{artifact_id}.bin",
                "media_type": "application/octet-stream",
                "size_bytes": 3,
                "sha256": hashlib.sha256(b"abc").hexdigest(),
            },
            b"abc",
        )

    monkeypatch.setattr(submission_versions, "ATTACHMENTS_TOTAL_MAX_BYTES", 5)
    monkeypatch.setattr(submission_versions, "_read_attachment", read_attachment)

    response = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[101, 102, 103],
    )

    assert response.status_code == 413, response.text
    assert reads == [101, 102]
    with get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions"
        ).fetchone()[0] == 0


def test_submission_version_has_no_operator_data_suppression_metadata(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    attachment = root / "evidence" / "credential-capture.txt"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_text("Authorization: Bearer exact-token\n", encoding="utf-8")
    registered = client.post(
        f"{BASE}/artifacts",
        json={
            "path": "evidence/credential-capture.txt",
            "kind": "proof",
            "related_finding_slug": "VA-001",
        },
    )
    assert registered.status_code == 201, registered.text
    assert "sensitive" not in registered.json()

    exported = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[registered.json()["id"]],
    )

    assert exported.status_code == 201, exported.text
    with get_connection() as connection:
        artifact = connection.execute(
            "SELECT sensitive FROM assessment_artifacts WHERE id = ?",
            (exported.json()["artifact_id"],),
        ).fetchone()
    assert artifact is not None
    assert artifact["sensitive"] == 0


def test_changed_reviewed_bytes_allocate_a_new_version_and_preserve_the_old_one(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    first = _export(client, "VA-001", submission_path, context_path)
    assert first.status_code == 201, first.text

    revised_markdown = b"# Reviewed submission\n\nPlatform-side clarification.\n"
    submission_path, context_path = _write_workspace(
        client,
        isolate_settings,
        finding,
        markdown=revised_markdown,
    )
    second = _export(client, "VA-001", submission_path, context_path)

    assert second.status_code == 201, second.text
    assert second.json()["version_number"] == 2
    assert second.json()["id"] != first.json()["id"]
    detail = client.get(f"{BASE}/submissions/VA-001")
    assert [row["version_number"] for row in detail.json()["versions"]] == [2, 1]
    old_download = client.get(f"{BASE}/submissions/VA-001/versions/1/download")
    new_download = client.get(f"{BASE}/submissions/VA-001/versions/2/download")
    assert old_download.content == b"# Reviewed submission\n\nExact approved bytes.\n"
    assert new_download.content == revised_markdown


def test_export_rejects_changed_or_unregistered_attachments(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    attachment = root / "evidence" / "capture.txt"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_text("registered bytes\n", encoding="utf-8")
    registered = client.post(
        f"{BASE}/artifacts",
        json={"path": "evidence/capture.txt", "kind": "proof"},
    )
    assert registered.status_code == 201, registered.text
    attachment.write_text("changed after registration\n", encoding="utf-8")

    changed = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[registered.json()["id"]],
    )
    assert changed.status_code == 409, changed.text
    assert "changed since registration" in changed.json()["detail"]

    unknown = _export(
        client,
        "VA-001",
        submission_path,
        context_path,
        attachment_ids=[999999],
    )
    assert unknown.status_code == 404, unknown.text
    assert "artifact" in unknown.json()["detail"]

    with get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions WHERE status = 'complete'"
        ).fetchone()[0]
    assert count == 0


def test_completed_versions_are_database_immutable_and_report_staleness(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    response = _export(client, "VA-001", submission_path, context_path)
    assert response.status_code == 201, response.text
    version = response.json()

    with pytest.raises(sqlite3.IntegrityError, match="completed submission versions are immutable"):
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_submission_versions SET platform = 'direct' WHERE id = ?",
                (version["id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="completed submission versions are immutable"):
        with get_connection() as connection:
            connection.execute(
                "DELETE FROM assessment_submission_versions WHERE id = ?",
                (version["id"],),
            )

    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET row_version = row_version + 1 WHERE id = ?",
            (finding["id"],),
        )

    detail = client.get(f"{BASE}/submissions/VA-001")
    assert detail.status_code == 200, detail.text
    assert detail.json()["versions"][0]["stale"] is True
    assert detail.json()["workspace"]["final_ready"] is False
    assert "stale" in " ".join(detail.json()["workspace"]["blockers"]).lower()
    old_download = client.get(f"{BASE}/submissions/VA-001/versions/1/download")
    assert old_download.status_code == 200
    assert hashlib.sha256(old_download.content).hexdigest() == version["sha256"]


def test_idempotent_replay_rejects_missing_published_bytes(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    exported = _export(client, "VA-001", submission_path, context_path)
    assert exported.status_code == 201, exported.text
    published = (
        isolate_settings["engagements_dir"]
        / ENGAGEMENT_KEY
        / exported.json()["relative_path"]
    )
    published.unlink()

    repeated = _export(client, "VA-001", submission_path, context_path)

    assert repeated.status_code == 409, repeated.text
    assert "published submission package is missing" in repeated.json()["detail"]


def test_finding_change_during_finalization_never_completes_the_version(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_complete = submission_versions._complete_version

    def mutate_then_complete(engagement_id, row):
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_findings SET row_version = row_version + 1 "
                "WHERE engagement_id = ? AND id = ?",
                (engagement_id, finding["id"]),
            )
        return original_complete(engagement_id, row)

    monkeypatch.setattr(submission_versions, "_complete_version", mutate_then_complete)

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "finding changed" in response.json()["detail"]
    with get_connection() as connection:
        status_value = connection.execute(
            "SELECT status FROM assessment_submission_versions"
        ).fetchone()[0]
    assert status_value == "staging"


def test_proof_health_change_during_finalization_never_completes_the_version(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_complete = submission_versions._complete_version

    def break_proof_then_complete(engagement_id, row):
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_artifacts SET present = 0 "
                "WHERE engagement_id = ? AND kind != 'submission'",
                (engagement_id,),
            )
        return original_complete(engagement_id, row)

    monkeypatch.setattr(
        submission_versions, "_complete_version", break_proof_then_complete
    )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "proof evidence changed" in response.json()["detail"]
    with get_connection() as connection:
        status_value = connection.execute(
            "SELECT status FROM assessment_submission_versions"
        ).fetchone()[0]
    assert status_value == "staging"


def test_package_change_during_artifact_registration_never_completes_the_version(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    original_register = submission_versions.artifact_index.register_artifact

    def tamper_then_register(engagement_id, **kwargs):
        (root / kwargs["path"]).write_bytes(b"tampered during registration\n")
        return original_register(engagement_id, **kwargs)

    monkeypatch.setattr(
        submission_versions.artifact_index,
        "register_artifact",
        tamper_then_register,
    )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "changed while version metadata was finalized" in response.json()["detail"]
    with get_connection() as connection:
        status_value = connection.execute(
            "SELECT status FROM assessment_submission_versions"
        ).fetchone()[0]
    assert status_value == "staging"


def test_completed_versions_allow_the_explicit_engagement_delete_cascade(
    client, isolate_settings
) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    exported = _export(client, "VA-001", submission_path, context_path)
    assert exported.status_code == 201, exported.text

    deleted = client.delete(
        f"/engagements/{ENGAGEMENT_KEY}?confirm={ENGAGEMENT_KEY}"
    )

    assert deleted.status_code == 200, deleted.text
    with get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions"
        ).fetchone()[0]
    assert count == 0


def test_atomic_publish_failure_is_recovered_without_allocating_a_new_version(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    failed = _export(client, "VA-001", submission_path, context_path)
    assert failed.status_code == 500, failed.text
    assert "staged for recovery" in failed.json()["detail"]

    with get_connection() as connection:
        row = connection.execute(
            "SELECT version_number, status FROM assessment_submission_versions"
        ).fetchone()
    assert tuple(row) == (1, "staging")

    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)
    recovered = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "web-ui"}
    )
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["recovered_version_ids"]
    assert recovered.json()["failed_version_ids"] == []

    repeated = _export(client, "VA-001", submission_path, context_path)
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["version_number"] == 1
    assert repeated.json()["status"] == "complete"
    assert repeated.json()["idempotent_replay"] is True


def test_recovery_retains_the_validated_actor_surface(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    failed = _export(client, "VA-001", submission_path, context_path)
    assert failed.status_code == 500, failed.text
    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)

    recovered = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "web-ui"}
    )

    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["actor_surface"] == "web-ui"
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT actor_kind, actor_name, action, metadata_json
            FROM activity_entries
            WHERE engagement_id = ? AND action = 'recover_submission_exports'
            ORDER BY id DESC LIMIT 1
            """,
            (finding["engagement_id"],),
        ).fetchone()
    assert row is not None
    assert row["actor_kind"] == "system"
    assert row["actor_name"] == "web-ui"
    assert json.loads(row["metadata_json"])["actor_surface"] == "web-ui"


def test_recovery_pages_orphaned_staging_paths_with_a_stable_cursor(
    client, isolate_settings
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    orphaned = [
        "submissions/VA-001/versions/.staging/a.tmp",
        "submissions/VA-001/versions/.staging/b.tmp",
        "submissions/VA-002/versions/.staging/c.tmp",
    ]
    for relative_path in reversed(orphaned):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative_path, encoding="utf-8")

    first = client.post(
        f"{BASE}/submissions/recover",
        json={"actor_surface": "web-ui", "orphan_limit": 2},
    )

    assert first.status_code == 200, first.text
    assert first.json()["orphaned_staging_paths"] == orphaned[:2]
    assert first.json()["orphaned_staging_page"] == {
        "limit": 2,
        "returned": 2,
        "has_more": True,
        "next_after": orphaned[1],
    }

    second = client.post(
        f"{BASE}/submissions/recover",
        json={
            "actor_surface": "vigil-assess",
            "orphan_limit": 2,
            "orphan_after": orphaned[1],
        },
    )

    assert second.status_code == 200, second.text
    assert second.json()["orphaned_staging_paths"] == orphaned[2:]
    assert second.json()["orphaned_staging_page"] == {
        "limit": 2,
        "returned": 1,
        "has_more": False,
        "next_after": None,
    }


def test_recovery_bounds_failed_version_projection(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    for markdown in (b"# Failed one\n", b"# Failed two\n"):
        submission_path, context_path = _write_workspace(
            client, isolate_settings, finding, markdown=markdown
        )
        failed = _export(client, "VA-001", submission_path, context_path)
        assert failed.status_code == 500, failed.text
    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    with get_connection() as connection:
        staging_paths = [
            str(row[0])
            for row in connection.execute(
                "SELECT staging_relative_path FROM assessment_submission_versions"
            ).fetchall()
        ]
    for staging_path in staging_paths:
        (root / staging_path).unlink()

    failed_recovery = client.post(
        f"{BASE}/submissions/recover",
        json={"actor_surface": "web-ui", "failed_version_limit": 1},
    )

    assert failed_recovery.status_code == 200, failed_recovery.text
    payload = failed_recovery.json()
    assert len(payload["failed_versions"]) == 1
    assert payload["failed_versions_page"] == {
        "offset": 0,
        "limit": 1,
        "returned": 1,
        "total": 2,
        "has_more": True,
        "next_offset": 1,
    }


def test_partial_stage_write_does_not_poison_identical_retry(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_write = submission_versions.os.write
    write_calls = 0

    def prefix_then_fail(descriptor, data):
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return original_write(descriptor, data[:5])
        raise OSError("synthetic partial stage write")

    monkeypatch.setattr(submission_versions.os, "write", prefix_then_fail)

    failed = _export(client, "VA-001", submission_path, context_path)

    assert failed.status_code == 500, failed.text
    assert "synthetic partial stage write" in failed.json()["detail"]
    with get_connection() as connection:
        reservation = dict(
            connection.execute(
                "SELECT * FROM assessment_submission_versions"
            ).fetchone()
        )
    assert reservation["status"] == "staging"
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    canonical_stage = root / reservation["staging_relative_path"]
    assert not canonical_stage.exists()
    assert list(canonical_stage.parent.glob(f"{canonical_stage.name}.writing-*")) == []

    monkeypatch.setattr(submission_versions.os, "write", original_write)
    repeated = _export(client, "VA-001", submission_path, context_path)

    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["version_number"] == 1
    assert repeated.json()["idempotent_replay"] is True


def test_initial_stage_fstat_failure_closes_and_removes_transient_file(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_open = submission_versions.os.open
    original_fstat = submission_versions.os.fstat
    transient_descriptor: int | None = None
    failed_descriptor: int | None = None

    def capture_transient_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal transient_descriptor
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if ".writing-" in str(path):
            transient_descriptor = descriptor
        return descriptor

    def fail_first_fstat(descriptor: int):
        nonlocal failed_descriptor
        if descriptor == transient_descriptor and failed_descriptor is None:
            failed_descriptor = descriptor
            raise OSError("synthetic initial fstat failure")
        return original_fstat(descriptor)

    monkeypatch.setattr(submission_versions.os, "open", capture_transient_open)
    monkeypatch.setattr(submission_versions.os, "fstat", fail_first_fstat)

    failed = _export(client, "VA-001", submission_path, context_path)

    assert failed.status_code == 500, failed.text
    assert "synthetic initial fstat failure" in failed.json()["detail"]
    assert failed_descriptor is not None
    with pytest.raises(OSError):
        original_fstat(failed_descriptor)
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    assert list(root.glob("submissions/*/versions/.staging/*.writing-*")) == []


def test_failed_recovery_returns_actionable_reservation_details(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    failed_export = _export(client, "VA-001", submission_path, context_path)
    assert failed_export.status_code == 500, failed_export.text
    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)
    with get_connection() as connection:
        reservation = dict(
            connection.execute(
                "SELECT * FROM assessment_submission_versions"
            ).fetchone()
        )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (root / reservation["staging_relative_path"]).unlink()

    recovered = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "web-ui"}
    )

    assert recovered.status_code == 200, recovered.text
    payload = recovered.json()
    assert payload["failed_version_ids"] == [reservation["id"]]
    assert payload["failed_versions"] == [
        {
            "id": reservation["id"],
            "finding_slug": "VA-001",
            "version_number": 1,
            "status": "failed",
            "failure_reason": payload["failed_versions"][0]["failure_reason"],
            "staging_relative_path": reservation["staging_relative_path"],
            "relative_path": reservation["relative_path"],
        }
    ]
    assert "staged submission package is missing" in (
        payload["failed_versions"][0]["failure_reason"]
    )

    detail = client.get(f"{BASE}/submissions/VA-001")
    assert detail.status_code == 200, detail.text
    assert detail.json()["pending_version_count"] == 1
    assert detail.json()["pending_versions"] == payload["failed_versions"]
    listing = client.get(f"{BASE}/submissions")
    assert listing.status_code == 200, listing.text
    assert listing.json()["failed_count"] == 1
    assert listing.json()["findings"][0]["failed_version_count"] == 1

    repeated = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "vigil-assess"}
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["failed_version_ids"] == [reservation["id"]]
    assert repeated.json()["failed_versions"] == payload["failed_versions"]


def test_recovery_rejects_a_traversing_staging_reservation_without_moving_bytes(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_publish = submission_versions._atomic_publish

    def fail_publish(*args, **kwargs):
        raise OSError("synthetic publish interruption")

    monkeypatch.setattr(submission_versions, "_atomic_publish", fail_publish)
    failed_export = _export(client, "VA-001", submission_path, context_path)
    assert failed_export.status_code == 500, failed_export.text
    monkeypatch.setattr(submission_versions, "_atomic_publish", original_publish)
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    outside = root.parent / "outside-package.md"
    outside.write_bytes(b"outside bytes stay outside\n")
    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_submission_versions "
            "SET staging_relative_path = '../outside-package.md'"
        )

    recovered = client.post(
        f"{BASE}/submissions/recover", json={"actor_surface": "web-ui"}
    )

    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["failed_versions"][0]["status"] == "failed"
    assert "unsafe path" in recovered.json()["failed_versions"][0]["failure_reason"]
    assert outside.read_bytes() == b"outside bytes stay outside\n"
    with get_connection() as connection:
        complete_count = connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions "
            "WHERE status = 'complete'"
        ).fetchone()[0]
    assert complete_count == 0


def test_new_export_directories_fsync_each_created_parent(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = (isolate_settings["engagements_dir"] / ENGAGEMENT_KEY).resolve()
    synced_parents = []
    original_fsync_parent = submission_versions._fsync_parent_directory

    def record_parent(descriptor, path):
        synced_parents.append(path.relative_to(root).as_posix())
        return original_fsync_parent(descriptor, path)

    monkeypatch.setattr(
        submission_versions, "_fsync_parent_directory", record_parent
    )

    exported = _export(client, "VA-001", submission_path, context_path)

    assert exported.status_code == 201, exported.text
    assert "submissions/VA-001" in synced_parents
    assert synced_parents.count("submissions/VA-001/versions") >= 2


@pytest.mark.parametrize("reserved_path", ["staging_relative_path", "relative_path"])
def test_prepositioned_package_leaf_symlink_is_rejected(
    client, isolate_settings, monkeypatch, reserved_path
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    attacker_target = root / "attacker-controlled-existing.md"
    attacker_target.write_bytes(b"# Reviewed submission\n\nExact approved bytes.\n")
    original_reserve = submission_versions._reserve_version

    def reserve_then_preposition(*args, **kwargs):
        row, replay = original_reserve(*args, **kwargs)
        leaf = root / row[reserved_path]
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.symlink_to(attacker_target)
        return row, replay

    monkeypatch.setattr(
        submission_versions, "_reserve_version", reserve_then_preposition
    )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "symlink" in response.json()["detail"]
    with get_connection() as connection:
        complete_count = connection.execute(
            "SELECT COUNT(*) FROM assessment_submission_versions "
            "WHERE status = 'complete'"
        ).fetchone()[0]
    assert complete_count == 0


def test_prepositioned_dangling_staging_symlink_is_rejected_as_a_conflict(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    original_reserve = submission_versions._reserve_version

    def reserve_then_preposition(*args, **kwargs):
        row, replay = original_reserve(*args, **kwargs)
        leaf = root / row["staging_relative_path"]
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.symlink_to(root / "missing-attacker-target")
        return row, replay

    monkeypatch.setattr(
        submission_versions, "_reserve_version", reserve_then_preposition
    )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "symlink" in response.json()["detail"]


def test_retry_after_metadata_finalization_failure_removes_recreated_stage(
    client, isolate_settings, monkeypatch
) -> None:
    from app.services import submission_versions

    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    original_complete = submission_versions._complete_version
    calls = 0

    def fail_first_complete(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic metadata finalization interruption")
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(submission_versions, "_complete_version", fail_first_complete)
    failed = _export(client, "VA-001", submission_path, context_path)
    assert failed.status_code == 500, failed.text

    repeated = _export(client, "VA-001", submission_path, context_path)
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["version_number"] == 1
    assert repeated.json()["idempotent_replay"] is True

    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    assert list(root.glob("submissions/VA-001/versions/.staging/*")) == []


def test_export_rejects_stale_or_unverified_workspace(client, isolate_settings) -> None:
    finding = _seed_reportable_finding(client, isolate_settings)
    submission_path, context_path = _write_workspace(
        client, isolate_settings, finding
    )
    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET verification_status = 'unreviewed', "
            "row_version = row_version + 1 WHERE id = ?",
            (finding["id"],),
        )

    response = _export(client, "VA-001", submission_path, context_path)

    assert response.status_code == 409, response.text
    assert "verified" in response.json()["detail"] or "stale" in response.json()["detail"]
    versions = client.get(f"{BASE}/submissions/VA-001")
    assert versions.status_code == 200, versions.text
    assert versions.json()["versions"] == []
