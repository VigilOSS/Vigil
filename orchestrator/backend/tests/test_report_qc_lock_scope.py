"""Report QC reads report.md outside the engagement write lock.

``report_qc_verdict`` proves the reviewed bytes are still the file on disk by
reading and hashing it. Doing that inside ``BEGIN IMMEDIATE`` held the single
write lock for the whole read of a large report, so every other writer waited
on it. The read now happens first; inside the lock the decision re-checks that
the registration still names the bytes that were read, so a registration that
lands in between is refused, never recorded against bytes nobody reviewed.
"""
from __future__ import annotations

from app import db as db_module
from app.services import artifact_index
from tests.test_report_export import ENGAGEMENT_KEY
from tests.test_submission_qc_verdict import (
    _record,
    _register_report,
    _report_payload,
    _root,
)
from tests.test_submission_versions_api import _seed_reportable_finding


def _thread_in_transaction() -> bool:
    connection = getattr(db_module._thread_connections, "connection", None)
    return bool(connection is not None and connection.in_transaction)


def test_report_qc_hashes_report_bytes_before_taking_the_write_lock(
    client, isolate_settings, monkeypatch
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings, b"# Acme internal report\n" * 4096)
    reads: list[bool] = []
    original = artifact_index.read_registered_artifact_bytes

    def observed(*args, **kwargs):
        reads.append(_thread_in_transaction())
        return original(*args, **kwargs)

    monkeypatch.setattr(artifact_index, "read_registered_artifact_bytes", observed)

    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))

    assert response.status_code == 201, response.text
    assert reads == [False]


def test_a_registration_between_the_read_and_the_lock_is_refused(
    client, isolate_settings, monkeypatch
) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings)
    original = artifact_index.read_registered_artifact_bytes

    def read_then_reregister(*args, **kwargs):
        content = original(*args, **kwargs)
        (_root(isolate_settings) / "report.md").write_bytes(b"# Acme report rewritten\n")
        artifact_index.register_artifact(
            db_module.get_engagement_by_key(ENGAGEMENT_KEY).id,
            path="report.md",
            kind="report",
            producer_agent_id="WRITE-REPORT",
        )
        return content

    monkeypatch.setattr(artifact_index, "read_registered_artifact_bytes", read_then_reregister)

    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))

    assert response.status_code == 422, response.text
    assert "differs from the registered report.md" in response.json()["detail"]


def test_report_drift_on_disk_is_still_refused(client, isolate_settings) -> None:
    _seed_reportable_finding(client, isolate_settings)
    artifact = _register_report(client, isolate_settings)
    (_root(isolate_settings) / "report.md").write_bytes(b"# Acme edited after registration\n")

    response = _record(client, "report_qc_verdict", _report_payload(client, artifact))

    assert response.status_code == 422, response.text
    assert "on disk differs from its registration" in response.json()["detail"]

