"""Report-readiness items that steer instead of refusing, and one item per finding gap.

A severity that departs from its CVSS band is an advisory the submission QC and
the operator still see, and an ungraded finding is named once, by the gate that
says how to grade it.
"""
from __future__ import annotations

import json

from app import db as db_module
from tests.test_report_export import (
    ENGAGEMENT_KEY,
    _add_finding,
    _finding,
    _record_finding,
    _seed,
)

_READINESS = f"/engagements/{ENGAGEMENT_KEY}/assessment/report-readiness"


def _as_web(isolate_settings) -> None:
    scope_path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["engagement_type"] = "web"
    scope_path.write_text(json.dumps(scope), encoding="utf-8")


def _items(body: dict, bucket: str, kind: str) -> list[dict]:
    return [item for item in body[bucket] if item["kind"] == kind]


def test_a_severity_outside_its_cvss_band_is_an_advisory_not_a_blocker(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-060", "Authorization bypass on export"))
    # cvss 8.1 is the high band; the stored severity says critical with no
    # recorded variance.
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET severity = 'critical' WHERE slug = 'VA-060'"
        )

    body = client.get(_READINESS).json()

    assert not _items(body, "blockers", "severity_cvss_mismatch"), body["blockers"]
    advisory = _items(body, "advisories", "severity_cvss_mismatch")
    assert [item["slug"] for item in advisory] == ["VA-060"]
    assert advisory[0]["severity"] == "advisory"
    assert "severity=critical but cvss_score=8.1 expects high" in advisory[0]["detail"]
    assert "--severity-variance-file" in advisory[0]["detail"]


def test_an_ungraded_reportable_finding_is_named_once(client, isolate_settings):
    _seed(client, isolate_settings)
    _as_web(isolate_settings)
    _record_finding(client, _finding("VA-061", "Ungraded high finding"))

    body = client.get(_READINESS).json()

    named = [
        item["kind"] for item in body["blockers"]
        if item.get("slug") == "VA-061"
        and item["kind"] in {"finding_verification_status", "unreviewed_findings"}
    ]
    assert named == ["unreviewed_findings"], body["blockers"]


def test_a_non_web_ungraded_finding_keeps_its_verification_status_blocker(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    scope_path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["engagement_type"] = "code"
    scope_path.write_text(json.dumps(scope), encoding="utf-8")
    _record_finding(client, _finding("VA-062", "Ungraded code-track finding"))

    body = client.get(_READINESS).json()

    assert [
        item["kind"] for item in body["blockers"] if item.get("slug") == "VA-062"
    ] == ["finding_verification_status"], body["blockers"]


def _drop_stored_score(slug: str, *, severity: str | None = None) -> None:
    """Model a row stored before writes derived the score from the vector."""
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT details_json FROM assessment_findings WHERE slug = ?", (slug,)
        ).fetchone()
        details = json.loads(row["details_json"])
        details.pop("cvss_score")
        connection.execute(
            "UPDATE assessment_findings SET details_json = ?"
            + (", severity = ?" if severity else "")
            + " WHERE slug = ?",
            (json.dumps(details), *((severity,) if severity else ()), slug),
        )


def test_a_vector_without_a_stored_score_is_not_a_missing_score(client, isolate_settings):
    from app.services.state_manager.cvss import base_score

    _seed(client, isolate_settings)
    payload = _finding("VA-063", "Vector-only legacy row")
    _add_finding(client, payload)
    _drop_stored_score("VA-063")

    body = client.get(_READINESS).json()

    assert not [
        item for item in body["blockers"]
        if item["kind"] == "finding_field_quality" and item.get("slug") == "VA-063"
        and "cvss_score" in item["detail"]
    ], body["blockers"]
    report = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft"
    ).json()
    record = next(r for r in report["standalone"] if r["slug"] == "VA-063")
    assert record["cvss_score"] == base_score(payload["details"]["cvss_vector"])


def test_a_vector_only_row_is_still_judged_against_its_band(client, isolate_settings):
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-064", "Vector-only row rated above its band"))
    _drop_stored_score("VA-064", severity="critical")

    body = client.get(_READINESS).json()

    advisory = _items(body, "advisories", "severity_cvss_mismatch")
    assert [item["slug"] for item in advisory] == ["VA-064"]
    assert "expects high" in advisory[0]["detail"]
