"""In a single-line file the line number locates nothing, so it cannot make two findings duplicates.

Every finding in a minified bundle sits on the bundle's one code line, so equal
`file:<bundle>:<line>` locations name unrelated defects. There, a location match
counts only with an equal structured `source_anchor` or `function`; an ordinary
multi-line file keeps the plain location match.
"""
from __future__ import annotations

import json

from app import db as db_module
from app.services.state_manager.findings import _duplicate_advisories
from tests.test_finding_response_shape import _base, _payload, _seed

_BUNDLE = "web/bundle.min.js"
_SOURCE = "app/routes/users.py"


def _record(client, slug: str) -> None:
    response = client.post(f"{_base()}/findings", json=_payload(slug))
    assert response.status_code == 201, response.text


def _code_file(connection, engagement_id: int, path: str, loc: int) -> None:
    repo = connection.execute(
        "INSERT INTO code_repos (engagement_id, repo_key, name, repo_path, active_generation) "
        "VALUES (?, ?, ?, ?, 1)",
        (engagement_id, f"acme-{path}", "acme", "/engagements/acme/src"),
    ).lastrowid
    connection.execute(
        "INSERT INTO code_files (engagement_id, repo_id, file_path, loc) VALUES (?, ?, ?, ?)",
        (engagement_id, repo, path, loc),
    )


def _advisories(client, isolate_settings, path: str, loc: int, sibling: dict, mine: dict) -> list[dict]:
    _seed(client, isolate_settings)
    _record(client, "CH-201")
    _record(client, "CH-202")
    location = f"file:{path}:2"
    with db_module.get_connection() as connection:
        rows = {
            row["slug"]: row for row in connection.execute(
                "SELECT id, slug, engagement_id, auth_context FROM assessment_findings "
                "WHERE slug IN ('CH-201', 'CH-202')"
            )
        }
        sibling_id, mine_id = int(rows["CH-201"]["id"]), int(rows["CH-202"]["id"])
        engagement_id = int(rows["CH-201"]["engagement_id"])
        _code_file(connection, engagement_id, path, loc)
        connection.execute(
            "UPDATE assessment_findings SET canonical_location = ?, details_json = ? WHERE id = ?",
            (location, json.dumps(sibling), sibling_id),
        )
        connection.commit()
        return _duplicate_advisories(
            connection, engagement_id, finding_id=mine_id, finding_slug="CH-202",
            canonical_location=location, root_cause_key="unrelated-root-cause",
            defect_family="access-control", auth_context=str(rows["CH-202"]["auth_context"]),
            details=mine,
        )


def test_unrelated_defects_in_one_bundle_line_are_not_duplicates(client, isolate_settings) -> None:
    advisories = _advisories(
        client, isolate_settings, _BUNDLE, 2,
        {"source_anchor": "new Function(a)"}, {"source_anchor": "location.href=b"},
    )
    assert [row for row in advisories if row["slug"] == "CH-201"] == []


def test_an_equal_anchor_in_one_bundle_line_is_a_probable_duplicate(client, isolate_settings) -> None:
    advisories = _advisories(
        client, isolate_settings, _BUNDLE, 2,
        {"source_anchor": "new Function(a)"}, {"source_anchor": "new Function(a)"},
    )
    (advisory,) = [row for row in advisories if row["slug"] == "CH-201"]
    assert advisory["matched_on"] == ["canonical_location+source_anchor"]


def test_an_ordinary_file_keeps_the_location_match(client, isolate_settings) -> None:
    advisories = _advisories(
        client, isolate_settings, _SOURCE, 120,
        {"source_anchor": "a"}, {"source_anchor": "b"},
    )
    (advisory,) = [row for row in advisories if row["slug"] == "CH-201"]
    assert advisory["matched_on"] == ["canonical_location"]
