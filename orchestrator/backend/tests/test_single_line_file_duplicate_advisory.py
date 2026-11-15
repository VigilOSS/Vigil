"""In a single-line file the line number locates nothing, so it cannot make two findings duplicates.

Every finding in a minified bundle sits on the bundle's one code line, so equal
`file:<bundle>:<line>` locations name unrelated defects. There, a location match
counts only with an equal structured `source_anchor` or `function`; an ordinary
multi-line file keeps the plain location match. The same holds for a bundle a
few lines long whose lines the structural index measured at megabytes each, and
for the withdrawn-finding re-mint guard and the dedup upsert: there the file
names a region, so only an equal anchor (or the exact tuple) ties two findings
together, and differing anchors keep two defects apart.
"""
from __future__ import annotations

import json

from app import db as db_module
from app.services.state_manager.findings import (
    _duplicate_advisories,
    _find_killed_remint_collision,
    _semantic_finding_match,
)
from tests.test_finding_response_shape import _base, _payload, _seed

_BUNDLE = "web/bundle.min.js"
_SOURCE = "app/routes/users.py"


def _record(client, slug: str) -> None:
    response = client.post(f"{_base()}/findings", json=_payload(slug))
    assert response.status_code == 201, response.text


def _code_file(connection, engagement_id: int, path: str, loc: int, *, size: int = 0) -> None:
    repo = connection.execute(
        "INSERT INTO code_repos (engagement_id, repo_key, name, repo_path, active_generation) "
        "VALUES (?, ?, ?, ?, 1)",
        (engagement_id, f"acme-{path}", "acme", "/engagements/acme/src"),
    ).lastrowid
    connection.execute(
        "INSERT INTO code_files (engagement_id, repo_id, file_path, loc, structural_source_size) "
        "VALUES (?, ?, ?, ?, ?)",
        (engagement_id, repo, path, loc, size),
    )


def _advisories(
    client, isolate_settings, path: str, loc: int, sibling: dict, mine: dict, *, size: int = 0
) -> list[dict]:
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
        _code_file(connection, engagement_id, path, loc, size=size)
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


# A bundle a few lines long whose lines the structural index measured at
# megabytes each: more than three lines, and still no line locates anything.
_WIDE_BUNDLE = "web/chunk.maverick.js"
_WIDE_BUNDLE_LOC = 5
_WIDE_BUNDLE_BYTES = 20_000_000


def _seed_findings(client, isolate_settings, path: str, loc: int, size: int, rows: dict) -> int:
    """Record one finding per slug in *rows* at ``file:<path>:2`` and index *path*.

    *rows* maps a slug to the column overrides it carries; ``details`` is
    stored as JSON. Returns the engagement id.
    """
    _seed(client, isolate_settings)
    for slug in rows:
        _record(client, slug)
    with db_module.get_connection() as connection:
        engagement_id = int(connection.execute(
            "SELECT engagement_id FROM assessment_findings WHERE slug = ?", (next(iter(rows)),)
        ).fetchone()[0])
        _code_file(connection, engagement_id, path, loc, size=size)
        for slug, over in rows.items():
            values = {"canonical_location": f"file:{path}:2", **over}
            values["details_json"] = json.dumps(values.pop("details", {}))
            assignments = ", ".join(f"{column} = ?" for column in values)
            connection.execute(
                f"UPDATE assessment_findings SET {assignments} WHERE slug = ?",
                (*values.values(), slug),
            )
        connection.commit()
    return engagement_id


def _killed(details: dict, **over) -> dict:
    return {
        "status": "false_positive", "defect_family": "injection",
        "root_cause_key": "banner-xss", "details": details, **over,
    }


def _remint(engagement_id: int, path: str, details: dict, **over):
    with db_module.get_connection() as connection:
        return _find_killed_remint_collision(
            connection, engagement_id,
            defect_family="injection",
            root_cause_key=over.get("root_cause_key", "summary-entity-dom"),
            auth_context=over.get("auth_context", "anonymous"),
            canonical_location=f"file:{path}:2",
            details=details,
        )


def test_a_measured_wide_bundle_line_does_not_make_duplicates(client, isolate_settings) -> None:
    advisories = _advisories(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC,
        {"source_anchor": "new Function(a)"}, {"source_anchor": "location.href=b"},
        size=_WIDE_BUNDLE_BYTES,
    )
    assert [row for row in advisories if row["slug"] == "CH-201"] == []


def test_an_unrelated_defect_in_a_wide_bundle_is_not_a_remint(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-032": _killed({"source_anchor": "e.innerHTML=t.banner"})},
    )
    assert _remint(
        engagement_id, _WIDE_BUNDLE, {"source_anchor": "n.outerHTML=s.summary"}
    ) is None


def test_a_wide_bundle_kill_without_an_anchor_does_not_claim_the_whole_bundle(
    client, isolate_settings
) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-032": _killed({})},
    )
    assert _remint(engagement_id, _WIDE_BUNDLE, {}) is None


def test_the_same_anchor_in_a_wide_bundle_is_still_a_remint(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-032": _killed({"source_anchor": "e.innerHTML=t.banner"})},
    )
    killed = _remint(engagement_id, _WIDE_BUNDLE, {"source_anchor": "e.innerHTML=t.banner"})
    assert killed is not None and killed["slug"] == "CH-032"


def test_the_same_function_in_a_wide_bundle_is_still_a_remint(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-032": _killed({"function": "Oi"})},
    )
    killed = _remint(engagement_id, _WIDE_BUNDLE, {"function": "Oi"})
    assert killed is not None and killed["slug"] == "CH-032"


def test_the_exact_tuple_in_a_wide_bundle_is_still_a_remint(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-032": _killed({}, auth_context="anonymous")},
    )
    killed = _remint(
        engagement_id, _WIDE_BUNDLE, {}, root_cause_key="banner-xss", auth_context="anonymous"
    )
    assert killed is not None and killed["slug"] == "CH-032"


def test_an_ordinary_file_kill_still_claims_the_file(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _SOURCE, 120, 4_000,
        {"CH-032": _killed({"source_anchor": "render(request.args)"})},
    )
    killed = _remint(engagement_id, _SOURCE, {"source_anchor": "redirect(request.args)"})
    assert killed is not None and killed["slug"] == "CH-032"


def _dedup(engagement_id: int, path: str, details: dict):
    with db_module.get_connection() as connection:
        return _semantic_finding_match(
            connection, engagement_id, slug=None,
            defect_family="injection", root_cause_key="dom-sink",
            canonical_location=f"file:{path}:2", auth_context="anonymous",
            title="DOM XSS", details=details,
        )


def _live(details: dict) -> dict:
    return {
        "defect_family": "injection", "root_cause_key": "dom-sink",
        "auth_context": "anonymous", "title": "DOM XSS", "details": details,
    }


def test_distinct_anchors_in_a_wide_bundle_are_not_merged(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _WIDE_BUNDLE, _WIDE_BUNDLE_LOC, _WIDE_BUNDLE_BYTES,
        {"CH-201": _live({"source_anchor": "e.innerHTML=t.banner"})},
    )
    assert _dedup(engagement_id, _WIDE_BUNDLE, {"source_anchor": "n.outerHTML=s.summary"}) is None
    same = _dedup(engagement_id, _WIDE_BUNDLE, {"source_anchor": "e.innerHTML=t.banner"})
    assert same is not None and same["slug"] == "CH-201"
    unanchored = _dedup(engagement_id, _WIDE_BUNDLE, {})
    assert unanchored is not None and unanchored["slug"] == "CH-201"


def test_an_ordinary_file_keeps_the_tuple_dedup(client, isolate_settings) -> None:
    engagement_id = _seed_findings(
        client, isolate_settings, _SOURCE, 120, 4_000,
        {"CH-201": _live({"source_anchor": "render(request.args)"})},
    )
    match = _dedup(engagement_id, _SOURCE, {"source_anchor": "redirect(request.args)"})
    assert match is not None and match["slug"] == "CH-201"
