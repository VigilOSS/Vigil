"""Which self-attested review numbers are obligations, and which only point."""
from __future__ import annotations

import json

import pytest

from app.services import code_analysis
from test_code_analysis_api import (
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _classify_file,
    _close_queue_item,
    _network_input_coverage,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    _seed_repo_files,
)


def _seed(client, isolate_settings, key, parser_tier):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    _classify_file(client, key, int(parser["id"]), parser_tier, {"critical": 90, "high": 60, "medium": 30}[parser_tier])
    _classify_file(client, key, int(helper["id"]), "low", 10)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", repo, parser


@pytest.mark.parametrize(("tier", "owes_every_family"), [("medium", False), ("high", True), ("critical", True)])
def test_closeout_records_every_family_only_on_critical_and_high(
    client, isolate_settings, tier, owes_every_family
):
    key = f"2026-11-13-acme-closeout-{tier}"
    base, _repo, parser = _seed(client, isolate_settings, key, tier)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _record_fixture_source_receipt(client, key, claim)
    progress = client.get(f"{base}/analysis-queue/{claim['id']}/progress").json()
    # The applicable list stays as guidance on every tier; only the owed list
    # is the closeout obligation.
    assert progress["applicable_vuln_classes"]
    assert bool(progress["missing_cwe_families"]) is owes_every_family
    partial = _network_input_coverage(default_effort=80)[:2]
    closed = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed two families", cwe_coverage=partial)
    assert closed.status_code == 200, closed.text
    # A critical/high closeout that names fewer families has the rest recorded
    # at effort 0; a medium one owes no entry per family.
    recorded = closed.json().get("unreviewed_families_recorded")
    reviewed = {entry["family"] for entry in partial}
    assert (recorded["families"] if recorded else []) == [
        family for family in progress["missing_cwe_families"] if family not in reviewed
    ]


def test_critical_effort_shortfall_is_owed_as_triggers_and_tracks_the_latest_attempt(
    client, isolate_settings
):
    key = "2026-11-13-acme-effort-advisory"
    base, repo, parser = _seed(client, isolate_settings, key, "critical")
    first = _claim_file_for_analysis(client, key, int(parser["id"]))
    _record_fixture_source_receipt(client, key, first)
    assert _close_queue_item(client, key, first, disposition="clean", notes="deep review",
                             cwe_coverage=_network_input_coverage(default_effort=80)).status_code == 200
    before = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert not [w for w in before["effort_warnings"] if "Critical file" in w]

    second = _claim_file_for_reanalysis(client, key, int(parser["id"]), reason="Acme focused recheck")
    _record_fixture_source_receipt(client, key, second)
    assert _close_queue_item(client, key, second, disposition="clean", notes="focused recheck",
                             cwe_coverage=_network_input_coverage(default_effort=40)).status_code == 200
    after = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    critical = [w for w in after["effort_warnings"] if "Critical file" in w]
    # The latest attempt's own numbers are the ones reported...
    assert critical and all("effort 40 < 70" in w for w in critical)
    # ...and, being self-attested, they are not gate reasons themselves; the
    # shortfall is owed as Phase 2B depth-floor triggers instead.
    assert not set(critical) & set(after["reasons"])
    assert [reason for reason in after["reasons"] if "depth-floor" in reason], after["reasons"]


@pytest.mark.parametrize(
    ("language", "slots", "expected"),
    [
        # `{{ }}`/`<% %>` interpolation is tagged xss + ssti, so html owes the
        # injection family its ssti tag implies, as Twig always did.
        ("html", ["NETWORK-INPUT"], {"web-app-injection", "injection"}),
        ("css", ["URL-COMPONENT"], {"web-app-injection"}),
        # Template languages whose include directives take a runtime expression
        # also owe path-traversal.
        ("blade", ["NETWORK-INPUT", "SERIALIZED-DATA"],
         {"web-app-injection", "injection", "path-traversal"}),
        ("twig", ["URL-COMPONENT"], {"web-app-injection", "injection", "path-traversal"}),
        # A FreeMarker interpolation into a URL attribute is tagged open-redirect.
        ("freemarker", ["FILE-CONTENT"],
         {"web-app-injection", "injection", "open-redirect", "path-traversal"}),
    ],
)
def test_markup_files_owe_only_families_their_structure_can_signal(language, slots, expected):
    assert set(code_analysis._applicable_families_for_file(slots, language=language)) == expected


@pytest.mark.parametrize("language", sorted(code_analysis.MARKUP_SIGNAL_FAMILIES))
def test_markup_language_owes_injection_when_its_index_tags_ssti(language):
    from assess.lib.treesitter_streaming import _STREAM_EXTRA_SINK_PATTERNS

    tags = {
        tag
        for _kind, _pattern, classes in _STREAM_EXTRA_SINK_PATTERNS.get(language, [])
        for tag in classes
    }
    families = code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language=language)
    if tags & {"ssti", "injection"}:
        assert "injection" in families, (language, sorted(tags), families)


# What a markup index's unavailable dimensions say about the code it held:
# a lightweight reader names the function-scoped dimensions a body it did not
# read left empty, and the streaming fallback names its structural baseline.
_UNREAD_BODY = ["call_sites", "dataflow", "security_sinks"]
_STREAMING_FALLBACK = ["call_sites", "classes", "dataflow", "exports", "functions"]


def test_blade_unread_server_code_owes_the_code_slot_families_too():
    """Blade's unread body can be `@php`, which runs on the server, so the file
    owes what a code file with the same slots owes."""
    markup = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language="blade"))
    unread = set(code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"], language="blade", unavailable_dimensions=_UNREAD_BODY,
    ))
    code = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language="php"))
    assert markup | code == unread, sorted(unread)
    assert "ssrf" in unread and "ssrf" not in markup


@pytest.mark.parametrize("language", ["html", "twig", "freemarker"])
@pytest.mark.parametrize("unavailable", [_UNREAD_BODY, ["call_sites", "dataflow"]])
def test_unread_browser_script_owes_client_side_families_only(language, unavailable):
    """In these languages the only body a reader holds unread is an inline
    `<script>`: code the browser runs, which can write the DOM or navigate but
    never handles the request."""
    markup = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language=language))
    unread = set(code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"], language=language, unavailable_dimensions=unavailable,
    ))
    assert unread == markup | {"web-app-injection", "open-redirect"}, sorted(unread)
    assert code_analysis._unread_code_suggested_families_for_file(
        ["NETWORK-INPUT"], language=language, unavailable_dimensions=unavailable,
    ) == []


@pytest.mark.parametrize("language", sorted(code_analysis.MARKUP_SIGNAL_FAMILIES))
def test_streaming_fallback_markup_suggests_the_code_families_it_cannot_require(language):
    """A fallback index read too little to say what code the file holds, so the
    code slot families point at it and `done` does not owe them."""
    markup = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language=language))
    required = set(code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"], language=language, unavailable_dimensions=_STREAMING_FALLBACK,
    ))
    suggested = set(code_analysis._unread_code_suggested_families_for_file(
        ["NETWORK-INPUT"], language=language, unavailable_dimensions=_STREAMING_FALLBACK,
    ))
    code = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language="php"))
    assert required == markup, sorted(required)
    assert suggested == code - markup, sorted(suggested)


def test_code_files_never_get_unread_code_suggestions():
    assert code_analysis._unread_code_suggested_families_for_file(
        ["NETWORK-INPUT"], language="php", unavailable_dimensions=_STREAMING_FALLBACK,
    ) == []


def test_markup_context_tags_still_name_families():
    families = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"], language="html", context_tags=["authentication"]
    )
    assert {"web-app-injection", "auth-bypass", "web-app-auth", "rate-limit"} <= set(families)
    assert not {"ssrf", "deserialization", "algorithmic-dos"} & set(families)


def test_code_files_keep_their_language_floor_and_slot_families():
    families = set(code_analysis._applicable_families_for_file(["NETWORK-INPUT"], language="php"))
    assert {"algorithmic-dos", "error-handling", "ssrf", "deserialization"} <= families


def test_unread_markup_code_reaches_every_reader_of_the_applicable_families(
    client, isolate_settings
):
    """Claim, listing, progress, closeout and the coverage matrix read one rule."""
    from app import db as db_module

    key = "2026-11-13-acme-unread-markup"
    base, repo, parser = _seed(client, isolate_settings, key, "high")
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET language = 'blade', "
            "structural_unavailable_dimensions_json = ? WHERE id = ?",
            (json.dumps(_UNREAD_BODY), int(parser["id"])),
        )
    expected = code_analysis._applicable_families_for_file(
        ["NETWORK-INPUT"], language="blade",
        unavailable_dimensions=_UNREAD_BODY,
    )
    assert "ssrf" in expected

    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    assert claim["applicable_vuln_classes"] == expected
    listed = client.get(f"{base}/analysis-queue").json()["items"]
    assert [row["applicable_vuln_classes"] for row in listed if row["id"] == claim["id"]] == [expected]
    _record_fixture_source_receipt(client, key, claim)
    progress = client.get(f"{base}/analysis-queue/{claim['id']}/progress").json()
    assert progress["applicable_vuln_classes"] == expected

    markup_only = [
        {"family": family, "effort": 80}
        for family in code_analysis.MARKUP_SIGNAL_FAMILIES["blade"]
    ]
    closed = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed the markup", cwe_coverage=markup_only)
    assert closed.status_code == 200, closed.text
    assert "ssrf" in closed.json()["unreviewed_families_recorded"]["families"]
    matrix = client.get(f"{base}/coverage?repo_id={repo['id']}&detail=cwe")
    assert matrix.status_code == 200, matrix.text
    [row] = [row for row in matrix.json()["files"] if row["file_id"] == parser["id"]]
    assert row["applicable_families"] == expected


def test_streaming_fallback_markup_suggestions_reach_every_reader_and_never_block_done(
    client, isolate_settings
):
    """Claim, listing, progress and the coverage matrix carry the suggestions;
    `done` on a high file accepts a result that covers only the required set."""
    from app import db as db_module

    key = "2026-11-13-acme-fallback-markup"
    base, repo, parser = _seed(client, isolate_settings, key, "high")
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET language = 'html', "
            "structural_unavailable_dimensions_json = ? WHERE id = ?",
            (json.dumps(_STREAMING_FALLBACK), int(parser["id"])),
        )
    identity = {"language": "html", "unavailable_dimensions": _STREAMING_FALLBACK}
    required = code_analysis._applicable_families_for_file(["NETWORK-INPUT"], **identity)
    suggested = code_analysis._unread_code_suggested_families_for_file(
        ["NETWORK-INPUT"], **identity
    )
    assert "ssrf" in suggested and "ssrf" not in required

    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    assert claim["applicable_vuln_classes"] == required
    assert claim["unread_code_suggested_vuln_classes"] == suggested
    listed = client.get(f"{base}/analysis-queue").json()["items"]
    [row] = [row for row in listed if row["id"] == claim["id"]]
    assert row["unread_code_suggested_vuln_classes"] == suggested
    _record_fixture_source_receipt(client, key, claim)
    progress = client.get(f"{base}/analysis-queue/{claim['id']}/progress").json()
    assert progress["unread_code_suggested_vuln_classes"] == suggested
    assert progress["missing_cwe_families"] == required

    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme reviewed the page",
        cwe_coverage=[{"family": family, "effort": 80} for family in required],
    )
    assert closed.status_code == 200, closed.text
    matrix = client.get(f"{base}/coverage?repo_id={repo['id']}&detail=cwe")
    assert matrix.status_code == 200, matrix.text
    [row] = [row for row in matrix.json()["files"] if row["file_id"] == parser["id"]]
    assert row["applicable_families"] == required
    assert row["unread_code_suggested_families"] == suggested
