"""File scope is a `<top-level>` callable a receipt must cover like any other.

The structural index publishes the file-scope lines between callables as
`<top-level>` records, one per contiguous segment, beside the real callables.
`total_functions` keeps counting functions only. A file's top-level code no
longer rides on whichever callable a receipt happened to name: every segment
needs an exact `callable_ref` or a reviewed span covering it, and a file whose
only callable is `<top-level>` keeps today's rule that a span must cover all of
its source lines.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module

from tests.test_code_analysis_api import (
    _append_repo_files,
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _classify_file,
    _complete_structural_payload,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _post_structural_callables,
    _registered_callables,
    _source_hash,
    write_engagement,
)
from tests.test_code_coverage_uncovered_gate import _complete, _gate, _uncovered_paths

from assess.lib.code_structural_metadata import (
    TOP_LEVEL_CALLABLE_NAME as AGENT_TOP_LEVEL_CALLABLE_NAME,
    validated_callable_records,
)
from assess.lib.treesitter_index import index_file

from app.services.code_analysis_support import TOP_LEVEL_CALLABLE_NAME

MIXED_PATH = "public/report.php"
MIXED_SOURCE = b"""<?php
require_once __DIR__ . '/bootstrap.php';
$id = $_GET['id'];

function acme_render($id)
{
    return htmlspecialchars($id);
}

echo acme_render($id);
"""
SCRIPT_PATH = "public/export.php"
SCRIPT_SOURCE = b"""<?php
$id = $_GET['id'];
$db = new mysqli('db.example.com', 'acme', 'secret', 'acme');
$rows = $db->query("SELECT * FROM exports WHERE id = " . $id);
echo json_encode($rows);
"""


def _callables(path: str, source: bytes) -> list[dict[str, object]]:
    return validated_callable_records(index_file(path, "php", source), rel_path=path)


def _setup(client, isolate_settings, key: str) -> tuple[int, list[dict[str, object]], dict[str, int]]:
    write_engagement(isolate_settings["engagements_dir"], key)
    repo = _create_repo(client, key, repo_key=f"{key}-repo")
    repo_id = int(repo["id"])
    _create_files(client, key, repo_id)
    files = _append_repo_files(
        client,
        key,
        repo_id,
        [
            {
                "file_path": path,
                "language": "php",
                "loc": len(source.splitlines()),
                "file_hash": _source_hash(path),
                "header_snippet": "<?php\n",
                "git_churn_score": 1,
                "has_past_cve_fix": False,
            }
            for path, source in ((MIXED_PATH, MIXED_SOURCE), (SCRIPT_PATH, SCRIPT_SOURCE))
        ],
    )
    ids = {str(row["file_path"]): int(row["id"]) for row in files}
    return repo_id, files, ids


def _publish(client, key, repo_id, files, ids, *, top_level: bool = True):
    registry = {
        ids[MIXED_PATH]: _callables(MIXED_PATH, MIXED_SOURCE),
        ids[SCRIPT_PATH]: _callables(SCRIPT_PATH, SCRIPT_SOURCE),
    }
    if not top_level:
        registry = {
            file_id: [item for item in records if item["name"] != TOP_LEVEL_CALLABLE_NAME]
            for file_id, records in registry.items()
        }
    response = _post_structural_callables(client, key, repo_id, files, registry)
    assert response.status_code == 200, response.text
    return registry


def _refs(file_id: int, records: list[dict[str, object]], *, top_level: bool | None = None):
    return [
        {"file_id": file_id, **record}
        for record in records
        if top_level is None or (record["name"] == TOP_LEVEL_CALLABLE_NAME) == top_level
    ]


def _receipt(client, key, claim, **payload):
    return client.post(
        f"/engagements/{key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="reviewed the sealed source of the claimed file",
            receipt_kind="file",
            cwe_coverage=_network_input_coverage(default_effort=80),
            **payload,
        ),
    )


def test_the_backend_names_the_top_level_callable_as_the_indexer_does() -> None:
    assert TOP_LEVEL_CALLABLE_NAME == AGENT_TOP_LEVEL_CALLABLE_NAME


def test_top_level_records_are_reported_beside_the_function_total(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-registry"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    _publish(client, key, repo_id, files, ids)

    assert {
        (name, start, end)
        for file_id, name, start, end in _registered_callables(repo_id)
        if file_id == ids[MIXED_PATH]
    } == {("acme_render", 5, 8), ("<top-level>", 2, 3), ("<top-level>", 10, 10)}
    detail = client.get(f"/engagements/{key}/assessment/code/files/{ids[MIXED_PATH]}").json()
    assert detail["total_functions"] == 1


def test_a_top_level_count_that_disagrees_with_its_records_is_refused(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-count"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    base = f"/engagements/{key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo_id}").json()
    records = _callables(MIXED_PATH, MIXED_SOURCE)
    updates = [
        {
            "file_id": row["id"],
            "source_sha256": row["file_hash"],
            "total_functions": 1 if row["id"] == ids[MIXED_PATH] else 0,
            "total_top_level_segments": 1 if row["id"] == ids[MIXED_PATH] else 0,
            "total_entry_points": 0,
            "total_sinks": 0,
            "total_exports": 0,
            "callables": records if row["id"] == ids[MIXED_PATH] else [],
        }
        for row in files
    ]
    response = client.post(
        f"{base}/files/bulk-structural-metadata",
        json=_complete_structural_payload(
            repo_id=repo_id,
            repo_generation=int(binding["active_generation"]),
            source_manifest_digest=str(binding["source_manifest_digest"]),
            updates=updates,
        ),
    )

    assert response.status_code == 422, response.text


def test_a_function_receipt_leaves_the_file_scope_owed(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-owed"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    _classify_file(client, key, ids[MIXED_PATH], "critical", 100)
    claim = _claim_file_for_analysis(client, key, ids[MIXED_PATH])
    receipt = _receipt(
        client, key, claim, callable_refs=_refs(ids[MIXED_PATH], registry[ids[MIXED_PATH]], top_level=False)
    )
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text

    assert _uncovered_paths(_gate(client, key, repo_id)) == {MIXED_PATH}


def test_citing_every_top_level_segment_discharges_the_file_scope(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-cited"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    _classify_file(client, key, ids[MIXED_PATH], "critical", 100)
    claim = _claim_file_for_analysis(client, key, ids[MIXED_PATH])
    receipt = _receipt(client, key, claim, callable_refs=_refs(ids[MIXED_PATH], registry[ids[MIXED_PATH]]))
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text

    assert _uncovered_paths(_gate(client, key, repo_id)) == set()


def test_one_cited_segment_of_two_still_owes_the_other(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-partial"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    _classify_file(client, key, ids[MIXED_PATH], "critical", 100)
    claim = _claim_file_for_analysis(client, key, ids[MIXED_PATH])
    refs = _refs(ids[MIXED_PATH], registry[ids[MIXED_PATH]])
    receipt = _receipt(client, key, claim, callable_refs=refs[:2])
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text

    assert _uncovered_paths(_gate(client, key, repo_id)) == {MIXED_PATH}


def test_a_reviewed_span_covers_file_scope_without_citing_it(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-span"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    _classify_file(client, key, ids[MIXED_PATH], "critical", 100)
    claim = _claim_file_for_analysis(client, key, ids[MIXED_PATH])
    receipt = _receipt(
        client,
        key,
        claim,
        callable_refs=_refs(ids[MIXED_PATH], registry[ids[MIXED_PATH]], top_level=False),
        reviewed_spans=[{"file_id": ids[MIXED_PATH], "start_line": 1, "end_line": 10}],
    )
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text

    assert _uncovered_paths(_gate(client, key, repo_id)) == set()


def test_a_script_whose_only_callable_is_top_level_needs_all_of_its_lines(client, isolate_settings) -> None:
    key = "2026-11-05-top-level-script"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    assert [(item["start_line"], item["end_line"]) for item in registry[ids[SCRIPT_PATH]]] == [(2, 5)]
    claim = _claim_file_for_analysis(client, key, ids[SCRIPT_PATH])

    partial = _receipt(
        client, key, claim, reviewed_spans=[{"file_id": ids[SCRIPT_PATH], "start_line": 2, "end_line": 4}]
    )
    assert partial.status_code == 409, partial.text
    source_lines = _receipt(
        client, key, claim, reviewed_spans=[{"file_id": ids[SCRIPT_PATH], "start_line": 2, "end_line": 5}]
    )
    assert source_lines.status_code == 201, source_lines.text
    cited = _receipt(client, key, claim, callable_refs=_refs(ids[SCRIPT_PATH], registry[ids[SCRIPT_PATH]]))
    assert cited.status_code == 201, cited.text


def test_a_receipt_that_cites_every_segment_may_add_a_narrow_span(client, isolate_settings) -> None:
    """Cited segments are proven by reference, so a span that only points at
    the sink line inside them is a highlight, never a partial claim."""
    key = "2026-11-05-top-level-highlight"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    registry = _publish(client, key, repo_id, files, ids)
    # The script reads request input into a SQL sink, as its index reports.
    connection = sqlite3.connect(str(db_module.database_path()))
    try:
        connection.execute(
            "UPDATE code_files SET total_sinks = 1, total_entry_points = 1,"
            " structural_signal_counts_json = ? WHERE id = ?",
            (
                '{"entry_points": 1, "imports": 0, "security_sinks": 1, "security_sources": 1}',
                ids[SCRIPT_PATH],
            ),
        )
        connection.commit()
    finally:
        connection.close()
    claim = _claim_file_for_analysis(client, key, ids[SCRIPT_PATH])

    highlighted = _receipt(
        client,
        key,
        claim,
        callable_refs=_refs(ids[SCRIPT_PATH], registry[ids[SCRIPT_PATH]]),
        reviewed_spans=[{"file_id": ids[SCRIPT_PATH], "start_line": 4, "end_line": 4, "label": "sql sink"}],
    )
    assert highlighted.status_code == 201, highlighted.text


def test_an_upgrade_that_adds_file_scope_keeps_receipts_and_surfaces_the_new_obligation(
    client, isolate_settings
) -> None:
    """Build and seal an index without `<top-level>`, bind a receipt to its
    function, then rebuild with the indexer that publishes file scope and sync
    it over the same generation: the receipt keeps its callable, and the file
    scope it never covered is owed until a new receipt covers it."""
    key = "2026-11-05-top-level-upgrade"
    repo_id, files, ids = _setup(client, isolate_settings, key)
    previous = _publish(client, key, repo_id, files, ids, top_level=False)
    _classify_file(client, key, ids[MIXED_PATH], "critical", 100)
    claim = _claim_file_for_analysis(client, key, ids[MIXED_PATH])
    receipt = _receipt(client, key, claim, callable_refs=_refs(ids[MIXED_PATH], previous[ids[MIXED_PATH]]))
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo_id)) == set()

    upgraded = _publish(client, key, repo_id, files, ids)

    connection = sqlite3.connect(str(db_module.database_path()))
    try:
        linked = connection.execute(
            """
            SELECT callables.name, callables.start_line, callables.end_line
            FROM code_analysis_result_callables AS links
            JOIN code_structural_callables AS callables ON callables.id = links.callable_id
            WHERE links.result_id = ?
            """,
            (receipt.json()["id"],),
        ).fetchall()
    finally:
        connection.close()
    assert linked == [("acme_render", 5, 8)]
    assert _uncovered_paths(_gate(client, key, repo_id)) == {MIXED_PATH}

    reclaim = _claim_file_for_reanalysis(
        client, key, ids[MIXED_PATH], reason="cover the file scope the upgraded index publishes"
    )
    covered = _receipt(client, key, reclaim, callable_refs=_refs(ids[MIXED_PATH], upgraded[ids[MIXED_PATH]]))
    assert covered.status_code == 201, covered.text
    done = _complete(client, key, reclaim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo_id)) == set()


def _indexed_obligation(file_path: str, language: str, source: bytes, status: str = "complete"):
    import json

    from app.services.code_analysis_support import structural_review_obligation

    indexed = index_file(file_path, language, source)
    assert indexed["analysis_status"] == status
    return structural_review_obligation(
        {
            "loc": len(source.splitlines()),
            "language": language,
            "structural_analysis_status": indexed["analysis_status"],
            "structural_analysis_mode": indexed["analysis_mode"],
            "structural_unavailable_dimensions_json": json.dumps(indexed["unavailable_dimensions"]),
            "structural_truncated_dimensions_json": json.dumps(indexed["truncated_dimensions"]),
            "structural_signal_counts_json": json.dumps(indexed["signal_counts"]),
            "total_functions": indexed["total_functions"],
        },
        tuple(
            (segment["line_start"], segment["line_end"])
            for segment in indexed.get("top_level_segments", ())
        ),
    )


@pytest.mark.parametrize(
    ("file_path", "language", "source"),
    [
        ("acme/auth.py", "python", b"class A:\n    token = fetch_token(read_env())\n"),
        ("web/config.js", "javascript", b"class A { static cfg = loadConfig(readFlags()) }\n"),
        ("web/widget.ts", "typescript", b"@Component({template: buildTemplate()}) class A {}\n"),
        ("scripts/boot.lua", "lua", b"local x = 1\nprint(x)\n"),
    ],
)
def test_load_time_code_outside_any_segment_owes_a_whole_file_span(
    file_path: str, language: str, source: bytes,
) -> None:
    """A parsed file with no callable and no segment can still run code when it
    loads, so having nothing to cite never means nothing to review."""
    loc = len(source.splitlines())

    requirement = _indexed_obligation(file_path, language, source).span_requirement(loc)

    assert requirement is not None
    assert requirement[0] == (1, loc)


def test_a_literal_configuration_file_owes_one_whole_file_span() -> None:
    """A file that only returns a literal array opens no `<top-level>` segment
    and has no callable, so one span over the whole file is all it owes."""
    source = b"""<?php
return [
    'name' => 'acme',
    'hosts' => ['app.example.com'],
];
"""
    loc = len(source.splitlines())
    obligation = _indexed_obligation("config/app.php", "php", source)

    assert not obligation.owes_callable
    assert obligation.top_level_spans == ()
    assert obligation.proven(
        loc=loc, function_cited=False, cited_top_level=set(), reviewed_spans=[(1, loc)]
    )
    assert not obligation.proven(
        loc=loc, function_cited=False, cited_top_level=set(), reviewed_spans=[(2, 4)]
    )


@pytest.mark.parametrize(
    ("file_path", "language", "source"),
    [
        ("web/site.css", "css", b"body {\n  color: #333;\n}\n.acme { margin: 0; }\n"),
        ("web/about.html", "html", b"<!doctype html>\n<html>\n<body><p>Acme</p></body>\n</html>\n"),
    ],
)
def test_a_complete_stylesheet_or_markup_page_owes_nothing(
    file_path: str, language: str, source: bytes,
) -> None:
    """A stylesheet or a page of markup has no callable and no file-scope code
    the index reads, so it owes no review a span could prove."""
    assert not _indexed_obligation(file_path, language, source).owed


def test_a_markup_page_with_an_inline_script_owes_a_whole_file_span() -> None:
    """The HTML readers take tags, not the script a `<script>` element runs, so
    a page carrying one owes a read of all of it, form or no form."""
    source = (
        b"<!doctype html>\n<html>\n<body>\n<form action=\"/search\"></form>\n"
        b"<script>\n  document.write(location.hash);\n</script>\n</body>\n</html>\n"
    )
    loc = len(source.splitlines())

    requirement = _indexed_obligation(
        "web/search.html", "html", source, status="degraded"
    ).span_requirement(loc)

    assert requirement is not None
    assert requirement[0] == (1, loc)


def test_the_span_requirement_reads_segments_in_line_order() -> None:
    """Registry rows come back in insertion order, which a rebuild that keeps
    receipt-bound segments can leave out of line order."""
    from app.services.code_analysis_support import StructuralReviewObligation

    requirement = StructuralReviewObligation(
        top_level_spans=((20, 22), (2, 3))
    ).span_requirement(30)

    assert requirement is not None
    assert requirement[0] == (2, 22)
