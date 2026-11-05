"""A structural index that scanned no function scope must say so.

A file whose function-scoped dimensions were never read reaches the backend
with those dimensions declared unavailable; reporting it as `complete` is the
false clean ADR 0015 exists to forbid. A file with no callable whose file scope
the indexer did read is a real measurement, but with no callable to cite it
still owes whole-file review proof.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.services.code_analysis_support import FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _complete_structural_payload,
    _create_files,
    _create_repo,
    _owned,
    _refresh_repo_files,
    _source_hash,
    write_engagement,
)

UNSCANNED_SCOPE_REASON = "unscanned_function_scope"
# Derived, not restated: a fourth hard-coded copy of this set is how deleting a
# dimension from the shared constant survived the suite. `entry_points` is the
# zero-callable file's own extra debt -- the catalogue is keyed on callables.
UNSCANNED_SCOPE_DIMENSIONS = sorted(
    {*FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS, "entry_points"}
)


def _structural_payload(client, engagement_key, repo, files, *, parser_update):
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": row["id"],
                "source_sha256": row["file_hash"],
                "total_functions": 0,
                "total_entry_points": 0,
                "total_sinks": 0,
                "total_exports": 0,
                "callables": [],
            }
            for row in files
        ],
    )
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    update = next(
        item for item in payload["updates"] if item["file_id"] == parser["id"]
    )
    update.update(parser_update)
    return payload


def _unscanned_scope_update() -> dict[str, object]:
    return {
        "structural_analysis_status": "degraded",
        "structural_analysis_mode": "tree_sitter",
        "structural_degradation_reason": UNSCANNED_SCOPE_REASON,
        "structural_unavailable_dimensions": list(UNSCANNED_SCOPE_DIMENSIONS),
    }


def _degraded_counts(files, parser_path) -> dict[str, object]:
    return {
        "degraded_files": 1,
        "degraded_file_paths": [parser_path],
        "analysis_status_counts": {
            "complete": len(files) - 1,
            "degraded": 1,
            "unsupported": 0,
        },
    }


def _prepare(client, isolate_settings, engagement_key, *, parser_update, counts=True):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    payload = _structural_payload(
        client, engagement_key, repo, files, parser_update=parser_update
    )
    if counts:
        payload.update(_degraded_counts(files, str(parser["file_path"])))
    return repo, files, parser, payload


def test_an_unscanned_function_scope_publishes_as_declared_coverage_debt(
    client, isolate_settings
) -> None:
    engagement_key = "2026-09-17-unscanned-scope-publish"
    repo, _files, parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update=_unscanned_scope_update(),
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text
    persisted = client.get(f"{base}/files/{parser['id']}").json()
    assert persisted["structural_analysis_status"] == "degraded"
    assert persisted["structural_degradation_reason"] == UNSCANNED_SCOPE_REASON
    assert persisted["structural_unavailable_dimensions"] == UNSCANNED_SCOPE_DIMENSIONS


def _file_scope_signal_update() -> dict[str, object]:
    """A zero-callable file whose `<top-level>` scope the indexer read."""
    return {
        "total_entry_points": 1,
        "total_sinks": 1,
        "structural_signal_counts": {
            "entry_points": 1,
            "imports": 3,
            "security_sinks": 1,
            "security_sources": 1,
        },
    }


def test_a_zero_callable_file_measured_at_file_scope_publishes_complete(
    client, isolate_settings
) -> None:
    """The indexer reads file scope as the `<top-level>` scope, so a module-level
    script with no callable reports a real measurement under `complete`."""
    engagement_key = "2026-09-17-unscanned-scope-file-scope"
    _repo, _files, parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update=_file_scope_signal_update(),
        counts=False,
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text
    persisted = client.get(f"{base}/files/{parser['id']}").json()
    assert persisted["structural_analysis_status"] == "complete"
    assert persisted["total_functions"] == 0
    assert persisted["total_sinks"] == 1


@pytest.mark.parametrize(
    "parser_update",
    [
        pytest.param(_file_scope_signal_update(), id="file-scope-signals"),
        pytest.param(
            {"structural_signal_counts": {
                "entry_points": 0,
                "imports": 4,
                "security_sinks": 0,
                "security_sources": 0,
            }},
            id="imports-only",
        ),
        pytest.param({}, id="no-signal"),
    ],
)
def test_a_partial_span_cannot_review_a_zero_callable_file(
    client, isolate_settings, parser_update
) -> None:
    """With no callable to cite, a whole-file span is the only review proof a
    zero-callable file with source can offer, whatever its signals: no signal
    is a measurement of the readers, not proof that a reviewer read the file."""
    engagement_key = "2026-09-17-zero-callable-signal-span"
    _repo, _files, parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update=parser_update,
        counts=False,
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    assert client.post(
        f"{base}/files/bulk-structural-metadata", json=payload
    ).status_code == 200
    claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser["id"]),
        publish_callable_registry=False,
    )

    partial = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[{"file_id": parser["id"], "start_line": 1, "end_line": 1}],
            evidence="One line cannot stand for a file-scope sink map.",
        ),
    )

    assert partial.status_code == 409, partial.text
    assert "no callable" in partial.json()["detail"]

    whole_file = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[
                {
                    "file_id": parser["id"],
                    "start_line": 1,
                    "end_line": parser["loc"],
                    "label": "whole-file manual review",
                }
            ],
            evidence="Every sealed source line was read by hand.",
        ),
    )
    assert whole_file.status_code == 201, whole_file.text


def test_a_measured_negative_with_callables_still_publishes_complete(
    client, isolate_settings
) -> None:
    """Functions present and genuinely no sinks is the common, honest case."""
    engagement_key = "2026-09-17-unscanned-scope-negative"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": row["id"],
                "source_sha256": row["file_hash"],
                "total_functions": 2,
                "total_entry_points": 0,
                "total_sinks": 0,
                "total_exports": 0,
            }
            for row in files
        ],
    )

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text


def test_an_empty_file_may_still_publish_complete(client, isolate_settings) -> None:
    """No callable and no signal at all is consistent with an unscannable file."""
    engagement_key = "2026-09-17-unscanned-scope-empty"
    _repo, _files, _parser, payload = _prepare(
        client, isolate_settings, engagement_key, parser_update={}, counts=False
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 200, response.text


def test_a_partial_span_cannot_review_a_file_whose_scope_was_never_scanned(
    client, isolate_settings
) -> None:
    engagement_key = "2026-09-17-unscanned-scope-span"
    repo, _files, parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update=_unscanned_scope_update(),
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    assert client.post(
        f"{base}/files/bulk-structural-metadata", json=payload
    ).status_code == 200
    claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser["id"]),
        publish_callable_registry=False,
    )

    partial = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[{"file_id": parser["id"], "start_line": 1, "end_line": 1}],
            evidence="One line cannot stand for source the index never scanned.",
        ),
    )

    assert partial.status_code == 409, partial.text
    assert "no function scope" in partial.json()["detail"]

    whole_file = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[
                {
                    "file_id": parser["id"],
                    "start_line": 1,
                    "end_line": parser["loc"],
                    "label": "whole-file manual review",
                }
            ],
            evidence="Every sealed source line was read by hand.",
        ),
    )
    assert whole_file.status_code == 201, whole_file.text


def test_a_partial_span_cannot_review_a_script_scope_file_without_callables(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-04-script-scope-span"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": "public/report.php",
                "language": "php",
                "loc": 80,
                "file_hash": _source_hash("script-scope-report"),
                "header_snippet": "<?php\n$id = $_GET['id'];\n",
                "git_churn_score": 0,
                "has_past_cve_fix": False,
            }
        ],
    )
    script = files[0]
    _classify_file(client, engagement_key, int(script["id"]), "critical", 100)
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo['id']}").json()
    payload = _complete_structural_payload(
        repo_id=int(repo["id"]),
        repo_generation=int(binding["active_generation"]),
        source_manifest_digest=str(binding["source_manifest_digest"]),
        updates=[
            {
                "file_id": script["id"],
                "source_sha256": script["file_hash"],
                "indexed_language": "php",
                "total_functions": 0,
                "total_entry_points": 0,
                "total_sinks": 3,
                "total_exports": 0,
                "callables": [],
            }
        ],
    )
    assert client.post(
        f"{base}/files/bulk-structural-metadata", json=payload
    ).status_code == 200
    claim = _claim_file_for_analysis(client, engagement_key, int(script["id"]))

    partial = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[{"file_id": script["id"], "start_line": 1, "end_line": 1}],
            evidence="The header line cannot stand for the whole script.",
        ),
    )
    assert partial.status_code == 409, partial.text
    assert "whole-file coverage" in partial.json()["detail"]

    whole_file = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            reviewed_spans=[
                {
                    "file_id": script["id"],
                    "start_line": 1,
                    "end_line": script["loc"],
                    "label": "whole-file manual review",
                }
            ],
            evidence="Every sealed source line was read by hand.",
        ),
    )
    assert whole_file.status_code == 201, whole_file.text


def test_an_unscanned_scope_file_is_named_in_structural_coverage_debt(
    client, isolate_settings
) -> None:
    engagement_key = "2026-09-17-unscanned-scope-debt"
    repo, _files, parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update=_unscanned_scope_update(),
    )
    base = f"/engagements/{engagement_key}/assessment/code"
    assert client.post(
        f"{base}/files/bulk-structural-metadata", json=payload
    ).status_code == 200

    readiness = client.get(f"{base}/readiness?target_phase=hunt").json()

    warnings = json.dumps(readiness["quality_gate"]["warnings"])
    assert "structural coverage debt" in warnings
    assert "1 degraded" in warnings


# ---------------------------------------------------------------------------
# The index-time mirror of the backend validator reads the same artifacts.
# ---------------------------------------------------------------------------

SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _sync_module():
    path = SCRIPTS_ROOT / "assess" / "commands" / "code_index_sync.py"
    spec = importlib.util.spec_from_file_location("test_scan_scope_sync", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _complete_artifact(**overrides) -> dict:
    artifact = {
        "total_functions": 0,
        "total_exports": 0,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
        "structural_index_available": True,
        "analysis_status": "complete",
        "analysis_mode": "tree_sitter",
        "degradation_reason": None,
        "source_size": 12,
        "bytes_scanned": 12,
        "unavailable_dimensions": [],
        "artifact_truncated": False,
        "truncated_dimensions": [],
        "signal_counts": {
            "entry_points": 0,
            "imports": 0,
            "security_sinks": 0,
            "security_sources": 0,
        },
    }
    artifact.update(overrides)
    return artifact


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"total_exports": 2}, id="exports"),
        pytest.param(
            {
                "signal_counts": {
                    "entry_points": 0,
                    "imports": 3,
                    "security_sinks": 0,
                    "security_sources": 0,
                }
            },
            id="imports",
        ),
    ],
)
def test_code_index_sync_accepts_a_complete_file_measured_at_file_scope(
    overrides: dict,
) -> None:
    module = _sync_module()

    metadata = module.validated_structural_metadata(
        _complete_artifact(**overrides),
        rel_path="routes/web.php",
        source_size=12,
    )

    assert metadata["structural_analysis_status"] == "complete"


def test_the_backend_mirror_of_the_function_scoped_dimensions_is_exact() -> None:
    """The backend mirrors the agent tree rather than importing from it
    (CODE-MAP.md), which is what lets the two lists drift apart unnoticed.

    Every other reader of this set now derives from whichever copy it can see,
    so a dimension deleted from one side stays self-consistent on that side and
    survives the suite. This is the one assertion that reads both.
    """
    from assess.lib.treesitter_index import FUNCTION_SCOPED_DIMENSIONS

    assert FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS == FUNCTION_SCOPED_DIMENSIONS


def test_code_index_sync_accepts_a_complete_file_with_no_signal_at_all() -> None:
    """A blank or comment-only file really does measure empty."""
    module = _sync_module()

    metadata = module.validated_structural_metadata(
        _complete_artifact(), rel_path="pkg/__init__.py", source_size=12
    )

    assert metadata["structural_analysis_status"] == "complete"
