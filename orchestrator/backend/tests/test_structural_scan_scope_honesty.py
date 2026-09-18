"""A structural index that scanned no function scope must say so.

`_detect_sinks` and `_detect_call_sites` read nothing but the spans
`_function_scan_lines` hands them, so a file with no callable — a Laravel
`routes/web.php`, a Blade template, a module-level script — reaches the backend
with every function-scoped dimension empty and nothing scanned. Reporting that
as `complete` is the false clean ADR 0015 exists to forbid, and it exempted the
file from the reviewed-span, coverage-integrity and structural-debt surfaces
that are meant to catch exactly it.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.services.code_analysis import FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _complete_structural_payload,
    _create_files,
    _create_repo,
    _owned,
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


def test_a_zero_callable_file_cannot_claim_complete_over_scanned_source(
    client, isolate_settings
) -> None:
    """The `zero-signal implies unavailable` direction the validator was missing.

    Imports prove the file had source the parser read; no callable proves the
    function-scoped detectors never ran over it. `complete` is then a claim the
    indexer cannot have made.
    """
    engagement_key = "2026-09-17-unscanned-scope-reject"
    _repo, _files, _parser, payload = _prepare(
        client,
        isolate_settings,
        engagement_key,
        parser_update={"structural_signal_counts": {
            "entry_points": 0,
            "imports": 3,
            "security_sinks": 0,
            "security_sources": 1,
        }},
        counts=False,
    )
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(f"{base}/files/bulk-structural-metadata", json=payload)

    assert response.status_code == 422, response.text
    assert "callable scope" in response.text


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
# The same rejection, one step earlier. `code-index sync` builds a single
# `updates` list per repository, so the backend's 422 names no file and takes
# the whole repo down with it: one dead, fully commented-out module is enough.
# The index-time mirror fails on the artifact that produced it, by path.
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
def test_code_index_sync_rejects_a_complete_file_with_no_callable_scope(
    overrides: dict,
) -> None:
    module = _sync_module()

    with pytest.raises(ValueError, match="routes/web.php"):
        module._validated_structural_metadata(
            _complete_artifact(**overrides),
            rel_path="routes/web.php",
            source_size=12,
        )


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

    metadata = module._validated_structural_metadata(
        _complete_artifact(), rel_path="pkg/__init__.py", source_size=12
    )

    assert metadata["structural_analysis_status"] == "complete"
