"""W3b — backend ``uncovered_high_risk_files`` structural-verification sub-gate.

A critical/high file that is terminal (analyzed/done) and whose structural index
found functions, but which was closed with ZERO evidenced function-level analysis
(no distinct analysis-result function rows), no linked finding, and no accepted-gap
resolution (all applicable families marked not_applicable), is the broad-18 near-miss where high files were
closed with no function analysis. The coverage gate now surfaces these under
``gate.uncovered_high_risk_files`` so the transition-phase code gate can block on
them — while leaving ``gate.passed`` (and the per-family effort threshold gate)
unchanged, so the effort dimension stays a WARN.

Escape valves proven here: record an evidenced analysis-result function row,
mark the applicable families not_applicable (accepted gap), or link a finding
at ``file:<path>``. Caller-claimed counters remain advisory.
"""
from __future__ import annotations

from app import db as db_module

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _finding_code_snapshot,
    _network_input_coverage,
    _publish_structural_totals,
    write_engagement,
)


def _prepare(client, isolate_settings, key):
    """Create a repo + critical parser.py with a non-zero structural function
    count, ready to be closed via the queue. Returns (repo, parser_file)."""
    write_engagement(isolate_settings["engagements_dir"], key)
    repo = _create_repo(client, key, repo_key=f"{key}-repo")
    files = _create_files(client, key, int(repo["id"]))
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    _classify_file(client, key, int(parser["id"]), "critical", 100)
    _publish_structural_totals(
        client,
        key,
        int(repo["id"]),
        files,
        {int(parser["id"]): {"total_functions": 5}},
    )
    return repo, parser


def _complete(client, key, queue_item, cwe_coverage, disposition="clean"):
    return client.post(
        f"/engagements/{key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["agent_name"],
            "lease_token": queue_item["lease_token"],
            "disposition": disposition,
            "notes": "completed structural coverage-gate fixture review",
            "cwe_coverage": cwe_coverage,
        },
    )


def _gate(client, key, repo_id):
    response = client.get(
        f"/engagements/{key}/assessment/code/coverage?repo_id={repo_id}"
    )
    assert response.status_code == 200, response.text
    return response.json()["gate"]


def _uncovered_paths(gate):
    return {u["file_path"] for u in gate.get("uncovered_high_risk_files", [])}


def _create_file_finding(client, key, slug, location, repo_id):
    author_id = f"coverage-author-{slug.lower()}"
    dispatch = client.post(
        f"/engagements/{key}/assessment/dispatches",
        json={
            "agent_id": author_id,
            "agent_role": "code-vuln-hunter",
            "task": f"record {slug}",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    response = client.post(
        f"/engagements/{key}/assessment/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "injection",
            "root_cause_key": slug.lower(),
            "auth_context": "anonymous",
            "canonical_location": location,
            "summary": "linked to the file under analysis",
            "evidence_ref": "findings.md",
            "notes": "",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "x"},
            "provenance": {
                "agent_id": author_id,
                "agent_name": "code-vuln-hunter",
                "code_snapshot": _finding_code_snapshot(client, key, int(repo_id)),
            },
            "links": [],
        },
    )
    assert response.status_code == 201, response.text


# ---------------------------------------------------------------------------
# Blocker fires: closed, structural functions exist, zero function analysis.
# ---------------------------------------------------------------------------


def test_uncovered_high_risk_file_flagged_when_closed_with_zero_function_analysis(
    client, isolate_settings
):
    key = "2026-06-26-uncov-block"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    # High effort (>= 70) so the effort gate is silent, isolating the structural
    # sub-gate; functions_analyzed defaults to 0 in _network_input_coverage.
    done = _complete(client, key, queue_item, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text

    gate = _gate(client, key, repo["id"])
    assert "src/parser.py" in _uncovered_paths(gate)
    # Effort gate is silent and gate.passed is unaffected: the structural hole is
    # intentionally invisible to gate.passed so the effort dimension stays WARN.
    assert gate["effort_warnings"] == []
    assert gate["passed"] is True


def test_public_file_patch_cannot_erase_structural_coverage_debt(
    client, isolate_settings
):
    key = "2026-08-05-uncov-structural-patch"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    done = _complete(client, key, queue_item, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo["id"])) == {"src/parser.py"}

    forged = client.patch(
        f"/engagements/{key}/assessment/code/files/{parser['id']}",
        json={"total_functions": 0},
    )

    assert forged.status_code == 400
    assert "total_functions" in forged.json()["detail"]
    persisted = client.get(
        f"/engagements/{key}/assessment/code/files/{parser['id']}"
    ).json()
    assert persisted["total_functions"] == 5
    assert _uncovered_paths(_gate(client, key, repo["id"])) == {"src/parser.py"}


def test_total_functions_zero_is_not_flagged(client, isolate_settings):
    # Without a structural index (total_functions=0) there is nothing to verify
    # against, so the file is not flagged even when closed with no analysis.
    key = "2026-06-26-uncov-nostruct"
    write_engagement(isolate_settings["engagements_dir"], key)
    repo = _create_repo(client, key, repo_key=f"{key}-repo")
    files = _create_files(client, key, int(repo["id"]))
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    _classify_file(client, key, int(parser["id"]), "critical", 100)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    done = _complete(client, key, queue_item, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    gate = _gate(client, key, repo["id"])
    assert _uncovered_paths(gate) == set()


# ---------------------------------------------------------------------------
# Caller-claimed counters are advisory, not function-level proof.
# ---------------------------------------------------------------------------


def test_claimed_functions_analyzed_cannot_clear_uncovered_without_result_evidence(
    client, isolate_settings
):
    key = "2026-06-26-uncov-claimed"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    coverage = _network_input_coverage(
        default_effort=80,
        overrides={fam: {"functions_analyzed": 999} for fam in (
            "web-app-injection", "web-app-auth", "ssrf",
            "open-redirect", "path-traversal", "algorithmic-dos", "error-handling",
        )},
    )
    done = _complete(client, key, queue_item, coverage)
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo["id"])) == {"src/parser.py"}


# ---------------------------------------------------------------------------
# Escape valve 1: record an evidenced analysis-result function row.
# ---------------------------------------------------------------------------


def test_analysis_result_function_row_clears_uncovered(client, isolate_settings):
    key = "2026-06-26-uncov-result"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    result = client.post(
        f"/engagements/{key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser["id"],
            "agent_name": "code-vuln-hunter",
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "bounded",
            "evidence": "reviewed sinks",
            "disposition": "clean",
            "confidence": "high",
            "notes": "",
        },
    )
    assert result.status_code == 201, result.text
    done = _complete(client, key, queue_item, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo["id"])) == set()


# ---------------------------------------------------------------------------
# Escape valve 2: accepted-gap — all applicable families not_applicable.
# ---------------------------------------------------------------------------


def test_accepted_gap_clears_uncovered(client, isolate_settings):
    key = "2026-06-26-uncov-accepted"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    coverage = _network_input_coverage(
        default_effort=0,
        overrides={fam: {"disposition": "not_applicable", "effort": 0, "notes": "no reachable sink"} for fam in (
            "web-app-injection", "web-app-auth", "ssrf",
            "open-redirect", "path-traversal", "algorithmic-dos", "error-handling",
        )},
    )
    done = _complete(client, key, queue_item, coverage)
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo["id"])) == set()


# ---------------------------------------------------------------------------
# Escape valve 3: a linked finding at file:<path>.
# ---------------------------------------------------------------------------


def test_linked_finding_clears_uncovered(client, isolate_settings):
    key = "2026-06-26-uncov-finding"
    repo, parser = _prepare(client, isolate_settings, key)
    _create_file_finding(
        client, key, "VA-047", "file:src/parser.py:12", repo["id"]
    )
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    done = _complete(client, key, queue_item, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text
    assert _uncovered_paths(_gate(client, key, repo["id"])) == set()


def test_legacy_whitespace_prefixed_linked_finding_clears_uncovered(
    client, isolate_settings
):
    key = "2026-08-04-uncov-legacy-finding"
    repo, parser = _prepare(client, isolate_settings, key)
    _create_file_finding(
        client, key, "VA-148", "file:src/parser.py:12", repo["id"]
    )
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = '\tfile:src/parser.py:12'
            WHERE engagement_id = (
                SELECT id FROM engagements WHERE key = ?
            ) AND slug = 'VA-148'
            """,
            (key,),
        )
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    done = _complete(
        client,
        key,
        queue_item,
        _network_input_coverage(default_effort=80),
    )
    assert done.status_code == 200, done.text

    assert _uncovered_paths(_gate(client, key, repo["id"])) == set()


# ---------------------------------------------------------------------------
# KEEP-WARN: a below-threshold effort score with an evidenced function result is
# an effort WARN, not a structural block.
# ---------------------------------------------------------------------------


def test_low_effort_with_evidenced_function_is_warn_not_uncovered(client, isolate_settings):
    key = "2026-06-26-uncov-loweffort"
    repo, parser = _prepare(client, isolate_settings, key)
    queue_item = _claim_file_for_analysis(client, key, int(parser["id"]))
    coverage = _network_input_coverage(
        default_effort=10,  # below the critical 70 threshold -> effort WARN
        overrides={fam: {"effort": 10, "functions_analyzed": 4} for fam in (
            "web-app-injection", "web-app-auth", "ssrf",
            "open-redirect", "path-traversal", "algorithmic-dos",
        )},
    )
    result = client.post(
        f"/engagements/{key}/assessment/code/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser["id"],
            "agent_name": queue_item["agent_name"],
            "lease_token": queue_item["lease_token"],
            "function_name": "parse_message",
            "hypothesis": "Low-effort review still inspected one concrete function.",
            "evidence": "Reviewed parse_message control flow and reachable sinks.",
            "disposition": "clean",
            "confidence": "medium",
            "notes": "",
        },
    )
    assert result.status_code == 201, result.text
    done = _complete(client, key, queue_item, coverage)
    assert done.status_code == 200, done.text
    gate = _gate(client, key, repo["id"])
    assert gate["effort_warnings"], "low effort should still raise an effort WARN"
    assert _uncovered_paths(gate) == set()
