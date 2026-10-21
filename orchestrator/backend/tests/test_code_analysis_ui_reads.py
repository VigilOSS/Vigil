"""Operator-UI read surfaces over code analysis.

The Code view pages analysis results server-side instead of downloading every
receipt (with each JSON column twice), shows per-repository review progress,
and names the actual reason a structural index is stale. These tests pin those
reads against the same "current receipt" and "reviewed file" definitions the
readiness gates use, so the UI can never show a different truth.
"""
from __future__ import annotations

import ast
import json
import re
import sqlite3
from pathlib import Path

import pytest
from app.services import code_analysis, code_analysis_support

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _seed_queue_contract_file,
    _seed_reviewed_parser,
    _structural_callable,
    write_engagement,
)
from tests.test_engagements_api import write_engagement as write_web_engagement

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CODE_LABELS = (
    _REPO_ROOT / "orchestrator" / "frontend" / "src" / "components" / "code" / "codeLabels.ts"
)


def _base(engagement_key: str) -> str:
    return f"/engagements/{engagement_key}/assessment/code"


def _seed_two_results(client, isolate_settings, engagement_key: str):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _publish_structural_callables(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {
            int(parser["id"]): [
                _structural_callable(
                    "decode_frame",
                    qualified_name="AcmeParser.decode_frame",
                    start_line=1,
                    end_line=2,
                )
            ]
        },
    )
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    parser_claim = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))
    clean = client.post(
        f"{_base(engagement_key)}/analysis-results",
        json=_owned(
            parser_claim,
            queue_item_id=parser_claim["id"],
            disposition="clean",
            confidence="high",
            hypothesis="Acme parser bounds checks",
            evidence="alpha bounds verified on every read path",
            cwe_id="CWE-787",
            slot_type="NETWORK-INPUT",
        ),
    )
    assert clean.status_code == 201, clean.text
    helper_claim = _claim_file_for_analysis(client, engagement_key, int(helper["id"]))
    needs_context = client.post(
        f"{_base(engagement_key)}/analysis-results",
        json=_owned(
            helper_claim,
            queue_item_id=helper_claim["id"],
            disposition="needs_context",
            confidence="medium",
            evidence="caller contract lives outside the snapshot",
            notes="needs the Acme gateway source",
        ),
    )
    assert needs_context.status_code == 201, needs_context.text
    return repo, clean.json(), needs_context.json()


def test_analysis_result_page_matches_the_current_receipt_listing(client, isolate_settings):
    engagement_key = "2026-10-20-code-result-page"
    _, clean, needs_context = _seed_two_results(client, isolate_settings, engagement_key)
    base = _base(engagement_key)

    listing = client.get(f"{base}/analysis-results").json()
    page = client.get(f"{base}/analysis-results/page").json()
    assert sorted(row["id"] for row in page["items"]) == sorted(row["id"] for row in listing)
    assert page["total"] == 2
    assert page["offset"] == 0
    assert page["count"] == 2
    assert page["has_more"] is False
    # Disposition order puts the open question before the clean receipt.
    assert [row["id"] for row in page["items"]] == [needs_context["id"], clean["id"]]
    # Unfiltered, the facets describe the whole current set.
    assert page["facets"]["disposition"] == {"clean": 1, "needs_context": 1}
    assert page["facets"]["confidence"] == {"high": 1, "medium": 1}

    item = next(row for row in page["items"] if row["id"] == clean["id"])
    assert item["file_path"] == "src/parser.py"
    assert item["cwe_id"] == "CWE-787"
    assert item["slot_type"] == "NETWORK-INPUT"
    assert item["callable_ref_count"] == len(item["callable_refs"])
    assert not [key for key in item if key.endswith("_json")]
    assert "cwe_coverage" not in item and "audit_metadata" not in item

    # A superseded receipt leaves both reads together.
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_results SET superseded_at = CURRENT_TIMESTAMP WHERE id = ?",
            (clean["id"],),
        )
        connection.commit()
    after = client.get(f"{base}/analysis-results/page").json()
    assert [row["id"] for row in after["items"]] == [needs_context["id"]]
    assert after["facets"]["disposition"] == {"needs_context": 1}


def test_analysis_result_page_pages_and_filters(client, isolate_settings):
    engagement_key = "2026-10-20-code-result-filters"
    _, clean, needs_context = _seed_two_results(client, isolate_settings, engagement_key)
    base = _base(engagement_key)

    first = client.get(f"{base}/analysis-results/page?limit=1").json()
    assert (first["total"], first["count"], first["has_more"]) == (2, 1, True)
    second = client.get(f"{base}/analysis-results/page?limit=1&offset=1").json()
    assert (second["count"], second["has_more"]) == (1, False)
    assert {first["items"][0]["id"], second["items"][0]["id"]} == {clean["id"], needs_context["id"]}

    def ids(query: str) -> list[int]:
        response = client.get(f"{base}/analysis-results/page?{query}")
        assert response.status_code == 200, response.text
        return [row["id"] for row in response.json()["items"]]

    assert ids("disposition=clean") == [clean["id"]]
    assert ids("disposition=clean&disposition=needs_context") == [needs_context["id"], clean["id"]]
    assert ids("confidence=medium") == [needs_context["id"]]
    assert ids("cwe=787") == [clean["id"]]
    assert ids("slot=network") == [clean["id"]]
    assert ids("file=helpers") == [needs_context["id"]]
    assert ids("agent=vuln-hunter") == [needs_context["id"], clean["id"]]
    # Free-text terms must all match; matching is case-insensitive.
    assert ids("q=ALPHA") == [clean["id"]]
    assert ids("q=gateway") == [needs_context["id"]]
    assert ids("q=alpha&q=gateway") == []
    # LIKE wildcards in operator input are literal.
    assert ids("q=%25") == []
    assert ids("function=AcmeParser.decode") == [clean["id"]]
    assert ids("q=decode_frame") == [clean["id"]]
    filtered = client.get(f"{base}/analysis-results/page?disposition=clean").json()
    assert filtered["total"] == 1
    # Each facet counts under every other filter, ignoring its own.
    assert filtered["facets"]["disposition"] == {"clean": 1, "needs_context": 1}
    assert filtered["facets"]["confidence"] == {"high": 1}
    by_confidence = client.get(f"{base}/analysis-results/page?confidence=medium").json()
    assert by_confidence["facets"]["disposition"] == {"needs_context": 1}
    assert by_confidence["facets"]["confidence"] == {"high": 1, "medium": 1}
    searched = client.get(f"{base}/analysis-results/page?q=gateway").json()
    assert searched["facets"]["disposition"] == {"needs_context": 1}

    assert client.get(f"{base}/analysis-results/page?limit=0").status_code == 422
    assert client.get(f"{base}/analysis-results/page?limit=201").status_code == 422


def test_current_listing_filters_narrow_the_shared_current_receipt_set(client, isolate_settings):
    """``/analysis-results`` filters only narrow the page's current-receipt set.

    Both reads are built on one current-receipt query; superseded receipts
    return to the listing only when explicitly requested.
    """
    engagement_key = "2026-10-20-code-result-listing"
    _, clean, needs_context = _seed_two_results(client, isolate_settings, engagement_key)
    base = _base(engagement_key)

    def ids(query: str = "") -> list[int]:
        response = client.get(f"{base}/analysis-results?{query}")
        assert response.status_code == 200, response.text
        return [row["id"] for row in response.json()]

    page_ids = {row["id"] for row in client.get(f"{base}/analysis-results/page").json()["items"]}
    assert set(ids()) == page_ids == {clean["id"], needs_context["id"]}
    assert ids() == sorted(page_ids, reverse=True)
    assert ids(f"file_id={clean['file_id']}") == [clean["id"]]
    assert ids(f"queue_item_id={needs_context['queue_item_id']}") == [needs_context["id"]]
    assert ids(f"lease_token={clean['lease_token']}") == [clean["id"]]
    assert ids("disposition=needs_context") == [needs_context["id"]]
    assert ids(f"disposition=clean&file_id={needs_context['file_id']}") == []

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_results SET superseded_at = CURRENT_TIMESTAMP WHERE id = ?",
            (clean["id"],),
        )
        connection.commit()
    assert ids() == [needs_context["id"]]
    assert ids(f"file_id={clean['file_id']}") == []
    assert ids("include_superseded=true") == [needs_context["id"], clean["id"]]
    assert ids(f"include_superseded=true&file_id={clean['file_id']}") == [clean["id"]]


def test_repo_review_progress_uses_the_readiness_review_definition(client, isolate_settings):
    engagement_key = "2026-10-20-code-review-progress"
    repo, parser, _, _ = _seed_reviewed_parser(client, isolate_settings, engagement_key)
    reference = _create_repo(
        client, engagement_key, repo_key=f"{engagement_key}-reference", repo_role="reference"
    )
    _create_files(client, engagement_key, int(reference["id"]))

    response = client.get(f"{_base(engagement_key)}/repos/review-progress")
    assert response.status_code == 200, response.text
    progress = {row["repo_id"]: row for row in response.json()}
    assert progress[repo["id"]] == {
        "repo_id": repo["id"],
        "repo_role": "analysis",
        "admitted_files": 2,
        "reviewed_files": 1,
        "finished_files": 1,
        "finished_not_reviewed": [],
    }
    # Reference code is reported, never counted as reviewed work.
    assert progress[reference["id"]]["repo_role"] == "reference"
    assert progress[reference["id"]]["reviewed_files"] == 0

    coverage = client.get(f"{_base(engagement_key)}/coverage").json()
    analysed = sum(row["analyzed"] for row in coverage["by_classification"].values())
    assert progress[repo["id"]]["reviewed_files"] == analysed
    assert progress[repo["id"]]["admitted_files"] == coverage["total_files"]
    assert parser["analysis_status"] == "analyzed"


_INDEXED = {
    "active_generation": 3,
    "structural_index_generation": 3,
    "structural_index_schema": code_analysis_support.STRUCTURAL_INDEX_SCHEMA,
    "structural_index_manifest_path": "evidence/code/acme/structural-index.json",
}


@pytest.mark.parametrize(
    ("overrides", "expected_codes"),
    [
        ({}, []),
        ({"structural_index_generation": None}, ["never_indexed"]),
        ({"structural_index_generation": 2}, ["snapshot_mismatch"]),
        ({"structural_index_schema": "structural-index/v5"}, ["format_outdated"]),
        ({"structural_index_schema": ""}, ["format_outdated"]),
        ({"structural_index_manifest_path": ""}, ["manifest_missing"]),
        (
            {"structural_index_generation": 2, "structural_index_schema": "structural-index/v6"},
            ["snapshot_mismatch", "format_outdated"],
        ),
    ],
)
def test_structural_index_state_names_the_stale_trigger_the_gate_uses(overrides, expected_codes):
    repo = {**_INDEXED, **overrides}
    state = code_analysis_support.structural_index_state(repo)
    assert [reason["code"] for reason in state["reasons"]] == expected_codes
    assert state["current"] is (not expected_codes)
    # The readiness gate's own predicate must agree with the projection.
    assert code_analysis._structural_index_current(repo) is state["current"]
    for reason in state["reasons"]:
        assert reason["message"].strip()


def test_repo_listing_carries_structural_index_state(client, isolate_settings):
    engagement_key = "2026-10-20-code-index-state"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    listed = client.get(f"{_base(engagement_key)}/repos").json()
    single = client.get(f"{_base(engagement_key)}/repos/{repo['id']}").json()
    for payload in (listed[0], single):
        state = payload["structural_index_state"]
        assert state["current"] is False
        assert [reason["code"] for reason in state["reasons"]] == ["never_indexed"]


def _emitted_blocker_codes() -> set[str]:
    source = Path(code_analysis.__file__).read_text(encoding="utf-8")
    codes: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_readiness_blocker"
        ):
            first = node.args[0]
            assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
                "readiness blocker codes must stay literal so the UI label map can cover them"
            )
            codes.add(first.value)
    return codes


def test_every_readiness_blocker_code_has_an_operator_label():
    source = _CODE_LABELS.read_text(encoding="utf-8")
    match = re.search(r"export const BLOCKER_LABELS[^=]*=\s*\{(.*?)\n\};", source, re.DOTALL)
    assert match, "codeLabels.ts must declare `export const BLOCKER_LABELS = { ... };`"
    labelled = set(re.findall(r"^\s{2}([a-z_]+):\s*\{", match.group(1), re.MULTILINE))
    emitted = _emitted_blocker_codes()
    assert emitted, "no readiness blocker codes found"
    assert emitted - labelled == set()
    assert labelled - emitted == set()


def _complete_suspicious(client, engagement_key: str, file_id: int, agent_name: str) -> tuple[dict, dict]:
    base = _base(engagement_key)
    claim = _claim_file_for_analysis(client, engagement_key, file_id, agent_name=agent_name)
    result = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="suspicious",
            evidence="Acme candidate path is still unresolved in the sealed source.",
        ),
    )
    assert result.status_code == 201, result.text
    done = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="suspicious",
            notes="Needs a finding or a clean terminal reanalysis.",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert done.status_code == 200, done.text
    return claim, result.json()


def _seed_awaiting_verdicts(client, isolate_settings, suffix: str):
    """Two files whose latest finished review is suspicious; one is already
    queued for re-review, so its receipt is no longer a current receipt."""
    engagement_key, repo, parser = _seed_queue_contract_file(client, isolate_settings, suffix)
    helper = next(
        row
        for row in client.get(f"{_base(engagement_key)}/files?repo_id={repo['id']}&limit=20").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    _classify_file(client, engagement_key, int(helper["id"]), "critical", 80)
    parser_claim, parser_result = _complete_suspicious(client, engagement_key, int(parser["id"]), "acme-hunter-a")
    _, helper_result = _complete_suspicious(client, engagement_key, int(helper["id"]), "acme-hunter-b")
    requeued = client.post(
        f"{_base(engagement_key)}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Resolve the Acme candidate.",
            "items": [{"file_id": parser["id"], "priority": 80, "supersedes": parser_claim["id"]}],
        },
    )
    assert requeued.status_code == 201, requeued.text
    return engagement_key, repo, parser_result, helper_result


def test_awaiting_verdict_scope_lists_exactly_the_readiness_obligation(client, isolate_settings):
    """Regression: readiness and the results filter must count the same
    suspicious attempts. One owner defines "awaiting a verdict"."""
    engagement_key, repo, parser_result, helper_result = _seed_awaiting_verdicts(
        client, isolate_settings, "awaiting-verdict"
    )
    base = _base(engagement_key)

    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    [blocker] = [b for b in readiness["blockers"] if b["code"] == "unresolved_suspicious_analysis"]
    assert blocker["message"].startswith("Repository has 2 current suspicious")

    # The current-receipt listing drops the receipt whose file is queued again.
    current = client.get(f"{base}/analysis-results/page?disposition=suspicious").json()
    assert [row["id"] for row in current["items"]] == [helper_result["id"]]

    page = client.get(f"{base}/analysis-results/page?scope=awaiting_verdict").json()
    assert page["total"] == 2
    assert page["file_total"] == 2
    assert sorted(row["id"] for row in page["items"]) == sorted([parser_result["id"], helper_result["id"]])
    assert all(row["awaiting_verdict"] for row in page["items"])
    assert page["awaiting_verdict"] == {"files": 2, "results": 2}
    # The same counts ride along on the default scope so a toggle can show them.
    assert current["awaiting_verdict"] == {"files": 2, "results": 2}
    assert [row["awaiting_verdict"] for row in current["items"]] == [True]
    # Filters narrow the scope like any other page.
    narrowed = client.get(f"{base}/analysis-results/page?scope=awaiting_verdict&file=helpers").json()
    assert [row["id"] for row in narrowed["items"]] == [helper_result["id"]]
    assert narrowed["file_total"] == 1
    assert client.get(f"{base}/analysis-results/page?scope=everything").status_code == 422

    obligations = code_analysis.unresolved_suspicious_analysis_obligations(
        int(client.get(f"/engagements/{engagement_key}").json()["id"])
    )
    assert obligations == [{"repo_id": repo["id"], "suspicious_count": page["file_total"]}]


def test_awaiting_verdict_flag_is_exactly_the_awaiting_verdict_scope(client, isolate_settings):
    """A receipt is flagged ``awaiting_verdict`` on any read exactly when the
    ``scope=awaiting_verdict`` page lists it. A second suspicious receipt on an
    awaiting attempt that carries no evidence backs nothing, so neither does."""
    engagement_key, _, _, helper_result = _seed_awaiting_verdicts(client, isolate_settings, "awaiting-flag")
    base = _base(engagement_key)
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        columns = [
            row[1]
            for row in connection.execute("PRAGMA table_info(code_analysis_results)").fetchall()
            if row[1] not in {"id", "result_fingerprint", "evidence", "evidence_ref"}
        ]
        listed = ", ".join(columns)
        bare_id = connection.execute(
            f"""
            INSERT INTO code_analysis_results ({listed}, result_fingerprint, evidence, evidence_ref)
            SELECT {listed}, result_fingerprint || '-bare', '', '' FROM code_analysis_results WHERE id = ?
            """,
            (helper_result["id"],),
        ).lastrowid
        connection.commit()

    scope_ids = {
        row["id"] for row in client.get(f"{base}/analysis-results/page?scope=awaiting_verdict&limit=50").json()["items"]
    }
    assert helper_result["id"] in scope_ids and bare_id not in scope_ids
    for row in client.get(f"{base}/analysis-results/page?limit=50").json()["items"]:
        assert row["awaiting_verdict"] is (row["id"] in scope_ids), row["id"]
    for result_id in (helper_result["id"], bare_id):
        record = client.get(f"{base}/analysis-results/{result_id}").json()
        assert record["awaiting_verdict"] is (result_id in scope_ids), result_id


def test_analysis_result_point_read_and_position(client, isolate_settings):
    engagement_key = "2026-10-20-code-result-record"
    _, clean, needs_context = _seed_two_results(client, isolate_settings, engagement_key)
    base = _base(engagement_key)

    record = client.get(f"{base}/analysis-results/{clean['id']}")
    assert record.status_code == 200, record.text
    body = record.json()
    assert body["id"] == clean["id"]
    assert body["file_path"] == "src/parser.py"
    assert body["evidence"] == "alpha bounds verified on every read path"
    assert body["current"] is True
    assert body["awaiting_verdict"] is False
    assert body["repo_id"] == clean["repo_id"] if "repo_id" in clean else isinstance(body["repo_id"], int)
    assert body["queue_status"] in {"processing", "done"}
    assert client.get(f"{base}/analysis-results/999999").status_code == 404

    # Page order puts the open question first, then the clean receipt.
    first = client.get(f"{base}/analysis-results/{needs_context['id']}/position").json()
    assert first["index"] == 0 and first["total"] == 2
    assert first["previous"] is None
    assert first["next"]["id"] == clean["id"]
    assert first["next"]["file_path"] == "src/parser.py"
    last = client.get(f"{base}/analysis-results/{clean['id']}/position").json()
    assert (last["index"], last["previous"]["id"], last["next"]) == (1, needs_context["id"], None)
    # Under filters the record may be outside the results.
    outside = client.get(f"{base}/analysis-results/{needs_context['id']}/position?disposition=clean").json()
    assert outside["index"] is None and outside["total"] == 1
    assert client.get(f"{base}/analysis-results/999999/position").status_code == 404

    # A superseded receipt stays readable by id but is no longer current.
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_results SET superseded_at = CURRENT_TIMESTAMP WHERE id = ?",
            (clean["id"],),
        )
        connection.commit()
    retired = client.get(f"{base}/analysis-results/{clean['id']}").json()
    assert retired["current"] is False
    assert retired["superseded_at"]


def test_current_queue_lanes_page_exactly_what_queue_stats_count(client, isolate_settings):
    """Regression: a current-only lane must list the latest attempts the
    stats count, not every finished attempt in the history."""
    engagement_key, _, _, _ = _seed_awaiting_verdicts(client, isolate_settings, "queue-lanes")
    base = _base(engagement_key)
    stats = client.get(f"{base}/analysis-queue/stats").json()
    assert stats["done"] == 1 and stats["pending"] == 1

    history = client.get(f"{base}/analysis-queue?status=done").json()
    assert history["total"] == 2  # the full history keeps the superseded attempt
    for status_name in ("pending", "processing", "done", "error", "needs_context"):
        lane = client.get(f"{base}/analysis-queue?status={status_name}&current_only=true&limit=1").json()
        assert lane["total"] == stats[status_name], status_name
        assert lane["count"] == min(1, stats[status_name])
    paged = client.get(f"{base}/analysis-queue?current_only=true&limit=1&offset=1").json()
    assert paged["total"] == stats["total"]
    assert paged["offset"] == 1


def test_review_progress_explains_finished_jobs_that_do_not_count(client, isolate_settings):
    """Regression: finished jobs whose receipts predate receipt binding count
    as done but review no files; progress must say why they do not count."""
    engagement_key = "2026-10-20-code-legacy-receipts"
    repo, parser, _, result = _seed_reviewed_parser(client, isolate_settings, engagement_key)
    base = _base(engagement_key)
    before = {row["repo_id"]: row for row in client.get(f"{base}/repos/review-progress").json()}
    assert before[repo["id"]]["reviewed_files"] == 1
    assert before[repo["id"]]["finished_files"] == 1
    assert before[repo["id"]]["finished_not_reviewed"] == []

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            "UPDATE code_analysis_results SET receipt_binding_status = 'legacy_unbound' WHERE id = ?",
            (result["id"],),
        )
        connection.commit()

    after = {row["repo_id"]: row for row in client.get(f"{base}/repos/review-progress").json()}
    row = after[repo["id"]]
    assert (row["reviewed_files"], row["finished_files"]) == (0, 1)
    [reason] = row["finished_not_reviewed"]
    assert (reason["code"], reason["count"]) == ("legacy_receipts", 1)
    assert reason["message"].strip()
    stats = client.get(f"{base}/analysis-queue/stats").json()
    assert stats["done"] == sum(r["finished_files"] for r in after.values() if r["repo_role"] == "analysis")

    page = client.get(f"{base}/analysis-results/page").json()
    assert page["total"] == 0
    [hidden] = page["not_listed"]
    assert (hidden["code"], hidden["count"]) == ("legacy_receipts", 1)
    assert hidden["message"].strip()
    assert parser["analysis_status"] == "analyzed"


def test_readiness_says_whether_the_code_track_applies(client, isolate_settings):
    web_key = "2026-10-20-120000-acme-web"
    write_web_engagement(isolate_settings["engagements_dir"], key=web_key)
    assert client.get(f"/engagements/{web_key}").status_code == 200
    web = client.get(f"{_base(web_key)}/readiness?target_phase=hunt").json()
    assert web["track_enabled"] is False
    # The gate itself stays fail-closed for CLI transitions.
    assert "no_repositories" in {blocker["code"] for blocker in web["blockers"]}

    code_key = "2026-10-20-code-track"
    code_dir = write_engagement(isolate_settings["engagements_dir"], code_key)
    scope = json.loads((code_dir / "scope.json").read_text(encoding="utf-8"))
    (code_dir / "scope.json").write_text(json.dumps({**scope, "engagement_type": "code"}), encoding="utf-8")
    # A code engagement owes code review before its first repository arrives.
    assert client.get(f"{_base(code_key)}/readiness?target_phase=hunt").json()["track_enabled"] is True
    _create_repo(client, code_key, repo_key=f"{code_key}-repo")
    assert client.get(f"{_base(code_key)}/readiness?target_phase=hunt").json()["track_enabled"] is True


def test_code_activity_chips_open_the_result_they_recorded(client, isolate_settings):
    engagement_key = "2026-10-20-code-activity-chip"
    _, clean, needs_context = _seed_two_results(client, isolate_settings, engagement_key)
    feed = client.get(f"/engagements/{engagement_key}/activity?category=code&limit=50").json()
    chips = {
        entity["ref"]["result_id"]: entity
        for item in feed["items"]
        for entity in item["entities"]
        if entity["type"] == "code_file"
    }
    assert set(chips) == {clean["id"], needs_context["id"]}
    chip = chips[clean["id"]]
    assert chip["ref"]["code_file_id"] == clean["file_id"]
    assert chip["ref"]["file_path"] == "src/parser.py"
    assert isinstance(chip["ref"]["repo_id"], int)
