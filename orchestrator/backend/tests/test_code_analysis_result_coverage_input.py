"""A source-review receipt's `cwe_coverage` and `confidence` meet the closeout's rules.

The receipt's coverage is merged into the file's effort exactly as the
closeout's is, so a receipt cannot store what a closeout would refuse: a
non-canonical family is a phantom `--cwe-matrix` column, and an effort outside
0-100 or a confidence outside high/medium/low is a number or word nothing
reads. Every problem is named in one refusal, and a sound entry is stored in
the closeout's canonical form.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _owned,
    _publish_structural_callables,
    _seed_repo_files,
)


def _claim(client, isolate_settings, key):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    _classify_file(client, key, int(parser["id"]), "critical", 90)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", _claim_file_for_analysis(
        client, key, int(parser["id"])
    )


def test_a_receipt_names_every_coverage_and_confidence_problem_at_once(client, isolate_settings):
    key = "2026-11-14-acme-receipt-coverage-refused"
    base, claim = _claim(client, isolate_settings, key)

    refused = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Acme parser reviewed.", confidence="certain",
        cwe_coverage=[
            {"family": "sql-injection", "effort": 80},
            {"family": "ssrf", "effort": 150},
            {"family": "ssrf", "effort": 40},
            {"family": "open-redirect", "effort": "deep"},
        ],
    ))

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    for problem in ("'sql-injection'", "150", "Duplicate", "open-redirect", "'certain'"):
        assert problem in detail, (problem, detail)
    assert client.get(f"{base}/analysis-results?queue_item_id={claim['id']}").json() == []


def test_a_receipt_stores_its_coverage_in_canonical_form(client, isolate_settings):
    key = "2026-11-14-acme-receipt-coverage-stored"
    base, claim = _claim(client, isolate_settings, key)

    created = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Acme parser reviewed.", confidence="High",
        cwe_coverage=[{"family": " sqli ", "effort": 80}],
    ))

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["cwe_coverage"] == [{"family": "sqli", "effort": 80}]
    assert body["confidence"] == "high"
