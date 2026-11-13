"""A claim carries each field once and the repository by reference.

Repeating the whole repository record on every item (its threat model alone
runs to kilobytes) and every JSON column twice, as the stored string and the
parsed value, would put a five-item claim past 100 KB of agent context. Each
item carries the parsed value only and a compact repository identity that names
the read returning the full record, so nothing is lost and nothing is repeated.
"""
from __future__ import annotations

import json

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _seed_repo,
)


def test_a_claimed_item_carries_one_copy_of_each_field_and_a_repo_reference(
    client, isolate_settings
):
    engagement_key = "2026-11-14-code-claim-shape"
    repo = _seed_repo(client, isolate_settings, engagement_key, repo_key="claim-shape-repo")
    parser = next(
        row for row in _create_files(client, engagement_key, int(repo["id"]))
        if row["file_path"] == "src/parser.py"
    )
    _classify_file(client, engagement_key, int(parser["id"]), "high", 79)

    item = _claim_file_for_analysis(client, engagement_key, int(parser["id"]))

    for scope in (item, item["file"]):
        doubled = [
            key for key in scope
            if key.endswith("_json") and key.removesuffix("_json") in scope
        ]
        assert doubled == [], doubled
    claimed_repo = item["repo"]
    assert claimed_repo["id"] == repo["id"]
    assert claimed_repo["active_generation"] == item["repo_generation"]
    assert f"vigil assess fetch code/repos/{repo['id']}" in claimed_repo["full_record"]
    full = client.get(
        f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}"
    ).json()
    assert "threat_model" not in claimed_repo
    # Every field the reference leaves out is on the record it names.
    assert set(claimed_repo["omitted_fields"]) <= set(full)
    assert "threat_model" in claimed_repo["omitted_fields"]
    assert len(json.dumps(claimed_repo)) < 2000
