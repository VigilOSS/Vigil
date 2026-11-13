"""A classification that records no context tags is named, never read as "none".

Context tags are the architect's structured record of what a file's job makes
it owe beyond its slot types. A classification that omits the field (every file
classified before the field existed, and any classification written without
it) has not said that no tag applies, so its families are not narrowed in
silence: coverage and code readiness name each such file and the command that
records its tags, and an explicit empty list records that none apply.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _create_repo,
    _refresh_repo_files,
    _seed_repo_files,
    _source_hash,
)


def _classify(client, key, file_id, **extra):
    response = client.post(
        f"/engagements/{key}/assessment/code/files/bulk-classify",
        json={"classifications": [{
            "file_id": file_id, "classification": "critical", "role": "parser",
            "slot_types": ["NETWORK-INPUT"], "analysis_priority": 90, **extra,
        }]},
    )
    assert response.status_code == 200, response.text


def test_untagged_classifications_are_named_until_the_architect_records_tags(
    client, isolate_settings
):
    key = "2026-11-14-acme-context-tags"
    _repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    base = f"/engagements/{key}/assessment/code"
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    _classify(client, key, int(parser["id"]))
    _classify(client, key, int(helper["id"]), context_tags=[])

    stored = client.get(f"{base}/files/{parser['id']}").json()
    assert stored["context_tags"] == [] and stored["context_tags_recorded"] is False
    assert client.get(f"{base}/files/{helper['id']}").json()["context_tags_recorded"] is True

    coverage = client.get(f"{base}/coverage").json()["gate"]
    unrecorded = coverage["context_tags_unrecorded"]
    assert unrecorded["count"] == 1
    assert unrecorded["sample_paths"] == ["src/parser.py"]
    assert unrecorded["by_classification"] == {"critical": 1}
    assert "code-record classify" in unrecorded["fix"]
    assert "context_tags_recorded=false" in unrecorded["full_list"]
    # A pointer, never a gate reason.
    assert not any("context_tags" in reason for reason in coverage["reasons"])
    readiness = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert readiness["context_tags_unrecorded"]["count"] == 1
    listed = client.get(f"{base}/files?context_tags_recorded=false").json()["items"]
    assert [row["file_path"] for row in listed] == ["src/parser.py"]

    _classify(client, key, int(parser["id"]), context_tags=["parser"])

    assert client.get(f"{base}/coverage").json()["gate"]["context_tags_unrecorded"] is None
    assert client.get(f"{base}/files/{parser['id']}").json()["context_tags"] == ["parser"]


def test_a_reclassification_that_omits_context_tags_keeps_the_recorded_ones(
    client, isolate_settings
):
    key = "2026-11-14-acme-context-tags-kept"
    _repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    base = f"/engagements/{key}/assessment/code"
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    _classify(client, key, int(parser["id"]), context_tags=["parser"])

    reclassified = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": parser["id"], "classification": "critical", "role": "parser",
        "slot_types": ["NETWORK-INPUT"], "analysis_priority": 95,
    }]})

    assert reclassified.status_code == 200, reclassified.text
    (derived,) = reclassified.json()["derived"]
    assert {key: derived[key] for key in ("file_id", "field", "value", "derived_from")} == {
        "file_id": parser["id"], "field": "context_tags", "value": ["parser"],
        "derived_from": "stored",
    }
    stored = client.get(f"{base}/files/{parser['id']}").json()
    assert stored["context_tags"] == ["parser"] and stored["context_tags_recorded"] is True
    assert stored["analysis_priority"] == 95

    cleared = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": parser["id"], "classification": "critical", "role": "parser",
        "slot_types": ["NETWORK-INPUT"], "analysis_priority": 95, "context_tags": [],
    }]})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["derived"] == []
    stored = client.get(f"{base}/files/{parser['id']}").json()
    assert stored["context_tags"] == [] and stored["context_tags_recorded"] is True


def test_the_unrecorded_count_and_its_full_list_read_cover_the_same_files(
    client, isolate_settings
):
    """The pointer's count is over analysis repositories (the obligation view);
    the read it names returns exactly those files, scoped like the pointer."""
    key = "2026-11-14-acme-context-tags-scope"
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    base = f"/engagements/{key}/assessment/code"
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    _classify(client, key, int(parser["id"]))
    reference = _create_repo(client, key, repo_key=f"{key}-framework", repo_role="reference")
    (framework,) = _refresh_repo_files(
        client, key, int(reference["id"]), [{
            "file_path": "src/framework.py", "language": "python", "loc": 20,
            "file_hash": _source_hash("acme-framework"),
            "header_snippet": "def route(request):\n    return request\n",
        }],
    )
    _classify(client, key, int(framework["id"]))

    for coverage_url, files_url in (
        (f"{base}/coverage", f"{base}/files?context_tags_recorded=false"),
        (
            f"{base}/coverage?repo_id={repo['id']}",
            f"{base}/files?context_tags_recorded=false&repo_id={repo['id']}",
        ),
    ):
        unrecorded = client.get(coverage_url).json()["gate"]["context_tags_unrecorded"]
        listed = client.get(files_url).json()
        assert unrecorded["count"] == listed["total"] == 1
        assert [row["file_path"] for row in listed["items"]] == ["src/parser.py"]
        assert "has_more" in unrecorded["paging"] and "offset" in unrecorded["paging"]

    scoped = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert f"repo_id={repo['id']}" in scoped["context_tags_unrecorded"]["full_list"]
