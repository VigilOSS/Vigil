"""`agent start --lane-file` resolves newline paths against real `code/files` rows.

The CLI's lane-file manifest reads exact file facts from `code/files` (or the
`code/files/lookup` body form for a selector too long for a query string). The
CLI suite drives that read with a hand-built fake page, so a fake carrying a
field the backend never serializes can hide a check that refuses every real
row. These tests feed the backend's own responses, through the real routes, to
the CLI functions that consume them, so the row shape cannot drift from the
serializer unnoticed.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from test_code_analysis_api import (
    _classify_file,
    _create_repo,
    _publish_structural_callables,
    _refresh_repo_files,
    _source_hash,
    write_engagement,
)

agent = importlib.import_module("assess.commands.agent")


class _BackendClient:
    """The `get`/`post` surface `_lane_file_manifest` uses, served by the app."""

    def __init__(self, client, engagement_key: str) -> None:
        self._client = client
        self._base = f"/engagements/{engagement_key}/assessment/"
        self.endpoints: list[str] = []

    def get(self, endpoint: str):
        self.endpoints.append(endpoint)
        response = self._client.get(self._base + endpoint)
        assert response.status_code == 200, response.text
        return response.json()

    def post(self, endpoint: str, payload: dict):
        self.endpoints.append(endpoint)
        response = self._client.post(self._base + endpoint, json=payload)
        assert response.status_code == 200, response.text
        return response.json()


def _file(path: str, loc: int) -> dict[str, object]:
    return {
        "file_path": path,
        "language": "python",
        "loc": loc,
        "file_hash": _source_hash(path),
        "header_snippet": "",
        "git_churn_score": 0,
        "has_past_cve_fix": False,
    }


_PATHS = ["src/auth/login.py", "src/web/views.py"]


@pytest.mark.parametrize("oversized_selector", [False, True])
def test_newline_lane_file_resolves_current_generation_backend_rows(
    client, isolate_settings, tmp_path: Path, monkeypatch, oversized_selector: bool
) -> None:
    paths = _PATHS
    expected_endpoint = "code/files?"
    if oversized_selector:
        # A selector whose query string exceeds the CLI's 8000-byte URL budget
        # is read through the `code/files/lookup` body form. A path that long
        # cannot exist on the test filesystem, so pad the planned query instead.
        planned = agent._selected_fact_queries
        monkeypatch.setattr(
            agent,
            "_selected_fact_queries",
            lambda *args: [query + "&pad=" + "x" * 8000 for query in planned(*args)],
        )
        expected_endpoint = "code/files/lookup"
    engagement_key = "2026-11-14-lane-file-rows"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="acme-lane-repo")
    repo_id = int(repo["id"])
    # Two refreshes put the repository past its first generation, so a
    # generation-shaped default on either side cannot satisfy the read.
    _refresh_repo_files(client, engagement_key, repo_id, [_file(path, 3) for path in paths])
    files = _refresh_repo_files(
        client, engagement_key, repo_id, [_file(path, 10 + index) for index, path in enumerate(paths)]
    )
    # Queue the files so each row carries the current attempt whose generation
    # the CLI compares; the first refresh's attempts are history.
    _publish_structural_callables(client, engagement_key, repo_id, files, {})
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "high", 50)
    created = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue",
        json={"items": [{"file_id": int(row["id"]), "priority": 50} for row in files]},
    )
    assert created.status_code == 201, created.text
    generation = int(
        client.get(f"/engagements/{engagement_key}/assessment/code/repos/{repo_id}").json()[
            "active_generation"
        ]
    )
    assert generation >= 2

    lane_file = tmp_path / "lane.txt"
    lane_file.write_text("\n".join(paths) + "\n", encoding="utf-8")
    backend = _BackendClient(client, engagement_key)
    lines = agent._lane_file_manifest(
        lane_file,
        client=backend,
        source_identity=[f"repo_id: {repo_id}", f"repo_generation: {generation}"],
    )

    listed = backend.get(f"code/files?repo_id={repo_id}")["items"]
    assert {row["queue"]["current_attempt"]["repo_generation"] for row in listed} == {generation}
    text = "\n".join(lines)
    expected_loc = sum(10 + index for index in range(len(paths)))
    assert f"items: {len(paths)}; total LOC: {expected_loc}" in text
    assert any(endpoint.startswith(expected_endpoint) for endpoint in backend.endpoints)


def test_queue_fetch_lane_file_resolves_real_fetch_output(
    client, isolate_settings, tmp_path: Path
) -> None:
    """A lane file that is the literal `code-dispatch fetch` output resolves."""
    engagement_key = "2026-11-14-lane-file-fetch"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="acme-fetch-repo")
    repo_id = int(repo["id"])
    files = _refresh_repo_files(client, engagement_key, repo_id, [_file(path, 7) for path in _PATHS])
    _publish_structural_callables(client, engagement_key, repo_id, files, {})
    for row in files:
        _classify_file(client, engagement_key, int(row["id"]), "high", 50)
    base = f"/engagements/{engagement_key}/assessment/code"
    created = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": int(row["id"]), "priority": 50} for row in files]},
    )
    assert created.status_code == 201, created.text
    fetched = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 10, "agent_name": "hunter-lane"}
    )
    assert fetched.status_code == 200, fetched.text
    generation = int(client.get(f"{base}/repos/{repo_id}").json()["active_generation"])

    lane_file = tmp_path / "lane.json"
    lane_file.write_text(json.dumps(fetched.json()), encoding="utf-8")
    lines = agent._lane_file_manifest(
        lane_file,
        client=_BackendClient(client, engagement_key),
        source_identity=[f"repo_id: {repo_id}", f"repo_generation: {generation}"],
    )

    text = "\n".join(lines)
    assert f"items: {len(_PATHS)}; total LOC: {7 * len(_PATHS)}" in text
    assert "scratch_dir" in text
