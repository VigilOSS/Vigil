"""`artifact register --agent-id` attributes bytes to a recorded dispatch.

Review gates read an artifact's producer history: a report QC reviewer must
differ from every agent that registered ``report.md``. An id that names no
dispatch would be stored as a producer nobody can be, so the verb refuses it
before any write. A registration of another kind without ``--agent-id`` (an
operator's own registration) needs no dispatch and makes no lookup; a report
registration without it is covered by test_report_writer_attribution.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import artifact
from assess.lib.client import AssessError


class _Client:
    def __init__(self, dispatches: set[str]) -> None:
        self.dispatches = dispatches
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        agent_id = endpoint.removeprefix("dispatches/")
        if agent_id not in self.dispatches:
            raise AssessError(f"HTTP 404: dispatch {agent_id} not found")
        return {"agent_id": agent_id, "agent_role": "report-writer"}

    def post(self, endpoint: str, payload: dict, **_kwargs) -> dict:
        self.posts.append((endpoint, payload))
        if endpoint == "artifacts/bulk":
            rows = [
                {"id": index + 1, "relative_path": item["path"], "present": True}
                for index, item in enumerate(payload["items"])
            ]
            return {
                "requested": len(rows), "registered": len(rows), "failed": 0,
                "outcomes": [
                    {"index": index, "path": row["relative_path"],
                     "relative_path": row["relative_path"], "artifact_id": row["id"],
                     "outcome": "registered", "status_code": None, "detail": ""}
                    for index, row in enumerate(rows)
                ],
                "artifacts": rows,
            }
        return {"id": 7, "relative_path": payload["path"], "present": True}

    def close(self) -> None:
        return None


@pytest.fixture()
def engagement(tmp_path: Path) -> Path:
    root = tmp_path / "engagements" / "acme"
    root.mkdir(parents=True)
    (root / "report.md").write_text("# Acme internal report\n", encoding="utf-8")
    (root / "notes.md").write_text("# Acme notes\n", encoding="utf-8")
    return root


def _run(
    monkeypatch, engagement: Path, client: _Client, *, paths: list[str], agent_id: str,
    kind: str = "report",
) -> None:
    monkeypatch.setattr(artifact, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(artifact, "load_config", lambda _dir: SimpleNamespace(
        base_url="http://backend.example", engagement_key="acme",
        engagement_dir=str(engagement),
    ))
    artifact._run_register(SimpleNamespace(
        engagement_dir=str(engagement), paths=paths, paths_file="", kind=kind,
        media_type="", agent_id=agent_id, agent_role="", command_run_id=None,
        finding="", as_json=True,
    ))


@pytest.mark.parametrize("paths", [["report.md"], ["report.md", "notes.md"]])
def test_an_agent_id_that_names_no_dispatch_is_refused_before_any_write(
    monkeypatch, engagement: Path, paths: list[str]
) -> None:
    client = _Client({"WRITE-REPORT"})
    with pytest.raises(AssessError) as refused:
        _run(monkeypatch, engagement, client, paths=paths, agent_id="WRITE-TYPO")
    assert client.posts == []
    assert "WRITE-TYPO" in str(refused.value) and "--agent-id" in str(refused.value)


@pytest.mark.parametrize("paths", [["report.md"], ["report.md", "notes.md"]])
def test_a_recorded_dispatch_is_stored_as_the_producer(
    monkeypatch, capsys, engagement: Path, paths: list[str]
) -> None:
    client = _Client({"WRITE-REPORT"})
    _run(monkeypatch, engagement, client, paths=paths, agent_id="WRITE-REPORT")
    capsys.readouterr()
    items = [
        payload for endpoint, payload in client.posts if endpoint == "artifacts"
    ] or client.posts[0][1]["items"]
    assert [item["producer_agent_id"] for item in items] == ["WRITE-REPORT"] * len(paths)


def test_an_unattributed_registration_needs_no_dispatch(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _Client(set())
    _run(monkeypatch, engagement, client, paths=["notes.md"], agent_id="", kind="notes")
    capsys.readouterr()
    assert client.gets == []
    assert client.posts[0][1]["producer_agent_id"] is None
