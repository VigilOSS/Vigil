"""Report and submission renders are attributed to their writer without the flag.

Report and submission QC refuse a reviewer that registered the bytes it reviews
(ADR 0045), so each registration of ``report.md`` or a submission workspace names
the dispatch that wrote it. A specialist's shell carries no dispatch identity, so
when ``--agent-id`` is omitted the backend's in-progress report-writer dispatches
decide: the one in scope is the writer, several are refused as ambiguous, and none
means the operator rendered.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from assess.commands import artifact
from assess.lib.client import AssessError
from assess.lib.producer_identity import resolve_report_writer


class _Client:
    """Serves `dispatches` (in-progress report-writer rows) and `dispatches/<id>`."""

    def __init__(self, in_progress: list[dict], recorded: set[str] = frozenset()) -> None:
        self.in_progress = in_progress
        self.recorded = set(recorded) | {row["agent_id"] for row in in_progress}
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        parts = urlsplit(endpoint)
        if parts.path == "dispatches":
            query = parse_qs(parts.query)
            assert query["role"] == ["report-writer"]
            assert query["status"] == ["in_progress"]
            return list(self.in_progress)
        agent_id = parts.path.removeprefix("dispatches/")
        if agent_id not in self.recorded:
            raise AssessError(f"HTTP 404: dispatch {agent_id} not found")
        return {"agent_id": agent_id, "agent_role": "report-writer"}

    def post(self, endpoint: str, payload: dict, **_kwargs) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": 7, "relative_path": payload["path"], "present": True}

    def close(self) -> None:
        return None


def _writer(agent_id: str, *slugs: str) -> dict:
    return {"agent_id": agent_id, "agent_role": "report-writer",
            "finding_slugs": list(slugs) or None}


def test_the_explicit_flag_is_verified_and_wins(capsys) -> None:
    client = _Client([_writer("WRITE-A")], recorded={"WRITE-B"})

    assert resolve_report_writer(client, "WRITE-B", operation="export submission") == "WRITE-B"
    assert client.gets == ["dispatches/WRITE-B"]
    with pytest.raises(AssessError, match="WRITE-TYPO"):
        resolve_report_writer(client, "WRITE-TYPO", operation="export submission")


def test_the_one_in_progress_writer_is_the_producer_and_is_named(capsys) -> None:
    client = _Client([_writer("WRITE-A")])

    assert resolve_report_writer(client, "", operation="register artifact") == "WRITE-A"
    err = capsys.readouterr().err
    assert "WRITE-A" in err and "--agent-id" in err


def test_a_submission_is_attributed_to_the_writer_scoped_to_its_finding(capsys) -> None:
    client = _Client([_writer("WRITE-A", "VA-001"), _writer("WRITE-B", "VA-002")])

    assert resolve_report_writer(
        client, "", operation="export submission", finding_slug="VA-002"
    ) == "WRITE-B"


def test_an_unscoped_writer_covers_a_finding_no_dispatch_names(capsys) -> None:
    client = _Client([_writer("WRITE-A", "VA-001"), _writer("WRITE-ALL")])

    assert resolve_report_writer(
        client, "", operation="export submission", finding_slug="VA-009"
    ) == "WRITE-ALL"


@pytest.mark.parametrize(("rows", "slug"), [
    ([_writer("WRITE-A"), _writer("WRITE-B")], None),
    ([_writer("WRITE-A", "VA-001"), _writer("WRITE-B", "VA-001")], "VA-001"),
])
def test_several_candidate_writers_are_refused_naming_each_and_the_fix(rows, slug) -> None:
    client = _Client(rows)

    with pytest.raises(AssessError) as refused:
        resolve_report_writer(client, "", operation="export submission", finding_slug=slug)
    message = str(refused.value)
    assert "WRITE-A" in message and "WRITE-B" in message
    assert "--agent-id" in message and "Runtime Identity" in message


def test_no_in_progress_writer_is_the_operator_s_render(capsys) -> None:
    client = _Client([_writer("WRITE-A", "VA-001")])

    assert resolve_report_writer(
        client, "", operation="export submission", finding_slug="VA-002"
    ) is None
    assert "operator" in capsys.readouterr().err


# -- artifact register -------------------------------------------------------

@pytest.fixture()
def engagement(tmp_path: Path) -> Path:
    root = tmp_path / "engagements" / "acme"
    root.mkdir(parents=True)
    (root / "report.md").write_text("# Acme internal report\n", encoding="utf-8")
    (root / "notes.md").write_text("# Acme notes\n", encoding="utf-8")
    return root


def _register(monkeypatch, engagement: Path, client: _Client, *, kind: str, path: str) -> None:
    monkeypatch.setattr(artifact, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(artifact, "load_config", lambda _dir: SimpleNamespace(
        base_url="http://backend.example", engagement_key="acme",
        engagement_dir=str(engagement),
    ))
    artifact._run_register(SimpleNamespace(
        engagement_dir=str(engagement), paths=[path], paths_file="", kind=kind,
        media_type="", agent_id="", agent_role="", command_run_id=None,
        finding="", as_json=True,
    ))


def test_report_registration_without_the_flag_names_the_in_progress_writer(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _Client([_writer("WRITE-REPORT")])

    _register(monkeypatch, engagement, client, kind="report", path="report.md")

    capsys.readouterr()
    assert client.posts[0][1]["producer_agent_id"] == "WRITE-REPORT"


def test_report_registration_with_no_writer_says_qc_needs_one(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _Client([])

    _register(monkeypatch, engagement, client, kind="report", path="report.md")

    assert client.posts[0][1]["producer_agent_id"] is None
    assert "report QC" in capsys.readouterr().err


def test_other_kinds_resolve_no_writer(monkeypatch, capsys, engagement: Path) -> None:
    client = _Client([_writer("WRITE-REPORT")])

    _register(monkeypatch, engagement, client, kind="notes", path="notes.md")

    capsys.readouterr()
    assert client.gets == []
    assert client.posts[0][1]["producer_agent_id"] is None


def test_the_writer_lookup_sends_only_keys_the_dispatch_list_declares() -> None:
    """Every backend GET refuses an undeclared query key."""
    from test_fetch_route_catalog import _backend_assessment_get_routes

    client = _Client([])
    resolve_report_writer(client, "", operation="export submission")
    [endpoint] = client.gets
    parts = urlsplit(endpoint)
    declared = _backend_assessment_get_routes()[parts.path]
    query = parse_qs(parts.query)
    assert set(query) <= set(declared)
    assert int(query["limit"][0]) <= declared["limit"]["maximum"]
