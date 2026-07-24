from __future__ import annotations

from types import SimpleNamespace

import pytest

from assess.commands.dispatch import handoff_renderer


class _FakeClient:
    handoff: dict[str, object]
    dispatch: dict[str, object] | None
    fetched: list[str]

    def __init__(self, _base_url: str, _engagement_key: str) -> None:
        self.fetched = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def get_handoff(self, _agent_id: str) -> dict[str, object]:
        return self.handoff

    def get_dispatch(self, _agent_id: str) -> dict[str, object] | None:
        return self.dispatch

    def get(self, endpoint: str) -> object:
        self.fetched.append(endpoint)
        slug = endpoint.removeprefix("findings/")
        return {"slug": slug, "title": f"Finding {slug}", "severity": "medium"}

    def get_engagement(self, endpoint: str) -> object:
        assert endpoint == "credentials"
        return []


def _run_renderer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    *,
    dispatch_slugs: object,
    handoff_slugs: object,
) -> _FakeClient:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    _FakeClient.handoff = {
        "agent_id": "agent-1",
        "agent_role": "recon-specialist",
        "summary": "Completed the assigned surface pass.",
        "finding_slugs": handoff_slugs,
        "next_steps": [],
        "coverage_gaps": [],
        "working_artifacts": [],
        "runtime_issues": [],
        "open_questions": [],
    }
    _FakeClient.dispatch = {
        "agent_id": "agent-1",
        "agent_role": "recon-specialist",
        "task": "Map the target surface",
        "status": "completed",
        "finding_slugs": dispatch_slugs,
    }
    client = _FakeClient("", "")
    monkeypatch.setattr(handoff_renderer, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(
        handoff_renderer,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="engagement",
            engagement_dir=str(engagement_dir),
        ),
    )
    handoff_renderer._render_handoff(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            max_lines=40,
            include_evidence=False,
        ),
        ["agent-1"],
    )
    return client


def test_render_handoff_separates_slug_sources_and_enriches_stable_union(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = _run_renderer(
        monkeypatch,
        tmp_path,
        dispatch_slugs=["D-001", "SHARED"],
        handoff_slugs=["SHARED", "H-001"],
    )

    output = capsys.readouterr().out
    assert "**Finding declarations:**" in output
    assert "**Findings recorded:**" not in output
    assert "**Dispatch-declared findings:** `D-001`, `SHARED`" in output
    assert "**Handoff-declared findings:** `SHARED`, `H-001`" in output
    assert client.fetched == [
        "findings/D-001",
        "findings/SHARED",
        "findings/H-001",
    ]
    assert output.index("`D-001` ") < output.index("`SHARED` ") < output.index("`H-001` ")


def test_render_handoff_does_not_claim_no_findings_when_neither_source_declares_slugs(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = _run_renderer(
        monkeypatch,
        tmp_path,
        dispatch_slugs=None,
        handoff_slugs=[],
    )

    output = capsys.readouterr().out
    assert "**Dispatch-declared findings:** (none declared)" in output
    assert "**Handoff-declared findings:** (none declared)" in output
    assert "(none declared in handoff or dispatch)" in output
    assert "no findings" not in output.lower()
    assert client.fetched == []
