"""`vigil assess finding merge` must relay the backend's merge warnings.

A merge that inherits a contradictory CVSS pair from one of its two inputs
COMPLETES — refusing would strand two duplicates the agent correctly identified,
and the pair was never authored by the merging caller. The backend reports the
defect on the response instead of blocking. That report is only useful if the
caller sees it: the primary caller here is an LLM agent reading this CLI's
streams, so a warning that reaches only the API and the websocket is a warning
the agent learns about much later, from a blocked report-readiness check.
"""
from __future__ import annotations

import argparse

from assess.commands import merge_finding


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self, response: dict) -> None:
        self._response = response
        self.posts: list[tuple[str, dict]] = []
        self.events: list[dict] = []

    def post(self, path: str, payload: dict) -> dict:
        self.posts.append((path, payload))
        return self._response

    def post_event(self, payload: dict) -> dict:
        self.events.append(payload)
        return {}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _run(monkeypatch, tmp_path, response: dict) -> _FakeClient:
    fake = _FakeClient(response)
    monkeypatch.setattr(merge_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(merge_finding, "AssessmentClient", lambda *a, **k: fake)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    merge_finding.register(sub)
    args = parser.parse_args(["merge", "VA-002", "VA-001", "same root cause"])
    args.engagement_dir = str(tmp_path)
    merge_finding.run(args)
    return fake


def test_merge_relays_a_backend_warning_to_stderr(tmp_path, monkeypatch, capsys):
    warning = (
        "merge completed, but VA-001 carries a contradictory CVSS pair inherited "
        "from one of the two findings: details.cvss_score=2.0 disagrees with "
        "details.cvss_vector. Repair it with `vigil assess finding update VA-001 "
        "--details-inline '{\"cvss_score\": <n>, \"cvss_vector\": \"<v>\"}'`"
    )
    fake = _run(monkeypatch, tmp_path, {"slug": "VA-001", "warnings": [warning]})

    captured = capsys.readouterr()
    # The merge still LANDED — the warning never costs the consolidation.
    assert fake.posts and fake.posts[0][0] == "findings/merge"
    assert "Merged VA-002 into VA-001" in captured.out
    # ...and the defect is on the caller's stderr, naming the repair verb.
    assert warning in captured.err
    assert "finding update VA-001" in captured.err


def test_a_clean_merge_says_nothing_extra(tmp_path, monkeypatch, capsys):
    """The relay must not add noise to the overwhelmingly common clean merge."""
    _run(monkeypatch, tmp_path, {"slug": "VA-001", "warnings": []})

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Merged VA-002 into VA-001" in captured.out


def test_a_response_without_the_key_is_not_an_error(tmp_path, monkeypatch, capsys):
    """An older backend (no `warnings` key) must not break the CLI."""
    _run(monkeypatch, tmp_path, {"slug": "VA-001"})

    assert capsys.readouterr().err == ""
