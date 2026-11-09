"""A root-cause grouping pass costs no claim review unless it is asked for.

``eliminates_finding`` claims the root fix RETIRES the sibling, which is a claim
change: the backend raises a claim review on a confirmed or downgraded sibling
and report readiness blocks on `finding_claim_review_pending`. A pure grouping
pass makes no such claim, so the cheap effect is the default and the expensive
one is explicit.
"""
from __future__ import annotations

import argparse

import pytest
from _fake_client import StubClient

from assess.commands import link_finding


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient(StubClient):
    def __init__(self) -> None:
        self.puts: list[tuple[str, dict]] = []

    def put(self, endpoint: str, payload: dict) -> dict:
        self.puts.append((endpoint, payload))
        return {
            "id": 1,
            "finding_slug": endpoint.split("/")[1],
            "root_cause_slug": payload["root_cause_slug"],
        }

def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    link_finding.register(parser.add_subparsers())
    args = parser.parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _run(tmp_path, monkeypatch, argv: list[str]) -> _FakeClient:
    fake = _FakeClient()
    monkeypatch.setattr(link_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(link_finding, "AssessmentClient", lambda *a, **k: fake)
    link_finding.run(_parse(argv, str(tmp_path)))
    return fake


def test_root_cause_grouping_defaults_to_the_verdict_preserving_effect(
    tmp_path, monkeypatch, capsys
) -> None:
    fake = _run(
        tmp_path, monkeypatch,
        ["link", "VA-070", "--root-cause", "VA-001", "--reason", "same missing control"],
    )
    capsys.readouterr()

    assert fake.puts[0][1]["root_cause_effect"] == "eliminates_attack_path"


def test_the_retiring_effect_must_be_asked_for(tmp_path, monkeypatch, capsys) -> None:
    fake = _run(
        tmp_path, monkeypatch,
        ["link", "VA-070", "--root-cause", "VA-001", "--reason", "the root fix retires it",
         "--effect", "eliminates_finding"],
    )
    capsys.readouterr()

    assert fake.puts[0][1]["root_cause_effect"] == "eliminates_finding"


def test_the_effect_vocabulary_is_closed(tmp_path) -> None:
    with pytest.raises(SystemExit):
        _parse(
            ["link", "VA-070", "--root-cause", "VA-001", "--effect", "eliminates_everything"],
            str(tmp_path),
        )
