"""CLI tests for the generalized `vigil assess link-finding` generic-link mode.

Covers the P1-C addition: a generic typed link (POST /findings/{slug}/links)
via --link-kind / --target-kind / --target-id / --target-ref, in addition to
the existing root-cause and intel modes. The unblock path (--link-kind
unblocked_by) is the first-class use. Backend + runtime are stubbed.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import link_finding


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": len(self.posts), **payload}

    def put(self, endpoint: str, payload: dict) -> dict:
        self.puts.append((endpoint, payload))
        return {"endpoint": endpoint, **payload}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    link_finding.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(link_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(link_finding, "AssessmentClient", lambda *a, **k: fake)


def test_generic_unblocked_by_posts_to_links(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "link-finding", "VA-070",
            "--link-kind", "unblocked_by",
            "--target-kind", "finding",
            "--target-ref", "VA-071",
            "--note", "VA-071 yields the admin session",
        ],
        str(tmp_path),
    )
    link_finding.run(args)
    capsys.readouterr()

    assert fake.puts == []  # generic mode does NOT touch the root-cause PUT route
    endpoint, payload = fake.posts[0]
    assert endpoint == "findings/VA-070/links"
    assert payload["link_kind"] == "unblocked_by"
    assert payload["target_kind"] == "finding"
    assert payload["target_ref"] == "VA-071"
    assert payload["target_id"] is None
    assert payload["notes"] == "VA-071 yields the admin session"


def test_generic_unblocks_blocked_technique_posts_to_links(tmp_path, monkeypatch, capsys):
    """The finding-side unblock of a blocked TECHNIQUE: the unblocking finding is
    the link subject, target_kind=blocked_technique, target_ref=<technique_key>.
    target_kind is free text end-to-end, so blocked_technique needs no backend
    change and the technique_key is passed verbatim (never resolved as a slug)."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "link-finding", "VA-071",
            "--link-kind", "unblocks",
            "--target-kind", "blocked_technique",
            "--target-ref", "bfla:host:api-example-com",
            "--note", "org-admin account provisioned; role-grant endpoint now reachable",
        ],
        str(tmp_path),
    )
    link_finding.run(args)
    capsys.readouterr()

    assert fake.puts == []
    endpoint, payload = fake.posts[0]
    assert endpoint == "findings/VA-071/links"
    assert payload["link_kind"] == "unblocks"
    assert payload["target_kind"] == "blocked_technique"
    assert payload["target_ref"] == "bfla:host:api-example-com"
    assert payload["target_id"] is None


def test_generic_link_by_target_id(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["link-finding", "VA-070", "--link-kind", "related", "--target-kind", "chain", "--target-id", "12"],
        str(tmp_path),
    )
    link_finding.run(args)
    capsys.readouterr()
    endpoint, payload = fake.posts[0]
    assert endpoint == "findings/VA-070/links"
    assert payload["target_kind"] == "chain"
    assert payload["target_id"] == 12
    assert payload["target_ref"] == ""


def test_generic_link_defaults_kind_related_when_only_target_given(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["link-finding", "VA-070", "--target-kind", "finding", "--target-ref", "VA-071"],
        str(tmp_path),
    )
    link_finding.run(args)
    capsys.readouterr()
    assert fake.posts[0][1]["link_kind"] == "related"


def test_generic_link_requires_target_id_or_ref(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["link-finding", "VA-070", "--link-kind", "unblocked_by", "--target-kind", "finding"], str(tmp_path))
    with pytest.raises(SystemExit) as exc:
        link_finding.run(args)
    assert exc.value.code == 1
    assert fake.posts == []
    assert "--target-id" in capsys.readouterr().err


def test_generic_link_rejects_root_cause_kind(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["link-finding", "VA-070", "--link-kind", "root_cause", "--target-kind", "finding", "--target-ref", "VA-071"],
        str(tmp_path),
    )
    with pytest.raises(SystemExit) as exc:
        link_finding.run(args)
    assert exc.value.code == 1
    assert fake.posts == []
    assert "--root-cause" in capsys.readouterr().err


def test_generic_link_conflicts_with_root_cause_mode(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["link-finding", "VA-070", "--root-cause", "VA-001", "--target-kind", "finding", "--target-ref", "VA-071"],
        str(tmp_path),
    )
    with pytest.raises(SystemExit) as exc:
        link_finding.run(args)
    assert exc.value.code == 1
    assert fake.posts == [] and fake.puts == []


def test_root_cause_mode_still_uses_put(tmp_path, monkeypatch, capsys):
    """Regression: the existing root-cause mode must keep hitting the PUT route
    and never the generic /links route."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["link-finding", "VA-070", "--root-cause", "VA-001", "--effect", "eliminates_finding"], str(tmp_path))
    link_finding.run(args)
    capsys.readouterr()
    assert fake.posts == []
    endpoint, payload = fake.puts[0]
    assert endpoint == "findings/VA-070/root-cause"
    assert payload["root_cause_slug"] == "VA-001"
