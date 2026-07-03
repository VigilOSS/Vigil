"""CLI tests for `vigil assess auth list` (WS3) + `auth-status --probe --identity`
per-session verdict persistence (WS4).

Backend + runtime are stubbed the same way the other assess CLI suites do
(``load_config`` + a fake non-context-managed client closed in a ``finally``; see
test_http_cmd.py). These pin: the list view renders EVERY stored identity with
metadata, the host/include-dead filters map to the exact backend query params,
raw cookie VALUES never leak into the list view (names only), and a
``--probe --identity`` run persists the classified verdict (while an
active-identity probe stays read-only).
"""
from __future__ import annotations

import argparse
import json
from urllib.parse import parse_qs, urlparse

from assess.commands import auth_cmd, auth_status


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records get_engagement calls and serves a canned identities listing."""

    def __init__(self, *, listing=None) -> None:
        self.gets: list[str] = []
        self._listing = listing if listing is not None else {"identities": {}, "active_identity": ""}
        self.closed = False

    def get_engagement(self, endpoint: str):
        self.gets.append(endpoint)
        return self._listing

    def close(self) -> None:
        self.closed = True


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    auth_cmd.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(auth_cmd, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(auth_cmd, "AssessmentClient", lambda *a, **k: fake)


def _query_of(endpoint: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(endpoint).query)


_LISTING = {
    "active_identity": "cap-aaaa",
    "identities": {
        "cap-aaaa": {
            "identity_name": "cap-aaaa",
            "auth_context": "user_a",
            "state": "available",
            "liveness_verdict": "live",
            "last_seen_at": "2026-07-03T11:00:00Z",
            "last_probed_at": "2026-07-03T11:30:00Z",
            "is_active": True,
            "cookies": {"MRHSession": "SECRET-VALUE-AAA"},
            "host_cookies": [
                {"host": "portal.example.com", "cookies": {"MRHSession": "SECRET-VALUE-AAA"}},
            ],
        },
        "cap-bbbb": {
            "identity_name": "cap-bbbb",
            "auth_context": "user_b",
            "state": "stale",
            "liveness_verdict": "unknown",
            "last_seen_at": "2026-07-01T00:00:00Z",
            "last_probed_at": None,
            "is_active": False,
            "cookies": {"MRHSession": "SECRET-VALUE-BBB", "csrf": "x"},
            "host_cookies": [
                {"host": "portal.example.com", "cookies": {"MRHSession": "SECRET-VALUE-BBB", "csrf": "x"}},
            ],
        },
    },
}


def test_list_renders_every_identity_with_metadata(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    # Both identities listed with their metadata columns.
    assert "cap-aaaa*" in out  # active identity flagged
    assert "cap-bbbb" in out
    assert "user_a" in out and "user_b" in out
    assert "available" in out and "stale" in out
    assert "live" in out and "unknown" in out
    # cookie NAMES surface; hosts surface.
    assert "MRHSession" in out
    assert "portal.example.com" in out
    # No filters -> bare endpoint.
    assert fake.gets == ["credentials"]
    assert fake.closed is True


def test_list_does_not_leak_raw_cookie_values(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    assert "SECRET-VALUE-AAA" not in out
    assert "SECRET-VALUE-BBB" not in out


def test_list_host_filter_maps_to_query_param(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--host", "portal.example.com"], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    assert len(fake.gets) == 1
    endpoint = fake.gets[0]
    assert endpoint.startswith("credentials?")
    assert _query_of(endpoint)["host"] == ["portal.example.com"]
    assert "include_dead" not in _query_of(endpoint)


def test_list_include_dead_maps_to_query_param(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--include-dead"], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    assert _query_of(fake.gets[0])["include_dead"] == ["true"]


def test_list_json_emits_raw_listing(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--json"], str(tmp_path))
    args.func(args)
    parsed = json.loads(capsys.readouterr().out)
    assert set(parsed["identities"]) == {"cap-aaaa", "cap-bbbb"}


def test_list_empty_store_renders_placeholder(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing={"identities": {}, "active_identity": ""})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    assert "no identities stored" in capsys.readouterr().out


def test_humanize_age_buckets():
    assert auth_cmd._humanize_age(None) == "-"
    assert auth_cmd._humanize_age("not-a-date") == "-"
    # A far-past timestamp reads in days.
    assert auth_cmd._humanize_age("2000-01-01T00:00:00Z").endswith("d")


# --------------------------------------------------------------------------- #
# auth-status --probe --identity: per-session verdict persistence (WS4)
# --------------------------------------------------------------------------- #

class _StatusCfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _status_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    auth_status.register(sub)
    return parser


def _parse_status(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _status_parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install_status(monkeypatch, tmp_path, *, verdict, material=None):
    """Stub the status command's collaborators so run() is network-free."""
    monkeypatch.setattr(auth_status, "load_config", lambda *a, **k: _StatusCfg(str(tmp_path)))
    monkeypatch.setattr(auth_status, "_last_auth_probe", lambda *_a, **_k: None)
    monkeypatch.setattr(auth_status, "AssessmentClient", lambda *a, **k: None)
    resolved_material = material if material is not None else {
        "identity_name": "cap-target",
        "auth_context": "user_b",
        "liveness": {"authed_marker": "Sign out"},
        "cookies": {"S": "1"},
    }
    calls: dict[str, object] = {}

    def fake_resolve(_dir, requested):
        calls["resolved"] = requested
        return (requested, dict(resolved_material))

    def fake_active(_dir):
        calls["active_used"] = True
        return dict(resolved_material)

    def fake_probe(_dir, identity, url, *, liveness_cfg, timeout=15):
        calls["probed_identity"] = identity
        return {"liveness": verdict, "reason": "stubbed", "http_status": 200, "error": None}

    def fake_persist(_dir, identity, v, probed_at):
        calls.setdefault("persisted", []).append((identity, v, probed_at))
        return {"identity_name": identity, "liveness_verdict": v}

    monkeypatch.setattr(auth_status, "resolve_identity", fake_resolve)
    monkeypatch.setattr(auth_status, "active_material", fake_active)
    monkeypatch.setattr(auth_status, "_run_identity_probe", fake_probe)
    monkeypatch.setattr(auth_status, "persist_liveness", fake_persist)
    return calls


def test_probe_identity_persists_live_verdict(tmp_path, monkeypatch, capsys):
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["auth-status", "--json", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    out = json.loads(capsys.readouterr().out)
    assert calls["resolved"] == "cap-target"      # targeted the requested identity
    assert calls["probed_identity"] == "cap-target"
    assert calls["persisted"][0][0] == "cap-target"
    assert calls["persisted"][0][1] == "live"     # verdict persisted
    assert out["liveness"] == "live"
    assert out["liveness_probe"]["persisted"] is True


def test_probe_identity_persists_dead_verdict(tmp_path, monkeypatch, capsys):
    calls = _install_status(monkeypatch, tmp_path, verdict="dead")
    args = _parse_status(
        ["auth-status", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert calls["persisted"][0][1] == "dead"


def test_probe_no_signature_persists_unknown_not_dead(tmp_path, monkeypatch, capsys):
    # A no-signature / transport-error verdict is `unknown`: it IS persisted
    # (records last_probed_at) but the backend leaves state untouched — nothing is
    # persisted as dead. Assert the verdict sent is `unknown`, never `dead`.
    calls = _install_status(monkeypatch, tmp_path, verdict="unknown")
    args = _parse_status(
        ["auth-status", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert calls["persisted"][0][1] == "unknown"
    assert calls["persisted"][0][1] != "dead"


def test_active_identity_probe_does_not_persist(tmp_path, monkeypatch, capsys):
    # No --identity: the active-identity probe stays READ-ONLY (no persistence).
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["auth-status", "--probe", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert "persisted" not in calls          # never wrote a verdict
    assert calls.get("active_used") is True  # used the active identity


def test_probe_missing_identity_reports_and_does_not_persist(tmp_path, monkeypatch, capsys):
    # A requested identity that resolves to empty material must not probe/persist.
    calls = _install_status(monkeypatch, tmp_path, verdict="live", material={})
    args = _parse_status(
        ["auth-status", "--json", "--probe", "--identity", "ghost", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    out = json.loads(capsys.readouterr().out)
    assert "persisted" not in calls
    assert out["liveness"] == "unknown"
    assert "ghost" in out["liveness_probe"]["error"]
