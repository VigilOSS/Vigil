"""CLI tests for `vigil assess record-attempt`.

The verb POSTs a NON-covering probe attempt to the shared ``probe-runs`` route.
Backend + runtime are stubbed (``load_config`` + a context-managed
``AssessmentClient``), matching the pattern the other assess CLI suites use.
These pin: the argparse non-covering choices, the payload round-trip (attack
family normalized, lens/target threaded), the --finding slug->id resolution and
its 404, and the WARN-first behavior on an out-of-vocab attack family.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import record_attempt


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self, findings: dict | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[str] = []
        self._findings = findings or {}

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": len(self.posts), **payload}

    def get(self, endpoint: str) -> dict:
        self.gets.append(endpoint)
        # endpoint is findings/<slug>
        slug = endpoint.split("/", 1)[1]
        if slug not in self._findings:
            from assess.lib.client import AssessError

            raise AssessError(f"HTTP 404: finding {slug} not found")
        return self._findings[slug]

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    record_attempt.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(record_attempt, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(record_attempt, "AssessmentClient", lambda *a, **k: fake)


def test_record_attempt_blocked_roundtrip(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-attempt",
            "--result-status", "blocked",
            "--attack-family", "SSRF",  # upper: normalized to ssrf
            "--lens", "tenant-boundary",
            "--target-host", "api.example.com",
            "--target-path", "/fetch",
            "--target-port", "443",
            "--auth-context", "member",
            "--notes", "WAF 403 on internal hosts",
        ],
        str(tmp_path),
    )
    record_attempt.run(args)
    capsys.readouterr()

    endpoint, payload = fake.posts[0]
    assert endpoint == "probe-runs"
    assert payload["result_status"] == "blocked"
    assert payload["attack_family"] == "ssrf"  # normalized
    assert payload["lens"] == "tenant-boundary"
    assert payload["target_host"] == "api.example.com"
    assert payload["target_path"] == "/fetch"
    assert payload["target_port"] == 443
    assert payload["auth_context"] == "member"
    assert payload["tool_name"] == "manual"  # helper default
    assert "finding_id" not in payload  # no --finding given


def test_record_attempt_rejects_covering_status(tmp_path, monkeypatch, capsys):
    """`tested`/`signal` (covering) are not accepted — argparse choices restrict
    the verb to the four non-covering statuses."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(SystemExit):
        _parse(
            ["record-attempt", "--result-status", "tested", "--attack-family", "ssrf"],
            str(tmp_path),
        )
    assert fake.posts == []


def test_record_attempt_resolves_finding_slug(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(findings={"VA-047": {"id": 91, "slug": "VA-047"}})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-attempt",
            "--result-status", "no-signal",
            "--attack-family", "idor",
            "--target-host", "app.example.com",
            "--finding", "VA-047",
        ],
        str(tmp_path),
    )
    record_attempt.run(args)
    capsys.readouterr()
    assert fake.gets == ["findings/VA-047"]
    assert fake.posts[0][1]["finding_id"] == 91


def test_record_attempt_finding_numeric_id_passthrough(tmp_path, monkeypatch, capsys):
    """A bare integer --finding is used directly without a slug lookup."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-attempt", "--result-status", "error", "--attack-family", "sqli", "--finding", "12"],
        str(tmp_path),
    )
    record_attempt.run(args)
    capsys.readouterr()
    assert fake.gets == []  # numeric id => no GET
    assert fake.posts[0][1]["finding_id"] == 12


def test_record_attempt_missing_finding_slug_errors(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(findings={})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-attempt", "--result-status", "attempted", "--attack-family", "ssrf", "--finding", "NOPE-1"],
        str(tmp_path),
    )
    from assess.lib.client import AssessError

    with pytest.raises(AssessError):
        record_attempt.run(args)
    assert fake.posts == []  # never records the attempt when the link cannot resolve


def test_record_attempt_unknown_family_warns_but_records(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-attempt", "--result-status", "attempted", "--attack-family", "not-a-real-class"],
        str(tmp_path),
    )
    record_attempt.run(args)
    err = capsys.readouterr().err
    assert "WARN" in err and "not a known" in err
    # WARN-first: still recorded, stored verbatim (normalized casing).
    assert fake.posts[0][1]["attack_family"] == "not-a-real-class"
