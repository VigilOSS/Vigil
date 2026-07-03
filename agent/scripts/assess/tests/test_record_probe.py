"""CLI tests for `vigil assess record-probe`.

The covering counterpart to record-attempt: it POSTs a COVERING probe run
(tested|signal) to the shared ``probe-runs`` route and REQUIRES ``--evidence-ref``.
Backend + runtime are stubbed, matching the record-attempt suite. These pin: the
argparse covering-only choices, the mandatory-evidence guard, the FK-link
threading (request_variant_id/service_id/coverage_item_id), the named input-slot
round-trip, and the shared --finding slug->id resolution.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import record_probe


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
    record_probe.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(record_probe, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(record_probe, "AssessmentClient", lambda *a, **k: fake)


def test_record_probe_covering_roundtrip_with_links(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe",
            "--result-status", "tested",
            "--attack-family", "IDOR",  # normalized to idor
            "--target-host", "app.example.com",
            "--target-path", "/orders/1001",
            "--input-slot", "path:id",  # named input preserved
            "--auth-context", "member",
            "--evidence-ref", "scans/idor-orders.txt",
            "--request-variant-id", "42",
            "--service-id", "7",
            "--coverage-item-id", "77",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()

    endpoint, payload = fake.posts[0]
    assert endpoint == "probe-runs"
    assert payload["result_status"] == "tested"
    assert payload["attack_family"] == "idor"
    assert payload["input_slot"] == "path:id"  # named slot round-trips
    assert payload["evidence_ref"] == "scans/idor-orders.txt"
    assert payload["request_variant_id"] == 42
    assert payload["service_id"] == 7
    assert payload["coverage_item_id"] == 77


def test_record_probe_requires_evidence(tmp_path, monkeypatch, capsys):
    """A covering verdict with no --evidence-ref is not coverage — hard error, no post."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-probe", "--result-status", "tested", "--attack-family", "ssrf", "--target-host", "h"],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "--evidence-ref is required" in err
    assert fake.posts == []


def test_record_probe_rejects_noncovering_status(tmp_path, monkeypatch, capsys):
    """attempted/blocked/no-signal/error belong to record-attempt — argparse rejects them here."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(SystemExit):
        _parse(
            ["record-probe", "--result-status", "blocked", "--attack-family", "ssrf", "--evidence-ref", "x"],
            str(tmp_path),
        )
    assert fake.posts == []


def test_record_probe_resolves_finding_slug(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(findings={"VA-047": {"id": 91, "slug": "VA-047"}})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe",
            "--result-status", "signal",
            "--attack-family", "ssrf",
            "--target-host", "api.example.com",
            "--evidence-ref", "scans/ssrf.txt",
            "--finding", "VA-047",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    assert fake.gets == ["findings/VA-047"]
    assert fake.posts[0][1]["finding_id"] == 91


def test_record_probe_unknown_family_warns_but_records(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-probe", "--result-status", "tested", "--attack-family", "not-a-real-class", "--evidence-ref", "e"],
        str(tmp_path),
    )
    record_probe.run(args)
    err = capsys.readouterr().err
    assert "WARN" in err and "not a known" in err
    assert fake.posts[0][1]["attack_family"] == "not-a-real-class"
