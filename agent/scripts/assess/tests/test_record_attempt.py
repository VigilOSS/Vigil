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
            "--input-slot", "query:url",
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


def test_record_attempt_rejects_covering_only_link_flags(tmp_path, monkeypatch, capsys):
    """FK-link flags (--coverage-item-id etc.) are covering-only (record-probe);
    record-attempt registers with include_links=False, so argparse rejects them."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(SystemExit):
        _parse(
            ["record-attempt", "--result-status", "blocked", "--attack-family", "ssrf", "--coverage-item-id", "77"],
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
            "--input-slot", "path",
            "--auth-context", "member",
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
        [
            "record-attempt", "--result-status", "error", "--attack-family", "sqli",
            "--target-host", "app.example.com", "--input-slot", "body:q", "--auth-context", "anonymous",
            "--finding", "12",
        ],
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
        [
            "record-attempt", "--result-status", "attempted", "--attack-family", "ssrf",
            "--target-host", "app.example.com", "--input-slot", "query:x", "--auth-context", "anonymous",
            "--finding", "NOPE-1",
        ],
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
        [
            "record-attempt", "--result-status", "attempted", "--attack-family", "not-a-real-class",
            "--target-host", "app.example.com", "--input-slot", "query:x", "--auth-context", "anonymous",
        ],
        str(tmp_path),
    )
    record_attempt.run(args)
    err = capsys.readouterr().err
    assert "WARN" in err and "not a known" in err
    # WARN-first: still recorded, stored verbatim (normalized casing).
    assert fake.posts[0][1]["attack_family"] == "not-a-real-class"


# -- WS3 required-input guards (run()-time, block-not-warn) --------------------

def _attempt_argv(**overrides) -> list[str]:
    """A record-attempt argv that PASSES every guard; overrides tweak one field."""
    base = {
        "--result-status": "blocked",
        "--attack-family": "ssrf",
        "--target-host": "api.example.com",
        "--input-slot": "query:url",
        "--auth-context": "anonymous",
    }
    base.update(overrides)
    argv = ["record-attempt"]
    for k, v in base.items():
        if v is not None:
            argv += [k, v]
    return argv


def test_record_attempt_rejects_missing_input_slot(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_attempt_argv(**{"--input-slot": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_attempt.run(args)
    err = capsys.readouterr().err
    assert "--input-slot is required" in err
    assert "See: vigil assess contract record-attempt" in err
    assert fake.posts == []


def test_record_attempt_rejects_missing_auth_context(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_attempt_argv(**{"--auth-context": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_attempt.run(args)
    assert "--auth-context is required" in capsys.readouterr().err
    assert fake.posts == []


def test_record_attempt_rejects_missing_target_host(tmp_path, monkeypatch, capsys):
    """record-attempt exposes no FK-link flags, so --target-host is unconditional.

    The rejection message must NOT dangle a --request-variant-id clause the verb
    cannot accept."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_attempt_argv(**{"--target-host": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_attempt.run(args)
    err = capsys.readouterr().err
    assert "--target-host is required" in err
    assert "--request-variant-id" not in err  # not offered by this verb
    assert fake.posts == []


def test_record_attempt_missing_required_flag_shows_pointer(tmp_path, monkeypatch, capsys):
    """A missing argparse-required flag (--attack-family) still surfaces the
    contract pointer on the ERROR path (not just on --help)."""
    with pytest.raises(SystemExit):
        _parse(
            ["record-attempt", "--result-status", "blocked", "--target-host", "h",
             "--input-slot", "query:x", "--auth-context", "anonymous"],
            str(tmp_path),
        )
    err = capsys.readouterr().err
    assert "See: vigil assess contract record-attempt" in err
