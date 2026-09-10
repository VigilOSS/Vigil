"""CLI tests for `vigil assess resolve` (the merged surface/coverage-item verb).

resolve absorbed resolve-surface + resolve-coverage-item into one verb with a
target-kind positional (``surface`` | ``coverage-item``). Backend + runtime are
stubbed. These pin: the target-kind routing to the right PATCH endpoint + payload
shape, each kind keeping its OWN status vocabulary (surface hyphenated, coverage-
item hyphen->underscore), the non-empty-rationale guard, the surface-only
--followup-condition rule, and the rejection of surface-only flags on a
coverage-item.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import resolve


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self) -> None:
        self.patches: list[tuple[str, dict]] = []

    def patch(self, endpoint: str, payload: dict) -> dict:
        self.patches.append((endpoint, payload))
        return {"id": int(endpoint.rsplit("/", 1)[-1]), "status": payload.get("status")}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    resolve.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(resolve, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(resolve, "AssessmentClient", lambda *a, **k: fake)


# -- surface -------------------------------------------------------------------


def test_resolve_surface_covered_roundtrip(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "surface", "42", "--status", "covered", "--rationale", "analyst confirmed"],
        str(tmp_path),
    )
    resolve.run(args)
    capsys.readouterr()
    endpoint, payload = fake.patches[0]
    assert endpoint == "surfaces/42"
    assert payload == {"status": "covered", "rationale": "analyst confirmed"}


def test_resolve_rejects_response_for_a_different_row(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    fake.patch = lambda _endpoint, payload: {"id": 999, "status": payload["status"]}
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "surface", "42", "--status", "covered", "--rationale", "confirmed"],
        str(tmp_path),
    )

    with pytest.raises(SystemExit) as exc:
        resolve.run(args)

    assert exc.value.code == 1
    assert "do not retry automatically" in capsys.readouterr().err


def test_resolve_surface_partially_covered_requires_followup(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "surface", "31", "--status", "partially-covered", "--rationale", "unauth tested"],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        resolve.run(args)
    assert fake.patches == []


def test_resolve_surface_partially_covered_with_followup(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "surface", "31", "--status", "partially-covered",
         "--rationale", "unauth tested", "--followup-condition", "needs auth re-test"],
        str(tmp_path),
    )
    resolve.run(args)
    capsys.readouterr()
    payload = fake.patches[0][1]
    assert payload["status"] == "partially-covered"
    assert payload["followup_condition"] == "needs auth re-test"


def test_resolve_surface_extra_flags_thread(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "surface", "5", "--status", "covered", "--rationale", "r",
         "--source-name", "analyst", "--evidence-ref", "scans/x.txt"],
        str(tmp_path),
    )
    resolve.run(args)
    capsys.readouterr()
    payload = fake.patches[0][1]
    assert payload["source_name"] == "analyst"
    assert payload["evidence_ref"] == "scans/x.txt"


def test_resolve_surface_rejects_seed_status(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["resolve", "surface", "5", "--status", "discovered", "--rationale", "r"], str(tmp_path))
    with pytest.raises(SystemExit):
        resolve.run(args)
    err = capsys.readouterr().err
    assert "invalid status" in err
    assert "See: vigil assess contract resolve" in err
    assert fake.patches == []


# -- coverage-item -------------------------------------------------------------


def test_resolve_coverage_item_covered_roundtrip(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "coverage-item", "77", "--status", "covered",
         "--rationale", "idor tested; user_b got 403"],
        str(tmp_path),
    )
    resolve.run(args)
    capsys.readouterr()
    endpoint, payload = fake.patches[0]
    assert endpoint == "coverage-items/77"
    # coverage-item rationale is appended to notes (not rationale).
    assert payload == {"status": "covered", "notes": "idor tested; user_b got 403"}


def test_resolve_coverage_item_status_normalization(tmp_path, monkeypatch, capsys):
    """Coverage-item statuses fold hyphen->underscore: 'NOT-APPLICABLE' -> 'not_applicable'."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "coverage-item", "5", "--status", "NOT-APPLICABLE", "--rationale", "static asset"],
        str(tmp_path),
    )
    resolve.run(args)
    capsys.readouterr()
    assert fake.patches[0][1]["status"] == "not_applicable"


def test_resolve_coverage_item_rejects_unknown_status(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["resolve", "coverage-item", "5", "--status", "bogus", "--rationale", "x"], str(tmp_path))
    with pytest.raises(SystemExit):
        resolve.run(args)
    err = capsys.readouterr().err
    assert "invalid status" in err
    assert "See: vigil assess contract resolve" in err
    assert fake.patches == []


def test_resolve_coverage_item_rejects_surface_only_flag(tmp_path, monkeypatch, capsys):
    """--followup-condition / --source-name / --evidence-ref are surface-only."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve", "coverage-item", "5", "--status", "covered", "--rationale", "r",
         "--followup-condition", "nope"],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        resolve.run(args)
    assert "only valid for `resolve surface`" in capsys.readouterr().err
    assert fake.patches == []


# -- shared: rationale + target-kind ------------------------------------------


@pytest.mark.parametrize("target_kind,status", [("surface", "deferred"), ("coverage-item", "deferred")])
def test_resolve_blank_rationale_errors(tmp_path, monkeypatch, capsys, target_kind, status):
    """--rationale is required for EVERY status/target-kind — a whitespace rationale
    is rejected before any PATCH."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["resolve", target_kind, "5", "--status", status, "--rationale", "   "], str(tmp_path))
    with pytest.raises(SystemExit):
        resolve.run(args)
    assert fake.patches == []


def test_resolve_rejects_unknown_target_kind(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _parse(["resolve", "bogus-kind", "5", "--status", "covered", "--rationale", "r"], str(tmp_path))


def test_resolve_missing_required_flag_shows_pointer(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit):
        _parse(["resolve", "surface", "5"], str(tmp_path))  # no --status/--rationale
    assert "See: vigil assess contract resolve" in capsys.readouterr().err
