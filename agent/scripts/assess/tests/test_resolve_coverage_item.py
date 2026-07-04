"""CLI tests for `vigil assess resolve-coverage-item`.

The verb PATCHes a coverage item by id (status + rationale->notes) via the
``coverage-items/{id}`` route. Backend + runtime are stubbed. These pin: the
PATCH endpoint + payload shape, status normalization (case + hyphen), and the
non-empty-rationale guard. The COVERAGE_STATUSES list is asserted to match the
backend CoverageStatus vocabulary so the CLI mirror cannot silently drift.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import resolve_coverage_item


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
        return {"id": 77, "status": payload.get("status"), "notes": payload.get("notes")}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    resolve_coverage_item.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(resolve_coverage_item, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(resolve_coverage_item, "AssessmentClient", lambda *a, **k: fake)


def test_resolve_coverage_item_covered_roundtrip(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve-coverage-item", "77", "--status", "covered", "--rationale", "idor tested; user_b got 403"],
        str(tmp_path),
    )
    resolve_coverage_item.run(args)
    capsys.readouterr()
    endpoint, payload = fake.patches[0]
    assert endpoint == "coverage-items/77"
    assert payload == {"status": "covered", "notes": "idor tested; user_b got 403"}


def test_resolve_coverage_item_status_normalization(tmp_path, monkeypatch, capsys):
    """Case-insensitive and hyphen->underscore: 'NOT-APPLICABLE' -> 'not_applicable'."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve-coverage-item", "5", "--status", "NOT-APPLICABLE", "--rationale", "static asset"],
        str(tmp_path),
    )
    resolve_coverage_item.run(args)
    capsys.readouterr()
    assert fake.patches[0][1]["status"] == "not_applicable"


@pytest.mark.parametrize("status", ["covered", "deferred"])
def test_resolve_coverage_item_blank_rationale_errors(tmp_path, monkeypatch, capsys, status):
    """--rationale is required for EVERY status (audit trail), not just the
    resolved-positive ones — a whitespace rationale is rejected for `deferred` too."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["resolve-coverage-item", "5", "--status", status, "--rationale", "   "],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        resolve_coverage_item.run(args)
    assert fake.patches == []


def test_resolve_coverage_item_rejects_unknown_status(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(SystemExit):
        _parse(
            ["resolve-coverage-item", "5", "--status", "bogus", "--rationale", "x"],
            str(tmp_path),
        )
    assert fake.patches == []

    # NOTE: the CLI-mirror-vs-backend-enum drift guard lives in the backend
    # suite (orchestrator/backend/tests/test_coverage_probe_cli_sync.py), where
    # both `app.*` and `assess.*` import — this suite runs in the repo-root venv
    # which has no backend `app` module.
