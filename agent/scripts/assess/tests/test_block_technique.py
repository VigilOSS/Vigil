"""CLI tests for `vigil assess block-technique` / `list-blocked-techniques`.

Backend + runtime are stubbed (``load_config`` + a context-managed
``AssessmentClient``) matching the pattern used by the other assess CLI suites.
These pin: the argparse retry_state default is "pending" (LOW-12), the payload
round-trips through a fake POST/GET, technique_key is derived when omitted, and
an out-of-enum --technique fails closed.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import block_technique


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records POSTs and serves them back on GET as the backend upsert would."""

    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._rows_by_key: dict[str, dict] = {}
        self._next_id = 0

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        assert endpoint == "blocked-techniques"
        key = payload["technique_key"]
        if key in self._rows_by_key:
            row = self._rows_by_key[key]
            row.update(payload)
        else:
            self._next_id += 1
            row = {"id": self._next_id, **payload}
            self._rows_by_key[key] = row
        return dict(row)

    def get(self, endpoint: str):
        assert endpoint == "blocked-techniques"
        return list(self._rows_by_key.values())

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    block_technique.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(block_technique, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(block_technique, "AssessmentClient", lambda *a, **k: fake)


def test_block_technique_roundtrip_default_retry_state_pending(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)

    # No --retry-state and no --technique-key: exercise the argparse default and
    # the derived key.
    args = _parse(
        [
            "block-technique",
            "--technique", "ssrf",  # lower-case: normalized to SSRF
            "--target-kind", "host",
            "--target-ref", "api.example.com",
            "--reason", "egress firewalled",
        ],
        str(tmp_path),
    )
    assert args.retry_state == "pending"  # argparse default (LOW-12)
    block_technique.run_block(args)
    capsys.readouterr()

    endpoint, payload = fake.posts[0]
    assert endpoint == "blocked-techniques"
    assert payload["technique"] == "SSRF"  # normalized
    assert payload["retry_state"] == "pending"
    # derived '<technique>:<target_kind>:<target_ref>', slugged
    assert payload["technique_key"] == "ssrf:host:api-example-com"

    # list-blocked-techniques renders the stored row.
    list_args = _parse(["list-blocked-techniques"], str(tmp_path))
    block_technique.run_list(list_args)
    out = capsys.readouterr().out
    assert "SSRF" in out
    assert "[pending]" in out
    assert "ssrf:host:api-example-com" in out


def test_block_technique_upsert_updates_same_key(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)

    for retry in ("pending", "no_retry"):
        args = _parse(
            [
                "block-technique",
                "--technique", "SSRF",
                "--target-kind", "host",
                "--target-ref", "api.example.com",
                "--reason", "wall",
                "--retry-state", retry,
            ],
            str(tmp_path),
        )
        block_technique.run_block(args)
    capsys.readouterr()

    rows = fake.get("blocked-techniques")
    assert len(rows) == 1  # upsert on the derived technique_key, not duplicated
    assert rows[0]["retry_state"] == "no_retry"


def test_block_technique_rejects_out_of_enum_technique(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "block-technique",
            "--technique", "NOT-A-REAL-CLASS",
            "--target-kind", "host",
            "--target-ref", "api.example.com",
            "--reason", "wall",
        ],
        str(tmp_path),
    )
    with pytest.raises(SystemExit) as exc:
        block_technique.run_block(args)
    assert exc.value.code == 1
    assert fake.posts == []  # never hit the backend
    assert "not a valid technique" in capsys.readouterr().err


def test_block_technique_doctrine_points_at_finding_side_unblock():
    """The doctrine fix: a blocked technique has no slug, so the unblock is
    recorded on the FINDING side (link-finding <finding> --link-kind unblocks
    --target-kind blocked_technique), never with the technique as the subject."""
    doc = block_technique.__doc__ or ""
    assert "blocked_technique" in doc
    assert "--link-kind unblocks" in doc
    assert "no slug" in doc.lower()
    # The old broken form (technique as the link subject) is gone.
    assert "<blocked-slug>" not in doc


def test_block_technique_notes_help_points_at_unblock_requirements():
    """--notes is a short cue; the durable home for unblock requirements is the
    finding's details.unblock_requirements."""
    parser = _parser()
    sub_action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    block_parser = sub_action.choices["block-technique"]
    notes_help = next(
        (a.help or "") for a in block_parser._actions if "--notes" in a.option_strings
    )
    assert "details.unblock_requirements" in notes_help


def test_list_blocked_techniques_json_and_empty(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)

    empty = _parse(["list-blocked-techniques"], str(tmp_path))
    block_technique.run_list(empty)
    assert "none" in capsys.readouterr().out

    args = _parse(
        [
            "block-technique",
            "--technique", "IDOR",
            "--target-kind", "finding",
            "--target-ref", "VA-047",
            "--reason", "needs a second account",
        ],
        str(tmp_path),
    )
    block_technique.run_block(args)
    capsys.readouterr()

    json_args = _parse(["list-blocked-techniques", "--json"], str(tmp_path))
    block_technique.run_list(json_args)
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["technique"] == "IDOR"
    assert rows[0]["technique_key"] == "idor:finding:va-047"
