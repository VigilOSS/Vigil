"""CLI tests for batch support + the verify/kill/update payload-via-flag migration.

The canonical batch convention (Part 2): the entity slug/id positional is
``nargs="+"`` and shared disposition flags apply to every listed entity via a
resilient loop with a per-entity failure tally. verify/kill/update additionally
migrated the trailing positional payload arg to ``--inline`` / ``--payload-file``
(a JSON blob passed positionally is now rejected with a pointer to the flags).

Backend + runtime are stubbed; these pin the loop fan-out, the partial-failure
tally + non-zero exit, single-slug backward-compat output, and the payload-flag
migration for verify/kill/update.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import (
    link_finding,
    resolve,
    update_finding,
    verify_finding,
)


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records post/patch/put/delete calls; ``fail_on`` forces a per-call error."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []
        self.deletes: list[str] = []
        self._fail_on = fail_on or set()

    def _maybe_fail(self, endpoint: str) -> None:
        if any(token in endpoint for token in self._fail_on):
            raise RuntimeError(f"boom on {endpoint}")

    def post(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.posts.append((endpoint, payload))
        return {"endpoint": endpoint, "ok": True}

    def patch(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.patches.append((endpoint, payload))
        return {"endpoint": endpoint, "id": len(self.patches), **payload}

    def put(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.puts.append((endpoint, payload))
        return {"endpoint": endpoint, **payload}

    def delete(self, endpoint: str) -> dict:
        self._maybe_fail(endpoint)
        self.deletes.append(endpoint)
        return {"endpoint": endpoint, "deleted": True}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _install(monkeypatch, module, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(module, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)


def _parse(module, argv, tmp_path) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    module.register(sub)
    args = parser.parse_args(argv)
    args.engagement_dir = str(tmp_path)
    return args


# ──────────────────────────────────────────────────────────────────────────
# Batch fan-out + partial-failure tally + single-slug backward-compat
# ──────────────────────────────────────────────────────────────────────────


def test_verify_batch_applies_same_payload_to_each(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        ["verify", "VA-1", "VA-2", "VA-3", "--disposition", "confirmed", "--reason", "reproduced"],
        tmp_path,
    )
    verify_finding.run(args)
    err = capsys.readouterr().err
    assert [ep for ep, _ in fake.posts] == [
        "findings/VA-1/verify",
        "findings/VA-2/verify",
        "findings/VA-3/verify",
    ]
    # Same payload object applied to each.
    assert all(p["disposition"] == "confirmed" and p["reason_text"] == "reproduced" for _, p in fake.posts)
    assert "verified 3 finding(s); 0 failed" in err


def test_verify_partial_failure_tally_and_nonzero_exit(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(fail_on={"VA-2"})
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        ["verify", "VA-1", "VA-2", "--disposition", "confirmed", "--reason", "r"],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "VA-2 failed" in err
    assert "verified 1 finding(s); 1 failed" in err
    # The healthy slug still went through.
    assert [ep for ep, _ in fake.posts] == ["findings/VA-1/verify"]


def test_verify_single_slug_prints_single_json(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        ["verify", "VA-1", "--disposition", "confirmed", "--reason", "r"],
        tmp_path,
    )
    verify_finding.run(args)
    out = capsys.readouterr().out
    # Single-slug backward compat: one pretty-printed JSON object on stdout.
    parsed = json.loads(out)
    assert parsed["endpoint"] == "findings/VA-1/verify"


def test_verify_false_positive_batch(tmp_path, monkeypatch, capsys):
    # kill-finding folded into `verify-finding --disposition false_positive`
    # (2026-07 CLI consolidation): the FP kill fields ride the verify verb.
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "VA-2",
            "--disposition", "false_positive",
            "--reason", "r", "--kill-reason", "kr", "--kill-check", "2",
        ],
        tmp_path,
    )
    verify_finding.run(args)
    assert [ep for ep, _ in fake.posts] == ["findings/VA-1/verify", "findings/VA-2/verify"]
    assert all(
        p["disposition"] == "false_positive"
        and p["details"]["kill_reason"] == "kr"
        and p["details"]["kill_check"] == 2
        for _, p in fake.posts
    )
    assert "verified 2 finding(s); 0 failed" in capsys.readouterr().err


def test_update_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "VA-2", "--status", "reported", "--reason", "published"],
        tmp_path,
    )
    update_finding.run(args)
    assert [ep for ep, _ in fake.patches] == ["findings/VA-1", "findings/VA-2"]
    assert "updated 2 finding(s); 0 failed" in capsys.readouterr().err


def test_reopen_draft_batch(tmp_path, monkeypatch, capsys):
    # reset-finding folded into `update-finding --status draft` (2026-07 CLI
    # consolidation): reopening for re-triage is a workflow_status patch.
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "VA-2", "--status", "draft", "--reason", "retest"],
        tmp_path,
    )
    update_finding.run(args)
    assert [ep for ep, _ in fake.patches] == ["findings/VA-1", "findings/VA-2"]
    assert all(p["workflow_status"] == "draft" for _, p in fake.patches)
    assert "updated 2 finding(s); 0 failed" in capsys.readouterr().err


def test_resolve_surface_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, resolve, tmp_path, fake)
    args = _parse(
        resolve,
        ["resolve", "surface", "42", "99", "17", "--status", "covered", "--rationale", "same verdict"],
        tmp_path,
    )
    resolve.run(args)
    assert [ep for ep, _ in fake.patches] == ["surfaces/42", "surfaces/99", "surfaces/17"]
    assert "resolved 3 surface(s); 0 failed" in capsys.readouterr().err


def test_resolve_coverage_item_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, resolve, tmp_path, fake)
    args = _parse(
        resolve,
        ["resolve", "coverage-item", "77", "88", "--status", "covered", "--rationale", "tested both"],
        tmp_path,
    )
    resolve.run(args)
    assert [ep for ep, _ in fake.patches] == ["coverage-items/77", "coverage-items/88"]
    assert "resolved 2 item(s); 0 failed" in capsys.readouterr().err


def test_link_finding_batch_many_siblings_one_root(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, link_finding, tmp_path, fake)
    args = _parse(
        link_finding,
        ["link", "VA-2", "VA-3", "VA-4", "--root-cause", "VA-1"],
        tmp_path,
    )
    link_finding.run(args)
    assert [ep for ep, _ in fake.puts] == [
        "findings/VA-2/root-cause",
        "findings/VA-3/root-cause",
        "findings/VA-4/root-cause",
    ]
    assert all(p["root_cause_slug"] == "VA-1" for _, p in fake.puts)
    assert "linked 3 finding(s); 0 failed" in capsys.readouterr().err


# ──────────────────────────────────────────────────────────────────────────
# verify/kill/update payload-via-flag migration (--inline / --payload-file)
# ──────────────────────────────────────────────────────────────────────────


def test_verify_payload_file_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text(json.dumps({"disposition": "confirmed", "reason_text": "from file"}), encoding="utf-8")
    args = _parse(verify_finding, ["verify", "VA-1", "--payload-file", str(payload_path)], tmp_path)
    verify_finding.run(args)
    _, payload = fake.posts[0]
    assert payload["disposition"] == "confirmed" and payload["reason_text"] == "from file"


def test_verify_inline_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        ["verify", "VA-1", "--inline", '{"disposition":"confirmed","reason_text":"inline"}'],
        tmp_path,
    )
    verify_finding.run(args)
    assert fake.posts[0][1]["reason_text"] == "inline"


def test_verify_rejects_positional_json_blob(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(verify_finding, ["verify", "VA-1", '{"disposition":"confirmed"}'], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    assert "looks like a JSON payload" in capsys.readouterr().err
    assert fake.posts == []


def test_verify_rejects_positional_json_file(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text("{}", encoding="utf-8")
    args = _parse(verify_finding, ["verify", "VA-1", str(payload_path)], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    assert "positional payload arg" in capsys.readouterr().err
    assert fake.posts == []


def test_verify_disposition_as_slug_hint(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(verify_finding, ["verify", "confirmed"], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "looks like a disposition" in err and "--disposition confirmed" in err


def test_verify_false_positive_payload_file_flag(tmp_path, monkeypatch, capsys):
    # kill-finding's payload-file flow is now verify-finding's (folded verb).
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "kill.json"
    payload_path.write_text(
        json.dumps(
            {
                "disposition": "false_positive",
                "reason_text": "guarded",
                "details": {"kill_reason": "validate_length caps input", "kill_check": 2},
            }
        ),
        encoding="utf-8",
    )
    args = _parse(verify_finding, ["verify", "VA-1", "--payload-file", str(payload_path)], tmp_path)
    verify_finding.run(args)
    assert fake.posts[0][0] == "findings/VA-1/verify"
    assert fake.posts[0][1]["details"]["kill_reason"] == "validate_length caps input"


def test_update_inline_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "--inline", '{"workflow_status":"draft","reason_text":"needs evidence"}'],
        tmp_path,
    )
    update_finding.run(args)
    assert fake.patches[0][0] == "findings/VA-1"
    assert fake.patches[0][1]["workflow_status"] == "draft"


def test_update_rejects_positional_json_file(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(update_finding, ["update", "VA-1", "patch.json", "--status", "reported"], tmp_path)
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    assert "looks like a JSON payload" in capsys.readouterr().err
    assert fake.patches == []
