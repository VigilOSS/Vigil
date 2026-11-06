"""A committed lease is recorded locally before anything is allowed to fail.

`code-dispatch fetch` and `adopt-lease` are the two verbs whose backend call
MINTS a capability: the lease token comes back in the response and exists
nowhere else. Everything between that response and the audit snapshot is a
window in which the token can be lost while the backend keeps the lease:

* a closed stdout/stderr consumer — `2>&1 | head` on a diagnostic-heavy
  command — makes the first diagnostic write raise `BrokenPipeError`, which
  unwinds the command before the snapshot;
* a malformed claim identity and an unsafe scratch path both print and exit
  before the snapshot.

The window is widest on a PARTIAL claim, where leases were granted and the
per-id report fires. These tests pin the ordering invariant: the snapshot
holding the lease tokens is durable before any diagnostic, any filesystem
preparation and any refusal.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


class _ClosedConsumer:
    """A pipe whose reader is gone: every write raises, as `head` does."""

    def __init__(self) -> None:
        self.attempts = 0

    def write(self, _text: str) -> int:
        self.attempts += 1
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False


def _claim_item(item_id: int, *, file_path: str) -> dict[str, object]:
    return {
        "id": item_id,
        "queue_item_id": item_id,
        "file_id": item_id + 100,
        "assigned_agent": "HUNT-1",
        "lease_token": f"f0c7a1d2-0000-4000-8000-{item_id:012d}",
        "applicable_vuln_classes": ["ssrf"],
        "file": {"file_path": file_path},
    }


class _PartialClaimClient:
    """Grants two of the three requested ids, so the per-id report fires."""

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, endpoint: str, _payload: dict):
        assert endpoint == "code/analysis-queue/fetch"
        return [
            _claim_item(41, file_path="src/parser.py"),
            _claim_item(42, file_path="src/helpers.py"),
        ]

    def get(self, _endpoint: str):
        return {
            "total": 1,
            "offset": 0,
            "count": 1,
            "has_more": False,
            "item_ids": [43],
            "items": [
                {
                    "id": 43,
                    "file_path": "src/other.py",
                    "status": "processing",
                    "agent_name": "HUNT-9",
                    "heartbeat_age_seconds": 30,
                }
            ],
        }


def _fetch_snapshots(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "tools" / "analysis-state").glob("*code-queue-fetch*.json"))


def test_a_partial_claim_is_durable_before_the_per_id_report(
    monkeypatch, tmp_path
) -> None:
    """The reported failure: `2>&1 | head` on a partial claim.

    The claim POST has committed, the first stderr write raises, and the
    command unwinds. The two granted lease tokens must already be on disk.
    """
    closed = _ClosedConsumer()
    monkeypatch.setattr(sys, "stderr", closed)
    monkeypatch.setattr(sys, "stdout", closed)
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PartialClaimClient)

    with pytest.raises(BrokenPipeError):
        code_dispatch._fetch(
            _config(tmp_path), 3, "HUNT-1", {"item_ids": [41, 42, 43]}
        )

    snapshots = _fetch_snapshots(tmp_path)
    assert len(snapshots) == 1, "the committed claim left no durable record"
    recorded = json.loads(snapshots[0].read_text(encoding="utf-8"))
    assert {entry["lease_token"] for entry in recorded} == {
        "f0c7a1d2-0000-4000-8000-000000000041",
        "f0c7a1d2-0000-4000-8000-000000000042",
    }
    assert {entry["id"] for entry in recorded} == {41, 42}
    # The scratch directory each lease owns is part of the handed-out claim, so
    # it belongs in the record the operator recovers from.
    assert all(isinstance(entry.get("scratch_dir"), str) for entry in recorded)


def test_the_scratch_directories_exist_before_the_per_id_report(
    monkeypatch, tmp_path
) -> None:
    """A closed consumer must not leave the lane without its working dirs."""
    closed = _ClosedConsumer()
    monkeypatch.setattr(sys, "stderr", closed)
    monkeypatch.setattr(sys, "stdout", closed)
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PartialClaimClient)

    with pytest.raises(BrokenPipeError):
        code_dispatch._fetch(
            _config(tmp_path), 3, "HUNT-1", {"item_ids": [41, 42, 43]}
        )

    recorded = json.loads(_fetch_snapshots(tmp_path)[0].read_text(encoding="utf-8"))
    for entry in recorded:
        assert (tmp_path / str(entry["scratch_dir"])).is_dir()


def test_a_malformed_claim_identity_is_refused_after_the_claim_is_recorded(
    monkeypatch, tmp_path, capsys
) -> None:
    """The backend already leased these rows, so the refusal cannot be the
    reason the operator never learns the tokens."""

    class _MalformedClient(_PartialClaimClient):
        def post(self, _endpoint: str, _payload: dict):
            return [
                _claim_item(41, file_path="src/parser.py"),
                {"id": 0, "lease_token": "", "file_id": 1},
            ]

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _MalformedClient)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._fetch(_config(tmp_path), 2, "HUNT-1", None)

    assert exc.value.code == 1
    assert "Invalid code-analysis claim identity" in capsys.readouterr().err
    recorded = json.loads(_fetch_snapshots(tmp_path)[0].read_text(encoding="utf-8"))
    assert any(
        entry.get("lease_token") == "f0c7a1d2-0000-4000-8000-000000000041"
        for entry in recorded
    )


def test_a_full_claim_still_records_and_prints_normally(monkeypatch, tmp_path, capsys):
    """The reordering must not change what a successful claim publishes."""

    class _FullClaimClient(_PartialClaimClient):
        def post(self, _endpoint: str, _payload: dict):
            return [_claim_item(41, file_path="src/parser.py")]

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FullClaimClient)

    code_dispatch._fetch(_config(tmp_path), 1, "HUNT-1", {"item_ids": [41]})

    captured = capsys.readouterr()
    printed = json.loads(captured.out)
    assert printed[0]["agent_name"] == "HUNT-1"
    assert printed[0]["lease_token"] == "f0c7a1d2-0000-4000-8000-000000000041"
    assert "scratch_dir" in printed[0]
    assert "Saved audit snapshot:" in captured.err
    recorded = json.loads(_fetch_snapshots(tmp_path)[0].read_text(encoding="utf-8"))
    assert recorded == printed


# ─────────────────────────────────────────────────────────────────────────────
# adopt-lease mints a lease token too, and its refusals precede its snapshot
# ─────────────────────────────────────────────────────────────────────────────

def _adopt_snapshots(tmp_path: Path) -> list[Path]:
    return sorted(
        (tmp_path / "tools" / "analysis-state").glob("*code-queue-adopt-lease*.json")
    )


def _adopt_response(**overrides) -> dict[str, object]:
    response: dict[str, object] = {
        "item_id": 41,
        "previous_agent_name": "HUNT-0",
        "previous_lease_token": "dead-lease-0000",
        "previous_lease_activity_at": "2026-11-07T09:00:00Z",
        "preserved_result_count": 3,
        "item": _claim_item(41, file_path="src/parser.py"),
    }
    response.update(overrides)
    return response


def test_an_adopted_lease_is_durable_before_its_diagnostics(monkeypatch, tmp_path):
    """Adoption is the lease-recovery verb, so losing ITS token is the worst
    place for this failure."""
    closed = _ClosedConsumer()
    monkeypatch.setattr(sys, "stderr", closed)
    monkeypatch.setattr(sys, "stdout", closed)

    class _AdoptClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, _payload: dict):
            assert endpoint == "code/analysis-queue/adopt-lease"
            return _adopt_response()

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _AdoptClient)

    with pytest.raises(BrokenPipeError):
        code_dispatch._adopt_lease(
            _config(tmp_path), "41", "HUNT-1", {"reason": "dead lane"}
        )

    recorded = json.loads(_adopt_snapshots(tmp_path)[0].read_text(encoding="utf-8"))
    assert recorded["item"]["lease_token"] == "f0c7a1d2-0000-4000-8000-000000000041"
    assert isinstance(recorded["item"].get("scratch_dir"), str)
    assert isinstance(recorded.get("previous_scratch_dir"), str)
    assert (tmp_path / str(recorded["item"]["scratch_dir"])).is_dir()


def test_a_malformed_adoption_response_is_recorded_before_it_is_refused(
    monkeypatch, tmp_path, capsys
):
    """The swap committed backend-side; whatever the backend said about it is
    the only evidence of the new token, so it is recorded before the refusal."""

    class _MalformedAdoptClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict):
            return {"item_id": 41, "lease_token": "f0c7a1d2-stranded"}

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _MalformedAdoptClient)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._adopt_lease(
            _config(tmp_path), "41", "HUNT-1", {"reason": "dead lane"}
        )

    assert exc.value.code == 1
    assert "lease adoption response" in capsys.readouterr().err
    recorded = json.loads(_adopt_snapshots(tmp_path)[0].read_text(encoding="utf-8"))
    assert recorded == {"item_id": 41, "lease_token": "f0c7a1d2-stranded"}


# ─────────────────────────────────────────────────────────────────────────────
# retry-needs-context commits new current attempts and must record them too
# ─────────────────────────────────────────────────────────────────────────────

class _RetryClient:
    endpoint: str = ""
    posted: dict = {}

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, endpoint: str, payload: dict):
        type(self).endpoint = endpoint
        type(self).posted = payload
        return {"retried": 2, "item_ids": [41, 42]}


def _retry_snapshots(tmp_path: Path, category: str) -> list[Path]:
    return sorted(
        (tmp_path / "tools" / "analysis-state").glob(f"*{category}*.json")
    )


def test_retry_needs_context_records_the_attempts_it_created(
    monkeypatch, tmp_path, capsys
) -> None:
    """The sibling of `retry-error`, with the same durable record.

    Both verbs return terminal rows to unleased `pending` as new current
    attempts. `retry-error` recorded that; `retry-needs-context` printed it and
    kept nothing, so an operator reconstructing a wave had a hole exactly where
    one verb's writes went.
    """
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _RetryClient)

    code_dispatch._retry_needs_context(
        _config(tmp_path), "41,42", "expansion supplied"
    )

    assert _RetryClient.endpoint == "code/analysis-queue/retry-needs-context"
    snapshots = _retry_snapshots(tmp_path, "code-queue-retry-needs-context")
    assert len(snapshots) == 1
    assert json.loads(snapshots[0].read_text(encoding="utf-8")) == {
        "retried": 2,
        "item_ids": [41, 42],
    }
    out = capsys.readouterr().out
    assert "Retried (needs_context -> pending): 2 item(s)" in out
    assert "Saved audit snapshot:" in out


def test_both_retry_verbs_record_the_same_metadata_shape(
    monkeypatch, tmp_path
) -> None:
    """The asymmetry this closes is the shape, not just the presence."""
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _RetryClient)

    code_dispatch._retry_error(_config(tmp_path), "41,42", "transient failure")
    code_dispatch._retry_needs_context(
        _config(tmp_path), "41,42", "expansion supplied"
    )

    manifest = json.loads(
        (tmp_path / "tools" / "analysis-state" / "artifact-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    by_kind = {
        entry["kind"]: entry
        for entry in manifest["entries"]
        if str(entry["kind"]).startswith("code-queue-retry-")
    }
    assert set(by_kind) == {
        "code-queue-retry-error",
        "code-queue-retry-needs-context",
    }
    for kind, command in (
        ("code-queue-retry-error", "code-dispatch retry-error"),
        ("code-queue-retry-needs-context", "code-dispatch retry-needs-context"),
    ):
        metadata = by_kind[kind]["metadata"]
        assert metadata["command"] == command
        assert metadata["item_ids"] == [41, 42]
        assert isinstance(metadata["reason"], str) and metadata["reason"]
