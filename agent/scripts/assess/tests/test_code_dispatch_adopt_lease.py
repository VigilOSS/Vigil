"""B9: the operator surface for an orphaned analysis lease.

`list` has to show how stale each lease is and how much durable work it holds,
`adopt-lease` has to pin the exact lease being replaced, and `progress` has to
say what a claimed item still owes before closeout. Without those three an
abandoned dispatch is only recoverable by discarding what it already wrote.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch
from assess.lib import contracts


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


_STALE_PAGE = {
    "total": 1,
    "offset": 0,
    "count": 1,
    "has_more": False,
    "item_ids": [41],
    "items": [
        {
            "id": 41,
            "file_id": 7,
            "file_path": "src/parser.py",
            "classification": "critical",
            "repo_id": 1,
            "status": "processing",
            "queue_mode": "initial",
            "priority": 100,
            "batch_theme": "parser-core",
            "agent_name": "hunter-a",
            "lease_token": "lease-a",
            "last_heartbeat_at": "2026-09-16T08:00:00Z",
            "lease_activity_at": "2026-09-16T08:00:00Z",
            "heartbeat_age_seconds": 5400,
            "current_result_count": 3,
            "adopted_leases": [],
        }
    ],
}

_ADOPTED = {
    "item_id": 41,
    "stale_minutes": 30,
    "reason": "hunter-a died mid-file",
    "previous_agent_name": "hunter-a",
    "previous_lease_token": "lease-a",
    "previous_lease_activity_at": "2026-09-16T08:00:00Z",
    "previous_lease_age_seconds": 5400,
    "preserved_result_count": 3,
    "adopted_leases": [{"agent_name": "hunter-a", "lease_token": "lease-a"}],
    "item": {
        "id": 41,
        "file_id": 7,
        "agent_name": "hunter-b",
        "lease_token": "lease-b",
        "status": "processing",
        "repo_generation": 2,
        "file": {"file_path": "src/parser.py"},
    },
}

_PROGRESS = {
    "item_id": 41,
    "file_id": 7,
    "file_path": "src/parser.py",
    "classification": "critical",
    "status": "processing",
    "queue_mode": "initial",
    "disposition": "",
    "agent_name": "hunter-b",
    "lease_token": "lease-b",
    "repo_generation": 2,
    "consumed_at": "2026-09-16T07:00:00Z",
    "last_heartbeat_at": "2026-09-16T08:00:00Z",
    "lease_activity_at": "2026-09-16T08:00:00Z",
    "heartbeat_age_seconds": 5400,
    "adopted_leases": [{"agent_name": "hunter-a", "lease_token": "lease-a"}],
    "applicable_vuln_classes": ["ssrf", "path-traversal"],
    "recorded_cwe_families": ["ssrf"],
    "missing_cwe_families": ["path-traversal"],
    "receipts": [
        {
            "id": 9,
            "agent_name": "hunter-a",
            "lease_token": "lease-a",
            "disposition": "clean",
            "receipt_kind": "call_chain",
            "receipt_binding_status": "structural",
            "evidence_present": True,
            "callable_count": 2,
            "reviewed_span_count": 0,
            "cwe_families": ["ssrf"],
            "finding_slug": "",
            "created_at": "2026-09-16T07:30:00Z",
        }
    ],
    "receipt_count": 1,
    "coverage_integrity": {"current_receipt_rows": 1, "plausible": True},
}


class _FakeClient:
    requested: list[str] = []
    posted: list[tuple[str, dict]] = []
    get_payload: object = _STALE_PAGE
    post_payload: object = _ADOPTED

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).requested.append(endpoint)
        return type(self).get_payload

    def post(self, endpoint: str, payload: dict):
        type(self).posted.append((endpoint, payload))
        return type(self).post_payload


@pytest.fixture
def fake_client(monkeypatch, tmp_path):
    _FakeClient.requested = []
    _FakeClient.posted = []
    _FakeClient.get_payload = _STALE_PAGE
    _FakeClient.post_payload = _ADOPTED
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FakeClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)
    return _FakeClient


def test_adopt_lease_and_progress_are_registered_actions() -> None:
    assert "adopt-lease" in code_dispatch._ACTION_HELP
    assert "progress" in code_dispatch._ACTION_HELP


def test_list_sends_stale_minutes_and_renders_lease_age(fake_client, tmp_path, capsys):
    filters, output = code_dispatch._parse_list_filters(
        ["--status", "processing", "--stale-minutes", "30"]
    )
    code_dispatch._list(_config(tmp_path), filters, output)

    assert fake_client.requested == [
        "code/analysis-queue?status=processing&stale_minutes=30"
    ]
    out = capsys.readouterr().out
    # 5400s renders as a readable age, and the receipt count is what decides
    # between adopting the row and discarding it.
    assert "1h30m" in out
    assert "hunter-a" in out
    assert "3" in out


def test_list_rejects_a_non_positive_stale_window(capsys):
    assert code_dispatch._parse_list_filters(["--stale-minutes", "30"]) == (
        {"stale_minutes": "30"},
        "table",
    )
    with pytest.raises(SystemExit) as exc:
        code_dispatch._parse_list_filters(["--stale-minutes", "0"])
    assert exc.value.code == 1
    assert capsys.readouterr().err


def test_adopt_lease_posts_the_exact_observed_identity(fake_client, tmp_path, capsys):
    code_dispatch._adopt_lease(
        _config(tmp_path),
        "41",
        "hunter-b",
        code_dispatch._parse_adopt_lease_options(
            [
                "--from-agent", "hunter-a",
                "--from-lease", "lease-a",
                "--stale-minutes", "30",
                "--reason", "hunter-a died mid-file",
            ]
        ),
    )

    endpoint, payload = fake_client.posted[0]
    assert endpoint == "code/analysis-queue/adopt-lease"
    assert payload == {
        "item_id": 41,
        "agent_name": "hunter-b",
        "expected_agent": "hunter-a",
        "expected_lease_token": "lease-a",
        "stale_minutes": 30,
        "reason": "hunter-a died mid-file",
    }
    captured = capsys.readouterr()
    # The claim record is the stdout contract, exactly as `fetch` returns one;
    # the human summary is a diagnostic.
    adopted = json.loads(captured.out)
    assert adopted["item"]["lease_token"] == "lease-b"
    assert adopted["previous_scratch_dir"].endswith("lease-cfdd1a8f80ac95cc")
    assert "preserved 3" in captured.err
    assert "lease-b" in captured.err


def test_adopt_lease_defaults_the_window_and_requires_the_swap_identity(capsys):
    options = code_dispatch._parse_adopt_lease_options(
        ["--from-agent", "hunter-a", "--from-lease", "lease-a", "--reason", "dead"]
    )
    assert options["stale_minutes"] == 10

    for tokens in (
        ["--from-lease", "lease-a", "--reason", "dead"],
        ["--from-agent", "hunter-a", "--reason", "dead"],
        ["--from-agent", "hunter-a", "--from-lease", "lease-a"],
        ["--from-agent", "hunter-a", "--from-lease", "lease-a", "--reason", " "],
        ["--from-agent", "hunter-a", "--from-lease", "lease-a", "--reason", "d",
         "--stale-minutes", "0"],
    ):
        with pytest.raises(SystemExit) as exc:
            code_dispatch._parse_adopt_lease_options(tokens)
        assert exc.value.code == 1
    assert capsys.readouterr().err


def test_progress_reports_what_the_claimed_item_still_owes(
    fake_client, tmp_path, capsys
):
    fake_client.get_payload = _PROGRESS
    code_dispatch._progress(_config(tmp_path), "41", as_json=False)

    assert fake_client.requested == ["code/analysis-queue/41/progress"]
    out = capsys.readouterr().out
    assert "src/parser.py" in out
    assert "path-traversal" in out
    assert "hunter-a" in out


def test_progress_json_is_the_raw_backend_payload(fake_client, tmp_path, capsys):
    fake_client.get_payload = _PROGRESS
    code_dispatch._progress(_config(tmp_path), "41", as_json=True)

    assert json.loads(capsys.readouterr().out) == _PROGRESS


def test_the_contract_documents_the_recovery_verbs() -> None:
    """Prompts point at the contract surface rather than restating it, so an
    undocumented verb is an undiscoverable one."""
    contract = contracts.get_contract("code-dispatch")
    rendered = " ".join(contract.preferred_invocations) + " ".join(contract.notes)
    assert "adopt-lease" in rendered
    assert "progress" in rendered
    assert "--stale-minutes" in rendered
    assert contracts.get_contract("code-dispatch adopt-lease") is contract
