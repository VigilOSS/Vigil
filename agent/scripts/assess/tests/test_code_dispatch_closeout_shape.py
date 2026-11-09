"""`code-dispatch` answers a closeout question before it costs a round trip.

Three costs a real hunt wave paid:

* `done` takes `notes` as a trailing positional and never checked it, so
  omitting it on `disposition=clean` spent a coverage-file parse and a POST
  before the backend said `notes are required when disposition='clean'`. The
  same was true of `--skip-reason` on `disposition=skipped`.
* `progress` printed only the families still owed relative to recorded
  receipts, never the full required set `done` enforces — so the authoritative
  list was reachable only through `--json`.
* the `list` table dropped `lease_token`, the one row value a lane needs to
  resume work after a context boundary, with nothing naming where to read it.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch
from _fake_client import StubClient


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


class _ForbiddenClient:
    def __init__(self, *_args, **_kwargs) -> None:
        raise AssertionError("an invocation-shape refusal must precede the client")


def _unparsable_coverage(tmp_path: Path) -> Path:
    """A coverage file that fails to parse.

    Pointing the invocation at one proves the shape refusal lands *before* the
    coverage file is read: if the order ever flips, this file's JSONDecodeError
    is what surfaces instead.
    """
    path = tmp_path / "coverage.json"
    path.write_text("{not json", encoding="utf-8")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# L6: the invocation shape is checked before the coverage file and the POST
# ─────────────────────────────────────────────────────────────────────────────

def test_done_requires_notes_for_clean_before_reading_the_coverage_file(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _ForbiddenClient)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._done(
            _config(tmp_path),
            "42",
            "HUNT-1",
            "lease-42",
            "clean",
            str(_unparsable_coverage(tmp_path)),
            "",
        )

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "notes are required when disposition='clean'" in err
    assert "notes" in err


def test_done_requires_a_standard_skip_reason_before_reading_the_coverage_file(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _ForbiddenClient)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._done(
            _config(tmp_path),
            "42",
            "HUNT-1",
            "lease-42",
            "skipped",
            str(_unparsable_coverage(tmp_path)),
            "",
        )

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "--skip-reason is required when disposition='skipped'" in err
    # The closed vocabulary, so the next attempt is the last one.
    assert "vendored-dependency" in err


def test_done_names_a_skip_reason_outside_the_standard_set(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _ForbiddenClient)

    with pytest.raises(SystemExit) as exc:
        code_dispatch._done(
            _config(tmp_path),
            "42",
            "HUNT-1",
            "lease-42",
            "skipped",
            str(_unparsable_coverage(tmp_path)),
            "",
            skip_reason="looked-boring",
        )

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "looked-boring" in err
    assert "generated-code" in err


@pytest.mark.parametrize("already_applied", [False, True])
def test_a_clean_close_with_notes_still_reaches_the_backend(monkeypatch, tmp_path, capsys, already_applied):
    posted: dict[str, object] = {}

    class _Client(StubClient):
        def post(self, endpoint: str, payload: dict):
            posted["endpoint"] = endpoint
            posted["payload"] = payload
            return {"updated": 0 if already_applied else 1, "total": 1,
                    "already_applied": already_applied}

    coverage = tmp_path / "coverage.json"
    coverage.write_text(json.dumps([{"family": "ssrf", "effort": 80}]), encoding="utf-8")
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._done(
        _config(tmp_path), "42", "HUNT-1", "lease-42", "clean",
        str(coverage), "Reviewed every decode path",
    )

    assert posted["endpoint"] == "code/analysis-queue/done"
    assert posted["payload"]["notes"] == "Reviewed every decode path"
    if already_applied:
        assert "Already applied (clean): 1 item(s)" in capsys.readouterr().out


def test_a_dry_run_renders_the_payload_and_names_what_would_be_refused(
    monkeypatch, tmp_path, capsys
):
    """A dry run reports; it does not refuse.

    `--dry-run` exists to show the operator the exact payload. Exiting early
    would show less than rendering it beside the defect, so the shape problems
    become part of the report and the run still succeeds.
    """
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _ForbiddenClient)
    coverage = tmp_path / "coverage.json"
    coverage.write_text(json.dumps([{"family": "ssrf", "effort": 80}]), encoding="utf-8")

    code_dispatch._done(
        _config(tmp_path), "42", "HUNT-1", "lease-42", "clean",
        str(coverage), "", dry_run=True,
    )

    out = capsys.readouterr().out
    assert "Dry run only" in out
    assert '"endpoint": "code/analysis-queue/done"' in out
    assert "notes are required when disposition='clean'" in out


# ─────────────────────────────────────────────────────────────────────────────
# L1: `progress` prints the whole required set, not only the remainder
# ─────────────────────────────────────────────────────────────────────────────

_PROGRESS = {
    "item_id": 41,
    "file_id": 7,
    "file_path": "src/checkout.py",
    "classification": "critical",
    "status": "processing",
    "queue_mode": "initial",
    "disposition": "",
    "agent_name": "HUNT-1",
    "lease_token": "f0c7a1d2-0000-4000-8000-000000000001",
    "lease_activity_at": "2026-11-07T10:00:00Z",
    "heartbeat_age_seconds": 42,
    "adopted_leases": [],
    "applicable_vuln_classes": ["business-logic", "race-condition", "type-confusion"],
    "path_suggested_vuln_classes": ["rate-limit"],
    "recorded_cwe_families": ["business-logic"],
    "missing_cwe_families": ["race-condition", "type-confusion"],
    "receipts": [],
    "receipt_count": 1,
    "coverage_integrity": {"plausible": True, "authoritative_blockers": [], "advisories": []},
}


def test_progress_prints_the_full_required_family_set(monkeypatch, tmp_path, capsys):
    class _Client(StubClient):
        def get(self, _endpoint: str):
            return _PROGRESS

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)
    code_dispatch._progress(_config(tmp_path), "41", as_json=False)

    out = capsys.readouterr().out
    for family in _PROGRESS["applicable_vuln_classes"]:
        assert family in out
    assert "business-logic" in out
    assert "race-condition" in out
    # The remainder stays, because it is the shorter list to act on.
    assert "still owed" in out


# ─────────────────────────────────────────────────────────────────────────────
# I1: the lease token a lane lost is readable from the supported verbs
# ─────────────────────────────────────────────────────────────────────────────

_LEASED_PAGE = {
    "total": 2,
    "offset": 0,
    "count": 2,
    "has_more": False,
    "item_ids": [41, 42],
    "items": [
        {
            "id": 41,
            "file_id": 7,
            "file_path": "src/checkout.py",
            "classification": "critical",
            "repo_id": 1,
            "status": "processing",
            "queue_mode": "initial",
            "priority": 100,
            "batch_theme": "checkout",
            "agent_name": "HUNT-1",
            "lease_token": "f0c7a1d2-0000-4000-8000-000000000001",
            "heartbeat_age_seconds": 42,
            "current_result_count": 3,
        },
        {
            "id": 42,
            "file_id": 8,
            "file_path": "src/helpers.py",
            "classification": "low",
            "repo_id": 1,
            "status": "pending",
            "queue_mode": "initial",
            "priority": 10,
            "batch_theme": "helpers",
            "agent_name": "",
            "lease_token": "",
            "heartbeat_age_seconds": None,
            "current_result_count": 0,
        },
    ],
}


@pytest.fixture
def leased_page(monkeypatch):
    requested: list[str] = []

    class _Client(StubClient):
        def get(self, endpoint: str):
            requested.append(endpoint)
            return _LEASED_PAGE

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)
    return requested


def test_show_tokens_is_a_render_flag_and_never_reaches_the_query(leased_page, tmp_path):
    filters, output = code_dispatch._parse_list_filters(
        ["--status", "processing", "--show-tokens"]
    )
    assert output == "table"
    code_dispatch._list(_config(tmp_path), filters, output)

    assert leased_page == ["code/analysis-queue?status=processing"]


def test_show_tokens_prints_the_lease_token_for_each_leased_row(
    leased_page, tmp_path, capsys
):
    filters, output = code_dispatch._parse_list_filters(["--show-tokens"])
    code_dispatch._list(_config(tmp_path), filters, output)

    out = capsys.readouterr().out
    assert "f0c7a1d2-0000-4000-8000-000000000001" in out
    assert "HUNT-1" in out


def test_a_leased_page_without_show_tokens_names_where_the_token_is(
    leased_page, tmp_path, capsys
):
    filters, output = code_dispatch._parse_list_filters([])
    code_dispatch._list(_config(tmp_path), filters, output)

    out = capsys.readouterr().out
    assert "f0c7a1d2-0000-4000-8000-000000000001" not in out
    assert "--show-tokens" in out
    assert "code-dispatch progress 41" in out


def test_a_page_with_no_leased_row_says_nothing_about_tokens(
    monkeypatch, tmp_path, capsys
):
    unleased = {
        **_LEASED_PAGE,
        "items": [item for item in _LEASED_PAGE["items"] if not item["lease_token"]],
    }

    class _Client(StubClient):
        def get(self, _endpoint: str):
            return unleased

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)
    filters, output = code_dispatch._parse_list_filters([])
    code_dispatch._list(_config(tmp_path), filters, output)

    assert "--show-tokens" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "tokens",
    [
        ["--show-tokens", "--show-tokens"],
        ["--show-tokens", "--json"],
        ["--show-tokens", "--ids-only"],
    ],
)
def test_show_tokens_rejects_a_contradictory_invocation(tokens, capsys):
    with pytest.raises(SystemExit) as exc:
        code_dispatch._parse_list_filters(tokens)

    assert exc.value.code == 1
    assert capsys.readouterr().err
