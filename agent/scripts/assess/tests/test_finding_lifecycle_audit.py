"""Finding lifecycle reads and audit-preserving correction controls."""
from __future__ import annotations

import argparse
import contextlib
import json
from types import SimpleNamespace

import pytest

from assess import cli
from assess.commands import record_finding, update_finding
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def test_finding_history_reads_the_existing_transition_ledger(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    expected = [
        {
            "id": 19,
            "action": "details_patched",
            "details_before_json": '{"correction_history":[]}',
            "details_after_json": '{"correction_history":["prior correction"]}',
            "reason_code": "claim_retracted",
        }
    ]
    requested: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        return expected

    monkeypatch.setattr(AssessmentClient, "get", get)

    cli.main(
        ["--engagement-dir", str(engagement), "finding", "history", "VA-021"]
    )

    assert requested == ["findings/VA-021/transitions?limit=101&offset=0"]
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert "UNTRUSTED DATA" in captured.err
    assert "showing 1-1 of 1 matching finding transitions" in captured.err


def test_finding_history_explicit_pagination_preserves_complete_rows(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        calls.append(endpoint)
        if "offset=1" in endpoint:
            return [
                {"id": 2, "action": "details_patched", "details_before_json": "X" * 4096},
                {"id": 1, "action": "created", "notes_before_json": "Y" * 4096},
            ]
        if "offset=3" in endpoint:
            return []
        raise AssertionError(endpoint)

    monkeypatch.setattr(AssessmentClient, "get", get)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "history",
            "VA-021",
            "--limit",
            "2",
            "--offset",
            "1",
            "--paginate",
        ]
    )

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert rows[0]["details_before_json"] == "X" * 4096
    assert rows[1]["notes_before_json"] == "Y" * 4096
    assert calls == [
        "findings/VA-021/transitions?limit=2&offset=1",
        "findings/VA-021/transitions?limit=2&offset=3",
    ]
    assert "showing 2-3 of 3 matching finding transitions" in captured.err


def test_finding_history_default_page_reports_continuation(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda _client, _endpoint: [
            {"id": 3, "action": "details_patched"},
            {"id": 2, "action": "details_patched"},
        ],
    )

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "history",
            "VA-021",
            "--limit",
            "1",
        ]
    )

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [3]
    assert "of at least 2 matching finding transitions" in captured.err
    assert (
        "continue with `vigil assess finding history VA-021 --limit 1 --offset 1`"
        in captured.err
    )


def test_retract_claim_replaces_current_claim_and_preserves_audit_and_evidence(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    current = {
        "slug": "VA-021",
        "summary": "Any user can read every tenant's invoices.",
        "evidence_ref": "scans/invoice-idor.txt",
        "notes": "Preserve these replay notes.",
        "details": {
            "evidence": "Captured request and response.",
            "correction_history": ["Earlier wording correction."],
        },
        "row_version": 7,
    }
    calls: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        calls.append(("GET", endpoint, None))
        return current

    def patch(_client, endpoint: str, payload: dict):
        calls.append(("PATCH", endpoint, payload))
        return {"finding": {**current, **payload, "row_version": 8}}

    monkeypatch.setattr(AssessmentClient, "get", get)
    monkeypatch.setattr(AssessmentClient, "patch", patch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "retract-claim",
            "VA-021",
            "--replacement-summary",
            "Authenticated users can read invoices belonging to their own tenant.",
            "--reason",
            "The original claim overgeneralized the captured tenant boundary.",
            "--source-name",
            "vulnerability-analyst",
        ]
    )

    assert calls[0] == ("GET", "findings/VA-021", None)
    method, endpoint, payload = calls[1]
    assert (method, endpoint) == ("PATCH", "findings/VA-021")
    assert payload is not None
    assert payload["summary"] == (
        "Authenticated users can read invoices belonging to their own tenant."
    )
    assert payload["expected_row_version"] == 7
    assert payload["details_mode"] == "merge"
    assert payload["reason_code"] == "claim_retracted"
    assert payload["reason_text"] == (
        "The original claim overgeneralized the captured tenant boundary."
    )
    assert payload["details"]["correction_history"][:-1] == [
        "Earlier wording correction."
    ]
    assert payload["details"]["correction_history"][-1] == {
        "finding_slug": "VA-021",
        "field": "summary",
        "retracted_claim": "Any user can read every tenant's invoices.",
        "replacement_claim": (
            "Authenticated users can read invoices belonging to their own tenant."
        ),
        "reason": "The original claim overgeneralized the captured tenant boundary.",
        "source_name": "vulnerability-analyst",
    }
    # Retraction changes the current claim and audit metadata only. Omitting these
    # fields is what preserves the sealed evidence and the working notes.
    assert "evidence_ref" not in payload
    assert "notes" not in payload
    assert "provenance" not in payload
    assert json.loads(capsys.readouterr().out)["finding"]["row_version"] == 8


def test_retract_claim_refuses_a_noop_replacement_before_patch(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    patched: list[dict] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {"slug": "VA-021", "summary": "Current claim", "row_version": 3},
    )
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda _client, _endpoint, payload: patched.append(payload),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "finding",
                "retract-claim",
                "VA-021",
                "--replacement-summary",
                "Current claim",
                "--reason",
                "No actual correction.",
            ]
        )

    assert exc.value.code == 1
    assert patched == []
    assert "must differ from the current summary" in capsys.readouterr().err


def test_retract_claim_rejects_an_unidentified_success_response(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {"slug": "VA-021", "summary": "Old claim", "row_version": 3},
    )
    monkeypatch.setattr(AssessmentClient, "patch", lambda *_args: {})

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "finding",
                "retract-claim",
                "VA-021",
                "--replacement-summary",
                "Corrected claim",
                "--reason",
                "The prior statement exceeded the evidence.",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "did not return canonical finding VA-021" in stderr
    assert "do not retry automatically" in stderr


class _RecordClient:
    def __init__(self, calls: list[tuple[str, dict]]) -> None:
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def get(self, _endpoint: str):
        return []

    def post(self, endpoint: str, payload: dict):
        self.calls.append((endpoint, payload))
        return {
            "finding": {"slug": payload["slug"], "title": payload["title"]},
            "duplicate_advisories": [
                {
                    "slug": "VA-008",
                    "submission_status": "duplicate",
                    "submission_ref": "H1-31415",
                    "matched_on": "root_cause_key",
                    "detail": (
                        "VA-008 was already submitted as H1-31415 and matches "
                        "root_cause_key."
                    ),
                }
            ],
        }

    def post_event(self, payload: dict):
        self.calls.append(("event", payload))


def _run_record_with_advisory(tmp_path, monkeypatch, *, quiet: bool) -> None:
    payload_path = tmp_path / "finding.json"
    payload_path.write_text(
        json.dumps(
            {
                "slug": "VA-021",
                "title": "Tenant invoice authorization gap",
                "defect_family": "idor",
                "root_cause_key": "invoice-owner-check",
                "canonical_location": "https://app.example/invoices/1",
            }
        ),
        encoding="utf-8",
    )
    calls: list[tuple[str, dict]] = []
    cfg = SimpleNamespace(
        base_url="http://backend.invalid",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )
    monkeypatch.setattr(record_finding, "load_config", lambda *_args: cfg)
    monkeypatch.setattr(
        record_finding, "AssessmentClient", lambda *_args: _RecordClient(calls)
    )
    monkeypatch.setattr(record_finding, "collect_validation_errors", lambda *_args: [])
    monkeypatch.setattr(
        record_finding, "file_lock", lambda *_args: contextlib.nullcontext()
    )
    monkeypatch.setattr(
        record_finding,
        "finding_lock_path",
        lambda *_args: str(tmp_path / "finding.lock"),
    )
    record_finding.run(
        argparse.Namespace(
            engagement_dir=str(tmp_path),
            agent_name="vulnerability-analyst",
            json_file=str(payload_path),
            allow_unindexed_evidence=True,
            update_slug="",
            allow_remint=False,
            quiet=quiet,
        )
    )


def test_finding_record_surfaces_backend_duplicate_advisories(
    tmp_path, monkeypatch, capsys
) -> None:
    _run_record_with_advisory(tmp_path, monkeypatch, quiet=False)

    captured = capsys.readouterr()
    assert captured.out.strip() == "VA-021"
    assert "duplicate advisory" in captured.err
    assert "VA-008" in captured.err
    assert "H1-31415" in captured.err
    assert "root_cause_key" in captured.err


def test_finding_record_quiet_suppresses_advisories_but_keeps_slug_stdout(
    tmp_path, monkeypatch, capsys
) -> None:
    _run_record_with_advisory(tmp_path, monkeypatch, quiet=True)

    captured = capsys.readouterr()
    assert captured.out.strip() == "VA-021"
    assert captured.err == ""


def test_finding_record_parser_exposes_quiet() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    record_finding.register(sub)

    args = parser.parse_args(["record", "analyst", "finding.json", "--quiet"])

    assert args.quiet is True


def test_update_submission_identity_flags_reach_existing_patch_fields(
    tmp_path, monkeypatch, capsys
) -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    update_finding.register(sub)
    args = parser.parse_args(
        [
            "update",
            "VA-021",
            "--submission-status",
            "submitted",
            "--submission-platform",
            "hackerone",
            "--submission-ref",
            "H1-31415",
            "--submission-url",
            "https://hackerone.com/reports/31415",
        ]
    )
    args.engagement_dir = str(tmp_path)
    captured: dict[str, object] = {}

    class _UpdateClient:
        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> bool:
            return False

        def get(self, endpoint: str):
            assert endpoint == "findings/VA-021"
            return {"slug": "VA-021", "row_version": 4}

        def patch(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"finding": {"slug": "VA-021", **payload}}

    monkeypatch.setattr(
        update_finding,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://backend.invalid",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *_args: _UpdateClient())

    update_finding.run(args)

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["submission_status"] == "submitted"
    assert payload["submission_platform"] == "hackerone"
    assert payload["submission_ref"] == "H1-31415"
    assert payload["submission_url"] == "https://hackerone.com/reports/31415"
    assert payload["expected_row_version"] == 4
    assert json.loads(capsys.readouterr().out)["finding"]["submission_ref"] == "H1-31415"


@pytest.mark.parametrize(
    "name,route",
    [
        ("finding history", "GET /assessment/findings/{slug}/transitions"),
        ("finding retract-claim", "PATCH /assessment/findings/{slug}"),
    ],
)
def test_new_finding_audit_commands_have_executable_contracts(name, route) -> None:
    contract = contracts.get_contract(name)

    assert contract is not None
    assert contract.schema_name == route


def test_finding_contract_documents_audit_actions_and_submission_identity() -> None:
    root = contracts.render_contract("finding")
    update = contracts.render_contract("finding update")
    record = contracts.render_contract("finding record")

    assert "finding history" in root
    assert "finding retract-claim" in root
    for flag in ("--submission-platform", "--submission-ref", "--submission-url"):
        assert flag in update
    assert "--quiet" in record
