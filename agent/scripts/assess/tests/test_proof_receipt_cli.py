"""Operator-facing creation and reads for durable proof receipts."""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient


_SHA = "a" * 64


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def _receipt(receipt_id: int = 31, **overrides) -> dict:
    row = {
        "id": receipt_id,
        "run_id": 17,
        "producer_dispatch_id": 4,
        "evidence_kind": "artifact",
        "expected_result": "the guard rejects access",
        "observed_result": "the protected row was returned",
        "artifact_id": 9,
        "source_read_id": None,
        "command_run_id": None,
        "artifact_relative_path": "evidence/raw/http.txt",
        "evidence_sha256": _SHA,
        "evidence_health": "healthy",
        "redaction_status": "raw",
        "derivative_of_receipt_id": None,
        "raw_receipt_id": receipt_id,
        "tombstone_reason": "",
        "created_at": "2026-09-09T12:00:00+00:00",
    }
    row.update(overrides)
    return row


def test_proof_receipt_create_preserves_artifact_evidence_contract(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, endpoint: str, payload: dict):
        calls.append((endpoint, payload))
        return _receipt(
            run_id=payload["run_id"],
            evidence_kind=payload["evidence_kind"],
            expected_result=payload["expected_result"],
            observed_result=payload["observed_result"],
            artifact_id=payload["artifact_id"],
            source_read_id=payload["source_read_id"],
            command_run_id=payload["command_run_id"],
            evidence_sha256=payload["evidence_sha256"],
            evidence_health=payload["evidence_health"],
            redaction_status=payload["redaction_status"],
            derivative_of_receipt_id=payload["derivative_of_receipt_id"],
            tombstone_reason=payload["tombstone_reason"],
        )

    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-receipt",
            "create",
            "--run-id",
            "17",
            "--kind",
            "artifact",
            "--expected-result",
            "the guard rejects access",
            "--observed-result",
            "the protected row was returned",
            "--artifact-id",
            "9",
            "--evidence-sha256",
            _SHA,
        ]
    )

    assert json.loads(capsys.readouterr().out)["id"] == 31
    assert calls == [
        (
            "proof-receipts",
            {
                "run_id": 17,
                "evidence_kind": "artifact",
                "expected_result": "the guard rejects access",
                "observed_result": "the protected row was returned",
                "artifact_id": 9,
                "source_read_id": None,
                "command_run_id": None,
                "evidence_sha256": _SHA,
                "evidence_health": "healthy",
                "redaction_status": "raw",
                "derivative_of_receipt_id": None,
                "tombstone_reason": "",
            },
        )
    ]


def test_proof_receipt_create_binds_command_evidence_to_an_execution(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    posted: list[dict] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, _endpoint: str, payload: dict):
        posted.append(payload)
        return _receipt(
            run_id=payload["run_id"],
            evidence_kind="command",
            expected_result="",
            observed_result=payload["observed_result"],
            artifact_id=None,
            command_run_id=payload["command_run_id"],
            artifact_relative_path="",
            evidence_sha256="b" * 64,
        )

    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-receipt",
            "create",
            "--run-id",
            "17",
            "--kind",
            "command",
            "--command-run-id",
            "88",
            "--observed-result",
            "recorded execution completed",
        ]
    )

    assert json.loads(capsys.readouterr().out)["command_run_id"] == 88
    assert posted[0]["command_run_id"] == 88


def test_proof_receipt_create_preserves_redacted_derivative_fields(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    payloads: list[dict] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, _endpoint: str, payload: dict):
        payloads.append(payload)
        return _receipt(
            32,
            evidence_kind="http_exchange",
            artifact_id=None,
            artifact_relative_path="",
            evidence_sha256="b" * 64,
            redaction_status="redacted",
            derivative_of_receipt_id=31,
            raw_receipt_id=31,
            **{
                key: payload[key]
                for key in (
                    "run_id",
                    "expected_result",
                    "observed_result",
                    "evidence_health",
                    "tombstone_reason",
                )
            },
        )

    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-receipt",
            "create",
            "--run-id",
            "17",
            "--kind",
            "http_exchange",
            "--redaction-status",
            "redacted",
            "--derivative-of-receipt-id",
            "31",
        ]
    )

    assert json.loads(capsys.readouterr().out)["raw_receipt_id"] == 31
    assert payloads[0]["redaction_status"] == "redacted"
    assert payloads[0]["derivative_of_receipt_id"] == 31


def test_proof_receipt_get_and_bounded_list_validate_canonical_rows(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    requested: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        if endpoint == "proof-receipts/31":
            return _receipt()
        if endpoint == "proof-receipts?finding_slug=VA-047&limit=2&offset=0":
            return [_receipt(), _receipt(30, raw_receipt_id=30)]
        raise AssertionError(endpoint)

    monkeypatch.setattr(AssessmentClient, "get", get)
    cli.main(["--engagement-dir", str(engagement), "proof-receipt", "get", "31"])
    assert json.loads(capsys.readouterr().out)["id"] == 31

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-receipt",
            "list",
            "--finding",
            "VA-047",
            "--limit",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [31]
    assert "continue with `vigil assess proof-receipt list --finding VA-047 --limit 1 --offset 1`" in captured.err
    assert "UNTRUSTED DATA" in captured.err
    assert requested == [
        "proof-receipts/31",
        "proof-receipts?finding_slug=VA-047&limit=2&offset=0",
    ]


@pytest.mark.parametrize(
    ("argv", "response"),
    [
        (["proof-receipt", "get", "31"], _receipt(32, raw_receipt_id=32)),
        (["proof-receipt", "list"], {"id": 31}),
        (["proof-receipt", "list"], [_receipt(evidence_sha256="not-a-sha")]),
    ],
)
def test_proof_receipt_reads_reject_malformed_or_wrong_identity(
    argv, response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--engagement-dir", str(engagement), *argv])

    assert exc.value.code == 1
    assert "proof-receipt" in capsys.readouterr().err


def test_proof_receipt_create_rejects_unbound_success_receipt(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda *_args, **_kwargs: _receipt(run_id=99),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-receipt",
                "create",
                "--run-id",
                "17",
                "--kind",
                "artifact",
                "--artifact-id",
                "9",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "write may have committed" in stderr
    assert "do not retry automatically" in stderr


@pytest.mark.parametrize(
    "response_override",
    [
        {"expected_result": "different expected result"},
        {"observed_result": "different observed result"},
        {"tombstone_reason": "different tombstone reason"},
        {"evidence_health": "stale"},
    ],
)
def test_proof_receipt_create_rejects_success_with_changed_authored_evidence(
    response_override, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda *_args, **_kwargs: _receipt(
            evidence_kind="source_observation",
            artifact_id=None,
            artifact_relative_path="",
            **response_override,
        ),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-receipt",
                "create",
                "--run-id",
                "17",
                "--kind",
                "source_observation",
                "--expected-result",
                "the guard rejects access",
                "--observed-result",
                "the protected row was returned",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "write may have committed" in stderr
    assert "do not retry automatically" in stderr


def test_proof_receipt_contract_documents_creation_and_reads() -> None:
    contract = contracts.get_contract("proof-receipt create")
    assert contract is not None
    assert contract.name == "proof-receipt"
    assert "create | list | get" in " ".join(contract.author_supplied_fields)
