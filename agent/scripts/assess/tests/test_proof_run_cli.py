"""Operator-facing lifecycle for assessment proof runs."""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def test_proof_run_start_and_finish_use_explicit_durable_transitions(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, endpoint: str, payload: dict):
        calls.append(("POST", endpoint, payload))
        return {
            "id": 17,
            "run_uuid": payload["run_uuid"],
            "run_kind": payload["run_kind"],
            "run_purpose": payload["run_purpose"],
            "producer_dispatch_id": 4,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": "running",
        }

    def patch(_client, endpoint: str, payload: dict):
        calls.append(("PATCH", endpoint, payload))
        return {
            "id": 17,
            "run_uuid": "verify-va-047",
            "run_kind": "web",
            "producer_dispatch_id": 4,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": payload["status"],
        }

    monkeypatch.setattr(AssessmentClient, "post", post)
    monkeypatch.setattr(AssessmentClient, "patch", patch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "start",
            "verify-va-047",
            "--kind",
            "web",
            "--agent-id",
            "VERIFY-1",
        ]
    )
    assert json.loads(capsys.readouterr().out)["status"] == "running"

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "finish",
            "17",
            "--status",
            "completed",
        ]
    )
    assert json.loads(capsys.readouterr().out)["status"] == "completed"
    assert calls == [
        (
            "POST",
            "assessment-runs",
            {
                "run_uuid": "verify-va-047",
                "run_kind": "web",
                "run_purpose": "proof",
                "producer_dispatch_agent_id": "VERIFY-1",
            },
        ),
        ("PATCH", "assessment-runs/17", {"status": "completed"}),
    ]


@pytest.mark.parametrize("terminal_status", ["completed", "failed"])
def test_proof_run_finish_exposes_success_and_failure(
    terminal_status, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda _client, _endpoint, payload: {
            "id": 23,
            "run_uuid": "run-23",
            "run_kind": "shared",
            "producer_dispatch_id": 7,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": payload["status"],
        },
    )

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "finish",
            "23",
            "--status",
            terminal_status,
        ]
    )

    assert json.loads(capsys.readouterr().out)["status"] == terminal_status


def test_proof_run_completed_request_reports_backend_enforced_partial(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda _client, _endpoint, _payload: {
            "id": 23,
            "run_uuid": "scan-23",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_id": 7,
            "producer_dispatch_agent_id": "HUNT-1",
            "status": "partial",
            "seal": {
                "requested_status": "completed",
                "effective_status": "partial",
                "blockers": [{"code": "unresolved_obligation"}],
            },
        },
    )

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "finish",
            "23",
            "--status",
            "completed",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "partial"
    assert result["seal"]["requested_status"] == "completed"


def test_proof_run_get_and_list_validate_canonical_read_shapes(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    requested: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        if endpoint == "assessment-runs/17":
            return {
                "id": 17,
                "run_uuid": "verify-va-047",
                "run_kind": "web",
                "producer_dispatch_id": 4,
                "producer_dispatch_agent_id": "VERIFY-1",
                "status": "completed",
            }
        if endpoint == "assessment-runs?limit=2&offset=0":
            return [
                {
                    "id": 17,
                    "run_uuid": "verify-va-047",
                    "run_kind": "web",
                    "producer_dispatch_id": 4,
                    "producer_dispatch_agent_id": "VERIFY-1",
                    "status": "completed",
                },
                {
                    "id": 16,
                    "run_uuid": "verify-va-046",
                    "run_kind": "web",
                    "producer_dispatch_id": 4,
                    "producer_dispatch_agent_id": "VERIFY-1",
                    "status": "failed",
                },
            ]
        raise AssertionError(endpoint)

    monkeypatch.setattr(AssessmentClient, "get", get)

    cli.main(
        ["--engagement-dir", str(engagement), "proof-run", "get", "17"]
    )
    assert json.loads(capsys.readouterr().out)["id"] == 17

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "list",
            "--limit",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [17]
    assert "continue with `vigil assess proof-run list --limit 1 --offset 1`" in captured.err
    assert requested == [
        "assessment-runs/17",
        "assessment-runs?limit=2&offset=0",
    ]


@pytest.mark.parametrize(
    ("argv", "response"),
    [
        (["proof-run", "get", "17"], {"id": 18, "status": "completed"}),
        (["proof-run", "list"], {"id": 17, "status": "completed"}),
    ],
)
def test_proof_run_reads_reject_malformed_or_wrong_identity(
    argv, response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--engagement-dir", str(engagement), *argv])

    assert exc.value.code == 1
    assert "proof-run" in capsys.readouterr().err


def test_proof_run_writes_reject_unbound_success_receipts(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda *_args, **_kwargs: {"id": 99, "status": "completed"},
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-run",
                "finish",
                "17",
                "--status",
                "completed",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "write may have committed" in stderr
    assert "do not retry automatically" in stderr


@pytest.mark.parametrize(
    "response_override",
    [
        {"status": "completed"},
        {"producer_dispatch_agent_id": "SOMEONE-ELSE"},
    ],
)
def test_proof_run_start_rejects_success_with_wrong_lifecycle_or_producer(
    response_override, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    response = {
        "id": 17,
        "run_uuid": "verify-va-047",
        "run_kind": "web",
        "run_purpose": "proof",
        "producer_dispatch_id": 4,
        "producer_dispatch_agent_id": "VERIFY-1",
        "status": "running",
        **response_override,
    }
    monkeypatch.setattr(AssessmentClient, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-run",
                "start",
                "verify-va-047",
                "--kind",
                "web",
                "--agent-id",
                "VERIFY-1",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "write may have committed" in stderr
    assert "do not retry automatically" in stderr


def test_proof_run_contract_documents_the_whole_lifecycle() -> None:
    contract = contracts.get_contract("proof-run finish")
    assert contract is not None
    assert contract.name == "proof-run"
    assert "start | begin | finish | list | get" in " ".join(
        contract.author_supplied_fields
    )
    contract_text = " ".join((*contract.author_supplied_fields, *contract.notes))
    for field in (
        "inventory_commitment_version",
        "inventory_count",
        "inventory_digest",
        "run-audit sources commitment",
    ):
        assert field in contract_text


def test_proof_run_scan_start_accepts_frozen_identity_and_resume_files(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    target = tmp_path / "target.json"
    generations = tmp_path / "generations.json"
    exclusions = tmp_path / "exclusions.json"
    target.write_text('{"repositories":["service-a"]}', encoding="utf-8")
    generations.write_text('[{"target_key":"service-a","generation":4}]', encoding="utf-8")
    exclusions.write_text('[{"target_key":"service-a","path":"vendor/"}]', encoding="utf-8")
    posted: list[dict] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, _endpoint: str, payload: dict):
        posted.append(payload)
        return {
            "id": 29,
            "run_uuid": payload["run_uuid"],
            "run_kind": payload["run_kind"],
            "run_purpose": payload["run_purpose"],
            "producer_dispatch_id": 4,
            "producer_dispatch_agent_id": payload["producer_dispatch_agent_id"],
            "status": "queued",
            "target_identity": payload["target_identity"],
            "source_generations": payload["source_generations"],
            "exclusions": payload["exclusions"],
            "resumed_from_run_id": payload["resumed_from_run_id"],
        }

    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "start",
            "scan-29",
            "--kind",
            "code",
            "--agent-id",
            "HUNT-1",
            "--purpose",
            "scan",
            "--target-identity-file",
            str(target),
            "--source-generations-file",
            str(generations),
            "--exclusions-file",
            str(exclusions),
            "--resume-from",
            "11",
        ]
    )

    assert json.loads(capsys.readouterr().out)["status"] == "queued"
    assert posted == [
        {
            "run_uuid": "scan-29",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_agent_id": "HUNT-1",
            "target_identity": {"repositories": ["service-a"]},
            "source_generations": [{"target_key": "service-a", "generation": 4}],
            "exclusions": [{"target_key": "service-a", "path": "vendor/"}],
            "resumed_from_run_id": 11,
        }
    ]


def test_proof_run_begin_owns_queued_to_running_transition(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def patch(_client, endpoint: str, payload: dict):
        calls.append((endpoint, payload))
        return {
            "id": 29,
            "run_uuid": "scan-29",
            "run_kind": "code",
            "run_purpose": "scan",
            "producer_dispatch_id": 4,
            "producer_dispatch_agent_id": "HUNT-1",
            "status": "running",
            "target_identity": {"repositories": ["service-a"]},
            "source_generations": [],
            "exclusions": [],
            "resumed_from_run_id": None,
        }

    monkeypatch.setattr(AssessmentClient, "patch", patch)
    cli.main(["--engagement-dir", str(engagement), "proof-run", "begin", "29"])

    assert json.loads(capsys.readouterr().out)["status"] == "running"
    assert calls == [("assessment-runs/29", {"status": "running"})]


# ── Verifier-independence preflight ──────────────────────────────────────────
#
# "The finding author cannot be its own verifier" was only enforced on the
# final `finding verify` write — after the proof run had already been executed
# against the target. `--for-finding` moves the same refusal to the top of the
# proof path, where it costs zero target traffic.


def _findings_get(rows: dict[str, dict]):
    def get(_client, endpoint: str):
        slug = endpoint.split("/", 1)[1]
        if slug not in rows:
            raise AssertionError(f"unexpected finding read {endpoint}")
        return rows[slug]

    return get


def test_proof_run_start_refuses_a_run_the_finding_author_would_own(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        _findings_get({"VA-047": {"slug": "VA-047", "provenance": {"agent_id": "HUNT-RUN-1"}}}),
    )

    def post(_client, _endpoint: str, _payload: dict):
        raise AssertionError("the run must be refused before any write")

    monkeypatch.setattr(AssessmentClient, "post", post)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-run",
                "start",
                "verify-va-047",
                "--kind",
                "web",
                "--agent-id",
                "HUNT-RUN-1",
                "--for-finding",
                "VA-047",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "VA-047" in stderr
    assert "HUNT-RUN-1" in stderr
    assert "independent" in stderr


def test_proof_run_start_accepts_an_independent_verifier_dispatch(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        _findings_get(
            {
                "VA-047": {"slug": "VA-047", "provenance": {"agent_id": "HUNT-RUN-1"}},
                "VA-048": {"slug": "VA-048", "provenance": {"agent_id": "HUNT-RUN-2"}},
            }
        ),
    )
    posted: list[tuple[str, dict]] = []

    def post(_client, endpoint: str, payload: dict):
        posted.append((endpoint, payload))
        if endpoint.endswith("/links"):
            return {"id": len(posted), "finding_slug": endpoint.split("/")[1], **payload}
        return {
            "id": 31,
            "run_uuid": payload["run_uuid"],
            "run_kind": payload["run_kind"],
            "run_purpose": payload["run_purpose"],
            "producer_dispatch_id": 9,
            "producer_dispatch_agent_id": payload["producer_dispatch_agent_id"],
            "status": "running",
        }

    monkeypatch.setattr(AssessmentClient, "post", post)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "proof-run",
            "start",
            "verify-va-047",
            "--kind",
            "web",
            "--agent-id",
            "VERIFY-1",
            "--for-finding",
            "VA-047",
            "--for-finding",
            "VA-048",
        ]
    )

    assert json.loads(capsys.readouterr().out)["status"] == "running"
    # The run and its finding associations must both be durable writes.
    assert posted[0][1] == {
        "run_uuid": "verify-va-047",
        "run_kind": "web",
        "run_purpose": "proof",
        "producer_dispatch_agent_id": "VERIFY-1",
    }
    assert posted[1:] == [
        ("findings/VA-047/links", {
            "link_kind": "proof_run", "target_kind": "assessment_run", "target_id": 31,
        }),
        ("findings/VA-048/links", {
            "link_kind": "proof_run", "target_kind": "assessment_run", "target_id": 31,
        }),
    ]


def test_proof_run_start_refuses_a_finding_with_no_resolvable_author(
    tmp_path, monkeypatch, capsys
) -> None:
    """An authorless finding cannot establish independence at verify time either,
    so the preflight says so here rather than letting the proof run burn."""
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        _findings_get({"VA-049": {"slug": "VA-049", "provenance": {}}}),
    )
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("the run must be refused before any write")
        ),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "proof-run",
                "start",
                "verify-va-049",
                "--kind",
                "code",
                "--agent-id",
                "VERIFY-1",
                "--for-finding",
                "VA-049",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "VA-049" in stderr
    assert "bind-author" in stderr
