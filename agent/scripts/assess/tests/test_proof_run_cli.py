"""Operator-facing lifecycle for assessment proof runs."""
from __future__ import annotations

import argparse
import json

import pytest

from assess import cli
from assess.commands import proof_run
from assess.lib import config, contracts
from assess.lib.client import AssessError, AssessmentClient


@pytest.fixture(autouse=True)
def _no_backend_probe(monkeypatch):
    """Every verb in this module reaches the backend through the fake clients
    installed per test, so the config loader's reachability probe must not run."""
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def _run_cli(engagement, *argv: str) -> None:
    """Drive the real root parser, which every proof-run verb is reached through."""
    cli.main(["--engagement-dir", str(engagement), *argv])


def test_proof_run_start_and_finish_use_explicit_durable_transitions(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[tuple[str, str, dict]] = []

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

    _run_cli(
        engagement, "proof-run", "start", "verify-va-047", "--kind", "web", "--agent-id",
        "VERIFY-1",
    )
    assert json.loads(capsys.readouterr().out)["status"] == "running"

    _run_cli(engagement, "proof-run", "finish", "17", "--status", "completed")
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

    _run_cli(engagement, "proof-run", "finish", "23", "--status", terminal_status)

    assert json.loads(capsys.readouterr().out)["status"] == terminal_status


def test_proof_run_completed_request_reports_backend_enforced_partial(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
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

    _run_cli(engagement, "proof-run", "finish", "23", "--status", "completed")

    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["status"] == "partial"
    assert result["seal"]["requested_status"] == "completed"
    assert "scan run 23 was sealed partial with 1 blocker(s) remaining" in captured.err
    assert "unresolved_obligation" in captured.err


def test_proof_run_completed_request_never_accepts_a_partial_proof_seal(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda _client, _endpoint, _payload: {
            "id": 23,
            "run_uuid": "verify-23",
            "run_kind": "web",
            "run_purpose": "proof",
            "producer_dispatch_id": 7,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": "partial",
            "seal": {
                "requested_status": "completed",
                "effective_status": "partial",
                "blockers": [{"code": "unread_source"}],
            },
        },
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_cli(engagement, "proof-run", "finish", "23", "--status", "completed")

    assert excinfo.value.code == 1
    assert "did not identify the canonical run" in capsys.readouterr().err


def test_proof_run_finish_surfaces_the_backend_completion_refusal(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    detail = (
        'proof run 23 cannot complete: 1 imported source is unread (obligation 4). '
        'Read each with `run-audit source-read record`, release one you will not '
        'read with `run-audit obligation release 23 <id> --agent-id VERIFY-1 '
        '--reason <text>`, or seal the truthful outcome with '
        '`proof-run finish 23 --status partial`.'
    )

    def refuse(_client, _endpoint, _payload):
        raise AssessError(f"HTTP 409:\n{json.dumps({'detail': detail})}")

    monkeypatch.setattr(AssessmentClient, "patch", refuse)

    with pytest.raises(SystemExit) as excinfo:
        _run_cli(engagement, "proof-run", "finish", "23", "--status", "completed")

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"proof-run finish: REFUSED: {detail}" in captured.err


def test_proof_run_finish_partial_records_the_operator_reason(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    calls: list[dict] = []

    def patch(_client, _endpoint, payload):
        calls.append(payload)
        return {
            "id": 23,
            "run_uuid": "verify-23",
            "run_kind": "web",
            "run_purpose": "proof",
            "producer_dispatch_id": 7,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": payload["status"],
        }

    monkeypatch.setattr(AssessmentClient, "patch", patch)

    _run_cli(
        engagement, "proof-run", "finish", "23", "--status", "partial", "--reason",
        "time box ended before the second file",
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "partial"
    assert captured.err == ""
    assert calls == [
        {"status": "partial", "reason": "time box ended before the second file"}
    ]


def test_proof_run_get_and_list_validate_canonical_read_shapes(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    requested: list[str] = []

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

    _run_cli(engagement, "proof-run", "get", "17")
    assert json.loads(capsys.readouterr().out)["id"] == 17

    _run_cli(engagement, "proof-run", "list", "--limit", "1")
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
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        _run_cli(engagement, *argv)

    assert exc.value.code == 1
    assert "proof-run" in capsys.readouterr().err


def test_proof_run_writes_reject_unbound_success_receipts(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(
        AssessmentClient,
        "patch",
        lambda *_args, **_kwargs: {"id": 99, "status": "completed"},
    )

    with pytest.raises(SystemExit) as exc:
        _run_cli(engagement, "proof-run", "finish", "17", "--status", "completed")

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
        _run_cli(
            engagement, "proof-run", "start", "verify-va-047", "--kind", "web", "--agent-id",
            "VERIFY-1",
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
    _run_cli(
        engagement, "proof-run", "start", "scan-29", "--kind", "code", "--agent-id", "HUNT-1",
        "--purpose", "scan", "--target-identity-file", str(target), "--source-generations-file",
        str(generations), "--exclusions-file", str(exclusions), "--resume-from", "11",
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
    _run_cli(engagement, "proof-run", "begin", "29")

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
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        _findings_get({"VA-047": {"slug": "VA-047", "provenance": {"agent_id": "HUNT-RUN-1"}}}),
    )

    def post(_client, _endpoint: str, _payload: dict):
        raise AssertionError("the run must be refused before any write")

    monkeypatch.setattr(AssessmentClient, "post", post)

    with pytest.raises(SystemExit) as exc:
        _run_cli(
            engagement, "proof-run", "start", "verify-va-047", "--kind", "web", "--agent-id",
            "HUNT-RUN-1", "--for-finding", "VA-047",
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
    get_finding = _findings_get(
        {
            "VA-047": {"slug": "VA-047", "provenance": {"agent_id": "HUNT-RUN-1"}},
            "VA-048": {"slug": "VA-048", "provenance": {"agent_id": "HUNT-RUN-2"}},
        }
    )

    def get(_client, endpoint: str):
        if endpoint != "assessment-runs/31":
            return get_finding(_client, endpoint)
        linked = [path.split("/")[1] for path, _payload in posted[1:]]
        return {
            "id": 31,
            "run_uuid": "verify-va-047",
            "run_kind": "web",
            "run_purpose": "proof",
            "producer_dispatch_id": 9,
            "producer_dispatch_agent_id": "VERIFY-1",
            "status": "running",
            "finding_slugs": [],
            "associated_finding_slugs": linked,
        }

    monkeypatch.setattr(AssessmentClient, "get", get)
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

    _run_cli(
        engagement, "proof-run", "start", "verify-va-047", "--kind", "web", "--agent-id",
        "VERIFY-1", "--for-finding", "VA-047", "--for-finding", "VA-048",
    )

    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "running"
    assert printed["associated_finding_slugs"] == ["VA-047", "VA-048"]
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
        _run_cli(
            engagement, "proof-run", "start", "verify-va-049", "--kind", "code", "--agent-id",
            "VERIFY-1", "--for-finding", "VA-049",
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "VA-049" in stderr
    assert "bind-author" in stderr


# ── The way out of a terminal run ────────────────────────────────────────────
#
# Importing more sources than were read seals a run `partial`, and partial is
# terminal: further source reads, new receipts, and terminal finding decisions
# are all refused. `--resume-from` is the architecture's answer — the child
# inherits the parent's sources, its source reads, and every receipt binding
# that is still healthy, and a new receipt may bind a source read from anywhere
# in the lineage, so the child re-binds and completes. It carried no help text
# at all, so the wall was discoverable and the door was not.


def _proof_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    proof_run.register(sub)
    return parser


def _start_option_help(option: str) -> str:
    sub_action = next(
        action
        for action in _proof_run_parser()._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    start = next(
        action
        for action in sub_action.choices["proof-run"]._actions
        if isinstance(action, argparse._SubParsersAction)
    ).choices["start"]
    return next(
        (action.help or "")
        for action in start._actions
        if option in action.option_strings
    )


def test_resume_from_help_names_the_recovery_it_performs() -> None:
    """A terminal run's only continuation must say what it inherits."""
    help_text = _start_option_help("--resume-from").lower()

    assert help_text.strip(), "--resume-from carries no help at all"
    assert "terminal" in help_text
    assert "partial" in help_text
    assert "source read" in help_text
    assert "receipt" in help_text
    # Naming --for-finding matters: the inherited bindings do NOT carry the
    # parent's finding associations, so a resumed run needs its own.
    assert "--for-finding" in help_text


def test_proof_run_start_reports_the_created_run_when_the_association_fails(
    tmp_path, monkeypatch, capsys
) -> None:
    """A created-but-unassociated run is recoverable, and the refusal says how.

    The run exists and has cost target traffic by the time the association is
    attempted, so swallowing the id would strand it: nothing names the run to
    link, and a fresh start would duplicate it.
    """
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        _findings_get({"VA-052": {"slug": "VA-052", "provenance": {"agent_id": "HUNT-1"}}}),
    )

    def post(_client, endpoint: str, payload: dict):
        if endpoint.endswith("/links"):
            raise AssessError("HTTP 409:\n{\"detail\": \"finding link conflict\"}")
        return {
            "id": 77,
            "run_uuid": payload["run_uuid"],
            "run_kind": payload["run_kind"],
            "run_purpose": payload["run_purpose"],
            "producer_dispatch_id": 11,
            "producer_dispatch_agent_id": payload["producer_dispatch_agent_id"],
            "status": "running",
        }

    monkeypatch.setattr(AssessmentClient, "post", post)

    with pytest.raises(SystemExit) as exc:
        _run_cli(
            engagement, "proof-run", "start", "verify-va-052", "--kind", "web", "--agent-id",
            "VERIFY-1", "--for-finding", "VA-052",
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "77" in stderr
    assert "VA-052" in stderr
    assert "finding link VA-052 --link-kind proof_run" in stderr
    assert "--target-kind assessment_run --target-id 77" in stderr
