"""Operator-facing contract for generic assessment-run accounting."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from assess import cli
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient


SHA = "a" * 64


def _engagement(tmp_path: Path) -> Path:
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def _source(source_id: int = 31, *, path: str = "src/main.py") -> dict:
    return {
        "id": source_id,
        "run_id": 17,
        "target_key": "service-a",
        "declared_root": ".",
        "path": path,
        "content_sha256": SHA,
        "byte_size": 120,
        "line_count": 8,
        "encoding": "utf-8",
        "inventory_status": "included",
        "exclusion_reason": "",
        "parser_status": "parsed",
        "parser_error": "",
    }


def _source_read(read_id: int = 41) -> dict:
    return {
        "id": read_id,
        "run_id": 17,
        "source_id": 31,
        "dispatch_id": 4,
        "dispatch_agent_id": "HUNT-1",
        "attempt": 1,
        "byte_start": 0,
        "byte_end": 120,
        "line_start": 1,
        "line_end": 8,
        "proof_receipt_id": None,
        "source_sha256": SHA,
        "source_path": "src/main.py",
        "target_key": "service-a",
        "encoding": "utf-8",
    }


def _obligation(obligation_id: int = 51, *, status: str = "open") -> dict:
    return {
        "id": obligation_id,
        "run_id": 17,
        "identity_key": "flow:input-to-open",
        "obligation_kind": "cross_file_flow",
        "object_type": "source",
        "object_key": "service-a:src/main.py",
        "hard": True,
        "status": status,
        "resolution": "reviewed" if status != "open" else "",
        "proof_receipt_ids": [71] if status != "open" else [],
    }


def _candidate(candidate_id: int = 61, *, state: str = "open") -> dict:
    return {
        "id": candidate_id,
        "run_id": 17,
        "identity_key": "candidate:path-traversal:main:7",
        "target_key": "service-a",
        "source_id": 31,
        "source_anchor": "src/main.py:7",
        "vulnerability_family": "CWE-22",
        "hypothesis": "user input reaches open",
        "originating_result_id": None,
        "dispatch_id": 4,
        "proof_receipt_ids": [71] if state != "open" else [],
        "state": state,
        "finding_slug": "VA-047" if state == "promoted" else "",
    }


def _tool_signal() -> dict:
    return {
        "id": 81,
        "run_id": 17,
        "identity_key": "asan:main:7",
        "signal_kind": "reproducible_crash",
        "dispatch_id": 4,
        "target_key": "service-a",
        "source_id": 31,
        "source_anchor": "src/main.py:7",
        "vulnerability_family": "memory-safety",
        "hypothesis": "input reaches unsafe copy",
        "observed_signature": "ASan heap overflow",
        "exact_input_sha256": SHA,
        "command_run_id": 91,
        "proof_receipt_ids": [71],
        "candidate_id": 61,
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _discovery_pass() -> dict:
    return {
        "id": 82,
        "run_id": 17,
        "identity_key": "discovery:pass-1",
        "dispatch_id": 4,
        "frontier_identity_sha256": SHA,
        "terminal_reason": "frontier_exhausted",
        "candidate_identity_keys": ["candidate:path-traversal:main:7"],
        "candidate_delta": 1,
        "proof_receipt_ids": [71],
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _code_receipt() -> dict:
    return {
        "id": 83,
        "run_id": 17,
        "receipt_kind": "variant_check",
        "receipt_id": 101,
        "target_key": "service-a",
        "obligation_id": 51,
        "candidate_ids": [61],
        "signal_ids": [],
        "proof_receipt_ids": [71],
        "obligation_status": "resolved",
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _audit_receipt(receipt_id: int = 71, *, kind: str = "command") -> dict:
    return {
        "id": receipt_id,
        "audit_run_id": 17,
        "run_id": 17,
        "origin_run_id": 17,
        "producer_dispatch_id": 4,
        "producer_dispatch_agent_id": "HUNT-1",
        "producer_dispatch_agent_role": "code-vuln-hunter",
        "evidence_kind": kind,
        "expected_result": "expected",
        "observed_result": "observed",
        "artifact_id": 81 if kind != "command" else None,
        "source_read_id": None,
        "command_run_id": 91 if kind == "command" else None,
        "artifact_relative_path": "evidence/event.json" if kind != "command" else "",
        "evidence_sha256": SHA,
        "evidence_health": "healthy",
        "redaction_status": "raw",
        "derivative_of_receipt_id": None,
        "raw_receipt_id": receipt_id,
        "tombstone_reason": "",
        "created_at": "2026-09-09T12:00:00+00:00",
        "command": {
            "id": 91,
            "run_uuid": "command-91",
            "command": "python -m compileall src",
            "argv": ["python", "-m", "compileall", "src"],
            "status": "completed",
        } if kind == "command" else None,
    }


def _decision_event(event_id: str = "candidate:81") -> dict:
    return {
        "id": event_id,
        "audit_run_id": 17,
        "object_type": "candidate",
        "object_id": 61,
        "origin_run_id": 17,
        "from_status": "open",
        "to_status": "rejected",
        "detail": "decisive contrary evidence",
        "proof_receipt_ids": [71],
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _write_case(case: str) -> tuple[list[str], str, str, dict, object]:
    if case == "sources-import":
        source = {key: value for key, value in _source().items() if key not in {"id", "run_id"}}
        payload = {"sources": [source]}
        return ["sources", "import", "17"], "post", "assessment-runs/17/sources", payload, [_source()]
    if case == "obligation-record":
        payload = {key: value for key, value in _obligation().items() if key not in {"id", "run_id"}}
        return ["obligation", "record", "17"], "post", "assessment-runs/17/obligations", payload, _obligation()
    if case == "obligation-update":
        payload = {"status": "resolved", "resolution": "reviewed", "proof_receipt_ids": [71]}
        return ["obligation", "update", "17", "51"], "patch", "assessment-runs/17/obligations/51", payload, _obligation(status="resolved")
    if case == "candidate-record":
        payload = {key: value for key, value in _candidate().items() if key not in {"id", "run_id", "dispatch_id"}}
        payload["dispatch_agent_id"] = "HUNT-1"
        return ["candidate", "record", "17"], "post", "assessment-runs/17/candidates", payload, _candidate()
    if case == "candidate-update":
        payload = {"state": "promoted", "reason": "confirmed", "proof_receipt_ids": [71], "finding_slug": "VA-047"}
        return ["candidate", "update", "17", "61"], "patch", "assessment-runs/17/candidates/61", payload, _candidate(state="promoted")
    if case == "tool-signal-record":
        payload = {
            **_tool_signal(),
            "dispatch_agent_id": "HUNT-1",
        }
        for field in ("id", "run_id", "dispatch_id", "candidate_id", "record_sha256", "created_at"):
            payload.pop(field)
        return ["tool-signal", "record", "17"], "post", "assessment-runs/17/tool-signals", payload, _tool_signal()
    if case == "discovery-pass-record":
        payload = {**_discovery_pass(), "dispatch_agent_id": "HUNT-1"}
        for field in ("id", "run_id", "dispatch_id", "candidate_delta", "record_sha256", "created_at"):
            payload.pop(field)
        return ["discovery-pass", "record", "17"], "post", "assessment-runs/17/discovery-passes", payload, _discovery_pass()
    if case == "code-receipt-record":
        payload = {
            key: value
            for key, value in _code_receipt().items()
            if key not in {"id", "run_id", "obligation_status", "record_sha256", "created_at"}
        }
        return ["code-receipt", "record", "17"], "post", "assessment-runs/17/code-receipts", payload, _code_receipt()
    raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    [
        "sources-import",
        "obligation-record",
        "obligation-update",
        "candidate-record",
        "candidate-update",
        "tool-signal-record",
        "discovery-pass-record",
        "code-receipt-record",
    ],
)
def test_run_audit_writes_json_documents_and_validates_bound_receipts(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    argv, method, endpoint, payload, response = _write_case(case)
    payload_path = tmp_path / f"{case}.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def write(_client, requested_endpoint: str, requested_payload: dict):
        calls.append((method, requested_endpoint, requested_payload))
        return response

    monkeypatch.setattr(AssessmentClient, method, write)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            *argv,
            str(payload_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert output == response
    assert calls == [(method, endpoint, payload)]


@pytest.mark.parametrize(
    "case",
    [
        "sources-import",
        "obligation-record",
        "obligation-update",
        "candidate-record",
        "candidate-update",
        "tool-signal-record",
        "discovery-pass-record",
        "code-receipt-record",
    ],
)
def test_run_audit_writes_reject_malformed_success_without_retrying(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    argv, method, _endpoint, payload, _response = _write_case(case)
    payload_path = tmp_path / f"{case}.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, method, lambda *_args, **_kwargs: {"id": True})

    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "run-audit",
                *argv,
                str(payload_path),
            ]
        )

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "write may have committed" in stderr
    assert "do not retry automatically" in stderr


def test_source_inventory_import_chunks_more_than_one_api_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    sources = [
        {
            key: value
            for key, value in _source(
                source_id=index + 1,
                path=f"src/generated-{index:05d}.py",
            ).items()
            if key not in {"id", "run_id"}
        }
        for index in range(10_001)
    ]
    payload_path = tmp_path / "large-inventory.json"
    payload_path.write_text(json.dumps({"sources": sources}), encoding="utf-8")
    batch_sizes: list[int] = []
    next_id = 1
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def post(_client, endpoint: str, payload: dict):
        nonlocal next_id
        assert endpoint == "assessment-runs/17/sources"
        batch = payload["sources"]
        batch_sizes.append(len(batch))
        response = [
            {**source, "id": next_id + index, "run_id": 17}
            for index, source in enumerate(batch)
        ]
        next_id += len(batch)
        return response

    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            "sources",
            "import",
            "17",
            str(payload_path),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert len(output) == 10_001
    assert batch_sizes == [1000] * 10 + [1]


def test_source_inventory_commitment_is_local_exact_and_per_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    first = {
        key: value
        for key, value in _source(path="src/main.py").items()
        if key not in {"id", "run_id"}
    }
    second = {**first, "target_key": "shared-library", "path": "src/lib.py"}
    payload_path = tmp_path / "inventory.json"
    payload_path.write_text(
        json.dumps({"sources": [second, first]}), encoding="utf-8"
    )
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda *_args, **_kwargs: pytest.fail("commitment must not call the backend"),
    )

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            "sources",
            "commitment",
            str(payload_path),
        ]
    )

    commitments = json.loads(capsys.readouterr().out)
    assert [item["target_key"] for item in commitments] == [
        "service-a",
        "shared-library",
    ]
    assert all(item["inventory_commitment_version"] == "v1" for item in commitments)
    assert all(item["inventory_count"] == 1 for item in commitments)
    assert all(
        len(item["inventory_digest"]) == 64
        and set(item["inventory_digest"]) <= set("0123456789abcdef")
        for item in commitments
    )


def test_run_audit_source_read_delivers_verified_bytes_before_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    source_root = engagement / "repo"
    source_path = source_root / "src" / "main.py"
    source_path.parent.mkdir(parents=True)
    content = b"first\nsecond\nthird\n"
    source_path.write_bytes(content)
    source = {
        **_source(),
        "declared_root": "repo",
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "line_count": 3,
    }
    receipt = {
        **_source_read(),
        "byte_start": 6,
        "byte_end": 13,
        "line_start": 2,
        "line_end": 2,
        "source_sha256": source["content_sha256"],
    }
    delivered = tmp_path / "delivered.py"
    calls: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        calls.append(("get", endpoint, None))
        return {
            "items": [source],
            "total": 1,
            "offset": 0,
            "limit": 1000,
            "has_more": False,
        }

    def post(_client, endpoint: str, payload: dict):
        assert delivered.read_bytes() == b"second\n"
        calls.append(("post", endpoint, payload))
        return receipt

    monkeypatch.setattr(AssessmentClient, "get", get)
    monkeypatch.setattr(AssessmentClient, "post", post)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            "source-read",
            "record",
            "17",
            "31",
            str(source_path),
            "--agent-id",
            "HUNT-1",
            "--attempt",
            "1",
            "--byte-start",
            "6",
            "--byte-end",
            "13",
            "--output",
            str(delivered),
        ]
    )

    assert json.loads(capsys.readouterr().out) == receipt
    assert calls == [
        ("get", "assessment-runs/17/sources?limit=1000&offset=0", None),
        (
            "post",
            "assessment-runs/17/source-reads",
            {
                "source_id": 31,
                "dispatch_agent_id": "HUNT-1",
                "attempt": 1,
                "byte_start": 6,
                "byte_end": 13,
                "line_start": 2,
                "line_end": 2,
                "proof_receipt_id": None,
            },
        ),
    ]


def test_run_audit_source_read_defaults_to_streaming_content_on_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    source_path = engagement / "main.ps1"
    content = "Write-Output 'ready'\n".encode("utf-16")
    source_path.write_bytes(content)
    source = {
        **_source(path="main.ps1"),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "line_count": 1,
        "encoding": "utf-16",
    }
    receipt = {
        **_source_read(),
        "byte_end": len(content),
        "line_end": 1,
        "source_sha256": source["content_sha256"],
        "source_path": "main.ps1",
        "encoding": "utf-16",
    }
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {
            "items": [source],
            "total": 1,
            "offset": 0,
            "limit": 1000,
            "has_more": False,
        },
    )
    monkeypatch.setattr(AssessmentClient, "post", lambda *_args: receipt)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            "source-read",
            "record",
            "17",
            "31",
            str(source_path),
            "--agent-id",
            "HUNT-1",
            "--attempt",
            "1",
        ]
    )

    captured = capsys.readouterr()
    assert captured.out == "Write-Output 'ready'\n"
    assert '"id": 41' in captured.err


@pytest.mark.parametrize("failure", ["digest", "outside-root", "not-included"])
def test_run_audit_source_read_fails_closed_before_recording_untrusted_files(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    engagement_path = tmp_path / "engagement"
    engagement_path.mkdir()
    engagement = _engagement(engagement_path)
    root = engagement / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside\n")
    source_path = root / "main.py"
    source_path.write_bytes(b"inside\n")
    expected_path = source_path
    expected_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if failure == "digest":
        expected_sha = "0" * 64
    elif failure == "outside-root":
        source_path.unlink()
        os.symlink(outside, source_path)
        expected_path = source_path
    source = {
        **_source(path="main.py"),
        "declared_root": "repo",
        "content_sha256": expected_sha,
        "byte_size": len(b"inside\n"),
        "line_count": 1,
    }
    if failure == "not-included":
        source["inventory_status"] = "excluded"
        source["exclusion_reason"] = "generated"
    posts: list[dict] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {
            "items": [source],
            "total": 1,
            "offset": 0,
            "limit": 1000,
            "has_more": False,
        },
    )
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda _client, _endpoint, payload: posts.append(payload),
    )

    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "run-audit",
                "source-read",
                "record",
                "17",
                "31",
                str(expected_path),
                "--agent-id",
                "HUNT-1",
                "--attempt",
                "1",
            ]
        )

    assert excinfo.value.code == 1
    assert posts == []
    assert "source-read record" in capsys.readouterr().err


def test_run_audit_source_read_malformed_receipt_warns_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    source_path = engagement / "main.py"
    content = b"pass\n"
    source_path.write_bytes(content)
    source = {
        **_source(path="main.py"),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "line_count": 1,
    }
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {
            "items": [source],
            "total": 1,
            "offset": 0,
            "limit": 1000,
            "has_more": False,
        },
    )
    monkeypatch.setattr(AssessmentClient, "post", lambda *_args: {"id": True})

    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "run-audit",
                "source-read",
                "record",
                "17",
                "31",
                str(source_path),
                "--agent-id",
                "HUNT-1",
                "--attempt",
                "1",
            ]
        )

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == "pass\n"
    assert "write may have committed" in captured.err
    assert "do not retry automatically" in captured.err


@pytest.mark.parametrize(
    ("family", "row"),
    [
        ("sources", _source()),
        ("source-read", _source_read()),
        ("obligation", _obligation()),
        ("candidate", _candidate()),
        ("commands", _audit_receipt()),
        ("observed-events", _audit_receipt(kind="http_exchange")),
        ("decision-history", _decision_event()),
    ],
)
def test_run_audit_lists_are_bounded_with_honest_continuation(
    family: str,
    row: dict,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    engagement = _engagement(tmp_path)
    plural = {
        "sources": "sources",
        "source-read": "source-reads",
        "obligation": "obligations",
        "candidate": "candidates",
        "commands": "commands",
        "observed-events": "observed-events",
        "decision-history": "decision-history",
    }[family]
    requested: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        return {"items": [row], "total": 2, "offset": 0, "limit": 1, "has_more": True}

    monkeypatch.setattr(AssessmentClient, "get", get)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            family,
            "list",
            "17",
            "--limit",
            "1",
        ]
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [row]
    assert "continue with `vigil assess run-audit" in captured.err
    assert requested == [f"assessment-runs/17/{plural}?limit=1&offset=0"]


@pytest.mark.parametrize(
    ("family", "rows"),
    [
        ("sources", [_source(), _source(32, path="src/other.py")]),
        ("source-read", [_source_read(), _source_read(42)]),
        ("obligation", [_obligation(), _obligation(52)]),
        ("candidate", [_candidate(), _candidate(62)]),
        ("commands", [_audit_receipt(), _audit_receipt(72)]),
        (
            "observed-events",
            [_audit_receipt(kind="http_exchange"), _audit_receipt(72, kind="oob_event")],
        ),
        ("decision-history", [_decision_event(), _decision_event("candidate:82")]),
    ],
)
def test_run_audit_lists_paginate_only_with_explicit_opt_in(
    family: str,
    rows: list[dict],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    engagement = _engagement(tmp_path)
    requested: list[str] = []
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        offset = int(endpoint.rsplit("offset=", 1)[1])
        return {
            "items": rows[offset : offset + 1],
            "total": 2,
            "offset": offset,
            "limit": 1,
            "has_more": offset + 1 < 2,
        }

    monkeypatch.setattr(AssessmentClient, "get", get)
    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "run-audit",
            family,
            "list",
            "17",
            "--limit",
            "1",
            "--paginate",
        ]
    )

    assert json.loads(capsys.readouterr().out) == rows
    assert [endpoint.rsplit("offset=", 1)[1] for endpoint in requested] == ["0", "1"]


def test_run_audit_candidate_history_and_comparison_are_identity_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    requested: list[str] = []
    history = [
        {
            "id": 81,
            "run_id": 17,
            "candidate_id": 61,
            "from_state": None,
            "to_state": "open",
            "reason": "created",
            "proof_receipt_ids": [],
            "created_at": "2026-09-09T12:00:00+00:00",
        }
    ]
    comparison = {
        "run_id": 17,
        "baseline_run_id": 11,
        "automatic_baseline": None,
        "target_compatible": True,
        "source_compatible": False,
        "classifications": {
            "new": ["new-candidate"],
            "persisting": [],
            "resolved": [],
            "unknown": ["baseline-only"],
        },
        "deterministic": True,
    }
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        if endpoint.endswith("/history"):
            return history
        return comparison

    monkeypatch.setattr(AssessmentClient, "get", get)
    cli.main(["--engagement-dir", str(engagement), "run-audit", "candidate", "history", "17", "61"])
    assert json.loads(capsys.readouterr().out) == history
    cli.main(["--engagement-dir", str(engagement), "run-audit", "compare", "17", "--baseline-run-id", "11"])
    assert json.loads(capsys.readouterr().out) == comparison
    assert requested == [
        "assessment-runs/17/candidates/61/history",
        "assessment-runs/17/comparison?baseline_run_id=11",
    ]


@pytest.mark.parametrize(
    ("argv", "response"),
    [
        (
            ["sources", "list", "17"],
            {"items": {}, "total": 0, "offset": 0, "limit": 50, "has_more": False},
        ),
        (
            ["candidate", "history", "17", "61"],
            [{"id": 81, "run_id": 18, "candidate_id": 61}],
        ),
        (
            ["compare", "17"],
            {"run_id": 18, "baseline_run_id": 11, "classifications": {}},
        ),
    ],
)
def test_run_audit_reads_reject_malformed_or_wrong_identity(
    argv: list[str],
    response: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--engagement-dir", str(engagement), "run-audit", *argv])

    assert excinfo.value.code == 1
    assert "run-audit" in capsys.readouterr().err


def test_run_audit_contract_documents_all_actions() -> None:
    contract = contracts.get_contract("run-audit candidate history")
    assert contract is not None
    text = " ".join(contract.author_supplied_fields)
    for action in (
        "sources commitment/import/list",
        "source-read record/list",
        "obligation record/update/list",
        "candidate record/update/list/history",
        "commands list",
        "observed-events list",
        "decision-history list",
        "compare",
    ):
        assert action in text
