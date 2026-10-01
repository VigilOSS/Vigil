from __future__ import annotations

import contextlib
import json
from types import SimpleNamespace

import pytest

from assess.commands import (
    artifact,
    code_classify,
    code_record_analysis,
    code_record_fuzz_campaign,
    code_record_fuzz_decision,
    code_record_modules,
    code_record_threat_model,
    code_record_variant_check,
    code_index_sync,
    http_cmd,
    ingest_httpx,
    record_finding,
    record_surface,
)
from assess.lib.client import AssessmentClient, AssessError, require_write_result


class _ContextClient:
    def __init__(self, response: dict) -> None:
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def close(self) -> None:
        return None


def _config(_engagement_dir):
    return SimpleNamespace(
        base_url="http://backend",
        engagement_key="eng",
        engagement_dir=_engagement_dir,
    )


def _strict_record_client(monkeypatch, module, response: dict):
    client = _ContextClient(response)
    client.post = lambda _endpoint, _payload: client.response
    monkeypatch.setattr(module, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(module, "load_config", _config)
    return client


@pytest.mark.parametrize("returned", [True, 1.0], ids=["bool", "float"])
def test_require_write_result_expected_integer_is_type_strict(returned) -> None:
    with pytest.raises(AssessError, match="durable result.*count"):
        require_write_result(
            {"count": returned},
            operation="record exact count",
            expected={"count": 1},
        )


def test_http_policy_set_rejects_response_that_does_not_echo_requested_state(
    monkeypatch,
) -> None:
    client = _ContextClient({"enabled": False})
    client.put = lambda _endpoint, _payload: client.response
    monkeypatch.setattr(http_cmd, "_client", lambda _args: client)

    with pytest.raises(AssessError, match="update capture policy") as exc:
        http_cmd._run_policy_set(
            SimpleNamespace(
                enabled=True,
                capture_request_bodies=None,
                capture_response_bodies=None,
                max_body_bytes=None,
                content_type_allow=None,
                content_type_deny=None,
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_artifact_register_rejects_response_for_a_different_path(
    monkeypatch,
) -> None:
    client = _ContextClient(
        {"id": 7, "relative_path": "notes/other.md", "present": True}
    )
    client.post = lambda _endpoint, _payload: client.response
    monkeypatch.setattr(artifact, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(artifact, "load_config", _config)

    with pytest.raises(AssessError, match="register artifact") as exc:
        artifact._run_register(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                paths=["notes/requested.md"],
                paths_file="",
                kind="note",
                media_type="text/markdown",
                agent_id="",
                agent_role="",
                command_run_id=None,
                finding="",
                as_json=True,
            )
        )

    assert "do not retry automatically" in str(exc.value)


@pytest.mark.parametrize(
    "response",
    [
        {"id": 9, "kind": "different", "payload": {"host": "a.example"}},
        {"id": 9, "kind": "scope", "payload": {"host": "b.example"}},
    ],
    ids=["wrong-kind", "wrong-payload"],
)
def test_record_decision_requires_requested_kind_and_payload(
    monkeypatch, response
) -> None:
    client = AssessmentClient("http://backend", "eng")
    monkeypatch.setattr(client, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(AssessError, match="record dispatch decision") as exc:
        client.record_decision(
            {"kind": "scope", "payload": {"host": "a.example"}}
        )

    assert "do not retry automatically" in str(exc.value)


def test_record_finding_rejects_response_bound_to_a_different_slug(
    monkeypatch, tmp_path, capsys
):
    events: list[dict] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            if endpoint == "dispatches/FINDING-AUTHOR-1":
                return {"agent_id": "FINDING-AUTHOR-1"}
            return []

        def post(self, endpoint: str, _payload: dict):
            assert endpoint == "findings"
            return {"finding": {"slug": "VA-999", "title": "wrong row"}}

        def post_event(self, payload: dict):
            events.append(payload)

    payload_file = tmp_path / "finding.json"
    payload_file.write_text(
        json.dumps(
            {
                "slug": "VA-100",
                "title": "Expected finding",
                "defect_family": "access-control",
                "canonical_location": "https://target.example/orders/1",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(record_finding, "AssessmentClient", FakeClient)
    monkeypatch.setattr(record_finding, "load_config", _config)
    monkeypatch.setattr(record_finding, "collect_validation_errors", lambda *_args: [])
    monkeypatch.setattr(record_finding, "file_lock", lambda *_args: contextlib.nullcontext())
    monkeypatch.setattr(
        record_finding,
        "finding_lock_path",
        lambda *_args: str(tmp_path / "finding.lock"),
    )

    with pytest.raises(SystemExit) as exc:
        record_finding.run(
            SimpleNamespace(
                agent_name="analyst",
                json_file=str(payload_file),
                engagement_dir=str(tmp_path),
                update_slug="",
                allow_remint=False,
                allow_unindexed_evidence=True,
                quiet=False,
                agent_id="FINDING-AUTHOR-1",
            )
        )

    assert exc.value.code == 1
    error = capsys.readouterr().err
    assert "canonical finding VA-100" in error
    assert "write may have committed" in error
    assert "do not retry automatically" in error
    assert events == []


def test_code_record_analysis_rejects_response_without_queue_result_identity(
    monkeypatch, tmp_path
):
    source = tmp_path / "analysis.json"
    source.write_text(
        json.dumps(
            {
                "queue_item_id": 7,
                "agent_name": "hunter-1",
                    "lease_token": "lease-1",
                    "disposition": "clean",
                    "reviewed_spans": [
                        {"file_id": 11, "start_line": 1, "end_line": 1}
                    ],
            }
        ),
        encoding="utf-8",
    )
    _strict_record_client(
        monkeypatch, code_record_analysis, {"message": "accepted"}
    )
    monkeypatch.setattr(
        code_record_analysis,
        "write_json_snapshot",
        lambda *_args, **_kwargs: tmp_path / "audit.json",
    )

    with pytest.raises(AssessError, match="record code analysis result") as exc:
        code_record_analysis.run(
            SimpleNamespace(analysis_json=str(source), engagement_dir=tmp_path)
        )

    assert "do not retry automatically" in str(exc.value)


@pytest.mark.parametrize(
    ("submitted_anchors", "returned_anchors", "binding_status"),
    [
        (
            {
                "callable_refs": [],
                "reviewed_spans": [
                    {"file_id": 11, "start_line": 1, "end_line": 1}
                ],
            },
            {
                "callable_refs": [],
                "reviewed_spans": [
                    {
                        "file_id": 11,
                        "file_path": "src/a.py",
                        "start_line": 1,
                        "end_line": 2,
                        "label": "",
                    }
                ],
            },
            "source_span",
        ),
        (
            {
                "callable_refs": [
                    {
                        "file_id": 11,
                        "name": "parse",
                        "qualified_name": "parse",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ],
                "reviewed_spans": [],
            },
            {
                "callable_refs": [
                    {
                        "callable_key": "a" * 64,
                        "file_id": 11,
                        "file_path": "src/a.py",
                        "name": "other",
                        "qualified_name": "other",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ],
                "reviewed_spans": [],
            },
            "structural",
        ),
        (
            {
                "callable_refs": [],
                "reviewed_spans": [
                    {"file_id": 11, "start_line": 1, "end_line": 1}
                ],
            },
            {
                "callable_refs": [],
                "reviewed_spans": [
                    {
                        "file_id": 11,
                        "file_path": "src/a.py",
                        "start_line": 1,
                        "end_line": 1,
                        "label": "",
                    }
                ],
            },
            "legacy_unbound",
        ),
    ],
    ids=["reviewed-span-mismatch", "callable-ref-mismatch", "binding-status-mismatch"],
)
def test_code_record_analysis_rejects_noncanonical_source_receipt_response(
    monkeypatch,
    tmp_path,
    submitted_anchors,
    returned_anchors,
    binding_status,
) -> None:
    submitted = {
        "queue_item_id": 7,
        "file_id": 11,
        "agent_name": "hunter-1",
        "lease_token": "lease-1",
        "disposition": "clean",
        "receipt_kind": "file",
        **submitted_anchors,
    }
    source = tmp_path / "analysis.json"
    source.write_text(json.dumps(submitted), encoding="utf-8")
    response = {
        "id": 9,
        "queue_item_id": 7,
        "file_id": 11,
        "agent_name": "hunter-1",
        "lease_token": "lease-1",
        "disposition": "clean",
        "receipt_kind": "file",
        "receipt_binding_status": binding_status,
        **returned_anchors,
    }
    _strict_record_client(monkeypatch, code_record_analysis, response)
    monkeypatch.setattr(
        code_record_analysis,
        "write_json_snapshot",
        lambda *_args, **_kwargs: tmp_path / "audit.json",
    )

    with pytest.raises(AssessError, match="record code analysis source receipt") as exc:
        code_record_analysis.run(
            SimpleNamespace(analysis_json=str(source), engagement_dir=tmp_path)
        )

    assert "do not retry automatically" in str(exc.value)


def test_code_record_threat_model_rejects_response_without_bound_repo_identity(
    monkeypatch, tmp_path
):
    source = tmp_path / "threat-model.json"
    source.write_text(json.dumps({"assets": []}), encoding="utf-8")
    _strict_record_client(
        monkeypatch, code_record_threat_model, {"message": "accepted"}
    )

    with pytest.raises(AssessError, match="record code threat model") as exc:
        code_record_threat_model.run(
            SimpleNamespace(
                repo_id="7",
                repo_generation=3,
                source_manifest_digest="a" * 64,
                threat_model_json=str(source),
                engagement_dir=tmp_path,
            )
        )

    assert "do not retry automatically" in str(exc.value)


@pytest.mark.parametrize(
    ("module", "argument", "payload", "operation"),
    [
        (
            code_record_variant_check,
            "receipt_json",
            {
                "dispatch_id": 17,
                "file_id": 42,
                "repo_id": 7,
                "repo_generation": 3,
                "source_manifest_digest": "a" * 64,
                "file_sha256": "b" * 64,
                "parent_finding_slugs": ["VF-001"],
                "status": "completed",
                "evidence_ref": "artifacts/variant.json",
                "rationale": "Reviewed every candidate variant.",
            },
            "record code variant check",
        ),
        (
            code_record_fuzz_decision,
            "decision_json",
            {
                "repo_id": 7,
                "repo_generation": 3,
                "source_manifest_digest": "a" * 64,
                "decision": "required",
                "target_ids": ["parser"],
                "evidence_ref": "artifacts/fuzz-decision.json",
                "rationale": "Native parser accepts attacker-controlled input.",
            },
            "record code fuzz decision",
        ),
        (
            code_record_fuzz_campaign,
            "receipt_json",
            {
                "dispatch_id": 17,
                "repo_id": 7,
                "repo_generation": 3,
                "source_manifest_digest": "a" * 64,
                "target_id": "parser",
                "covered_finding_slugs": ["VF-001"],
                "engine": "libfuzzer",
                "sanitizers": ["address"],
                "run_budget_seconds": 60,
                "executions": 100,
                "outcome": "completed_no_crash",
                "crash_count": 0,
                "triage_summary": "No sanitizer crash observed.",
                "evidence_ref": "artifacts/fuzz-campaign.json",
                "rationale": "Exercised the current parser entrypoint.",
            },
            "record code fuzz campaign",
        ),
    ],
    ids=["variant-check", "fuzz-decision", "fuzz-campaign"],
)
def test_code_receipt_commands_reject_response_without_bound_identity(
    monkeypatch, tmp_path, module, argument, payload, operation
):
    source = tmp_path / f"{argument}.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    _strict_record_client(monkeypatch, module, {"message": "accepted"})

    with pytest.raises(AssessError, match=operation) as exc:
        module.run(
            SimpleNamespace(**{argument: str(source)}, engagement_dir=tmp_path)
        )

    assert "do not retry automatically" in str(exc.value)


def test_code_classify_rejects_success_object_without_result_counts(
    monkeypatch, tmp_path
):
    payload_file = tmp_path / "classifications.json"
    payload_file.write_text(
        json.dumps(
            [
                {
                    "file_id": 7,
                    "classification": "medium",
                    "role": "helper",
                    "slot_types": [],
                    "analysis_priority": 40,
                }
            ]
        ),
        encoding="utf-8",
    )

    client = _ContextClient({"message": "accepted"})
    client.post = lambda _endpoint, _payload: client.response
    monkeypatch.setattr(code_classify, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(code_classify, "load_config", _config)

    with pytest.raises(AssessError, match="classify code files") as exc:
        code_classify.run(
            SimpleNamespace(
                classifications_json=str(payload_file),
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_code_index_sync_rejects_response_without_bound_repo_identity(
    monkeypatch, tmp_path
):
    payload = {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "structural_input_digest": "b" * 64,
        "structural_index_schema": "vigil.structural-index/v1",
        "updates": [{"file_id": 11}],
    }
    client = _ContextClient({"updated": 1})
    client.get = lambda _endpoint: [{"id": 7}]
    client.post = lambda _endpoint, _payload, **_kwargs: client.response
    monkeypatch.setattr(code_index_sync, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(code_index_sync, "load_config", _config)
    monkeypatch.setattr(code_index_sync, "_load_manifest", lambda _path: {})
    monkeypatch.setattr(
        code_index_sync,
        "_resolve_per_repo_manifests",
        lambda _top, _path, **_filters: [("repo", {"repo_id": 7, "repo_key": "repo"})],
    )
    monkeypatch.setattr(
        code_index_sync,
        "_prepare_repo_payload",
        lambda _client, _backend, _manifest, _root: payload,
    )

    with pytest.raises(AssessError, match="sync structural metadata") as exc:
        code_index_sync.run(
            SimpleNamespace(
                manifest=str(tmp_path / "manifest.json"),
                index_dir=str(tmp_path / "index"),
                repo_id=None,
                repo_key=None,
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_ingest_httpx_rejects_success_object_without_upsert_count(tmp_path):
    results_file = tmp_path / "httpx.jsonl"
    results_file.write_text(
        json.dumps(
            {
                "input": "https://target.example",
                "status_code": 200,
                "host": "192.0.2.4",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    client = _ContextClient({"message": "accepted"})
    client.post = lambda _endpoint, _payload: client.response

    with pytest.raises(AssessError, match="upsert host liveness") as exc:
        ingest_httpx.ingest_httpx_results(
            results_file,
            cfg=_config(tmp_path),
            client=client,
        )

    assert "do not retry automatically" in str(exc.value)


def test_http_har_import_rejects_success_object_without_import_count(
    monkeypatch, tmp_path
):
    har_file = tmp_path / "flows.har"
    har_file.write_text(json.dumps({"log": {"entries": []}}), encoding="utf-8")
    client = _ContextClient({"message": "accepted"})
    client.post = lambda _endpoint, _payload: client.response
    monkeypatch.setattr(http_cmd, "_client", lambda _args: client)

    with pytest.raises(AssessError, match="import HAR flows") as exc:
        http_cmd._run_import_har(
            SimpleNamespace(file=str(har_file), as_json=False)
        )

    assert "do not retry automatically" in str(exc.value)


def test_record_surface_requires_canonical_row_identity(monkeypatch, tmp_path):
    client = _ContextClient(
        {
            "surface_type": "api_documentation",
            "target_descriptor": "https://target.example",
        }
    )
    client.post = lambda _endpoint, _payload: client.response
    client.post_event = lambda _payload: {"id": 1}
    monkeypatch.setattr(record_surface, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(record_surface, "load_config", _config)

    with pytest.raises(AssessError, match="record surface") as exc:
        record_surface.run(
            SimpleNamespace(
                type="api_documentation",
                target="https://target.example",
                source="analyst",
                rationale="discovered",
                evidence_ref="",
                status="discovered",
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)


@pytest.mark.parametrize(
    ("method", "args", "response"),
    [
        ("record_dispatch", ({"agent_id": "worker-1"},), {"status": "running"}),
        ("update_dispatch", ("worker-1", {"status": "closed"}), {"id": 3}),
        ("record_handoff", ({"agent_id": "worker-1"},), {"status": "complete"}),
        ("update_handoff", ("worker-1", {"summary": "done"}), {"id": 4}),
        ("record_decision", ({"decision_type": "scope"},), {"status": "recorded"}),
        ("update_decision", (8, {"status": "applied"}), {"id": 9}),
    ],
)
def test_dispatch_write_helpers_require_canonical_row_identity(
    monkeypatch, method, args, response
):
    client = AssessmentClient("http://backend", "eng")
    monkeypatch.setattr(client, "post", lambda *_args, **_kwargs: response)
    monkeypatch.setattr(client, "patch", lambda *_args, **_kwargs: response)

    with pytest.raises(AssessError, match="write may have committed"):
        getattr(client, method)(*args)


@pytest.mark.parametrize(
    "response",
    [
        [],
        [{"id": 1, "repo_id": 7, "module_key": "different"}],
        [{"id": True, "repo_id": 7, "module_key": "auth_login"}],
    ],
    ids=["empty", "wrong-key", "bool-id"],
)
def test_code_record_modules_rejects_noncanonical_receipt(
    response, monkeypatch, tmp_path
) -> None:
    source = tmp_path / "modules.json"
    source.write_text(
        json.dumps([{"module_key": "auth_login", "name": "Authentication"}]),
        encoding="utf-8",
    )
    client = _ContextClient(response)
    client.get = lambda _endpoint: []
    client.post = lambda _endpoint, _payload: response
    monkeypatch.setattr(code_record_modules, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(code_record_modules, "load_config", _config)

    with pytest.raises(AssessError, match="record code modules.*may have committed") as exc:
        code_record_modules.run(
            SimpleNamespace(
                repo_id="7",
                modules_json=str(source),
                engagement_dir=str(tmp_path),
            )
        )

    assert "do not retry automatically" in str(exc.value)
