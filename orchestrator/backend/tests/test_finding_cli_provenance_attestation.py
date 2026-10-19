"""The documented code-finding invocations store an ATTESTED binding.

``code_snapshot_attestation`` is what makes a stored binding worth anything:
the backend resolves ``provenance.agent_id`` to a real dispatch row, and a
binding that resolves to nothing reads ``unattested``. The documented CLI
invocations used to produce exactly that — ``finding verify`` had no way to name
the verifying dispatch at all, so every documented code verification stored a
binding with nothing behind it.

These run the real ``finding record`` / ``finding verify`` argparse surface
against the real backend, so the assertion is on durable state, not on a
request body.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from app import db as db_module
from tests.proof_fixtures import RUNTIME_PROOF_PLAN

_ENGAGEMENT_KEY = "2026-09-18-cli-attestation"
_DIGEST = "5c" * 32
_REPO_GENERATION = 4


def _load_assess_module(module_filename: str, module_name: str):
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = scripts_root / "assess" / "commands" / module_filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _BackendClient:
    """``AssessmentClient`` surface, served by the live FastAPI test client."""

    def __init__(self, test_client):
        self._client = test_client

    def __call__(self, *_args, **_kwargs) -> "_BackendClient":
        return self

    def __enter__(self) -> "_BackendClient":
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def close(self) -> None:
        return None

    def _url(self, endpoint: str) -> str:
        return f"/engagements/{_ENGAGEMENT_KEY}/assessment/{endpoint}"

    def get(self, endpoint: str):
        response = self._client.get(self._url(endpoint))
        if response.status_code == 404:
            from assess.lib.client import AssessError

            raise AssessError(f"HTTP 404\n{response.text}")
        assert response.status_code == 200, response.text
        return response.json()

    def post(self, endpoint: str, payload: dict):
        response = self._client.post(self._url(endpoint), json=payload)
        assert response.status_code in (200, 201), response.text
        return response.json()

    def post_event(self, _payload: dict) -> None:
        return None


def _write_engagement(engagements_dir: Path) -> Path:
    engagement_dir = engagements_dir / _ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": _ENGAGEMENT_KEY,
                "target": "https://example.com",
                "created_at": "2026-09-18T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "engagement_type": "code",
                "status": "in_progress",
                "current_phase": "code-verify",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    return engagement_dir


def _dispatch(client, agent_id: str, role: str) -> None:
    created = client.post(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": role,
            "task": "Review the parser for unbounded copies.",
            "status": "in-progress",
            "skills": "code-review",
        },
    )
    assert created.status_code in (200, 201), created.text


@pytest.fixture()
def code_engagement(client, isolate_settings):
    engagement_dir = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get("/engagements").status_code == 200
    _dispatch(client, "CH-1", "code-vuln-hunter")
    _dispatch(client, "VF-1", "code-vuln-verifier")
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (_ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )
        connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, repo_path, active_generation,
                source_manifest_digest, source_snapshot_quality
            ) VALUES (?, 'bound-repo', 'Bound repo', '/tmp/bound-repo', ?, ?, 'verified')
            """,
            (engagement_id, _REPO_GENERATION, _DIGEST),
        )
    return engagement_dir


def _finding_json(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "slug": "CH-001",
                "title": "Unchecked parser length",
                "severity": "high",
                "defect_family": "buffer-overflow",
                "root_cause_key": "parse_packet-length",
                "canonical_location": "file:src/parser.c:41",
                "summary": "An attacker-controlled length reaches a fixed-size copy.",
                "details": {
                    "evidence": "The copy length is attacker controlled.",
                    "impact": "Memory corruption",
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _args(module, argv: list[str], engagement_dir: Path):
    parser = argparse.ArgumentParser()
    module.register(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    args.engagement_dir = str(engagement_dir)
    return args


def _plan_file(engagement: Path) -> str:
    path = engagement / "next-test.json"
    path.write_text(json.dumps(RUNTIME_PROOF_PLAN), encoding="utf-8")
    return str(path)


def _stored(client, slug: str) -> dict:
    response = client.get(
        f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/{slug}"
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_recording_and_parking_a_code_finding_stores_an_attested_binding(
    client, code_engagement, monkeypatch, capsys
) -> None:
    module = _load_assess_module("record_finding.py", "attestation_record_finding")
    monkeypatch.setattr(module, "AssessmentClient", _BackendClient(client))
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://backend.test",
            engagement_key=_ENGAGEMENT_KEY,
            engagement_dir=str(code_engagement),
        ),
    )
    json_file = _finding_json(code_engagement / "finding.json")

    module.run(
        _args(
            module,
            [
                "record",
                "code-vuln-hunter",
                str(json_file),
                "--agent-id",
                "CH-1",
                "--allow-unindexed-evidence",
                "--pending-runtime-proof",
                "Static dataflow only; no runtime trigger yet.",
                "--next-test-file",
                _plan_file(code_engagement),
            ],
            code_engagement,
        )
    )

    assert capsys.readouterr().out.strip() == "CH-001"
    stored = _stored(client, "CH-001")
    # One invocation produced both the record and the park.
    assert stored["verification_status"] == "pending_runtime_proof"
    assert stored["next_test"] == RUNTIME_PROOF_PLAN
    # The binding was derived, never transcribed, and it is CURRENT.
    assert stored["provenance"]["code_snapshot"] == {
        "repo_id": 1,
        "repo_generation": _REPO_GENERATION,
        "source_manifest_digest": _DIGEST,
    }
    assert stored["code_snapshot_status"] == "current"
    # And it is worth something: the attestation resolves to a real dispatch.
    assert stored["provenance"]["code_snapshot_attestation"]["agent_id"] == "CH-1"
    assert isinstance(stored["provenance"]["code_snapshot_attestation"]["dispatch_id"], int)
    assert stored["code_snapshot_attestation_status"] == "attested"


def test_verifying_a_code_finding_re_attests_under_the_verifier_dispatch(
    client, code_engagement, monkeypatch, capsys
) -> None:
    record_module = _load_assess_module(
        "record_finding.py", "attestation_record_finding_two"
    )
    monkeypatch.setattr(record_module, "AssessmentClient", _BackendClient(client))
    monkeypatch.setattr(
        record_module,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://backend.test",
            engagement_key=_ENGAGEMENT_KEY,
            engagement_dir=str(code_engagement),
        ),
    )
    json_file = _finding_json(code_engagement / "finding.json")
    record_module.run(
        _args(
            record_module,
            [
                "record",
                "code-vuln-hunter",
                str(json_file),
                "--agent-id",
                "CH-1",
                "--allow-unindexed-evidence",
            ],
            code_engagement,
        )
    )
    capsys.readouterr()

    verify_module = _load_assess_module(
        "verify_finding.py", "attestation_verify_finding"
    )
    monkeypatch.setattr(verify_module, "AssessmentClient", _BackendClient(client))
    monkeypatch.setattr(
        verify_module,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://backend.test",
            engagement_key=_ENGAGEMENT_KEY,
            engagement_dir=str(code_engagement),
        ),
    )

    verify_module.run(
        _args(
            verify_module,
            [
                "verify",
                "CH-001",
                "--status",
                "pending_runtime_proof",
                "--reason",
                "Re-read the current sealed source; runtime trigger still owed.",
                "--agent-id",
                "VF-1",
                "--next-test-file",
                _plan_file(code_engagement),
            ],
            code_engagement,
        )
    )
    capsys.readouterr()

    stored = _stored(client, "CH-001")
    assert stored["verification_status"] == "pending_runtime_proof"
    assert stored["code_snapshot_status"] == "current"
    assert stored["provenance"]["code_snapshot_attestation"]["write_mode"] == "verify"
    assert stored["provenance"]["code_snapshot_attestation"]["agent_id"] == "VF-1"
    assert stored["code_snapshot_attestation_status"] == "attested"
    # The AUTHOR is not rebound by a verifier attestation.
    assert stored["provenance"]["agent_id"] == "CH-1"
