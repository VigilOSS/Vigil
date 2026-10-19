"""`finding verify` / `finding record --pending-runtime-proof` carry a runtime proof plan.

The backend requires ``next_test`` on every ``pending_runtime_proof`` verdict and
rejects it on every other one. The CLI checks the plan file before any write, so
a record cannot land and then fail to park for want of a plan.
"""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient

PLAN = {
    "hypothesis": "The Acme export id is not bound to the requesting tenant.",
    "confirm_if": "A second tenant reads the first tenant's export.",
    "falsify_if": "A second tenant receives 403 for the export.",
    "route_hint": "live",
    "prerequisites": "Two tenant accounts.\n",
}


class _Backend:
    def __init__(self):
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        if endpoint == "findings":
            return []
        if endpoint.startswith("findings/"):
            return {"slug": endpoint.split("/", 1)[1],
                    "canonical_location": "https://example.com/exports/1", "provenance": {}}
        if endpoint.startswith("dispatches/"):
            return {"agent_id": endpoint.split("/", 1)[1]}
        raise AssertionError(f"unexpected GET {endpoint}")

    def post(self, endpoint: str, payload: dict):
        self.posts.append((endpoint, payload))
        slug = payload.get("slug") or endpoint.split("/")[1]
        return {"finding": {"slug": slug, "title": "Acme export replay",
                            "verification_status": payload.get("verification_status", "")},
                "transition": {"action": "verified"}}


@pytest.fixture
def backend(monkeypatch):
    fake = _Backend()
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", fake.get)
    monkeypatch.setattr(AssessmentClient, "post", fake.post)
    monkeypatch.setattr(AssessmentClient, "post_event", lambda *_a, **_k: None)
    return fake


@pytest.fixture
def engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def _plan_file(engagement, plan) -> str:
    path = engagement / "next-test.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return str(path)


def _verify(engagement, *extra: str) -> None:
    cli.main(["--engagement-dir", str(engagement), "finding", "verify", "VA-001",
              "--reason", "Source accepted; runtime proof owed.", *extra])


def test_verify_sends_the_plan_file_verbatim(engagement, backend, capsys):
    _verify(engagement, "--status", "pending_runtime_proof",
            "--next-test-file", _plan_file(engagement, PLAN))
    capsys.readouterr()
    assert backend.posts == [("findings/VA-001/verify", backend.posts[0][1])]
    assert backend.posts[0][1]["next_test"] == PLAN


def test_verify_pending_without_a_plan_fails_before_writing(engagement, backend, capsys):
    with pytest.raises(SystemExit) as exc:
        _verify(engagement, "--status", "pending_runtime_proof")
    assert exc.value.code != 0
    assert "--next-test-file" in capsys.readouterr().err
    assert backend.posts == []


def test_verify_rejects_a_plan_for_any_other_status(engagement, backend, capsys):
    with pytest.raises(SystemExit) as exc:
        _verify(engagement, "--status", "disputed",
                "--next-test-file", _plan_file(engagement, PLAN))
    assert exc.value.code != 0
    assert "pending_runtime_proof" in capsys.readouterr().err
    assert backend.posts == []


@pytest.mark.parametrize(
    "plan",
    [
        {**PLAN, "owner": "acme"},
        {**PLAN, "route_hint": "remote"},
        {**PLAN, "hypothesis": "  "},
        {**PLAN, "confirm_if": 3},
        {**PLAN, "prerequisites": None},
        {key: value for key, value in PLAN.items() if key != "route_hint"},
        ["not", "an", "object"],
    ],
    ids=["unknown-key", "unknown-route", "blank", "non-string", "null-optional",
         "missing", "not-object"],
)
def test_verify_rejects_a_malformed_plan_before_writing(engagement, backend, capsys, plan):
    with pytest.raises(SystemExit) as exc:
        _verify(engagement, "--status", "pending_runtime_proof",
                "--next-test-file", _plan_file(engagement, plan))
    assert exc.value.code != 0
    assert "next_test" in capsys.readouterr().err
    assert backend.posts == []


def test_verify_payload_file_must_also_carry_the_plan(engagement, backend, capsys):
    payload = engagement / "verify.json"
    payload.write_text(json.dumps({"verification_status": "pending_runtime_proof",
                                   "reason_text": "Runtime proof owed."}), encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["--engagement-dir", str(engagement), "finding", "verify", "VA-001",
                  "--payload-file", str(payload)])
    assert "next_test" in capsys.readouterr().err
    assert backend.posts == []


def _record(engagement, *extra: str) -> None:
    finding = engagement / "finding.json"
    finding.write_text(json.dumps({
        "title": "Acme export replay", "severity": "high",
        "canonical_location": "https://example.com/exports/1",
        "summary": "Export results are not bound to the requesting tenant.",
        "details": {"evidence": "Handler omits the tenant check.", "impact": "Cross-tenant read"},
    }), encoding="utf-8")
    cli.main(["--engagement-dir", str(engagement), "finding", "record", "vulnerability-analyst",
              str(finding), "--agent-id", "VA-RUN-1", "--allow-unindexed-evidence", *extra])


def test_record_park_carries_the_plan(engagement, backend, capsys):
    _record(engagement, "--pending-runtime-proof", "Runtime proof owed.",
            "--next-test-file", _plan_file(engagement, PLAN))
    capsys.readouterr()
    endpoints = [endpoint for endpoint, _ in backend.posts]
    assert endpoints == ["findings", "findings/VA-001/verify"]
    assert backend.posts[1][1]["next_test"] == PLAN


@pytest.mark.parametrize("extra", [
    ("--pending-runtime-proof", "Runtime proof owed."),
    ("--next-test-file", "PLAN"),
], ids=["park-without-plan", "plan-without-park"])
def test_record_refuses_an_unpaired_park_or_plan_before_recording(engagement, backend, capsys, extra):
    args = [_plan_file(engagement, PLAN) if value == "PLAN" else value for value in extra]
    with pytest.raises(SystemExit) as exc:
        _record(engagement, *args)
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--next-test-file" in err and "--pending-runtime-proof" in err
    assert backend.posts == []


def test_verify_contract_documents_the_plan_flag_and_every_field():
    text = contracts.render_contract("finding verify")
    assert "--next-test-file" in text
    for name, _domain, _meaning in contracts.NEXT_TEST_FIELDS:
        assert name in text
    for hint in contracts.NEXT_TEST_ROUTE_HINTS:
        assert hint in text
    assert "--next-test-file" in contracts.render_contract("finding record")


def test_record_rejects_overlong_park_before_first_write(engagement, backend):
    with pytest.raises(SystemExit):
        _record(engagement, "--pending-runtime-proof", "x" * 4097,
                "--next-test-file", _plan_file(engagement, PLAN))
    assert backend.posts == []


def test_failed_park_retry_preserves_literal_argv(engagement, backend, monkeypatch, capsys):
    import shlex
    from assess.lib.client import AssessError
    reason = "Acme's $TOKEN $(touch nope) `touch nope`\nsecond line"
    plan = engagement / "next test's $value.json"
    plan.write_text(json.dumps(PLAN))
    original = backend.post
    def fail_park(_client, endpoint, payload):
        if endpoint.endswith('/verify'):
            raise AssessError('HTTP 409: state changed')
        return original(endpoint, payload)
    monkeypatch.setattr(AssessmentClient, 'post', fail_park)
    with pytest.raises(SystemExit):
        _record(engagement, '--pending-runtime-proof', reason, '--next-test-file', str(plan))
    error = capsys.readouterr().err
    retry = error.split('Retry only the park: `', 1)[1].rsplit('`.', 1)[0]
    assert shlex.split(retry) == ['vigil', 'assess', 'finding', 'verify', 'VA-001',
        '--status', 'pending_runtime_proof', '--reason', reason, '--next-test-file', str(plan)]
    assert [endpoint for endpoint, _ in backend.posts] == ['findings']
