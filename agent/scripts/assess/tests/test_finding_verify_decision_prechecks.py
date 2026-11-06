"""`finding verify` pre-checks every structured decision file locally.

The backend owns each contract. These pins exist because a misspelled field in
a counter-check, confirm-check or severity-variance document used to surface as
a raw Pydantic 422 with no field roster — while `--next-test-file` named every
problem before the first write. The re-band and operator-authority pre-checks
live here too: both decide whether the command may POST at all.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import verify_finding


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str) -> dict:
        return {"slug": endpoint.split("/")[-1], "canonical_location": "https://acme.example/x", "provenance": {}}

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"finding": {"slug": endpoint.split("/")[1]}}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:
        return None


def _args(tmp_path, monkeypatch, argv: list[str]) -> tuple[argparse.Namespace, _FakeClient]:
    fake = _FakeClient()
    monkeypatch.setattr(verify_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(verify_finding, "AssessmentClient", lambda *a, **k: fake)
    parser = argparse.ArgumentParser()
    verify_finding.register(parser.add_subparsers())
    args = parser.parse_args(argv)
    args.engagement_dir = str(tmp_path)
    return args, fake


def _write(tmp_path, name: str, payload: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


_CONFIRM_CHECK = {
    "method": "Replay the claim against the expected guard",
    "attempted_falsification": "Check whether the guard defeats the claim",
    "expected_result": "The guard prevents the claimed outcome",
    "observed_result": "The claimed outcome still occurs",
    "completed": True,
    "proof_receipt_ids": [17],
}
_COUNTER_CHECK = {
    "method": "Trace the guarded source path",
    "expected_result": "attacker input reaches the sink",
    "observed_result": "every path is rejected before the sink",
    "falsified_claim": "attacker input reaches the sink",
    "completed": True,
    "proof_receipt_ids": [17],
}
_SEVERITY_VARIANCE = {
    "normal_band": "medium",
    "chosen_severity": "high",
    "actor": "code-vuln-verifier",
    "reason": "The exposed records trigger a contractual incident.",
    "proof_receipt_id": 17,
}


def test_a_confirm_check_falsified_claim_is_routed_to_its_two_real_homes(
    tmp_path, monkeypatch, capsys
) -> None:
    """``falsified_claim`` belongs on a counter check; a falsified SUB-claim on a
    confirmed finding belongs in ``details.honest_bounds``."""
    check = _write(
        tmp_path,
        "confirm-check.json",
        {**_CONFIRM_CHECK, "falsified_claim": "the admin path is also reachable"},
    )
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "confirmed", "--reason", "r",
         "--proof-receipt-id", "17", "--confirm-check-file", check],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "confirm_check.falsified_claim" in err
    assert "counter" in err
    assert "details.honest_bounds" in err
    assert fake.posts == []


def test_each_structured_decision_file_names_its_unknown_and_missing_fields(
    tmp_path, monkeypatch, capsys
) -> None:
    counter = _write(
        tmp_path,
        "counter-check.json",
        {**{k: v for k, v in _COUNTER_CHECK.items() if k != "observed_result"},
         "observed_results": "every path is rejected before the sink"},
    )
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "false_positive", "--reason", "r",
         "--counter-check-file", counter],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "counter_check.observed_results is not a counter_check field" in err
    assert "counter_check.observed_result is required" in err
    assert fake.posts == []


def test_a_severity_variance_file_names_its_closed_band_vocabulary(
    tmp_path, monkeypatch, capsys
) -> None:
    variance = _write(
        tmp_path, "variance.json", {**_SEVERITY_VARIANCE, "normal_band": "moderate"}
    )
    confirm = _write(tmp_path, "confirm-check.json", _CONFIRM_CHECK)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "confirmed", "--reason", "r",
         "--proof-receipt-id", "17", "--confirm-check-file", confirm,
         "--severity-variance-file", variance],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "severity_variance.normal_band must be one of" in err
    assert fake.posts == []


def test_well_formed_decision_files_still_reach_the_backend(
    tmp_path, monkeypatch
) -> None:
    confirm = _write(tmp_path, "confirm-check.json", _CONFIRM_CHECK)
    variance = _write(tmp_path, "variance.json", _SEVERITY_VARIANCE)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "confirmed", "--reason", "r",
         "--proof-receipt-id", "17", "--confirm-check-file", confirm,
         "--severity-variance-file", variance],
    )

    verify_finding.run(args)

    assert [endpoint for endpoint, _ in fake.posts] == ["findings/VA-1/verify"]
    payload = fake.posts[0][1]
    assert payload["confirm_check"] == _CONFIRM_CHECK
    assert payload["severity_variance"] == _SEVERITY_VARIANCE
    # An unclaimed operator authority never travels: the request field exists to
    # waive the receipt gate, so a default `false` on every verification would
    # make the waiver look available where it was not asked for.
    assert "operator_authority" not in payload
    assert "operator_authority_intel_id" not in payload


def test_a_terminal_verdict_may_carry_new_severity(tmp_path, monkeypatch) -> None:
    """The backend accepts a re-band with any terminal disposition, so the CLI
    must not refuse the write before it is sent."""
    confirm = _write(tmp_path, "confirm-check.json", _CONFIRM_CHECK)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "confirmed", "--reason", "program calibration",
         "--new-severity", "high", "--proof-receipt-id", "17",
         "--confirm-check-file", confirm],
    )

    verify_finding.run(args)

    assert fake.posts[0][1]["new_severity"] == "high"


def test_a_non_terminal_verdict_cannot_carry_new_severity(
    tmp_path, monkeypatch, capsys
) -> None:
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "VA-2", "--status", "disputed", "--reason", "contested",
         "--new-severity", "low"],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "confirmed, downgraded, false_positive" in err
    # The remedy names every slug in the batch, not just the first.
    assert "vigil assess finding update VA-1 VA-2 --severity low" in err
    assert fake.posts == []


def test_operator_authority_requires_an_intel_id_and_a_terminal_status(
    tmp_path, monkeypatch, capsys
) -> None:
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "downgraded", "--reason", "deployment config settles it",
         "--new-severity", "low", "--operator-authority"],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    assert "--intel-id" in capsys.readouterr().err
    assert fake.posts == []


def test_an_operator_authority_verdict_needs_no_receipt_or_confirm_check(
    tmp_path, monkeypatch
) -> None:
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "downgraded",
         "--reason", "The deployment config disables the affected route.",
         "--new-severity", "low", "--operator-authority", "--intel-id", "42"],
    )

    verify_finding.run(args)

    payload = fake.posts[0][1]
    assert payload["operator_authority"] is True
    assert payload["operator_authority_intel_id"] == 42
    assert payload.get("proof_receipt_ids") == []
    assert "confirm_check" not in payload


def test_a_kill_check_outside_its_range_fails_before_the_post(
    tmp_path, monkeypatch, capsys
) -> None:
    """The details schema bounds the check number locally, so 7 never travels."""
    counter = _write(tmp_path, "counter-check.json", _COUNTER_CHECK)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "false_positive", "--reason", "falsified",
         "--counter-check-file", counter,
         "--details-inline", json.dumps({"kill_reason": "The guard dominates.", "kill_check": 7})],
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "details.kill_check" in err
    assert fake.posts == []


def test_a_kill_with_no_authored_kill_fields_names_both_before_the_post(
    tmp_path, monkeypatch, capsys
) -> None:
    """The fields may already be stored on the finding, so this warns rather than
    refusing — but the roster has to arrive before the round trip, not as a 400."""
    counter = _write(tmp_path, "counter-check.json", _COUNTER_CHECK)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "VA-2", "--status", "false_positive", "--reason", "falsified",
         "--counter-check-file", counter],
    )

    verify_finding.run(args)

    err = capsys.readouterr().err
    assert "details.kill_reason" in err
    assert "details.kill_check" in err
    assert "1 to 5" in err
    # The settling-test rule, which an agent otherwise meets on its second attempt.
    assert "required_followup" in err
    assert "blocked" in err
    assert len(fake.posts) == 2


def test_a_complete_kill_payload_is_silent(tmp_path, monkeypatch, capsys) -> None:
    counter = _write(tmp_path, "counter-check.json", _COUNTER_CHECK)
    args, fake = _args(
        tmp_path,
        monkeypatch,
        ["verify", "VA-1", "--status", "false_positive", "--reason", "falsified",
         "--counter-check-file", counter,
         "--details-inline", json.dumps({
             "kill_reason": "Every path passes the guard before the read.",
             "kill_check": 4,
         })],
    )

    verify_finding.run(args)

    assert "kill_reason" not in capsys.readouterr().err
    assert len(fake.posts) == 1
