"""Finding-verb guidance routes each reader to the act that is theirs to take.

A refusal or contract note is followed literally by whichever agent reads it,
so it has to name the actor: a specialist cannot register its own dispatch, an
operator clearing a pending claim review needs the exact decision command, and
a verb that resets a verdict has to say so before it runs.
"""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib import contract_registry
from assess.lib.client import AssessError
from test_finding_provenance_autofill import (
    _Backend,
    _engagement,
    _file_finding_payload,
)


class _UnregisteredAuthorBackend(_Backend):
    def get(self, endpoint: str):
        if endpoint.startswith("dispatches/"):
            raise AssessError(f"GET {endpoint} failed: HTTP 404")
        return super().get(endpoint)


def test_an_unresolved_author_is_told_to_return_to_the_operator(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _UnregisteredAuthorBackend()
    backend.install(monkeypatch)

    with pytest.raises(SystemExit):
        cli.main([
            "--engagement-dir", str(engagement), "finding", "record",
            "code-vuln-hunter", str(json_file), "--agent-id", "CH-404",
            "--allow-unindexed-evidence",
        ])

    err = capsys.readouterr().err
    assert "Runtime Identity" in err
    assert "returns to the operator" in err
    assert backend.posts == []


def test_retract_claim_contract_carries_the_verdict_effect_notes():
    """Every finding write verb renders the shared change-policy notes."""
    notes = contract_registry._CONTRACT_SPECS["finding retract-claim"].notes
    assert set(contract_registry.FINDING_CHANGE_EFFECT_NOTES) <= set(notes)


def _decision_payload(line: str) -> dict:
    prefix = "vigil assess agent decision --kind claim_equivalence --payload-json '"
    assert prefix in line, line
    return json.loads(line.split(prefix, 1)[1].split("'", 1)[0])


def test_a_claim_review_effect_names_the_decision_command_with_the_slug():
    from assess.lib.client import verdict_effect_line

    line = verdict_effect_line(
        "finding update", "VA-001",
        {"verification_effect": "claim_review", "changed_axes": ["summary"]},
    )
    payload = _decision_payload(line)
    assert payload["finding_slug"] == "VA-001"
    assert "vigil assess finding get VA-001" in line
    assert line.index("--kind claim_equivalence") < line.index("fresh proof receipts")


def test_a_claim_review_effect_fills_in_the_audit_values_the_response_carries():
    from assess.lib.client import verdict_effect_line

    line = verdict_effect_line(
        "finding update", "VA-001",
        {
            "verification_effect": "claim_review",
            "changed_axes": ["summary"],
            "finding": {
                "slug": "VA-001",
                "verification_audit": {
                    "claim_transition_id": 41,
                    "current_claim_sha256": "ab" * 32,
                },
            },
        },
    )
    payload = _decision_payload(line)
    assert payload["claim_transition_id"] == 41
    assert payload["new_claim_sha256"] == "ab" * 32


def test_the_claim_review_contract_meaning_names_the_decision_command():
    meaning = dict(contract_registry._FINDING_CHANGE_EFFECT_MEANINGS)["claim_review"]
    assert "vigil assess agent decision --kind claim_equivalence" in meaning


def test_decision_kind_help_lists_every_gated_kind_and_stays_open():
    import argparse

    from assess.commands import agent

    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    decision = parser._subparsers._group_actions[0].choices["agent"]
    action = next(
        a for a in decision._subparsers._group_actions[0].choices["decision"]._actions
        if a.dest == "decision_kind"
    )
    assert action.choices is None
    for kind in contract_registry.GATED_DECISION_KINDS:
        assert kind in action.help


def test_retract_claim_names_the_verdict_invalidation_on_stderr(tmp_path, monkeypatch, capsys):
    from assess.lib import config
    from assess.lib.client import AssessmentClient

    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda _c, _e: {
        "slug": "VA-001", "summary": "Every Acme tenant is exposed.", "row_version": 3,
        "details": {}, "verification_status": "confirmed"})
    monkeypatch.setattr(AssessmentClient, "patch", lambda _c, _e, _p, **_k: {
        "finding": {"slug": "VA-001", "summary": "Only Acme invoices are exposed.",
                    "verification_status": "unreviewed"},
        "verification_effect": "invalidate", "changed_axes": ["retraction", "summary"]})
    cli.main(["--engagement-dir", str(tmp_path), "finding", "retract-claim", "VA-001",
              "--replacement-summary", "Only Acme invoices are exposed.",
              "--reason", "scope narrowed"])
    err = capsys.readouterr().err
    assert "finding retract-claim: VA-001 verdict effect invalidate (retraction, summary)" in err
    assert "fresh proof run" in err
