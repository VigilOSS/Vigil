"""`finding corroborate`, `chain list`, the finding-list CHAIN cell, and empty fetch reads."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess import cli
from assess.commands import fetch, list_findings
from assess.lib import config, contracts
from assess.lib.client import AssessError, AssessmentClient


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def _config() -> SimpleNamespace:
    return SimpleNamespace(base_url="http://example.test", engagement_key="eng")


def _link_response(**over):
    return {
        "id": 7,
        "finding_slug": "VA-047",
        "link_kind": "corroborated_by",
        "target_kind": "dispatch",
        "target_id": None,
        "target_ref": "LANE-B",
        "notes": "Re-derived the sink from the router.",
        "retired_at": None,
        "verification_effect": "keep",
        "verification_invalidated": False,
        "changed_axes": ["link"],
        **over,
    }


def test_finding_corroborate_links_the_dispatch_and_leaves_the_verdict(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    posted: list[tuple[str, dict]] = []

    def post(_client, endpoint: str, payload: dict):
        posted.append((endpoint, payload))
        return _link_response()

    monkeypatch.setattr(AssessmentClient, "post", post)

    cli.main([
        "--engagement-dir", str(engagement),
        "finding", "corroborate", "VA-047",
        "--dispatch", "LANE-B",
        "--reason", "Re-derived the sink from the router.",
    ])

    assert posted == [(
        "findings/VA-047/links",
        {
            "link_kind": "corroborated_by",
            "target_kind": "dispatch",
            "target_ref": "LANE-B",
            "notes": "Re-derived the sink from the router.",
            "provenance": {"dispatch_agent_id": "LANE-B", "source_name": "LANE-B"},
        },
    )]
    captured = capsys.readouterr()
    assert json.loads(captured.out)["id"] == 7
    assert "VA-047 corroborated by dispatch LANE-B (link 7)" in captured.err
    assert "verdict effect keep" in captured.err


def test_finding_corroborate_requires_the_dispatch(tmp_path, monkeypatch) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--engagement-dir", str(engagement), "finding", "corroborate", "VA-047"])

    assert exc.value.code == 2


def test_finding_corroborate_refuses_a_response_naming_another_dispatch(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient, "post", lambda *_args: _link_response(target_ref="LANE-Z")
    )

    with pytest.raises(SystemExit) as exc:
        cli.main([
            "--engagement-dir", str(engagement),
            "finding", "corroborate", "VA-047", "--dispatch", "LANE-B",
        ])

    assert exc.value.code == 1
    assert "target_ref" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["finding corroborate", "chain list", "chain"])
def test_new_verbs_resolve_through_the_contract_registry(name: str) -> None:
    contract = contracts.get_contract(name)

    assert contract is not None
    assert contract.preferred_invocations


def test_finding_get_names_the_lanes_that_re_derived_it(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    row = {
        "slug": "VA-047",
        "verification_status": "confirmed",
        "corroboration": {
            "lane_count": 2,
            "summary": "independently re-derived by 2 lanes",
            "dispatches": [
                {"agent_id": "LANE-B", "agent_role": "code-vuln-hunter"},
                {"agent_id": "LANE-C", "agent_role": "code-variant-hunter"},
            ],
        },
    }
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: row)

    cli.main(["--engagement-dir", str(engagement), "finding", "get", "VA-047"])

    captured = capsys.readouterr()
    assert json.loads(captured.out) == row
    assert (
        "finding get: VA-047 independently re-derived by 2 lanes (LANE-B, LANE-C)"
        in captured.err
    )


class _ChainClient(StubClient):
    """Serves the chain, chain-link and finding reads `chain list` composes."""

    chains = [
        {"id": 2, "chain_key": "ssrf-to-metadata", "title": "SSRF to cloud metadata",
         "status": "active", "severity": "critical", "narrative": "n"},
        {"id": 1, "chain_key": "idor-takeover", "title": "IDOR to takeover",
         "status": "active", "severity": "high", "narrative": "n"},
        {"id": 3, "chain_key": "draft-only", "title": "No steps yet",
         "status": "draft", "severity": "medium", "narrative": ""},
    ]
    links = [
        {"id": 13, "chain_id": 2, "chain_key": "ssrf-to-metadata", "relation": "step",
         "entity_kind": "finding", "entity_id": None, "entity_ref": "VA-003"},
        {"id": 12, "chain_id": 2, "chain_key": "ssrf-to-metadata", "relation": "step",
         "entity_kind": "finding", "entity_id": None, "entity_ref": "VA-002"},
        {"id": 11, "chain_id": 1, "chain_key": "idor-takeover", "relation": "step",
         "entity_kind": "finding", "entity_id": 1, "entity_ref": ""},
        {"id": 10, "chain_id": 1, "chain_key": "idor-takeover", "relation": "evidence",
         "entity_kind": "artifact", "entity_id": None, "entity_ref": "notes/idor.md"},
    ]
    findings = [
        {"id": 1, "slug": "VA-001", "severity": "high", "verification_status": "confirmed",
         "workflow_status": "reported", "title": "IDOR"},
        {"id": 2, "slug": "VA-002", "severity": "medium", "verification_status": "confirmed",
         "workflow_status": "active", "title": "SSRF"},
        {"id": 3, "slug": "VA-003", "severity": "high", "verification_status": "unreviewed",
         "workflow_status": "active", "title": "Metadata read"},
    ]

    def __init__(self, *_args, **_kwargs) -> None:
        self.calls: list[str] = []

    def get(self, endpoint: str):
        self.calls.append(endpoint)
        if endpoint == "attack-chains":
            return list(self.chains)
        if endpoint == "attack-chain-links":
            return list(self.links)
        raise AssertionError(f"unexpected GET {endpoint}")

    def get_all_pages(self, endpoint: str, *, page_size: int = 5000):
        self.calls.append(f"{endpoint}#all")
        assert endpoint == "findings?view=list"
        return list(self.findings)


def test_chain_list_orders_steps_and_counts_verified_finding_steps(
    monkeypatch, capsys
) -> None:
    from assess.commands import list_chains

    monkeypatch.setattr(list_chains, "AssessmentClient", _ChainClient)
    monkeypatch.setattr(list_chains, "load_config", lambda _path: _config())

    list_chains.run(SimpleNamespace(engagement_dir="/tmp/eng", as_json=True))

    captured = capsys.readouterr()
    chains = {chain["chain_key"]: chain for chain in json.loads(captured.out)}
    ssrf = chains["ssrf-to-metadata"]
    assert [step["slug"] for step in ssrf["steps"]] == ["VA-002", "VA-003"]
    assert (ssrf["finding_step_count"], ssrf["verified_finding_step_count"]) == (2, 1)
    assert ssrf["all_finding_steps_verified"] is False
    idor = chains["idor-takeover"]
    assert [step["slug"] for step in idor["steps"]] == ["VA-001"]
    assert [entry["entity_ref"] for entry in idor["other_links"]] == ["notes/idor.md"]
    assert idor["all_finding_steps_verified"] is True
    assert chains["draft-only"]["finding_step_count"] == 0
    assert chains["draft-only"]["all_finding_steps_verified"] is False
    assert "UNTRUSTED DATA" in captured.err


def test_chain_list_table_names_each_step_and_its_verification(
    monkeypatch, capsys
) -> None:
    from assess.commands import list_chains

    monkeypatch.setattr(list_chains, "AssessmentClient", _ChainClient)
    monkeypatch.setattr(list_chains, "load_config", lambda _path: _config())

    list_chains.run(SimpleNamespace(engagement_dir="/tmp/eng", as_json=False))

    out = capsys.readouterr().out
    assert (
        "ssrf-to-metadata | critical | active | 1/2 finding steps verified | "
        "SSRF to cloud metadata"
    ) in out
    assert "  1. VA-002 [medium] confirmed (step)" in out
    assert "  2. VA-003 [high] unreviewed (step)" in out
    assert "draft-only | medium | draft | 0/0 finding steps verified | No steps yet" in out


def test_chain_list_table_names_the_fields_it_leaves_out_and_the_json_view(
    monkeypatch, capsys
) -> None:
    from assess.commands import list_chains

    monkeypatch.setattr(list_chains, "AssessmentClient", _ChainClient)
    monkeypatch.setattr(list_chains, "load_config", lambda _path: _config())

    list_chains.run(SimpleNamespace(engagement_dir="/tmp/eng", as_json=False))

    last = capsys.readouterr().out.strip().splitlines()[-1]
    for field in ("narrative", "evidence_ref", "notes"):
        assert field in last
    assert "`vigil assess chain list --json`" in last


def test_chain_list_reports_an_empty_ledger(monkeypatch, capsys) -> None:
    from assess.commands import list_chains

    class _Empty(_ChainClient):
        chains: list = []
        links: list = []

    monkeypatch.setattr(list_chains, "AssessmentClient", _Empty)
    monkeypatch.setattr(list_chains, "load_config", lambda _path: _config())

    list_chains.run(SimpleNamespace(engagement_dir="/tmp/eng", as_json=False))

    assert capsys.readouterr().out.strip() == "No attack chains recorded."


def test_finding_list_table_names_the_chains_each_finding_is_a_step_of(
    monkeypatch, capsys
) -> None:
    calls: list[str] = []

    class _Client(StubClient):
        def get(self, endpoint: str):
            calls.append(endpoint)
            if endpoint == "attack-chain-links":
                return list(_ChainClient.links)
            return [
                *_ChainClient.findings,
                {"id": 4, "slug": "VA-004", "severity": "low", "title": "Unchained",
                 "verification_status": "unreviewed", "workflow_status": "active"},
            ]

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(SimpleNamespace(
        engagement_dir="/tmp/eng", severity=None, workflow_status=None,
        verification_status=None, source_name=None, slug=None,
        root_cause_slug=None, search=None, holding=False, limit=None,
        offset=0, json=False,
    ))

    rows = {
        line.split(" | ", 1)[0]: line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("VA-")
    }
    assert rows["VA-001"].endswith(" | CHAIN[idor-takeover]")
    assert rows["VA-002"].endswith(" | CHAIN[ssrf-to-metadata]")
    assert "CHAIN[" not in rows["VA-004"]
    assert calls[-1] == "attack-chain-links"


def test_finding_list_table_survives_a_failed_chain_link_read(monkeypatch, capsys) -> None:
    """The chain column is an annotation; losing it must not lose the table."""

    class _Client(StubClient):
        def get(self, endpoint: str):
            if endpoint == "attack-chain-links":
                raise AssessError("GET attack-chain-links failed: HTTP 503")
            return list(_ChainClient.findings)

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(SimpleNamespace(
        engagement_dir="/tmp/eng", severity=None, workflow_status=None,
        verification_status=None, source_name=None, slug=None,
        root_cause_slug=None, search=None, holding=False, limit=None,
        offset=0, json=False,
    ))

    out = capsys.readouterr().out
    rows = [line for line in out.splitlines() if line.startswith("VA-")]
    assert [row.split(" | ", 1)[0] for row in rows] == ["VA-001", "VA-002", "VA-003"]
    assert all("CHAIN[" not in row for row in rows)
    assert "HTTP 503" in out
    assert "vigil assess chain list" in out


class _EmptyFetchClient(StubClient):
    def get(self, endpoint: str):
        return []


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (
            "coverage-items?host=api.example.com&status=open",
            "fetch: coverage-items returned 0 rows for host=api.example.com, "
            "status=open; the read succeeded and nothing matched those filters.",
        ),
        (
            "attack-chains",
            "fetch: attack-chains returned 0 rows; the read succeeded and the "
            "engagement holds none on this route.",
        ),
    ],
)
def test_fetch_says_when_a_successful_read_returned_no_rows(
    endpoint: str, expected: str, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(fetch, "AssessmentClient", _EmptyFetchClient)
    monkeypatch.setattr(fetch, "load_config", lambda _path: _config())

    fetch.run(SimpleNamespace(
        engagement_dir="/tmp/eng", endpoint=endpoint, list_routes=False,
        json=False, compact=False, paginate=False, jq="",
    ))

    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert expected in captured.err
