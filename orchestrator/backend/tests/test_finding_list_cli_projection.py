"""The CLI finding readers use the projected ``view=list`` ledger.

``finding list`` (table and ``--json``), ``chain list``, the record clobber
guard and the phase gates only read list fields, so they read
``GET /findings?view=list``. Each check here drives the real command against the
real backend twice — once as shipped, once with the ``view=list`` query stripped
so the same command is served full rows — and requires identical output, plus a
much smaller payload and no extra requests.
"""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

from app import db as db_module
from app.services.state_manager import findings as findings_module
from tests.test_finding_list_recency import ENGAGEMENT_KEY, _base
from tests.test_finding_list_view_projection import _seed_ledger


def _strip_list_view(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    query = [(key, value) for key, value in parse_qsl(parts.query) if (key, value) != ("view", "list")]
    return parts.path + (f"?{urlencode(query)}" if query else "")


class _Bridge:
    """An ``AssessmentClient`` stand-in that forwards reads to the test backend."""

    def __init__(self, client, *, full_rows: bool) -> None:
        self.client = client
        self.full_rows = full_rows
        self.calls: list[str] = []
        self.bytes_by_route: dict[str, int] = {}

    def __call__(self, *_args, **_kwargs) -> "_Bridge":
        return self

    def __enter__(self) -> "_Bridge":
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def get(self, endpoint: str):
        from assess.lib.client import AssessError

        self.calls.append(endpoint)
        if self.full_rows:
            endpoint = _strip_list_view(endpoint)
        response = self.client.get(f"{_base()}/{endpoint}")
        if response.status_code >= 400:
            raise AssessError(f"HTTP {response.status_code}: {response.text}")
        route = urlsplit(endpoint).path
        self.bytes_by_route[route] = self.bytes_by_route.get(route, 0) + len(response.content)
        return response.json()

    def get_all_pages(self, endpoint: str, *, page_size: int = 1000) -> list:
        rows: list = []
        separator = "&" if "?" in endpoint else "?"
        offset = 0
        while True:
            page = self.get(f"{endpoint}{separator}limit={page_size}&offset={offset}")
            rows.extend(page)
            if len(page) < page_size:
                return rows
            offset += len(page)


def _config(_path=None, **_kwargs):
    return argparse.Namespace(
        base_url="http://backend.example",
        engagement_key=ENGAGEMENT_KEY,
        engagement_dir="/engagements/acme",
        agent_root="/engagements",
    )


def _run(module, bridge, monkeypatch, capsys, argv: list[str]):
    monkeypatch.setattr(module, "AssessmentClient", bridge)
    monkeypatch.setattr(module, "load_config", _config)
    parser = argparse.ArgumentParser()
    module.register(parser.add_subparsers(dest="action"))
    args = parser.parse_args(argv)
    args.engagement_dir = "/engagements/acme"
    capsys.readouterr()
    args.func(args)
    return capsys.readouterr()


def _both(module, client, monkeypatch, capsys, argv):
    full = _Bridge(client, full_rows=True)
    full_out = _run(module, full, monkeypatch, capsys, argv)
    projected = _Bridge(client, full_rows=False)
    projected_out = _run(module, projected, monkeypatch, capsys, argv)
    return full, full_out, projected, projected_out


def _record_chain(client) -> None:
    created = client.post(
        f"{_base()}/attack-chains",
        json={
            "title": "Acme export IDOR to account takeover",
            "severity": "critical",
            "links": [
                {"entity_kind": "finding", "entity_ref": "VA-001", "relation": "step"},
                {"entity_kind": "finding", "entity_ref": "VA-002", "relation": "step"},
            ],
        },
    )
    assert created.status_code in {200, 201}, created.text


@pytest.mark.parametrize(
    "argv",
    [
        ["list"],
        ["list", "--severity", "high"],
        ["list", "--verification-status", "blocked"],
        ["list", "--holding"],
        ["list", "--limit", "3"],
        ["list", "--limit", "2", "--offset", "4"],
    ],
)
def test_finding_list_table_is_identical_on_the_projected_ledger(
    argv, client, isolate_settings, monkeypatch, capsys
) -> None:
    from assess.commands import list_findings

    _seed_ledger(client, isolate_settings, bulky_details=20_000)
    _record_chain(client)

    full, full_out, projected, projected_out = _both(list_findings, client, monkeypatch, capsys, argv)

    assert projected_out.out == full_out.out
    assert projected_out.err == full_out.err
    # The same requests in the same order; the ledger read is the projected one.
    assert projected.calls == full.calls
    assert projected.calls[0].startswith("findings?view=list&")
    assert projected.bytes_by_route["findings"] * 10 < full.bytes_by_route["findings"]
    if argv == ["list", "--verification-status", "blocked"]:
        assert "BLOCKED: needs a second Acme tenant account" in projected_out.out


@pytest.mark.parametrize(
    "argv",
    [
        ["list", "--json"],
        ["list", "--severity", "critical", "--json"],
        ["list", "--limit", "3", "--json"],
    ],
)
def test_finding_list_json_rows_are_identical_and_name_what_they_leave_out(
    argv, client, isolate_settings, monkeypatch, capsys
) -> None:
    from assess.commands import list_findings

    _seed_ledger(client, isolate_settings, bulky_details=20_000)

    full, full_out, projected, projected_out = _both(list_findings, client, monkeypatch, capsys, argv)

    assert json.loads(projected_out.out) == json.loads(full_out.out)
    assert projected_out.err == full_out.err
    assert projected.bytes_by_route["findings"] * 10 < full.bytes_by_route["findings"]
    # The rows are list fields only; stderr names what they leave out and the
    # point read that returns it.
    for field in ("summary", "details", "notes", "provenance", "proof_receipts", "next_test"):
        assert field in projected_out.err
    assert "`vigil assess finding get <slug>`" in projected_out.err


def test_finding_list_json_fields_are_served_by_the_list_view() -> None:
    from assess.commands import list_findings

    # root_cause_role exists only on the --root-cause group rows.
    served = set(list_findings._JSON_LIST_FIELDS) - {"root_cause_role"}
    assert served <= set(findings_module.FINDING_LIST_VIEW_FIELDS)


def test_chain_list_is_identical_on_the_projected_ledger(
    client, isolate_settings, monkeypatch, capsys
) -> None:
    from assess.commands import list_chains

    _seed_ledger(client, isolate_settings, bulky_details=20_000)
    _record_chain(client)

    for argv in (["list"], ["list", "--json"]):
        full, full_out, projected, projected_out = _both(list_chains, client, monkeypatch, capsys, argv)
        assert projected_out.out == full_out.out
        assert projected_out.err == full_out.err
        assert len(projected.calls) == len(full.calls)
        assert projected.bytes_by_route["findings"] * 10 < full.bytes_by_route["findings"]


def test_record_clobber_guard_reads_the_projected_ledger(
    client, isolate_settings, monkeypatch, capsys
) -> None:
    from assess.commands import record_finding

    _seed_ledger(client, isolate_settings, bulky_details=20_000)
    existing = client.get(f"{_base()}/findings/VA-001").json()
    payload = {
        "defect_family": existing["defect_family"],
        "root_cause_key": existing["root_cause_key"],
        "auth_context": existing["auth_context"],
        "canonical_location": existing["canonical_location"],
    }
    outcomes = []
    for full_rows in (True, False):
        bridge = _Bridge(client, full_rows=full_rows)
        monkeypatch.setattr(record_finding, "AssessmentClient", bridge)
        with pytest.raises(SystemExit):
            record_finding._guard_finding_clobber(
                payload, candidate_slug="VA-900",
                base_url="http://backend.example", engagement_key=ENGAGEMENT_KEY,
            )
        outcomes.append((bridge, capsys.readouterr().err))
    (full, full_err), (projected, projected_err) = outcomes
    assert "collides with existing finding VA-001" in projected_err
    assert projected_err == full_err
    assert projected.calls == ["findings?view=list"]
    assert projected.bytes_by_route["findings"] * 10 < full.bytes_by_route["findings"]

    bridge = _Bridge(client, full_rows=False)
    monkeypatch.setattr(record_finding, "AssessmentClient", bridge)
    record_finding._guard_finding_clobber(
        {**payload, "root_cause_key": "a-distinct-root"}, candidate_slug="VA-901",
        base_url="http://backend.example", engagement_key=ENGAGEMENT_KEY,
    )


def test_complete_gates_share_one_projected_finding_read(
    client, isolate_settings, monkeypatch
) -> None:
    from assess.commands import transition_phase

    _seed_ledger(client, isolate_settings, bulky_details=20_000)
    for slug in ("VA-001", "VA-005"):
        with db_module.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_findings SET verification_status='confirmed', status='active', "
                "severity='high' WHERE slug=?",
                (slug,),
            )
    gate_blockers = {}
    for full_rows in (True, False):
        bridge = _Bridge(client, full_rows=full_rows)
        monkeypatch.setattr(transition_phase, "AssessmentClient", bridge)
        blockers = transition_phase._check_preconditions(
            "complete", "web", "/engagements/acme", SimpleNamespace(),
            cfg=SimpleNamespace(base_url="http://backend.example", engagement_key=ENGAGEMENT_KEY),
        )
        finding_reads = [call for call in bridge.calls if urlsplit(call).path == "findings"]
        gate_blockers[full_rows] = (blockers, finding_reads, bridge)
    full_blockers, full_reads, full = gate_blockers[True]
    blockers, reads, projected = gate_blockers[False]

    assert blockers == full_blockers
    assert {"missing_blind_triage", "chain_construction_unchained"} <= {b["kind"] for b in blockers}
    assert reads == ["findings?view=list"]
    assert projected.bytes_by_route["findings"] * 10 < full.bytes_by_route["findings"]
