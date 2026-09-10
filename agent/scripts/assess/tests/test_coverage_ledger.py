"""W2 — coverage ledger: per-host route counts, real_app/OR-inclusion, and the
measured + VISIBLE coverage-state projection.

The ledger is the centerpiece: it makes an uncovered in-scope host obvious at a
glance. These tests pin the BLUNT route-count heuristic (>=6 live routes), the
OR-inclusion that catches small high-value APIs under the threshold, the
parking/redirect/dead exclusion, the WAF "needs_browser_reprobe" surfacing, and
the rule that a RECORDED VERDICT (a finding) — not a mere completed dispatch —
is what flips a host to ``covered``.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

from assess.lib import coverage_checks as cc
from assess.commands import coverage as coverage_cmd
from assess.lib.config import Config
from _fake_client import FakeAssessmentClient, host_of


# --------------------------------------------------------------------------- #
# work-item seeding helpers
#
# The former per-engagement ``cases.db`` ``work_items`` table was folded into
# the orchestrator backend; ``load_route_stats_by_host`` now reads the buffer
# through ``client.get_all_pages("work-items")``. These helpers seed that same
# durable state on the backend-less ``FakeAssessmentClient`` instead of a local
# sqlite db.
# --------------------------------------------------------------------------- #


def _make_fake() -> FakeAssessmentClient:
    return FakeAssessmentClient()


def _insert_work_item(
    fake,
    *,
    queue_key: str,
    url: str,
    url_path: str,
    case_type: str = "api",
    status: str = "pending",
    response_status: int | None = 200,
    live_status: str | None = None,
) -> None:
    # ``add_row`` auto-derives the row's ``host`` column from ``url`` — the same
    # column ``load_route_stats_by_host`` groups on — so no host is passed here.
    fake.add_row(
        queue_key=queue_key,
        method="GET",
        url=url,
        url_path=url_path,
        type=case_type,
        source="test",
        status=status,
        response_status=response_status,
        live_status=live_status,
        query_params="{}",
        body_params="{}",
    )


def _cfg(eng_dir: Path) -> Config:
    return Config(
        base_url="http://127.0.0.1:18000",
        engagement_dir=str(eng_dir),
        engagement_key="2026-06-26-000000-ledger",
        agent_root=str(eng_dir / "agent"),
    )


def _empty_verdict() -> dict:
    return {
        "has_finding": False,
        "finding_count": 0,
        "verified_count": 0,
        "strongest_status": None,
        "max_severity": None,
        "auth_contexts": [],
        "verification_statuses": [],
        "slugs": [],
    }


def _verdict(**over) -> dict:
    base = _empty_verdict()
    base.update({"has_finding": True, "finding_count": 1})
    base.update(over)
    return base


def _per_host_payload(*, hosts=None, finding_verdicts=None) -> dict:
    return {
        "objectives": [
            "waf_tier",
            "service_inventory",
            "directory_fuzz",
            "tech_fingerprint",
            "osint",
        ],
        "hosts": hosts or [],
        "finding_verdicts": finding_verdicts or {},
        "engagement_signals": {},
    }


def _host_row(host: str, *, waf: bool = False) -> dict:
    def cell(met: bool) -> dict:
        return {"met": met, "evidence": [], "deferred": False}

    return {
        "host": host,
        "outcomes": {
            "waf_tier": cell(waf),
            "service_inventory": cell(True),
            "directory_fuzz": cell(False),
            "tech_fingerprint": cell(False),
            "osint": cell(False),
        },
        "unmet_objectives": [],
        "deferred_objectives": [],
        "deferrals": [],
    }


def test_dispatch_host_lanes_resolve_concrete_application_units():
    dispatches = [
        {
            "agent_id": "va-1",
            "agent_role": "vulnerability-analyst",
            "application_unit_id": 7,
        },
        {
            "agent_id": "va-unattributed",
            "agent_role": "vulnerability-analyst",
            "application_unit_id": None,
        },
    ]
    units = [{"id": 7, "host": "app.example.com", "path_prefix": "/api"}]
    assert cc.dispatched_hosts_from_rows(dispatches, units) == {
        "app.example.com": ["vulnerability-analyst"]
    }


# --------------------------------------------------------------------------- #
# load_route_stats_by_host
# --------------------------------------------------------------------------- #


def test_route_stats_counts_distinct_live_paths():
    fake = _make_fake()
    base = "https://a.example.com"
    for i in range(3):
        _insert_work_item(
            fake, queue_key=f"k{i}", url=f"{base}/p{i}", url_path=f"/p{i}",
            response_status=200,
        )
    # Duplicate path (different query) — distinct by url_path, counts once.
    _insert_work_item(
        fake, queue_key="kdup", url=f"{base}/p0?x=1", url_path="/p0", response_status=200,
    )
    # A dead path: counts toward total but NOT live.
    _insert_work_item(
        fake, queue_key="kdead", url=f"{base}/dead", url_path="/dead",
        response_status=0, live_status="blackholed@5m",
    )
    # host_root crawl seed — excluded from routes entirely.
    _insert_work_item(
        fake, queue_key="kroot", url=base, url_path="/", case_type="host_root",
        response_status=200,
    )

    stats = cc.load_route_stats_by_host(fake)
    assert "a.example.com" in stats
    row = stats["a.example.com"]
    assert row["live_routes"] == 3
    assert row["total_routes"] == 4  # 3 live + 1 dead, host_root excluded


def test_route_stats_live_status_stamp_counts_as_live():
    fake = _make_fake()
    _insert_work_item(
        fake, queue_key="k1", url="https://b.example.com/x", url_path="/x",
        response_status=0, live_status="live@9m",
    )
    stats = cc.load_route_stats_by_host(fake)
    assert stats["b.example.com"]["live_routes"] == 1


def test_route_stats_detects_api_auth_graphql():
    fake = _make_fake()
    host = "https://api.example.com"
    _insert_work_item(fake, queue_key="kapi", url=f"{host}/api/v1/users", url_path="/api/v1/users")
    _insert_work_item(fake, queue_key="kauth", url=f"{host}/login", url_path="/login")
    _insert_work_item(fake, queue_key="kgql", url=f"{host}/graphql", url_path="/graphql")
    stats = cc.load_route_stats_by_host(fake)["api.example.com"]
    assert stats["api_like"] is True
    assert stats["auth_like"] is True
    assert stats["graphql_like"] is True


def test_route_stats_empty_buffer_is_empty():
    # The former "missing cases.db → {}" concept is gone now that the buffer
    # lives behind the backend; an EMPTY work-item buffer yields an empty map.
    assert cc.load_route_stats_by_host(_make_fake()) == {}


# --------------------------------------------------------------------------- #
# build_coverage_ledger — state machine
# --------------------------------------------------------------------------- #


def _ledger(**over):
    kwargs = dict(
        scope_data={"hosts": ["target.example", "*.target.example"]},
        route_stats_by_host={},
        per_host_payload=_per_host_payload(),
        dispatched_hosts={},
        route_threshold=6,
    )
    kwargs.update(over)
    return cc.build_coverage_ledger(**kwargs)


def _row_for(ledger: dict, host: str) -> dict:
    rows = {r["host"]: r for r in ledger["hosts"]}
    assert host in rows, f"{host} not in ledger: {list(rows)}"
    return rows[host]


def test_real_app_over_threshold_without_finding_is_uncovered():
    host = "app.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 8, "total_routes": 8,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(hosts=[_host_row(host)]),
    )
    row = _row_for(ledger, host)
    assert row["real_app"] is True
    assert row["route_count"] == 8
    assert row["coverage_state"] == "uncovered"
    assert row["has_recorded_verdict"] is False


def test_real_app_with_finding_is_covered():
    host = "app.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 8, "total_routes": 8,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(
            hosts=[_host_row(host)],
            finding_verdicts={host: _verdict(verified_count=1, strongest_status="active")},
        ),
    )
    row = _row_for(ledger, host)
    assert row["coverage_state"] == "covered"
    assert row["has_recorded_verdict"] is True
    assert row["finding_verdict"]["has_finding"] is True


def test_dedicated_lane_without_finding_stays_uncovered():
    """A shallow lane (completed dispatch) must NOT clear a host."""
    host = "app.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 8, "total_routes": 8,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(hosts=[_host_row(host)]),
        dispatched_hosts={host: ["vulnerability-analyst"]},
    )
    row = _row_for(ledger, host)
    assert row["dedicated_lane"] is True
    assert row["lane_roles"] == ["vulnerability-analyst"]
    assert row["coverage_state"] == "uncovered"


def test_small_api_under_threshold_is_real_app_via_or_inclusion():
    """Crown-jewel microservices are few-paths/high-value: the OR-inclusion
    keeps a 2-route API surface in the ledger as a real_app gap."""
    host = "api.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 2, "total_routes": 2,
                                    "api_like": True, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(hosts=[_host_row(host)]),
    )
    row = _row_for(ledger, host)
    assert row["real_app"] is True
    assert row["api_auth_graphql"] is True
    assert row["coverage_state"] == "uncovered"


def test_parking_host_excluded():
    host = "parked.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 1, "total_routes": 1,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(hosts=[_host_row(host)]),
    )
    row = _row_for(ledger, host)
    assert row["real_app"] is False
    assert row["coverage_state"] == "excluded"


def test_waf_host_low_routes_needs_browser_reprobe():
    host = "waf.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 2, "total_routes": 2,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(hosts=[_host_row(host, waf=True)]),
    )
    row = _row_for(ledger, host)
    assert row["waf"] is True
    assert row["needs_browser_reprobe"] is True
    assert row["coverage_state"] == "needs_browser_reprobe"


def test_waf_host_with_finding_is_covered_not_reprobe():
    host = "waf.target.example"
    ledger = _ledger(
        route_stats_by_host={host: {"live_routes": 2, "total_routes": 2,
                                    "api_like": False, "auth_like": False,
                                    "graphql_like": False}},
        per_host_payload=_per_host_payload(
            hosts=[_host_row(host, waf=True)],
            finding_verdicts={host: _verdict()},
        ),
    )
    row = _row_for(ledger, host)
    assert row["coverage_state"] == "covered"


def test_finding_only_host_is_real_app_and_covered():
    """A host with a verdict but no recon routes is a real target — covered."""
    host = "admin.target.example"
    ledger = _ledger(
        per_host_payload=_per_host_payload(
            finding_verdicts={host: _verdict(max_severity="high")},
        ),
    )
    row = _row_for(ledger, host)
    assert row["real_app"] is True
    assert row["coverage_state"] == "covered"


def test_out_of_scope_host_excluded_from_ledger():
    host = "vendor.target.example"
    ledger = _ledger(
        scope_data={"hosts": ["*.target.example"], "out_of_scope": ["vendor.target.example"]},
        route_stats_by_host={host: {"live_routes": 9, "total_routes": 9,
                                    "api_like": True, "auth_like": False,
                                    "graphql_like": False}},
    )
    assert host not in {r["host"] for r in ledger["hosts"]}


def test_summary_counts_each_state():
    payload_hosts = [
        _host_row("covered.target.example"),
        _host_row("uncovered.target.example"),
        _host_row("waf.target.example", waf=True),
        _host_row("parked.target.example"),
    ]
    ledger = _ledger(
        route_stats_by_host={
            "covered.target.example": {"live_routes": 8, "total_routes": 8,
                                   "api_like": False, "auth_like": False, "graphql_like": False},
            "uncovered.target.example": {"live_routes": 8, "total_routes": 8,
                                     "api_like": False, "auth_like": False, "graphql_like": False},
            "waf.target.example": {"live_routes": 1, "total_routes": 1,
                               "api_like": False, "auth_like": False, "graphql_like": False},
            "parked.target.example": {"live_routes": 1, "total_routes": 1,
                                  "api_like": False, "auth_like": False, "graphql_like": False},
        },
        per_host_payload=_per_host_payload(
            hosts=payload_hosts,
            finding_verdicts={"covered.target.example": _verdict()},
        ),
    )
    summary = ledger["summary"]
    assert summary["covered"] == 1
    assert summary["uncovered"] == 1
    assert summary["needs_browser_reprobe"] == 1
    assert summary["excluded"] == 1
    assert summary["total"] == 4


# --------------------------------------------------------------------------- #
# command — end-to-end render
# --------------------------------------------------------------------------- #


class FakeClient:
    def __init__(self, *, per_host_payload, dispatches=None):
        self._per_host_payload = per_host_payload
        self._dispatches = dispatches or []
        self.calls: list[str] = []
        # Folded-in work-item buffer the command reads via
        # ``load_route_stats_by_host`` → ``get_all_pages("work-items")``.
        self._rows: list[dict] = []
        self._next_id = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def add_row(self, **fields) -> dict:
        row = dict(fields)
        self._next_id += 1
        row.setdefault("id", self._next_id)
        if "host" not in row and row.get("url"):
            row["host"] = host_of(row["url"])
        self._rows.append(row)
        return row

    def get_all_pages(self, endpoint: str, **kwargs):
        path = endpoint.partition("?")[0].strip("/")
        if path == "work-items":
            return list(self._rows)
        return []

    def get(self, endpoint: str):
        self.calls.append(endpoint)
        if endpoint == "coverage-readiness/by-host":
            return self._per_host_payload
        if endpoint == "application-units":
            return []
        raise AssertionError(f"unexpected endpoint {endpoint}")

    def list_dispatches(self, **filters):
        return self._dispatches


def _write_scope(eng_dir: Path, hosts: list[str]) -> None:
    (eng_dir / "scope.json").write_text(
        json.dumps({"hosts": hosts, "current_phase": "consume"}), encoding="utf-8"
    )


def test_command_json_output_flags_uncovered_gap(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir()
    _write_scope(eng_dir, ["target.example", "*.target.example"])

    payload = _per_host_payload(hosts=[_host_row("app.target.example")])
    fake = FakeClient(per_host_payload=payload)
    base = "https://app.target.example"
    for i in range(7):
        _insert_work_item(fake, queue_key=f"k{i}", url=f"{base}/p{i}", url_path=f"/p{i}")

    monkeypatch.setattr(coverage_cmd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(coverage_cmd, "AssessmentClient", lambda *a, **k: fake)

    args = SimpleNamespace(engagement_dir=str(eng_dir), route_threshold=6, as_json=True)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        coverage_cmd.run(args)

    data = json.loads(out.getvalue())
    rows = {r["host"]: r for r in data["hosts"]}
    assert rows["app.target.example"]["coverage_state"] == "uncovered"
    assert data["summary"]["uncovered"] == 1


def test_command_text_output_surfaces_uncovered_block(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir()
    _write_scope(eng_dir, ["target.example", "*.target.example"])

    payload = _per_host_payload(hosts=[_host_row("app.target.example")])
    fake = FakeClient(per_host_payload=payload)
    base = "https://app.target.example"
    for i in range(7):
        _insert_work_item(fake, queue_key=f"k{i}", url=f"{base}/p{i}", url_path=f"/p{i}")

    monkeypatch.setattr(coverage_cmd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(coverage_cmd, "AssessmentClient", lambda *a, **k: fake)

    args = SimpleNamespace(engagement_dir=str(eng_dir), route_threshold=6, as_json=False)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        coverage_cmd.run(args)

    text = out.getvalue()
    assert "app.target.example" in text
    assert "uncovered" in text.lower()
