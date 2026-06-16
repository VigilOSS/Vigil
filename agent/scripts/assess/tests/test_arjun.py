"""Offline tests for the Arjun feature: enrichment helpers, target selection,
and the verb's flag→cmd construction. No docker, no backend, no billed calls."""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import arjun_select, kali_arjun
from assess.lib import arjun_enrich


# --------------------------------------------------------------------------
# arjun_enrich — pure helpers (slot routing, sqli rule, signals, rationale,
# JSON parsing, param merge)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "method,expected",
    [
        ("GET", "query_params"),
        ("get", "query_params"),
        ("POST", "body_params"),
        ("JSON", "body_params"),
        ("XML", "body_params"),
        ("", "query_params"),
        ("WEIRD", "query_params"),
    ],
)
def test_slot_for_method(method, expected):
    assert arjun_enrich.slot_for_method(method) == expected


@pytest.mark.parametrize(
    "params,expected",
    [
        (["id"], True),
        (["uid"], True),
        (["q"], True),
        (["search"], True),
        (["url"], False),
        (["file"], False),
        ([], False),
    ],
)
def test_routes_to_sqli(params, expected):
    assert arjun_enrich.routes_to_sqli(params) is expected


def test_build_signals_includes_params_header_params_and_marker():
    sig = arjun_enrich.build_signals(["a", "b"], header_params=["X-Tok"])
    assert "arjun:a" in sig
    assert "arjun:b" in sig
    assert "arjun-header:X-Tok" in sig
    assert "arjun-discovered-hidden-param" in sig


def test_build_signals_empty_is_empty():
    assert arjun_enrich.build_signals([], header_params=[]) == []


def test_triage_rationale_names_sqlmap_for_db_param():
    r = arjun_enrich.build_triage_rationale(method="GET", params=["id"])
    assert "sqlmap" in r.lower()
    assert "`id`" in r


def test_triage_rationale_no_sqlmap_for_non_db_param():
    r = arjun_enrich.build_triage_rationale(method="GET", params=["url"])
    assert "sqlmap" not in r.lower()
    assert "query" in r.lower()


def test_triage_rationale_body_param_says_body():
    r = arjun_enrich.build_triage_rationale(method="JSON", params=["payload"])
    assert "body" in r.lower()


def test_triage_rationale_header_params_noted():
    r = arjun_enrich.build_triage_rationale(
        method="GET", params=[], header_params=["X-Forwarded-For"]
    )
    assert "header" in r.lower()
    assert "`X-Forwarded-For`" in r


def test_parse_arjun_json_flat_url_to_list():
    recs = arjun_enrich.parse_arjun_json(json.dumps({"http://x/a": ["p1", "p2"]}))
    assert len(recs) == 1
    assert recs[0]["endpoint"] == "http://x/a"
    assert recs[0]["method"] == "GET"
    assert recs[0]["params"] == ["p1", "p2"]


def test_parse_arjun_json_per_endpoint_object_with_method_and_headers():
    payload = {"http://x/a": {"params": ["p"], "method": "post", "headers": {"H": 1}}}
    recs = arjun_enrich.parse_arjun_json(json.dumps(payload))
    assert recs[0]["method"] == "POST"
    assert recs[0]["params"] == ["p"]
    # `headers` echoes the REQUEST headers arjun was given, not discovered params,
    # so it must NOT become a finding.
    assert recs[0]["header_params"] == []


def test_parse_arjun_json_list_of_records():
    payload = [{"url": "http://x/a", "method": "JSON", "params": ["p"]}]
    recs = arjun_enrich.parse_arjun_json(payload and json.dumps(payload))
    assert recs[0]["method"] == "JSON"
    assert recs[0]["endpoint"] == "http://x/a"


def test_parse_arjun_json_invalid_returns_empty():
    assert arjun_enrich.parse_arjun_json("not json{{") == []


def test_parse_arjun_json_default_method_applied():
    recs = arjun_enrich.parse_arjun_json(
        json.dumps({"http://x/a": ["p"]}), default_method="POST"
    )
    assert recs[0]["method"] == "POST"


def test_merge_params_into_field_new_and_existing():
    assert arjun_enrich.merge_params_into_field(None, ["a"]) == json.dumps({"a": ""})
    merged = arjun_enrich.merge_params_into_field('{"x": "1"}', ["a"])
    assert json.loads(merged) == {"a": "", "x": "1"}


def test_merge_params_into_field_idempotent():
    once = arjun_enrich.merge_params_into_field(None, ["a", "b"])
    twice = arjun_enrich.merge_params_into_field(once, ["a", "b"])
    assert once == twice


# --------------------------------------------------------------------------
# arjun_select.select_targets — the gating that keeps Arjun off raw URL dumps
# --------------------------------------------------------------------------
def test_select_targets_live_only_by_default():
    rows = [
        {"url": "http://h/a", "url_path": "/a", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/b", "url_path": "/b", "type": "form", "status": "pending",
         "live_status": "blackholed", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/c", "url_path": "/c", "type": "form", "status": "pending",
         "live_status": "", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows)
    assert out == ["http://h/a"]


def test_select_targets_include_unknown_opts_in_blank_status():
    rows = [
        {"url": "http://h/c", "url_path": "/c", "type": "form", "status": "pending",
         "live_status": "", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows, include_unknown=True) == ["http://h/c"]


def test_select_targets_excludes_inert_and_skipped():
    rows = [
        {"url": "http://h/i.png", "url_path": "/i.png", "type": "image", "status": "skipped",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/v", "url_path": "/v", "type": "video", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/ok", "url_path": "/ok", "type": "form", "status": "skipped",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows) == []


def test_select_targets_dedups_id_varied_paths_by_template():
    # Both normalize to path:/explore-mvps/{year}, so the (host, template) dedup
    # collapses these id/year-varied URLs into one Arjun target (the scale story).
    rows = [
        {"url": "http://h/explore-mvps/2024/M0004", "url_path": "/explore-mvps/2024/M0004",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/explore-mvps/2023/G0058", "url_path": "/explore-mvps/2023/G0058",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows)
    assert len(out) == 1


def test_select_targets_param_poor_only():
    rows = [
        {"url": "http://h/rich", "url_path": "/rich", "type": "form", "status": "pending",
         "live_status": "live", "query_params": json.dumps({"a": "", "b": "", "c": ""}),
         "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/poor", "url_path": "/poor", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows, param_poor_only=True) == ["http://h/poor"]


def test_select_targets_max_per_host():
    rows = [
        {"url": f"http://h/p{i}", "url_path": f"/p{i}", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"}
        for i in range(5)
    ]
    out = arjun_select.select_targets(rows, max_per_host=2)
    assert len(out) == 2


# --------------------------------------------------------------------------
# kali_arjun.run — flag → cmd construction (monkeypatched exec)
# --------------------------------------------------------------------------
def _arjun_ns(**over):
    ns = argparse.Namespace(
        target_url="http://t/api/item",
        import_file="",
        method="GET",
        output_json="",
        output_text="",
        output_burp=kali_arjun._UNSET,
        wordlist="",
        chunks="",
        threads="",
        delay="",
        timeout_http="",
        rate_limit="",
        stable=False,
        headers=kali_arjun._UNSET,
        passive=None,
        include="",
        disable_redirects=False,
        casing="",
        quiet=False,
        extra_args="",
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


@pytest.fixture
def captured_cmd(monkeypatch):
    box: dict = {}

    def fake_exec(cmd, **kwargs):
        box["cmd"] = cmd
        return object()

    monkeypatch.setattr(kali_arjun, "kali_exec", fake_exec)
    monkeypatch.setattr(kali_arjun, "emit_result", lambda r: None)
    monkeypatch.setattr(kali_arjun, "kali_args_to_kwargs", lambda a: {})
    monkeypatch.setattr(kali_arjun, "extend_cmd_with_extra_args", lambda cmd, a: None)
    return box


def test_run_default_get_writes_json_to_scan_dir(captured_cmd):
    kali_arjun.run(_arjun_ns())
    cmd = captured_cmd["cmd"]
    assert cmd[0] == "arjun"
    assert "-u" in cmd and "http://t/api/item" in cmd
    assert "-m" in cmd and cmd[cmd.index("-m") + 1] == "GET"
    # JSON output always present, defaulted under scans/arjun/
    assert "-oJ" in cmd
    json_path = cmd[cmd.index("-oJ") + 1]
    assert json_path.startswith("scans/arjun/")


def test_run_json_method_and_headers_and_passive(captured_cmd):
    kali_arjun.run(_arjun_ns(method="JSON", headers="Authorization: Bearer X", passive=""))
    cmd = captured_cmd["cmd"]
    assert cmd[cmd.index("-m") + 1] == "JSON"
    assert cmd[cmd.index("--headers") + 1] == "Authorization: Bearer X"
    assert "--passive" in cmd  # bare passive, no source arg follows


def test_run_passive_with_sources(captured_cmd):
    kali_arjun.run(_arjun_ns(passive="wayback,otx"))
    cmd = captured_cmd["cmd"]
    assert cmd[cmd.index("--passive") + 1] == "wayback,otx"


def test_run_burp_sentinels(captured_cmd):
    # absent -> no -oB
    kali_arjun.run(_arjun_ns())
    assert "-oB" not in captured_cmd["cmd"]
    # bare -> "-oB" with no following value
    kali_arjun.run(_arjun_ns(output_burp=""))
    assert "-oB" in captured_cmd["cmd"]
    # value -> "-oB" + addr
    kali_arjun.run(_arjun_ns(output_burp="127.0.0.1:9090"))
    cmd = captured_cmd["cmd"]
    assert cmd[cmd.index("-oB") + 1] == "127.0.0.1:9090"


def test_run_requires_one_of_u_or_i(captured_cmd):
    from assess.lib.client import AssessError

    with pytest.raises(AssessError):
        kali_arjun.run(_arjun_ns(target_url="", import_file=""))
    with pytest.raises(AssessError):
        kali_arjun.run(_arjun_ns(target_url="http://t/", import_file="/tmp/x.txt"))


# --------------------------------------------------------------------------
# ingest-arjun — a missing JSON is a clean no-op (arjun writes none on 0 finds)
# --------------------------------------------------------------------------
def test_ingest_arjun_missing_json_is_noop(tmp_path, capsys):
    from assess.commands import ingest_arjun

    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # exists; the no-op returns before db_init/load_config
    ns = argparse.Namespace(
        db_path=str(db),
        json_file=str(tmp_path / "absent.json"),
        source="arjun",
        default_method="GET",
        engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)  # must NOT raise SystemExit
    out = json.loads(capsys.readouterr().out)
    assert out["records"] == 0
    assert out["enriched"] == 0
    assert "note" in out


def test_run_writes_empty_json_artifact_when_arjun_finds_nothing(
    tmp_path, monkeypatch, captured_cmd
):
    # arjun (faked via captured_cmd) writes no -oJ file; the verb must guarantee
    # an empty {} so the artifact always exists for ingest-arjun.
    class _Cfg:
        engagement_dir = str(tmp_path)

    monkeypatch.setattr("assess.lib.config.load_config", lambda *a, **k: _Cfg())
    ns = _arjun_ns(target_url="http://host.example/path")
    ns.engagement_dir = str(tmp_path)
    kali_arjun.run(ns)
    found = list((tmp_path / "scans" / "arjun" / "host.example").glob("*.json"))
    assert found, "verb did not create the guaranteed JSON artifact"
    assert found[0].read_text() == "{}"


# --------------------------------------------------------------------------
# ingest-arjun row matching + non-destructive enrichment (regression bugs found
# on the live cms.gov run: host-blind matching + curated-priority downgrade)
# --------------------------------------------------------------------------
def _mem_db():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE work_items (id INTEGER PRIMARY KEY, method TEXT, url TEXT, url_path TEXT, "
        "type TEXT, query_params TEXT, body_params TEXT, path_params TEXT, priority_score INTEGER, "
        "priority_reason TEXT, cluster_key TEXT, terminal_reason TEXT, signals TEXT, selected_by TEXT, "
        "triage_rationale TEXT, params_key_sig TEXT, status TEXT)"
    )
    return conn


def test_match_existing_row_distinguishes_same_path_different_host():
    from assess.commands import ingest_arjun

    conn = _mem_db()
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (1,'GET','https://aps.example/u/apps','/u/apps')")
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (2,'GET','https://elmo.example/u/apps','/u/apps')")
    aps = ingest_arjun._match_existing_row(conn, method="GET", url_path="/u/apps", url="https://aps.example/u/apps")
    elmo = ingest_arjun._match_existing_row(conn, method="GET", url_path="/u/apps", url="https://elmo.example/u/apps")
    assert aps["id"] == 1
    assert elmo["id"] == 2


def test_enrich_existing_never_downgrades_curated_priority():
    from assess.commands import ingest_arjun

    conn = _mem_db()
    conn.execute(
        "INSERT INTO work_items (id, method, url, url_path, type, query_params, body_params, path_params, "
        "priority_score, cluster_key, priority_reason, selected_by, signals, status) "
        "VALUES (1,'GET','https://h/apps','/apps','unknown','{}','{}','{}',95,'curated:high','curated','curated-src','[\"curated-sig\"]','pending')"
    )
    row = dict(conn.execute("SELECT * FROM work_items WHERE id=1").fetchone())
    record = {"endpoint": "https://h/apps", "method": "GET", "params": ["automation"], "header_params": []}
    ingest_arjun._enrich_existing(conn, row, record)
    after = dict(conn.execute("SELECT * FROM work_items WHERE id=1").fetchone())
    assert after["priority_score"] == 95            # not downgraded to gf:api (20)
    assert after["cluster_key"] == "curated:high"   # curated cluster preserved
    assert after["selected_by"] == "curated-src"    # provenance preserved
    assert "automation" in after["query_params"]    # discovered param still added
    sigs = json.loads(after["signals"])
    assert "curated-sig" in sigs and "arjun:automation" in sigs  # signals merged, not replaced


def test_merge_signal_lists_dedups_and_preserves():
    assert arjun_enrich.merge_signal_lists('["a"]', ["a", "b"]) == ["a", "b"]
    assert arjun_enrich.merge_signal_lists(None, ["x"]) == ["x"]
    assert arjun_enrich.merge_signal_lists("garbage{", ["x"]) == ["x"]
