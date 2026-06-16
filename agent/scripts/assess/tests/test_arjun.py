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
    assert recs[0]["header_params"] == ["H"]


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
