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


def test_merge_params_into_field_refuses_to_overwrite_malformed_existing():
    # A non-empty value that is not a JSON object must NOT be silently replaced by
    # `{new}` (that would destroy whatever the column held) — it raises so the
    # caller can preserve the original and record the discovery in signals instead.
    with pytest.raises(ValueError):
        arjun_enrich.merge_params_into_field("not-json{", ["a"])
    with pytest.raises(ValueError):
        arjun_enrich.merge_params_into_field('["a","list","not","an","object"]', ["a"])


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


def test_select_targets_keeps_distinct_sibling_routes():
    # Two distinct routes that merely share a 2-segment prefix must BOTH be
    # probed: the old 2-segment cluster key collapsed /api/users/search and
    # /api/users/export to /api/users and silently dropped one from Arjun.
    rows = [
        {"url": "http://h/api/users/search", "url_path": "/api/users/search",
         "type": "api", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/api/users/export", "url_path": "/api/users/export",
         "type": "api", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows, max_per_host=50)
    assert sorted(out) == ["http://h/api/users/export", "http://h/api/users/search"]


def test_select_targets_param_poor_only():
    rows = [
        {"url": "http://h/rich", "url_path": "/rich", "type": "form", "status": "pending",
         "live_status": "live", "query_params": json.dumps({"a": "", "b": "", "c": ""}),
         "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/poor", "url_path": "/poor", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows, param_poor_only=True) == ["http://h/poor"]


def test_arjun_select_run_writes_list_and_reports_budget_drops(tmp_path, capsys):
    # End-to-end run(): the gated list is written, the summary carries the per-gate
    # drop breakdown, and a budget-truncated host warns on stderr (not silent).
    from assess.commands import arjun_select as asel
    from assess.lib.db import db_init, db_insert_work_item

    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    for name in ("alpha", "beta", "gamma"):
        db_insert_work_item(
            str(db), queue_key=f"k:{name}", method="GET",
            url=f"https://h.example/{name}", url_path=f"/{name}",
            case_type="form", live_status="live",
        )
    out_file = tmp_path / "targets.txt"
    ns = argparse.Namespace(
        db_path=str(db), out=str(out_file), include_unknown=True,
        max_per_host=1, param_poor_only=False, engagement_dir=str(tmp_path),
    )
    asel.run(ns)
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["selected"] == 1
    assert summary["drops"]["dropped_by_budget"] == 2
    assert "max-per-host" in captured.err           # truncation surfaced, not silent
    assert len([ln for ln in out_file.read_text().splitlines() if ln.strip()]) == 1


def test_select_targets_stats_account_for_every_scanned_row():
    # Every scanned row is either selected or dropped by exactly one gate; the
    # stats must balance so a truncated run can never look like full coverage.
    def _r(url, path, **over):
        base = {"url": url, "url_path": path, "type": "form", "status": "pending",
                "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"}
        base.update(over)
        return base

    rows = [
        _r("", ""),                                            # dropped_no_url
        _r("ws://h/s", "/s"),                                  # dropped_non_http
        _r("http://h/a.png", "/a.png", type="image"),         # dropped_inert
        _r("http://h/sk", "/sk", status="skipped"),           # dropped_skipped_status
        _r("http://h/dead", "/dead", live_status="blackholed"),  # dropped_not_live
        _r("http://h/p/2024/M0004", "/p/2024/M0004"),         # \ id-varied: collapse
        _r("http://h/p/2023/G0058", "/p/2023/G0058"),         # / to one template
        _r("http://h/one", "/one"),                           # template 2 (budget keeps 1)
        _r("http://h/two", "/two"),                           # template 3 (budget drops)
    ]
    stats: dict = {}
    out = arjun_select.select_targets(rows, max_per_host=1, stats=stats)

    assert stats["scanned"] == len(rows)
    pre = (stats["dropped_no_url"] + stats["dropped_non_http"] + stats["dropped_inert"]
           + stats["dropped_skipped_status"] + stats["dropped_not_live"]
           + stats["dropped_param_rich"])
    assert pre + stats["eligible"] == stats["scanned"]                       # nothing vanishes
    assert stats["collapsed_by_dedup"] + stats["templates_after_dedup"] == stats["eligible"]
    assert stats["dropped_by_budget"] + stats["selected"] == stats["templates_after_dedup"]
    assert stats["collapsed_by_dedup"] == 1                                  # the 2024/2023 pair
    assert stats["dropped_by_budget"] == 2                                   # 3 templates, cap 1
    assert len(out) == stats["selected"] == 1


def test_select_targets_skips_non_http_and_hostless():
    rows = [
        {"url": "ws://h/socket", "url_path": "/socket", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "mailto:a@b.com", "url_path": "", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "/relative/only", "url_path": "/relative/only", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://h/ok", "url_path": "/ok", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows) == ["https://h/ok"]


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


def test_run_passive_with_explicit_host(captured_cmd):
    # arjun's --passive value is a HOST to harvest params for (not a source list);
    # passing it through verbatim lets the operator harvest a different domain.
    kali_arjun.run(_arjun_ns(passive="example.com"))
    cmd = captured_cmd["cmd"]
    assert cmd[cmd.index("--passive") + 1] == "example.com"


def test_run_bare_passive_with_import_file_is_rejected(captured_cmd):
    # Bare --passive harvests for the -u target's own domain (arjun derives the
    # host from the URL); with -i there is no single URL, so it must be rejected.
    from assess.lib.client import AssessError

    with pytest.raises(AssessError):
        kali_arjun.run(_arjun_ns(target_url="", import_file="/tmp/targets.txt", passive=""))
    with pytest.raises(AssessError):  # explicit `--passive -` is the same derive-from-url mode
        kali_arjun.run(_arjun_ns(target_url="", import_file="/tmp/targets.txt", passive="-"))


def test_run_passive_explicit_host_allowed_with_import_file(captured_cmd):
    # An explicit harvest host IS valid with -i (harvest that domain, scan the list).
    kali_arjun.run(_arjun_ns(target_url="", import_file="/tmp/targets.txt", passive="example.com"))
    cmd = captured_cmd["cmd"]
    assert cmd[cmd.index("--passive") + 1] == "example.com"
    assert "-i" in cmd


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


def test_ingest_arjun_run_creates_new_and_enriches_existing(tmp_path, monkeypatch, capsys):
    # End-to-end over a REAL schema: a discovered endpoint that is not yet in the
    # buffer must actually LAND in it (the create path), and a matching one must be
    # enriched — proving neither finding is silently dropped between JSON and DB.
    from assess.commands import ingest_arjun
    from assess.lib.db import db_init, db_insert_work_item, db_query

    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))
    db_insert_work_item(
        str(db),
        queue_key="seed:GET:/known",
        method="GET",
        url="https://h.example/known",
        url_path="/known",
        case_type="unknown",
        source="seed",
    )

    arjun_json = {
        "https://h.example/known": {"params": ["debug"], "method": "GET"},
        "https://h.example/brand-new": {"params": ["id"], "method": "GET"},
    }
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    class _Cfg:
        engagement_dir = str(tmp_path)

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")

    ns = argparse.Namespace(
        db_path=str(db), json_file=str(jf), source="arjun",
        default_method="GET", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)
    out = json.loads(capsys.readouterr().out)
    assert out["enriched"] == 1
    assert out["created"] == 1
    assert out["malformed_preserved"] == 0

    created = db_query(
        str(db),
        "SELECT query_params, selected_by FROM work_items WHERE url = ?",
        ("https://h.example/brand-new",),
    )
    assert len(created) == 1, "new arjun endpoint was silently dropped, not inserted"
    assert "id" in json.loads(created[0]["query_params"])
    assert created[0]["selected_by"] == "arjun"

    enriched = db_query(
        str(db), "SELECT query_params FROM work_items WHERE url = ?", ("https://h.example/known",)
    )
    assert "debug" in json.loads(enriched[0]["query_params"])


def test_ingest_arjun_candidates_on_two_hosts_create_two_rows(tmp_path, monkeypatch, capsys):
    # Same method/path/params discovered on two in-scope hosts must create TWO
    # work items. A host-blind candidate queue_key (`arjun:METHOD:url_path:sig`)
    # collapsed them into one via UNIQUE(queue_key); the key must carry the host.
    from assess.commands import ingest_arjun
    from assess.lib.db import db_init, db_query

    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))

    arjun_json = {
        "https://aps.example/u/apps": {"params": ["file"], "method": "POST"},
        "https://elmo.example/u/apps": {"params": ["file"], "method": "POST"},
    }
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    class _Cfg:
        engagement_dir = str(tmp_path)

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")

    ns = argparse.Namespace(
        db_path=str(db), json_file=str(jf), source="arjun",
        default_method="POST", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)

    rows = db_query(str(db), "SELECT url FROM work_items ORDER BY url", ())
    urls = [r["url"] for r in rows]
    assert urls == ["https://aps.example/u/apps", "https://elmo.example/u/apps"], \
        "host-blind queue_key collapsed two distinct host surfaces into one row"


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


def test_match_existing_row_distinguishes_same_url_different_method():
    # Same url present as BOTH a GET and a POST work item: a POST Arjun run must
    # enrich the POST row, not the lowest-id GET row. The old exact-URL lookup
    # (`WHERE url = ? ORDER BY id LIMIT 1`) ignored method and returned the GET
    # row (id 1), writing the discovered body params onto the wrong surface.
    from assess.commands import ingest_arjun

    conn = _mem_db()
    # GET row gets the LOWER id so the old ORDER BY id LIMIT 1 picks it wrongly.
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (1,'GET','https://h.example/api/item','/api/item')")
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (2,'POST','https://h.example/api/item','/api/item')")
    post = ingest_arjun._match_existing_row(
        conn, method="POST", url_path="/api/item", url="https://h.example/api/item"
    )
    get = ingest_arjun._match_existing_row(
        conn, method="GET", url_path="/api/item", url="https://h.example/api/item"
    )
    assert post["id"] == 2, "POST run must match the POST row, not the lower-id GET row"
    assert get["id"] == 1, "GET run must still match the GET row"


def test_ingest_arjun_post_enriches_post_row_not_get_row(tmp_path, monkeypatch, capsys):
    # End-to-end over the REAL schema: a url present as BOTH a GET and a POST work
    # item, with the GET row at the LOWER id. A POST Arjun enrichment for that url
    # must write the discovered body param onto the POST row and leave the GET
    # row's params untouched — the old url-only match enriched the wrong (GET) row.
    from assess.commands import ingest_arjun
    from assess.lib.db import db_init, db_insert_work_item, db_query

    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    # Insert the GET row first so it lands at the lower id.
    db_insert_work_item(
        str(db), queue_key="seed:GET:/api/item", method="GET",
        url="https://h.example/api/item", url_path="/api/item",
        case_type="unknown", source="seed",
    )
    db_insert_work_item(
        str(db), queue_key="seed:POST:/api/item", method="POST",
        url="https://h.example/api/item", url_path="/api/item",
        case_type="unknown", source="seed",
    )

    arjun_json = {"https://h.example/api/item": {"params": ["payload"], "method": "POST"}}
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    class _Cfg:
        engagement_dir = str(tmp_path)

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")

    ns = argparse.Namespace(
        db_path=str(db), json_file=str(jf), source="arjun",
        default_method="POST", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)
    out = json.loads(capsys.readouterr().out)
    assert out["enriched"] == 1
    assert out["created"] == 0

    post_row = db_query(
        str(db),
        "SELECT body_params, query_params FROM work_items WHERE method = 'POST' AND url = ?",
        ("https://h.example/api/item",),
    )[0]
    get_row = db_query(
        str(db),
        "SELECT body_params, query_params FROM work_items WHERE method = 'GET' AND url = ?",
        ("https://h.example/api/item",),
    )[0]
    # The POST row (correct surface) received the discovered body param...
    assert "payload" in json.loads(post_row["body_params"])
    # ...and the GET row (wrong surface) was left untouched.
    assert "payload" not in json.loads(get_row["body_params"])
    assert "payload" not in json.loads(get_row["query_params"])


def test_match_existing_row_does_not_match_substring_or_subdomain_host():
    from assess.commands import ingest_arjun

    conn = _mem_db()
    # Rows on a subdomain and on a substring-containing host, sharing the path.
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (1,'GET','https://app.cms.example/apps','/apps')")
    conn.execute("INSERT INTO work_items (id, method, url, url_path) VALUES (2,'GET','https://evilcms.example/apps','/apps')")
    # An endpoint on the APEX host must match NEITHER (different origins) — the old
    # `LIKE '%cms.example%'` fallback would have wrongly matched both.
    apex = ingest_arjun._match_existing_row(
        conn, method="GET", url_path="/apps", url="https://cms.example/apps"
    )
    assert apex is None
    # The exact subdomain endpoint still matches its own row.
    sub = ingest_arjun._match_existing_row(
        conn, method="GET", url_path="/apps", url="https://app.cms.example/apps"
    )
    assert sub["id"] == 1


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


def test_enrich_existing_preserves_malformed_param_column():
    # If the target param column is corrupt JSON, enrichment must PRESERVE it
    # (never overwrite/destroy it) while still capturing the discovery in signals.
    from assess.commands import ingest_arjun

    conn = _mem_db()
    conn.execute(
        "INSERT INTO work_items (id, method, url, url_path, type, query_params, body_params, path_params, "
        "priority_score, cluster_key, priority_reason, selected_by, signals, params_key_sig, status) "
        "VALUES (1,'GET','https://h/x','/x','unknown','THIS-IS-NOT-JSON','{}','{}',50,'c','r','seed','[\"s\"]','sig0','pending')"
    )
    row = dict(conn.execute("SELECT * FROM work_items WHERE id=1").fetchone())
    record = {"endpoint": "https://h/x", "method": "GET", "params": ["foo"], "header_params": []}
    res = ingest_arjun._enrich_existing(conn, row, record)
    after = dict(conn.execute("SELECT * FROM work_items WHERE id=1").fetchone())
    assert after["query_params"] == "THIS-IS-NOT-JSON"      # corrupt column NOT destroyed
    assert after["params_key_sig"] == "sig0"                # signature not recomputed from garbage
    sigs = json.loads(after["signals"])
    assert "arjun:foo" in sigs                              # discovery NOT lost
    assert "arjun-param-field-malformed-preserved" in sigs  # and loudly flagged
    assert "s" in sigs                                      # original signal preserved
    assert res["malformed_param_field"] is True


def test_merge_signal_lists_dedups_and_preserves():
    assert arjun_enrich.merge_signal_lists('["a"]', ["a", "b"]) == ["a", "b"]
    assert arjun_enrich.merge_signal_lists(None, ["x"]) == ["x"]
    # A corrupt prior signals value is unrecoverable, but the loss is FLAGGED
    # (marker prepended) rather than silently dropped.
    assert arjun_enrich.merge_signal_lists("garbage{", ["x"]) == [
        arjun_enrich.SIGNALS_UNPARSED_MARKER,
        "x",
    ]
