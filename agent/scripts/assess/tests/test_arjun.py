"""Offline tests for the Arjun feature: enrichment helpers, target selection,
and the verb's flag→cmd construction. No docker, no backend, no billed calls."""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import arjun_select, arjun_sweep, kali_arjun
from assess.lib import arjun_enrich

from _fake_client import FakeAssessmentClient


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config` (arjun commands read
    `.engagement_dir` / `.base_url` / `.engagement_key`)."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


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
    assert out == [("GET", "http://h/a")]


def test_select_targets_include_unknown_opts_in_blank_status():
    rows = [
        {"url": "http://h/c", "url_path": "/c", "type": "form", "status": "pending",
         "live_status": "", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows, include_unknown=True) == [("GET", "http://h/c")]


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
    assert sorted(out) == [("GET", "http://h/api/users/export"), ("GET", "http://h/api/users/search")]


def test_select_targets_param_poor_only():
    rows = [
        {"url": "http://h/rich", "url_path": "/rich", "type": "form", "status": "pending",
         "live_status": "live", "query_params": json.dumps({"a": "", "b": "", "c": ""}),
         "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/poor", "url_path": "/poor", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    assert arjun_select.select_targets(rows, param_poor_only=True) == [("GET", "http://h/poor")]


def test_arjun_select_run_writes_list_and_reports_budget_drops(tmp_path, monkeypatch, capsys):
    # End-to-end run(): the gated list is written, the summary carries the per-gate
    # drop breakdown, and a budget-truncated host warns on stderr (not silent).
    # The work buffer lives in the backend now; seed rows on the fake client and
    # let run() read them via get_all_pages("work-items").
    from assess.commands import arjun_select as asel

    fake = FakeAssessmentClient()
    for name in ("alpha", "beta", "gamma"):
        fake.add_row(
            queue_key=f"k:{name}", method="GET",
            url=f"https://h.example/{name}", url_path=f"/{name}",
            type="form", status="pending", live_status="live",
            query_params="{}", body_params="{}", path_params="{}",
        )
    monkeypatch.setattr(asel, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(asel, "AssessmentClient", lambda *a, **k: fake)

    out_file = tmp_path / "targets.txt"
    ns = argparse.Namespace(
        out=str(out_file), include_unknown=True,
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
    assert arjun_select.select_targets(rows) == [("GET", "https://h/ok")]


def test_select_targets_max_per_host():
    rows = [
        {"url": f"http://h/p{i}", "url_path": f"/p{i}", "type": "form", "status": "pending",
         "live_status": "live", "query_params": "{}", "body_params": "{}", "path_params": "{}"}
        for i in range(5)
    ]
    out = arjun_select.select_targets(rows, max_per_host=2)
    assert len(out) == 2


def test_select_targets_keeps_method_variants_separate():
    # Same route exposed as GET (query surface) AND POST (body surface). The old
    # (host, template) key collapsed them to one URL, and since `kali arjun -i`
    # applies a single global `-m`, the discarded verb's hidden body params were
    # never scanned. Method is now part of the dedup key, so BOTH survive, each
    # tagged with its own method.
    rows = [
        {"url": "http://h/api/search", "url_path": "/api/search", "method": "GET",
         "type": "api", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "http://h/api/search", "url_path": "/api/search", "method": "POST",
         "type": "api", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows)
    assert sorted(out) == [("GET", "http://h/api/search"), ("POST", "http://h/api/search")]


def test_select_targets_keeps_same_host_different_port_separate():
    # The same hostname on two ports is two live listeners; stripping the port
    # before the dedup key collapsed them and silently skipped one service. The
    # origin (scheme/host/port) is now in the key, so both are scanned.
    rows = [
        {"url": "https://app.example:8443/login", "url_path": "/login", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://app.example/login", "url_path": "/login", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows)
    assert sorted(u for _m, u in out) == [
        "https://app.example/login",
        "https://app.example:8443/login",
    ]


def test_select_targets_collapses_explicit_default_port():
    # An explicit default port and a bare URL are the SAME service; the origin
    # normalizes the scheme default away so they collapse (no spurious fork).
    rows = [
        {"url": "https://app.example:443/login", "url_path": "/login", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://app.example/login", "url_path": "/login", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows)
    assert len(out) == 1


def test_select_targets_budget_is_per_origin_not_hostname():
    # Per-host budget keys on ORIGIN: two ports on one hostname are distinct
    # services and each gets its own cap (the politeness limit protects a single
    # listener's request volume, and these are two listeners).
    rows = [
        {"url": "https://app.example:8443/a", "url_path": "/a", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://app.example:8443/b", "url_path": "/b", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://app.example/c", "url_path": "/c", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
        {"url": "https://app.example/d", "url_path": "/d", "method": "GET",
         "type": "form", "status": "pending", "live_status": "live",
         "query_params": "{}", "body_params": "{}", "path_params": "{}"},
    ]
    out = arjun_select.select_targets(rows, max_per_host=1)
    # One per origin: the :8443 service AND the :443 service each keep 1.
    assert len(out) == 2
    has_8443 = {("8443" in u) for _m, u in out}
    assert has_8443 == {True, False}, "budget must keep one URL from EACH port-origin"


def test_arjun_select_run_writes_method_specific_sidecars(tmp_path, monkeypatch, capsys):
    # run() must emit per-method sidecar lists so `kali arjun -i <out>.POST -m POST`
    # scans the body surface separately from the GET query surface — a single flat
    # list scanned under one -m would miss the other verb's hidden params.
    from assess.commands import arjun_select as asel

    fake = FakeAssessmentClient()
    fake.add_row(
        queue_key="k:get", method="GET",
        url="https://h.example/api/search", url_path="/api/search",
        type="api", status="pending", live_status="live",
        query_params="{}", body_params="{}", path_params="{}",
    )
    fake.add_row(
        queue_key="k:post", method="POST",
        url="https://h.example/api/search", url_path="/api/search",
        type="api", status="pending", live_status="live",
        query_params="{}", body_params="{}", path_params="{}",
    )
    monkeypatch.setattr(asel, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(asel, "AssessmentClient", lambda *a, **k: fake)

    out_file = tmp_path / "targets.txt"
    ns = argparse.Namespace(
        out=str(out_file), include_unknown=False,
        max_per_host=0, param_poor_only=False, engagement_dir=str(tmp_path),
    )
    asel.run(ns)
    summary = json.loads(capsys.readouterr().out)
    assert summary["selected"] == 2
    assert summary["selected_by_method"] == {"GET": 1, "POST": 1}

    get_sidecar = tmp_path / "targets.txt.GET"
    post_sidecar = tmp_path / "targets.txt.POST"
    assert get_sidecar.read_text().splitlines() == ["https://h.example/api/search"]
    assert post_sidecar.read_text().splitlines() == ["https://h.example/api/search"]
    assert summary["method_outputs"]["GET"] == str(get_sidecar)
    assert summary["method_outputs"]["POST"] == str(post_sidecar)
    # The union --out still carries every URL (backward-compatible).
    assert out_file.read_text().count("https://h.example/api/search") == 2


# NOTE: `test_arjun_select_run_anchors_relative_db_to_engagement` and
# `test_ingest_arjun_anchors_relative_db_to_engagement` were removed. Both pinned
# the anchoring of a relative `cases.db` positional to the engagement root. The
# local `cases.db` work buffer was folded into the backend `assessment_work_items`
# table, so neither command opens a db anymore (arjun-select and ingest-arjun read
# the buffer over HTTP via AssessmentClient); there is no db path to anchor and no
# `db_path` field in either summary. The engagement-relative resolution that
# remains — the `--json-file` path — is still covered by
# `test_ingest_arjun_anchors_relative_json_to_engagement` below.


def test_ingest_arjun_anchors_relative_json_to_engagement(tmp_path, capsys, monkeypatch):
    # A relative `--json-file` (e.g. `scans/arjun/out.json`) from a drifted cwd must
    # anchor to the engagement, not the process cwd. The artifact lives under <eng>;
    # the cwd is elsewhere and has no such file, so an UNANCHORED path would hit the
    # missing-file branch and report a CLEAN no-op — silently dropping a real
    # `kali arjun` discovery. Anchoring makes the drift-tolerant call find it.
    from assess.commands import ingest_arjun

    eng = tmp_path / "engagement"
    eng.mkdir()
    (eng / "scope.json").write_text("{}", encoding="utf-8")

    fake = FakeAssessmentClient()
    fake.add_row(
        queue_key="seed:GET:/known", method="GET",
        url="https://h.example/known", url_path="/known", type="unknown",
        source="seed", status="pending",
        query_params="{}", body_params="{}", path_params="{}",
    )

    arjun_json = {"https://h.example/known": {"params": ["debug"], "method": "GET"}}
    rel = "scans/arjun/out.json"
    jf = eng / rel
    jf.parent.mkdir(parents=True, exist_ok=True)
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg(str(eng)))
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_arjun, "AssessmentClient", lambda *a, **k: fake)

    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)

    ns = argparse.Namespace(
        json_file=rel, source="arjun",
        default_method="GET", engagement_dir=str(eng),
    )
    ingest_arjun.run(ns)  # must FIND the anchored artifact, not report the cwd no-op
    out = json.loads(capsys.readouterr().out)
    assert out["json_file"] == str(jf)   # anchored to the engagement, not the cwd
    assert out["records"] == 1
    assert out["enriched"] == 1

    enriched = fake.row_for_url("https://h.example/known")
    assert "debug" in json.loads(enriched[0]["query_params"])


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
    # End-to-end: a discovered endpoint that is not yet in the buffer must
    # actually LAND in it (the create path, via work-items/bulk), and a matching
    # one must be enriched — proving neither finding is silently dropped between
    # the JSON and the backend work buffer.
    from assess.commands import ingest_arjun

    fake = FakeAssessmentClient()
    fake.add_row(
        queue_key="seed:GET:/known",
        method="GET",
        url="https://h.example/known",
        url_path="/known",
        type="unknown",
        source="seed",
        status="pending",
        query_params="{}", body_params="{}", path_params="{}",
    )

    arjun_json = {
        "https://h.example/known": {"params": ["debug"], "method": "GET"},
        "https://h.example/brand-new": {"params": ["id"], "method": "GET"},
    }
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_arjun, "AssessmentClient", lambda *a, **k: fake)

    ns = argparse.Namespace(
        json_file=str(jf), source="arjun",
        default_method="GET", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)
    out = json.loads(capsys.readouterr().out)
    assert out["enriched"] == 1
    assert out["created"] == 1
    assert out["malformed_preserved"] == 0

    created = fake.row_for_url("https://h.example/brand-new")
    assert len(created) == 1, "new arjun endpoint was silently dropped, not inserted"
    assert "id" in json.loads(created[0]["query_params"])
    assert created[0]["selected_by"] == "arjun"

    enriched = fake.row_for_url("https://h.example/known")
    assert "debug" in json.loads(enriched[0]["query_params"])


def test_ingest_arjun_candidates_on_two_hosts_create_two_rows(tmp_path, monkeypatch, capsys):
    # Same method/path/params discovered on two in-scope hosts must create TWO
    # work items. A host-blind candidate queue_key (`arjun:METHOD:url_path:sig`)
    # collapsed them into one via UNIQUE(queue_key); the key must carry the host.
    from assess.commands import ingest_arjun

    fake = FakeAssessmentClient()

    arjun_json = {
        "https://aps.example/u/apps": {"params": ["file"], "method": "POST"},
        "https://elmo.example/u/apps": {"params": ["file"], "method": "POST"},
    }
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_arjun, "AssessmentClient", lambda *a, **k: fake)

    ns = argparse.Namespace(
        json_file=str(jf), source="arjun",
        default_method="POST", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)

    urls = sorted(row["url"] for row in fake.rows)
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
# during a live run: host-blind matching + curated-priority downgrade)
# --------------------------------------------------------------------------
# `_match_existing_row` now matches over the backend-fetched work-item ROW DICTS
# (pre-sorted by id) instead of an SQLite connection — the work buffer moved to
# the backend. These helpers/tests pass the same rows as a list of dicts.


def test_match_existing_row_distinguishes_same_path_different_host():
    from assess.commands import ingest_arjun

    rows = [
        {"id": 1, "method": "GET", "url": "https://aps.example/u/apps", "url_path": "/u/apps"},
        {"id": 2, "method": "GET", "url": "https://elmo.example/u/apps", "url_path": "/u/apps"},
    ]
    aps = ingest_arjun._match_existing_row(rows, method="GET", url_path="/u/apps", url="https://aps.example/u/apps")
    elmo = ingest_arjun._match_existing_row(rows, method="GET", url_path="/u/apps", url="https://elmo.example/u/apps")
    assert aps["id"] == 1
    assert elmo["id"] == 2


def test_match_existing_row_distinguishes_same_url_different_method():
    # Same url present as BOTH a GET and a POST work item: a POST Arjun run must
    # enrich the POST row, not the lowest-id GET row. The old exact-URL lookup
    # (`WHERE url = ? ORDER BY id LIMIT 1`) ignored method and returned the GET
    # row (id 1), writing the discovered body params onto the wrong surface.
    from assess.commands import ingest_arjun

    # GET row gets the LOWER id so a naive "first by id" match picks it wrongly.
    rows = [
        {"id": 1, "method": "GET", "url": "https://h.example/api/item", "url_path": "/api/item"},
        {"id": 2, "method": "POST", "url": "https://h.example/api/item", "url_path": "/api/item"},
    ]
    post = ingest_arjun._match_existing_row(
        rows, method="POST", url_path="/api/item", url="https://h.example/api/item"
    )
    get = ingest_arjun._match_existing_row(
        rows, method="GET", url_path="/api/item", url="https://h.example/api/item"
    )
    assert post["id"] == 2, "POST run must match the POST row, not the lower-id GET row"
    assert get["id"] == 1, "GET run must still match the GET row"


def test_ingest_arjun_post_enriches_post_row_not_get_row(tmp_path, monkeypatch, capsys):
    # End-to-end: a url present as BOTH a GET and a POST work item, with the GET
    # row at the LOWER id. A POST Arjun enrichment for that url must write the
    # discovered body param onto the POST row and leave the GET row's params
    # untouched — the old url-only match enriched the wrong (GET) row.
    from assess.commands import ingest_arjun

    fake = FakeAssessmentClient()
    # Seed the GET row first so it lands at the lower id.
    fake.add_row(
        queue_key="seed:GET:/api/item", method="GET",
        url="https://h.example/api/item", url_path="/api/item",
        type="unknown", source="seed", status="pending",
        query_params="{}", body_params="{}", path_params="{}",
    )
    fake.add_row(
        queue_key="seed:POST:/api/item", method="POST",
        url="https://h.example/api/item", url_path="/api/item",
        type="unknown", source="seed", status="pending",
        query_params="{}", body_params="{}", path_params="{}",
    )

    arjun_json = {"https://h.example/api/item": {"params": ["payload"], "method": "POST"}}
    jf = tmp_path / "arjun.json"
    jf.write_text(json.dumps(arjun_json), encoding="utf-8")

    monkeypatch.setattr(ingest_arjun, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_arjun, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_arjun, "AssessmentClient", lambda *a, **k: fake)

    ns = argparse.Namespace(
        json_file=str(jf), source="arjun",
        default_method="POST", engagement_dir=str(tmp_path),
    )
    ingest_arjun.run(ns)
    out = json.loads(capsys.readouterr().out)
    assert out["enriched"] == 1
    assert out["created"] == 0

    post_row = next(r for r in fake.rows if r["method"] == "POST" and r["url"] == "https://h.example/api/item")
    get_row = next(r for r in fake.rows if r["method"] == "GET" and r["url"] == "https://h.example/api/item")
    # The POST row (correct surface) received the discovered body param...
    assert "payload" in json.loads(post_row["body_params"])
    # ...and the GET row (wrong surface) was left untouched.
    assert "payload" not in json.loads(get_row["body_params"])
    assert "payload" not in json.loads(get_row["query_params"])


def test_match_existing_row_does_not_match_substring_or_subdomain_host():
    from assess.commands import ingest_arjun

    # Rows on a subdomain and on a substring-containing host, sharing the path.
    rows = [
        {"id": 1, "method": "GET", "url": "https://app.cms.example/apps", "url_path": "/apps"},
        {"id": 2, "method": "GET", "url": "https://evilcms.example/apps", "url_path": "/apps"},
    ]
    # An endpoint on the APEX host must match NEITHER (different origins) — the old
    # `LIKE '%cms.example%'` fallback would have wrongly matched both.
    apex = ingest_arjun._match_existing_row(
        rows, method="GET", url_path="/apps", url="https://cms.example/apps"
    )
    assert apex is None
    # The exact subdomain endpoint still matches its own row.
    sub = ingest_arjun._match_existing_row(
        rows, method="GET", url_path="/apps", url="https://app.cms.example/apps"
    )
    assert sub["id"] == 1


def test_enrich_existing_never_downgrades_curated_priority():
    # `_enrich_existing(row, record)` now RETURNS `(summary, bulk_item)` — the
    # work-items/bulk upsert payload — instead of mutating a db connection. The
    # enrichment must not downgrade a curated row's priority/cluster/provenance.
    from assess.commands import ingest_arjun

    row = {
        "id": 1, "queue_key": "seed:GET:/apps", "method": "GET",
        "url": "https://h/apps", "url_path": "/apps", "type": "unknown",
        "query_params": "{}", "body_params": "{}", "path_params": "{}",
        "priority_score": 95, "cluster_key": "curated:high",
        "priority_reason": "curated", "selected_by": "curated-src",
        "signals": '["curated-sig"]', "status": "pending",
    }
    record = {"endpoint": "https://h/apps", "method": "GET", "params": ["automation"], "header_params": []}
    _summary, item = ingest_arjun._enrich_existing(row, record)
    assert item["priority_score"] == 95            # not downgraded to gf:api (20)
    assert item["cluster_key"] == "curated:high"   # curated cluster preserved
    assert item["selected_by"] == "curated-src"    # provenance preserved
    assert "automation" in item["query_params"]    # discovered param still added
    sigs = json.loads(item["signals"])
    assert "curated-sig" in sigs and "arjun:automation" in sigs  # signals merged, not replaced


def test_enrich_existing_preserves_malformed_param_column():
    # If the target param column is corrupt JSON, enrichment must PRESERVE it
    # (never overwrite/destroy it) while still capturing the discovery in signals.
    from assess.commands import ingest_arjun

    row = {
        "id": 1, "queue_key": "seed:GET:/x", "method": "GET",
        "url": "https://h/x", "url_path": "/x", "type": "unknown",
        "query_params": "THIS-IS-NOT-JSON", "body_params": "{}", "path_params": "{}",
        "priority_score": 50, "cluster_key": "c", "priority_reason": "r",
        "selected_by": "seed", "signals": '["s"]', "params_key_sig": "sig0",
        "status": "pending",
    }
    record = {"endpoint": "https://h/x", "method": "GET", "params": ["foo"], "header_params": []}
    summary, item = ingest_arjun._enrich_existing(row, record)
    assert item["query_params"] == "THIS-IS-NOT-JSON"      # corrupt column NOT destroyed
    assert item["params_key_sig"] == "sig0"                # signature not recomputed from garbage
    sigs = json.loads(item["signals"])
    assert "arjun:foo" in sigs                              # discovery NOT lost
    assert "arjun-param-field-malformed-preserved" in sigs  # and loudly flagged
    assert "s" in sigs                                      # original signal preserved
    assert summary["malformed_param_field"] is True


def test_merge_signal_lists_dedups_and_preserves():
    assert arjun_enrich.merge_signal_lists('["a"]', ["a", "b"]) == ["a", "b"]
    assert arjun_enrich.merge_signal_lists(None, ["x"]) == ["x"]
    # A corrupt prior signals value is unrecoverable, but the loss is FLAGGED
    # (marker prepended) rather than silently dropped.
    assert arjun_enrich.merge_signal_lists("garbage{", ["x"]) == [
        arjun_enrich.SIGNALS_UNPARSED_MARKER,
        "x",
    ]


# --------------------------------------------------------------------------
# Incomplete-run guard — a timed-out/killed list run is NOT a clean negative
# (the "arjun scanned 2 of 134 then SIGTERM, reported a false 0" trap).
# --------------------------------------------------------------------------
from assess.lib import kali_cli  # noqa: E402


def test_count_list_targets(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("https://a/1\n\n# comment\nhttps://b/2\n  \nhttps://c/3\n")
    assert kali_cli.count_list_targets(str(f)) == 3
    assert kali_cli.count_list_targets("/no/such/file") == 0
    assert kali_cli.count_list_targets("") == 0


def test_count_list_targets_anchors_container_path(tmp_path):
    # Finding 2: the tool sees an in-container `/engagements/<key>/...` path; read
    # raw on the host it doesn't exist (returns 0, silently disabling the guard).
    # With engagement_dir it must anchor to the host file and count correctly.
    (tmp_path / "scans" / "arjun-sweep").mkdir(parents=True)
    listfile = tmp_path / "scans" / "arjun-sweep" / "GET.txt"
    listfile.write_text("https://x/a\nhttps://x/b\nhttps://x/c\n")
    container = "/engagements/eng/scans/arjun-sweep/GET.txt"
    assert kali_cli.count_list_targets(container) == 0  # the bug, unanchored
    assert kali_cli.count_list_targets(container, engagement_dir=str(tmp_path)) == 3
    # engagement-relative paths anchor too.
    assert kali_cli.count_list_targets(
        "scans/arjun-sweep/GET.txt", engagement_dir=str(tmp_path)
    ) == 3
    # a bare host-absolute path is read as-is (no engagement_dir needed).
    assert kali_cli.count_list_targets(str(listfile)) == 3


def test_incomplete_sentinel_round_trip():
    # Finding 1: a killed/timed-out run with no output writes a sentinel instead
    # of a bare {} so ingest can tell it apart from a real "0 params" negative.
    from assess.lib import arjun_enrich as ae

    sentinel = ae.incomplete_sentinel()
    assert ae.artifact_is_incomplete(sentinel) is True
    assert ae.parse_arjun_json(sentinel) == []  # sentinel key is skipped, no junk record
    # a genuine empty / real artifact is NOT flagged incomplete
    assert ae.artifact_is_incomplete("{}") is False
    assert ae.artifact_is_incomplete('{"https://x/a": ["id", "q"]}') is False
    assert len(ae.parse_arjun_json('{"https://x/a": ["id", "q"]}')) == 1


def test_mark_artifact_incomplete_preserves_partial_records():
    text = arjun_enrich.mark_artifact_incomplete(
        '{"https://x/a": ["id", "q"]}'
    )

    assert arjun_enrich.artifact_is_incomplete(text) is True
    assert arjun_enrich.parse_arjun_json(text) == [
        {
            "endpoint": "https://x/a",
            "method": "GET",
            "params": ["id", "q"],
            "header_params": [],
        }
    ]


def test_kali_arjun_marks_existing_incomplete_artifact(tmp_path, monkeypatch):
    from assess.lib import config

    artifact = tmp_path / "scans" / "arjun" / "out.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"https://x/a": ["id"]}', encoding="utf-8")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda _flag: argparse.Namespace(engagement_dir=str(tmp_path)),
    )

    kali_arjun._ensure_json_artifact(
        argparse.Namespace(engagement_dir=str(tmp_path)),
        "/engagements/eng/scans/arjun/out.json",
        incomplete=True,
    )

    text = artifact.read_text(encoding="utf-8")
    assert arjun_enrich.artifact_is_incomplete(text) is True
    assert arjun_enrich.parse_arjun_json(text)[0]["endpoint"] == "https://x/a"


def test_arjun_sweep_marks_existing_incomplete_artifact(tmp_path):
    artifact = tmp_path / "GET.json"
    artifact.write_text('{"https://x/a": ["id"]}', encoding="utf-8")

    arjun_sweep._ensure_json_artifact(artifact, incomplete=True)

    text = artifact.read_text(encoding="utf-8")
    assert arjun_enrich.artifact_is_incomplete(text) is True
    assert arjun_enrich.parse_arjun_json(text)[0]["endpoint"] == "https://x/a"


def test_parse_list_progress():
    assert kali_cli.parse_list_progress("Scanning 12/134 ...") == (12, 134)
    assert kali_cli.parse_list_progress("Processing: 3 / 50") == (3, 50)
    # highest wins; a keyword prefix is REQUIRED so a bare fraction (a URL path,
    # a status ratio) is never mistaken for progress.
    assert kali_cli.parse_list_progress("Scanning 1/10 ... Scanning 7/10") == (7, 10)
    assert kali_cli.parse_list_progress("no progress markers") is None
    assert kali_cli.parse_list_progress("GET /api/v1/10 -> 200/404") is None


def test_incomplete_warning_fires_on_timed_out_multitarget():
    note = kali_cli.incomplete_list_run_warning(
        tool="arjun", total_targets=134, timed_out=True, return_code=143,
        stdout_preview="Scanning 2/134",
    )
    assert "INCOMPLETE" in note and "2 of 134" in note
    # killed via non-zero rc (not just timed_out) also counts
    assert kali_cli.incomplete_list_run_warning(
        tool="arjun", total_targets=10, timed_out=False, return_code=143) != ""


def test_incomplete_warning_silent_on_clean_or_single():
    assert kali_cli.incomplete_list_run_warning(
        tool="arjun", total_targets=50, timed_out=False, return_code=0) == ""
    # a single-target timeout is a different problem, not flagged as a list truncation
    assert kali_cli.incomplete_list_run_warning(
        tool="arjun", total_targets=1, timed_out=True, return_code=143) == ""


def test_kali_arjun_warns_incomplete_on_timed_out_list(tmp_path, monkeypatch, capsys):
    listfile = tmp_path / "targets.txt"
    listfile.write_text("https://a/1\nhttps://b/2\nhttps://c/3\n")

    class _R:
        timed_out = True
        return_code = 143
        stdout_preview = "Scanning 1/3"
        stderr_preview = ""

    monkeypatch.setattr(kali_arjun, "kali_exec", lambda cmd, **k: _R())
    monkeypatch.setattr(kali_arjun, "emit_result", lambda r: None)
    monkeypatch.setattr(kali_arjun, "kali_args_to_kwargs", lambda a: {})
    monkeypatch.setattr(kali_arjun, "extend_cmd_with_extra_args", lambda cmd, a: None)
    monkeypatch.setattr(kali_arjun, "_ensure_json_artifact", lambda a, p, **k: None)

    kali_arjun.run(_arjun_ns(target_url="", import_file=str(listfile)))
    err = capsys.readouterr().err
    assert "INCOMPLETE" in err and "arjun" in err


def test_kali_arjun_silent_when_single_url_completes(captured_cmd, capsys):
    # the default -u (single target) run that does NOT time out emits no incomplete warning
    kali_arjun.run(_arjun_ns())
    assert "INCOMPLETE" not in capsys.readouterr().err
