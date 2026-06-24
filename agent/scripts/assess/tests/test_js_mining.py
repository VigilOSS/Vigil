"""js-mining stage: bounded JS asset fetch -> jsluice/regex endpoint extraction
-> trufflehog secret scan -> endpoint ingest. Best-effort, rate-capped,
header-carrying (header injection is exercised by the kali_exec central injector
and the host-route header tests; here we pin argv shape + the pipeline seams)."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from assess.commands import js_mining


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _scope(tmp_path: Path, **fields) -> None:
    payload = {"engagement_type": "web", "hosts": ["example.com"]}
    payload.update(fields)
    (tmp_path / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def _args(tmp_path: Path, **over) -> SimpleNamespace:
    ns = SimpleNamespace(engagement_dir=str(tmp_path))
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def _container_to_host(tmp_path: Path, path: str) -> Path:
    prefix = "/engagements/eng/"
    if path.startswith(prefix):
        return tmp_path / path[len(prefix):]
    return Path(path)


def _install_seams(monkeypatch, tmp_path, *, captured, body_text=None, jsluice_lines=None, th_lines=None):
    """Stub kali_exec for the three tools and ingest_endpoints.run.

    httpx stub writes one stored body (so the regex extractor + trufflehog have a
    file); jsluice stub writes its JSONL output; trufflehog stub writes its JSON
    detections — all at the container -> host mapped path."""
    monkeypatch.setattr(js_mining, "load_config", lambda d: _cfg(tmp_path))

    def fake_kali(cmd, **kwargs):
        captured.append(list(cmd))
        tool = kwargs.get("tool_name")
        if tool == "httpx" and body_text is not None:
            # -store-response-dir is the bodies dir; drop one body file there.
            d_idx = cmd.index("-store-response-dir")
            bodies = _container_to_host(tmp_path, cmd[d_idx + 1])
            bodies.mkdir(parents=True, exist_ok=True)
            (bodies / "https-example-com-abc.txt").write_text(body_text, encoding="utf-8")
        elif tool == "jsluice" and jsluice_lines is not None:
            # bash -lc "... > <out> ..."; pull the jsluice.jsonl host path.
            out = tmp_path / "scans" / "web-discovery" / "js-mining" / "jsluice.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("".join(line + "\n" for line in jsluice_lines), encoding="utf-8")
        elif tool == "trufflehog" and th_lines is not None:
            out = tmp_path / "scans" / "web-discovery" / "js-mining" / "trufflehog.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("".join(line + "\n" for line in th_lines), encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(js_mining, "kali_exec", fake_kali)

    ingested: list[str] = []

    def fake_ingest(ns):
        ingested.append(ns.input_file)

    monkeypatch.setattr(js_mining.ingest_endpoints, "run", fake_ingest)
    return ingested


def _katana_source(tmp_path: Path) -> Path:
    p = tmp_path / "katana.jsonl"
    p.write_text(
        '{"request":{"endpoint":"https://example.com/app.js"}}\n'
        '{"request":{"endpoint":"https://example.com/index.html"}}\n'
        '{"request":{"endpoint":"https://example.com/vendor.min.js?v=2"}}\n',
        encoding="utf-8",
    )
    return p


def _run(monkeypatch, tmp_path, args, **seams):
    captured: list[list[str]] = []
    ingested = _install_seams(monkeypatch, tmp_path, captured=captured, **seams)
    out = io.StringIO()
    with redirect_stdout(out):
        js_mining.run(args)
    summary = json.loads(out.getvalue())
    return captured, ingested, summary


def test_selects_js_from_katana_and_fetches_bounded(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    body = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" \
           'fetch("/api/v2/users");'
    captured, ingested, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path=str(tmp_path / "cases.db"),
              target="example.com"),
        body_text=body, jsluice_lines=[], th_lines=[],
    )

    # Two .js URLs selected from the katana crawl (html dropped).
    assert summary["js_assets_selected"] == 2
    js_list = tmp_path / "scans" / "web-discovery" / "js-mining" / "js_targets.txt"
    targets = js_list.read_text(encoding="utf-8").split()
    assert "https://example.com/app.js" in targets
    assert "https://example.com/vendor.min.js?v=2" in targets
    assert not any(".html" in t for t in targets)

    # httpx body fetch ran with -store-response (the central injector adds the
    # attribution header on the real path; here we pin -store-response presence).
    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    assert httpx_runs and "-store-response" in httpx_runs[0]

    # The regex extractor recovered the /api/v2/users endpoint from the body.
    assert summary["endpoints_extracted"] >= 1
    assert summary["endpoints_ingested"] == summary["endpoints_extracted"]
    assert ingested  # ingest-endpoints was called with the endpoints file


def test_max_js_bounds_fetch(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    captured, _, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), max_js=1, db_path=""),
        body_text="HTTP/1.1 200 OK\r\n\r\n", jsluice_lines=[], th_lines=[],
    )
    assert summary["js_assets_selected"] == 1  # bounded by --max-js


def test_rate_cap_clamps_body_fetch(monkeypatch, tmp_path):
    _scope(tmp_path, rate_limit=3)
    src = _katana_source(tmp_path)
    captured, _, _ = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path=""),
        body_text="HTTP/1.1 200 OK\r\n\r\n", jsluice_lines=[], th_lines=[],
    )
    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    rate = httpx_runs[0][httpx_runs[0].index("-rate-limit") + 1]
    assert rate == "3"  # clamped to per-host cap (below the default 30)


def test_jsluice_endpoints_merged_when_present(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    captured, _, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path=str(tmp_path / "cases.db"),
              target="example.com"),
        body_text="HTTP/1.1 200 OK\r\n\r\n// no regex-shaped endpoints here",
        jsluice_lines=['{"url":"https://example.com/admin/secret"}'],
        th_lines=[],
    )
    assert summary["jsluice_ran"] is True
    endpoints = (tmp_path / "scans" / "web-discovery" / "js-mining" / "js_endpoints.txt"
                 ).read_text(encoding="utf-8")
    assert "https://example.com/admin/secret" in endpoints


def test_off_target_endpoints_filtered(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    _, _, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path="", target="example.com"),
        body_text="HTTP/1.1 200 OK\r\n\r\n",
        jsluice_lines=['{"url":"https://cdn.othercorp.com/leak"}',
                       '{"url":"https://example.com/keep"}'],
        th_lines=[],
    )
    endpoints = (tmp_path / "scans" / "web-discovery" / "js-mining" / "js_endpoints.txt"
                 ).read_text(encoding="utf-8")
    assert "example.com/keep" in endpoints
    assert "othercorp.com" not in endpoints  # off-target host dropped


def test_off_scope_endpoints_dropped_without_target(monkeypatch, tmp_path):
    # Recon-pipeline path: _run_js calls js-mining with target="" (multi-apex), so
    # the engagement scope allowlist — not --target — must keep off-scope endpoint
    # hosts out of the work buffer. Regression for the verify-flagged LOW.
    _scope(tmp_path)  # hosts: ["example.com"]
    src = _katana_source(tmp_path)
    _, _, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path="", target=""),
        body_text="HTTP/1.1 200 OK\r\n\r\n",
        jsluice_lines=['{"url":"https://cdn.othercorp.com/leak"}',
                       '{"url":"https://example.com/keep"}'],
        th_lines=[],
    )
    endpoints = (tmp_path / "scans" / "web-discovery" / "js-mining" / "js_endpoints.txt"
                 ).read_text(encoding="utf-8")
    assert "example.com/keep" in endpoints
    assert "othercorp.com" not in endpoints  # off-scope host dropped without --target


def test_trufflehog_digest_and_no_secrets_flag(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    th = ['{"DetectorName":"AWS","Verified":true,"Raw":"AKIA...",'
          '"SourceMetadata":{"Data":{"Filesystem":{"file":"/b/app.js"}}}}']
    _, _, summary = _run(
        monkeypatch, tmp_path,
        _args(tmp_path, urls_file=str(src), db_path=""),
        body_text="HTTP/1.1 200 OK\r\n\r\n", jsluice_lines=[], th_lines=th,
    )
    assert summary["secrets"]["findings_count"] == 1
    assert summary["secrets"]["detector_counts"]["AWS"] == 1

    # --no-secrets skips the trufflehog scan entirely.
    captured: list[list[str]] = []
    _install_seams(monkeypatch, tmp_path, captured=captured,
                   body_text="HTTP/1.1 200 OK\r\n\r\n", jsluice_lines=[], th_lines=th)
    out = io.StringIO()
    with redirect_stdout(out):
        js_mining.run(_args(tmp_path, urls_file=str(src), db_path="", no_secrets=True))
    summary2 = json.loads(out.getvalue())
    assert summary2["secrets"] == {"skipped": True}
    assert not any(c and c[0] == "bash" and "trufflehog" in " ".join(c) for c in captured)


def test_no_js_assets_exits_clean(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = tmp_path / "empty.jsonl"
    src.write_text('{"request":{"endpoint":"https://example.com/page.html"}}\n', encoding="utf-8")
    captured: list[list[str]] = []
    _install_seams(monkeypatch, tmp_path, captured=captured, body_text=None)
    # No .js → returns without fetching anything (best-effort, no crash).
    js_mining.run(_args(tmp_path, urls_file=str(src), db_path=""))
    assert not captured  # nothing dispatched


def test_best_effort_survives_httpx_failure(monkeypatch, tmp_path):
    _scope(tmp_path)
    src = _katana_source(tmp_path)
    monkeypatch.setattr(js_mining, "load_config", lambda d: _cfg(tmp_path))

    def boom(cmd, **kwargs):
        if kwargs.get("tool_name") == "httpx":
            return SimpleNamespace(return_code=1)  # fetch failed
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(js_mining, "kali_exec", boom)
    monkeypatch.setattr(js_mining.ingest_endpoints, "run", lambda ns: None)
    out = io.StringIO()
    with redirect_stdout(out):
        js_mining.run(_args(tmp_path, urls_file=str(src), db_path=""))  # must not raise
    summary = json.loads(out.getvalue())
    assert summary["verb"] == "js-mining"
    assert summary["bodies_scanned"] == 0
