"""web-discovery pipeline Phase-4 fixes: httpx-liveness seating (Fix 2) and
katana-metadata preservation (Fix 3).

These drive the real ``web_discovery.run`` with the execution seams (kali_exec /
host_exec / ingest-httpx / ingest-endpoints) stubbed, asserting on the JSON-line
work-item file each stage hands to ingest-endpoints — not on a live runtime or
backend. The seam emulates httpx AND katana writing their ``-o`` JSONL so the
real Stage-2b / Stage-4 readers run against produced files.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from assess.commands import web_discovery


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _scope(tmp_path: Path, **fields) -> None:
    payload = {"engagement_type": "web", "hosts": ["example.com"]}
    payload.update(fields)
    (tmp_path / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def _hosts_file(tmp_path: Path, hosts: list[str]) -> Path:
    p = tmp_path / "hosts.txt"
    p.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return p


def _args(tmp_path: Path, hosts_file: Path, **over) -> SimpleNamespace:
    ns = SimpleNamespace(hosts_file=str(hosts_file), engagement_dir=str(tmp_path))
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


class _Client:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _install_seams(monkeypatch, tmp_path, *, captured, ingested,
                   httpx_rows: dict[str, list[str]], katana_rows: list[str]):
    """Stub kali_exec to emulate httpx + katana writing their -o JSONL, and
    ingest-endpoints.run to record (input_file, source, parsed-rows)."""
    monkeypatch.setattr(web_discovery, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(web_discovery, "AssessmentClient", lambda *a, **k: _Client())
    monkeypatch.setattr(
        web_discovery, "ingest_httpx_results",
        lambda *a, **k: {"upserted": 0, "by_class": {}},
    )

    container_prefix = "/engagements/eng/"

    def _to_host(path: str) -> Path:
        if path.startswith(container_prefix):
            return tmp_path / path[len(container_prefix):]
        return Path(path)

    def fake_kali(cmd, **kwargs):
        captured.append(list(cmd))
        tool = kwargs.get("tool_name")
        out = cmd[cmd.index("-o") + 1] if "-o" in cmd else ""
        if tool == "httpx":
            ports = cmd[cmd.index("-p") + 1] if "-p" in cmd else ""
            rows = httpx_rows.get(ports, [])
            if out:
                host_out = _to_host(out)
                host_out.parent.mkdir(parents=True, exist_ok=True)
                host_out.write_text("".join(r + "\n" for r in rows), encoding="utf-8")
        elif tool == "katana" and out:
            host_out = _to_host(out)
            host_out.parent.mkdir(parents=True, exist_ok=True)
            host_out.write_text("".join(r + "\n" for r in katana_rows), encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(web_discovery, "kali_exec", fake_kali)

    def fake_ingest(ns):
        path = Path(ns.input_file)
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line) if line.startswith("{") else line)
        ingested.append({"input_file": ns.input_file, "source": ns.source, "rows": rows})

    monkeypatch.setattr(web_discovery.ingest_endpoints, "run", fake_ingest)


# ---------------------------------------------------------------------------
# Fix 2 — seat httpx liveness as work items
# ---------------------------------------------------------------------------
def test_seats_live_httpx_results_as_work_items(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com", "dead.example.com"])
    captured, ingested = [], []
    httpx_rows = {
        "80,443": ['{"url":"https://live.example.com","input":"live.example.com","status_code":200}'],
        web_discovery._REVALIDATE_PORTS: [
            '{"url":"https://dead.example.com:8080","input":"dead.example.com","status_code":401}'
        ],
    }
    _install_seams(monkeypatch, tmp_path, captured=captured, ingested=ingested,
                   httpx_rows=httpx_rows, katana_rows=[])

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container",
                            no_crawl=True, db_path="cases.db"))

    # Exactly one ingest call (Stage 2b; no katana → no Stage 4).
    assert len(ingested) == 1
    call = ingested[0]
    assert call["source"] == "web-discovery"
    rows = call["rows"]
    assert len(rows) == 2
    # Shape per the plan.
    for r in rows:
        assert r["method"] == "GET"
        assert r["type"] == "unknown"
        assert r["source"] == "web-discovery"
        assert r["live_status"] == "live"
        assert r["signals"] == ["httpx-live"]
    # Revalidation hit (non-standard port) is seated FIRST.
    assert rows[0]["url"] == "https://dead.example.com:8080"
    assert rows[0]["response_status"] == 401
    assert rows[1]["url"] == "https://live.example.com"
    assert rows[1]["response_status"] == 200


def test_seat_liveness_default_off_without_db(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured, ingested = [], []
    httpx_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, ingested=ingested,
                   httpx_rows=httpx_rows, katana_rows=[])

    # No --db → nothing to seat (and nothing to ingest at all).
    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=True))
    assert ingested == []


def test_no_seat_liveness_flag_overrides_db_default(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured, ingested = [], []
    httpx_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, ingested=ingested,
                   httpx_rows=httpx_rows, katana_rows=[])

    # --db set but --no-seat-liveness → Stage 2b skipped.
    web_discovery.run(_args(tmp_path, hosts_file, runtime="container",
                            no_crawl=True, db_path="cases.db", seat_liveness=False))
    assert ingested == []


def test_seat_liveness_helper_dedups_and_orders(tmp_path):
    path = tmp_path / "httpx_live.jsonl"
    path.write_text(
        '{"url":"https://a.example.com","status_code":200}\n'
        '{"url":"https://a.example.com","status_code":200}\n'   # dup
        '{"url":"https://b.example.com:9443","status_code":403}\n'
        '{"failed":true,"url":"https://dead.example.com"}\n',   # skipped (failed)
        encoding="utf-8",
    )
    out = web_discovery._seat_liveness_work_items(path)
    urls = [r["url"] for r in out]
    assert urls == ["https://b.example.com:9443", "https://a.example.com"]  # dedup + port-first


# ---------------------------------------------------------------------------
# Fix 3 — preserve katana metadata as {url, content_type, ...} JSONL
# ---------------------------------------------------------------------------
def test_katana_metadata_emitted_as_jsonl(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured, ingested = [], []
    httpx_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    katana_rows = [
        '{"request":{"endpoint":"https://live.example.com/api/x"},'
        '"response":{"status_code":200,"headers":{"content_type":"application/json"},'
        '"technologies":["nginx","php"]}}',
        # bare endpoint, no response block (the -or/-ob default) → url-only row.
        '{"request":{"endpoint":"https://live.example.com/page"}}',
    ]
    _install_seams(monkeypatch, tmp_path, captured=captured, ingested=ingested,
                   httpx_rows=httpx_rows, katana_rows=katana_rows,
                   )

    # seat_liveness=False isolates this to the Stage-4 katana ingest.
    web_discovery.run(_args(tmp_path, hosts_file, runtime="container",
                            no_crawl=False, db_path="cases.db", seat_liveness=False))

    assert len(ingested) == 1
    call = ingested[0]
    assert call["input_file"].endswith("katana_urls.jsonl")
    assert call["source"] == "web-discovery"
    rows = {r["url"]: r for r in call["rows"]}
    enriched = rows["https://live.example.com/api/x"]
    assert enriched["content_type"] == "application/json"
    assert enriched["response_status"] == 200
    assert enriched["tech"] == "nginx,php"
    # Backward-compatible bare row: just the url, still valid for ingest.
    bare = rows["https://live.example.com/page"]
    assert bare == {"url": "https://live.example.com/page"}


def test_katana_records_unit_backward_compatible(tmp_path):
    katana = tmp_path / "katana.jsonl"
    katana.write_text(
        # bare-URL legacy shapes still parse to a url-only record.
        '{"endpoint":"https://h/a"}\n'
        '{"url":"https://h/b"}\n'
        # response metadata threaded forward when present.
        '{"request":{"endpoint":"https://h/c"},'
        '"response":{"status_code":204,"headers":{"content-type":"text/html"}}}\n'
        # duplicate url enriches the same record once.
        '{"request":{"endpoint":"https://h/a"},'
        '"response":{"headers":{"content_type":"image/png"}}}\n',
        encoding="utf-8",
    )
    out = web_discovery._katana_records(katana)
    by_url = {r["url"]: r for r in out}
    assert set(by_url) == {"https://h/a", "https://h/b", "https://h/c"}
    assert by_url["https://h/b"] == {"url": "https://h/b"}
    assert by_url["https://h/c"]["content_type"] == "text/html"
    assert by_url["https://h/c"]["response_status"] == 204
    # /a was first seen bare then enriched with the later content_type.
    assert by_url["https://h/a"]["content_type"] == "image/png"
    # sorted by url
    assert [r["url"] for r in out] == ["https://h/a", "https://h/b", "https://h/c"]
