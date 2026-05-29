"""CLI ingest-httpx: parse httpx -json, classify, upsert host-liveness rows."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_ingest_httpx():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "ingest_httpx_under_test",
        Path(__file__).resolve().parents[3] / "agent" / "scripts" / "assess" / "commands" / "ingest_httpx.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HTTPX_LINES = [
    json.dumps({"input": "https://a.example.com", "url": "https://a.example.com",
                "scheme": "https", "status_code": 200, "host": "1.2.3.4",
                "title": "Home", "webserver": "nginx", "failed": False,
                "timestamp": "2999-01-01T00:00:00Z", "tech": ["nginx", "php"]}),
    # 403 wall — still a reachable origin (TCP/HTTP answered), not dead.
    json.dumps({"input": "b.example.com:8443", "scheme": "https", "status_code": 403,
                "host": "5.6.7.8", "failed": False, "timestamp": "2999-01-01T00:00:00Z"}),
    # connect failure, no IP → blackholed.
    json.dumps({"input": "c.example.com", "failed": True, "timestamp": "2999-01-01T00:00:00Z"}),
    "{ not valid json",          # malformed → skipped
    "",                            # blank → skipped
    "# a comment",                # comment → skipped
]


def _run(monkeypatch, tmp_path):
    module = _load_ingest_httpx()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)
        ),
    )
    captured = {}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def post(self, endpoint, payload):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"upserted": len(payload.get("rows", []))}

        def close(self):
            pass

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    results = tmp_path / "live.jsonl"
    results.write_text("\n".join(_HTTPX_LINES) + "\n", encoding="utf-8")
    module.run(SimpleNamespace(
        engagement_dir=str(tmp_path), results_file=str(results),
        source="httpx", run_id=None, run_uuid="",
    ))
    return captured


def test_ingest_httpx_classifies_and_normalizes(monkeypatch, tmp_path):
    captured = _run(monkeypatch, tmp_path)
    assert captured["endpoint"] == "host-liveness"
    rows = {r["host"]: r for r in captured["payload"]["rows"]}

    # Malformed/blank/comment lines skipped → exactly 3 real records. The CLI
    # strips scheme+path but leaves the port; the backend is the single host
    # normalization authority (port-strip is covered in test_host_liveness_api).
    assert set(rows) == {"a.example.com", "b.example.com:8443", "c.example.com"}
    # 200 → live, with IP + tech captured.
    assert rows["a.example.com"]["reachability_class"] == "live"
    assert rows["a.example.com"]["host_ip"] == "1.2.3.4"
    assert "nginx" in rows["a.example.com"]["tech"]
    # 403 wall → still live (TCP/HTTP answered), not dead.
    assert rows["b.example.com:8443"]["reachability_class"] == "live"
    # failed, no IP → blackholed.
    assert rows["c.example.com"]["reachability_class"] == "blackholed"


def test_ingest_httpx_missing_file_exits(monkeypatch, tmp_path):
    module = _load_ingest_httpx()
    monkeypatch.setattr(
        module, "load_config",
        lambda flag: SimpleNamespace(base_url="http://x", engagement_key="eng", engagement_dir=str(tmp_path)),
    )
    with pytest.raises(SystemExit):
        module.run(SimpleNamespace(
            engagement_dir=str(tmp_path), results_file=str(tmp_path / "nope.jsonl"),
            source="httpx", run_id=None, run_uuid="",
        ))
