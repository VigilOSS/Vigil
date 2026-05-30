"""dns-discovery + web-discovery pipeline verbs: stage argv, de-noise, flow."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load(name: str, rel: str):
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    module_path = Path(__file__).resolve().parents[3] / rel
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENG_KEY = "eng"


def _cfg(tmp_path):
    return SimpleNamespace(base_url="http://example.test", engagement_key=ENG_KEY, engagement_dir=str(tmp_path))


def _container_to_host(path: str, tmp_path) -> str:
    return path.replace(f"/engagements/{ENG_KEY}/", str(tmp_path) + "/")


def _make_fake_exec(tmp_path, canned: dict):
    """Fake kali_exec: writes canned[tool_name] to the stage's output path
    (the -o arg, or the `> 'path'` redirect target of an sh -c script)."""
    calls: list[dict] = []

    def fake(cmd, **kwargs):
        tool = kwargs.get("tool_name", "")
        calls.append({"cmd": list(cmd), "kwargs": kwargs, "tool": tool})
        out_container = None
        if "-o" in cmd:
            out_container = cmd[cmd.index("-o") + 1]
        elif cmd[:2] == ["sh", "-c"]:
            script = cmd[2]
            if "> " in script:
                out_container = script.rsplit("> ", 1)[1].strip().strip("'\"")
        if out_container and tool in canned:
            host = Path(_container_to_host(out_container, tmp_path))
            host.parent.mkdir(parents=True, exist_ok=True)
            host.write_text(canned[tool], encoding="utf-8")
        return SimpleNamespace(return_code=0)

    return fake, calls


# --------------------------------------------------------------------------- web

def test_web_discovery_pipeline(monkeypatch, tmp_path):
    web = _load("web_discovery_ut", "agent/scripts/assess/commands/web_discovery.py")
    monkeypatch.setattr(web, "load_config", lambda flag: _cfg(tmp_path))

    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.example.com\n_dmarc.example.com\nb.example.com\n", encoding="utf-8")  # one noise line

    httpx_jsonl = "\n".join([
        json.dumps({"input": "https://a.example.com", "url": "https://a.example.com",
                    "scheme": "https", "status_code": 200, "host": "1.2.3.4", "failed": False,
                    "timestamp": "2999-01-01T00:00:00Z"}),
    ])
    katana_jsonl = json.dumps({"request": {"endpoint": "https://a.example.com/login"}})
    fake_exec, calls = _make_fake_exec(tmp_path, {"httpx": httpx_jsonl, "katana": katana_jsonl})
    monkeypatch.setattr(web, "kali_exec", fake_exec)

    ingest_calls = {}

    def _fake_ingest(path, **kw):
        ingest_calls["path"] = str(path)
        return {"upserted": 1, "rows": 1, "by_class": {"live": 1}, "parse_errors": 0}

    monkeypatch.setattr(web, "ingest_httpx_results", _fake_ingest)

    class _Client:
        def __init__(self, *a, **k): pass
        def close(self): pass
    monkeypatch.setattr(web, "AssessmentClient", _Client)

    endpoints_called = {}
    monkeypatch.setattr(web.ingest_endpoints, "run", lambda a: endpoints_called.setdefault("ran", True))

    web.run(SimpleNamespace(
        engagement_dir=str(tmp_path), hosts_file=str(hosts), ports="80,443",
        httpx_threads="50", httpx_rate_limit="150", tech_detect=False,
        no_crawl=False, katana_depth="2", katana_extra_args="-kf all", db_path="", stage_timeout=600,
    ))

    # De-noise dropped the _dmarc line.
    denoised = (tmp_path / "scans" / "web-discovery" / "denoised_hosts.txt").read_text()
    assert "a.example.com" in denoised and "b.example.com" in denoised
    assert "_dmarc" not in denoised

    httpx_call = next(c for c in calls if c["tool"] == "httpx")
    assert "-json" in httpx_call["cmd"] and "-p" in httpx_call["cmd"]
    assert "-tech-detect" not in httpx_call["cmd"]      # default: lean bulk pass
    assert "ingest_httpx" not in str(httpx_call)        # sanity
    assert ingest_calls.get("path", "").endswith("httpx_live.jsonl")

    katana_call = next(c for c in calls if c["tool"] == "katana")
    assert "-d" in katana_call["cmd"] and "2" in katana_call["cmd"]
    assert "-kf" in katana_call["cmd"] and "all" in katana_call["cmd"]   # extra-args knob threaded
    assert endpoints_called == {}                       # no --db → no work-buffer ingest


def test_web_discovery_no_crawl_and_db_ingest(monkeypatch, tmp_path):
    web = _load("web_discovery_ut2", "agent/scripts/assess/commands/web_discovery.py")
    monkeypatch.setattr(web, "load_config", lambda flag: _cfg(tmp_path))
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.example.com\n", encoding="utf-8")
    httpx_jsonl = json.dumps({"input": "https://a.example.com", "url": "https://a.example.com",
                              "status_code": 200, "host": "1.2.3.4", "failed": False,
                              "timestamp": "2999-01-01T00:00:00Z"})
    fake_exec, calls = _make_fake_exec(tmp_path, {"httpx": httpx_jsonl})
    monkeypatch.setattr(web, "kali_exec", fake_exec)
    monkeypatch.setattr(web, "ingest_httpx_results", lambda path, **kw: {"upserted": 1, "rows": 1, "by_class": {}, "parse_errors": 0})

    class _Client:
        def __init__(self, *a, **k): pass
        def close(self): pass
    monkeypatch.setattr(web, "AssessmentClient", _Client)

    web.run(SimpleNamespace(
        engagement_dir=str(tmp_path), hosts_file=str(hosts), ports="443",
        httpx_threads="50", httpx_rate_limit="150", tech_detect=False,
        no_crawl=True, katana_depth="2", katana_extra_args="", db_path="", stage_timeout=600,
    ))
    assert not any(c["tool"] == "katana" for c in calls)   # --no-crawl honored


# --------------------------------------------------------------------------- dns

def test_dns_discovery_pipeline_real_dnsx_flags(monkeypatch, tmp_path):
    dns = _load("dns_discovery_ut", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))

    canned = {
        "subfinder": "api.example.com\n_dmarc.example.com\n",   # includes noise
        "crt.sh": "portal.example.com\n",
        "dnsx": "api.example.com\nportal.example.com\n",
    }
    fake_exec, calls = _make_fake_exec(tmp_path, canned)
    monkeypatch.setattr(dns, "kali_exec", fake_exec)

    dns.run(SimpleNamespace(
        engagement_dir=str(tmp_path), apexes=["example.com"], no_passive=False, no_ct=False,
        recursive=False, subfinder_threads="20", brute=False, wordlist="/wl.txt",
        dns_rate="1500", dnsx_profile="polite-cdn", resolver_profile="public-tcp",
        dnsx_extra_args="", stage_timeout=600,
    ))

    tools = [c["tool"] for c in calls]
    assert "subfinder" in tools and "crt.sh" in tools and "dnsx" in tools
    assert not any(t == "puredns" for t in calls if isinstance(t, str))  # brute off

    # Merge+de-noise dropped the _dmarc noise.
    merged = (tmp_path / "scans" / "dns-discovery" / "subs_merged.txt").read_text()
    assert "api.example.com" in merged and "portal.example.com" in merged
    assert "_dmarc" not in merged

    # dnsx stage uses REAL dnsx flags from the polite-cdn profile, not --dnsx-profile.
    dnsx_call = next(c for c in calls if c["tool"] == "dnsx")
    assert "--dnsx-profile" not in dnsx_call["cmd"]
    assert "-rl" in dnsx_call["cmd"] and "100" in dnsx_call["cmd"]   # polite-cdn rate_limit
    assert "-r" in dnsx_call["cmd"]                                   # public-tcp resolvers


def test_dns_discovery_brute_opt_in(monkeypatch, tmp_path):
    dns = _load("dns_discovery_ut2", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    fake_exec, calls = _make_fake_exec(tmp_path, {"subfinder": "a.example.com\n", "dnsx": "a.example.com\n"})
    monkeypatch.setattr(dns, "kali_exec", fake_exec)
    dns.run(SimpleNamespace(
        engagement_dir=str(tmp_path), apexes=["example.com"], no_passive=False, no_ct=True,
        recursive=False, subfinder_threads="20", brute=True, wordlist="/wl.txt",
        dns_rate="1500", dnsx_profile="polite-cdn", resolver_profile="public-tcp",
        dnsx_extra_args="", stage_timeout=600,
    ))
    puredns = [c for c in calls if c["tool"] == "puredns"]
    assert len(puredns) == 1
    assert "bruteforce" in puredns[0]["cmd"] and "/wl.txt" in puredns[0]["cmd"]


def test_web_discovery_zero_live_hosts_does_not_crash(monkeypatch, tmp_path):
    web = _load("web_discovery_ut3", "agent/scripts/assess/commands/web_discovery.py")
    monkeypatch.setattr(web, "load_config", lambda flag: _cfg(tmp_path))
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.example.com\n", encoding="utf-8")
    # canned has NO 'httpx' entry → fake_exec writes no httpx_live.jsonl (httpx found nothing).
    fake_exec, calls = _make_fake_exec(tmp_path, {})
    monkeypatch.setattr(web, "kali_exec", fake_exec)
    monkeypatch.setattr(web, "ingest_httpx_results",
                        lambda path, **kw: {"upserted": 0, "rows": 0, "by_class": {}, "parse_errors": 0})

    class _Client:
        def __init__(self, *a, **k): pass
        def close(self): pass
    monkeypatch.setattr(web, "AssessmentClient", _Client)

    # Must complete cleanly (no FileNotFoundError); no katana since no live URLs.
    web.run(SimpleNamespace(
        engagement_dir=str(tmp_path), hosts_file=str(hosts), ports="443",
        httpx_threads="50", httpx_rate_limit="150", tech_detect=False,
        no_crawl=False, katana_depth="2", katana_extra_args="", db_path="", stage_timeout=600,
    ))
    assert not any(c["tool"] == "katana" for c in calls)
