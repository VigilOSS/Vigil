"""egress-check verb: robust verdict, advisory egress_decision, control safety."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "egress_check_ut",
        Path(__file__).resolve().parents[3] / "agent" / "scripts" / "assess" / "commands" / "egress_check.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENG_KEY = "eng"


def _cfg(tmp_path):
    return SimpleNamespace(base_url="http://x", engagement_key=ENG_KEY, engagement_dir=str(tmp_path))


def _wire(monkeypatch, mod, tmp_path, probe_lines: str):
    monkeypatch.setattr(mod, "load_config", lambda flag: _cfg(tmp_path))

    def fake_exec(cmd, **kwargs):
        # The probe script redirects to `> '<container path>'`; translate to host.
        script = cmd[2]
        target = script.rsplit("> ", 1)[1].strip().strip("'\"")
        host = target.replace(f"/engagements/{ENG_KEY}/", str(tmp_path) + "/")
        Path(host).parent.mkdir(parents=True, exist_ok=True)
        Path(host).write_text(probe_lines, encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(mod, "kali_exec", fake_exec)

    recorded = {}

    class _Client:
        def __init__(self, *a, **k): pass
        def record_decision(self, payload): recorded["decision"] = payload; return {"id": 1}
        def close(self): pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(mod, "AssessmentClient", _Client)
    return recorded


def _args(tmp_path, **over):
    base = dict(
        engagement_dir=str(tmp_path), cluster="dla", hosts="a.example.com,b.example.com",
        control=["example.com"], sample=10, block_threshold=80,
        emit_blocked_hosts=str(tmp_path / "blocked.txt"), no_record=False, stage_timeout=60,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_cluster_blackholed_records_decision(monkeypatch, tmp_path, capsys):
    mod = _load()
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"     # control: live
        "a.example.com 000 0.000000 \n"          # blackholed (no connect, no ip)
        "b.example.com 000 0.000000 \n"
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path))

    out = capsys.readouterr().out
    assert "verdict=cluster_blackholed" in out
    assert "egress_block_pct=100" in out
    assert recorded["decision"]["kind"] == "egress_decision"
    assert recorded["decision"]["payload"]["blocked_pct"] == 100
    assert sorted(recorded["decision"]["payload"]["blackholed_hosts"]) == ["a.example.com", "b.example.com"]
    assert (tmp_path / "blocked.txt").read_text().split() == ["a.example.com", "b.example.com"]


def test_control_failure_records_nothing(monkeypatch, tmp_path, capsys):
    mod = _load()
    probe = (
        "example.com 000 0.000000 \n"            # control DOWN → transient/global, not a cluster block
        "a.example.com 000 0.000000 \n"
        "b.example.com 000 0.000000 \n"
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path))
    assert "verdict=control_failure" in capsys.readouterr().out
    assert "decision" not in recorded


def test_reachable_with_000_proxy_artifact(monkeypatch, tmp_path, capsys):
    mod = _load()
    # http_code 000 but a remote_ip is present → TCP completed → live, NOT blackholed
    # (the §9 CONNECT-proxy-artifact lesson). So the cluster is reachable.
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"
        "a.example.com 000 0.000000 9.9.9.9\n"   # 000 + IP → live
        "b.example.com 403 0.030000 5.6.7.8\n"   # wall → live
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path))
    out = capsys.readouterr().out
    assert "verdict=reachable" in out
    assert "egress_block_pct=0" in out
    assert "decision" not in recorded


def test_garbled_sample_line_does_not_dilute_blocked_pct(monkeypatch, tmp_path, capsys):
    mod = _load()
    # 2 blackholed + 1 host with NO probe line. The unclassified host must be
    # excluded from the denominator, so the block is still detected (not masked).
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"   # control live
        "a.example.com 000 0.000000 \n"        # blackholed
        "b.example.com 000 0.000000 \n"        # blackholed
        # c.example.com produced no line (timeout writing) → unclassified
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path, hosts="a.example.com,b.example.com,c.example.com"))
    out = capsys.readouterr().out
    assert "egress_block_pct=100" in out          # 2/2 classified, not 2/3
    assert "verdict=cluster_blackholed" in out
    assert recorded["decision"]["payload"]["sampled"] == 3   # total sample still reported


def test_no_record_skips_decision_but_writes_blocked_file(monkeypatch, tmp_path):
    mod = _load()
    probe = "example.com 200 0.04 1.2.3.4\na.example.com 000 0.0 \nb.example.com 000 0.0 \n"
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path, no_record=True))
    assert "decision" not in recorded                          # --no-record honored
    assert (tmp_path / "blocked.txt").read_text().split() == ["a.example.com", "b.example.com"]
