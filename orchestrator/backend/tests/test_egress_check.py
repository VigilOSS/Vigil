"""egress-check verb: robust verdict, advisory egress_decision, control safety."""
from __future__ import annotations

import base64
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


def _captured_probe_line(
    host: str,
    code: int,
    time_connect: float,
    remote_ip: str,
    *,
    headers: str = "",
    body: str = "",
) -> str:
    encoded_headers = base64.b64encode(headers.encode()).decode() or "-"
    encoded_body = base64.b64encode(body.encode()).decode() or "-"
    return (
        f"{host} {code:03d} {time_connect:.6f} {remote_ip or '-'} "
        f"{encoded_headers} {encoded_body}\n"
    )


def _cfg(tmp_path):
    return SimpleNamespace(base_url="http://x", engagement_key=ENG_KEY, engagement_dir=str(tmp_path))


def _wire(monkeypatch, mod, tmp_path, probe_lines: str, artifact_response=None):
    monkeypatch.setattr(mod, "load_config", lambda flag: _cfg(tmp_path))
    recorded = {}

    def fake_exec(cmd, **kwargs):
        recorded["exec_kwargs"] = kwargs
        # The probe script redirects to `> '<container path>'`; translate to host.
        script = cmd[2]
        target = script.rsplit("> ", 1)[1].strip().strip("'\"")
        host = target.replace(f"/engagements/{ENG_KEY}/", str(tmp_path) + "/")
        Path(host).parent.mkdir(parents=True, exist_ok=True)
        Path(host).write_text(probe_lines, encoding="utf-8")
        return SimpleNamespace(return_code=0, run_id=37)

    monkeypatch.setattr(mod, "kali_exec", fake_exec)

    class _Client:
        def __init__(self, *a, **k): pass
        def post(self, endpoint, payload):
            assert endpoint == "artifacts"
            recorded["artifact"] = payload
            return artifact_response or {
                "id": 91,
                "relative_path": "scans/egress-check/probe.txt",
            }
        def record_decision(self, payload):
            recorded["decision"] = payload
            return {"id": 1}
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
    assert recorded["decision"]["payload"]["subtype"] == "connectivity_check"
    assert recorded["decision"]["payload"]["blocked_pct"] == 100
    assert sorted(recorded["decision"]["payload"]["blackholed_hosts"]) == ["a.example.com", "b.example.com"]
    assert recorded["decision"]["payload"]["artifact_ref"] == "scans/egress-check/probe.txt"
    assert recorded["decision"]["payload"]["provenance"]["command_run_id"] == 37
    assert recorded["artifact"] == {
        "path": "scans/egress-check/probe.txt",
        "kind": "egress-connectivity-observation",
        "media_type": "text/plain",
        "producer_command_run_id": 37,
    }
    assert (tmp_path / "blocked.txt").read_text().split() == ["a.example.com", "b.example.com"]
    assert "destinations" not in recorded["exec_kwargs"]


def test_control_failure_records_inconclusive_observation(monkeypatch, tmp_path, capsys):
    mod = _load()
    probe = (
        "example.com 000 0.000000 \n"            # control DOWN → transient/global, not a cluster block
        "a.example.com 000 0.000000 \n"
        "b.example.com 000 0.000000 \n"
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path))
    captured = capsys.readouterr()
    assert "verdict=control_failure" in captured.out
    assert "inconclusive" in captured.err
    assert "likely a transient/global egress issue" not in captured.err
    payload = recorded["decision"]["payload"]
    assert payload["verdict"] == "control_failure"
    assert payload["subtype"] == "connectivity_check"
    assert payload["conclusion"] == "inconclusive"
    assert payload["reason"] == "controls_not_live"
    assert payload["control_observations"] == {"example.com": "blackholed"}
    assert payload["artifact_ref"] == "scans/egress-check/probe.txt"
    assert payload["provenance"]["artifact_id"] == 91


def test_unclassified_sample_records_inconclusive_observation(monkeypatch, tmp_path, capsys):
    mod = _load()
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"
        "a.example.com 200 0.030000 5.6.7.8\n"
        # b.example.com produced no parseable observation.
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)

    mod.run(_args(tmp_path))

    captured = capsys.readouterr()
    assert "verdict=inconclusive" in captured.out
    assert "1 of 2 sampled host(s) had no classified observation" in captured.err
    payload = recorded["decision"]["payload"]
    assert payload["verdict"] == "inconclusive"
    assert payload["reason"] == "unclassified_samples"
    assert payload["classified"] == 1
    assert payload["sampled"] == 2
    assert payload["sample_observations"] == {
        "a.example.com": "live",
        "b.example.com": "unobserved",
    }


def test_sparse_blackhole_output_cannot_establish_a_cluster_verdict(
    monkeypatch, tmp_path, capsys
):
    mod = _load()
    hosts = ",".join(f"host-{index}.example.com" for index in range(10))
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"
        "host-0.example.com 000 0.000000 \n"
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)

    mod.run(_args(tmp_path, hosts=hosts))

    captured = capsys.readouterr()
    assert "verdict=inconclusive" in captured.out
    assert "egress_block_pct=10" in captured.out
    payload = recorded["decision"]["payload"]
    assert payload["reason"] == "unclassified_samples"
    assert payload["blocked_pct"] == 10
    assert payload["classified"] == 1
    assert payload["sampled"] == 10
    assert not (tmp_path / "blocked.txt").exists()


def test_artifact_write_response_must_identify_registered_probe(monkeypatch, tmp_path):
    mod = _load()
    probe = (
        "example.com 000 0.000000 \n"
        "a.example.com 000 0.000000 \n"
        "b.example.com 000 0.000000 \n"
    )
    recorded = _wire(
        monkeypatch,
        mod,
        tmp_path,
        probe,
        artifact_response={"relative_path": "scans/egress-check/probe.txt"},
    )

    with pytest.raises(Exception, match="canonical artifact") as exc_info:
        mod.run(_args(tmp_path))

    # The response named our canonical path and then failed to name a row, so the
    # write is KNOWN to have landed — reporting only "may have committed" is what
    # makes a duplicate retry look reasonable. Either way it stays non-retryable.
    assert "committed but response invalid" in str(exc_info.value)
    assert "do not retry automatically" in str(exc_info.value)
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
    assert recorded["decision"]["payload"]["verdict"] == "reachable"
    assert recorded["decision"]["payload"]["artifact_ref"] == (
        "scans/egress-check/probe.txt"
    )


def test_edge_block_response_is_inconclusive_not_reachable(
    monkeypatch, tmp_path, capsys
):
    mod = _load()
    probe = "".join(
        [
            _captured_probe_line(
                "example.com",
                200,
                0.04,
                "1.2.3.4",
                headers="HTTP/2 200\r\nserver: envoy\r\nx-request-id: ctrl\r\n",
                body="ok",
            ),
            _captured_probe_line(
                "a.example.com",
                403,
                0.03,
                "5.6.7.8",
                headers=(
                    "HTTP/2 403\r\nserver: AmazonS3\r\n"
                    "x-cache: Error from cloudfront\r\n"
                    "x-amz-cf-id: edge-request\r\n"
                ),
                body=(
                    "<Error><Code>AccessDenied</Code>"
                    "<Message>Request blocked.</Message></Error>"
                ),
            ),
            _captured_probe_line(
                "b.example.com",
                200,
                0.03,
                "5.6.7.9",
                headers="HTTP/2 200\r\nserver: nginx\r\nx-request-id: app\r\n",
                body="application response",
            ),
        ]
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)

    mod.run(_args(tmp_path))

    captured = capsys.readouterr()
    assert "verdict=inconclusive" in captured.out
    assert "WAF/edge-block response" in captured.err
    assert "0 of 2 sampled host(s) had no classified observation" not in captured.err
    payload = recorded["decision"]["payload"]
    assert payload["conclusion"] == "inconclusive"
    assert payload["reason"] == "waf_or_edge_block_samples"
    assert payload["sample_observations"]["a.example.com"] == "waf_challenge"
    assert "CloudFront/S3 edge-block envelope" in payload[
        "waf_or_edge_observations"
    ]["a.example.com"]


def test_garbled_sample_line_does_not_inflate_blocked_pct(monkeypatch, tmp_path, capsys):
    mod = _load()
    # 2 blackholed + 1 host with NO probe line is only 67% of the requested
    # sample, so it cannot satisfy the 80% cluster threshold.
    probe = (
        "example.com 200 0.040000 1.2.3.4\n"   # control live
        "a.example.com 000 0.000000 \n"        # blackholed
        "b.example.com 000 0.000000 \n"        # blackholed
        # c.example.com produced no line (timeout writing) → unclassified
    )
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path, hosts="a.example.com,b.example.com,c.example.com"))
    out = capsys.readouterr().out
    assert "egress_block_pct=67" in out
    assert "verdict=inconclusive" in out
    assert recorded["decision"]["payload"]["reason"] == "unclassified_samples"
    assert recorded["decision"]["payload"]["sampled"] == 3   # total sample still reported
    assert not (tmp_path / "blocked.txt").exists()


def test_no_record_skips_decision_but_writes_blocked_file(monkeypatch, tmp_path):
    mod = _load()
    probe = "example.com 200 0.04 1.2.3.4\na.example.com 000 0.0 \nb.example.com 000 0.0 \n"
    recorded = _wire(monkeypatch, mod, tmp_path, probe)
    mod.run(_args(tmp_path, no_record=True))
    assert "decision" not in recorded                          # --no-record honored
    assert (tmp_path / "blocked.txt").read_text().split() == ["a.example.com", "b.example.com"]
