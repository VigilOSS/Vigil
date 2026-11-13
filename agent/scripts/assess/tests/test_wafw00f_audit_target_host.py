"""A wafw00f run's command-run row names the hosts it measured.

A WAF measurement (``provenance.waf``) must cite a run whose structured target
names each measured host, so the audit row records the positional target, or
every host of an ``-i`` list read through the engagement mount — never a proxy.
"""
from __future__ import annotations

from pathlib import Path

from assess.lib.kali_audit import MAX_COMMAND_RUN_TARGET_HOST_LEN, _extract_target_host


def _list_file(engagement: Path, lines: list[str]) -> str:
    relative = "scans/live_hosts.txt"
    path = engagement / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"/engagements/{engagement.name}/{relative}"


def test_wafw00f_positional_target_names_its_host():
    assert _extract_target_host("wafw00f", ["wafw00f", "-a", "https://API.example.com/"]) == "api.example.com"


def test_wafw00f_proxy_is_not_the_target():
    cmd = ["wafw00f", "-p", "http://proxy.example:8080", "https://api.example.com"]
    assert _extract_target_host("wafw00f", cmd) == "api.example.com"
    assert _extract_target_host("wafw00f", ["wafw00f", "-p", "http://proxy.example:8080"]) == ""


def test_wafw00f_input_list_names_each_host(tmp_path):
    engagement = tmp_path / "acme-eng"
    engagement.mkdir()
    listed = _list_file(engagement, ["https://www.example.com/", "https://api.example.com", "https://www.example.com/x"])
    cmd = ["wafw00f", "-a", "-i", listed, "-o", "scans/waf.csv"]
    assert _extract_target_host("wafw00f", cmd, engagement_dir=engagement) == "api.example.com,www.example.com"


def test_wafw00f_input_list_that_does_not_fit_stays_empty(tmp_path):
    engagement = tmp_path / "acme-eng"
    engagement.mkdir()
    hosts = [f"https://h{index:03d}.example.com" for index in range(MAX_COMMAND_RUN_TARGET_HOST_LEN // 10)]
    listed = _list_file(engagement, hosts)
    assert _extract_target_host("wafw00f", ["wafw00f", "-i", listed], engagement_dir=engagement) == ""
