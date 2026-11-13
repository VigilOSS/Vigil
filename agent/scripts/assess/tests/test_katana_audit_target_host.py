"""A katana run's command-run row names its target host like httpx/nuclei/ffuf/sqlmap.

``-u <url>`` names one seed, so the row carries that host. ``-list <file>``
names its seeds in a file the wrapper wrote under the engagement mount; the
pre-exec row reads that file through the same ``/engagements/<key>/`` mapping
the wrapper used, so ``command-run list --target-host <seed host>`` finds the
crawl instead of an empty column:

* one distinct seed host -> that host, exactly what the exact-match filter wants;
* several -> the sorted distinct hosts joined by ``,`` (a hostname never holds a
  comma), bounded by the 512-character request field;
* a list that cannot be read beneath the engagement, or whose hosts do not fit,
  stays empty rather than naming some of its seeds as if they were all of them.
"""
from __future__ import annotations

from pathlib import Path

from assess.lib.kali_audit import (
    MAX_COMMAND_RUN_TARGET_HOST_LEN,
    _extract_target_host,
    _post_pre_exec_row,
)


def _seed_file(engagement: Path, lines: list[str]) -> str:
    """Write a seed list the way web-discovery does and return its container path."""
    relative = "scans/web-discovery/runs/r1/live_urls.txt"
    path = engagement / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"/engagements/{engagement.name}/{relative}"


def _engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "acme-eng"
    engagement.mkdir()
    return engagement


def test_katana_single_seed_names_its_host():
    cmd = ["katana", "-u", "https://Portal.Example.com:8443/login?next=/", "-jc", "-d", "5"]
    assert _extract_target_host("katana", cmd) == "portal.example.com"


def test_katana_list_with_one_distinct_host_names_that_host(tmp_path):
    engagement = _engagement(tmp_path)
    seeds = _seed_file(
        engagement,
        ["https://app.example.com/", "https://APP.example.com:8443/login", "http://app.example.com/a"],
    )
    cmd = ["katana", "-list", seeds, "-jc"]

    assert _extract_target_host("katana", cmd, engagement_dir=engagement) == "app.example.com"


def test_katana_list_with_several_hosts_names_each_seed_host(tmp_path):
    engagement = _engagement(tmp_path)
    seeds = _seed_file(
        engagement,
        ["https://b.example.com/", "https://a.example.com/x", "", "https://b.example.com/y"],
    )

    host = _extract_target_host("katana", ["katana", "-list", seeds], engagement_dir=engagement)

    assert host == "a.example.com,b.example.com"


def test_katana_list_resolves_an_engagement_relative_path(tmp_path):
    engagement = _engagement(tmp_path)
    _seed_file(engagement, ["https://app.example.com/"])
    cmd = ["katana", "-list", "scans/web-discovery/runs/r1/live_urls.txt"]

    assert _extract_target_host("katana", cmd, engagement_dir=engagement) == "app.example.com"


def test_katana_list_outside_the_engagement_or_unreadable_stays_empty(tmp_path):
    engagement = _engagement(tmp_path)
    other = tmp_path / "other-eng"
    other.mkdir()
    foreign = _seed_file(other, ["https://app.example.com/"])

    assert _extract_target_host("katana", ["katana", "-list", foreign], engagement_dir=engagement) == ""
    missing = f"/engagements/{engagement.name}/scans/none.txt"
    assert _extract_target_host("katana", ["katana", "-list", missing], engagement_dir=engagement) == ""
    escape = "../other-eng/scans/web-discovery/runs/r1/live_urls.txt"
    assert _extract_target_host("katana", ["katana", "-list", escape], engagement_dir=engagement) == ""
    # Without an engagement there is no mapping to read the list through.
    assert _extract_target_host("katana", ["katana", "-list", foreign]) == ""


def test_katana_list_whose_hosts_do_not_fit_stays_empty(tmp_path):
    engagement = _engagement(tmp_path)
    hosts = [f"https://host-{n:03d}.example.com/" for n in range(40)]
    seeds = _seed_file(engagement, hosts)

    host = _extract_target_host("katana", ["katana", "-list", seeds], engagement_dir=engagement)

    assert len(",".join(f"host-{n:03d}.example.com" for n in range(40))) > MAX_COMMAND_RUN_TARGET_HOST_LEN
    assert host == ""


def _pre_exec(cmd: list[str], engagement: Path) -> dict:
    posted: list[dict] = []

    class _Client:
        def post(self, endpoint, payload):
            posted.append(payload)
            return {"id": 1}

    _post_pre_exec_row(
        _Client(),
        cmd=cmd,
        technique="DISCOVERY",
        intent="crawl",
        probe_kind="fingerprint",
        phase="recon",
        destructive=False,
        agent_name="recon-specialist",
        engagement_dir=engagement,
        container_name="vigil",
        timeout=60,
        force=False,
        started_at_iso="2026-11-14T00:00:00Z",
        stdout_path="",
        stderr_path="",
        working_dir="",
        scope_version="",
        auth_context="anonymous",
        tool_name="katana",
        run_uuid="0" * 32,
    )
    return posted[0]


def test_katana_pre_exec_row_carries_the_target_host(tmp_path):
    payload = _pre_exec(["katana", "-u", "https://app.example.com/", "-jc", "-fs", "fqdn"], tmp_path)
    assert payload["target_host"] == "app.example.com"


def test_katana_list_pre_exec_row_carries_the_seed_hosts(tmp_path):
    engagement = _engagement(tmp_path)
    seeds = _seed_file(engagement, ["https://app.example.com/", "https://api.example.com/v1"])

    payload = _pre_exec(["katana", "-list", seeds, "-jc", "-jsonl"], engagement)

    assert payload["target_host"] == "api.example.com,app.example.com"
