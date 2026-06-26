"""Host-routed attribution-header injection coverage.

The host path (`_host_dispatch` in web-discovery / dns-discovery, which runs an
audited tool on the host via ``host-exec``) historically applied NO required
headers, so a host-routed httpx liveness pass sent no program attribution
header. These tests pin the gap fix: the host path now shares kali_exec's
injectable/skip classifier (``_apply_required_headers``), so an injectable tool
(httpx) carries the engagement's ``required_headers`` while a skip-set tool
(gau) does NOT — the handle must never leak to an archive/DNS endpoint.

They also pin the shared-source guarantee: the container path (kali.kali_exec)
and the host path import the SAME classifier object from kali_output.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assess.commands import dns_discovery, web_discovery
from assess.lib import kali, kali_output


def _scope(eng_dir: Path, **fields) -> None:
    eng_dir.mkdir(parents=True, exist_ok=True)
    payload = {"engagement_type": "web", "hosts": ["example.com"]}
    payload.update(fields)
    (eng_dir / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def _capture_host_exec(monkeypatch, module) -> list[list[str]]:
    """Replace ``module.host_exec.run`` with a capturing stub that records the
    argv the host path built and exits 0 like the real runner."""
    captured: list[list[str]] = []

    def _fake_run(ns):
        captured.append(list(ns.command))
        raise SystemExit(0)

    monkeypatch.setattr(module.host_exec, "run", _fake_run)
    return captured


def test_container_and_host_paths_share_one_classifier() -> None:
    # The factoring guarantee: kali_exec's classifier IS the kali_output one the
    # host path imports, so a future edit can never diverge the two surfaces.
    assert kali._apply_required_headers is kali_output._apply_required_headers
    assert web_discovery._apply_required_headers is kali_output._apply_required_headers
    assert dns_discovery._apply_required_headers is kali_output._apply_required_headers


def test_host_routed_httpx_carries_required_header(tmp_path, monkeypatch) -> None:
    eng_dir = tmp_path / "eng"
    _scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    captured = _capture_host_exec(monkeypatch, web_discovery)

    res = web_discovery._host_dispatch(
        ["httpx", "-l", "in.txt", "-p", "80,443"],
        intent="web-discovery: httpx liveness",
        tool_name="httpx",
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    assert res.return_code == 0
    assert len(captured) == 1
    argv = captured[0]
    # The header rides as a -H pair appended to the host-routed argv.
    assert "-H" in argv
    h_idx = argv.index("-H")
    assert argv[h_idx + 1] == "X-Bug-Bounty: vigiloss"


def test_host_routed_skip_set_tool_gets_no_header(tmp_path, monkeypatch) -> None:
    # gau is in the skip-set: injecting the handle would leak it to the public
    # archive (web.archive.org / CommonCrawl), so the host path must NOT add -H.
    eng_dir = tmp_path / "eng"
    _scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    captured = _capture_host_exec(monkeypatch, web_discovery)

    web_discovery._host_dispatch(
        ["gau", "example.com"],
        intent="web-discovery: passive url harvest",
        tool_name="gau",
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    assert captured == [["gau", "example.com"]]
    assert "-H" not in captured[0]


def test_host_routed_httpx_no_header_when_scope_has_none(tmp_path, monkeypatch) -> None:
    # No required_headers configured → argv unchanged (today's default behavior).
    eng_dir = tmp_path / "eng"
    _scope(eng_dir)
    captured = _capture_host_exec(monkeypatch, web_discovery)

    web_discovery._host_dispatch(
        ["httpx", "-l", "in.txt"],
        intent="web-discovery: httpx liveness",
        tool_name="httpx",
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    assert captured == [["httpx", "-l", "in.txt"]]


def test_host_routed_httpx_does_not_duplicate_existing_header(tmp_path, monkeypatch) -> None:
    # Idempotency: an already-present -H for the same name is not re-added.
    eng_dir = tmp_path / "eng"
    _scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    captured = _capture_host_exec(monkeypatch, web_discovery)

    web_discovery._host_dispatch(
        ["httpx", "-l", "in.txt", "-H", "X-Bug-Bounty: already"],
        intent="web-discovery: httpx liveness",
        tool_name="httpx",
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    argv = captured[0]
    assert argv.count("-H") == 1
    assert "X-Bug-Bounty: already" in argv


def test_dns_host_dispatch_skips_dnsx_header(tmp_path, monkeypatch) -> None:
    # The dns-discovery host path shares the same classifier; dnsx is skip-set,
    # so the attribution header is correctly never applied to a DNS probe.
    eng_dir = tmp_path / "eng"
    _scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    captured = _capture_host_exec(monkeypatch, dns_discovery)

    dns_discovery._host_dispatch(
        ["dnsx", "-l", "hosts.txt"],
        intent="dns-discovery: resolve",
        tool_name="dnsx",
        technique="DISCOVERY",
        phase="recon",
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    assert captured == [["dnsx", "-l", "hosts.txt"]]
    assert "-H" not in captured[0]


@pytest.mark.parametrize("warn_tool", ["whatweb"])
def test_host_routed_non_injectable_http_tool_warns(tmp_path, monkeypatch, capsys, warn_tool) -> None:
    # An HTTP-capable but non-injectable tool (no -H) WARNs (never blocks) and
    # leaves argv untouched — same contract as the container path.
    eng_dir = tmp_path / "eng"
    _scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    captured = _capture_host_exec(monkeypatch, web_discovery)

    web_discovery._host_dispatch(
        [warn_tool, "https://example.com"],
        intent="web-discovery: fingerprint",
        tool_name=warn_tool,
        timeout=60,
        engagement_dir=str(eng_dir),
    )

    assert captured == [[warn_tool, "https://example.com"]]
    assert "no known -H injection" in capsys.readouterr().err
