"""W6 — kali_resolve correctness (I-11 IPv4-before-IPv6, curl-only ``--resolve``).

I-11: ``resolve_host_ips`` must return IPv4 (A) addresses BEFORE IPv6 (AAAA),
regardless of the order ``socket.getaddrinfo`` happens to return them in. The
``--resolve`` pin uses ``ips[0]``; pinning an AAAA on an IPv4-only container
runtime makes the in-container HTTP request fail with http=000, which the
false-negative guard would surface as a (suppressed) real surface. Keeping the
first pinned address an IPv4 keeps the common case probe-able.

curl-only ``--resolve`` (I-10 generalized): ``--resolve host:port:ip`` is a
curl-specific feature. ffuf, httpx, nuclei, and katana all reject it ("flag
provided but not defined: -resolve", exit 2 — the probe never fires), verified
empirically against the shipped image (katana v1.5.0 / httpx v1.9.0 / nuclei
v3.7.1). So ``RESOLVE_PIN_TOOLS`` is ``{"curl"}``; injecting the pin into any of
the others turns a recoverable Docker-Desktop resolver flap into a hard, silent
total failure of every pinned run (the reported katana ``-u`` breakage). They
STAY http-probers so the post-run http=000 false-negative guard still arms and
records a transport error.
"""
from __future__ import annotations

import socket

import pytest

from assess.lib import kali_resolve, runtime_route
from assess.lib.kali_output import is_http_prober


def _docker_desktop() -> runtime_route.RuntimeInfo:
    return runtime_route.RuntimeInfo(
        platform="darwin", is_docker_desktop=True, recommended="host"
    )


# --------------------------------------------------------------------------- #
# I-11 — IPv4 (A) before IPv6 (AAAA) in resolve_host_ips.
# --------------------------------------------------------------------------- #


def _gai(*entries):
    """Build a fake getaddrinfo return list from (family, ip) pairs."""
    out = []
    for family, ip in entries:
        sockaddr = (ip, 0) if family == socket.AF_INET else (ip, 0, 0, 0)
        out.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return out


def test_resolve_host_ips_returns_ipv4_before_ipv6_even_when_aaaa_first(monkeypatch):
    # getaddrinfo hands us AAAA first (a common ordering under RFC 6724 / a v6
    # preferring resolver), then A.
    fake = _gai(
        (socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"),
        (socket.AF_INET, "93.184.216.34"),
    )
    monkeypatch.setattr(kali_resolve.socket, "getaddrinfo", lambda *a, **k: fake)

    ips = kali_resolve.resolve_host_ips("example.com")

    assert ips[0] == "93.184.216.34", "the first (pinned) address must be IPv4"
    assert ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]


def test_resolve_host_ips_orders_all_v4_before_all_v6_preserving_intra_order(monkeypatch):
    fake = _gai(
        (socket.AF_INET6, "2001:db8::2"),
        (socket.AF_INET, "203.0.113.10"),
        (socket.AF_INET6, "2001:db8::1"),
        (socket.AF_INET, "203.0.113.11"),
    )
    monkeypatch.setattr(kali_resolve.socket, "getaddrinfo", lambda *a, **k: fake)

    ips = kali_resolve.resolve_host_ips("multi.example.com")

    # All IPv4 first (in their original relative order), then all IPv6.
    assert ips == ["203.0.113.10", "203.0.113.11", "2001:db8::2", "2001:db8::1"]


def test_resolve_host_ips_dedups_repeated_addresses(monkeypatch):
    fake = _gai(
        (socket.AF_INET, "198.51.100.7"),
        (socket.AF_INET, "198.51.100.7"),  # dup (different socktype rows)
        (socket.AF_INET6, "2001:db8::9"),
    )
    monkeypatch.setattr(kali_resolve.socket, "getaddrinfo", lambda *a, **k: fake)

    assert kali_resolve.resolve_host_ips("dup.example.com") == [
        "198.51.100.7",
        "2001:db8::9",
    ]


def test_resolve_host_ips_returns_empty_on_resolution_failure(monkeypatch):
    def boom(*_a, **_k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(kali_resolve.socket, "getaddrinfo", boom)
    assert kali_resolve.resolve_host_ips("nope.invalid") == []


def test_apply_resolve_pin_pins_the_ipv4_address(monkeypatch):
    """End-to-end: a curl probe on Docker Desktop pins the IPv4 (ips[0]),
    never the AAAA, so the in-container request stays probe-able."""
    fake = _gai(
        (socket.AF_INET6, "2606:2800:220:1::1"),
        (socket.AF_INET, "93.184.216.34"),
    )
    monkeypatch.setattr(kali_resolve.socket, "getaddrinfo", lambda *a, **k: fake)
    cmd = ["curl", "-sS", "https://example.com/"]

    pinned = kali_resolve.apply_resolve_pin(cmd, "curl", runtime=_docker_desktop())

    assert pinned == "93.184.216.34"
    assert "--resolve" in cmd
    assert cmd[cmd.index("--resolve") + 1] == "example.com:443:93.184.216.34"


def test_apply_resolve_pin_distributes_multi_address_hosts(monkeypatch):
    """A multi-A target must not always concentrate traffic on address zero."""
    addresses = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    monkeypatch.setattr(kali_resolve.secrets, "choice", lambda values: values[-1])
    cmd = ["curl", "-sS", "https://example.com/"]

    pinned = kali_resolve.apply_resolve_pin(
        cmd,
        "curl",
        runtime=_docker_desktop(),
        ips=addresses,
    )

    assert pinned == "203.0.113.12"
    assert cmd[cmd.index("--resolve") + 1] == "example.com:443:203.0.113.12"


# --------------------------------------------------------------------------- #
# I-10 — ffuf takes no --resolve pin: must be OUT of RESOLVE_PIN_TOOLS.
# --------------------------------------------------------------------------- #


def test_ffuf_is_not_in_resolve_pin_tools():
    assert "ffuf" not in kali_resolve.RESOLVE_PIN_TOOLS


def test_apply_resolve_pin_is_noop_for_ffuf(monkeypatch):
    """ffuf has no --resolve flag (it aborts with exit 2). The pin must NOT be
    injected — leaving the run for the http=000 retry guard to flag instead."""
    # Resolution would succeed; the no-op must come from the tool-set gate, not
    # a resolution miss.
    monkeypatch.setattr(kali_resolve, "resolve_host_ips", lambda _h: ["93.184.216.34"])
    cmd = ["ffuf", "-u", "http://example.com/FUZZ", "-w", "/tmp/w.txt"]

    pinned = kali_resolve.apply_resolve_pin(
        cmd, "ffuf", runtime=_docker_desktop(), ips=["93.184.216.34"]
    )

    assert pinned is None
    assert "--resolve" not in cmd


def test_only_curl_pins(monkeypatch):
    """curl is the ONLY tool that accepts curl-style ``--resolve host:port:ip``."""
    monkeypatch.setattr(kali_resolve, "resolve_host_ips", lambda _h: ["93.184.216.34"])
    cmd = ["curl", "-sS", "https://example.com/"]

    pinned = kali_resolve.apply_resolve_pin(
        cmd, "curl", runtime=_docker_desktop(), ips=["93.184.216.34"]
    )

    assert pinned == "93.184.216.34"
    assert "--resolve" in cmd


@pytest.mark.parametrize("tool", ["httpx", "nuclei", "katana", "ffuf", "sqlmap"])
def test_go_tools_are_not_pinned(tool, monkeypatch):
    """httpx/nuclei/katana (and ffuf/sqlmap) reject curl-style ``--resolve``
    ("flag provided but not defined: -resolve", exit 2) — verified empirically
    against the shipped image (katana v1.5.0 / httpx v1.9.0 / nuclei v3.7.1). They
    MUST be out of RESOLVE_PIN_TOOLS so the pin is never injected; otherwise the
    CR-36 host-pin turns a recoverable Docker-Desktop resolver flap into a hard,
    silent total failure of every single-target run (the katana ``-u`` failure an
    operator reported). The no-op must come from the tool-set gate, not a
    resolution miss, so resolution is stubbed to succeed."""
    assert tool not in kali_resolve.RESOLVE_PIN_TOOLS
    monkeypatch.setattr(kali_resolve, "resolve_host_ips", lambda _h: ["93.184.216.34"])
    cmd = [tool, "-u", "https://example.com/"]

    pinned = kali_resolve.apply_resolve_pin(
        cmd, tool, runtime=_docker_desktop(), ips=["93.184.216.34"]
    )

    assert pinned is None
    assert "--resolve" not in cmd


@pytest.mark.parametrize("tool", ["ffuf", "httpx", "nuclei", "katana"])
def test_unpinned_probers_keep_the_transport_error_safety_net(tool):
    """Safety net intact: the un-pinned tools stay http-probers, so the post-run
    http=000 false-negative guard arms for them and records a transport error
    (not a target verdict) when the container resolver actually flaps — the
    safety property holds without the broken pin."""
    assert is_http_prober(tool) is True
