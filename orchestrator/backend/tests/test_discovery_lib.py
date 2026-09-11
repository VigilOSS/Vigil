"""Tests for the pure host de-noise filter used by the discovery pipelines."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib.discovery import denoise_hosts, is_noise_host  # noqa: E402


def test_is_noise_host_matches_known_patterns():
    noisy = [
        "_dmarc.northstar.example",
        "_dkim.foo.northstar.example",
        "dhcp-10-1-2-3.northstar.example",
        "dha-12-345.health.northstar.example",
        "dhpcile7.hq.northstar.example",
        "jdoe-laptop.northstar.example",
        "00-08-74-ab.ops.northstar.example",
        "3.2.1.10.in-addr.rev.northstar.example",
    ]
    for h in noisy:
        assert is_noise_host(h) is True, h


def test_is_noise_host_keeps_real_origins():
    for h in (
        "api.northstar.example",
        "portal.ocean.example",
        "gitlab.lab.ocean.example",
        "vault.research.example",
    ):
        assert is_noise_host(h) is False, h


def test_denoise_hosts_dedupes_normalizes_and_counts():
    lines = [
        "https://Api.Northstar.Example/login",  # scheme+path stripped, lowercased
        "api.northstar.example",                 # dup of the above
        "_dmarc.northstar.example",              # noise
        "dhcp-1-2-3.northstar.example",          # noise
        "",                                  # blank
        "# comment",                        # comment
        "portal.ocean.example:8443",              # port preserved (distinct target)
    ]
    kept, dropped = denoise_hosts(lines)
    assert kept == ["api.northstar.example", "portal.ocean.example:8443"]
    assert dropped == 2


def test_mac_ptr_regex_does_not_drop_real_hex_prefixed_hosts():
    # Two leading hex pairs is too common in corporate naming — must be KEPT.
    for h in (
        "ad-01-portal.northstar.example",
        "fe-80-gw.northstar.example",
        "ba-be-portal.northstar.example",
        "ce-12-34.example.com",
    ):
        assert is_noise_host(h) is False, h
    # Real MAC-octet PTR names (>=3 leading hex octets) are still dropped.
    assert is_noise_host("00-08-74-ab-cd-ef.ops.northstar.example") is True
    assert is_noise_host("00-08-74-xx.ops.northstar.example") is True  # 3 hex octets → MAC-noise


def test_normalize_host_bare_ipv6_and_trailing_dot():
    from assess.lib.discovery import normalize_host
    assert normalize_host("2001:db8::1") == "2001:db8::1"      # bare IPv6 not truncated
    assert normalize_host("[2001:db8::1]:443") == "[2001:db8::1]"
    assert normalize_host("host.example.com.") == "host.example.com"  # trailing dot stripped
    assert normalize_host("https://Host.Example.com:8443/x") == "host.example.com"
