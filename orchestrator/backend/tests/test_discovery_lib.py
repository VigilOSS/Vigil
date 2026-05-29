"""Tests for the pure host de-noise filter used by the discovery pipelines."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib.discovery import denoise_hosts, is_noise_host  # noqa: E402


def test_is_noise_host_matches_known_patterns():
    noisy = [
        "_dmarc.example.mil",
        "_dkim.foo.example.mil",
        "dhcp-10-1-2-3.example.mil",
        "dha-12-345.health.mil",
        "dhpcile7.hq.af.mil",
        "jdoe-laptop.example.mil",
        "00-08-74-ab.amc.af.mil",
        "3.2.1.10.in-addr.rev.example.mil",
    ]
    for h in noisy:
        assert is_noise_host(h) is True, h


def test_is_noise_host_keeps_real_origins():
    for h in ("api.example.mil", "portal.navy.mil", "gitlab.nswc.navy.mil", "vault.darpa.mil"):
        assert is_noise_host(h) is False, h


def test_denoise_hosts_dedupes_normalizes_and_counts():
    lines = [
        "https://Api.Example.mil/login",   # scheme+path stripped, lowercased
        "api.example.mil",                  # dup of the above
        "_dmarc.example.mil",               # noise
        "dhcp-1-2-3.example.mil",           # noise
        "",                                  # blank
        "# comment",                        # comment
        "portal.navy.mil:8443",             # port preserved (distinct target)
    ]
    kept, dropped = denoise_hosts(lines)
    assert kept == ["api.example.mil", "portal.navy.mil:8443"]
    assert dropped == 2
