"""Tests for the shared reachability verdict helper (lib/reachability.py)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib.reachability import (  # noqa: E402
    BLACKHOLED,
    CURL_WRITE_FORMAT,
    LIVE,
    TLS13_RESET,
    UNKNOWN,
    classify_probe,
    parse_curl_w,
)


# --- LIVE: any positive reachability signal --------------------------------

def test_live_when_remote_ip_present_even_if_code_zero():
    # CONNECT-proxy artifact: http_code 000 but TCP completed (remote_ip set).
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="23.1.2.3") == LIVE


def test_live_when_connect_time_positive():
    assert classify_probe(http_code="000", time_connect=0.04, remote_ip="") == LIVE


def test_walls_are_live():
    # 401/403/302 walls are reachable origins, not dead (the §9 lesson).
    for code in ("401", "403", "302", "200"):
        assert classify_probe(http_code=code, time_connect=0.02, remote_ip="10.0.0.1") == LIVE


def test_httpx_failed_false_is_live():
    assert classify_probe(http_code="200", failed=False) == LIVE


def test_answered_code_without_connect_fields_is_live():
    # httpx gave a status but no timing/ip fields, and didn't mark failed.
    assert classify_probe(http_code="200") == LIVE


# --- TLS-1.3 reset (recoverable) -------------------------------------------

def test_tls_reset_via_curl_exit_35():
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="", curl_exit=35) == TLS13_RESET


def test_tls_reset_via_stderr_signature():
    v = classify_probe(http_code="000", time_connect=0.0, remote_ip="",
                       stderr="OpenSSL SSL_connect: Connection reset by peer in TLS handshake")
    assert v == TLS13_RESET


# --- BLACKHOLED: clean TCP failure, no IP ----------------------------------

def test_blackholed_on_connect_refused():
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="", curl_exit=7) == BLACKHOLED


def test_blackholed_on_timeout():
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="", curl_exit=28) == BLACKHOLED


def test_blackholed_on_httpx_failed_true():
    assert classify_probe(http_code="0", failed=True, remote_ip="") == BLACKHOLED


def test_blackholed_on_zero_code_no_signal():
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="") == BLACKHOLED


def test_sentinel_ip_does_not_count_as_connected():
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="0.0.0.0") == BLACKHOLED


# --- UNKNOWN: not enough signal --------------------------------------------

def test_unknown_when_no_signal_at_all():
    assert classify_probe() == UNKNOWN


def test_dns_resolve_failure_is_unknown_not_blackholed():
    # curl exit 6 = couldn't resolve host; that's a name problem, not an egress
    # blackhole — must not be counted toward a cluster blackhole verdict.
    assert classify_probe(http_code="000", time_connect=0.0, remote_ip="", curl_exit=6) == UNKNOWN


# --- parse_curl_w ----------------------------------------------------------

def test_parse_curl_w_full_line():
    out = parse_curl_w("403 0.041 23.1.2.3")
    assert out == {"http_code": "403", "time_connect": 0.041, "remote_ip": "23.1.2.3"}


def test_parse_curl_w_missing_remote_ip():
    out = parse_curl_w("000 0.000")
    assert out["http_code"] == "000"
    assert out["time_connect"] == 0.0
    assert out["remote_ip"] == ""


def test_parse_then_classify_roundtrip():
    parsed = parse_curl_w("000 0.000 ")
    assert classify_probe(curl_exit=7, **parsed) == BLACKHOLED
    assert "%{http_code}" in CURL_WRITE_FORMAT
