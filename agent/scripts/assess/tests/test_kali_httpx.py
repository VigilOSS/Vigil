"""Offline tests for the `kali httpx` typed wrapper's flag -> argv construction.
No docker, no backend, no billed calls.

Covers the Wave-1 "httpx ergonomics" promotions: -ports/-p (I-6 alt-port
liveness undercount), -content-length/-cl, -path, -store-response/-sr, and
-store-response-dir/-srd. Mirrors the captured_cmd pattern in test_arjun.py /
test_kali_arjun.py."""
from __future__ import annotations

import argparse

import pytest

from assess.commands import kali_httpx
from assess.lib.client import AssessError


def _httpx_ns(**over):
    ns = argparse.Namespace(
        target_url="http://t.example/",
        target_list="",
        ports="",
        path="",
        status_code=False,
        title=False,
        content_length=False,
        tech_detect=False,
        tls_grab=False,
        web_server=False,
        show_ip=False,
        cdn=False,
        favicon=False,
        location=False,
        follow_redirects=False,
        threads="",
        rate_limit="",
        timeout_http="",
        retries="",
        headers=None,
        match_codes="",
        filter_codes="",
        output_json=False,
        store_response=False,
        store_response_dir="",
        output="",
        extra_args="",
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


@pytest.fixture
def captured_cmd(monkeypatch):
    box: dict = {}

    def fake_exec(cmd, **kwargs):
        box["cmd"] = cmd
        return object()

    monkeypatch.setattr(kali_httpx, "kali_exec", fake_exec)
    monkeypatch.setattr(kali_httpx, "emit_result", lambda r: None)
    monkeypatch.setattr(kali_httpx, "kali_args_to_kwargs", lambda a: {})
    return box


def test_run_requires_u_or_l():
    with pytest.raises(AssessError):
        kali_httpx.run(_httpx_ns(target_url="", target_list=""))


# --------------------------------------------------------------------------
# I-6 — -ports/-p alt-port liveness undercount fix
# --------------------------------------------------------------------------
def test_ports_flag_produces_typed_argv(captured_cmd):
    kali_httpx.run(_httpx_ns(ports="80,443,8080,8443"))
    cmd = captured_cmd["cmd"]
    assert "-ports" in cmd
    assert cmd[cmd.index("-ports") + 1] == "80,443,8080,8443"


def test_ports_flag_absent_when_unset(captured_cmd):
    kali_httpx.run(_httpx_ns())
    assert "-ports" not in captured_cmd["cmd"]


def test_ports_short_alias_registered():
    # -p is registered as an alias for -ports on the same dest, so an operator
    # invocation using the short form still lands in args.ports.
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kali_httpx.register(sub)
    ns = parser.parse_args([
        "httpx", "-u", "http://t.example/", "-p", "8080,8443",
        "--technique", "RECON", "--intent", "x", "--probe-kind", "fingerprint",
        "--phase", "recon", "--timeout", "30",
    ])
    assert ns.ports == "8080,8443"


# --------------------------------------------------------------------------
# -content-length / -cl
# --------------------------------------------------------------------------
def test_content_length_flag_emits_cl(captured_cmd):
    kali_httpx.run(_httpx_ns(content_length=True))
    assert "-cl" in captured_cmd["cmd"]
    assert "-content-length" not in captured_cmd["cmd"]


def test_content_length_flag_absent_when_unset(captured_cmd):
    kali_httpx.run(_httpx_ns())
    assert "-cl" not in captured_cmd["cmd"]


# --------------------------------------------------------------------------
# -path
# --------------------------------------------------------------------------
def test_path_flag_produces_typed_argv(captured_cmd):
    kali_httpx.run(_httpx_ns(path="/api/v1"))
    cmd = captured_cmd["cmd"]
    assert "-path" in cmd
    assert cmd[cmd.index("-path") + 1] == "/api/v1"


def test_path_flag_absent_when_unset(captured_cmd):
    kali_httpx.run(_httpx_ns())
    assert "-path" not in captured_cmd["cmd"]


# --------------------------------------------------------------------------
# -store-response / -sr + -store-response-dir / -srd
# --------------------------------------------------------------------------
def test_store_response_flags_produce_typed_argv(captured_cmd):
    kali_httpx.run(_httpx_ns(store_response=True, store_response_dir="scans/httpx_bodies"))
    cmd = captured_cmd["cmd"]
    assert "-store-response" in cmd
    assert "-store-response-dir" in cmd
    assert cmd[cmd.index("-store-response-dir") + 1] == "scans/httpx_bodies"


def test_store_response_flags_absent_when_unset(captured_cmd):
    kali_httpx.run(_httpx_ns())
    cmd = captured_cmd["cmd"]
    assert "-store-response" not in cmd
    assert "-store-response-dir" not in cmd


def test_store_response_dir_alone_still_passed_through(captured_cmd):
    # The wrapper is a typed passthrough, not a cross-flag validator — it does
    # not second-guess -store-response-dir without -store-response (httpx's own
    # semantics govern that combination).
    kali_httpx.run(_httpx_ns(store_response_dir="scans/httpx_bodies"))
    cmd = captured_cmd["cmd"]
    assert "-store-response" not in cmd
    assert "-store-response-dir" in cmd


# --------------------------------------------------------------------------
# -web-server stays typed; no colliding -server flag was introduced.
# --------------------------------------------------------------------------
def test_web_server_flag_has_no_bare_server_alias(captured_cmd):
    kali_httpx.run(_httpx_ns(web_server=True))
    cmd = captured_cmd["cmd"]
    assert "-web-server" in cmd
    assert "-server" not in cmd


# --------------------------------------------------------------------------
# All new flags together — full argv shape, mirrors how other kali-verb tests
# pin the whole command (see test_kali_arjun / test_arjun captured_cmd tests).
# --------------------------------------------------------------------------
def test_all_new_typed_flags_together(captured_cmd):
    kali_httpx.run(_httpx_ns(
        ports="80,443,8080,8443",
        content_length=True,
        store_response=True,
        store_response_dir="scans/bodies",
        path="/health",
    ))
    cmd = captured_cmd["cmd"]
    assert cmd[0] == "httpx"
    assert cmd[cmd.index("-u") + 1] == "http://t.example/"
    assert cmd[cmd.index("-ports") + 1] == "80,443,8080,8443"
    assert cmd[cmd.index("-path") + 1] == "/health"
    assert "-cl" in cmd
    assert "-store-response" in cmd
    assert cmd[cmd.index("-store-response-dir") + 1] == "scans/bodies"
