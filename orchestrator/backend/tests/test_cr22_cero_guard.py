"""Tests for the CR-22 distinct-TARGET-IP guard (cero whole-CIDR hazard).

The CR-3 guard (warn_excessive_resolver_ips) counts RESOLVER destinations and is
wired only into the DNS/web-discovery path; it does NOT cover cero. A whole-CIDR
cero run in the container NAT-saturates the macOS Docker Desktop userspace proxy
exactly like a large resolver list (engagement I-001), so cero needs its own
WARN-only guard keyed on distinct SCAN-TARGET IPs.

This covers:
  * count_distinct_target_ips — bare IP / CIDR expansion / over-cap CIDR / mixed
    file / hostname / blanks+comments;
  * warn_excessive_target_ips — narrow firing conditions (Docker-Desktop +
    container route + over cap), no-op everywhere else, never raises;
  * kali_cero.run — a -l file of wide CIDRs WARNs; a small resolved-IP list (the
    cero.md DEFAULT pattern) stays quiet.

Pure/in-process only — no docker, no network, no tool execution (VIGIL_KALI_NOOP).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

# Match the convention in test_recon_foundations.py / test_kali_cli.py: make
# `assess.*` importable from the agent script tree.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib import runtime_route as rr  # noqa: E402


_DESKTOP = rr.RuntimeInfo(platform="darwin", is_docker_desktop=True, recommended="host")
_LINUX = rr.RuntimeInfo(platform="linux", is_docker_desktop=False, recommended="container")


@pytest.fixture(autouse=True)
def _clear_runtime_cache():
    rr.reset_runtime_cache()
    yield
    rr.reset_runtime_cache()


# --------------------------------------------------------------------------- #
# count_distinct_target_ips
# --------------------------------------------------------------------------- #


def test_count_single_bare_ip_is_one():
    assert rr.count_distinct_target_ips(["10.0.0.1"]) == 1


def test_count_hostname_is_one_unresolved_at_plan_time():
    assert rr.count_distinct_target_ips(["example.com"]) == 1
    assert rr.count_distinct_target_ips(["a.example.com", "b.example.com"]) == 2


def test_count_slash30_cidr_expands_to_four():
    # A /30 is exactly 4 addresses (well within the enum threshold).
    assert rr.count_distinct_target_ips(["192.168.0.0/30"]) == 4


def test_count_slash24_cidr_is_enumerated_not_over_cap():
    # /24 is the IPv4 enum threshold (boundary, inclusive) → real count, 256.
    assert rr.count_distinct_target_ips(["10.1.2.0/24"]) == 256


def test_count_cidr_wider_than_slash24_is_instantly_over_cap():
    # A /16 (and anything wider, e.g. /8) short-circuits to the over-cap sentinel
    # WITHOUT enumerating 65k+/16M hosts.
    over = rr._TARGET_IP_OVER_CAP_SENTINEL
    assert rr.count_distinct_target_ips(["10.0.0.0/16"]) == over
    assert rr.count_distinct_target_ips(["10.0.0.0/8"]) == over


def test_count_ipv6_cidr_wider_than_slash120_is_over_cap():
    over = rr._TARGET_IP_OVER_CAP_SENTINEL
    assert rr.count_distinct_target_ips(["2001:db8::/64"]) == over
    # /120 is the IPv6 enum threshold (boundary) → enumerated (256 addrs).
    assert rr.count_distinct_target_ips(["2001:db8::/120"]) == 256


def test_count_mixed_file_entries_sums_expected():
    entries = [
        "10.0.0.1",          # bare IP            -> 1
        "192.168.0.0/30",    # /30               -> 4
        "scanme.example.com",  # hostname        -> 1
        "172.16.5.0/30",     # /30               -> 4
    ]
    assert rr.count_distinct_target_ips(entries) == 10


def test_count_skips_blanks_and_comments():
    entries = [
        "",
        "   ",
        "# a comment",
        "  # indented comment",
        "10.0.0.1",
        "",
    ]
    assert rr.count_distinct_target_ips(entries) == 1


def test_count_non_cidr_slash_entry_counts_as_one():
    # A URL/path slips through ip_network() as a ValueError → counts as 1 host.
    assert rr.count_distinct_target_ips(["https://example.com/path"]) == 1


def test_count_over_cap_short_circuits_before_huge_enumeration():
    # A wide CIDR FIRST in the list returns immediately; later entries are moot.
    over = rr._TARGET_IP_OVER_CAP_SENTINEL
    assert rr.count_distinct_target_ips(["10.0.0.0/8", "10.0.0.1"]) == over


# --------------------------------------------------------------------------- #
# warn_excessive_target_ips
# --------------------------------------------------------------------------- #


def test_warn_fires_on_desktop_container_over_cap(capsys):
    fired = rr.warn_excessive_target_ips(80, route="container", runtime=_DESKTOP)
    assert fired is True
    err = capsys.readouterr().err
    assert "WARN:" in err
    assert "cero" in err
    assert "target IPs" in err
    # Caveat about hostnames resolving to multiple A-records is present.
    assert "A-records" in err
    # Points at both guides.
    assert "docker-desktop-network-hazards.md" in err
    assert "cero.md" in err


def test_warn_silent_at_or_under_cap(capsys):
    assert rr.warn_excessive_target_ips(50, route="container", runtime=_DESKTOP) is False
    assert rr.warn_excessive_target_ips(1, route="container", runtime=_DESKTOP) is False
    assert capsys.readouterr().err == ""


def test_warn_noop_on_host_route(capsys):
    assert rr.warn_excessive_target_ips(9999, route="host", runtime=_DESKTOP) is False
    assert capsys.readouterr().err == ""


def test_warn_noop_on_native_linux(capsys):
    assert rr.warn_excessive_target_ips(10**6, route="container", runtime=_LINUX) is False
    assert capsys.readouterr().err == ""


def test_warn_never_raises_even_with_huge_count():
    # WARN-only posture: never raises regardless of magnitude.
    assert rr.warn_excessive_target_ips(10**9, route="container", runtime=_DESKTOP) is True


def test_warn_respects_resolver_ip_cap_env_override(monkeypatch, capsys):
    # CR-22 reuses VIGIL_RESOLVER_IP_CAP (no new env).
    monkeypatch.setenv("VIGIL_RESOLVER_IP_CAP", "5")
    assert rr.warn_excessive_target_ips(6, route="container", runtime=_DESKTOP) is True
    capsys.readouterr()
    assert rr.warn_excessive_target_ips(5, route="container", runtime=_DESKTOP) is False


# --------------------------------------------------------------------------- #
# kali_cero.run — guard wiring (VIGIL_KALI_NOOP, no real container)
# --------------------------------------------------------------------------- #


def _import(name: str):
    return importlib.import_module(name)


def _run_cero_with_input_list(monkeypatch, tmp_path, list_lines, *, runtime):
    """Drive `kali cero -l <file>` end-to-end with a stubbed kali_exec.

    Returns the captured stderr. Forces the runtime to ``runtime`` so the guard's
    Docker-Desktop gate is deterministic on any host.
    """
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")
    cero_mod = _import("assess.commands.kali_cero")

    list_file = tmp_path / "targets.txt"
    list_file.write_text("\n".join(list_lines) + "\n", encoding="utf-8")

    def fake_kali_exec(cmd, **kwargs):
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    monkeypatch.setattr(cero_mod, "kali_exec", fake_kali_exec)
    # Pin the runtime so the guard gate is deterministic (no docker probe). Patch
    # detect_runtime on the SAME runtime_route module object kali_cero imported,
    # NOT this test's top-level `rr`: a sibling test file's autouse fixture pops
    # `assess.*` from sys.modules, so a re-imported kali_cero binds a FRESH
    # runtime_route instance that is not the stale `rr` captured at collection.
    # Patching cero_mod.runtime_route makes the pin survive any import order.
    monkeypatch.setattr(cero_mod.runtime_route, "detect_runtime", lambda *a, **k: runtime)

    cli.main(
        [
            "kali",
            "cero",
            "-l",
            str(list_file),
            "--technique",
            "OSINT",
            "--intent",
            "cero cr22 guard test",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "600",
        ]
    )


def test_cero_input_list_of_wide_cidrs_emits_warn(monkeypatch, tmp_path, capsys):
    _run_cero_with_input_list(
        monkeypatch,
        tmp_path,
        ["10.0.0.0/16", "172.16.0.0/16"],
        runtime=_DESKTOP,
    )
    err = capsys.readouterr().err
    assert "WARN:" in err
    assert "cero" in err
    assert "exceeds the in-container cap" in err


def test_cero_small_resolved_ip_list_stays_quiet(monkeypatch, tmp_path, capsys):
    # The cero.md DEFAULT pattern: a short list of already-resolved IPs. This must
    # NOT trip the guard (no NAT-table wedge risk), even on Docker Desktop.
    resolved = [f"203.0.113.{i}" for i in range(1, 11)]  # 10 distinct IPs
    _run_cero_with_input_list(
        monkeypatch,
        tmp_path,
        resolved,
        runtime=_DESKTOP,
    )
    err = capsys.readouterr().err
    assert "WARN:" not in err


def test_cero_wide_cidr_list_stays_quiet_on_native_linux(monkeypatch, tmp_path, capsys):
    # Even a /8 is a transparent no-op off Docker Desktop (native Linux / remote).
    _run_cero_with_input_list(
        monkeypatch,
        tmp_path,
        ["10.0.0.0/8"],
        runtime=_LINUX,
    )
    err = capsys.readouterr().err
    assert "WARN:" not in err
