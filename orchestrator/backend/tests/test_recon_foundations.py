"""Tests for the shared recon-execution FOUNDATIONS (CR-3/4/9/12/16/17/18/19/20).

Covers the PURE discovery helpers (wordlist_head, cluster_productive_parents,
wildcard_parent_candidates) and the runtime_route platform-branch logic
(Darwin-DockerDesktop vs Linux, the CR-3 dest-IP WARN firing only on
docker-desktop+container+over-threshold, resolve_runtime auto routing, and the
resolver-list path resolution + distinct-IP counting).

Pure/in-process only — no docker, no network, no tool execution.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Match the convention in test_discovery_lib.py: make `assess.lib.*` importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib.discovery import (  # noqa: E402
    cluster_productive_parents,
    wildcard_parent_candidates,
    wordlist_head,
)
from assess.lib import runtime_route as rr  # noqa: E402


# --------------------------------------------------------------------------- #
# CR-19 — wordlist_head
# --------------------------------------------------------------------------- #


def test_wordlist_head_caps_to_first_n_preserving_order():
    lines = [f"label{i}" for i in range(100)]
    head = wordlist_head(lines, 10)
    assert head == [f"label{i}" for i in range(10)]
    # Frequency order preserved (NOT sorted).
    assert head[0] == "label0"


def test_wordlist_head_identity_when_under_cap():
    lines = ["a", "b", "c"]
    assert wordlist_head(lines, 500_000) == ["a", "b", "c"]
    # exactly-at-cap is identity too
    assert wordlist_head(lines, 3) == ["a", "b", "c"]


def test_wordlist_head_returns_new_list_not_alias():
    lines = ["a", "b", "c"]
    out = wordlist_head(lines, 500_000)
    assert out == lines and out is not lines


def test_wordlist_head_nonpositive_cap_is_empty():
    assert wordlist_head(["a", "b"], 0) == []
    assert wordlist_head(["a", "b"], -5) == []


# --------------------------------------------------------------------------- #
# CR-20 — cluster_productive_parents
# --------------------------------------------------------------------------- #


def test_cluster_groups_children_under_immediate_parent():
    resolved = [
        "a.origin.api.t.com",
        "b.origin.api.t.com",
        "c.origin.api.t.com",
        "d.origin.api.t.com",
        "e.origin.api.t.com",
        "lonely.cdn.t.com",  # only 1 child under cdn.t.com → not productive
    ]
    parents = cluster_productive_parents(
        resolved, min_children=5, bruted_apexes=["t.com"]
    )
    assert parents == ["origin.api.t.com"]


def test_cluster_respects_min_children_threshold():
    resolved = ["a.x.t.com", "b.x.t.com", "c.x.t.com"]
    # 3 children, threshold 5 → nothing productive
    assert cluster_productive_parents(resolved, min_children=5, bruted_apexes=["t.com"]) == []
    # threshold 3 → x.t.com qualifies
    assert cluster_productive_parents(resolved, min_children=3, bruted_apexes=["t.com"]) == ["x.t.com"]


def test_cluster_excludes_the_bruted_apex_itself():
    # Direct children of the apex cluster under the apex, which must be skipped.
    resolved = [f"h{i}.t.com" for i in range(10)]
    assert cluster_productive_parents(resolved, min_children=2, bruted_apexes=["t.com"]) == []


def test_cluster_dedupes_children_and_normalizes():
    resolved = [
        "A.origin.t.com",
        "a.origin.t.com.",  # trailing dot + case dup of the above
        "b.origin.t.com",
        "b.origin.t.com:443",  # port stripped → dup of b
    ]
    # distinct children of origin.t.com = {a, b} = 2
    assert cluster_productive_parents(resolved, min_children=2, bruted_apexes=["t.com"]) == ["origin.t.com"]
    assert cluster_productive_parents(resolved, min_children=3, bruted_apexes=["t.com"]) == []


def test_cluster_skips_blanks_comments_and_two_label_hosts():
    resolved = ["", "# comment", "t.com", "a.b.t.com", "c.b.t.com"]
    assert cluster_productive_parents(resolved, min_children=2, bruted_apexes=["t.com"]) == ["b.t.com"]


# --------------------------------------------------------------------------- #
# CR-17 — wildcard_parent_candidates
# --------------------------------------------------------------------------- #


def test_wildcard_candidates_returns_distinct_sorted_parents():
    hosts = [
        "x.review.library.acme.example",
        "y.review.library.acme.example",
        "z.media.library.acme.example",
        "library.acme.example",  # 2-label apex → no deeper parent
    ]
    assert wildcard_parent_candidates(hosts) == ["media.library.acme.example", "review.library.acme.example"]


def test_wildcard_candidates_handles_noise_and_dedup():
    hosts = ["a.svc.t.com", "a.svc.t.com.", "B.SVC.T.COM", "", "#c"]
    assert wildcard_parent_candidates(hosts) == ["svc.t.com"]


# --------------------------------------------------------------------------- #
# runtime_route — platform detection branches
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_runtime_cache():
    rr.reset_runtime_cache()
    yield
    rr.reset_runtime_cache()


def _darwin_desktop(monkeypatch):
    monkeypatch.setattr(rr.platform, "system", lambda: "Darwin")
    # docker info names Docker Desktop
    monkeypatch.setattr(
        rr, "_docker_info_text", lambda runner=None: "operatingsystem docker desktop desktop-linux"
    )
    return rr.detect_runtime(force=True)


def _linux_native(monkeypatch):
    monkeypatch.setattr(rr.platform, "system", lambda: "Linux")
    # native linux docker info — no desktop signal
    monkeypatch.setattr(rr, "_docker_info_text", lambda runner=None: "operatingsystem ubuntu 22.04")
    return rr.detect_runtime(force=True)


def test_detect_runtime_darwin_docker_desktop(monkeypatch):
    info = _darwin_desktop(monkeypatch)
    assert info.platform == "darwin"
    assert info.is_docker_desktop is True
    assert info.recommended == "host"


def test_detect_runtime_darwin_without_docker_info_still_desktop(monkeypatch):
    monkeypatch.setattr(rr.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(rr, "_docker_info_text", lambda runner=None: "")
    info = rr.detect_runtime(force=True)
    # Darwin + no docker info → safe-default to Docker Desktop (guards active).
    assert info.is_docker_desktop is True
    assert info.recommended == "host"


def test_detect_runtime_linux_native_is_noop(monkeypatch):
    info = _linux_native(monkeypatch)
    assert info.platform == "linux"
    assert info.is_docker_desktop is False
    assert info.recommended == "container"


def test_detect_runtime_is_cached(monkeypatch):
    monkeypatch.setattr(rr.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(rr, "_docker_info_text", lambda runner=None: "")
    first = rr.detect_runtime(force=True)
    # Now flip the platform; without force the cache must win.
    monkeypatch.setattr(rr.platform, "system", lambda: "Linux")
    second = rr.detect_runtime()
    assert second is first
    assert second.platform == "darwin"


# --------------------------------------------------------------------------- #
# runtime_route — resolve_runtime auto routing
# --------------------------------------------------------------------------- #

_DESKTOP = rr.RuntimeInfo(platform="darwin", is_docker_desktop=True, recommended="host")
_LINUX = rr.RuntimeInfo(platform="linux", is_docker_desktop=False, recommended="container")


def test_resolve_auto_routes_dns_heavy_to_host_on_desktop():
    route = rr.resolve_runtime(
        "auto", tool="puredns", runtime=_DESKTOP, check_host_binary=False
    )
    assert route == "host"


def test_resolve_auto_stays_container_on_linux():
    route = rr.resolve_runtime(
        "auto", tool="puredns", runtime=_LINUX, check_host_binary=False
    )
    assert route == "container"


def test_resolve_auto_non_dns_tool_stays_container_even_on_desktop():
    route = rr.resolve_runtime(
        "auto", tool="curl", runtime=_DESKTOP, check_host_binary=False
    )
    assert route == "container"


def test_resolve_explicit_container_always_container():
    assert (
        rr.resolve_runtime("container", tool="puredns", runtime=_DESKTOP, check_host_binary=False)
        == "container"
    )


def test_resolve_explicit_host_with_binary_present():
    assert (
        rr.resolve_runtime("host", tool="puredns", runtime=_DESKTOP, check_host_binary=False)
        == "host"
    )


def test_resolve_host_falls_back_to_container_when_binary_missing(monkeypatch, capsys):
    monkeypatch.setattr(rr.shutil, "which", lambda _t: None)
    route = rr.resolve_runtime(
        "host", tool="puredns", runtime=_DESKTOP, check_host_binary=True
    )
    assert route == "container"
    err = capsys.readouterr().err
    assert "WARN" in err and "host PATH" in err


def test_resolve_auto_host_binary_missing_stays_container_silently(monkeypatch, capsys):
    monkeypatch.setattr(rr.shutil, "which", lambda _t: None)
    route = rr.resolve_runtime(
        "auto", tool="puredns", runtime=_DESKTOP, check_host_binary=True
    )
    assert route == "container"
    # auto path is silent (no nag) when the host binary is simply absent
    assert capsys.readouterr().err == ""


def test_resolve_httpx_is_host_eligible_for_bulk_liveness():
    assert (
        rr.resolve_runtime("auto", tool="httpx", runtime=_DESKTOP, check_host_binary=False)
        == "host"
    )


# --------------------------------------------------------------------------- #
# CR-3 — warn_excessive_resolver_ips (WARN only, narrow firing conditions)
# --------------------------------------------------------------------------- #


def test_warn_fires_on_desktop_container_over_threshold(capsys):
    fired = rr.warn_excessive_resolver_ips(80, threshold=50, route="container", runtime=_DESKTOP)
    assert fired is True
    err = capsys.readouterr().err
    assert "WARN" in err
    assert "distinct resolver IPs" in err
    assert "docker-desktop-network-hazards.md" in err


def test_warn_silent_at_or_under_threshold(capsys):
    assert rr.warn_excessive_resolver_ips(50, threshold=50, route="container", runtime=_DESKTOP) is False
    assert rr.warn_excessive_resolver_ips(10, threshold=50, route="container", runtime=_DESKTOP) is False
    assert capsys.readouterr().err == ""


def test_warn_noop_on_host_route(capsys):
    assert rr.warn_excessive_resolver_ips(9999, threshold=50, route="host", runtime=_DESKTOP) is False
    assert capsys.readouterr().err == ""


def test_warn_noop_on_native_linux(capsys):
    assert rr.warn_excessive_resolver_ips(9999, threshold=50, route="container", runtime=_LINUX) is False
    assert capsys.readouterr().err == ""


def test_warn_never_raises_even_with_huge_count():
    # Pure smoke: the guard is advisory; it must never throw.
    rr.warn_excessive_resolver_ips(10**9, threshold=50, route="container", runtime=_DESKTOP)


def test_resolver_ip_cap_env_override(monkeypatch):
    monkeypatch.setenv("VIGIL_RESOLVER_IP_CAP", "5")
    assert rr.resolver_ip_cap() == 5
    # default threshold (None) now reads the env override
    assert rr.warn_excessive_resolver_ips(6, route="container", runtime=_DESKTOP) is True
    assert rr.warn_excessive_resolver_ips(5, route="container", runtime=_DESKTOP) is False


def test_resolver_ip_cap_invalid_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("VIGIL_RESOLVER_IP_CAP", "not-an-int")
    assert rr.resolver_ip_cap() == rr.DEFAULT_RESOLVER_IP_CAP


# --------------------------------------------------------------------------- #
# CR-12 / CR-18 — shipped resolver lists + path resolution + distinct count
# --------------------------------------------------------------------------- #


def test_shipped_resolver_lists_exist_and_are_within_cap():
    premium = rr.premium_anycast_path()
    trusted = rr.trusted_anycast_path()
    assert premium.is_file(), premium
    assert trusted.is_file(), trusted

    n_premium = rr.count_distinct_resolver_ips(premium)
    n_trusted = rr.count_distinct_resolver_ips(trusted)

    # CR-18: ~40 premium-anycast IPs; must stay under the in-container dest-IP cap.
    assert 30 <= n_premium <= rr.DEFAULT_RESOLVER_IP_CAP, n_premium
    # CR-12: ~12-16 trusted validation-tier IPs.
    assert 10 <= n_trusted <= 16, n_trusted
    # The trusted set is a subset-by-design of the brute set.
    assert n_trusted < n_premium


def test_count_distinct_resolver_ips_handles_comments_dups_and_prefixes(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "1.1.1.1",
                "1.1.1.1",  # dup
                "8.8.8.8",
                "tcp:9.9.9.9",  # transport prefix stripped
                "8.8.4.4:53",  # host:port → host
            ]
        ),
        encoding="utf-8",
    )
    assert rr.count_distinct_resolver_ips(f) == 4


def test_count_distinct_resolver_ips_missing_file_is_zero(tmp_path):
    assert rr.count_distinct_resolver_ips(tmp_path / "nope.txt") == 0


def test_container_staged_path_format():
    assert (
        rr.container_staged_path("acme", "premium-anycast.txt")
        == "/engagements/acme/wordlists/premium-anycast.txt"
    )


def test_resolver_data_dir_resolves_under_assess_data():
    d = rr.resolver_data_dir()
    assert d.name == "resolvers"
    assert d.parent.name == "data"
    assert d.parent.parent.name == "assess"
