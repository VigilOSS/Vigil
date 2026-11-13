"""An automated crawl follows only the hosts scope.json declares.

katana's default field scope is `rdn`, so a crawl seeded on one declared host
followed any sibling subdomain of its registrable domain that a page linked —
a live request to an undeclared host, which the ingest scope filter only saw
after it was sent. Every crawl Vigil assembles (`web-discovery`, `kali katana`)
now carries a fence derived from the engagement's scope.json allowlist: a bare
host admits that host only, a wildcard admits its apex and every subdomain, an
`out_of_scope` carve-out is excluded, and a caller who supplies its own scope
flags through the passthrough args owns the boundary and is told so.

`_follows` models how katana judges a discovered URL under the argv: the field
scope (a named one relative to the seed, or a custom regex) and the crawl-scope
and out-of-scope regexes must all agree. The fence regexes use only syntax Go's
RE2 shares with Python's `re`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from assess.commands import kali_katana
from assess.lib import scope as scope_lib


def _value(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv else None


def _follows(argv: list[str], seed: str, url: str) -> bool:
    host = urlsplit(url).hostname or ""
    seed_host = urlsplit(seed).hostname or ""
    field_scope = _value(argv, "-fs") or "rdn"
    if field_scope == "fqdn":
        in_field = host == seed_host
    elif field_scope in {"rdn", "dn"}:
        in_field = host.split(".")[-2:] == seed_host.split(".")[-2:]
    else:
        in_field = bool(re.search(field_scope, host))
    crawl_scope = _value(argv, "-cs")
    out_scope = _value(argv, "-cos")
    return (
        in_field
        and (crawl_scope is None or bool(re.search(crawl_scope, url)))
        and (out_scope is None or not re.search(out_scope, url))
    )


def _fence(hosts: list[str], *, out_of_scope: list[str] | None = None, seeds=()) -> list[str]:
    scope = {"hosts": hosts, **({"out_of_scope": out_of_scope} if out_of_scope else {})}
    return scope_lib.crawl_fence(scope, seed_hosts=seeds).argv


def test_a_bare_host_scope_does_not_follow_a_linked_sibling_subdomain() -> None:
    argv = _fence(["app.example.com"])
    seed = "https://app.example.com/login"

    assert _follows(argv, seed, "https://app.example.com/account")
    assert not _follows(argv, seed, "https://cdn.example.com/js/fp.js")
    for smuggled in (
        "https://app.example.com.evil.example/",
        "https://evil-app.example.com/",
        "https://app.example.com@evil.example/",
        "https://evil.example/?next=https://app.example.com/",
    ):
        assert not _follows(argv, seed, smuggled), smuggled


def test_a_wildcard_scope_follows_its_subdomains_and_stays_inside_them() -> None:
    argv = _fence(["*.example.com"])
    seed = "https://app.example.com/"

    assert _follows(argv, seed, "https://cdn.example.com/js/app.js")
    assert _follows(argv, seed, "https://example.com/")
    assert not _follows(argv, seed, "https://example.com.evil.example/")
    assert not _follows(argv, seed, "https://cdn.example.org/")


def test_an_out_of_scope_carve_out_is_excluded_from_a_wildcard_crawl() -> None:
    argv = _fence(["*.example.com"], out_of_scope=["admin.example.com"])
    seed = "https://app.example.com/"

    assert not _follows(argv, seed, "https://admin.example.com/panel")
    assert _follows(argv, seed, "https://shop.example.com/")


def test_a_seed_scope_json_does_not_declare_is_named() -> None:
    fence = scope_lib.crawl_fence({"hosts": ["app.example.com"]}, seed_hosts=["other.example.org"])

    assert any("other.example.org" in warning for warning in fence.warnings)


def test_a_passthrough_scope_flag_is_detected_in_every_spelling() -> None:
    for tokens in (["-fs", "rdn"], ["-field-scope=dn"], ["-cs", ".*"], ["-ns"], ["-no-scope"]):
        assert scope_lib.crawl_fence_overrides(tokens), tokens
    assert scope_lib.crawl_fence_overrides(["-kf", "all", "-ef", "png"]) == []


def test_a_double_dash_scope_flag_is_an_override_too() -> None:
    """katana's flag parser takes `--flag` as it takes `-flag`."""
    for tokens in (
        ["--cs", ".*"], ["--crawl-scope=.*"], ["--fs", "rdn"], ["--field-scope", "dn"],
        ["--ns"], ["--no-scope"], ["--fs=rdn"],
    ):
        assert scope_lib.crawl_fence_overrides(tokens), tokens
    assert scope_lib.crawl_fence_overrides(["--kf", "all", "--", "-cs"]) == []


def test_a_multi_host_bare_scope_says_each_seed_stays_on_its_own_host() -> None:
    fence = scope_lib.crawl_fence({"hosts": ["app.example.com", "api.example.com"]})

    assert _value(fence.argv, "-fs") == "fqdn"
    assert "each seed stays on its own host" in fence.summary
    assert "seed each host" in fence.summary


def test_a_wildcard_scope_says_the_crawl_follows_declared_hosts() -> None:
    fence = scope_lib.crawl_fence({"hosts": ["*.example.com"]})

    assert "follows links between declared hosts" in fence.summary


# -- kali katana --------------------------------------------------------------


def _katana_args(tmp_path: Path, **over) -> SimpleNamespace:
    base = dict(
        target_url="https://app.example.com/", target_list="", no_jc=False, no_jsl=False,
        depth="5", concurrency="5", rate_limit="", allow_fast_crawl=False, field_scope="",
        known_files="", crawl_out_scope="", headers=None, keep_bodies=False,
        include_static=False, headless=False, output="", jsonl=False, extra_args="",
        crawl_budget="", timeout=60, engagement_dir=str(tmp_path),
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def katana_run(monkeypatch, tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": ["app.example.com"]}), encoding="utf-8")
    captured: list[list[str]] = []
    monkeypatch.setattr(kali_katana, "_resolve_rate_cap", lambda _args: None)
    monkeypatch.setattr(kali_katana, "kali_args_to_kwargs", lambda _args: {})
    monkeypatch.setattr(
        kali_katana, "load_config", lambda _flag: SimpleNamespace(engagement_dir=str(tmp_path))
    )
    monkeypatch.setattr(
        kali_katana, "kali_exec", lambda cmd, **_kw: captured.append(list(cmd)) or SimpleNamespace()
    )
    monkeypatch.setattr(kali_katana, "emit_result", lambda _result: None)

    def run(**over):
        kali_katana.run(_katana_args(tmp_path, **over))
        return captured[-1]

    return run


def test_the_katana_verb_fences_its_crawl_to_scope_json_by_default(katana_run) -> None:
    argv = katana_run()

    assert _value(argv, "-fs") == "fqdn"
    assert not _follows(argv, "https://app.example.com/", "https://cdn.example.com/x.js")
    assert _follows(argv, "https://app.example.com/", "https://app.example.com/a")


def test_an_explicit_field_scope_keeps_the_scope_json_crawl_regex(katana_run) -> None:
    argv = katana_run(field_scope="rdn")

    assert _value(argv, "-fs") == "rdn"
    assert not _follows(argv, "https://app.example.com/", "https://cdn.example.com/x.js")


def test_passthrough_scope_flags_replace_the_fence_with_a_warning(katana_run, capsys) -> None:
    argv = katana_run(extra_args="-fs rdn")

    assert "-cs" not in argv
    assert argv.count("-fs") == 1
    assert "own the crawl boundary" in capsys.readouterr().err


@pytest.mark.parametrize("network, inside, outside", [
    ("203.0.113.0/24", ["203.0.113.7", "203.0.113.255"], ["203.0.114.7", "203.0.11.7"]),
    ("198.51.100.64/26", ["198.51.100.64", "198.51.100.127"], ["198.51.100.63", "198.51.100.128"]),
    ("192.0.2.9/32", ["192.0.2.9"], ["192.0.2.90", "192.0.2.8"]),
    ("10.0.0.0/8", ["10.200.3.4"], ["11.0.0.1", "110.0.0.1"]),
])
def test_an_ipv4_out_of_scope_network_is_excluded_from_the_crawl(network, inside, outside) -> None:
    argv = _fence(["*.example.com"], out_of_scope=[network], seeds=["app.example.com"])
    out_scope = _value(argv, "-cos")

    assert out_scope is not None
    for address in inside:
        assert re.search(out_scope, f"https://{address}/admin"), address
    for address in outside:
        assert not re.search(out_scope, f"https://{address}:8443/"), address


def test_an_ipv6_out_of_scope_network_is_named_because_the_fence_cannot_express_it() -> None:
    fence = scope_lib.crawl_fence(
        {"hosts": ["app.example.com"], "out_of_scope": ["2001:db8::/32"]}
    )

    assert any("2001:db8::/32" in warning for warning in fence.warnings)


def test_a_caller_field_scope_is_not_described_as_one_host_per_seed() -> None:
    fence = scope_lib.crawl_fence({"hosts": ["10.0.0.0/24"]}, field_scope="rdn")

    (warning,) = [w for w in fence.warnings if "no crawlable host" in w]
    assert "each seed stays on its own host" not in warning
    assert "rdn" in warning
