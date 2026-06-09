"""Regression tests for ``agent/scripts/assess/lib/scope.py`` admission rules.

Wave 1 (unchoke the hot path) fixes three silent-drop bugs in scope parsing.
The doctrine is "no silent drops": a scope entry the operator authored must
either be admitted or WARN — never vanish. Each test below feeds an input that
was *previously dropped* and asserts it is now admitted (or warned), per the
master plan's "verify a choke fix is real" guidance.

Loaded in-process via importlib so the suite stays hermetic (no FastAPI).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_scope_module():
    scripts_root = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = scripts_root / "assess" / "lib" / "scope.py"
    spec = importlib.util.spec_from_file_location("test_scope_lib_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scope = _load_scope_module()




def test_cidr_entry_is_classified_as_network_not_single_host():
    entry = scope.classify_scope_entry("10.0.0.0/24")
    assert entry is not None
    assert entry["entry_kind"] == "cidr"
    assert entry["host"] == "10.0.0.0/24"


def test_cidr_entry_admits_every_address_in_range():
    entries = scope.scope_entries({"hosts": ["10.0.0.0/24"]})
    assert scope.host_in_scope("10.0.0.1", entries)
    assert scope.host_in_scope("10.0.0.200", entries)
    assert scope.host_in_scope("10.0.0.255", entries)
    assert not scope.host_in_scope("10.0.1.1", entries)
    assert not scope.host_in_scope("evil.example.com", entries)


def test_ipv6_cidr_entry_admits_in_range_addresses():
    entries = scope.scope_entries({"hosts": ["2001:db8::/32"]})
    assert scope.host_in_scope("2001:db8::1", entries)
    assert not scope.host_in_scope("2001:dead::1", entries)


def test_bare_ip_without_slash_is_still_a_plain_host():
    entry = scope.classify_scope_entry("10.0.0.5")
    assert entry is not None
    assert entry["entry_kind"] == "bare_host"
    assert entry["host"] == "10.0.0.5"




def test_single_label_host_is_admitted_from_scope_entry():
    entry = scope.classify_scope_entry("intranet")
    assert entry is not None
    assert entry["entry_kind"] == "bare_host"
    assert entry["host"] == "intranet"


def test_single_label_host_with_port_is_admitted():
    entry = scope.classify_scope_entry("intranet:8080")
    assert entry is not None
    assert entry["host"] == "intranet"


def test_single_label_host_matches_itself():
    entries = scope.scope_entries({"hosts": ["intranet"]})
    assert scope.host_in_scope("intranet", entries)
    assert not scope.host_in_scope("other", entries)


def test_free_text_token_parsing_still_rejects_bare_single_label():
    assert scope.host_from_token("intranet") == ""
    assert scope.host_from_token("intranet", allow_single_label=True) == "intranet"




def test_path_bearing_url_entry_warns_and_admits_host(capsys):
    scope._warned_scope_keys.clear()
    entry = scope.classify_scope_entry("https://app.example.com/admin")
    assert entry is not None
    assert entry["entry_kind"] == "url"
    assert entry["host"] == "app.example.com"
    err = capsys.readouterr().err
    assert "app.example.com" in err
    assert "path" in err.lower()


def test_pathless_url_entry_does_not_warn(capsys):
    scope._warned_scope_keys.clear()
    entry = scope.classify_scope_entry("https://app.example.com/")
    assert entry is not None
    assert entry["entry_kind"] == "url"
    assert capsys.readouterr().err == ""
