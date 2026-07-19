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

import pytest


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


# ---------------------------------------------------------------------------
# out_of_scope denylist (carve-outs under an in-scope wildcard)
# ---------------------------------------------------------------------------


def test_out_of_scope_entries_parses_bare_host_and_wildcard():
    deny = scope.out_of_scope_entries(
        {"out_of_scope": ["appointments.acme-regional.example", "*.mobile.acme-net.example"]}
    )
    kinds = {(e["scope_entry"], e["entry_kind"]) for e in deny}
    assert ("appointments.acme-regional.example", "bare_host") in kinds
    assert ("*.mobile.acme-net.example", "wildcard") in kinds


def test_host_admitted_wildcard_with_bare_host_carve_out():
    allow = scope.scope_entries({"hosts": ["*.acme-regional.example"]})
    deny = scope.out_of_scope_entries({"out_of_scope": ["appointments.acme-regional.example"]})
    # In-scope subdomain still admitted...
    assert scope.host_admitted("app.acme-regional.example", allow, deny)
    # ...but the explicit OOS carve-out is rejected even though the wildcard
    # would otherwise cover it.
    assert scope.host_in_scope("appointments.acme-regional.example", allow)
    assert not scope.host_admitted("appointments.acme-regional.example", allow, deny)


def test_host_admitted_wildcard_carve_out_rejects_subtree():
    allow = scope.scope_entries({"hosts": ["*.mobile.acme.example"]})
    deny = scope.out_of_scope_entries({"out_of_scope": ["*.mobile.acme-net.example"]})
    # OOS wildcard rejects the carved-out subtree...
    assert not scope.host_admitted("x.mobile.acme-net.example", allow, deny)
    assert not scope.host_admitted("mobile.acme-net.example", allow, deny)
    # ...while a sibling under the in-scope wildcard is still admitted.
    assert scope.host_admitted("mobile.acme.example", allow, deny)


def test_host_admitted_rejects_host_not_in_allowlist():
    allow = scope.scope_entries({"hosts": ["*.acme-regional.example"]})
    deny = scope.out_of_scope_entries({"out_of_scope": ["appointments.acme-regional.example"]})
    assert not scope.host_admitted("evil.example.com", allow, deny)


def test_host_admitted_absent_out_of_scope_matches_legacy_behavior():
    allow = scope.scope_entries({"hosts": ["*.acme-regional.example"]})
    # Absent and empty out_of_scope both yield an empty denylist, so admission
    # is identical to plain host_in_scope.
    deny_absent = scope.out_of_scope_entries({"hosts": ["*.acme-regional.example"]})
    deny_empty = scope.out_of_scope_entries({"out_of_scope": []})
    assert deny_absent == []
    assert deny_empty == []
    for deny in (deny_absent, deny_empty):
        assert scope.host_admitted("app.acme-regional.example", allow, deny)
        assert scope.host_admitted("appointments.acme-regional.example", allow, deny)
        assert not scope.host_admitted("evil.example.com", allow, deny)


def test_out_of_scope_non_list_raises_system_exit():
    with pytest.raises(SystemExit):
        scope.out_of_scope_entries({"out_of_scope": "appointments.acme-regional.example"})


def test_scope_enforcement_defaults_to_enforce_and_only_explicit_bypass_disables_it():
    assert scope.scope_enforcement({}) == "enforce"
    assert scope.scope_enforcement({"scope_enforcement": "enforce"}) == "enforce"
    assert scope.scope_enforcement({"scope_enforcement": "bypass"}) == "bypass"
    # Typos and unknown values must never become an implicit bypass.
    assert scope.scope_enforcement({"scope_enforcement": "disabled"}) == "enforce"


def test_target_admission_enforces_allow_and_deny_lists_by_default():
    scope_doc = {
        "hosts": ["*.example.test"],
        "out_of_scope": ["admin.example.test"],
    }

    admitted = scope.target_admission(scope_doc, "https://api.example.test/v1")
    carved_out = scope.target_admission(scope_doc, "admin.example.test")
    unrelated = scope.target_admission(scope_doc, "other.test")

    assert admitted["admitted"] is True
    assert admitted["scope_enforcement"] == "enforce"
    assert admitted["bypassed"] is False
    assert carved_out["admitted"] is False
    assert "out-of-scope" in carved_out["reason"]
    assert unrelated["admitted"] is False


def test_target_admission_global_bypass_allows_every_parseable_target_and_marks_verdict():
    scope_doc = {
        "hosts": ["example.test"],
        "out_of_scope": ["blocked.test"],
        "scope_enforcement": "bypass",
    }

    verdict = scope.target_admission(scope_doc, "https://blocked.test/path")

    assert verdict["admitted"] is True
    assert verdict["scope_enforcement"] == "bypass"
    assert verdict["bypassed"] is True
    assert "global scope bypass" in verdict["reason"]


def test_denied_tools_are_normalized_deduplicated_and_invalid_shapes_fail_closed():
    assert scope.denied_tools({"denied_tools": [" Nuclei ", "nuclei", "SQLMAP", 7]}) == {
        "nuclei",
        "sqlmap",
    }
    with pytest.raises(SystemExit, match="denied_tools.*list"):
        scope.denied_tools({"denied_tools": "nuclei"})


def test_denied_tools_reads_canonical_nested_tool_policy():
    assert scope.denied_tools(
        {"tool_policy": {"denied_tools": [" Nuclei ", "SQLMAP"]}}
    ) == {"nuclei", "sqlmap"}

    with pytest.raises(SystemExit, match="tool_policy.*object"):
        scope.denied_tools({"tool_policy": ["nuclei"]})


def test_aggregate_rate_limit_parses_positive_number_and_rejects_invalid_values():
    assert scope.aggregate_rate_limit({"rate_limit_aggregate_rps": 12.5}) == 12.5
    assert scope.aggregate_rate_limit({}) is None
    assert scope.aggregate_rate_limit({"rate_limit_aggregate_rps": 0}) is None
    assert scope.aggregate_rate_limit({"rate_limit_aggregate_rps": "fast"}) is None
