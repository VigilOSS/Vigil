"""Per-host recon objectives name the record that closes them.

An unmet objective in ``check-phase-readiness --by-host`` must say which durable
row satisfies it, so an agent never has to read Vigil's source to learn it. The
WAF flag the coverage ledger raises follows the measured ``waf_detected`` value,
so a host measured with no WAF is not routed to a browser reprobe.
"""
from __future__ import annotations

import importlib

from assess.lib import coverage_checks as cc


def _backend_coverage_readiness():
    # The state_manager package re-exports a ``coverage_readiness`` function
    # that shadows the module of the same name on attribute import.
    return importlib.import_module("app.services.state_manager.coverage_readiness")


def _row(host: str, waf_cell: dict) -> dict:
    empty = {"met": False, "evidence": [], "deferred": False}
    return {
        "host": host,
        "outcomes": {
            "waf_tier": waf_cell,
            "service_inventory": dict(empty),
            "directory_fuzz": dict(empty),
            "tech_fingerprint": dict(empty),
            "osint": dict(empty),
        },
        "unmet_objectives": [],
        "deferred_objectives": [],
        "deferrals": [],
    }


def test_every_unmet_objective_names_the_record_that_closes_it():
    section = cc.annotate_by_host_payload({
        "objectives": list(cc._PER_HOST_OBJECTIVES),
        "hosts": [_row("api.example.com", {"met": False, "evidence": [], "deferred": False})],
    })
    lines = cc.per_host_warning_lines(section)
    by_objective = {
        objective: next(line for line in lines if f"objective {objective} " in line)
        for objective in cc._PER_HOST_OBJECTIVES
    }
    for objective, line in by_objective.items():
        assert "closed by" in line, line
        assert "coverage_deferral" in line, line
    waf = by_objective["waf_tier"]
    assert "provenance.waf" in waf
    assert "none_detected" in waf
    assert '"hosts": ["api.example.com"]' in waf
    assert "vigil assess contract intel record tech-component" in waf


def test_by_host_section_keeps_the_waf_presence_flag():
    section = cc.annotate_by_host_payload({
        "objectives": list(cc._PER_HOST_OBJECTIVES),
        "hosts": [_row(
            "api.example.com",
            {"met": True, "evidence": ["none_detected"], "deferred": False, "waf_detected": False},
        )],
    })
    cell = section["hosts"][0]["outcomes"]["waf_tier"]
    assert cell["met"] is True
    assert cell["waf_detected"] is False


def test_ledger_waf_flag_follows_measured_presence_not_objective_closure():
    measured_absent = _row(
        "origin.example.com",
        {"met": True, "evidence": ["none_detected"], "deferred": False, "waf_detected": False},
    )
    fronted = _row(
        "www.example.com",
        {"met": True, "evidence": ["Cloudflare"], "deferred": False, "waf_detected": True},
    )
    assert cc._host_waf_flag(measured_absent) is False
    assert cc._host_waf_flag(fronted) is True


def test_tech_fingerprint_hint_lists_the_sources_the_backend_counts():
    backend = _backend_coverage_readiness()

    assert set(cc._TECH_FINGERPRINT_SOURCES) == set(backend._TECH_SCAN_SOURCE_TOKENS)
    for source in cc._TECH_FINGERPRINT_SOURCES:
        assert backend._row_is_tech_scan_evidence({"source_name": source})
    section = cc.annotate_by_host_payload({
        "objectives": list(cc._PER_HOST_OBJECTIVES),
        "hosts": [_row("api.example.com", {"met": False, "evidence": [], "deferred": False})],
    })
    line = next(
        line for line in cc.per_host_warning_lines(section) if "objective tech_fingerprint " in line
    )
    for source in cc._TECH_FINGERPRINT_SOURCES:
        assert source in line


def test_waf_hint_vendor_examples_are_vendors_the_backend_classifies():
    backend = _backend_coverage_readiness()

    assert cc._HINT_WAF_VENDOR_EXAMPLES
    for vendor in cc._HINT_WAF_VENDOR_EXAMPLES:
        assert backend._row_is_waf_classification({"component": vendor}), vendor
