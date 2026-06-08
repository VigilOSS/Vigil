"""Tests for Wave 6d — the consolidated phase-readiness assembly.

Covers ``state_manager.phase_readiness`` plus the
``GET /engagements/{key}/assessment/phase-readiness?phase=…`` endpoint. The
module's central contract is that it ASSEMBLES per-phase results by CALLING the
existing, unchanged gates (``coverage_readiness`` / ``per_host_coverage`` /
``report_readiness`` / ``depth_ledger`` / intel readiness) — those function
names and their routes stay stable. These tests assert the per-phase
composition and the stable-name invariant.
"""
from __future__ import annotations

import pytest

import importlib

from app.services import state_manager
from tests.test_engagements_api import write_engagement

pr_mod = importlib.import_module("app.services.state_manager.phase_readiness")


ENGAGEMENT_KEY = "2026-05-17-100000-phaserdy"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def test_stable_function_names_unchanged():
    """The four behind-the-front-door functions keep their names (safety invariant)."""
    for name in ("coverage_readiness", "report_readiness", "per_host_coverage", "depth_ledger"):
        assert hasattr(state_manager, name), name
        assert callable(getattr(state_manager, name)), name


def test_phases_vocabulary():
    assert pr_mod.PHASES == ("recon", "collect", "consume", "verify", "exploit", "report")
    assert pr_mod.PHASE_REQUIRE_STAGE["recon"] == "enum"
    assert pr_mod.PHASE_REQUIRE_STAGE["collect"] == "collection"
    assert pr_mod.PHASE_REQUIRE_STAGE["consume"] == "consumption"
    assert pr_mod.PHASE_REQUIRE_STAGE["verify"] is None


def test_normalize_phase_accepts_consume_test_alias():
    assert pr_mod._normalize_phase("consume-test") == "consume"
    assert pr_mod._normalize_phase("CONSUME") == "consume"
    with pytest.raises(ValueError):
        pr_mod._normalize_phase("bogus")


@pytest.mark.parametrize(
    "phase,expect_keys",
    [
        ("recon", {"coverage", "per_host_coverage", "intel"}),
        ("collect", {"coverage", "per_host_coverage"}),
        ("consume", {"coverage", "per_host_coverage", "depth_ledger", "intel"}),
        ("verify", {"coverage", "depth_ledger"}),
        ("exploit", {"coverage"}),
        ("report", {"report_readiness", "intel"}),
    ],
)
def test_phase_composition(client, isolate_settings, phase, expect_keys):
    """Each phase assembles exactly the gates depth-gate §6 specifies."""
    eng_id = _seed(client, isolate_settings)
    payload = state_manager.phase_readiness(eng_id, phase)
    assert payload["phase"] == phase
    assert "ready" in payload
    assert "require_stage" in payload
    for key in expect_keys:
        assert key in payload, f"{phase} should compose {key}; got {sorted(payload)}"


def test_collect_phase_omits_depth_and_intel(client, isolate_settings):
    eng_id = _seed(client, isolate_settings)
    payload = state_manager.phase_readiness(eng_id, "collect")
    assert "depth_ledger" not in payload
    assert "intel" not in payload


def test_endpoint_serves_phase_readiness(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "consume"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["phase"] == "consume"
    assert "coverage" in body and "depth_ledger" in body and "intel" in body


def test_endpoint_unknown_phase_is_422(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "bogus"})
    assert resp.status_code == 422, resp.text


def test_endpoint_consume_test_alias(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "consume-test"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["phase"] == "consume"


def test_stable_routes_still_present(client, isolate_settings):
    """The old readiness routes remain reachable (safety invariant — KEEP)."""
    _seed(client, isolate_settings)
    for route in ("coverage-readiness", "report-readiness", "coverage-readiness/by-host"):
        resp = client.get(f"{ASSESSMENT_BASE}/{route}")
        assert resp.status_code == 200, f"{route}: {resp.text}"


def _load_cpr_module():
    """Load the check-phase-readiness CLI command module (lives in the agent tree)."""
    import sys
    from pathlib import Path
    scripts_root = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    return importlib.import_module("assess.commands.check_phase_readiness")


def test_report_phase_json_ready_reflects_strict_intel_failure():
    """`--phase report --strict` with report-readiness OK but open intel
    must exit nonzero AND set JSON `ready=false` (matching the non-report phases),
    so automation consuming `--json` never treats a strict failure as ready."""
    from types import SimpleNamespace
    mod = _load_cpr_module()

    class _Client:
        def get_engagement(self, *_a, **_k):
            raise AssertionError("intel provided in backend; the fallback must not fire")

    args = SimpleNamespace(strict=True)
    backend = {
        "report_readiness": {"ready": True, "blockers": [], "advisories": []},
        "intel": {"applicable": True, "open_leads": [{"id": 1, "lead_status": "open"}]},
    }
    proj: dict = {}
    exit_nonzero = mod._run_report_phase(_Client(), args, backend, proj, [])
    assert exit_nonzero is True
    assert proj["ready"] is False, "JSON ready must reflect the strict exit verdict"

    proj2: dict = {}
    backend2 = {"report_readiness": {"ready": True}, "intel": {"applicable": True}}
    e2 = mod._run_report_phase(_Client(), args, backend2, proj2, [])
    assert e2 is False
    assert proj2["ready"] is True


def test_cli_phase_choices_accept_consume_test_alias():
    """The persisted web phase is 'consume-test'; the CLI must accept it via
    argparse choices and normalize it to 'consume', else `check-phase-readiness
    --phase "$current_phase"` fails with usage exit 2 during the consume phase."""
    import argparse

    mod = _load_cpr_module()
    assert "consume-test" in mod._CLI_PHASE_CHOICES
    assert mod._PHASE_ALIASES["consume-test"] == "consume"
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    mod.register(sub)
    ns = parser.parse_args(["check-phase-readiness", "--phase", "consume-test"])
    assert ns.phase == "consume-test"
