"""Tests for the consolidated phase-readiness assembly.

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
    assert pr_mod.PHASES == (
        "recon", "collect", "consume-test", "verify", "exploit", "report",
    )
    assert pr_mod.PHASE_REQUIRE_STAGE["recon"] == "enum"
    assert pr_mod.PHASE_REQUIRE_STAGE["collect"] == "collection"
    assert pr_mod.PHASE_REQUIRE_STAGE["consume-test"] == "consumption"
    assert pr_mod.PHASE_REQUIRE_STAGE["verify"] is None


def test_normalize_phase_resolves_the_short_consume_alias():
    """The canonical spelling is the persisted ``consume-test``; the short
    ``consume`` form is accepted on input and resolved here so it never reaches
    the assembly's branching."""
    assert pr_mod._normalize_phase("consume") == "consume-test"
    assert pr_mod._normalize_phase("consume_test") == "consume-test"
    assert pr_mod._normalize_phase("CONSUME-TEST") == "consume-test"
    with pytest.raises(ValueError):
        pr_mod._normalize_phase("bogus")


@pytest.mark.parametrize(
    "phase,expect_keys",
    [
        ("recon", {"coverage", "per_host_coverage", "intel"}),
        ("collect", {"coverage", "per_host_coverage"}),
        ("consume-test", {"coverage", "per_host_coverage", "depth_ledger", "intel"}),
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
    assert payload["track"] == "web"
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
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "consume-test"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["phase"] == "consume-test"
    assert body["engagement_key"] == ENGAGEMENT_KEY
    assert "coverage" in body and "depth_ledger" in body and "intel" in body


def test_endpoint_unknown_phase_is_422(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "bogus"})
    assert resp.status_code == 422, resp.text


def test_endpoint_short_consume_alias_resolves_to_the_canonical_phase(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"{ASSESSMENT_BASE}/phase-readiness", params={"phase": "consume"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["phase"] == "consume-test"


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

        def get(self, endpoint: str):
            # report is a depth phase (ADR 0012): the report gate previews the
            # depth ledger + would-block set. Both are web-only skipped here so the
            # preview is a no-op that must NOT change the strict-intel exit verdict.
            if endpoint == "application-units/depth-ledger":
                return {"skipped": True, "units": [], "summary": {}}
            if endpoint == "application-units/terminal-block":
                return {"skipped": True, "blocking": [], "warned_under_observed": [],
                        "deferred": [], "deferral_count": 0}
            raise AssertionError(f"unexpected endpoint {endpoint}")

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


def test_cli_phase_choices_accept_the_persisted_phase_and_its_short_alias():
    """The persisted web phase is 'consume-test'; the CLI must accept it via
    argparse choices (else `check-phase-readiness --phase "$current_phase"`
    fails with usage exit 2 during that phase) AND still accept the short
    `consume` form, which resolves to the canonical spelling."""
    import argparse

    mod = _load_cpr_module()
    assert "consume-test" in mod._CLI_PHASE_CHOICES
    assert "consume" in mod._CLI_PHASE_CHOICES
    assert mod._PHASE_ALIASES["consume"] == "consume-test"
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    mod.register(sub)
    for typed in ("consume-test", "consume"):
        ns = parser.parse_args(["check-phase-readiness", "--phase", typed])
        assert ns.phase == typed
        assert mod.canonical_phase(ns.phase) == "consume-test"


# ---------------------------------------------------------------------------
# P-1 (item 2.1) — recon-pipeline stage-completion audit over the command-run
# ledger. This is the sub-check that diffs ``assessment_command_runs`` against
# a per-phase EXPECTED-STAGE checklist and flags timed_out / partial_results /
# never-ran stages. It is a SEPARATE function from per_host_coverage (which must
# never read the command-run ledger); these tests pin the gap detection.
# ---------------------------------------------------------------------------


def _seed_command_run(
    eng_id: int,
    *,
    command: str,
    status: str | None = None,
    timed_out: bool = False,
    return_code: int | None = None,
    phase: str = "recon",
) -> dict:
    """Insert a single command-run row through the service layer.

    ``tool_name`` is left as the route-collapsed ``command`` so the audit must
    derive the stage from the persisted ``tool_bin`` (e.g. ``katana``) exactly
    as production rows do — no argv hand-parsing.
    """
    return state_manager.record_command_run(
        eng_id,
        command=command,
        tool_name="command",
        agent_name="recon-specialist",
        phase=phase,
        started_at="2026-05-17T10:00:00Z",
        completed_at="2026-05-17T10:01:00Z",
        return_code=return_code,
        timed_out=timed_out,
        status=status,
    )


def _seed_clean_recon_pipeline(eng_id: int) -> None:
    """Record one cleanly-successful run for every recon EXPECTED stage."""
    for command in (
        "dnsx -l hosts.txt -resp",
        "httpx -l hosts.txt -title",
        "katana -u https://app.example.com -jc",
        "gau app.example.com",
        "trufflehog filesystem ./scans",
    ):
        _seed_command_run(eng_id, command=command, status="completed", return_code=0)


def test_stage_audit_flags_timed_out_crawl_and_never_run_historical(client, isolate_settings):
    """A recon ledger with a timed-out katana AND no gau run flags BOTH gaps.

    This is the exact false-GREEN the audit exists to catch: katana timed out
    (partial corpus) and gau never ran, yet the durable-state gate was green.
    """
    eng_id = _seed(client, isolate_settings)
    # Stages that ran cleanly so they are NOT flagged.
    _seed_command_run(eng_id, command="dnsx -l hosts.txt", status="completed", return_code=0)
    _seed_command_run(eng_id, command="httpx -l hosts.txt", status="completed", return_code=0)
    _seed_command_run(eng_id, command="trufflehog filesystem ./scans", status="completed", return_code=0)
    # katana timed out → crawl stage is a gap.
    timed = _seed_command_run(
        eng_id, command="katana -u https://app.example.com", status="timed_out", timed_out=True
    )
    # gau is NOT recorded → historical_urls stage never ran.

    audit = pr_mod.stage_completion_audit(eng_id, "recon")
    assert audit["applicable"] is True
    gaps = {g["stage"]: g for g in audit["gaps"]}
    assert set(gaps) == {"crawl", "historical_urls"}, audit
    assert gaps["crawl"]["disposition"] == "timed_out"
    assert int(timed["id"]) in gaps["crawl"]["command_run_ids"]
    assert gaps["historical_urls"]["disposition"] == "never_ran"
    assert gaps["historical_urls"]["command_run_ids"] == []
    assert audit["open_gap_count"] == 2
    assert set(audit["satisfied_stages"]) == {"subdomain_enum", "http_liveness", "secret_mining"}


def test_stage_audit_clean_ledger_has_no_gaps(client, isolate_settings):
    """When every EXPECTED recon stage ran cleanly the audit reports no gaps."""
    eng_id = _seed(client, isolate_settings)
    _seed_clean_recon_pipeline(eng_id)
    audit = pr_mod.stage_completion_audit(eng_id, "recon")
    assert audit["applicable"] is True
    assert audit["gaps"] == []
    assert audit["open_gap_count"] == 0
    assert set(audit["satisfied_stages"]) == set(pr_mod.PHASE_EXPECTED_STAGES["recon"])


def test_stage_audit_flags_partial_results(client, isolate_settings):
    """A completed-but-partial katana is a crawl gap with disposition partial_results.

    ``partial_results`` is only settable via the finalize PATCH, so the row is
    recorded (running) then finalized completed-with-partial — mirroring a real
    job that finished but truncated its output corpus.
    """
    eng_id = _seed(client, isolate_settings)
    _seed_command_run(eng_id, command="dnsx -l hosts.txt", status="completed", return_code=0)
    _seed_command_run(eng_id, command="httpx -l hosts.txt", status="completed", return_code=0)
    _seed_command_run(eng_id, command="gau app.example.com", status="completed", return_code=0)
    _seed_command_run(eng_id, command="trufflehog filesystem ./scans", status="completed", return_code=0)
    running = _seed_command_run(eng_id, command="katana -u https://app.example.com")
    finalized = state_manager.finalize_command_run(
        eng_id,
        command_run_id=int(running["id"]),
        status_value="completed",
        return_code=0,
        ended_at="2026-05-17T10:05:00Z",
        partial_results=True,
    )
    assert finalized["partial_results"] is True

    audit = pr_mod.stage_completion_audit(eng_id, "recon")
    gaps = {g["stage"]: g for g in audit["gaps"]}
    assert set(gaps) == {"crawl"}, audit
    assert gaps["crawl"]["disposition"] == "partial_results"
    assert int(running["id"]) in gaps["crawl"]["command_run_ids"]


def test_stage_audit_not_applicable_for_phase_without_expected_stages(client, isolate_settings):
    """Phases with no EXPECTED-STAGE checklist (verify) report applicable=False."""
    eng_id = _seed(client, isolate_settings)
    audit = pr_mod.stage_completion_audit(eng_id, "verify")
    assert audit["applicable"] is False
    assert audit["gaps"] == []
    assert audit["expected_stages"] == []


def test_phase_readiness_folds_stage_audit_into_recon_and_collect_only(client, isolate_settings):
    """The assembly carries ``stage_audit`` exactly on the pipeline phases."""
    eng_id = _seed(client, isolate_settings)
    for phase in ("recon", "collect"):
        payload = state_manager.phase_readiness(eng_id, phase)
        assert "stage_audit" in payload, phase
        assert payload["stage_audit"]["phase"] == phase
    for phase in ("consume-test", "verify", "exploit", "report"):
        payload = state_manager.phase_readiness(eng_id, phase)
        assert "stage_audit" not in payload, phase
