"""Transition gates that steer rather than refuse, and terminal gates that name their blockers.

An empty-state edge (no services, an empty work buffer, no active findings) and
the cross-finding chain pass are advisories: they print the count and the
command that inspects it, and the phase advances. The terminal `complete` edge
names every report-readiness blocker instead of a bare ``report_not_ready``, and
a walk across `report` and `complete` runs each terminal check once.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from assess.commands import transition_phase


def _confirmed_high(slug: str, finding_id: int) -> dict:
    return {
        "id": finding_id, "slug": slug, "severity": "high",
        "verification_status": "confirmed", "workflow_status": "active",
    }


def _wire(monkeypatch, tmp_path, *, current_phase, services=(), work_items=(),
          findings=(), readiness=None, chains=(), chain_links=(), dispatches=(),
          stage_audits=None):
    (tmp_path / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": current_phase}),
        encoding="utf-8",
    )
    requested: list[str] = []
    recorded: list[dict] = []

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_e):
            return False

        def get_all_pages(self, endpoint, **_k):
            requested.append(endpoint)
            if endpoint.startswith("work-items"):
                return list(work_items)
            raise AssertionError(f"unexpected paged read {endpoint}")

        def get(self, path):
            requested.append(path)
            if path == "services":
                return list(services)
            if path.startswith("phase-readiness?phase="):
                phase = path.split("=", 1)[1]
                return {"stage_audit": (stage_audits or {}).get(
                    phase, {"applicable": True, "phase": phase, "expected_stages": [],
                            "gaps": [], "open_gap_count": 0})}
            if path == "findings?view=list":
                return list(findings)
            if path == "report-readiness":
                return {
                    "report_qc": {"required": False, "status": "missing", "issue": ""},
                    **(readiness or {"ready": True, "blockers": [], "advisories": []}),
                }
            if path == "application-units/terminal-block":
                return {"skipped": False, "blocking": [], "warned_under_observed": [],
                        "deferred": [], "deferral_count": 0}
            if path == "attack-chains":
                return list(chains)
            if path == "attack-chain-links":
                return list(chain_links)
            if path.startswith("dispatches"):
                return list(dispatches)
            if path.startswith("dispatch-decisions") or path.startswith("artifacts/search"):
                return []
            raise AssertionError(f"unexpected read {path}")

        def record_decision(self, payload):
            recorded.append(payload)
            return {"id": len(recorded)}

    monkeypatch.setattr(transition_phase, "AssessmentClient", _Client)
    monkeypatch.setattr(transition_phase, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_dir=str(tmp_path),
        engagement_key="eng", agent_root=str(tmp_path)))
    return requested, recorded


def _run(tmp_path, target, **overrides):
    args = dict(engagement_dir=str(tmp_path), target_phase=target, force=False,
                reason="", track="auto")
    args.update(overrides)
    transition_phase.run(SimpleNamespace(**args))


def _phase(tmp_path) -> str:
    return json.loads((tmp_path / "scope.json").read_text())["current_phase"]


def test_collect_with_no_services_advances_and_names_the_inspect_command(
    monkeypatch, tmp_path, capsys
):
    _wire(monkeypatch, tmp_path, current_phase="recon", services=[])

    _run(tmp_path, "collect")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "collect"
    assert "[no_services]" in err
    assert "0 live services" in err
    assert "vigil assess check-phase-readiness --phase recon --by-host" in err


def test_consume_test_with_an_empty_buffer_advances_and_names_the_inspect_command(
    monkeypatch, tmp_path, capsys
):
    _wire(monkeypatch, tmp_path, current_phase="collect", work_items=[])

    _run(tmp_path, "consume-test")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "consume-test"
    assert "[empty_work_buffer]" in err
    assert "0 pending work items" in err
    assert "vigil assess work-buffer stats" in err


def test_leaving_recon_prints_open_stage_gaps_with_the_resolving_commands(
    monkeypatch, tmp_path, capsys
):
    audit = {
        "applicable": True, "phase": "recon",
        "expected_stages": ["subdomain_enum", "http_liveness", "crawl"],
        "gaps": [
            {"stage": "subdomain_enum", "label": "Subdomain enumeration",
             "disposition": "timed_out", "command_run_ids": [3, 4]},
            {"stage": "crawl", "label": "Crawl", "disposition": "never_ran",
             "command_run_ids": []},
        ],
        "open_gap_count": 2,
    }
    requested, _ = _wire(monkeypatch, tmp_path, current_phase="recon",
                         services=[{"id": 1}], stage_audits={"recon": audit})

    _run(tmp_path, "collect")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "collect"
    assert "phase-readiness?phase=recon" in requested
    assert "[open_stage_gaps]" in err
    assert "2 open stage gap(s)" in err
    assert "subdomain_enum (Subdomain enumeration): timed_out [run(s) #3, #4]" in err
    assert "crawl (Crawl): never ran" in err
    assert "--kind coverage_deferral" in err
    assert "vigil assess check-phase-readiness --phase recon" in err


def test_a_clean_stage_audit_adds_no_transition_advisory(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, current_phase="collect", work_items=[{"id": 1}])

    _run(tmp_path, "consume-test")

    assert _phase(tmp_path) == "consume-test"
    assert "open_stage_gaps" not in capsys.readouterr().err


def test_verify_with_no_active_findings_advances_and_counts_what_is_recorded(
    monkeypatch, tmp_path, capsys
):
    _wire(
        monkeypatch, tmp_path, current_phase="consume-test",
        findings=[
            {"slug": "VA-001", "workflow_status": "draft", "severity": "low"},
            {"slug": "VA-002", "workflow_status": "draft", "severity": "medium"},
        ],
    )

    _run(tmp_path, "verify")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "verify"
    assert "[no_active_findings]" in err
    assert "0 active findings" in err
    assert "2 recorded" in err and "draft=2" in err
    assert "vigil assess finding list" in err


def test_chain_pass_is_an_advisory_naming_the_unchained_findings(
    monkeypatch, tmp_path, capsys
):
    findings = [
        _confirmed_high("VA-010", 10),
        _confirmed_high("VA-011", 11),
        _confirmed_high("VA-012", 12),
    ]
    _wire(
        monkeypatch, tmp_path, current_phase="exploit", findings=findings,
        chains=[{"id": 1, "chain_key": "chain-a"}],
        chain_links=[
            {"id": 1, "chain_id": 1, "relation": "step", "entity_kind": "finding",
             "entity_ref": "VA-010"},
            {"id": 2, "chain_id": 1, "relation": "step", "entity_kind": "finding",
             "entity_id": 11, "entity_ref": ""},
        ],
    )

    _run(tmp_path, "report")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "report"
    assert "[chain_construction_unchained]" in err
    assert "VA-012" in err
    assert "VA-010" not in err.split("[chain_construction_unchained]", 1)[1].splitlines()[0]
    assert "vigil assess chain list" in err
    assert "0 completed exploit-developer dispatch" in err


def test_chain_pass_advisory_is_silent_when_every_confirmed_high_is_chained(
    monkeypatch, tmp_path, capsys
):
    findings = [_confirmed_high("VA-020", 20), _confirmed_high("VA-021", 21)]
    _wire(
        monkeypatch, tmp_path, current_phase="exploit", findings=findings,
        chains=[{"id": 1, "chain_key": "chain-b"}],
        chain_links=[
            {"id": 1, "chain_id": 1, "relation": "step", "entity_kind": "finding",
             "entity_ref": "VA-020"},
            {"id": 2, "chain_id": 1, "relation": "step", "entity_kind": "finding",
             "entity_ref": "VA-021"},
        ],
    )

    _run(tmp_path, "report")

    assert "chain_construction" not in capsys.readouterr().err
    assert _phase(tmp_path) == "report"


def test_complete_names_each_report_readiness_blocker(monkeypatch, tmp_path, capsys):
    readiness = {
        "ready": False,
        "blockers": [
            {"kind": "finding_field_quality", "slug": "VA-030",
             "detail": "missing structured fields: impact"},
            {"kind": "duplicate_root_cause", "slugs": ["VA-031", "VA-032"],
             "detail": "root_cause_key=acme-authz"},
        ],
        "advisories": [],
    }
    _wire(monkeypatch, tmp_path, current_phase="report", readiness=readiness)

    try:
        _run(tmp_path, "complete")
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("complete advanced past readiness blockers")

    err = capsys.readouterr().err
    assert "[finding_field_quality]" in err and "VA-030" in err
    assert "missing structured fields: impact" in err
    assert "[duplicate_root_cause]" in err and "VA-031" in err
    assert "report_not_ready" not in err
    assert _phase(tmp_path) == "report"


def test_complete_prints_readiness_advisories_grouped_by_kind(monkeypatch, tmp_path, capsys):
    readiness = {
        "ready": True,
        "blockers": [],
        "advisories": [
            {"kind": "severity_cvss_mismatch", "slug": f"VA-04{i}",
             "detail": f"severity=high but cvss_score=5.{i} expects medium"}
            for i in range(5)
        ],
    }
    _wire(monkeypatch, tmp_path, current_phase="report", readiness=readiness)

    _run(tmp_path, "complete")

    err = capsys.readouterr().err
    assert _phase(tmp_path) == "complete"
    line = next(row for row in err.splitlines() if "[severity_cvss_mismatch]" in row)
    assert "5 report-readiness advisory item(s)" in line
    assert "VA-040" in line and "VA-042" in line
    assert "+2 more" in line
    assert "vigil assess check-phase-readiness --phase report" in line


def test_walk_across_report_and_complete_runs_each_terminal_check_once(
    monkeypatch, tmp_path, capsys
):
    readiness = {
        "ready": False,
        "blockers": [{"kind": "finding_field_quality", "slug": "VA-050",
                      "detail": "missing structured fields: evidence"}],
        "advisories": [],
    }
    requested, _ = _wire(
        monkeypatch, tmp_path, current_phase="exploit", readiness=readiness,
        findings=[_confirmed_high("VA-051", 51), _confirmed_high("VA-052", 52)],
    )

    try:
        _run(tmp_path, "complete")
    except SystemExit:
        pass

    err = capsys.readouterr().err
    assert requested.count("report-readiness") == 1
    assert requested.count("application-units/terminal-block") == 1
    assert requested.count("attack-chain-links") == 1
    assert err.count("[finding_field_quality]") == 1
    assert err.count("[chain_construction_unchained]") == 1



class _CodeReadinessClient:
    def __init__(self, readiness: dict) -> None:
        self.readiness = readiness

    def get(self, path):
        assert path == f"code/readiness?target_phase={self.readiness['target_phase']}"
        return self.readiness


def test_code_transition_prints_the_readiness_advisories_it_receives():
    readiness = {
        "target_phase": "verify-variant",
        "transition_ready": True,
        "blockers": [],
        "quality_gate": {"passed": True, "warnings": []},
        "depth_advisories": [
            {"file_path": f"src/acme/handler_{i}.py", "classification": "high",
             "passes": 1, "signal_passes": 1, "findings": 0}
            for i in range(4)
        ],
    }

    items = transition_phase._check_code_preconditions(
        "verify-variant", _CodeReadinessClient(readiness)
    )

    by_kind = {item["kind"]: item for item in items}
    assert all(item["severity"] == "advisory" for item in items)
    depth = by_kind["code_depth_advisory"]["detail"]
    assert "4 critical/high file(s)" in depth and "src/acme/handler_0.py" in depth
    assert "+1 more" in depth and "vigil assess code-coverage" in depth


_UNRECORDED_TAGS = {
    "count": 12, "by_classification": {"critical": 2, "medium": 10},
    "sample_paths": [f"src/acme/{i}.py" for i in range(10)], "omitted": 2,
    "full_list": "vigil assess fetch 'code/files?context_tags_recorded=false&limit=10000'",
    "paging": "while has_more is true, read the next page with offset",
    "fix": "re-classify each file with its context_tags",
}


def test_code_transition_names_files_whose_context_tags_are_unrecorded():
    readiness = {
        "target_phase": "verify-variant", "transition_ready": True, "blockers": [],
        "quality_gate": {"passed": True, "warnings": []},
        "context_tags_unrecorded": _UNRECORDED_TAGS,
    }

    items = transition_phase._check_code_preconditions(
        "verify-variant", _CodeReadinessClient(readiness)
    )

    (item,) = [item for item in items if item["kind"] == "code_context_tags_unrecorded"]
    assert item["severity"] == "advisory"
    assert "12 classified file(s)" in item["detail"] and "src/acme/0.py" in item["detail"]
    assert "+9 more" in item["detail"]
    assert "context_tags_recorded=false" in item["detail"]
    assert "while has_more is true" in item["detail"]


def _code_items(**extra):
    readiness = {
        "target_phase": "verify-variant", "transition_ready": not extra.get("blockers"),
        "blockers": [], "quality_gate": {"passed": True, "warnings": []}, **extra,
    }
    return transition_phase._check_code_preconditions("verify-variant", _CodeReadinessClient(readiness))


def test_code_transition_names_optional_families_bundle_conflicts_and_exclusions():
    items = _code_items(
        optional_families={
            "files": 5, "by_family": {"ssrf": 5, "xxe": 4},
            "sample_paths": [f"web/acme-{i}.min.js" for i in range(3)], "omitted": 2,
            "detail": "server-only families a client-bundle tag makes optional",
            "full_list": "vigil assess fetch 'code/files?context_tag=client-bundle&limit=10000'",
        },
        client_bundle_conflicts={
            "count": 4, "sample": [{"file_path": "web/acme-server.js", "signals": ["tag server-route"]}],
            "omitted": 3, "full_list": "vigil assess fetch 'code/files?client_bundle_conflict=true'",
            "fix": "re-classify it without the tag",
        },
        family_exclusions={
            "families": [{"family": "algorithmic-dos", "decision_id": 7, "ruling": "Acme rule 7",
                          "recorded_at": "2026-11-15T00:00:00Z"}],
            "depth_floor_triggers_ruled_out": 2,
            "invalid_decisions": [{"decision_id": 9, "problems": ["ruling must quote the ruling"]}],
            "detail": "review families a current vuln_family_exclusion decision puts out of bounds",
        },
    )
    by_kind = {item["kind"]: item for item in items}
    optional = by_kind["code_optional_families"]
    assert optional["severity"] == "advisory" and optional["overrideable"] is True
    assert "web/acme-0.min.js" in optional["detail"] and "+2 more" in optional["detail"]
    assert "ssrf 5" in optional["detail"] and "context_tag=client-bundle" in optional["detail"]
    conflicts = by_kind["code_client_bundle_conflicts"]
    assert "web/acme-server.js" in conflicts["detail"] and "+3 more" in conflicts["detail"]
    assert "client_bundle_conflict=true" in conflicts["detail"] and "re-classify" in conflicts["detail"]
    exclusions = by_kind["code_family_exclusions"]
    assert "algorithmic-dos" in exclusions["detail"] and "decision 7" in exclusions["detail"]
    assert "Acme rule 7" in exclusions["detail"]
    assert "decision 9 excludes nothing" in exclusions["detail"]


def test_a_file_counting_blocker_names_its_sample_paths_and_full_list():
    items = _code_items(blockers=[{
        "code": "files_unclassified", "message": "12 admitted files are unclassified.",
        "overrideable": False, "sample_paths": [f"src/acme/{i}.py" for i in range(10)], "omitted": 2,
        "full_list": "vigil assess fetch 'code/files?accounting=unclassified&repo_id=1&limit=10000'",
    }])
    (blocker,) = [item for item in items if item["kind"] == "files_unclassified"]
    assert blocker["severity"] == "block"
    assert "src/acme/0.py" in blocker["detail"] and "src/acme/3.py" not in blocker["detail"]
    assert "+9 more" in blocker["detail"]
    assert "accounting=unclassified" in blocker["detail"]
