"""CLI render tests for `vigil assess resume-brief` — the Per-Input Coverage grid.

resume_brief.py renders the backend brief JSON to markdown. These pin the new
## Per-Input Coverage section: the empty-state no-op, host+path grouping, the
covering/non-covering verdict word, the observed_http_status wall code, the
per-cell count, the lens suffix, and the truncation hint. They also assert the
old flat "non-covering probe runs" line no longer renders under ## Attempts, and
that Per-Input Coverage renders AFTER Attempts.
"""
from __future__ import annotations

from assess.commands import resume_brief


def test_resume_hydration_reconciles_all_orphans_before_backend_read(
    monkeypatch, tmp_path, capsys
):
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(
        resume_brief,
        "load_config",
        lambda _d: type(
            "Cfg",
            (),
            {
                "base_url": "http://backend",
                "engagement_key": "eng",
                "engagement_dir": str(tmp_path),
            },
        )(),
    )

    def fake_sweep(ns):
        events.append(("sweep", ns))
        print("internal sweep output")

    class FakeClient:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint):
            events.append(("get", endpoint))
            return {"engagement": {"key": "eng"}}

    monkeypatch.setattr(resume_brief.kali_sweep_orphans, "run", fake_sweep)
    monkeypatch.setattr(resume_brief, "AssessmentClient", FakeClient)

    resume_brief.run(
        type(
            "Args",
            (),
            {
                "engagement_dir": str(tmp_path),
                "q": "",
                "finding": "",
                "agent_id": "",
                "since": "",
                "max_age_hours": None,
                "per_input_limit": None,
                "all_cells": False,
                "as_json": True,
            },
        )()
    )

    assert [name for name, _ in events] == ["sweep", "get"]
    sweep_args = events[0][1]
    assert sweep_args.scope == "all"
    assert sweep_args.max_age_seconds == 3600
    assert sweep_args.dry_run is False
    assert sweep_args.engagement_dir == str(tmp_path)
    assert "internal sweep output" not in capsys.readouterr().out


def test_resume_hydration_surfaces_bounded_orphan_attention_summary(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(
        resume_brief,
        "load_config",
        lambda _d: type(
            "Cfg",
            (),
            {
                "base_url": "http://backend",
                "engagement_key": "eng",
                "engagement_dir": str(tmp_path),
            },
        )(),
    )

    def fake_sweep(_ns):
        print("still-running id=1 lots of internal detail")
        print(
            '{"summary":{"still_running":2,"skipped":1},'
            '"jobs_summary":{"still_running":3,"skipped":0},'
            '"host_processes_summary":{"unverifiable":4,"failed":1},'
            '"scope":"all"}'
        )

    class FakeClient:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, _endpoint):
            return {"engagement": {"key": "eng"}}

    monkeypatch.setattr(resume_brief.kali_sweep_orphans, "run", fake_sweep)
    monkeypatch.setattr(resume_brief, "AssessmentClient", FakeClient)

    resume_brief.run(
        type(
            "Args",
            (),
            {
                "engagement_dir": str(tmp_path),
                "q": "",
                "finding": "",
                "agent_id": "",
                "since": "",
                "max_age_hours": None,
                "per_input_limit": None,
                "all_cells": False,
                "as_json": True,
            },
        )()
    )

    captured = capsys.readouterr()
    assert "lots of internal detail" not in captured.out
    assert "orphan reconciliation needs attention" in captured.err
    assert "command_runs:still_running=2,skipped=1" in captured.err
    assert "jobs:still_running=3" in captured.err
    assert "host_processes:unverifiable=4,failed=1" in captured.err


def test_per_input_coverage_empty_is_noop():
    lines: list = []
    resume_brief._render_per_input_coverage(lines, {})
    assert lines == []
    resume_brief._render_per_input_coverage(lines, {"cells": [], "cells_count": 0})
    assert lines == []


def test_per_input_coverage_grid_groups_and_formats():
    per_input = {
        "cells": [
            {
                "target_host": "app.example.com", "target_path": "/orders/1001",
                "attack_family": "idor", "input_slot": "path:id",
                "auth_context": "member", "count": 2, "covering": True,
                "latest_status": "tested", "observed_http_status": 200,
                "lens": "tenant-boundary",
            },
            {
                "target_host": "app.example.com", "target_path": "/orders/1001",
                "attack_family": "idor", "input_slot": "path:id",
                "auth_context": "anonymous", "count": 1, "covering": False,
                "latest_status": "blocked", "observed_http_status": 403,
                "lens": "",
            },
        ],
        "cells_count": 2,
    }
    lines: list = []
    resume_brief._render_per_input_coverage(lines, per_input)
    out = "\n".join(lines)
    assert "## Per-Input Coverage" in out
    # both cells share one host+path group header (rendered once)
    assert out.count("- app.example.com/orders/1001:") == 1
    # covering cell: verdict(wall) + count + lens suffix
    assert "  - idor path:id [member] tested(200) x2 — tenant-boundary" in out
    # non-covering cell: wall code surfaced, no lens suffix
    assert "  - idor path:id [anonymous] blocked(403) x1" in out


def test_per_input_coverage_no_wall_code_omits_parens():
    per_input = {
        "cells": [{
            "target_host": "h", "target_path": "/p", "attack_family": "ssrf",
            "input_slot": "query:url", "auth_context": "member", "count": 1,
            "covering": False, "latest_status": "no-signal",
            "observed_http_status": None, "lens": "",
        }],
        "cells_count": 1,
    }
    lines: list = []
    resume_brief._render_per_input_coverage(lines, per_input)
    out = "\n".join(lines)
    assert "no-signal x1" in out
    assert "no-signal(" not in out  # None wall -> no parenthesized code


def test_per_input_coverage_marks_covered_when_latest_status_is_noncovering():
    per_input = {
        "cells": [{
            "target_host": "h", "target_path": "/p", "attack_family": "idor",
            "input_slot": "path:id", "auth_context": "member", "count": 2,
            "covering": True, "latest_status": "blocked",
            "observed_http_status": 403, "lens": "tenant-boundary",
            "evidence_ref": "traffic/probes/idor-a.txt",
        }],
        "cells_count": 1,
    }
    lines: list = []
    resume_brief._render_per_input_coverage(lines, per_input)
    out = "\n".join(lines)
    assert "covered; latest=blocked(403) x2" in out
    assert "— tenant-boundary" in out


def test_per_input_coverage_truncation_hint():
    cells = [
        {
            "target_host": f"h{i}", "target_path": "/p", "attack_family": "idor",
            "input_slot": "path:id", "auth_context": "member", "count": 1,
            "covering": False, "latest_status": "attempted",
            "observed_http_status": None, "lens": "",
        }
        for i in range(resume_brief._PER_INPUT_RENDER_LIMIT)
    ]
    per_input = {"cells": cells, "cells_count": 50}
    lines: list = []
    resume_brief._render_per_input_coverage(lines, per_input)
    out = "\n".join(lines)
    assert f"… showing {resume_brief._PER_INPUT_RENDER_LIMIT} of 50 input-cells" in out


def test_attempts_no_longer_renders_noncovering_probe_list():
    """The flat 'non-covering probe runs' sub-list was removed from ## Attempts;
    probe coverage renders only in ## Per-Input Coverage now."""
    # both sources empty -> whole section is a no-op
    lines: list = []
    resume_brief._render_attempts(lines, {
        "blocked_techniques": [], "blocked_techniques_count": 0,
        "roe_blocked_findings": [], "roe_blocked_findings_count": 0,
    })
    assert lines == []
    # with a blocked technique, the section renders but carries NO probe line
    lines = []
    resume_brief._render_attempts(lines, {
        "blocked_techniques": [{
            "id": 1, "technique": "SSRF", "retry_state": "pending",
            "target_kind": "host", "target_ref": "h", "reason": "wall", "notes": "",
        }],
        "blocked_techniques_count": 1,
        "roe_blocked_findings": [], "roe_blocked_findings_count": 0,
    })
    out = "\n".join(lines)
    assert "## Attempts" in out
    assert "non-covering probe runs" not in out


def test_finding_line_appends_blocked_reason_for_provisioning_block():
    # resume-brief _finding_summary shape: a disposition='blocked' finding is
    # active/verified, so the base line says nothing about being blocked. The
    # marker restores WHY it stalled (the block_reason).
    row = {
        "slug": "VA-047", "severity": "high",
        "workflow_status": "active", "verification_state": "verified",
        "verification_disposition": "blocked",
        "block_reason": "Needs finance-admin account and this WONT be given",
        "title": "IDOR on /orders",
    }
    line = resume_brief._finding_line(row)
    assert line.startswith("VA-047 high active/verified IDOR on /orders")
    assert "BLOCKED: Needs finance-admin account and this WONT be given" in line


def test_finding_line_no_marker_for_non_blocked_finding_with_block_reason():
    # A block_reason on a pending/none finding must NOT render as BLOCKED — the
    # marker is gated on the disposition, not the field's presence.
    row = {
        "slug": "VA-048", "severity": "medium",
        "workflow_status": "active", "verification_state": "verified",
        "verification_disposition": "pending_runtime_proof",
        "block_reason": "held pending CMS sandbox",
        "title": "held vector",
    }
    line = resume_brief._finding_line(row)
    assert "BLOCKED" not in line


def test_finding_line_no_marker_for_normal_finding():
    row = {
        "slug": "VA-001", "severity": "low",
        "workflow_status": "active", "verification_state": "verified",
        "verification_disposition": "confirmed",
        "block_reason": "",
        "title": "Reflected XSS",
    }
    line = resume_brief._finding_line(row)
    assert line == "VA-001 low active/verified Reflected XSS"
    assert "BLOCKED" not in line


def test_render_markdown_surfaces_blocked_reason_in_findings_bucket():
    # End-to-end through the markdown renderer: a blocked finding in the verified
    # bucket carries its reason so the operator never has to open the finding.
    brief = {
        "findings": {
            "verified": [{
                "slug": "VA-047", "severity": "high",
                "workflow_status": "active", "verification_state": "verified",
                "verification_disposition": "blocked",
                "block_reason": "Needs finance-admin account and this WONT be given",
                "title": "IDOR on /orders",
            }],
        },
    }
    out = resume_brief._render_markdown(brief)
    assert "BLOCKED: Needs finance-admin account and this WONT be given" in out


def test_render_markdown_orders_per_input_after_attempts():
    brief = {
        "attempts": {
            "blocked_techniques": [{
                "id": 1, "technique": "SSRF", "retry_state": "pending",
                "target_kind": "host", "target_ref": "h", "reason": "wall", "notes": "",
            }],
            "blocked_techniques_count": 1,
            "roe_blocked_findings": [], "roe_blocked_findings_count": 0,
        },
        "per_input_coverage": {
            "cells": [{
                "target_host": "h", "target_path": "/p", "attack_family": "idor",
                "input_slot": "path:id", "auth_context": "member", "count": 1,
                "covering": True, "latest_status": "tested",
                "observed_http_status": 200, "lens": "",
            }],
            "cells_count": 1,
        },
    }
    out = resume_brief._render_markdown(brief)
    assert "## Attempts" in out and "## Per-Input Coverage" in out
    assert out.index("## Attempts") < out.index("## Per-Input Coverage")
