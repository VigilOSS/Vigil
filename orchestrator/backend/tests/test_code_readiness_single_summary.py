"""A readiness read that carries its coverage summary computes it once."""
from __future__ import annotations

from app.services import code_analysis
from test_code_analysis_api import _classify_file, _publish_structural_callables, _seed_repo_files


def _count_computations(monkeypatch):
    summaries: list[object] = []
    gaps: list[object] = []
    real_summary = code_analysis.code_coverage_summary
    real_gaps = code_analysis.structural_review_gaps
    monkeypatch.setattr(
        code_analysis, "code_coverage_summary",
        lambda *a, **k: summaries.append(k) or real_summary(*a, **k),
    )
    monkeypatch.setattr(
        code_analysis, "structural_review_gaps",
        lambda *a, **k: gaps.append(1) or real_gaps(*a, **k),
    )
    return summaries, gaps


def _seed(client, isolate_settings, key):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    for row in files:
        _classify_file(client, key, int(row["id"]), "high", 60)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code"


def test_readiness_with_coverage_is_one_summary_computation(client, isolate_settings, monkeypatch):
    key = "2026-11-13-acme-single-summary"
    base = _seed(client, isolate_settings, key)
    expected = client.get(f"{base}/coverage").json()
    summaries, gaps = _count_computations(monkeypatch)

    response = client.get(
        f"{base}/readiness?target_phase=verify-variant&include_debt_paths=true&include_coverage=true"
    )

    assert response.status_code == 200, response.text
    assert response.json()["coverage"] == expected
    assert len(summaries) == 1 and len(gaps) == 1


def test_readiness_omits_coverage_unless_asked(client, isolate_settings):
    key = "2026-11-13-acme-readiness-no-summary"
    base = _seed(client, isolate_settings, key)
    payload = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert "coverage" not in payload


def test_service_returns_the_summary_it_gated_on(client, isolate_settings, monkeypatch):
    key = "2026-11-13-acme-service-summary"
    _seed(client, isolate_settings, key)
    engagement_id = int(client.get(f"/engagements/{key}").json()["id"])
    expected = code_analysis.code_coverage_summary(engagement_id)
    summaries, gaps = _count_computations(monkeypatch)
    payload = code_analysis.code_readiness(
        engagement_id, target_phase="verify-variant", include_coverage=True
    )
    assert payload["coverage"] == expected
    assert len(summaries) == 1 and len(gaps) == 1


def test_resume_brief_reads_the_summary_its_readiness_gated_on(
    client, isolate_settings, monkeypatch
):
    import json
    from pathlib import Path

    key = "2026-11-13-acme-resume-summary"
    base = _seed(client, isolate_settings, key)
    root = Path(client.get(f"/engagements/{key}").json()["engagement_root"])
    scope = json.loads((root / "scope.json").read_text(encoding="utf-8"))
    scope["tracks"] = {"code": {"phase": "hunt"}}
    (root / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    expected_gate = client.get(f"{base}/coverage").json()["gate"]
    summaries, gaps = _count_computations(monkeypatch)

    brief = client.get(f"/engagements/{key}/assessment/resume-brief")

    assert brief.status_code == 200, brief.text
    section = brief.json()["code_analysis"]
    assert section["next_gate"] is not None, section
    assert section["coverage_gate"]["passed"] is (expected_gate["passed"] is True)
    assert len(summaries) == 1 and len(gaps) == 1
