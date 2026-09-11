import json
import tomllib
from pathlib import Path

import pytest

from app.config import settings
from tests.proof_fixtures import post_artifact_backed_source_observation


ENGAGEMENT_KEY = "2026-06-01-090000-report-export"

# The single-file report template's data node, byte-for-byte as it appears in
# the built dist/template.html. The backend anchors injection on the closing
# </script> tag so a FAKE template here exercises the real replacement path.
_DATA_NODE = '<script id="vigil-report-data" type="application/json">"__VIGIL_REPORT_DATA__"</script>'

# A second, identical sentinel string elsewhere in the template (mirrors the JS
# constant baked into the real bundle). It MUST survive injection untouched —
# only the data node is anchored on </script>.
_FAKE_TEMPLATE = (
    "<!doctype html><html><head><title>Vigil Report</title>"
    f"{_DATA_NODE}"
    '</head><body><div id="root"></div>'
    '<script type="module">const SENTINEL="__VIGIL_REPORT_DATA__";</script>'
    "</body></html>"
)


def test_report_export_distribution_version_matches_vigil_release_version():
    backend_root = Path(__file__).resolve().parents[1]
    repository_root = Path(__file__).resolve().parents[3]
    backend_version = tomllib.loads(
        (backend_root / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    release_version = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]

    assert backend_version == release_version


@pytest.fixture
def fake_template(tmp_path, monkeypatch):
    template_path = tmp_path / "template.html"
    template_path.write_text(_FAKE_TEMPLATE, encoding="utf-8")
    original = settings.report_template_path
    object.__setattr__(settings, "report_template_path", template_path)
    try:
        yield template_path
    finally:
        object.__setattr__(settings, "report_template_path", original)


def _write_engagement(engagements_dir: Path, *, current_phase: str = "report") -> None:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://acme.example",
                "hostname": "acme.example",
                "created_at": "2026-06-01T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "acme.example",
                "scope_mode": "host_only",
                "scope_hosts": ["acme.example"],
                "scope": ["acme.example"],
                "status": "in_progress",
                "current_phase": current_phase,
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")


def _seed(client, isolate_settings, **kwargs) -> None:
    _write_engagement(isolate_settings["engagements_dir"], **kwargs)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _finding(slug: str, title: str, *, severity: str = "high") -> dict:
    return {
        "slug": slug,
        "title": title,
        "severity": severity,
        "workflow_status": "exploited",
        "verification_status": "unreviewed",
        "canonical_location": f"https://acme.example/{slug.lower()}",
        "summary": title,
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": f"SOURCE-{slug}"},
        "details": {
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "steps_to_reproduce": ["Replay the recorded request."],
            "remediation": "Enforce authorization.",
            "impact": "Unauthorized access.",
            "evidence": "Verified with a replayable request.",
        },
    }


def _add_finding(client, payload: dict) -> None:
    author_id = str(payload["provenance"]["agent_id"])
    author = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatches",
        json={
            "agent_id": author_id,
            "agent_role": "vulnerability-analyst",
            "task": f"record {payload['slug']}",
        },
    )
    assert author.status_code == 201, author.text
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/assessment/findings", json=payload)
    assert response.status_code in {200, 201}, response.text
    slug = str(payload["slug"])
    verifier_id = f"VERIFY-{slug}"
    dispatch = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatches",
        json={
            "agent_id": verifier_id,
            "agent_role": "code-vuln-verifier",
            "task": f"independently verify {slug}",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/assessment-runs",
        json={
            "run_uuid": f"report-export-{slug}",
            "run_kind": "code",
            "producer_dispatch_agent_id": verifier_id,
        },
    )
    assert run.status_code == 201, run.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"/engagements/{ENGAGEMENT_KEY}/assessment/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "the report finding survives independent review",
            "observed_result": "the report finding was independently reproduced",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    verified = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independently reproduced",
            "proof_receipt_ids": [receipt.json()["id"]],
        },
    )
    assert verified.status_code == 200, verified.text


def test_report_export_writes_injected_report_and_registers_artifact(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-001", "Missing authorization on admin API"))

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mode"] == "draft"
    assert body["artifact_id"] >= 1
    assert body["relative_path"].startswith("reports/")
    assert body["size_bytes"] > 0

    # The written file exists, contains the engagement key, and the data node
    # sentinel has been replaced (no longer present anchored to </script>).
    engagement_root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    written = engagement_root / body["relative_path"]
    assert written.is_file()
    contents = written.read_text(encoding="utf-8")
    assert ENGAGEMENT_KEY in contents
    assert '"__VIGIL_REPORT_DATA__"</script>' not in contents
    # The injected payload's engagement target made it into the data node.
    assert "https://acme.example" in contents
    assert contents.endswith("</html>")

    # The artifact is registered in the assessment artifact index with
    # kind=report (proven by a successful id-scoped download lookup).
    download = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/{body['artifact_id']}/download"
    )
    assert download.status_code == 200, download.text


def test_report_export_escapes_script_breakout_in_finding_title(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    # An attacker-influenced finding title containing a literal </script>.
    # Slug must be canonical <PREFIX>-<>=3 digits>.
    _add_finding(
        client,
        _finding("VA-013", "Broken </script><script>alert(1)</script> auth guard"),
    )

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    body = response.json()

    engagement_root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    contents = (engagement_root / body["relative_path"]).read_text(encoding="utf-8")

    # The raw </script> from the title must NOT appear inside the injected JSON
    # data node — every "<"/">" is escaped to </>. Isolate the
    # data-node slice so the genuine trailing </script>/<body> tags don't trip
    # the assertion.
    start = contents.index('id="vigil-report-data"')
    node_open_end = contents.index(">", start) + 1
    node_close = contents.index("</script>", node_open_end)
    data_node = contents[node_open_end:node_close]
    assert "</script>" not in data_node
    assert "<" not in data_node and ">" not in data_node
    assert "\\u003c/script\\u003e" in data_node


def test_report_export_escapes_html_comment_script_double_escape(
    client, isolate_settings, fake_template
):
    # The script-data-double-escape breakout: a finding title of "<!--<script>"
    # (no balancing -->) would, under a </-only escape, flip the HTML tokenizer
    # into script-data-double-escaped state and swallow the data node's own
    # closing </script> plus the rest of the document (incl. the SPA mount node
    # and bundle). Escaping every "<"/">" must neutralize it entirely.
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-014", "Stored XSS via <!--<script> comment smuggling"))

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    contents = (
        isolate_settings["engagements_dir"]
        / ENGAGEMENT_KEY
        / response.json()["relative_path"]
    ).read_text(encoding="utf-8")

    start = contents.index('id="vigil-report-data"')
    node_open_end = contents.index(">", start) + 1
    node_close = contents.index("</script>", node_open_end)
    data_node = contents[node_open_end:node_close]
    # No raw HTML-tokenizer-significant sequence survives inside the data node.
    assert "<!--" not in data_node
    assert "<script" not in data_node
    assert "<" not in data_node and ">" not in data_node
    # The markup AFTER the (correctly-closed) data node still contains the SPA
    # mount node + bundle — i.e. the document was not swallowed into the script.
    after_node = contents[node_close:]
    assert 'id="root"' in after_node


def test_report_export_same_second_exports_are_distinct_artifacts(
    client, isolate_settings, fake_template
):
    # Two exports for the same engagement+mode requested back-to-back (same UTC
    # second, e.g. an API retry or two UI sessions) must each be a distinct
    # artifact — not overwrite each other on a timestamp-only path. Otherwise
    # the first response's artifact_id/download would later serve the second
    # export's contents.
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-001", "Missing authorization on admin API"))

    first = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    second = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert first.status_code == 200 and second.status_code == 200
    a, b = first.json(), second.json()
    assert a["relative_path"] != b["relative_path"]
    assert a["artifact_id"] != b["artifact_id"]
    # Both files persist independently on disk.
    root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    assert (root / a["relative_path"]).is_file()
    assert (root / b["relative_path"]).is_file()
    # Each artifact_id downloads its own file (no cross-serving).
    for body in (a, b):
        dl = client.get(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/{body['artifact_id']}/download"
        )
        assert dl.status_code == 200, dl.text


def test_report_findings_coerce_string_steps_to_list(client, isolate_settings):
    # Agents occasionally record steps_to_reproduce as a single string (a
    # numbered multi-step block) instead of a list. The report-findings
    # projection must coerce it to a list so downstream renderers (the
    # single-file HTML report's per-finding markdown, which iterates with
    # .forEach) don't receive a raw string. Content must be preserved.
    _seed(client, isolate_settings)
    payload = _finding("VA-050", "Finding with string steps")
    payload["details"]["steps_to_reproduce"] = "1. Build with ASAN. 2. Send the crafted record. 3. Observe the crash."
    _add_finding(client, payload)

    resp = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft"
    )
    assert resp.status_code == 200, resp.text
    records = resp.json()["standalone"]
    rec = next(r for r in records if r["slug"] == "VA-050")
    assert rec["steps_to_reproduce"] == [
        "1. Build with ASAN. 2. Send the crafted record. 3. Observe the crash."
    ]


def test_report_findings_project_repro_runs_alongside_steps(client, isolate_settings):
    # The command-run ids behind the steps travel with them, coerced the same way,
    # so a report renderer can show what backs each reproduction without re-parsing
    # details_json. Integer ids stringify rather than being dropped.
    _seed(client, isolate_settings)
    payload = _finding("VA-051", "Finding with backed steps")
    payload["details"]["repro_runs"] = [56052, "56054"]
    _add_finding(client, payload)

    resp = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft"
    )
    assert resp.status_code == 200, resp.text
    rec = next(r for r in resp.json()["standalone"] if r["slug"] == "VA-051")
    assert rec["repro_runs"] == ["56052", "56054"]


def test_readiness_advises_on_steps_with_no_repro_runs(client, isolate_settings):
    """Unbacked reproduction steps advise; they never block.

    The empty-``steps_to_reproduce`` blocker already stops a finding carrying no
    reproduction at all. This one says something weaker but distinct: the steps
    exist and nothing stands behind them, so nobody can tell a transcript from a
    reconstruction. Gating on it would block every finding recorded before
    ``repro_runs`` existed, so it stays an advisory — and the engagement must still
    read as ready.
    """
    _seed(client, isolate_settings)
    # The shared ``_finding`` helper scores in the `high` band; re-band both to
    # `critical` (vector AND score together — they are validated as a pair) so
    # the only thing separating these two findings is ``repro_runs``.
    critical_cvss = {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1,
    }
    unbacked = _finding("VA-060", "Steps with nothing behind them", severity="critical")
    unbacked["details"].update(critical_cvss)
    _add_finding(client, unbacked)
    backed = _finding("VA-061", "Steps with runs behind them", severity="critical")
    backed["details"].update(critical_cvss)
    backed["details"]["repro_runs"] = [56052]
    _add_finding(client, backed)

    resp = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/report-readiness")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    advisories = [
        a for a in body["advisories"] if a.get("kind") == "finding_repro_runs_missing"
    ]
    assert [a["slug"] for a in advisories] == ["VA-060"]
    assert "repro_runs" in advisories[0]["detail"]
    # Advisory only — it appears in no blocker and does not flip readiness.
    assert not any(
        b.get("kind") == "finding_repro_runs_missing" for b in body["blockers"]
    )
    assert body["ready"] is True, body["blockers"]


def test_report_export_final_mode_blocked_when_not_ready(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    # A confirmed finding missing structured quality fields (no
    # impact/evidence/cvss_vector/steps) → report_readiness raises a
    # `finding_field_quality` blocker → not ready. (An empty engagement is
    # considered ready, so we must seed a low-quality finding to exercise the
    # gate deterministically.)
    _add_finding(
        client,
        {
            "slug": "VA-001",
            "title": "Low-quality finding",
            "severity": "high",
            "workflow_status": "exploited",
            "verification_status": "unreviewed",
            "canonical_location": "https://acme.example/va-001",
            "summary": "missing the structured fields the report gate requires",
            "evidence_ref": "findings.md",
            "source_name": "test",
            "provenance": {"agent_id": "SOURCE-VA-001"},
            "details": {},
        },
    )

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "final"}
    )
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["ready"] is False
    assert detail["blocker_count"] >= 1


def test_report_export_missing_template_returns_503(client, isolate_settings, tmp_path):
    _seed(client, isolate_settings)
    missing = tmp_path / "does-not-exist" / "template.html"
    original = settings.report_template_path
    object.__setattr__(settings, "report_template_path", missing)
    try:
        response = client.post(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
        )
    finally:
        object.__setattr__(settings, "report_template_path", original)
    assert response.status_code == 503, response.text
    assert "fix" in response.json()["detail"]


def test_report_export_download_serves_html_and_404s_for_wrong_id(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-001", "Missing authorization on admin API"))

    export = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert export.status_code == 200, export.text
    artifact_id = export.json()["artifact_id"]

    download = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/{artifact_id}/download"
    )
    assert download.status_code == 200, download.text
    assert download.headers["content-type"].startswith("text/html")
    assert "attachment" in download.headers.get("content-disposition", "")
    assert ENGAGEMENT_KEY in download.text

    # An artifact id that does not exist → 404.
    missing = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/999999/download"
    )
    assert missing.status_code == 404


def test_report_export_download_rejects_non_report_artifact(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    engagement_root = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_root / "notes").mkdir(parents=True, exist_ok=True)
    (engagement_root / "notes" / "triage.md").write_text("# notes\n", encoding="utf-8")

    # Register a non-report artifact and try to download it via the report route.
    reg = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/artifacts",
        json={"path": "notes/triage.md", "kind": "note"},
    )
    assert reg.status_code == 201, reg.text
    note_id = reg.json()["id"]

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/{note_id}/download"
    )
    assert response.status_code == 404
