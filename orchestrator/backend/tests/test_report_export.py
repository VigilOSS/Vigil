import json
import re
import tomllib
from pathlib import Path

import pytest

from app.api import report_export
from app.config import settings
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation


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


def _command_run(client, suffix: str) -> int:
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        json={
            "run_uuid": f"report-export-repro-{suffix}",
            "command": f"curl https://acme.example/{suffix}",
            "tool_name": "curl", "agent_name": "SOURCE-VA-001",
            "phase": "verify", "status": "completed", "return_code": 0,
            "started_at": "2026-09-25T12:00:00Z",
            "completed_at": "2026-09-25T12:00:01Z",
            "stdout": "observed outcome",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


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


def _record_finding(client, payload: dict) -> None:
    """Record a finding and stop there — no verification.

    An unverified finding is NOT report-durable: both report projections admit
    only ``confirmed``/``downgraded``. ``assessment_summary`` counts it anyway,
    which is exactly the disagreement the delivered summary must not inherit.
    """
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


def _verify_finding(
    client,
    slug: str,
    *,
    disposition: str = "confirmed",
    attempt: str = "",
) -> None:
    """Independently verify ``slug``, standing a real proof receipt behind it.

    ``attempt`` disambiguates a SECOND verification of the same finding: a
    material relationship change (a root-cause link) invalidates the standing
    confirmation, and re-confirming needs its own dispatch, run and receipt.
    """
    suffix = f"-{attempt}" if attempt else ""
    verifier_id = f"VERIFY-{slug}{suffix}"
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
            "run_uuid": f"report-export-{slug}{suffix}",
            "run_kind": "code",
            "producer_dispatch_agent_id": verifier_id,
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/{slug}/links",
        json={
            "link_kind": "proof_run",
            "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
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
    receipt_id = receipt.json()["id"]
    verify_payload: dict = {
        "verification_status": disposition,
        "reason_text": "independently reproduced",
        "proof_receipt_ids": [receipt_id],
    }
    if disposition in {"confirmed", "downgraded"}:
        verify_payload["confirm_check"] = completed_confirm_check(receipt_id)
    if disposition == "false_positive":
        verify_payload["reason_text"] = "the suspected path is not attacker reachable"
        # A false-positive kill is a terminal state, so the API requires the
        # verification check that settled it (1-5) and the rationale behind it —
        # not merely an assertion that the finding is wrong.
        verify_payload["details"] = {
            "kill_reason": "the shared guard rejects the crafted request on every route",
            "kill_check": 2,
        }
        verify_payload["counter_check"] = {
            "method": "independent reachability review",
            "expected_result": "an attacker-controlled path reaches the suspected sink",
            "observed_result": "no attacker-controlled path reaches the sink",
            "falsified_claim": "the suspected path is attacker reachable",
            "completed": True,
            "proof_receipt_ids": [receipt_id],
        }
    verified = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/{slug}/verify",
        json=verify_payload,
    )
    assert verified.status_code == 200, verified.text


def _add_finding(client, payload: dict) -> None:
    _record_finding(client, payload)
    _verify_finding(client, str(payload["slug"]))


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
    first, second = _command_run(client, "first"), _command_run(client, "second")
    payload["details"]["repro_runs"] = [first, str(second)]
    _add_finding(client, payload)

    resp = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft"
    )
    assert resp.status_code == 200, resp.text
    rec = next(r for r in resp.json()["standalone"] if r["slug"] == "VA-051")
    assert rec["repro_runs"] == [str(first), str(second)]


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
    backed["details"]["repro_runs"] = [_command_run(client, "readiness")]
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


def test_report_export_download_rejects_modified_artifact(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-001", "Missing authorization on admin API"))
    export = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert export.status_code == 200, export.text
    artifact = export.json()
    report_path = (
        isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / artifact["relative_path"]
    )
    original = report_path.read_bytes()
    report_path.write_bytes(b"X" + original[1:])

    download = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export/"
        f"{artifact['artifact_id']}/download"
    )

    assert download.status_code == 409
    assert b"X" + original[1:] not in download.content


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


# ── Delivered-payload projection ──────────────────────────────────────────
#
# The exported HTML is the one Vigil artifact whose reader is the CLIENT rather
# than the operator, so what the payload carries is a disclosure decision. These
# pin it: the injected JSON holds exactly the keys the report template renders,
# and nothing else travels along for the ride. Narrowing the AUDIENCE is not the
# masking ADR 0019 forbids — every field that survives ships verbatim.

# ── The renderer's own contract, parsed ───────────────────────────────────
#
# `orchestrator/report/src/types.ts` declares the payload the template renders,
# and the allow-lists in report_export.py are the backend half of that contract.
# This suite used to RESTATE those lists and assert set-equality against its own
# copy, which is not a guard: a one-word deletion moves both sides in a single
# edit and the suite stays green. `npm run build`'s `tsc --noEmit` catches drift
# in ONE direction only — a component reading a field types.ts does not declare —
# so a field the BACKEND stops sending stays invisible until a delivered report
# renders blank. No backend test read the renderer's source at all. These do.
#
# Same shape as tests/test_finding_patch_contract_mirror.py, which pins the
# hand-written `finding update` roster against its Pydantic model.

_TYPES_TS = (
    Path(__file__).resolve().parents[3] / "orchestrator" / "report" / "src" / "types.ts"
)

# `name?: type;` / `name: type;` at the start of an interface-body line. An index
# signature (`[key: string]: unknown`) starts with `[` and is deliberately not a
# field.
_INTERFACE_MEMBER = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:", re.MULTILINE)


def _declared_fields(interface: str) -> set[str]:
    """The field names one `export interface` in types.ts declares."""
    source = _TYPES_TS.read_text(encoding="utf-8")
    match = re.search(
        rf"^export interface {interface} \{{\n(.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{interface} is not declared in {_TYPES_TS}"
    body = re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.DOTALL)
    body = re.sub(r"//[^\n]*", "", body)
    fields = set(_INTERFACE_MEMBER.findall(body))
    assert fields, f"{interface} parsed to no fields — the parser has drifted"
    return fields


def test_the_types_ts_parser_still_finds_the_declarations_it_reads():
    """If types.ts moves or is restructured, say so here rather than silently.

    Every mirror assertion below is only as good as this parse; an interface
    renamed out from under it must fail loudly, not compare two empty sets.
    """
    assert _TYPES_TS.is_file(), _TYPES_TS
    assert "report_id" in _declared_fields("ReportFinding")
    assert "finding_count" in _declared_fields("ReportSummary")
    assert "narrative" in _declared_fields("ReportAttackChain")
    assert "entity_ref" in _declared_fields("ReportAttackChainLink")
    assert "blockers" in _declared_fields("ReportReadiness")


def test_finding_allow_list_mirrors_the_report_finding_contract():
    assert set(report_export._FINDING_FIELDS) == _declared_fields("ReportFinding")


def test_summary_allow_list_mirrors_the_report_summary_contract():
    # The delivered summary has two halves: keys copied verbatim out of
    # assessment_summary, and the finding rollups derived from the report's own
    # body. Together they are exactly ReportSummary, and they never overlap.
    passthrough = set(report_export._SUMMARY_FIELDS)
    derived = set(report_export._DERIVED_SUMMARY_FIELDS)
    assert passthrough.isdisjoint(derived)
    assert passthrough | derived == _declared_fields("ReportSummary")


def test_attack_chain_allow_lists_mirror_the_report_chain_contracts():
    assert set(report_export._CHAIN_FIELDS) == _declared_fields("ReportAttackChain")
    assert set(report_export._CHAIN_LINK_FIELDS) == _declared_fields(
        "ReportAttackChainLink"
    )


def test_readiness_allow_list_mirrors_the_report_readiness_contract():
    assert set(report_export._READINESS_FIELDS) == _declared_fields("ReportReadiness")


# Top-level payload keys, mirroring orchestrator/report/src/types.ts ReportData.
_PAYLOAD_KEYS = {
    "generated_at",
    "vigil_version",
    "mode",
    "engagement",
    "summary",
    "finding_groups",
    "attack_chains",
    "attack_chain_links",
    "report_readiness",
}

_SUMMARY_KEYS = _declared_fields("ReportSummary")

# ReportFinding. The root-cause keys are written onto the record by
# links.py:_root_cause_link_metadata and therefore exist on SIBLINGS ONLY — they
# are the only conditionally-present fields in the whole payload, which is why a
# fixture holding nothing but a standalone finding left them uncovered.
_FINDING_KEYS = _declared_fields("ReportFinding")
_SIBLING_ONLY_KEYS = {"root_cause_effect", "root_cause_note"}
_STANDALONE_FINDING_KEYS = _FINDING_KEYS - _SIBLING_ONLY_KEYS


def _injected_payload(isolate_settings, relative_path: str) -> dict:
    """Decode the JSON the export injected into the template's data node."""
    contents = (
        isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / relative_path
    ).read_text(encoding="utf-8")
    start = contents.index('id="vigil-report-data"')
    node_open_end = contents.index(">", start) + 1
    node_close = contents.index("</script>", node_open_end)
    return json.loads(contents[node_open_end:node_close])


def test_report_payload_carries_only_the_fields_the_template_renders(
    client, isolate_settings, fake_template
):
    _seed(client, isolate_settings)
    payload_in = _finding("VA-070", "Missing authorization on admin API")
    # Operator-internal content on three columns the template never reads. Each
    # carries a distinctive marker so its absence is provable from the bytes on
    # disk, not only from the decoded key set.
    payload_in["notes"] = "TRIAGE-NOTE-MARKER: client contact thinks this is wontfix"
    payload_in["details"]["attack_scenario"] = "DETAILS-SCRATCH-MARKER: internal pivot analysis"
    payload_in["provenance"]["tooling"] = "PROVENANCE-MARKER"
    _add_finding(client, payload_in)

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    relative_path = response.json()["relative_path"]
    payload = _injected_payload(isolate_settings, relative_path)

    assert set(payload) == _PAYLOAD_KEYS
    assert set(payload["summary"]) == _SUMMARY_KEYS
    assert set(payload["finding_groups"]) == {
        "mode",
        "groups",
        "standalone",
        "group_count",
        "standalone_count",
        "finding_count",
    }
    record = next(r for r in payload["finding_groups"]["standalone"] if r["slug"] == "VA-070")
    assert set(record) == _STANDALONE_FINDING_KEYS

    # The dropped columns are gone from the delivered bytes entirely.
    delivered = (
        isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / relative_path
    ).read_text(encoding="utf-8")
    for marker in ("TRIAGE-NOTE-MARKER", "DETAILS-SCRATCH-MARKER", "PROVENANCE-MARKER"):
        assert marker not in delivered


def test_report_findings_keep_every_column_on_the_operator_projection(
    client, isolate_settings
):
    """The narrowing is the delivery boundary's, not the projection's.

    ``list_report_finding_groups`` also backs ``GET report-findings`` and
    ``vigil assess finding report --json``, which the operator and the
    report-writer specialist read. ADR 0019 forbids withholding anything there,
    so the columns the exported HTML drops must still be on this response.
    """
    _seed(client, isolate_settings)
    payload_in = _finding("VA-071", "Missing authorization on admin API")
    payload_in["notes"] = "TRIAGE-NOTE-MARKER"
    _add_finding(client, payload_in)

    resp = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/report-findings?mode=draft")
    assert resp.status_code == 200, resp.text
    record = next(r for r in resp.json()["standalone"] if r["slug"] == "VA-071")
    assert record["notes"] == "TRIAGE-NOTE-MARKER"
    assert record["provenance"]["agent_id"] == "SOURCE-VA-071"
    assert record["details"]["cvss_vector"]
    assert record["submission_status"] == "none"


def test_report_payload_omits_readiness_from_a_final_export(
    client, isolate_settings, fake_template
):
    """A final export renders no readiness, so it must not ship one.

    ``ready`` is a precondition of a final export, so its blockers are empty by
    construction — but its ADVISORIES are not, and they quote internal QA doubt
    about the engagement's own evidence ("no audited dispatch or command run
    stands behind it"). The Statistics tab deliberately renders readiness in
    draft mode only; the payload now matches.
    """
    _seed(client, isolate_settings)
    backed = _finding("VA-072", "Missing authorization on admin API", severity="critical")
    backed["details"].update(
        {
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "repro_runs": [_command_run(client, "final-payload")],
        }
    )
    _add_finding(client, backed)

    final = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "final"}
    )
    assert final.status_code == 200, final.text
    payload = _injected_payload(isolate_settings, final.json()["relative_path"])
    assert set(payload) == _PAYLOAD_KEYS - {"report_readiness"}

    draft = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert draft.status_code == 200, draft.text
    draft_payload = _injected_payload(isolate_settings, draft.json()["relative_path"])
    assert set(draft_payload["report_readiness"]) == _declared_fields("ReportReadiness")


def test_report_payload_carries_attack_chain_steps_in_recorded_order(
    client, isolate_settings, fake_template
):
    """The ordered path itself reaches the report, not just its narrative.

    report_readiness already GATES on these rows — every ``step`` link must
    resolve to a reportable finding — while the report rendered only the prose
    narrative beside them. The links travel in the order they were recorded,
    which is the only step order the schema carries.
    """
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-080", "Auth guard never runs"))
    _add_finding(client, _finding("VA-081", "Admin export reachable"))

    chain = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/attack-chains",
        json={
            "chain_key": "chain-admin-takeover",
            "title": "Unauthenticated admin takeover",
            "severity": "critical",
            "narrative": "Reach the admin API, then export the user table.",
            "evidence_ref": "findings.md",
            "provenance": {"agent_id": "CHAIN-MARKER"},
            "links": [
                {"relation": "step", "entity_kind": "finding", "entity_ref": "VA-080"},
                {"relation": "step", "entity_kind": "finding", "entity_ref": "VA-081"},
                {
                    "relation": "supporting-evidence",
                    "entity_kind": "artifact",
                    "entity_ref": "findings.md",
                    "notes": "capture of the unauthenticated request",
                },
            ],
        },
    )
    assert chain.status_code == 201, chain.text

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    relative_path = response.json()["relative_path"]
    payload = _injected_payload(isolate_settings, relative_path)

    links = payload["attack_chain_links"]
    assert [link["entity_ref"] for link in links] == ["VA-080", "VA-081", "findings.md"]
    assert [link["relation"] for link in links] == ["step", "step", "supporting-evidence"]
    assert set(links[0]) == _declared_fields("ReportAttackChainLink")
    assert links[0]["chain_key"] == "chain-admin-takeover"

    # The chain row itself is projected too: evidence_ref and provenance_json
    # are as unrendered as the finding columns above.
    assert set(payload["attack_chains"][0]) == _declared_fields("ReportAttackChain")
    delivered = (
        isolate_settings["engagements_dir"] / ENGAGEMENT_KEY / relative_path
    ).read_text(encoding="utf-8")
    assert "CHAIN-MARKER" not in delivered


def test_report_payload_carries_every_root_cause_group_key(
    client, isolate_settings, fake_template
):
    """A root-cause group exercises the fields a standalone finding cannot.

    ``root_cause_effect`` and ``root_cause_note`` exist on SIBLINGS ONLY —
    links.py:_root_cause_link_metadata writes them onto the record when the
    group is assembled — and FullReport.tsx renders both: the effect becomes the
    sibling's tag (`eliminates attack path` rather than a flat "shares root
    cause"), the note the line explaining why the sibling exists. A fixture
    holding one standalone finding covers neither, so deleting either from the
    allow-list used to pass this entire suite while a delivered report silently
    lost its root-cause grouping.
    """
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-090", "Shared auth guard never runs"))
    _add_finding(client, _finding("VA-091", "Admin export reachable through the same guard"))

    link = client.put(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/findings/VA-091/root-cause",
        json={
            "root_cause_slug": "VA-090",
            "sibling_order": 1,
            "root_cause_effect": "eliminates_attack_path",
            "note": "ROOT-CAUSE-NOTE: reachable only because the VA-090 guard never runs.",
        },
    )
    assert link.status_code == 200, link.text
    # Linking is a material relationship change, so it invalidates the sibling's
    # standing confirmation. Re-confirm or the draft projection drops it and the
    # group never forms.
    _verify_finding(client, "VA-091", attempt="relinked")

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    payload = _injected_payload(isolate_settings, response.json()["relative_path"])

    group = next(
        g for g in payload["finding_groups"]["groups"] if g["root"]["slug"] == "VA-090"
    )
    assert set(group["root"]) == _STANDALONE_FINDING_KEYS
    sibling = next(s for s in group["siblings"] if s["slug"] == "VA-091")

    # Every field ReportFinding declares, including the sibling-only ones.
    assert set(sibling) == _FINDING_KEYS
    assert _SIBLING_ONLY_KEYS <= set(sibling)
    # Verbatim, not masked or reshaped — the narrowing drops fields whole.
    assert sibling["root_cause_effect"] == "eliminates_attack_path"
    assert sibling["root_cause_note"] == (
        "ROOT-CAUSE-NOTE: reachable only because the VA-090 guard never runs."
    )
    # The link's own row id is the one piece of that metadata the template has
    # no use for, so it stays behind.
    assert "root_cause_link_id" not in sibling


def test_report_summary_counts_exactly_the_findings_the_report_contains(
    client, isolate_settings, fake_template
):
    """The headline numbers describe the report's own body, not the triage queue.

    ``assessment_summary`` is not mode-filtered: its ``finding_workflow_statuses``
    and ``finding_verification_statuses`` are unfiltered ``GROUP BY``s over every
    row of assessment_findings, and its ``finding_count``/``finding_severities``
    count everything that is not merged or false-positive — including findings no
    report projection admits. The finding LIST is filtered (only
    ``confirmed``/``downgraded`` reach a draft), so the summary and the body
    disagreed: a client's donut, headline count and Workflow chart described
    internal triage state, down to a literal `false positive` row.

    This is the disclosure argument the export already accepted when it stopped
    shipping ``report_readiness`` in a final export.
    """
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-100", "Missing authorization on admin API"))
    # Recorded, never verified: counted by assessment_summary, admitted by
    # neither report projection.
    _record_finding(client, _finding("VA-101", "UNREVIEWED-MARKER suspicion"))
    # Verified false-positive: dropped from assessment_summary's finding_count,
    # but still a `false_positive` row on its unfiltered workflow rollup.
    _record_finding(client, _finding("VA-102", "FALSE-POSITIVE-MARKER suspicion"))
    _verify_finding(client, "VA-102", disposition="false_positive")

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    relative_path = response.json()["relative_path"]
    payload = _injected_payload(isolate_settings, relative_path)

    body = payload["finding_groups"]
    delivered = [
        *(
            record
            for group in body["groups"]
            for record in (group["root"], *group["siblings"])
        ),
        *body["standalone"],
    ]
    assert [record["slug"] for record in delivered] == ["VA-100"]

    summary = payload["summary"]
    assert set(summary) == _SUMMARY_KEYS
    assert summary["finding_count"] == len(delivered) == body["finding_count"]
    assert summary["finding_severities"] == {"high": 1}
    assert summary["finding_workflow_statuses"] == {"exploited": 1}
    assert summary["finding_verification_statuses"] == {"confirmed": 1}

    # Neither excluded finding survives anywhere else in the payload either —
    # not in the body, not in a rollup key. `report_readiness` is exempt and only
    # exempt: a DRAFT ships it precisely so the operator reading one is told
    # which findings are being held back and why, and a final export ships none
    # at all (see test_report_payload_omits_readiness_from_a_final_export).
    delivered = json.dumps(
        {key: value for key, value in payload.items() if key != "report_readiness"}
    )
    assert "UNREVIEWED-MARKER" not in delivered
    assert "FALSE-POSITIVE-MARKER" not in delivered
    assert "false_positive" not in delivered
    assert "unreviewed" not in delivered

    # ADR 0019: the OPERATOR's own summary is untouched — it still counts the
    # unverified finding and still names the false-positive disposition. The
    # narrowing lives at the delivery boundary and nowhere else.
    operator = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/summary")
    assert operator.status_code == 200, operator.text
    operator_summary = operator.json()
    assert operator_summary["finding_count"] == 2
    assert operator_summary["finding_workflow_statuses"]["false_positive"] == 1
    assert operator_summary["finding_verification_statuses"]["unreviewed"] == 1


def test_report_summary_keeps_the_engagement_rollups_that_are_not_triage_state(
    client, isolate_settings, fake_template
):
    """Scope-shaped counts still travel; they describe the engagement, not QA.

    ``attack_chain_count`` counts the chains the payload ships in full,
    ``open_surface_count`` and ``credential_count`` describe what the assessment
    reached. None of them is a triage disposition, and the Statistics tab renders
    all three as stat cards, so all three are copied verbatim.
    """
    _seed(client, isolate_settings)
    _add_finding(client, _finding("VA-110", "Missing authorization on admin API"))

    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/report-export", json={"mode": "draft"}
    )
    assert response.status_code == 200, response.text
    payload = _injected_payload(isolate_settings, response.json()["relative_path"])

    summary = payload["summary"]
    operator = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/summary").json()
    for field in report_export._SUMMARY_FIELDS:
        assert summary[field] == operator[field]
