"""CLI tests for `vigil assess export-submission`.

Drives the real argparse parser (`export_submission.register`) and `run`, with a
fake client that returns canned finding / finding-links / command-run payloads and
records every GET and POST. Pins the behaviour the plan locks down:

  * draft always writes and inserts `[NEEDS: ...]` markers for missing proof;
  * final mode strict-gates on title / severity+CVSS / platform taxonomy /
    attacker-impact / >=1 proof, raising `AssessError` and writing nothing;
  * `direct` drops the VRT/weakness taxonomy fields (and its gate);
  * the generated submission is registered as `kind="submission"` and NO payload
    ever carries `submission_status`;
  * command evidence comes ONLY from explicit finding-links (no fuzzy search);
  * internal ids (UUIDs / absolute engagement paths / cases.db) are scrubbed
    from the output while the human-readable slug survives.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import export_submission
from assess.lib.client import AssessError

# An INTERNAL agent UUID (known from a command-run row) that must be FLAGGED (not
# rewritten) when it leaks into the output.
_UUID = "550e8400-e29b-41d4-a716-446655440000"
# A TARGET-application UUID that is PROOF (e.g. IDOR on a UUID-keyed resource) and
# must reach the report-writer verbatim — the old blanket regex used to redact it.
_TARGET_UUID = "11111111-2222-3333-4444-555555555555"


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Routes GETs to canned payloads and records every GET/POST endpoint."""

    def __init__(self, finding: dict, *, links=None, command_runs=None) -> None:
        self._finding = finding
        self._links = links or []
        self._command_runs = command_runs or {}
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        if endpoint.startswith("findings/"):
            slug = endpoint.split("/", 1)[1]
            if _nonempty_slug(self._finding) != slug:
                raise AssessError(f"HTTP 404: finding {slug} not found")
            return self._finding
        if endpoint == "finding-links":
            return self._links
        if endpoint.startswith("command-runs/"):
            run_id = int(endpoint.split("/", 1)[1])
            if run_id not in self._command_runs:
                raise AssessError(f"HTTP 404: command-run {run_id} not found")
            return self._command_runs[run_id]
        raise AssessError(f"unexpected GET {endpoint}")

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": len(self.posts), **payload}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _nonempty_slug(finding: dict) -> str:
    return str(finding.get("slug") or "")


# -- fixtures / builders ------------------------------------------------------

def _poc_request() -> dict:
    return {
        "method": "GET",
        "url": "https://app.example.com/orders/1001",
        "headers": {"Cookie": "session=member"},
        "body": "",
    }


def _poc_response() -> dict:
    return {"status": 200, "headers": {"Content-Type": "application/json"}, "body_excerpt": '{"owner":"someone-else"}'}


def _finding(slug: str = "VA-047", *, severity: str = "high", evidence_ref: str = "", details: dict | None = None) -> dict:
    """A finding as returned by GET /findings/{slug}: details_json is a RAW STRING."""
    return {
        "id": 91,
        "slug": slug,
        "title": "IDOR exposes other users' orders on /orders/{id}",
        "severity": severity,
        "summary": "An anonymous member can read another member's order by id.",
        "auth_context": "member",
        "canonical_location": "/orders/1001",
        "evidence_ref": evidence_ref,
        "details_json": json.dumps(details or {}),
    }


def _complete_details(**overrides) -> dict:
    """details that satisfy the bugcrowd/hackerone strict gate; override to break one."""
    base = {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 6.5,
        "vrt_category": "broken_access_control.idor",
        "weakness": "CWE-639 Authorization Bypass Through User-Controlled Key",
        "impact": "An authenticated member can read any other member's order records by id.",
        "poc_request": _poc_request(),
        "poc_response": _poc_response(),
        "remediation": "Enforce an ownership check on the order id server-side.",
        "steps_to_reproduce": ["Log in as member A", "GET /orders/1001 (member B's order)", "Observe B's data"],
    }
    base.update(overrides)
    return base


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    export_submission.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(export_submission, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(export_submission, "AssessmentClient", lambda *a, **k: fake)


def _submission_path(tmp_path, slug: str = "VA-047"):
    return tmp_path / "submissions" / slug / "submission.md"


# -- draft vs final -----------------------------------------------------------

def test_draft_writes_with_needs_markers(tmp_path, monkeypatch, capsys):
    # A bare finding: no CVSS, no vrt, no impact/summary, no proof.
    fake = _FakeClient(_finding(details={}))
    fake._finding["summary"] = ""  # remove the impact fallback too
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "[NEEDS: CVSS vector]" in body
    assert "[NEEDS: VRT category]" in body
    assert "[NEEDS: attacker-impact statement]" in body
    assert "[NEEDS: proof" in body
    # draft still registers the artifact.
    assert any(ep == "artifacts" for ep, _ in fake.posts)


def test_final_blocks_when_incomplete_and_writes_nothing(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details={}))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "missing proof-critical fields" in str(exc.value)
    assert not _submission_path(tmp_path).exists()
    assert fake.posts == []


def test_final_passes_with_complete_finding(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "[NEEDS:" not in body
    assert "broken_access_control.idor" in body  # VRT rendered
    assert "**PoC Request:**" in body and "**PoC Response:**" in body
    # context companion written alongside.
    ctx = json.loads((tmp_path / "submissions" / "VA-047" / "submission-context.json").read_text())
    assert ctx["mode"] == "final" and ctx["missing"] == [] and ctx["proof"]["has_proof"] is True


# -- per-platform blockers (each blocks final, passes draft) ------------------

@pytest.mark.parametrize(
    "platform, break_kwargs, marker",
    [
        ("bugcrowd", {"vrt_category": ""}, "VRT category"),
        ("hackerone", {"weakness": ""}, "weakness"),
        ("bugcrowd", {"impact": "", }, "attacker-impact statement"),
        ("bugcrowd", {"cvss_vector": ""}, "CVSS vector"),
    ],
)
def test_platform_blocker_gates_final_but_draft_writes(tmp_path, monkeypatch, capsys, platform, break_kwargs, marker):
    details = _complete_details(**break_kwargs)
    finding = _finding(details=details)
    if "impact" in break_kwargs and not break_kwargs["impact"]:
        finding["summary"] = ""  # kill the impact fallback so the gate really trips

    # final: blocks.
    fake_final = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake_final)
    args = _parse(["export-submission", "VA-047", "--platform", platform], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert marker in str(exc.value)
    assert fake_final.posts == []

    # draft: writes with the matching marker.
    fake_draft = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake_draft)
    args = _parse(["export-submission", "VA-047", "--platform", platform, "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert f"[NEEDS: {marker}]" in _submission_path(tmp_path).read_text()


def test_missing_proof_gates_final(tmp_path, monkeypatch, capsys):
    # No poc pair, no poc_code, no evidence_ref -> no proof.
    details = _complete_details(poc_request={}, poc_response={})
    finding = _finding(details=details, evidence_ref="")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "proof (poc_request+poc_response, poc_code, or evidence_ref)" in str(exc.value)


def test_evidence_ref_alone_satisfies_proof(tmp_path, monkeypatch, capsys):
    details = _complete_details(poc_request={}, poc_response={})
    finding = _finding(details=details, evidence_ref="scans/idor-orders.txt")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    body = _submission_path(tmp_path).read_text()
    assert "scans/idor-orders.txt" in body
    assert "[NEEDS: proof" not in body


def test_flags_supply_taxonomy(tmp_path, monkeypatch, capsys):
    # Details omit vrt/weakness; the CLI flags supply them and satisfy the gate.
    details = _complete_details(vrt_category="", weakness="")
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["export-submission", "VA-047", "--platform", "bugcrowd", "--vrt-category", "server_security_misconfiguration"],
        str(tmp_path),
    )
    export_submission.run(args)
    capsys.readouterr()
    assert "server_security_misconfiguration" in _submission_path(tmp_path).read_text()


# -- direct mode --------------------------------------------------------------

def test_direct_mode_drops_taxonomy_and_gate(tmp_path, monkeypatch, capsys):
    # No vrt, no weakness — direct must still pass final and omit both fields.
    details = _complete_details(vrt_category="", weakness="")
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "direct"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    body = _submission_path(tmp_path).read_text()
    assert "VRT" not in body
    assert "Weakness" not in body
    assert "Direct disclosure" in body


# -- artifact registration / submission_status invariant ----------------------

def test_artifact_registered_as_submission_without_submission_status(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    artifact_posts = [(ep, payload) for ep, payload in fake.posts if ep == "artifacts"]
    assert len(artifact_posts) == 1
    _, payload = artifact_posts[0]
    assert payload["kind"] == "submission"
    assert payload["related_finding_slug"] == "VA-047"
    assert payload["path"] == "submissions/VA-047/submission.md"  # engagement-relative
    # HARD INVARIANT: submission_status must never appear in ANY payload.
    for _ep, any_payload in fake.posts:
        assert "submission_status" not in any_payload


# -- command evidence: explicit links only, no fuzzy search -------------------

def test_command_evidence_from_links_only(tmp_path, monkeypatch, capsys):
    links = [
        {"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5},
        {"finding_slug": "VA-047", "target_kind": "probe_run", "target_id": 9},  # ignored (wrong kind)
        {"finding_slug": "VA-999", "target_kind": "command_run", "target_id": 7},  # ignored (other finding)
    ]
    command_runs = {
        5: {"id": 5, "command": "curl -s https://app.example.com/orders/1001", "intent": "reproduce IDOR", "return_code": 0},
        7: {"id": 7, "command": "curl -s https://app.example.com/secret", "intent": "unrelated", "return_code": 0},
    }
    fake = _FakeClient(_finding(details=_complete_details()), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "curl -s https://app.example.com/orders/1001" in body  # linked run embedded
    assert "app.example.com/secret" not in body  # other finding's run not pulled in
    # Decision 4: NO fuzzy command search — only finding-links + the exact run by id.
    assert "finding-links" in fake.gets
    assert "command-runs/5" in fake.gets
    assert not any(g.startswith("command-runs?") for g in fake.gets)


# -- internal-id hygiene (faithful body + non-destructive warnings) -----------

def _context(tmp_path, slug: str = "VA-047") -> dict:
    return json.loads((tmp_path / "submissions" / slug / "submission-context.json").read_text())


def test_hygiene_flags_leaks_without_mutating_body(tmp_path, monkeypatch, capsys):
    abs_evidence = f"{tmp_path}/scans/idor.txt"
    links = [{"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5}]
    command_runs = {
        5: {
            "id": 5,
            # producer_agent_id is a KNOWN internal id, echoed in the command; a
            # cases.db reference and an absolute engagement path are also present.
            "producer_agent_id": _UUID,
            "command": f"vigil assess kali exec --agent-id {_UUID} -- sqlite3 {tmp_path}/cases.db 'select 1'",
            "intent": "reproduce",
            "return_code": 0,
        }
    }
    fake = _FakeClient(_finding(details=_complete_details(), evidence_ref=abs_evidence), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    err = capsys.readouterr().err

    body = _submission_path(tmp_path).read_text()
    # FAITHFUL: nothing is rewritten — content reaches the report-writer verbatim.
    assert _UUID in body                     # internal agent id NOT redacted
    assert str(tmp_path) in body             # absolute path NOT stripped
    assert "cases.db" in body                # db reference NOT clipped
    assert "scans/idor.txt" in body
    assert "VA-047" not in body              # slug kept out of the heading by design

    # ...but every internal-id leak is FLAGGED non-destructively.
    warnings = "\n".join(_context(tmp_path)["hygiene_warnings"])
    assert _UUID in warnings
    assert "engagement path" in warnings
    assert "cases.db" in warnings
    # And the warnings surface on stderr so the report-writer sees them in-line.
    assert "WARN export-submission" in err


def test_target_uuid_in_poc_reaches_output_verbatim(tmp_path, monkeypatch, capsys):
    """Regression: a blanket UUID scrub corrupted proof. Target-app ids are never touched."""
    poc_request = {
        "method": "GET",
        "url": f"https://app.example.com/api/invoices/{_TARGET_UUID}",
        "headers": {"Cookie": "session=member"},
        "body": "",
    }
    fake = _FakeClient(_finding(details=_complete_details(poc_request=poc_request)))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert _TARGET_UUID in body
    # A target-app UUID is not an internal id, so it is never flagged.
    assert all(_TARGET_UUID not in w for w in _context(tmp_path)["hygiene_warnings"])


# -- overwrite guard ----------------------------------------------------------

def test_overwrite_guard(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    # Second run without --overwrite must refuse.
    fake2 = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake2)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "already exists" in str(exc.value)
    assert fake2.posts == []  # nothing re-registered

    # With --overwrite it proceeds.
    fake3 = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake3)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--overwrite"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert any(ep == "artifacts" for ep, _ in fake3.posts)


# -- json output --------------------------------------------------------------

def test_json_summary_shape(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--json"], str(tmp_path))
    export_submission.run(args)
    out = json.loads(capsys.readouterr().out)
    assert out["slug"] == "VA-047"
    assert out["platform"] == "bugcrowd"
    assert out["mode"] == "final"
    assert out["path"] == "submissions/VA-047/submission.md"
    assert out["missing"] == []
    assert out["artifact_registered"] is True
    assert out["hygiene_warnings"] == []  # clean finding: no internal-id leaks
