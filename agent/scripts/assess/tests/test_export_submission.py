"""CLI tests for `vigil assess export-submission`.

Drives the real argparse parser (`export_submission.register`) and `run`, with a
fake client that returns canned finding / finding-links / command-run payloads and
records every GET and POST. Pins the behaviour the plan locks down:

  * the output is the platform copy-paste layout — `**Title:**` / `**VRT:**` (or
    `**Weakness:**`; `direct` drops both) / `**Severity:**` / `**CVSS:**` header
    lines, a `---` separator, the stable `### ` sections (Summary / Steps to
    Reproduce / Evidence / Attack Scenario / Impact / Remediation), then a second
    `---` and the ONE "OPERATOR DETAILS — NOT FOR SUBMISSION" reference section the
    operator never pastes (present in BOTH draft and final);
  * draft always writes and inserts `[NEEDS: ...]` markers for missing proof;
  * final mode strict-gates on title / severity+CVSS / platform taxonomy /
    attacker-impact / >=1 proof, raising `AssessError` and writing nothing;
  * `### Evidence` renders ONLY the authored `details.evidence` (`[NEEDS: evidence]`
    in a draft when absent) — the raw structured proof (poc_* / evidence_ref) and
    the linked command runs are NOT rendered into it; they, the finding metadata,
    and any hygiene warnings are consolidated into the single OPERATOR DETAILS
    section (mirrored by the context JSON `linked_command_runs` array). The old
    separate "OPERATOR NOTES" and "COMMAND REFERENCE" blocks no longer exist;
  * `direct` drops the VRT/weakness taxonomy fields (and its gate);
  * the generated submission is registered as `kind="submission"` and NO payload
    ever carries `submission_status`;
  * linked command runs come ONLY from explicit finding-links (no fuzzy search);
  * internal ids (UUIDs / absolute engagement paths / cases.db) are FLAGGED
    non-destructively while the finding content survives verbatim.
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
    # Evidence renders its own draft marker; the proof marker lives under OPERATOR DETAILS.
    assert "[NEEDS: evidence]" in body
    assert "[NEEDS: proof" in body
    # Stable sections still render their headers even when empty, with markers.
    assert "[NEEDS: summary]" in body
    assert "[NEEDS: steps to reproduce]" in body
    assert "[NEEDS: remediation]" in body
    # Copy-paste layout: header field lines + separator + ### sections.
    assert body.startswith("**Title:**")
    assert "**CVSS:** [NEEDS: CVSS vector]" in body
    assert "\n---\n" in body
    assert "### Summary" in body and "### Evidence" in body
    # The single OPERATOR DETAILS reference section is present below the second divider.
    assert "## OPERATOR DETAILS — NOT FOR SUBMISSION" in body
    # The retired separate blocks no longer exist.
    assert "## OPERATOR NOTES" not in body
    assert "## COMMAND REFERENCE" not in body
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
    # Copy-paste header field lines, then a separator, then the ### body sections.
    assert body.startswith("**Title:** IDOR exposes other users' orders on /orders/{id}")
    assert "**VRT:** broken_access_control.idor" in body  # VRT header line
    assert "**Severity:** HIGH" in body
    assert "**CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)" in body
    header, _, sections = body.partition("\n---\n")
    assert "### Summary" not in header  # first separator really splits header from body
    assert "### Steps to Reproduce" in sections and "### Impact" in sections
    # Structured proof lives under OPERATOR DETAILS, NOT in the pasteable Evidence section.
    assert "**PoC Request:**" in body and "**PoC Response:**" in body
    details = body[body.index("## OPERATOR DETAILS"):]
    assert "**PoC Request:**" in details and "**PoC Response:**" in details
    evidence = body[body.index("### Evidence"):body.index("### Impact")]
    assert "PoC Request" not in evidence and "PoC Response" not in evidence
    # The single OPERATOR DETAILS section is present; the retired blocks are gone.
    assert "## OPERATOR DETAILS — NOT FOR SUBMISSION" in body
    assert "## OPERATOR NOTES" not in body
    assert "## COMMAND REFERENCE" not in body
    # context companion written alongside.
    ctx = json.loads((tmp_path / "submissions" / "VA-047" / "submission-context.json").read_text())
    assert ctx["mode"] == "final" and ctx["missing"] == [] and ctx["proof"]["has_proof"] is True
    assert ctx["linked_command_runs"] == []


def test_operator_details_surfaces_full_record(tmp_path, monkeypatch, capsys):
    """Everything else on the record is surfaced below the paste line so the LLM
    edits with the full picture — dedup/merge, root cause, chain, verification, notes."""
    finding = _finding(details=_complete_details(
        chain_required="true",
        chain_rationale="Needs the VA-002 oracle to supply victim userIds.",
        propagation_verdict="Write reaches the prod routing path; not gated to the caller's env.",
        discovered_by="exploit-developer",
    ))
    finding["merged_into_slug"] = "EX-003"
    finding["root_cause_key"] = "missing-flauthz:tame-writes"
    finding["defect_family"] = "broken-function-level-authorization"
    finding["verification_state"] = "verified"
    finding["notes"] = "MECHANISM: no E00207 caller-authz on qtame writes. REACHABILITY: prod accepted."
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    details = body[body.index("## OPERATOR DETAILS"):]  # below the never-paste line
    assert "Merged into: EX-003" in details
    assert "missing-flauthz:tame-writes" in details
    assert "broken-function-level-authorization" in details
    assert "Chain rationale" in details and "VA-002 oracle" in details
    assert "Propagation verdict" in details
    assert "Verification state: verified" in details
    assert "Discovered by: exploit-developer" in details
    assert "Investigation notes" in details and "no E00207" in details
    # notes never leak above the paste line
    assert "no E00207" not in body[: body.index("## OPERATOR DETAILS")]


def test_location_method_not_doubled(tmp_path, monkeypatch, capsys):
    """canonical_location already carrying the method must not become 'POST POST …'."""
    finding = _finding(details=_complete_details(request_method="POST"))
    finding["canonical_location"] = "POST https://app.example.com/api/tame/qtameSubmit"
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "POST POST" not in body
    assert "Location: POST https://app.example.com/api/tame/qtameSubmit" in body


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
    # Neither the Bugcrowd VRT nor the HackerOne weakness taxonomy line appears.
    assert "VRT" not in body
    assert "Weakness" not in body
    # Still the copy-paste layout: Title + Severity + CVSS header, then the body.
    assert body.startswith("**Title:**")
    assert "**Severity:**" in body and "**CVSS:**" in body
    assert "### Summary" in body


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


# -- linked command runs: REFERENCE, not force-rendered Evidence --------------

def test_linked_runs_are_reference_not_evidence(tmp_path, monkeypatch, capsys):
    # A distinctive command (orders/1002) so it never collides with the PoC's own
    # request line (orders/1001) when we check which section it lands in.
    links = [
        {"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5},
        {"finding_slug": "VA-047", "target_kind": "probe_run", "target_id": 9},  # ignored (wrong kind)
        {"finding_slug": "VA-999", "target_kind": "command_run", "target_id": 7},  # ignored (other finding)
    ]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "reproduce IDOR", "return_code": 0},
        7: {"id": 7, "command": "curl -s https://app.example.com/secret", "intent": "unrelated", "return_code": 0},
    }
    fake = _FakeClient(_finding(details=_complete_details()), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "app.example.com/secret" not in body  # other finding's run not pulled in

    # The linked run appears ONLY under the single OPERATOR DETAILS section, never in Evidence.
    assert "## OPERATOR DETAILS — NOT FOR SUBMISSION" in body
    assert "**Linked command runs**" in body
    ref_idx = body.index("## OPERATOR DETAILS")
    assert "curl -sk https://app.example.com/orders/1002" in body[ref_idx:]
    evidence = body[body.index("### Evidence"):body.index("### Impact")]
    assert "curl -sk https://app.example.com/orders/1002" not in evidence
    assert "orders/1002" not in evidence

    # ...and as structured reference in the context JSON's linked_command_runs.
    runs = _context(tmp_path)["linked_command_runs"]
    assert [r["id"] for r in runs] == [5]
    assert runs[0]["intent"] == "reproduce IDOR" and runs[0]["return_code"] == 0
    assert "orders/1002" in runs[0]["command"]

    # Decision 4: NO fuzzy command search — only finding-links + the exact run by id.
    assert "finding-links" in fake.gets
    assert "command-runs/5" in fake.gets
    assert not any(g.startswith("command-runs?") for g in fake.gets)


def test_operator_details_consolidates_all_reference(tmp_path, monkeypatch, capsys):
    """One OPERATOR DETAILS section holds metadata + structured proof + linked runs.

    Pins the consolidation: the three previously-separate mechanisms (raw poc_* in
    Evidence, a COMMAND REFERENCE block, an OPERATOR NOTES block) are now one
    section, and `### Evidence` carries only the authored prose.
    """
    links = [{"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5}]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "reproduce", "return_code": 0},
    }
    details = _complete_details(
        evidence="Response carried member B's masked order (o***1002). <-- proof",
        cwe_id="CWE-639",
        owasp_category="A01:2021",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
    )
    fake = _FakeClient(_finding(details=details), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()

    # Exactly one reference section, below a second `---`; the retired blocks are gone.
    assert body.count("## OPERATOR DETAILS — NOT FOR SUBMISSION") == 1
    assert "## OPERATOR NOTES" not in body
    assert "## COMMAND REFERENCE" not in body
    assert body.count("\n---\n") >= 2  # header separator + OPERATOR DETAILS separator

    details_section = body[body.index("## OPERATOR DETAILS"):]
    # Finding metadata weaves into OPERATOR DETAILS (kept out of the pasteable header).
    assert "CWE-639" in details_section
    assert "A01:2021" in details_section
    assert "cwe.mitre.org/data/definitions/639.html" in details_section
    assert "member" in details_section  # auth context
    # Structured proof + linked runs are here too.
    assert "**Structured proof**" in details_section
    assert "**PoC Request:**" in details_section and "**PoC Response:**" in details_section
    assert "**Linked command runs**" in details_section
    assert "curl -sk https://app.example.com/orders/1002" in details_section

    # `### Evidence` renders ONLY the authored prose — no raw proof, no linked command.
    evidence = body[body.index("### Evidence"):body.index("### Impact")]
    assert "Response carried member B's masked order (o***1002). <-- proof" in evidence
    assert "PoC Request" not in evidence and "PoC Response" not in evidence
    assert "curl -sk" not in evidence
    assert "CWE-639" not in evidence


def test_evidence_authored_from_details_evidence(tmp_path, monkeypatch, capsys):
    """Evidence renders the finding's authored `details.evidence`, not a linked run."""
    links = [{"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5}]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "reproduce", "return_code": 0},
    }
    details = _complete_details(evidence="Response body carried member B's masked order (o***1002).")
    fake = _FakeClient(_finding(details=details), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    evidence = body[body.index("### Evidence"):body.index("### Impact")]
    # Authored evidence prose lands in the Evidence section...
    assert "Response body carried member B's masked order (o***1002)." in evidence
    # ...while the linked command stays out of Evidence (it's reference below the divider).
    assert "curl -sk" not in evidence
    assert "curl -sk https://app.example.com/orders/1002" in body


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
    # The slug / engagement-path / internal-UUID hygiene checks scan only the
    # PASTEABLE body (above the second `---`), so exercise a real leak by authoring
    # them INTO the copy-paste Evidence section — where flagging is genuinely
    # correct. cases.db stays only in the linked command run (below the divider) to
    # prove that one check still scans the whole document.
    details = _complete_details(
        evidence=f"Reproduced; artifact saved to {abs_evidence} under internal agent {_UUID}.",
    )
    fake = _FakeClient(_finding(details=details, evidence_ref=abs_evidence), links=links, command_runs=command_runs)
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


def test_slug_in_operator_details_only_does_not_warn(tmp_path, monkeypatch, capsys):
    """A slug that appears ONLY in the never-paste OPERATOR DETAILS reference (here,
    the investigation notes) is not a leak — the operator never pastes it — so the
    slug hygiene check (pasteable body only) must stay silent."""
    finding = _finding(details=_complete_details())
    finding["notes"] = "Tracked as VA-047 in the work queue; see the linked run for repro."
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    # The slug is present below the second divider (in the notes reference)...
    details = body[body.index("## OPERATOR DETAILS"):]
    assert "VA-047" in details
    # ...but never in the pasteable body, and NO slug warning fires.
    assert "VA-047" not in body[: body.index("## OPERATOR DETAILS")]
    warnings = _context(tmp_path)["hygiene_warnings"]
    assert not any("finding slug" in w for w in warnings)


def test_slug_in_pasteable_body_still_warns(tmp_path, monkeypatch, capsys):
    """A slug that leaks into the copy-paste body (here, the summary) is a real leak
    and must still be flagged."""
    finding = _finding(details=_complete_details())
    finding["summary"] = "Finding VA-047: an authenticated member can read another member's order."
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "VA-047" in body[: body.index("## OPERATOR DETAILS")]  # leaked above the paste line
    warnings = _context(tmp_path)["hygiene_warnings"]
    assert any("finding slug" in w and "VA-047" in w for w in warnings)


# -- steps: no double-numbering of pre-numbered items -------------------------

def test_pre_numbered_steps_are_not_double_numbered(tmp_path, monkeypatch, capsys):
    """An authored step that already starts with '1. ' / '2) ' must not render as
    '1. 1. …' — the leading enumerator is stripped before the renderer prepends its
    own counter."""
    details = _complete_details(
        steps_to_reproduce=[
            "1. Log in as member A",
            "2) GET /orders/1001 (member B's order)",
            "Observe member B's data in the response",  # unnumbered: left as-is
        ]
    )
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    steps = body[body.index("### Steps to Reproduce"):body.index("### Evidence")]
    # No doubled counters.
    assert "1. 1." not in steps
    assert "2. 2)" not in steps
    # The author's own enumerator is gone; the renderer's counter is authoritative.
    assert "1. Log in as member A" in steps
    assert "2. GET /orders/1001 (member B's order)" in steps
    assert "3. Observe member B's data in the response" in steps


# -- title word-count hygiene warning (advisory, not a hard gate) -------------

@pytest.mark.parametrize(
    "title, expect_warn",
    [
        # 15 words -> warns.
        ("This finding demonstrates a very long run on submission title that clearly exceeds the limit", True),
        # 10 words -> no warning.
        ("Short concise title that stays under the required word limit", False),
    ],
)
def test_title_word_count_warns_but_does_not_gate(tmp_path, monkeypatch, capsys, title, expect_warn):
    finding = _finding(details=_complete_details())
    finding["title"] = title
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    # A complete finding: final mode must still WRITE (the title warning never gates).
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    assert _submission_path(tmp_path).exists()  # never blocked by the title warning
    warnings = _context(tmp_path)["hygiene_warnings"]
    assert any("max 12" in w for w in warnings) is expect_warn


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
    assert out["linked_command_runs"] == 0  # no linked runs on this finding
    assert out["artifact_registered"] is True
    assert out["hygiene_warnings"] == []  # clean finding: no internal-id leaks


# -- A2: operational-header overlay (rendered FROM finding fields) ------------

def _write_scope(engagement_dir, required_headers):
    """Minimal scope.json so rate_caps_for_dir surfaces the Deconfliction header."""
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["app.example.com"], "required_headers": required_headers}),
        encoding="utf-8",
    )


def test_a2_operational_header_renders_from_fields(tmp_path, monkeypatch, capsys):
    """The Asset/POC/Run/Pass if/Deconfliction overlay is emitted in the copy-paste
    header (above the first `---`), each line sourced from a finding field so a
    re-render reproduces it — not hand-applied text a re-render would wipe."""
    _write_scope(tmp_path, {"X-Bug-Bounty": "vigiloss"})
    finding = _finding(
        evidence_ref="scans/va-003-poc.sh",
        details=_complete_details(
            run="bash scans/va-003-poc.sh",
            pass_if="HTTP 200 returns another member's order record",
        ),
    )
    finding["canonical_location"] = "https://app.example.com/api/orders/1001"
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    header, sep, _sections = body.partition("\n---\n")
    assert sep == "\n---\n"
    # All five operational lines render, and all sit in the pasteable header block.
    assert "**Asset:** https://app.example.com/api/orders/1001" in header
    assert "**POC:** scans/va-003-poc.sh" in header
    assert "**Run:** bash scans/va-003-poc.sh" in header
    assert "**Pass if:** HTTP 200 returns another member's order record" in header
    assert "**Deconfliction:** X-Bug-Bounty: vigiloss" in header
    # Still the platform copy-paste layout — the overlay sits after CVSS, not before Title.
    assert body.startswith("**Title:**")


def test_a2_operational_header_survives_overwrite(tmp_path, monkeypatch, capsys):
    """The overlay is rebuilt from fields on `--overwrite`, so re-rendering never
    wipes it (the A2 defect being fixed)."""
    _write_scope(tmp_path, {"X-Bug-Bounty": "vigiloss"})
    finding = _finding(
        evidence_ref="scans/va-003-poc.sh",
        details=_complete_details(run="bash scans/va-003-poc.sh", pass_if="HTTP 200 leak"),
    )
    finding["canonical_location"] = "https://app.example.com/api/orders/1001"
    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd", "--overwrite"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    header = _submission_path(tmp_path).read_text().partition("\n---\n")[0]
    for line in (
        "**Asset:** https://app.example.com/api/orders/1001",
        "**POC:** scans/va-003-poc.sh",
        "**Run:** bash scans/va-003-poc.sh",
        "**Pass if:** HTTP 200 leak",
        "**Deconfliction:** X-Bug-Bounty: vigiloss",
    ):
        assert line in header


def test_a2_operational_lines_omitted_without_backing_data(tmp_path, monkeypatch, capsys):
    """No scope.json (no attribution header) and no run/pass_if → those lines are
    omitted entirely; the Asset line (from canonical_location) still renders."""
    finding = _finding(details=_complete_details())  # no run/pass_if, no scope.json written
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["export-submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    header = _submission_path(tmp_path).read_text().partition("\n---\n")[0]
    assert "**Run:**" not in header
    assert "**Pass if:**" not in header
    assert "**Deconfliction:**" not in header
    assert "**Asset:** /orders/1001" in header  # canonical_location is present
