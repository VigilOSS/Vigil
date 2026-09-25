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
  * final mode strict-gates on lifecycle, platform fields, attacker impact, a
    finding-linked indexed artifact that is present on disk now, readiness, and
    hygiene, raising `AssessError` and leaving no unregistered output;
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
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from assess.commands import export_submission
from assess.lib.client import AssessError
from assess.lib.finding_render import UNTRUSTED_DATA_NOTICE

# An INTERNAL agent UUID (known from a command-run row) that must be FLAGGED (not
# rewritten) when it leaks into the output.
_UUID = "550e8400-e29b-41d4-a716-446655440000"
# A TARGET-application UUID that is PROOF (e.g. IDOR on a UUID-keyed resource) and
# must reach the report-writer verbatim — a blanket scrub would destroy the finding.
_TARGET_UUID = "11111111-2222-3333-4444-555555555555"


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Routes GETs to canned payloads and records every GET/POST endpoint."""

    def __init__(
        self,
        finding: dict,
        *,
        links=None,
        command_runs=None,
        artifacts=None,
        readiness=None,
        decisions=None,
        decisions_error: str = "",
        post_error: str = "",
        post_response: dict | None = None,
    ) -> None:
        self._finding = finding
        self._links = links or []
        self._command_runs = command_runs or {}
        self._artifacts = artifacts
        self._readiness = readiness or {"ready": True, "blockers": [], "advisories": []}
        # `dispatch-decisions` rows, newest first (the backend orders created_at
        # DESC). The default is EMPTY, so the whole suite exercises the "no
        # rehearsal recorded" advisory as its background state — which is the
        # honest default for a fixture nobody rehearsed.
        self._decisions = decisions if decisions is not None else []
        self._decisions_error = decisions_error
        self._post_error = post_error
        self._post_response = post_response
        self.engagement_dir = ""
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        if endpoint.startswith("dispatch-decisions?"):
            if self._decisions_error:
                raise AssessError(self._decisions_error)
            params = parse_qs(urlsplit(endpoint).query)
            kind = params.get("kind", [""])[0]
            return [row for row in self._decisions if row.get("kind") == kind]
        if endpoint.startswith("findings/"):
            slug = endpoint.split("/", 1)[1]
            if _nonempty_slug(self._finding) != slug:
                raise AssessError(f"HTTP 404: finding {slug} not found")
            return self._finding
        if endpoint == "finding-links":
            return self._links
        if endpoint == "report-readiness":
            return self._readiness
        if endpoint.startswith("artifacts/") and not endpoint.startswith("artifacts/search?"):
            artifact_id = int(endpoint.split("/", 1)[1])
            artifacts = self._artifacts or []
            row = next(
                (item for item in artifacts if item.get("id") == artifact_id),
                None,
            )
            if row is None:
                raise AssessError(f"HTTP 404: artifact {artifact_id} not found")
            return row
        if endpoint.startswith("artifacts/search?"):
            if self._artifacts is not None:
                params = parse_qs(urlsplit(endpoint).query)
                offset = int(params.get("offset", ["0"])[0])
                limit = int(params.get("limit", ["1000"])[0])
                return self._artifacts[offset : offset + limit]
            evidence_ref = str(self._finding.get("evidence_ref") or "").strip()
            if not evidence_ref:
                return []
            if evidence_ref.startswith("/engagements/test-eng/"):
                relative_path = evidence_ref.removeprefix("/engagements/test-eng/")
            elif Path(evidence_ref).is_absolute() and self.engagement_dir:
                try:
                    relative_path = Path(evidence_ref).resolve().relative_to(
                        Path(self.engagement_dir).resolve()
                    ).as_posix()
                except ValueError:
                    return []
            else:
                relative_path = evidence_ref
            return [
                {
                    "id": 7,
                    "relative_path": relative_path,
                    "present": True,
                    "related_finding_slug": _nonempty_slug(self._finding),
                }
            ]
        if endpoint.startswith("command-runs/"):
            run_id = int(endpoint.split("/", 1)[1])
            if run_id not in self._command_runs:
                raise AssessError(f"HTTP 404: command-run {run_id} not found")
            return self._command_runs[run_id]
        raise AssessError(f"unexpected GET {endpoint}")

    def post(self, endpoint: str, payload: dict) -> dict:
        if self._post_error:
            raise AssessError(self._post_error)
        self.posts.append((endpoint, payload))
        if self._post_response is not None:
            return self._post_response
        if endpoint == "submissions/recover":
            return {
                "recovered_version_ids": [77],
                "failed_version_ids": [],
                "failed_versions": [],
                "orphaned_staging_paths": [],
            }
        if endpoint.startswith("submissions/") and endpoint.endswith("/exports"):
            return {
                "id": 77,
                "version_number": 1,
                "status": "complete",
                "relative_path": "submissions/VA-047/versions/0001/submission.md",
                "sha256": "a" * 64,
                "idempotent_replay": False,
            }
        return {
            "id": len(self.posts),
            **payload,
            "relative_path": payload.get("path", ""),
        }

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


def _finding(
    slug: str = "VA-047",
    *,
    severity: str = "high",
    evidence_ref: str = "scans/idor-orders.txt",
    details: dict | None = None,
) -> dict:
    """A finding as returned by GET /findings/{slug}, with parsed details."""
    return {
        "id": 91,
        "slug": slug,
        "title": "IDOR exposes other users' orders on /orders/{id}",
        "severity": severity,
        "summary": "An anonymous member can read another member's order by id.",
        "auth_context": "member",
        "canonical_location": "/orders/1001",
        "evidence_ref": evidence_ref,
        "workflow_status": "active",
        "verification_status": "confirmed",
        "row_version": 9,
        "updated_at": "2026-09-09T12:00:00Z",
        "details": dict(details or {}),
    }


def _complete_details(**overrides) -> dict:
    """details that satisfy the bugcrowd/hackerone strict gate; override to break one."""
    base = {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 6.5,
        "vrt_category": "broken_access_control.idor",
        "weakness": "CWE-639 Authorization Bypass Through User-Controlled Key",
        "impact": "An authenticated member can read any other member's order records by id.",
        "evidence": "The response returns member B's order fields while authenticated as member A.",
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
    fake.engagement_dir = str(tmp_path)
    # Normal successful fixtures model both sides of durable truth: the index row
    # and the current file. Tests that pass an explicit artifact result own the
    # on-disk setup themselves, which lets them model stale index state.
    if fake._artifacts is None:
        relative, reason = export_submission._normalize_evidence_path(
            str(fake._finding.get("evidence_ref") or ""),
            str(tmp_path),
            "test-eng",
        )
        if relative and not reason:
            evidence = tmp_path / relative
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("durable proof\n", encoding="utf-8")
    monkeypatch.setattr(export_submission, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(export_submission, "AssessmentClient", lambda *a, **k: fake)


def _submission_path(tmp_path, slug: str = "VA-047"):
    return tmp_path / "submissions" / slug / "submission.md"


# -- draft vs final -----------------------------------------------------------

def test_draft_writes_with_needs_markers(tmp_path, monkeypatch, capsys):
    # A bare finding: no CVSS, no vrt, no impact/summary, no proof.
    fake = _FakeClient(_finding(details={}, evidence_ref=""))
    fake._finding["summary"] = ""  # remove the impact fallback too
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "missing proof-critical fields" in str(exc.value)
    assert not _submission_path(tmp_path).exists()
    assert fake.posts == []


def test_final_passes_with_complete_finding(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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
    assert "member B's order fields" in evidence
    assert "PoC Request" not in evidence and "PoC Response" not in evidence
    # The single OPERATOR DETAILS section is present; the retired blocks are gone.
    assert "## OPERATOR DETAILS — NOT FOR SUBMISSION" in body
    assert "## OPERATOR NOTES" not in body
    assert "## COMMAND REFERENCE" not in body
    # context companion written alongside.
    ctx = json.loads((tmp_path / "submissions" / "VA-047" / "submission-context.json").read_text())
    assert ctx["mode"] == "final" and ctx["missing"] == []
    assert ctx["proof"]["has_content_proof"] is True
    assert ctx["proof"]["has_durable_proof"] is True
    assert "has_proof" not in ctx["proof"]
    assert ctx["linked_command_runs"] == []


def test_final_snapshots_context_and_calls_shared_version_api(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "submission",
            "VA-047",
            "--platform",
            "bugcrowd",
            "--attachment-id",
            "42",
            "--attachment-id",
            "17",
            "--json",
        ],
        str(tmp_path),
    )

    export_submission.run(args)

    output = json.loads(capsys.readouterr().out)
    context_path = tmp_path / "submissions" / "VA-047" / "submission-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    markdown = _submission_path(tmp_path).read_bytes()
    assert context["submission_sha256"] == hashlib.sha256(markdown).hexdigest()
    assert context["source_finding"] == {
        "id": 91,
        "row_version": 9,
        "updated_at": "2026-09-09T12:00:00Z",
        "workflow_status": "active",
        "verification_status": "confirmed",
    }
    version_posts = [
        (endpoint, payload)
        for endpoint, payload in fake.posts
        if endpoint == "submissions/VA-047/exports"
    ]
    assert version_posts == [
        (
            "submissions/VA-047/exports",
            {
                "platform": "bugcrowd",
                "submission_path": "submissions/VA-047/submission.md",
                "context_path": "submissions/VA-047/submission-context.json",
                "attachment_ids": [42, 17],
                "actor_surface": "vigil-assess",
            },
        )
    ]
    assert output["version"] == {
        "id": 77,
        "version_number": 1,
        "status": "complete",
        "relative_path": "submissions/VA-047/versions/0001/submission.md",
        "sha256": "a" * 64,
        "idempotent_replay": False,
    }



def test_draft_does_not_create_an_immutable_version(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--draft"],
        str(tmp_path),
    )

    export_submission.run(args)
    capsys.readouterr()

    assert not any(endpoint.startswith("submissions/") for endpoint, _ in fake.posts)


def test_recover_mode_uses_the_shared_recovery_api_without_rendering(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "--recover", "--json"], str(tmp_path))

    export_submission.run(args)

    assert json.loads(capsys.readouterr().out) == {
        "recovered_version_ids": [77],
        "failed_version_ids": [],
        "failed_versions": [],
        "orphaned_staging_paths": [],
    }
    assert fake.posts == [
        ("submissions/recover", {"actor_surface": "vigil-assess"})
    ]
    assert not _submission_path(tmp_path).exists()


def test_recover_human_output_prints_failure_reasons_and_orphan_paths(
    tmp_path, monkeypatch, capsys
):
    recovery = {
        "recovered_version_ids": [],
        "failed_version_ids": [12],
        "failed_versions": [
            {
                "id": 12,
                "finding_slug": "VA-047",
                "version_number": 3,
                "status": "failed",
                "failure_reason": "staged package is missing",
                "staging_relative_path": "submissions/VA-047/versions/.staging/0003.tmp",
                "relative_path": "submissions/VA-047/versions/0003/submission.md",
            }
        ],
        "orphaned_staging_paths": [
            "submissions/VA-099/versions/.staging/orphan.tmp"
        ],
    }
    fake = _FakeClient(
        _finding(details=_complete_details()), post_response=recovery
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "--recover"], str(tmp_path))

    export_submission.run(args)

    output = capsys.readouterr().out
    assert "VA-047 version 3 (id=12): staged package is missing" in output
    assert "submissions/VA-047/versions/.staging/0003.tmp" in output
    assert "submissions/VA-047/versions/0003/submission.md" in output
    assert "submissions/VA-099/versions/.staging/orphan.tmp" in output


def test_recover_mode_consumes_every_bounded_diagnostic_page(
    tmp_path, monkeypatch, capsys
) -> None:
    failed_one = {
        "id": 12,
        "finding_slug": "VA-047",
        "version_number": 3,
        "status": "failed",
        "failure_reason": "first failed stage",
        "staging_relative_path": "submissions/VA-047/versions/.staging/0003.tmp",
        "relative_path": "submissions/VA-047/versions/0003/submission.md",
    }
    failed_two = {
        **failed_one,
        "id": 13,
        "version_number": 4,
        "failure_reason": "second failed stage",
        "staging_relative_path": "submissions/VA-047/versions/.staging/0004.tmp",
        "relative_path": "submissions/VA-047/versions/0004/submission.md",
    }
    orphan_one = "submissions/VA-098/versions/.staging/a.tmp"
    orphan_two = "submissions/VA-099/versions/.staging/b.tmp"
    responses = [
        {
            "actor_surface": "vigil-assess",
            "recovered_version_ids": [77],
            "failed_version_ids": [12],
            "failed_versions": [failed_one],
            "failed_versions_page": {
                "offset": 0,
                "limit": 1,
                "returned": 1,
                "total": 2,
                "has_more": True,
                "next_offset": 1,
            },
            "orphaned_staging_paths": [orphan_one],
            "orphaned_staging_page": {
                "limit": 1,
                "returned": 1,
                "has_more": True,
                "next_after": orphan_one,
            },
        },
        {
            "actor_surface": "vigil-assess",
            "recovered_version_ids": [],
            "failed_version_ids": [13],
            "failed_versions": [failed_two],
            "failed_versions_page": {
                "offset": 1,
                "limit": 1,
                "returned": 1,
                "total": 2,
                "has_more": False,
                "next_offset": None,
            },
            "orphaned_staging_paths": [orphan_two],
            "orphaned_staging_page": {
                "limit": 1,
                "returned": 1,
                "has_more": False,
                "next_after": None,
            },
        },
    ]

    class PagedRecoveryClient(_FakeClient):
        def post(self, endpoint: str, payload: dict) -> dict:
            self.posts.append((endpoint, payload))
            assert endpoint == "submissions/recover"
            return responses.pop(0)

    fake = PagedRecoveryClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "--recover", "--json"], str(tmp_path))

    export_submission.run(args)

    result = json.loads(capsys.readouterr().out)
    assert result["recovered_version_ids"] == [77]
    assert result["failed_version_ids"] == [12, 13]
    assert result["failed_versions"] == [failed_one, failed_two]
    assert result["orphaned_staging_paths"] == [orphan_one, orphan_two]
    assert result["failed_versions_page"]["returned"] == 2
    assert result["failed_versions_page"]["has_more"] is False
    assert result["failed_versions_page"]["next_offset"] is None
    assert result["orphaned_staging_page"]["returned"] == 2
    assert result["orphaned_staging_page"]["has_more"] is False
    assert result["orphaned_staging_page"]["next_after"] is None
    assert fake.posts == [
        ("submissions/recover", {"actor_surface": "vigil-assess"}),
        (
            "submissions/recover",
            {
                "actor_surface": "vigil-assess",
                "failed_version_offset": 1,
                "orphan_after": orphan_one,
            },
        ),
    ]


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
    finding["verification_status"] = "confirmed"
    finding["notes"] = "MECHANISM: no E00207 caller-authz on qtame writes. REACHABILITY: prod accepted."
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    details = body[body.index("## OPERATOR DETAILS"):]  # below the never-paste line
    assert "Merged into: EX-003" in details
    assert "missing-flauthz:tame-writes" in details
    assert "broken-function-level-authorization" in details
    assert "Chain rationale" in details and "VA-002 oracle" in details
    assert "Propagation verdict" in details
    assert "Verification status: confirmed" in details
    assert "Discovered by: exploit-developer" in details
    assert "Investigation notes" in details and "no E00207" in details
    # notes never leak above the paste line
    assert "no E00207" not in body[: body.index("## OPERATOR DETAILS")]


def test_operator_details_and_context_preserve_structured_verification_audit(
    tmp_path, monkeypatch, capsys
):
    finding = _finding(details=_complete_details())
    finding["verification_audit"] = {
        "proof_receipt_ids": [46, 44, 45],
        "proof_receipt_total": 3,
        "counter_checks": [
            {
                "id": 12,
                "transition_id": 31,
                "verifier_dispatch_id": 8,
                "method": "cross-tenant negative control",
                "expected_result": "another tenant's record is returned",
                "observed_result": "every request was denied before the read",
                "falsified_claim": "tenant isolation can be bypassed",
                "completed": True,
                "proof_receipt_ids": [44, 45],
                "created_at": "2026-09-09 12:00:00",
            }
        ],
        "counter_check_total": 1,
        "severity_variances": [
            {
                "id": 13,
                "transition_id": 32,
                "normal_band": "medium",
                "chosen_severity": "high",
                "actor": "code-vuln-verifier",
                "reason": "Contractual breach notification applies.",
                "proof_receipt_id": 46,
                "created_at": "2026-09-09 12:01:00",
            }
        ],
        "severity_variance_total": 1,
        "record_limit": 100,
        "truncated": False,
    }
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)

    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--draft"],
        str(tmp_path),
    )
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    operator_details = body[body.index("## OPERATOR DETAILS") :]
    assert "Structured verification audit" in operator_details
    assert "cross-tenant negative control" in operator_details
    assert "every request was denied before the read" in operator_details
    assert "tenant isolation can be bypassed" in operator_details
    assert "Contractual breach notification applies." in operator_details
    assert "Proof receipts: 44, 45" in operator_details
    assert "Proof receipt: 46" in operator_details
    assert "Decision proof receipts: 46, 44, 45" in operator_details

    context = json.loads(
        (tmp_path / "submissions" / "VA-047" / "submission-context.json").read_text()
    )
    assert context["verification_audit"] == finding["verification_audit"]


def test_location_method_not_doubled(tmp_path, monkeypatch, capsys):
    """canonical_location already carrying the method must not become 'POST POST …'."""
    finding = _finding(details=_complete_details(request_method="POST"))
    finding["canonical_location"] = "POST https://app.example.com/api/tame/qtameSubmit"
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "POST POST" not in body
    assert "Location: POST https://app.example.com/api/tame/qtameSubmit" in body


def test_location_method_kept_when_location_merely_starts_with_the_verb(
    tmp_path, monkeypatch, capsys
):
    """The reference Location line composes the verb; the pasteable Asset does not.

    Under OPERATOR DETAILS, below the never-paste line, composing
    `request_method` onto the location gives the report-writer the fuller picture —
    that section exists to gather context. The dedup there compares the location's
    first whitespace-delimited token rather than testing a prefix, so
    'POSTMAN collection endpoint …' keeps its real verb instead of having it
    swallowed. Above the paste boundary nothing is composed: Asset is
    `canonical_location` verbatim, so the author decides whether the verb belongs in
    what a triager reads.
    """
    finding = _finding(details=_complete_details(request_method="POST"))
    finding["canonical_location"] = "POSTMAN collection endpoint /api/orders/1001"
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    header = body.partition("\n---\n")[0]
    assert "**Asset:** POSTMAN collection endpoint /api/orders/1001" in header
    assert "- Location: POST POSTMAN collection endpoint /api/orders/1001" in body


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

    # final: blocks.
    fake_final = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake_final)
    args = _parse(["submission", "VA-047", "--platform", platform], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert marker in str(exc.value)
    assert fake_final.posts == []

    # draft: writes with the matching marker.
    fake_draft = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake_draft)
    args = _parse(["submission", "VA-047", "--platform", platform, "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert f"[NEEDS: {marker}]" in _submission_path(tmp_path).read_text()


@pytest.mark.parametrize(
    ("field", "marker"),
    [
        ("summary", "summary"),
        ("steps_to_reproduce", "steps to reproduce"),
        ("evidence", "evidence"),
        ("remediation", "remediation"),
    ],
)
def test_final_requires_every_outward_facing_body_section(
    tmp_path,
    monkeypatch,
    field,
    marker,
):
    details = _complete_details()
    finding = _finding(details=details)
    if field == "summary":
        finding["summary"] = ""
    elif field == "remediation":
        details[field] = ""
        finding["remediation"] = ""
        finding["details"] = dict(details)
    else:
        details[field] = [] if field == "steps_to_reproduce" else ""
        finding["details"] = dict(details)

    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    with pytest.raises(AssessError) as exc:
        export_submission.run(args)

    assert marker in str(exc.value)
    assert not _submission_path(tmp_path).exists()


def test_missing_proof_gates_final(tmp_path, monkeypatch, capsys):
    # No poc pair, no poc_code, no evidence_ref -> no proof.
    details = _complete_details(poc_request={}, poc_response={})
    finding = _finding(details=details, evidence_ref="")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "indexed, present evidence artifact" in str(exc.value)


def test_indexed_present_evidence_ref_satisfies_durable_proof(tmp_path, monkeypatch, capsys):
    details = _complete_details(poc_request={}, poc_response={})
    finding = _finding(details=details, evidence_ref="scans/idor-orders.txt")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    body = _submission_path(tmp_path).read_text()
    assert "scans/idor-orders.txt" in body
    assert "[NEEDS: proof" not in body


def test_inline_poc_does_not_replace_durable_evidence(tmp_path, monkeypatch, capsys):
    finding = _finding(details=_complete_details(), evidence_ref="")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)

    final_args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(final_args)
    assert "indexed, present evidence artifact" in str(exc.value)
    assert not _submission_path(tmp_path).exists()

    draft_args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--draft"],
        str(tmp_path),
    )
    export_submission.run(draft_args)
    capsys.readouterr()
    context = _context(tmp_path)
    assert context["proof"]["has_content_proof"] is True
    assert context["proof"]["has_durable_proof"] is False


@pytest.mark.parametrize(
    "evidence_ref, artifacts",
    [
        ("scans/idor-orders.txt", []),
        (
            "scans/idor-orders.txt",
            [{"relative_path": "scans/idor-orders.txt", "present": False, "related_finding_slug": "VA-047"}],
        ),
        (
            "scans/idor-orders.txt",
            [{"relative_path": "scans/idor-orders.txt", "present": True, "related_finding_slug": "VA-047"}],
        ),
        ("https://evidence.example/idor", []),
        ("../outside.txt", []),
        ("/tmp/outside.txt", []),
    ],
)
def test_final_rejects_non_durable_evidence(tmp_path, monkeypatch, evidence_ref, artifacts):
    fake = _FakeClient(_finding(details=_complete_details(), evidence_ref=evidence_ref), artifacts=artifacts)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "indexed, present evidence artifact" in str(exc.value)
    assert not _submission_path(tmp_path).exists()


def test_final_rejects_evidence_indexed_to_another_finding(tmp_path, monkeypatch):
    evidence = tmp_path / "scans" / "idor-orders.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("durable proof\n", encoding="utf-8")
    fake = _FakeClient(
        _finding(details=_complete_details()),
        artifacts=[
            {
                "id": 7,
                "relative_path": "scans/idor-orders.txt",
                "present": True,
                "related_finding_slug": "VA-999",
            }
        ],
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    with pytest.raises(AssessError, match="indexed, present evidence artifact"):
        export_submission.run(args)


def test_final_finds_exact_evidence_beyond_first_search_page(tmp_path, monkeypatch, capsys):
    evidence = tmp_path / "scans" / "idor-orders.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("durable proof\n", encoding="utf-8")
    decoys = [
        {
            "id": index,
            "relative_path": f"scans/decoy-{index}.txt",
            "present": True,
            "related_finding_slug": "VA-047",
        }
        for index in range(1000)
    ]
    decoys.append(
        {
            "id": 2001,
            "relative_path": "scans/idor-orders.txt",
            "present": True,
            "related_finding_slug": "VA-047",
        }
    )
    fake = _FakeClient(_finding(details=_complete_details()), artifacts=decoys)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    export_submission.run(args)
    capsys.readouterr()

    assert _submission_path(tmp_path).exists()
    assert any("offset=1000" in endpoint for endpoint in fake.gets)


def test_final_uses_evidence_artifact_id_as_the_exact_link(
    tmp_path, monkeypatch, capsys
):
    evidence = tmp_path / "scans" / "idor-orders.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("durable proof\n", encoding="utf-8")
    finding = _finding(details=_complete_details())
    finding["evidence_artifact_id"] = 700
    fake = _FakeClient(
        finding,
        artifacts=[
            {
                "id": 700,
                "relative_path": "scans/idor-orders.txt",
                "present": True,
                "related_finding_slug": None,
            }
        ],
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    export_submission.run(args)
    capsys.readouterr()

    assert "artifacts/700" in fake.gets
    assert not any(endpoint.startswith("artifacts/search?") for endpoint in fake.gets)


def test_final_rejects_evidence_artifact_id_path_mismatch(
    tmp_path, monkeypatch
):
    evidence = tmp_path / "scans" / "idor-orders.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("durable proof\n", encoding="utf-8")
    finding = _finding(details=_complete_details())
    finding["evidence_artifact_id"] = 701
    fake = _FakeClient(
        finding,
        artifacts=[
            {
                "id": 701,
                "relative_path": "scans/other.txt",
                "present": True,
                "related_finding_slug": "VA-047",
            },
            {
                "id": 702,
                "relative_path": "scans/idor-orders.txt",
                "present": True,
                "related_finding_slug": "VA-047",
            },
        ],
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    with pytest.raises(AssessError, match="indexed, present evidence artifact"):
        export_submission.run(args)

    assert "artifacts/701" in fake.gets
    assert not _submission_path(tmp_path).exists()


@pytest.mark.parametrize("reference", ["absolute", "mounted"])
def test_final_normalizes_contained_evidence_paths(tmp_path, monkeypatch, capsys, reference):
    evidence_ref = (
        str(tmp_path / "scans" / "idor-orders.txt")
        if reference == "absolute"
        else "/engagements/test-eng/scans/idor-orders.txt"
    )
    fake = _FakeClient(_finding(details=_complete_details(), evidence_ref=evidence_ref))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    proof = _context(tmp_path)["proof"]
    assert proof["evidence_path"] == "scans/idor-orders.txt"
    assert proof["has_durable_proof"] is True


def test_hackerone_weakness_falls_back_to_cwe_id(tmp_path, monkeypatch, capsys):
    details = _complete_details(weakness="", cwe_id="CWE-639")
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "hackerone"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert "**Weakness:** CWE-639" in _submission_path(tmp_path).read_text()


@pytest.mark.parametrize(
    "field, value",
    [
        ("workflow_status", "draft"),
        ("workflow_status", "merged"),
        ("workflow_status", "false_positive"),
        ("verification_status", "unreviewed"),
        ("verification_status", "pending_runtime_proof"),
    ],
)
def test_final_requires_verified_report_candidate(tmp_path, monkeypatch, field, value):
    finding = _finding(details=_complete_details())
    finding[field] = value
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert field in str(exc.value)
    assert not _submission_path(tmp_path).exists()


def test_final_blocks_only_target_specific_readiness_blockers(tmp_path, monkeypatch, capsys):
    unrelated = {"kind": "finding_field_quality", "slug": "VA-999", "detail": "unrelated"}
    fake = _FakeClient(
        _finding(details=_complete_details()),
        readiness={"ready": False, "blockers": [unrelated], "advisories": []},
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert _submission_path(tmp_path).exists()

    target_dir = tmp_path / "target-blocked"
    target = {"kind": "duplicate_root_cause", "slugs": ["VA-047", "VA-048"], "detail": "duplicate"}
    fake = _FakeClient(
        _finding(details=_complete_details()),
        readiness={"ready": False, "blockers": [unrelated, target], "advisories": []},
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--output", str(target_dir)],
        str(tmp_path),
    )
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "duplicate_root_cause" in str(exc.value)
    assert not (target_dir / "submission.md").exists()


def test_flags_supply_taxonomy(tmp_path, monkeypatch, capsys):
    # Details omit vrt/weakness; the CLI flags supply them and satisfy the gate.
    details = _complete_details(vrt_category="", weakness="")
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--vrt-category", "server_security_misconfiguration"],
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
    args = _parse(["submission", "VA-047", "--platform", "direct"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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


def test_retired_links_are_not_exported_as_current_evidence(
    tmp_path, monkeypatch, capsys
):
    """A link the operator RETIRED is history, not evidence.

    ``list_finding_links`` deliberately returns retired rows so the history stays
    inspectable; the export path is the layer that has to tell "was linked once"
    from "is evidence now". Without the filter the withdrawn run comes back in
    OPERATOR DETAILS and steers the report writer at material the operator
    explicitly invalidated.
    """
    links = [
        {
            "finding_slug": "VA-047",
            "target_kind": "command_run",
            "target_id": 5,
            "retired_at": None,
        },
        {
            "finding_slug": "VA-047",
            "target_kind": "command_run",
            "target_id": 6,
            "retired_at": "2026-08-01T12:00:00Z",
        },
    ]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "reproduce IDOR", "return_code": 0},
        6: {"id": 6, "command": "curl -sk https://app.example.com/retired-probe", "intent": "withdrawn", "return_code": 0},
    }
    fake = _FakeClient(_finding(details=_complete_details()), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "orders/1002" in body
    assert "retired-probe" not in body

    runs = _context(tmp_path)["linked_command_runs"]
    assert [r["id"] for r in runs] == [5]
    # The retired run is not even fetched — the filter runs before resolution.
    assert "command-runs/6" not in fake.gets


def test_empty_retired_at_is_treated_as_a_live_link(tmp_path, monkeypatch, capsys):
    # The backend serializes "never retired" as null, but an empty string is the
    # same statement; neither may drop a live link out of the submission.
    links = [
        {"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5, "retired_at": ""},
    ]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "reproduce IDOR", "return_code": 0},
    }
    fake = _FakeClient(_finding(details=_complete_details()), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    assert [r["id"] for r in _context(tmp_path)["linked_command_runs"]] == [5]


# -- repro runs: the audit trail behind Steps to Reproduce --------------------

def test_repro_runs_render_real_argv_separately_from_linked_runs(
    tmp_path, monkeypatch, capsys
):
    """`details.repro_runs` renders the argv that actually produced the steps.

    Kept in its own block, and sourced independently of the evidence links, because
    the two claims differ: a linked run is evidence the finding is real, a repro run
    is the audit row behind one authored step. Rendering the row's REAL command is
    the whole point — it is what lets a reader diff a claimed step against what ran
    instead of trusting a paraphrase.
    """
    links = [{"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5}]
    command_runs = {
        5: {"id": 5, "command": "curl -sk https://app.example.com/orders/1002", "intent": "evidence", "return_code": 0},
        # Declared in step order and NOT linked as evidence — the two sets are
        # independent, so a repro run must render without an evidence link.
        11: {"id": 11, "command": "curl -sk -b 'session=member_a' https://app.example.com/login", "intent": "auth as member A", "return_code": 0},
        12: {"id": 12, "command": "curl -sk -b 'session=member_a' https://app.example.com/orders/1001", "intent": "read B's order", "return_code": 0},
    }
    details = _complete_details(repro_runs=[11, "12"])
    fake = _FakeClient(_finding(details=details), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    ref_idx = body.index("## OPERATOR DETAILS")
    reference = body[ref_idx:]
    # A separate block from the linked-evidence runs, with the real argv in it.
    assert "**Reproduction runs**" in reference
    assert "**Linked command runs**" in reference
    assert "curl -sk -b 'session=member_a' https://app.example.com/login" in reference
    assert "curl -sk -b 'session=member_a' https://app.example.com/orders/1001" in reference
    # Never above the paste boundary — this is reference, like every other run.
    assert "session=member_a" not in body[:ref_idx]

    context = _context(tmp_path)
    assert [r["id"] for r in context["repro_runs"]] == [11, 12]  # declared order
    assert context["repro_runs_unresolved"] == []
    # A string id is accepted and resolved the same as an integer one.
    assert "command-runs/11" in fake.gets and "command-runs/12" in fake.gets
    # Steps ARE backed, so no "no command run stands behind these steps" advisory.
    assert not any("repro_runs is empty" in a for a in context["advisories"])


def test_authored_steps_without_repro_runs_advise_but_never_block(
    tmp_path, monkeypatch, capsys
):
    """Unbacked steps are an advisory, not a refusal.

    The steps may well be right; the problem is that nobody can tell them apart
    from a reconstruction. Blocking here would gate every finding recorded before
    the field existed, so the render says so and publishes.
    """
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    captured = capsys.readouterr()

    assert _submission_path(tmp_path).exists()  # final mode still publishes
    context = _context(tmp_path)
    assert any("repro_runs is empty" in a for a in context["advisories"])
    assert "ADVISORY" in captured.err
    # An advisory is an opinion, never a hygiene warning (those fail closed).
    assert not any("repro_runs" in w for w in context["hygiene_warnings"])
    assert context["repro_runs"] == []


def test_draft_marks_missing_repro_runs_with_a_needs_marker(tmp_path, monkeypatch, capsys):
    """A draft names the gap where the runs would have rendered."""
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "[NEEDS: details.repro_runs" in body
    # Below the never-paste divider with the rest of the reference material.
    assert body.index("[NEEDS: details.repro_runs") > body.index("## OPERATOR DETAILS")


@pytest.mark.parametrize("draft", [True, False])
def test_unresolved_repro_runs_advise_but_never_block(tmp_path, monkeypatch, capsys, draft):
    """A declared run the audit log cannot produce is reported, not refused.

    It IS the failure this field exists to catch — a step attributed to a run that
    never happened — but the export cannot tell that case apart from a run row that
    is momentarily unreachable, and refusing on the ambiguity would let a backend
    hiccup block the publish of a finished, verified finding. So it advises, in both
    modes, and the report-writer decides. Draft and final are asserted together
    because the whole point is that they behave the same here.
    """
    command_runs = {11: {"id": 11, "command": "curl -sk https://app.example.com/login", "return_code": 0}}
    details = _complete_details(repro_runs=[11, 99, "not-an-id"])
    fake = _FakeClient(_finding(details=details), command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    argv = ["submission", "VA-047", "--platform", "bugcrowd"] + (["--draft"] if draft else [])
    export_submission.run(_parse(argv, str(tmp_path)))
    captured = capsys.readouterr()

    # Published either way — nothing about repro runs fails a final export closed.
    assert _submission_path(tmp_path).exists()
    context = _context(tmp_path)
    assert "ADVISORY" in captured.err
    assert any("details.repro_runs cites 99" in a for a in context["advisories"])
    assert any("details.repro_runs cites 'not-an-id'" in a for a in context["advisories"])
    # Advisories are opinions; a hygiene warning is a fact that DOES fail closed.
    # Keeping these apart is what makes the non-blocking behaviour reliable.
    assert not any("repro_runs" in w for w in context["hygiene_warnings"])
    # The backend's own reason is carried through, not replaced by a guess at it —
    # "does not resolve" covers both a 404 and a transient failure honestly.
    assert context["repro_runs_unresolved"] == [
        "99 (does not resolve: HTTP 404: command-run 99 not found)",
        "'not-an-id' (not a command-run id)",
    ]

    body = _submission_path(tmp_path).read_text()
    # The runs that DID resolve still render — one bad id does not blank the block.
    assert "curl -sk https://app.example.com/login" in body
    # ...and the bad ids are named where the missing argv would have been, not only
    # in the advisories block, because that is where the report-writer is reading.
    reference = body[body.index("## OPERATOR DETAILS"):]
    assert "**Unresolved** — `details.repro_runs` cites 99" in reference
    # An unresolved claim suppresses the "nothing stands behind these steps"
    # advisory: the finding's problem is a wrong id, not an absent one, and saying
    # both would point the report-writer at two different fixes.
    assert not any("repro_runs is empty" in a for a in context["advisories"])


def test_submission_outputs_render_proof_verbatim(tmp_path, monkeypatch, capsys):
    """Nothing is masked on the way out — the render is faithful to the finding.

    A masking pass over the render breaks the deliverable three ways, all pinned
    here: collapsing every ``-b``/``--cookie`` argument to one placeholder leaves a
    two-identity repro showing one identity, rewriting a credential the TARGET
    disclosed erases the finding itself, and running over ``details_json`` as
    serialized text can invalidate the JSON and blank every details-sourced section.
    Masking is the report-writer's decision, stored in the finding so a re-render
    reproduces it.
    """
    admin = "session=admin_a1b2c3d4"
    member = "session=member_e5f6g7h8"
    links = [
        {"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5},
    ]
    command_runs = {
        5: {
            "id": 5,
            # The admin-vs-member distinction IS the finding; a masking pass that
            # rewrites both -b values to one placeholder erases it.
            "command": (
                f"curl -b '{admin}' https://app.example.com/orders/1001; "
                f"curl -b '{member}' https://app.example.com/orders/1001"
            ),
            "intent": "cross-identity read as admin then member",
            "return_code": 0,
        },
    }
    details = _complete_details(
        # A double-quoted header inside details: any rewrite over the serialized
        # ``details_json`` can consume this JSON escape and blank the sections below.
        steps_to_reproduce=[
            'Replay: curl -s https://app.example.com/orders/1001 -H "Cookie: session=abc123def456"',
            "Observe another member's order fields",
        ],
        attack_scenario="An attacker replays the session to read other members' orders.",
        # The disclosed credential IS the proof — masking it leaves nothing.
        poc_response={
            "status": 200,
            "headers": {"set-cookie": "__prerender_bypass=0c3eab9f7d21"},
            "body": '{"owner":"someone-else"}',
        },
    )
    fake = _FakeClient(
        _finding(details=details),
        links=links,
        command_runs=command_runs,
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd"],
        str(tmp_path),
    )

    export_submission.run(args)
    capsys.readouterr()

    markdown = _submission_path(tmp_path).read_text()
    context = (
        tmp_path / "submissions" / "VA-047" / "submission-context.json"
    ).read_text()

    # Each identity survives independently — the repro is still runnable.
    assert admin in markdown
    assert member in markdown
    # The target's disclosed credential — the proof itself — is intact.
    assert "__prerender_bypass=0c3eab9f7d21" in markdown
    # A double-quoted header in details costs nothing below it.
    assert "### Attack Scenario" in markdown
    assert '-H "Cookie: session=abc123def456"' in markdown
    assert "<YOUR_SESSION_COOKIE>" not in markdown
    assert "<REDACTED_CREDENTIAL>" not in markdown
    assert "<YOUR_SESSION_COOKIE>" not in context
    # The trust label belongs to internal/prompt-bound renderings. It must never
    # become authored platform submission prose.
    assert UNTRUSTED_DATA_NOTICE not in markdown


@pytest.mark.parametrize("draft", [True, False])
def test_submission_credential_store_shape_is_flagged_or_refused_without_redaction(
    tmp_path, monkeypatch, capsys, draft
):
    stored_credential = {
        "credential_key": "member-cookie",
        "kind": "cookie",
        "principal": "member@example.test",
        "secret": "session=preserve-authored-bytes",
    }
    details = _complete_details(
        evidence=(
            "An internal credential-store row was pasted here by mistake: "
            + json.dumps(stored_credential, sort_keys=True)
        )
    )
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    argv = ["submission", "VA-047", "--platform", "bugcrowd"]
    if draft:
        argv.append("--draft")
    args = _parse(argv, str(tmp_path))

    if draft:
        export_submission.run(args)
        body = _submission_path(tmp_path).read_text()
        assert stored_credential["secret"] in body
        warnings = "\n".join(_context(tmp_path)["hygiene_warnings"])
        assert "credential-store object" in warnings
        assert stored_credential["secret"] not in warnings
        assert "WARN export submission" in capsys.readouterr().err
    else:
        with pytest.raises(AssessError, match="credential-store object"):
            export_submission.run(args)
        assert not _submission_path(tmp_path).exists()
        assert fake.posts == []


def test_correction_history_is_preserved_only_below_submission_boundary(
    tmp_path, monkeypatch, capsys
):
    correction = "Retracts VA-001: the original response belonged to the test account."
    fake = _FakeClient(
        _finding(details=_complete_details(correction_history=[correction]))
    )
    _install(monkeypatch, tmp_path, fake)

    export_submission.run(
        _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    )
    capsys.readouterr()

    markdown = _submission_path(tmp_path).read_text()
    pasteable, operator = markdown.split(
        "## OPERATOR DETAILS — NOT FOR SUBMISSION", 1
    )
    assert correction not in pasteable
    assert correction in operator


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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
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
    assert "WARN export submission" in err


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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert "VA-047" in body[: body.index("## OPERATOR DETAILS")]  # leaked above the paste line
    warnings = _context(tmp_path)["hygiene_warnings"]
    assert any("finding slug" in w and "VA-047" in w for w in warnings)


# -- steps: rendered verbatim, never renumbered or stripped -------------------

def test_steps_render_verbatim_without_renumbering(tmp_path, monkeypatch, capsys):
    """Authored step text reaches the submission byte-for-byte.

    The renderer imposes no counter of its own and strips nothing, so an author who
    numbers their own steps keeps that numbering — including the non-sequential and
    sub-step forms (`2a.`, `2024.`) that any strip-and-renumber pass would rewrite
    into something the author never wrote. Each step becomes one `- ` item purely so
    the steps stay separate lines when pasted into a platform form.
    """
    details = _complete_details(
        steps_to_reproduce=[
            "1. Log in as member A",
            "2) GET /orders/1001 (member B's order)",
            "2a. Repeat as the second member",
            "2024. Renewal year field accepts a past date",
            "Observe member B's data in the response",
        ]
    )
    fake = _FakeClient(_finding(details=details))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    steps = body[body.index("### Steps to Reproduce"):body.index("### Evidence")]
    for authored in (
        "1. Log in as member A",
        "2) GET /orders/1001 (member B's order)",
        "2a. Repeat as the second member",
        "2024. Renewal year field accepts a past date",
        "Observe member B's data in the response",
    ):
        assert authored in steps, f"step not rendered verbatim: {authored}"
    # No marker and no counter are contributed, so nothing can double up.
    assert "1. 1." not in steps
    assert "2. 2)" not in steps
    assert "- 1. Log in" not in steps


def test_authored_step_block_renders_byte_for_byte(tmp_path, monkeypatch, capsys):
    """A single authored string is the preferred shape and passes through untouched.

    Prose elsewhere in a submission cites step numbers ("follow the location header
    from step 2"); those references resolve only against numbers the author wrote,
    so the whole block ships exactly as stored.
    """
    block = (
        "1. Log in as member A and note the session cookie\n"
        "2. GET /orders/1001 — member B's order\n"
        "3. Follow the location header from step 2 and observe member B's data"
    )
    details = _complete_details(steps_to_reproduce=block)
    _install(monkeypatch, tmp_path, _FakeClient(_finding(details=details)))
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    assert block in body
    # A string is authored content, not a missing field — the final gate passed.
    assert "[NEEDS: steps to reproduce]" not in body
    assert _context(tmp_path)["missing"] == []


# -- hygiene warnings: diagnostic in draft, strict in final -------------------

@pytest.mark.parametrize(
    "title, expect_advisory",
    [
        # 15 words -> advises.
        ("This finding demonstrates a very long run on submission title that clearly exceeds the limit", True),
        # 10 words -> silent.
        ("Short concise title that stays under the required word limit", False),
    ],
)
def test_title_word_count_advises_but_never_blocks(
    tmp_path, monkeypatch, capsys, title, expect_advisory
):
    """Title length is editorial advice, not a gate.

    Failing a FINAL export on it would let a 13-word title block publication of a
    finished, verified finding — code overruling the author on prose. It is reported
    as an advisory and kept out of `hygiene_warnings` (whose entries DO fail closed)
    so the two authorities cannot be confused.
    """
    finding = _finding(details=_complete_details())
    finding["title"] = title
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    export_submission.run(args)
    captured = capsys.readouterr()

    # Publishes either way — a long title never blocks.
    assert _submission_path(tmp_path).exists()
    context = _context(tmp_path)
    # Never a hygiene warning, whatever the length.
    assert not any("max 12" in w for w in context["hygiene_warnings"])

    body = _submission_path(tmp_path).read_text()
    title_advisories = [a for a in context["advisories"] if "max 12" in a]
    if expect_advisory:
        assert title_advisories
        assert "ADVISORY" in captured.err
        assert "**Advisories** (non-blocking — your call):" in body
    else:
        # Scoped to the TITLE advisory: this finding also has no `repro_runs`, which
        # earns its own advisory (see the repro-runs tests below). Asserting the
        # whole list were empty would make this title test fail on any unrelated
        # advisory the command learns to emit.
        assert title_advisories == []


# -- overwrite guard ----------------------------------------------------------

def test_overwrite_guard(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    # Second run without --overwrite must refuse.
    fake2 = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake2)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "already exists" in str(exc.value)
    assert fake2.posts == []  # nothing re-registered

    # With --overwrite it proceeds.
    fake3 = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake3)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--overwrite"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert any(ep == "artifacts" for ep, _ in fake3.posts)


# -- json output --------------------------------------------------------------

def test_json_summary_shape(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--json"], str(tmp_path))
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
    assert out["has_content_proof"] is True
    assert out["has_durable_proof"] is True
    assert "has_proof" not in out


def test_final_output_must_be_inside_engagement(tmp_path, monkeypatch):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--output", str(outside)],
        str(tmp_path),
    )
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    assert "inside the engagement" in str(exc.value)
    assert not (outside / "submission.md").exists()


def test_final_fails_when_submission_artifact_registration_fails(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(
        _finding(details=_complete_details()),
        post_error="HTTP 422: artifact payload rejected before commit",
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_submission.run(args)
    captured = capsys.readouterr()
    assert "artifact registration failed" in str(exc.value)
    assert "Wrote final" not in captured.out
    assert not _submission_path(tmp_path).exists()
    assert not (_submission_path(tmp_path).parent / "submission-context.json").exists()


def test_final_rejects_malformed_submission_artifact_receipt(
    tmp_path, monkeypatch, capsys
):
    submission = _submission_path(tmp_path)
    context = submission.parent / "submission-context.json"
    submission.parent.mkdir(parents=True)
    submission.write_text("previous submission\n", encoding="utf-8")
    context.write_text('{"previous": true}\n', encoding="utf-8")
    fake = _FakeClient(
        _finding(details=_complete_details()),
        post_response={"message": "accepted"},
    )
    _install(monkeypatch, tmp_path, fake)
    written_before_receipt: dict[str, bytes] = {}
    original_post = fake.post

    def capture_written_files(endpoint: str, payload: dict) -> dict:
        if endpoint == "artifacts":
            written_before_receipt["submission"] = submission.read_bytes()
            written_before_receipt["context"] = context.read_bytes()
        return original_post(endpoint, payload)

    fake.post = capture_written_files
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--overwrite"],
        str(tmp_path),
    )

    with pytest.raises(AssessError, match="artifact registration failed") as exc:
        export_submission.run(args)

    captured = capsys.readouterr()
    assert "do not retry automatically" in str(exc.value)
    assert "reconcil" in str(exc.value)
    assert "Wrote final" not in captured.out
    assert submission.read_bytes() == written_before_receipt["submission"]
    assert context.read_bytes() == written_before_receipt["context"]
    assert submission.read_bytes() != b"previous submission\n"
    assert context.read_bytes() != b'{"previous": true}\n'


def test_failed_final_registration_restores_overwritten_outputs(tmp_path, monkeypatch):
    submission = _submission_path(tmp_path)
    context = submission.parent / "submission-context.json"
    submission.parent.mkdir(parents=True)
    submission.write_text("previous submission\n", encoding="utf-8")
    context.write_text('{"previous": true}\n', encoding="utf-8")
    fake = _FakeClient(
        _finding(details=_complete_details()),
        post_error="HTTP 422: artifact payload rejected before commit",
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--overwrite"],
        str(tmp_path),
    )

    with pytest.raises(AssessError, match="artifact registration failed"):
        export_submission.run(args)

    assert submission.read_text(encoding="utf-8") == "previous submission\n"
    assert context.read_text(encoding="utf-8") == '{"previous": true}\n'


def test_final_context_write_failure_rolls_back_submission(tmp_path, monkeypatch):
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    original_write_text = Path.write_text

    def fail_context_write(path: Path, data: str, *args, **kwargs):
        if path.name == "submission-context.json":
            raise OSError("synthetic context write failure")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_context_write)

    with pytest.raises(AssessError, match="output write failed"):
        export_submission.run(args)

    assert not _submission_path(tmp_path).exists()
    assert not (_submission_path(tmp_path).parent / "submission-context.json").exists()


def test_draft_surfaces_target_readiness_blocker_without_gating(tmp_path, monkeypatch, capsys):
    blocker = {"kind": "finding_field_quality", "slug": "VA-047", "detail": "missing evidence prose"}
    fake = _FakeClient(
        _finding(details=_complete_details()),
        readiness={"ready": False, "blockers": [blocker], "advisories": []},
    )
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()
    assert _context(tmp_path)["readiness_blockers"] == [blocker]


# -- A2: operational-header overlay (rendered FROM finding fields) ------------

def _write_scope(engagement_dir, required_headers):
    """Minimal scope.json so rate_caps_for_dir surfaces the Deconfliction header."""
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["app.example.com"], "required_headers": required_headers}),
        encoding="utf-8",
    )


def test_a2_operational_header_renders_from_fields(tmp_path, monkeypatch, capsys):
    """The Asset/Run/Pass if/Deconfliction overlay is emitted in the copy-paste
    header (above the first `---`), each line sourced from a finding field so a
    re-render reproduces it — not hand-applied text a re-render would wipe.

    Nothing above the paste boundary is composed by the exporter. Asset renders
    `canonical_location` verbatim, and there is no `POC:` line: a pointer derived
    from `evidence_ref` names an internal `scans/…` artifact, which means nothing to
    a triager and puts the engagement's layout in text the operator pastes. The
    proof pointer stays under OPERATOR DETAILS.
    """
    _write_scope(tmp_path, {"X-Bug-Bounty": "researcher"})
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
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    header, sep, _sections = body.partition("\n---\n")
    assert sep == "\n---\n"
    assert "**Asset:** https://app.example.com/api/orders/1001" in header
    assert "**Run:** bash scans/va-003-poc.sh" in header
    assert "**Pass if:** HTTP 200 returns another member's order record" in header
    assert "**Deconfliction:** X-Bug-Bounty: researcher" in header
    # No derived proof pointer in the pasteable block; it lives below the line.
    # The artifact path appears in the header ONLY inside the authored Run command —
    # the author put it there, so it stays; nothing derives a second copy from
    # evidence_ref.
    assert "**POC:**" not in body
    assert header.count("scans/va-003-poc.sh") == 1
    assert "- **Evidence reference:** scans/va-003-poc.sh" in body
    # Still the platform copy-paste layout — the overlay sits after CVSS, not before Title.
    assert body.startswith("**Title:**")


def test_a2_operational_header_survives_overwrite(tmp_path, monkeypatch, capsys):
    """The overlay is rebuilt from fields on `--overwrite`, so re-rendering never
    wipes it (the A2 defect being fixed)."""
    _write_scope(tmp_path, {"X-Bug-Bounty": "researcher"})
    finding = _finding(
        evidence_ref="scans/va-003-poc.sh",
        details=_complete_details(run="bash scans/va-003-poc.sh", pass_if="HTTP 200 leak"),
    )
    finding["canonical_location"] = "https://app.example.com/api/orders/1001"
    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--overwrite"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    header = _submission_path(tmp_path).read_text().partition("\n---\n")[0]
    for line in (
        "**Asset:** https://app.example.com/api/orders/1001",
        "**Run:** bash scans/va-003-poc.sh",
        "**Pass if:** HTTP 200 leak",
        "**Deconfliction:** X-Bug-Bounty: researcher",
    ):
        assert line in header


def test_a2_operational_lines_omitted_without_backing_data(tmp_path, monkeypatch, capsys):
    """No scope.json (no attribution header) and no run/pass_if → those lines are
    omitted entirely; the Asset line (from canonical_location) still renders."""
    finding = _finding(details=_complete_details())  # no run/pass_if, no scope.json written
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    header = _submission_path(tmp_path).read_text().partition("\n---\n")[0]
    assert "**Run:**" not in header
    assert "**Pass if:**" not in header
    assert "**Deconfliction:**" not in header
    assert "**Asset:** /orders/1001" in header  # canonical_location is present


def test_final_render_keeps_every_details_section(tmp_path, monkeypatch, capsys):
    """A FINAL, publishable submission carries all details-sourced content.

    This failure mode is silent and fires at the last step before filing: the strict
    gate reads the raw finding and passes, so any renderer that reads a mangled copy
    drops Attack Scenario, the operational header, the finding metadata and the whole
    structured-proof block at exit 0 with no warning. A section that was never
    rendered reads exactly like a section nobody wrote.
    """
    _write_scope(tmp_path, {"X-Bug-Bounty": "researcher"})
    details = _complete_details(
        steps_to_reproduce=[
            'curl -s https://app.example.com/orders/1001 -H "Cookie: session=abc123def456"',
        ],
        attack_scenario="An attacker reads any member's order by id.",
        cwe_id="CWE-639",
        owasp_category="A01:2021 Broken Access Control",
        run="bash scans/va-047-poc.sh",
        pass_if="HTTP 200 returns another member's order record",
    )
    finding = _finding(details=details)
    finding["canonical_location"] = "https://app.example.com/api/orders/1001"
    finding["notes"] = "Mechanism: no ownership check on the order id."
    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    for expected in (
        "### Attack Scenario",
        "**Run:** bash scans/va-047-poc.sh",
        "**Pass if:** HTTP 200 returns another member's order record",
        "**Asset:** https://app.example.com/api/orders/1001",
        "**Deconfliction:** X-Bug-Bounty: researcher",
        "- CWE: CWE-639",
        "- OWASP: A01:2021 Broken Access Control",
        "**PoC Request:**",
        "**PoC Response:**",
        "Investigation notes",
    ):
        assert expected in body, f"missing from final submission: {expected}"


def test_malformed_details_warn_instead_of_blanking_silently(
    tmp_path, monkeypatch, capsys
):
    """Corrupt details must announce themselves, not render as an unauthored finding."""
    finding = _finding(details=_complete_details())
    finding["details"] = '{"evidence": "truncated'  # an object is required
    _install(monkeypatch, tmp_path, _FakeClient(finding))
    args = _parse(
        ["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path)
    )

    export_submission.run(args)
    captured = capsys.readouterr()

    assert "details" in captured.err
    assert "not an object" in captured.err
    assert "VA-047" in captured.err


# -- prose advisories: length/shape opinions that never block -----------------
#
# Same authority split the title advisory is pinned on above: these are surfaced
# in the context JSON, on stderr, and under OPERATOR DETAILS, and NEVER added to
# `hygiene_warnings` (whose entries fail a final export closed). The unit tests
# below drive `prose_advisories` directly because the thing most likely to break
# them is markdown segmentation, and a false positive there costs the
# report-writer's trust in every advisory the command emits, existing ones
# included.

_BODY_SECTIONS = (
    ("summary", "Summary"),
    ("steps_to_reproduce", "Steps to Reproduce"),
    ("evidence", "Evidence"),
    ("attack_scenario", "Attack Scenario"),
    ("impact", "Impact"),
    ("remediation", "Remediation"),
)


def _body(operator_details: str = "", **sections: str) -> str:
    """A submission-shaped document: header block, `---`, `### ` sections, `---`,
    then the never-paste OPERATOR DETAILS reference."""
    unknown = set(sections) - {key for key, _ in _BODY_SECTIONS}
    assert not unknown, f"unknown section(s): {sorted(unknown)}"
    lines = ["**Title:** a title", "", "---", ""]
    for key, heading in _BODY_SECTIONS:
        if key in sections:
            lines += [f"### {heading}", "", sections[key], ""]
    lines += ["---", "", "## OPERATOR DETAILS — NOT FOR SUBMISSION", "", operator_details]
    return "\n".join(lines) + "\n"


def _words(count: int) -> str:
    """A grammatical sentence of exactly `count` words."""
    assert count >= 3
    return "The tenant " + " ".join(["reads"] * (count - 3)) + " everything."


def _tagged_words(tag: str, count: int) -> str:
    """`_words`, but distinguishable by its opening word, for quote-identity tests."""
    assert count >= 3
    return f"{tag} tenant " + " ".join(["reads"] * (count - 3)) + " everything."


def _advisories(**kwargs) -> list[str]:
    return export_submission.prose_advisories(_body(**kwargs))


def _only(advisories: list[str], needle: str) -> list[str]:
    return [a for a in advisories if needle in a]


@pytest.mark.parametrize("count, expect", [(26, True), (25, False)])
def test_sentence_length_advises_at_the_word_budget(count, expect):
    """25 words is the ceiling, so 25 is silent and 26 speaks."""
    hits = _only(_advisories(summary=_words(count)), "over 25 words")
    assert bool(hits) is expect
    if expect:
        assert hits == [
            '1 sentence runs over 25 words (longest 26, in Summary: "The tenant '
            'reads reads reads reads reads reads…"). Long sentences are the most '
            "common reason a triager re-reads a submission — consider splitting "
            "them."
        ]


@pytest.mark.parametrize("count, expect", [(21, True), (20, False)])
def test_steps_carry_the_tighter_sentence_budget(count, expect):
    """Steps cap at 20 words, and a Steps sentence is reported ONLY there.

    Partitioning by section rather than layering the two caps is what keeps a
    23-word step from being named twice, in two advisories, as two problems.
    """
    advisories = _advisories(steps_to_reproduce=f"1. {_words(count)}")
    steps_hits = _only(advisories, "over 20 words in Steps to Reproduce")
    assert bool(steps_hits) is expect
    assert _only(advisories, "over 25 words") == []


def test_steps_length_advisory_also_carries_the_quote():
    """The Steps-to-Reproduce advisory names its sentence the same way the
    general one does — the two message shapes are kept consistent."""
    advisories = _advisories(steps_to_reproduce=f"1. {_words(21)}")
    hits = _only(advisories, "over 20 words in Steps to Reproduce")
    assert hits == [
        "1 sentence runs over 20 words in Steps to Reproduce (longest 21: "
        '"The tenant reads reads reads reads reads reads…"). A step that has '
        "to be re-read is a step a triager can execute wrong — consider "
        "splitting them."
    ]


def test_length_advisory_quotes_the_longest_offender():
    """Two sentences trip the same advisory; the quote names the one already
    picked out by "longest N" — not merely the first or the last one found."""
    shorter = _tagged_words("Alpha", 26)
    longer = _tagged_words("Bravo", 30)
    hits = _only(_advisories(summary=f"{shorter} {longer}"), "over 25 words")
    assert hits == [
        "2 sentences run over 25 words (longest 30, in Summary: "
        '"Bravo tenant reads reads reads reads reads reads…"). Long sentences '
        "are the most common reason a triager re-reads a submission — consider "
        "splitting them."
    ]
    assert "Alpha" not in hits[0]


def test_length_advisory_quote_keeps_exactly_the_word_budget():
    """The quote is capped to exactly 8 words, not 7 or 9 — the same off-by-one
    a hand-rolled slice is easiest to get wrong."""
    sentence = " ".join(f"word{i:02d}" for i in range(1, 27)) + "."
    hits = _only(_advisories(summary=sentence), "over 25 words")
    assert hits
    quoted = hits[0].split('"')[1]
    assert quoted == "word01 word02 word03 word04 word05 word06 word07 word08…"


def test_length_advisory_quote_respects_the_character_ceiling():
    """A quote made of few but very long words can blow the character budget
    while still inside the 8-word cap — the same shape an inline code span
    produces, since `_word_count` treats it as one word. The character ceiling
    is the backstop."""
    long_words = " ".join(f"identifier-block-{i:03d}-extra-long" for i in range(8))
    filler = " ".join(["padding"] * 20)
    sentence = f"{long_words} {filler} tail."
    hits = _only(_advisories(summary=sentence), "over 25 words")
    assert hits
    quoted = hits[0].split('"')[1]
    assert quoted.endswith("…")
    assert len(quoted) <= 71  # 70-char budget plus the ellipsis character


def test_length_advisory_quote_neutralizes_backticks_and_pipes():
    """A quoted fragment must never smuggle a stray backtick, pipe, or newline
    into the OPERATOR DETAILS bullet it renders inside — any of the three could
    corrupt the block (an unterminated fence, a stray table row, or a line that
    escapes the `- ` list item entirely)."""
    sentence = (
        "Run `curl -s https://app.example.com/a|b -o out.json` and then read the "
        "response body twice before moving on to the next step in the flow "
        + " ".join(["more"] * 8)
        + "."
    )
    hits = _only(_advisories(summary=sentence), "over 25 words")
    assert hits
    assert "`" not in hits[0]
    assert "|" not in hits[0]
    assert "\n" not in hits[0]
    assert "'curl" in hits[0]  # the backtick is swapped, not merely dropped


@pytest.mark.parametrize(
    "kind, section",
    [
        # A fenced curl invocation: ~30 whitespace-delimited tokens.
        (
            "fence",
            "```\ncurl -s -X POST https://app.example.com/api/v2/invoices/41198/pdf "
            "-H 'Authorization: Bearer TOKEN' -H 'Accept: application/pdf' "
            "--resolve app.example.com:443:203.0.113.10 -o other-invoice.pdf "
            "-w '%{http_code}' --max-time 30 --retry 2\n```",
        ),
        # A markdown table: the classic "176-word sentence" false positive.
        (
            "table",
            "| endpoint | tenant | status | body |\n|---|---|---|---|\n"
            "| the invoice pdf download endpoint under api v2 | tenant a which is "
            "the attacker account here | two hundred which is the success code | "
            "another company entirely with its own billing address and line items |",
        ),
        # An unfenced HTTP request/response pair, headers included.
        (
            "http",
            "POST /api/v2/invoices/41198/pdf HTTP/1.1\n"
            "Host: billing.example.com\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
            "Accept: application/pdf, application/json, text/plain, text/html\n"
            "User-Agent: an extremely long user agent string with many many words\n"
            "\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/pdf\n"
            "Content-Disposition: attachment; filename=invoice-41198-northwind.pdf\n",
        ),
    ],
)
def test_structural_content_is_never_measured_as_prose(kind, section):
    """Code fences, tables, and HTTP blocks are removed BEFORE segmentation.

    A splitter that reads any of them as prose reports a sentence nobody wrote —
    the failure mode that makes this whole class of linter useless. Each fixture
    here is far over every word budget as raw tokens and must still be silent.
    """
    assert _advisories(evidence=section) == [], kind
    # ...and the same content inside Steps, whose budget is tighter still.
    assert _advisories(steps_to_reproduce=f"1. Run it.\n{section}") == [], kind


def test_prose_around_a_code_block_is_not_joined_across_it():
    """A dropped block ends the paragraph, so the text either side stays separate.

    Without that, the sentence before a fence and the sentence after it merge into
    one run and are measured as a single over-long sentence.
    """
    body = _body(
        evidence=f"{_words(15)}\n```\ncurl -s https://app.example.com/x\n```\n{_words(15)}"
    )
    assert export_submission.prose_advisories(body) == []


def test_exploit_flow_ordered_list_is_not_counted_as_summary_prose():
    """The WS5 Exploit flow lives INSIDE the authored `summary` string.

    It is a convention (a bold marker plus an ordered list), not a schema key, so a
    Summary sentence counter that reads its items as prose fires on every finding
    that has a flow. That is a guaranteed false positive, and the control below
    proves the exclusion is doing the work rather than the fixture being short.
    """
    flow = "\n".join(
        [
            "The admin points the webhook at the metadata service.",
            "",
            "**Exploit flow**",
            "",
            "1. The admin saves a webhook whose URL is the metadata endpoint.",
            "2. The app fetches that URL server-side.",
            "3. The response echoes the metadata body back.",
            "4. That body carries live IAM credentials.",
            "5. The attacker replays them against the AWS API.",
        ]
    )
    assert _only(_advisories(summary=flow), "Summary is") == []

    # Control: the same six sentences as plain prose DO exceed the 4-sentence budget.
    prose = flow.replace("**Exploit flow**\n\n", "")
    prose = "\n".join(line.split(". ", 1)[-1] for line in prose.split("\n"))
    assert _only(_advisories(summary=prose), "Summary is 6 sentences (budget 4)")


def test_exploit_flow_items_are_still_length_checked():
    """The flow is excluded from the COUNT, not from the document.

    A flow step is prose and a rambling one is worth splitting, so the sentence
    length budget still reaches it. Scoping the exclusion any wider would create a
    place to hide unbounded prose inside the Summary.
    """
    flow = f"Short lead.\n\n**Exploit flow**\n\n1. {_words(30)}"
    assert _only(_advisories(summary=flow), "over 25 words")


@pytest.mark.parametrize("count, expect", [(11, True), (10, False)])
def test_step_count_advises_at_the_suggested_ceiling(count, expect):
    steps = "\n".join(f"{i}. Do the thing." for i in range(1, count + 1))
    hits = _only(_advisories(steps_to_reproduce=steps), "steps_to_reproduce has")
    assert bool(hits) is expect
    if expect:
        assert hits == [
            "steps_to_reproduce has 11 steps (suggested ceiling 10). Worth a look: "
            "are any of these confirmations, alternates, or dead ends that don't "
            "gate a later step? Dropping a step re-triggers repro rehearsal."
        ]


def test_step_count_reads_the_render_not_the_authored_list_length():
    """The preferred authored shape is ONE string holding the whole numbered block.

    `len(details.steps_to_reproduce)` is 1 for that shape however many steps it
    holds, so counting the list would never fire. A multi-element list is the other
    shape, and there each item is a step even with no enumerator on it.
    """
    one_string = "\n".join(f"{i}. Do the thing." for i in range(1, 15))
    assert _only(
        export_submission.prose_advisories(
            _body(steps_to_reproduce=one_string), steps=[one_string]
        ),
        "has 14 steps",
    )
    items = [f"Do the thing {i}." for i in range(14)]
    assert _only(
        export_submission.prose_advisories(
            _body(steps_to_reproduce="\n\n".join(items)), steps=items
        ),
        "has 14 steps",
    )


def test_step_headings_win_over_nested_enumerators():
    """`#### Step N — [actor] …` labels are the steps; a numbered sub-action is not."""
    steps = "\n\n".join(
        f"#### Step {i} — [attacker] act\n\n1. first\n2. second" for i in range(1, 5)
    )
    assert _only(_advisories(steps_to_reproduce=steps), "steps_to_reproduce has") == []


@pytest.mark.parametrize(
    "key, heading, budget",
    [("summary", "Summary", 4), ("attack_scenario", "Attack Scenario", 3), ("impact", "Impact", 2)],
)
def test_section_sentence_budgets(key, heading, budget):
    at_budget = " ".join(f"Sentence {i} sits here." for i in range(budget))
    over = " ".join(f"Sentence {i} sits here." for i in range(budget + 1))
    assert _only(_advisories(**{key: at_budget}), f"{heading} is") == []
    hits = _only(_advisories(**{key: over}), f"{heading} is")
    assert hits and f"{heading} is {budget + 1} sentences (budget {budget})" in hits[0]
    assert "ceiling, not a target" in hits[0]


@pytest.mark.parametrize(
    "remediation, expect",
    [
        ("- one\n- two\n- three\n- four", True),
        ("- one\n- two\n- three", False),
        ("1. one\n2. two\n3. three\n4. four", True),
        # Prose remediation is measured in sentences: two fixes, one line.
        ("Parameterize the query. Add a WAF rule as defense-in-depth.", False),
    ],
)
def test_remediation_is_budgeted_in_items(remediation, expect):
    """An item is a list entry when Remediation is a list, a sentence when it is prose."""
    hits = _only(_advisories(remediation=remediation), "Remediation is")
    assert bool(hits) is expect


# A submission's sign-off sits after the last `###` heading, so with no heading to
# close that section it lands INSIDE it. Recognised by SHAPE — a bold label with a
# bare value — never by the word "Researcher", since a submission may sign off with
# a role, a handle, or a contact address.
_SIGN_OFFS = [
    "**Researcher:** Priya Natarajan — priya.natarajan@research.example",
    "**Reported by:** @a-handle",
    "**Contact:** security@example.test",
    "**Disclosure:**",
]


@pytest.mark.parametrize("sign_off", _SIGN_OFFS)
def test_trailing_sign_off_is_not_counted_as_last_section_content(sign_off):
    """A three-fix Remediation under a sign-off is a three-fix Remediation.

    Counting the footer as the third item is a PHANTOM item: it is not in the
    Structure template and nothing in the schema or the renderer emits it. The cost
    is not a stray number — a hand-corrected canonical example was compressed to
    two fixes to leave room for it, so a tool false positive rewrote a teaching
    artifact.
    """
    remediation = (
        "Parameterize the login query. Add a WAF rule as defense-in-depth. "
        "Rotate the credentials the injection exposed."
    )
    body = _body(remediation=f"{remediation}\n\n{sign_off}")
    assert _only(export_submission.prose_advisories(body), "Remediation is") == []


def test_genuine_over_budget_remediation_still_fires_under_a_sign_off():
    """Trimming the footer must not blind the check to the items above it."""
    remediation = "Fix one. Fix two. Fix three. Fix four."
    body = _body(remediation=f"{remediation}\n\n{_SIGN_OFFS[0]}")
    assert _only(
        export_submission.prose_advisories(body), "Remediation is 4 items (budget 3)"
    )


def test_a_bold_label_carrying_a_sentence_is_content_not_a_sign_off():
    """The shape test is "bare value", not "bold label".

    A labelled line with real sentence punctuation is remediation prose whatever
    labels it, so it still counts. Otherwise `**Also:** …` would be a place to park
    unbounded content outside every budget.
    """
    body = _body(
        remediation="Fix one. Fix two. Fix three.\n\n**Also:** rotate the exposed credentials."
    )
    assert _only(
        export_submission.prose_advisories(body), "Remediation is 4 items (budget 3)"
    )


def test_a_section_made_entirely_of_labelled_lines_is_kept_whole():
    """Trimming must never leave the last section with nothing in it.

    `**Primary fix:** …` / `**Defense in depth:** …` is a plausible Remediation
    shape, and every one of its lines matches the footer shape. Walking the whole
    section away would silence every advisory about it — over-trimming that hides a
    real defect, which is worse than the phantom item the trim exists to remove.
    """
    remediation = "\n".join(
        [
            "**Primary fix:** parameterize the login query with bound placeholders",
            "**Defense in depth:** add a WAF rule on the login endpoint",
            "**Also:** rotate the credentials the injection exposed",
            "**And:** audit the other three call sites",
        ]
    )
    advisories = export_submission.prose_advisories(_body(remediation=remediation))
    assert _only(advisories, "Remediation is 4 items (budget 3)")
    # ...and each labelled line is its own item, so the four are never joined into
    # one 34-word "sentence" nobody wrote.
    assert _only(advisories, "over 25 words") == []


def test_sign_off_trimming_is_scoped_to_the_document_tail():
    """Only the LAST section is closed by end-of-body; every other one has a heading.

    A trailing bold-labelled line inside Summary is closed by `### Steps to
    Reproduce` and is ordinary content, so it is still counted. Trimming every
    section's tail would delete real prose to fix a defect that exists in one place.
    """
    body = _body(
        summary="One here. Two here. Three here. Four here.\n\n**Note:** see the appendix",
        remediation="Fix it.",
    )
    assert _only(
        export_submission.prose_advisories(body), "Summary is 5 sentences (budget 4)"
    )


def test_sign_off_trimming_stops_at_a_closing_code_fence():
    """A Remediation that ends in a fenced patch keeps its fence and its prose."""
    body = _body(
        remediation="Apply the escaping helper at the interpolation site:\n"
        "```python\nrequest = escape(name)\n```"
    )
    assert export_submission.prose_advisories(body) == []


@pytest.mark.parametrize("count, expect", [(16, True), (15, False)])
def test_evidence_block_length_advises_at_the_line_budget(count, expect):
    block = "```\n" + "\n".join(f"line {i}" for i in range(count)) + "\n```"
    hits = _only(_advisories(evidence=block), "Evidence block")
    assert bool(hits) is expect
    if expect:
        assert hits == [
            "Evidence block 1 is 16 lines of content (budget 15). Consider "
            "truncating to the lines carrying the proof marker."
        ]


def test_evidence_block_length_ignores_blank_spacing():
    """Three well-spaced request/response pairs are inside the documented budget.

    Counting the blank lines between them would fire on a canonical example
    (`submission-direct-sql-injection-login.md` is 17 raw / 15 content lines), and
    an advisory that flags hand-corrected exemplar prose is one the report-writer
    learns to ignore.
    """
    pairs = "\n\n".join("\n".join(f"pair {p} line {i}" for i in range(5)) for p in range(3))
    assert _only(_advisories(evidence=f"```\n{pairs}\n```"), "Evidence block") == []


def test_evidence_block_length_names_the_block_that_ran_long():
    short = "\n".join(f"line {i}" for i in range(4))
    long = "\n".join(f"line {i}" for i in range(41))
    body = _body(evidence=f"```\n{short}\n```\n\n```\n{long}\n```")
    assert _only(export_submission.prose_advisories(body), "Evidence block") == [
        "Evidence block 2 is 41 lines of content (budget 15). Consider truncating "
        "to the lines carrying the proof marker."
    ]


def test_operator_details_content_is_never_measured():
    """Everything below the SECOND `---` is reference the operator never pastes.

    It legitimately carries whole PoC requests, response dumps, command
    transcripts, and investigation notes — measuring any of it as submission prose
    would fire on every render. The window is `pasteable_body`, the same one the
    hygiene gate scans.
    """
    reference = "\n".join(
        [
            "**Structured proof:**",
            "",
            "```",
            *[f"transcript line {i}" for i in range(41)],
            "```",
            "",
            "**Investigation notes** (working record):",
            "",
            _words(60),
            " ".join(_words(8) for _ in range(9)),
        ]
    )
    assert export_submission.prose_advisories(_body(operator_details=reference)) == []


# -- prose advisories: wiring through the command ------------------------------

def _bloated_details(**overrides) -> dict:
    """A complete, gate-passing finding that trips EVERY prose advisory at once."""
    summary = " ".join(
        [
            "An authenticated member reads another member's order by changing the "
            "numeric id in the download URL, and the ownership check that should "
            "stop them never runs anywhere in the request path at all.",
            *[f"Supporting sentence {i} sits here." for i in range(6)],
        ]
    )
    steps = "\n".join(
        [
            "1. Log in as member A and capture the session cookie from the browser "
            "devtools panel before doing anything else at all in this reproduction.",
            *[f"{i}. Do the thing." for i in range(2, 13)],
        ]
    )
    evidence = "The response returns member B's order fields while authenticated as member A.\n\n```\n" + "\n".join(
        f"order-field-{i}: value" for i in range(20)
    ) + "\n```"
    base = _complete_details(
        summary=summary,
        steps_to_reproduce=steps,
        evidence=evidence,
        attack_scenario=" ".join(f"Scenario sentence {i} sits here." for i in range(5)),
        impact=" ".join(f"Impact sentence {i} sits here." for i in range(4)),
        remediation="- Enforce ownership.\n- Rotate ids.\n- Add logging.\n- Add a WAF rule.",
    )
    base.update(overrides)
    return base


def _bloated_finding() -> dict:
    finding = _finding(details=_bloated_details())
    # `summary` is a top-level column; `_evaluate` reads it from there.
    finding["summary"] = _bloated_details()["summary"]
    return finding


def test_final_export_publishes_with_every_prose_advisory_firing(
    tmp_path, monkeypatch, capsys
):
    """THE regression: nothing added here changes the blocking set.

    A finished, verified finding whose prose runs past every ceiling is still a
    publishable finding. If any of these ever failed a final export closed, the
    tool would be overruling the author on style at the last step before filing —
    and the ceilings would stop being falsifiable, because the report-writer could
    no longer decide that this finding needs the extra sentence.
    """
    fake = _FakeClient(_bloated_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))

    export_submission.run(args)  # final mode, no --draft: must NOT raise
    captured = capsys.readouterr()

    assert _submission_path(tmp_path).exists()
    context = _context(tmp_path)
    assert context["mode"] == "final" and context["missing"] == []
    # Every new advisory family present...
    advisories = context["advisories"]
    for needle in (
        "over 25 words",
        "over 20 words in Steps to Reproduce",
        "steps_to_reproduce has 12 steps",
        "Summary is 7 sentences (budget 4)",
        "Attack Scenario is 5 sentences (budget 3)",
        "Impact is 4 sentences (budget 2)",
        "Remediation is 4 items (budget 3)",
        "Evidence block 1 is 20 lines of content (budget 15)",
    ):
        assert _only(advisories, needle), f"missing advisory: {needle}"
    # ...and NONE of them in the blocking set, which is unchanged.
    assert context["hygiene_warnings"] == []
    assert "ADVISORY export submission:" in captured.err
    assert "WARN export submission:" not in captured.err


def test_prose_advisories_surface_in_the_operator_details_block(
    tmp_path, monkeypatch, capsys
):
    """Surfaced where the report-writer is already reading, under the never-paste line."""
    fake = _FakeClient(_bloated_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd", "--draft"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    reference = body[body.index("## OPERATOR DETAILS"):]
    assert "**Advisories** (non-blocking — your call):" in reference
    assert "Summary is 7 sentences (budget 4)" in reference
    # The advisory text itself is never re-measured: it is woven in AFTER the scan
    # render, so the command cannot advise on its own prose.
    assert sum(a.count("Summary is 7 sentences") for a in _context(tmp_path)["advisories"]) == 1


def test_prose_advisories_stay_silent_on_a_tight_finding(tmp_path, monkeypatch, capsys):
    """The default fixture is inside every ceiling, so it earns no prose advisory."""
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path))
    export_submission.run(args)
    capsys.readouterr()

    advisories = _context(tmp_path)["advisories"]
    for needle in ("over 25 words", "over 20 words", "steps_to_reproduce has", "budget"):
        assert _only(advisories, needle) == [], needle


# -- repro-rehearsal advisory: decision-row state, never blocking ---------------
#
# The one advisory that measures BACKEND STATE rather than the rendered prose. The
# rehearsal (agent/phases/phase-8-report.md) is the only check that EXECUTES the
# steps, so it is the only one that can catch a step whose removal takes state a
# later step needs — the defect a post-rehearsal trim introduces. It lands at
# export time because that is where the trim happens and where the report-writer is
# reading; it joins `advisories` and never `hygiene_warnings`, so a final export
# publishes with it firing.

_REHEARSAL_ADVISORY = "no repro_rehearsal decision is recorded for this finding"


def _decision(
    slug: str = "VA-047",
    *,
    verdict: str = "followed",
    runs_checked=None,
    created_at: str = "2026-08-01T12:00:00Z",
    row_id: int = 1,
    kind: str = "repro_rehearsal",
) -> dict:
    payload = {"finding_slug": slug, "verdict": verdict}
    if runs_checked is not None:
        payload["runs_checked"] = runs_checked
    return {"id": row_id, "kind": kind, "created_at": created_at, "payload": payload}


def _rehearsal_hits(context: dict) -> list[str]:
    return [a for a in context["advisories"] if "repro_rehearsal" in a]


def _run_final(tmp_path, monkeypatch, fake: _FakeClient, *, draft: bool = False) -> None:
    _install(monkeypatch, tmp_path, fake)
    argv = ["submission", "VA-047", "--platform", "bugcrowd"] + (["--draft"] if draft else [])
    export_submission.run(_parse(argv, str(tmp_path)))


def test_missing_rehearsal_advises_with_the_action_that_clears_it(
    tmp_path, monkeypatch, capsys
):
    """The weak-but-sound check: no rehearsal on record for this finding at all.

    Pinned verbatim because the advisory has to name the observed state AND the
    command that fixes it — an advisory that only says something is wrong sends the
    report-writer looking for the verb.
    """
    fake = _FakeClient(_finding(details=_complete_details(repro_runs=[11])),
                       command_runs={11: {"id": 11, "command": "curl -sk /login"}})
    _run_final(tmp_path, monkeypatch, fake)
    captured = capsys.readouterr()

    assert _rehearsal_hits(_context(tmp_path)) == [
        "no repro_rehearsal decision is recorded for this finding — a rehearsal is "
        "what catches a step that removes state a later step needs, which reading "
        "the steps cannot. Run details.steps_to_reproduce from a cold start and "
        "stamp the outcome with `vigil assess agent decision --kind repro_rehearsal "
        '--payload-json \'{"finding_slug":"<slug>","verdict":"followed",'
        "\"runs_checked\":[<run_id>, ...]}'` before publishing."
    ]
    assert "ADVISORY export submission:" in captured.err


def test_missing_rehearsal_never_blocks_a_final_export(tmp_path, monkeypatch, capsys):
    """THE regression, mirroring the prose-advisory one: the blocking set is unchanged.

    A finished, verified finding nobody rehearsed is still a publishable finding —
    the rehearsal is process state, not a fact about the document, and gating on it
    would let a missing decision row hold a correct submission hostage.
    """
    fake = _FakeClient(_finding(details=_complete_details()))
    _run_final(tmp_path, monkeypatch, fake)  # final mode, no --draft: must NOT raise
    capsys.readouterr()

    assert _submission_path(tmp_path).exists()
    context = _context(tmp_path)
    assert context["mode"] == "final" and context["missing"] == []
    assert _rehearsal_hits(context)
    # The four canonical hygiene warnings stay the only blocking family.
    assert context["hygiene_warnings"] == []
    assert not any("rehearsal" in w for w in context["hygiene_warnings"])


def test_rehearsal_advisory_surfaces_in_the_operator_details_block(
    tmp_path, monkeypatch, capsys
):
    """Draft mode surfaces it too — that is the whole point of choosing export time."""
    fake = _FakeClient(_finding(details=_complete_details()))
    _run_final(tmp_path, monkeypatch, fake, draft=True)
    capsys.readouterr()

    body = _submission_path(tmp_path).read_text()
    reference = body[body.index("## OPERATOR DETAILS"):]
    assert "**Advisories** (non-blocking — your call):" in reference
    assert _REHEARSAL_ADVISORY in reference
    # Never above the paste boundary: this is operator reference, not submission prose.
    assert "repro_rehearsal" not in body[:body.index("## OPERATOR DETAILS")]


def test_recorded_followed_rehearsal_is_silent(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision()],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert _rehearsal_hits(_context(tmp_path)) == []


def test_rehearsal_for_another_finding_does_not_count(tmp_path, monkeypatch, capsys):
    """Rows are matched on payload.finding_slug — the endpoint has no slug filter."""
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision("VA-048"), _decision("VA-049")],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert _rehearsal_hits(_context(tmp_path))


def test_decisions_of_another_kind_do_not_count(tmp_path, monkeypatch, capsys):
    """The kind filter is server-side; a blind-triage verdict is not a rehearsal."""
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision(kind="blind_triage_verdict", verdict="Accept@P3")],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert "dispatch-decisions?kind=repro_rehearsal&limit=1000" in fake.gets
    assert _rehearsal_hits(_context(tmp_path))


def test_the_kind_is_re_checked_on_the_rows_themselves():
    """Defence in depth for a caller that hands over an UNFILTERED decision list.

    `blind_triage_verdict` rows carry a `finding_slug` in the same payload shape, so
    reading one as a rehearsal would report an `Accept@P3` triage verdict as a
    rehearsal that did not follow — a wrong statement about the finding, from a row
    that is doing its job.
    """
    triage = _decision(kind="blind_triage_verdict", verdict="Accept@P3")
    assert export_submission.repro_rehearsal_advisories([triage], "VA-047") == [
        a for a in export_submission.repro_rehearsal_advisories([], "VA-047")
    ]
    assert _REHEARSAL_ADVISORY in export_submission.repro_rehearsal_advisories(
        [triage], "VA-047"
    )[0]


def test_failed_rehearsal_quotes_the_recorded_verdict(tmp_path, monkeypatch, capsys):
    """A recorded rehearsal that did not follow is a stronger signal than absence.

    The verdict is quoted rather than translated: a value this command does not
    recognise is not the same fact as `failed`, and asserting the wrong one sends
    the report-writer to fix something that is fine.
    """
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision(verdict="failed")],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    hits = _rehearsal_hits(_context(tmp_path))
    assert len(hits) == 1
    assert "records verdict 'failed', not 'followed'" in hits[0]
    assert "back to the specialist that recorded it" in hits[0]


def test_unrecognised_verdict_is_named_not_translated(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision(verdict="pass")],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    hits = _rehearsal_hits(_context(tmp_path))
    assert len(hits) == 1
    assert "records verdict 'pass', not 'followed'" in hits[0]
    # It does NOT claim the rehearsal failed — only that nothing recorded `followed`.
    assert "failed" not in hits[0]


@pytest.mark.parametrize(
    "newest_verdict, expect_advisory",
    [("followed", False), ("failed", True)],
)
def test_the_newest_rehearsal_row_wins(
    tmp_path, monkeypatch, capsys, newest_verdict, expect_advisory
):
    """A re-rehearsal supersedes the row before it, in both directions.

    Reading every row instead of the newest would make a fixed reproduction advise
    forever off its first failure, and a later failure invisible behind an earlier
    pass. The rows are handed over OLDEST-first — the reverse of the backend's
    `created_at DESC` — so the answer has to come from the sort, not from position.
    """
    older = "followed" if newest_verdict == "failed" else "failed"
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[
            _decision(verdict=older, created_at="2026-08-01T09:00:00Z", row_id=1),
            _decision(verdict=newest_verdict, created_at="2026-08-01T17:00:00Z", row_id=2),
        ],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert bool(_rehearsal_hits(_context(tmp_path))) is expect_advisory


def test_same_second_rehearsals_break_the_tie_on_row_id(tmp_path, monkeypatch, capsys):
    """`created_at` has one-second resolution, so the id is the real ordering.

    The failed row is handed over FIRST, so a positional read would return it and
    the assertion below would fail; only the id tie-break reaches the later pass.
    """
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[
            _decision(verdict="failed", created_at="2026-08-01T09:00:00Z", row_id=3),
            _decision(verdict="followed", created_at="2026-08-01T09:00:00Z", row_id=4),
        ],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert _rehearsal_hits(_context(tmp_path)) == []


def test_rehearsal_checked_a_run_the_finding_no_longer_declares(
    tmp_path, monkeypatch, capsys
):
    """The staleness signal, keyed on CONTENT rather than a timestamp.

    Dropping a step removes its id from `details.repro_runs` (the build rule), so a
    `runs_checked` id the finding no longer declares is the signature of a
    reproduction that changed after it was rehearsed. The advisory states what it
    observed rather than asserting a step was dropped — a corrected run id produces
    the same observation and earns the same cheap answer.
    """
    command_runs = {11: {"id": 11, "command": "curl -sk /login", "return_code": 0}}
    fake = _FakeClient(
        _finding(details=_complete_details(repro_runs=[11])),
        command_runs=command_runs,
        decisions=[_decision(runs_checked=[11, 12])],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    hits = _rehearsal_hits(_context(tmp_path))
    assert len(hits) == 1
    assert "checked run 12, which details.repro_runs no longer declares" in hits[0]
    assert "re-run the rehearsal against the trimmed steps" in hits[0]
    # Still not a blocker.
    assert _context(tmp_path)["hygiene_warnings"] == []


def test_a_partially_checked_rehearsal_is_not_staleness(tmp_path, monkeypatch, capsys):
    """The noisy direction must stay silent.

    `runs_checked` records what the rehearsal DIFFED, not what it covered, so a
    rehearsal that checked one of three runs is normal. Firing on it would make the
    advisory arrive on findings nobody touched — the false-positive shape that
    teaches a reader to skip the advisory block.
    """
    command_runs = {
        11: {"id": 11, "command": "curl -sk /login", "return_code": 0},
        12: {"id": 12, "command": "curl -sk /orders/1001", "return_code": 0},
    }
    fake = _FakeClient(
        _finding(details=_complete_details(repro_runs=[11, "12"])),
        command_runs=command_runs,
        decisions=[_decision(runs_checked=[11])],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    assert _rehearsal_hits(_context(tmp_path)) == []


def test_staleness_is_skipped_when_the_finding_declares_no_runs(
    tmp_path, monkeypatch, capsys
):
    """`repro_runs` empty already has its own advisory; naming both is two fixes."""
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions=[_decision(runs_checked=[11, 12])],
    )
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    context = _context(tmp_path)
    assert _rehearsal_hits(context) == []
    assert any("repro_runs is empty" in a for a in context["advisories"])


def test_a_backend_failure_emits_no_rehearsal_advisory(tmp_path, monkeypatch, capsys):
    """Fail soft: "could not ask" is not "no rehearsal on record".

    They have opposite fixes, so collapsing them would send the report-writer to
    re-run a rehearsal that already passed. The export still publishes.
    """
    fake = _FakeClient(
        _finding(details=_complete_details()),
        decisions_error="HTTP 503:\nbackend unavailable",
    )
    _run_final(tmp_path, monkeypatch, fake)
    captured = capsys.readouterr()

    assert _submission_path(tmp_path).exists()  # final mode still publishes
    context = _context(tmp_path)
    assert _rehearsal_hits(context) == []
    assert context["hygiene_warnings"] == []
    assert "repro-rehearsal decisions unavailable" in captured.err
    assert "not evaluated for this render" in captured.err


def test_a_finding_with_no_authored_steps_is_not_asked_about(
    tmp_path, monkeypatch, capsys
):
    """No steps, no reproduction to rehearse — and no round trip to find that out.

    Export runs repeatedly in the author -> write-back -> re-render loop, so the
    early drafts that have nothing to rehearse should not pay for the read.
    """
    fake = _FakeClient(_finding(details=_complete_details(steps_to_reproduce=[])))
    _run_final(tmp_path, monkeypatch, fake, draft=True)
    capsys.readouterr()

    assert not any(g.startswith("dispatch-decisions") for g in fake.gets)
    assert _rehearsal_hits(_context(tmp_path)) == []


def test_rehearsal_read_costs_exactly_one_round_trip(tmp_path, monkeypatch, capsys):
    """One filtered read, at the endpoint's max page size — the blind-triage shape."""
    fake = _FakeClient(_finding(details=_complete_details()))
    _run_final(tmp_path, monkeypatch, fake)
    capsys.readouterr()

    reads = [g for g in fake.gets if g.startswith("dispatch-decisions")]
    assert reads == ["dispatch-decisions?kind=repro_rehearsal&limit=1000"]
