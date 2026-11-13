"""A transition blocker names every subject it holds, or how to read the rest.

A blocker is the list the operator works through before the edge opens, so a
blocker that names five of eight findings and ends in "..." leaves three to be
found some other way, and nothing on the line says how. Finding-slug blockers
are computed here and no other command lists them, so they name every slug.
App-unit blockers keep a sample and give the count left out and the command that
renders every unit.

Structural assertions over each blocker's detail: every subject, or the omitted
count and the follow-up command — not the surrounding wording.
"""
from __future__ import annotations

import pytest

from assess.commands import transition_phase

_SLUGS = [f"VA-{n:03d}" for n in range(1, 9)]


class _Client:
    def __init__(self, *, findings=(), artifacts=(), terminal_block=None):
        self._findings = list(findings)
        self._artifacts = list(artifacts)
        self._terminal_block = terminal_block

    def get(self, path):
        if path in ("findings?view=list", "findings"):
            return list(self._findings)
        if path == "application-units/terminal-block":
            return self._terminal_block
        if path.startswith("artifacts/search?"):
            if "offset=0" not in path:
                return []
            if "kind=" in path:
                kind = path.split("kind=", 1)[1].split("&", 1)[0]
                return [row for row in self._artifacts if row["kind"] == kind]
            if "finding=" in path:
                slug = path.split("finding=", 1)[1].split("&", 1)[0]
                return [row for row in self._artifacts if row["related_finding_slug"] == slug]
            return list(self._artifacts)
        return []

    def get_engagement(self, *_a, **_k):
        return {"items": []}


def _blocker(blockers, kind):
    matches = [row for row in blockers if row["kind"] == kind]
    assert len(matches) == 1, blockers
    return matches[0]["detail"]


def _names_every_slug(detail: str) -> None:
    for slug in _SLUGS:
        assert slug in detail, (slug, detail)


def test_missing_submission_qc_names_every_finding():
    findings = [{"slug": slug, "severity": "low", "verification_status": "confirmed",
                 "workflow_status": "reported"} for slug in _SLUGS]
    artifacts = [{"kind": "submission", "related_finding_slug": slug} for slug in _SLUGS]
    blockers = transition_phase._submission_qc_blockers(
        _Client(findings=findings, artifacts=artifacts))
    _names_every_slug(_blocker(blockers, "missing_submission_qc"))


def test_missing_blind_triage_names_every_finding():
    findings = [{"slug": slug, "severity": "medium", "verification_status": "confirmed",
                 "workflow_status": "reported"} for slug in _SLUGS]
    blockers = transition_phase._blind_triage_blockers(_Client(findings=findings))
    _names_every_slug(_blocker(blockers, "missing_blind_triage"))


@pytest.mark.parametrize(
    ("verification_status", "kind"),
    [("unreviewed", "unverified_high_findings"), ("confirmed", "missing_variant_pass")],
)
def test_exploit_entry_blockers_name_every_finding(verification_status, kind):
    findings = [{"slug": slug, "severity": "high", "verification_status": verification_status,
                 "workflow_status": "active"} for slug in _SLUGS]
    blockers = transition_phase._check_web_preconditions("exploit", _Client(findings=findings))
    _names_every_slug(_blocker(blockers, kind))


def _blue(slug: str, **fields) -> dict:
    return {"slug": slug, "severity": "high", "workflow_status": "active",
            "verification_status": "unreviewed", "details": {}, **fields}


@pytest.mark.parametrize(
    ("check", "findings", "kind"),
    [
        ("_blue_check_investigate_to_verify",
         [_blue(slug, workflow_status="draft") for slug in _SLUGS], "findings_still_draft"),
        ("_blue_check_investigate_to_verify", [_blue(slug) for slug in _SLUGS],
         "missing_mitre_techniques"),
        ("_blue_check_investigate_to_verify", [_blue(slug) for slug in _SLUGS],
         "missing_evidence_artifacts"),
        ("_blue_check_verify_to_respond", [_blue(slug) for slug in _SLUGS], "unreviewed_findings"),
        ("_blue_check_respond_to_report",
         [_blue(slug, verification_status="confirmed") for slug in _SLUGS],
         "missing_containment_closure"),
        ("_blue_check_report_to_complete", [_blue(slug) for slug in _SLUGS], "findings_not_closed"),
    ],
)
def test_blue_blockers_name_every_finding(check, findings, kind):
    blockers = getattr(transition_phase, check)(_Client(findings=findings))
    _names_every_slug(_blocker(blockers, kind))


def _unit(n: int) -> dict:
    return {"host": "app.acme.example", "path_prefix": f"/area-{n}"}


@pytest.mark.parametrize(
    ("terminal_block", "kind", "follow_up"),
    [
        ({"blocking": [{"unit": _unit(n)} for n in range(8)]}, "depth_unsatisfied_units",
         "`vigil assess check-phase-readiness --phase report`"),
        ({"blocking": [{"unit": _unit(n), "block_grain": "class", "uncovered_classes": ["sqli"]}
                       for n in range(8)]},
         "depth_uncovered_classes", "`vigil assess check-phase-readiness --phase report`"),
        ({"warned_under_observed": [{"unit": _unit(n)} for n in range(8)]},
         "depth_under_observed_units", "`vigil assess check-phase-readiness --phase report --json`"),
    ],
)
def test_depth_blockers_count_the_units_left_out_and_name_the_full_listing(
    terminal_block, kind, follow_up
):
    result = {"skipped": False, "blocking": [], "warned_under_observed": [],
              "deferral_count": 0, **terminal_block}
    detail = _blocker(
        transition_phase._depth_backstop_blockers(_Client(terminal_block=result)), kind)
    assert "+2 more" in detail
    assert follow_up in detail
    assert "/area-5" in detail and "/area-6" not in detail
