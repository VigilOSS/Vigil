"""B8 CLI half: `code-ingest --role` and the reference-repo operator surface.

The role decides whether the ingest buys a coverage obligation, so it has to
be visible in three places: the flag that sets it, the durable receipt the
commit returns, and the coverage view that would otherwise show a silently
shrunken denominator.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import code_coverage, code_ingest
from assess.lib.contracts import CODE_REPO_ROLES, render_contract


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="command"))
    return parser


def test_role_defaults_to_unset_so_a_re_ingest_cannot_silently_downgrade():
    """An omitted --role must not overwrite a repository's recorded role.

    Re-ingesting a reference repository after an upstream update is routine;
    if the flag defaulted to ``analysis`` on the wire, forgetting it would
    hand the engagement a coverage obligation over the host framework — the
    exact failure B8 exists to remove.
    """
    parsed = _parser().parse_args(["code-ingest", "/srv/repo"])

    assert parsed.role is None


def test_role_accepts_every_registered_value_and_rejects_others():
    parser = _parser()

    for role in CODE_REPO_ROLES:
        parsed = parser.parse_args(["code-ingest", "/srv/repo", "--role", role])
        assert parsed.role == role

    with pytest.raises(SystemExit):
        parser.parse_args(["code-ingest", "/srv/repo", "--role", "vendored"])


def test_commit_receipt_requires_the_durable_repository_role():
    """The role is durable state, so the receipt must prove what was written."""
    receipt = {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "retired": 0,
        "repo_role": "reference",
    }

    assert code_ingest._require_refresh_commit_receipt(
        receipt, requested_repo_id=7
    ) == (3, "a" * 64, "reference")

    with pytest.raises(Exception, match="repo_role"):
        code_ingest._require_refresh_commit_receipt(
            {**receipt, "repo_role": "vendored"}, requested_repo_id=7
        )

    with pytest.raises(Exception, match="repo_role"):
        code_ingest._require_refresh_commit_receipt(
            {key: value for key, value in receipt.items() if key != "repo_role"},
            requested_repo_id=7,
        )


def test_contract_documents_the_role_flag():
    rendered = render_contract("code-ingest")

    assert "--role" in rendered
    for role in CODE_REPO_ROLES:
        assert role in rendered


def test_coverage_names_reference_repositories_that_carry_no_obligation(capsys):
    code_coverage._print_coverage(
        {
            "total_files": 12,
            "by_classification": {},
            "by_status": {},
            "findings_summary": {
                "total_code_findings": 0,
                "by_severity": {},
                "variant_count": 0,
            },
            "confidence": {},
            "reference_repos": [
                {
                    "repo_id": 4,
                    "repo_key": "keycloak",
                    "name": "keycloak",
                    "admitted_files": 21044,
                }
            ],
            "gate": {"passed": True, "reasons": []},
        }
    )

    out = capsys.readouterr().out
    assert "keycloak" in out
    assert "21044" in out or "21,044" in out


def test_unqueued_blocker_repair_offers_the_reference_role(capsys):
    code_coverage._print_transition_readiness(
        "hunt",
        {
            "target_phase": "hunt",
            "transition_ready": False,
            "blockers": [
                {
                    "code": "admitted_files_unqueued",
                    "message": "Repository has 21044 admitted file(s) with no queue row.",
                    "overrideable": True,
                    "repo_id": 4,
                }
            ],
        },
    )

    out = capsys.readouterr().out
    assert "--role reference" in out
