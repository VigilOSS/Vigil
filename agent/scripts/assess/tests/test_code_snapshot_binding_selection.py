"""The derived code-snapshot binding picks its repository by agent start's rule.

`agent start` renders Code Source Identity for the analysis repositories only:
a `reference` repository is navigation source, never a reviewed subject, so it
is never a derivation candidate either. An engagement with one analysis and one
reference repository derives the analysis binding. When the choice is genuinely
ambiguous the refusal hands over the values an explicit binding needs, and
`--code-repo-id` selects the repository. Naming a reference repository with the
flag binds it with a warning: the choice is deliberate, and the repository owes
no coverage.
"""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib.client import AssessError
from assess.lib.code_snapshot_binding import current_binding
from test_finding_provenance_autofill import (
    _Backend,
    _engagement,
    _file_finding_payload,
)

_A = "ab" * 32
_B = "cd" * 32
_R = "ef" * 32

_ANALYSIS = {
    "id": 7, "repo_key": "acme-app", "active_generation": 3,
    "source_manifest_digest": _A, "repo_role": "analysis",
}
_SECOND_ANALYSIS = {
    "id": 9, "repo_key": "acme-api", "active_generation": 5,
    "source_manifest_digest": _B, "repo_role": "analysis",
}
_REFERENCE = {
    "id": 8, "repo_key": "acme-framework", "active_generation": 2,
    "source_manifest_digest": _R, "repo_role": "reference",
}


class _Listing:
    def __init__(self, repos):
        self.repos = repos

    def get(self, endpoint):
        if endpoint == "code/repos":
            return [dict(repo) for repo in self.repos]
        repo_id = int(endpoint.rsplit("/", 1)[1])
        return next(dict(repo) for repo in self.repos if repo["id"] == repo_id)


def _binding(repo: dict) -> dict:
    return {
        "repo_id": repo["id"],
        "repo_generation": repo["active_generation"],
        "source_manifest_digest": repo["source_manifest_digest"],
    }


def test_a_reference_repository_does_not_make_the_derivation_ambiguous():
    binding = current_binding(_Listing([_ANALYSIS, _REFERENCE]), operation="finding record")
    assert binding == _binding(_ANALYSIS)


def test_only_reference_repositories_leave_nothing_to_derive_from():
    with pytest.raises(AssessError, match="no active indexed analysis repository"):
        current_binding(_Listing([_REFERENCE]), operation="finding record")


def test_the_ambiguity_refusal_prints_each_candidate_as_a_paste_ready_binding():
    with pytest.raises(AssessError) as info:
        current_binding(
            _Listing([_ANALYSIS, _REFERENCE, _SECOND_ANALYSIS]),
            operation="finding record",
        )
    message = str(info.value)
    assert "--code-repo-id" in message
    pasted = [
        json.loads(line[line.index("{"):])
        for line in message.splitlines()
        if '{"code_snapshot"' in line
    ]
    assert pasted == [
        {"code_snapshot": _binding(_ANALYSIS)},
        {"code_snapshot": _binding(_SECOND_ANALYSIS)},
    ]
    # The reference repository was never a candidate.
    assert "acme-framework" not in message


def _record(engagement, json_file, *extra):
    cli.main([
        "--engagement-dir", str(engagement), "finding", "record",
        "code-vuln-hunter", str(json_file), "--agent-id", "CH-1",
        "--allow-unindexed-evidence", *extra,
    ])


def test_record_derives_past_a_reference_repository(tmp_path, monkeypatch, capsys):
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend(repos=[dict(_ANALYSIS), dict(_REFERENCE)])
    backend.install(monkeypatch)

    _record(engagement, json_file)

    capsys.readouterr()
    assert backend.payload_for("findings")["provenance"]["code_snapshot"] == _binding(_ANALYSIS)


def test_record_code_repo_id_selects_one_of_several_analysis_repositories(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend(repos=[dict(_ANALYSIS), dict(_SECOND_ANALYSIS)])
    backend.install(monkeypatch)

    _record(engagement, json_file, "--code-repo-id", "9")

    capsys.readouterr()
    assert backend.payload_for("findings")["provenance"]["code_snapshot"] == _binding(
        _SECOND_ANALYSIS
    )


def test_record_refuses_a_code_repo_id_that_contradicts_the_authored_binding(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    authored = _file_finding_payload()
    authored["provenance"] = {"code_snapshot": _binding(_ANALYSIS)}
    json_file.write_text(json.dumps(authored), encoding="utf-8")
    backend = _Backend(repos=[dict(_ANALYSIS), dict(_SECOND_ANALYSIS)])
    backend.install(monkeypatch)

    with pytest.raises(SystemExit) as exit_info:
        _record(engagement, json_file, "--code-repo-id", "9")

    assert exit_info.value.code == 1
    assert "--code-repo-id 9" in capsys.readouterr().err
    assert backend.posts == []


def _verify(engagement, slug, *extra):
    cli.main([
        "--engagement-dir", str(engagement), "finding", "verify", slug,
        "--status", "pending_runtime_proof",
        "--next-test-file", str(engagement / "next-test.json"),
        "--reason", "Runtime trigger still owed.", "--agent-id", "VF-1", *extra,
    ])


def test_verify_code_repo_id_binds_an_unbound_finding_among_several_repositories(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1"},
        },
        repos=[dict(_ANALYSIS), dict(_SECOND_ANALYSIS)],
    )
    backend.install(monkeypatch)

    _verify(engagement, "CH-001", "--code-repo-id", "9")

    capsys.readouterr()
    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["code_snapshot"] == _binding(_SECOND_ANALYSIS)


def test_verify_refuses_a_code_repo_id_that_contradicts_the_stored_binding(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1", "code_snapshot": {"repo_id": 7}},
        },
        repos=[dict(_ANALYSIS), dict(_SECOND_ANALYSIS)],
    )
    backend.install(monkeypatch)

    with pytest.raises(SystemExit):
        _verify(engagement, "CH-001", "--code-repo-id", "9")

    assert "--code-repo-id 9" in capsys.readouterr().err
    assert backend.posts == []


def test_record_binds_a_named_reference_repository_with_a_warning(
    tmp_path, monkeypatch, capsys
):
    """Naming a reference repository is a deliberate choice: bound, and warned.

    A reference repository is never an automatic candidate, but a defect can
    genuinely live in vendored reference source. The explicit flag binds it and
    says that the repository carries no coverage obligation.
    """
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend(repos=[dict(_ANALYSIS), dict(_REFERENCE)])
    backend.install(monkeypatch)

    _record(engagement, json_file, "--code-repo-id", str(_REFERENCE["id"]))

    err = capsys.readouterr().err
    assert "WARN finding record: --code-repo-id 8 (acme-framework) is a reference repository" in err
    assert "no coverage obligation" in err
    assert backend.payload_for("findings")["provenance"]["code_snapshot"] == _binding(_REFERENCE)


def test_verify_binds_a_named_reference_repository_with_a_warning(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1"},
        },
        repos=[dict(_ANALYSIS), dict(_REFERENCE)],
    )
    backend.install(monkeypatch)

    _verify(engagement, "CH-001", "--code-repo-id", str(_REFERENCE["id"]))

    err = capsys.readouterr().err
    assert "WARN finding verify: --code-repo-id 8 (acme-framework) is a reference repository" in err
    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["code_snapshot"] == _binding(_REFERENCE)


def test_a_named_inactive_repository_is_still_refused():
    inactive = {**_SECOND_ANALYSIS, "active_generation": 0}
    with pytest.raises(AssessError, match="not an active analysis repository"):
        current_binding(
            _Listing([_ANALYSIS, inactive]), repo_id=inactive["id"], operation="finding record"
        )


def test_a_stored_reference_binding_is_read_without_a_warning(capsys):
    binding = current_binding(
        _Listing([_ANALYSIS, _REFERENCE]),
        repo_id=_REFERENCE["id"],
        stored=True,
        operation="finding verify",
    )
    assert binding == _binding(_REFERENCE)
    assert capsys.readouterr().err == ""


def test_verify_keeps_reading_a_stored_binding_that_names_a_reference_repository(
    tmp_path, monkeypatch, capsys
):
    """A binding already stored is the finding's own record, whatever its role."""
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1", "code_snapshot": {"repo_id": _REFERENCE["id"]}},
        },
        repos=[dict(_ANALYSIS), dict(_REFERENCE)],
    )
    backend.install(monkeypatch)

    _verify(engagement, "CH-001")

    capsys.readouterr()
    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["code_snapshot"] == _binding(_REFERENCE)


def test_verify_refuses_a_code_repo_id_contradicting_an_authored_inline_binding(
    tmp_path, monkeypatch, capsys
):
    """The same contradiction `finding record` refuses."""
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1"},
        },
        repos=[dict(_ANALYSIS), dict(_SECOND_ANALYSIS)],
    )
    backend.install(monkeypatch)
    inline = json.dumps({"code_snapshot": _binding(_ANALYSIS)})

    with pytest.raises(SystemExit):
        _verify(engagement, "CH-001", "--code-repo-id", "9", "--provenance-inline", inline)

    assert "--code-repo-id 9" in capsys.readouterr().err
    assert backend.posts == []
