"""`finding update|verify --payload-file` fills what it can and says so.

A payload file is a complete document for the finding CONTENT. The control
flags around it (who is writing, why, which row version it was read at) are
not content, so they fill the matching key when the file leaves it out; only a
real conflict, the same key with two different values, is refused. The row
version an author did not write is read just before the PATCH like the flag
path does, except where a fetched token would let the write erase a concurrent
writer: notes replace/rotate, details replace, and any field whose change puts
the verdict under claim review or invalidates it. Notes without a mode append.
A verify payload derives a ``file:`` finding's code-snapshot binding exactly
as the flag path does. Each of these prints one line naming what it filled.
"""
from __future__ import annotations

import argparse
import json

import pytest
from _fake_client import StubClient

from assess import cli
from assess.commands import update_finding
from test_finding_provenance_autofill import _Backend, _DIGEST, _PLAN, _engagement


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "acme-web"


class _FakeClient(StubClient):
    def __init__(self) -> None:
        self.gets: list[str] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint: str) -> dict:
        self.gets.append(endpoint)
        return {"slug": endpoint.rsplit("/", 1)[-1], "row_version": 7}

    def patch(self, endpoint: str, payload: dict) -> dict:
        self.patches.append((endpoint, payload))
        return {"finding": {"slug": endpoint.split("/")[1], "row_version": 8}}


def _update(
    tmp_path, monkeypatch, payload: dict, *flags: str, fake: _FakeClient | None = None
) -> _FakeClient:
    fake = fake if fake is not None else _FakeClient()
    monkeypatch.setattr(update_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *a, **k: fake)
    path = tmp_path / "patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    parser = argparse.ArgumentParser()
    update_finding.register(parser.add_subparsers())
    args = parser.parse_args(["update", "VA-1", "--payload-file", str(path), *flags])
    args.engagement_dir = str(tmp_path)
    update_finding.run(args)
    return fake


def _refused_update(tmp_path, monkeypatch, capsys, payload: dict, *flags: str) -> str:
    fake = _FakeClient()
    with pytest.raises(SystemExit) as exc:
        _update(tmp_path, monkeypatch, payload, *flags, fake=fake)
    assert exc.value.code == 1
    assert fake.patches == []
    return capsys.readouterr().err


# -- control flags fill the payload ------------------------------------------


def test_update_control_flags_fill_keys_the_payload_leaves_out(
    tmp_path, monkeypatch, capsys
):
    fake = _update(
        tmp_path, monkeypatch, {"summary": "Reworded summary."},
        "--agent-id", "RW-1", "--reason", "Reworded for the program.",
        "--reason-code", "presentation", "--source-name", "report-writer",
        "--expected-row-version", "4",
    )

    assert fake.patches == [
        (
            "findings/VA-1",
            {
                "summary": "Reworded summary.",
                "dispatch_agent_id": "RW-1",
                "reason_text": "Reworded for the program.",
                "reason_code": "presentation",
                "source_name": "report-writer",
                "expected_row_version": 4,
            },
        )
    ]
    # The explicit token is used as given, never replaced by a read.
    assert fake.gets == []
    filled = [line for line in capsys.readouterr().err.splitlines() if "from flags" in line]
    assert len(filled) == 1
    for key in ("dispatch_agent_id", "reason_text", "reason_code", "source_name",
                "expected_row_version"):
        assert key in filled[0]


def test_update_a_flag_that_restates_the_payload_is_accepted(tmp_path, monkeypatch, capsys):
    fake = _update(
        tmp_path, monkeypatch,
        {"summary": "s", "reason_text": "same", "expected_row_version": 4},
        "--reason", "same",
    )

    assert fake.patches[0][1]["reason_text"] == "same"
    assert "from flags" not in capsys.readouterr().err


def test_update_a_flag_that_contradicts_the_payload_is_refused(
    tmp_path, monkeypatch, capsys
):
    err = _refused_update(
        tmp_path, monkeypatch, capsys,
        {"summary": "s", "reason_text": "from file", "expected_row_version": 4},
        "--reason", "from flag",
    )

    assert "--reason" in err and "reason_text" in err
    assert "from file" in err and "from flag" in err


def test_update_content_flags_still_conflict_with_the_file(tmp_path, monkeypatch, capsys):
    err = _refused_update(
        tmp_path, monkeypatch, capsys,
        {"summary": "file", "expected_row_version": 4}, "--summary", "flag",
    )

    assert "--summary" in err


# -- expected_row_version is read when the author did not write it ------------


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "Reworded title"},
        {"details": {"remediation": "Bind the session to the owner."}},
        {"submission_status": "submitted", "submission_ref": "ACME-1"},
    ],
)
def test_update_payload_without_a_token_reads_the_current_row_version(
    payload, tmp_path, monkeypatch, capsys
):
    fake = _update(tmp_path, monkeypatch, payload)

    assert fake.gets == ["findings/VA-1"]
    assert fake.patches == [("findings/VA-1", {**payload, "expected_row_version": 7})]
    err = capsys.readouterr().err
    assert "expected_row_version" in err and "7" in err


@pytest.mark.parametrize(
    ("payload", "named"),
    [
        ({"summary": "working copy"}, "summary"),
        ({"severity": "high"}, "severity"),
        ({"canonical_location": "GET /api/orders/{id}"}, "canonical_location"),
        ({"evidence_ref": "scans/idor.txt"}, "evidence_ref"),
        ({"details": {"steps_to_reproduce": "1. Request order 2"}}, "details.steps_to_reproduce"),
        (
            {"title": "t", "details": {"remediation": "r", "impact": "Reads any order."}},
            "details.impact",
        ),
    ],
)
def test_update_payload_claim_fields_need_the_token_the_author_read(
    payload, named, tmp_path, monkeypatch, capsys
):
    # A payload file is composed from a read of the finding. A token fetched at
    # PATCH time would make the compare-and-swap vacuous and let the file erase
    # a concurrent writer's change to the claim the verdict rests on.
    fake = _FakeClient()
    with pytest.raises(SystemExit) as exc:
        _update(tmp_path, monkeypatch, payload, fake=fake)

    assert exc.value.code == 1
    assert fake.patches == [] and fake.gets == []
    err = capsys.readouterr().err
    assert named in err
    assert "expected_row_version" in err and "--expected-row-version" in err


def test_update_payload_claim_fields_use_the_token_the_file_carries(tmp_path, monkeypatch):
    fake = _update(
        tmp_path, monkeypatch,
        {"summary": "working copy", "details": {"impact": "x"}, "expected_row_version": 3},
    )

    assert fake.gets == []
    assert fake.patches[0][1]["expected_row_version"] == 3


@pytest.mark.parametrize(
    "payload",
    [
        {"notes": "rewritten", "notes_mode": "replace"},
        {"notes": "rewritten", "notes_mode": "rotate"},
        {"details": {"impact": "x"}, "details_mode": "replace"},
    ],
)
def test_update_replace_and_rotate_still_need_the_token_the_author_read(
    payload, tmp_path, monkeypatch, capsys
):
    err = _refused_update(tmp_path, monkeypatch, capsys, payload)

    assert "expected_row_version" in err and "--expected-row-version" in err


def test_update_replace_takes_the_token_from_the_flag(tmp_path, monkeypatch):
    fake = _update(
        tmp_path, monkeypatch, {"notes": "rewritten", "notes_mode": "replace"},
        "--expected-row-version", "5",
    )

    assert fake.gets == []
    assert fake.patches[0][1]["expected_row_version"] == 5


def test_update_a_written_token_must_still_be_usable(tmp_path, monkeypatch, capsys):
    err = _refused_update(
        tmp_path, monkeypatch, capsys, {"summary": "s", "expected_row_version": 0}
    )

    assert "expected_row_version" in err


# -- notes default to append --------------------------------------------------


def test_update_payload_notes_without_a_mode_append(tmp_path, monkeypatch, capsys):
    fake = _update(tmp_path, monkeypatch, {"notes": "checkpoint"})

    assert fake.patches == [
        ("findings/VA-1", {"notes": "checkpoint", "notes_mode": "append"})
    ]
    # An append commutes server-side; it needs no read.
    assert fake.gets == []
    assert "notes_mode" in capsys.readouterr().err


def test_update_payload_notes_with_an_unknown_mode_is_refused(tmp_path, monkeypatch, capsys):
    err = _refused_update(
        tmp_path, monkeypatch, capsys,
        {"notes": "n", "notes_mode": "overwrite", "expected_row_version": 4},
    )

    assert "notes_mode" in err


# -- verify -------------------------------------------------------------------


def _verify_payload(**over) -> dict:
    payload = {
        "verification_status": "pending_runtime_proof",
        "reason_text": "Runtime trigger still owed.",
        "next_test": dict(_PLAN),
    }
    payload.update(over)
    return payload


def _verify(engagement, payload: dict, *flags: str) -> None:
    path = engagement / "verify.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    cli.main([
        "--engagement-dir", str(engagement), "finding", "verify", "CH-001",
        "--payload-file", str(path), *flags,
    ])


def _file_backend(monkeypatch, **finding) -> _Backend:
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1"},
            **finding,
        }
    )
    backend.install(monkeypatch)
    return backend


def test_verify_payload_file_derives_the_code_snapshot_binding(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _file_backend(monkeypatch)

    _verify(engagement, _verify_payload(), "--agent-id", "VF-1")

    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["code_snapshot"] == {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": _DIGEST,
    }
    assert provenance["agent_id"] == "VF-1"
    err = capsys.readouterr().err
    assert "code_snapshot" in err and "repo 7" in err


def test_verify_payload_file_authored_binding_still_wins(tmp_path, monkeypatch, capsys):
    engagement = _engagement(tmp_path)
    backend = _file_backend(monkeypatch)
    authored = {"repo_id": 7, "repo_generation": 2, "source_manifest_digest": _DIGEST}

    _verify(
        engagement,
        _verify_payload(provenance={"agent_id": "VF-1", "code_snapshot": authored}),
    )

    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["code_snapshot"] == authored


def test_verify_payload_file_does_not_derive_over_a_stale_binding(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _file_backend(monkeypatch, code_snapshot_status="stale")

    with pytest.raises(SystemExit):
        _verify(engagement, _verify_payload(), "--agent-id", "VF-1")

    assert "superseded source snapshot" in capsys.readouterr().err
    assert backend.posts == []


def test_verify_control_flags_fill_and_conflicts_are_refused(
    tmp_path, monkeypatch, capsys
):
    engagement = _engagement(tmp_path)
    backend = _file_backend(monkeypatch, canonical_location="https://app.example/a")
    payload = _verify_payload()
    del payload["reason_text"]

    _verify(
        engagement, payload,
        "--agent-id", "VF-1", "--reason", "Runtime trigger still owed.",
        "--reason-code", "needs_runtime", "--source-name", "code-vuln-verifier",
    )

    sent = backend.payload_for("findings/CH-001/verify")
    assert sent["provenance"] == {"agent_id": "VF-1"}
    assert sent["reason_text"] == "Runtime trigger still owed."
    assert sent["reason_code"] == "needs_runtime"
    assert sent["source_name"] == "code-vuln-verifier"
    assert "from flags" in capsys.readouterr().err

    backend.posts.clear()
    with pytest.raises(SystemExit):
        _verify(
            engagement, _verify_payload(provenance={"agent_id": "VF-2"}),
            "--agent-id", "VF-1",
        )
    err = capsys.readouterr().err
    assert "--agent-id" in err and "VF-2" in err and "VF-1" in err
    assert backend.posts == []


def test_verify_content_flags_still_conflict_with_the_file(tmp_path, monkeypatch, capsys):
    engagement = _engagement(tmp_path)
    backend = _file_backend(monkeypatch)

    with pytest.raises(SystemExit):
        _verify(engagement, _verify_payload(), "--status", "blocked")

    assert "--status" in capsys.readouterr().err
    assert backend.posts == []
