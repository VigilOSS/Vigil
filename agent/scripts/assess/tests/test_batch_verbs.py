"""CLI tests for batch support + finding mutation input contracts.

The canonical batch convention (Part 2): the entity slug/id positional is
``nargs="+"`` and shared verification flags apply to every listed entity via a
resilient loop with a per-entity failure tally. verify/kill/update additionally
migrated structured request documents to ``--payload-file`` (a JSON blob passed
positionally or through the retired generic ``--inline`` flag is rejected with
migration guidance).

Backend + runtime are stubbed; these pin the loop fan-out, the partial-failure
tally + non-zero exit, single-slug backward-compat output, and the payload-flag
migration for verify/kill/update.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from assess.commands import (
    link_finding,
    resolve,
    update_finding,
    verify_finding,
)


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records post/patch/put/delete calls; ``fail_on`` forces a per-call error."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []
        self.deletes: list[str] = []
        self._fail_on = fail_on or set()

    def _maybe_fail(self, endpoint: str) -> None:
        if any(token in endpoint for token in self._fail_on):
            raise RuntimeError(f"boom on {endpoint}")

    def post(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.posts.append((endpoint, payload))
        response = {"endpoint": endpoint, "ok": True}
        if endpoint.startswith("findings/") and endpoint.endswith("/verify"):
            response["finding"] = {"slug": endpoint.split("/")[1]}
        elif endpoint == "artifacts":
            path = Path(payload["path"])
            response.update(
                {
                    "id": len(self.posts),
                    "relative_path": path.name if path.is_absolute() else path.as_posix(),
                }
            )
        return response

    def patch(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.patches.append((endpoint, payload))
        response_id = (
            int(endpoint.rsplit("/", 1)[-1])
            if endpoint.startswith(("surfaces/", "coverage-items/"))
            else len(self.patches)
        )
        response = {"endpoint": endpoint, "id": response_id, **payload}
        if endpoint.startswith("findings/") and "/links/" not in endpoint:
            response["finding"] = {"slug": endpoint.split("/")[1]}
        return response

    def get(self, endpoint: str) -> dict:
        self._maybe_fail(endpoint)
        return {"slug": endpoint.rsplit("/", 1)[-1], "row_version": 7}

    def put(self, endpoint: str, payload: dict) -> dict:
        self._maybe_fail(endpoint)
        self.puts.append((endpoint, payload))
        if endpoint.startswith("findings/") and endpoint.endswith("/root-cause"):
            return {
                "id": len(self.puts),
                "finding_slug": endpoint.split("/")[1],
                "root_cause_slug": payload["root_cause_slug"],
            }
        return {"endpoint": endpoint, **payload}

    def delete(self, endpoint: str) -> dict:
        self._maybe_fail(endpoint)
        self.deletes.append(endpoint)
        return {"endpoint": endpoint, "deleted": True}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _install(monkeypatch, module, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(module, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)


def _parse(module, argv, tmp_path) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    module.register(sub)
    args = parser.parse_args(argv)
    args.engagement_dir = str(tmp_path)
    return args


# ──────────────────────────────────────────────────────────────────────────
# Batch fan-out + partial-failure tally + single-slug backward-compat
# ──────────────────────────────────────────────────────────────────────────


def test_verify_batch_applies_same_payload_to_each(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "VA-2", "VA-3",
            "--status", "confirmed",
            "--reason", "reproduced",
            "--proof-receipt-id", "17",
        ],
        tmp_path,
    )
    verify_finding.run(args)
    err = capsys.readouterr().err
    assert [ep for ep, _ in fake.posts] == [
        "findings/VA-1/verify",
        "findings/VA-2/verify",
        "findings/VA-3/verify",
    ]
    # Same payload object applied to each.
    assert all(
        p["verification_status"] == "confirmed"
        and p["reason_text"] == "reproduced"
        and p["proof_receipt_ids"] == [17]
        for _, p in fake.posts
    )
    assert "verified 3 finding(s); 0 failed" in err


def test_verify_partial_failure_tally_and_nonzero_exit(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(fail_on={"VA-2"})
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "VA-2",
            "--status", "confirmed",
            "--reason", "r",
            "--proof-receipt-id", "17",
        ],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "VA-2 failed" in err
    assert "verified 1 finding(s); 1 failed" in err
    # The healthy slug still went through.
    assert [ep for ep, _ in fake.posts] == ["findings/VA-1/verify"]


def test_verify_single_slug_prints_single_json(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1",
            "--status", "confirmed",
            "--reason", "r",
            "--proof-receipt-id", "17",
        ],
        tmp_path,
    )
    verify_finding.run(args)
    out = capsys.readouterr().out
    # Single-slug backward compat: one pretty-printed JSON object on stdout.
    parsed = json.loads(out)
    assert parsed["endpoint"] == "findings/VA-1/verify"


def test_verify_false_positive_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    counter_check_path = tmp_path / "counter-check.json"
    counter_check = {
        "method": "trace guarded path",
        "expected_result": "attacker input reaches the sink",
        "observed_result": "every path is rejected before the sink",
        "falsified_claim": "attacker input reaches the sink",
        "completed": True,
        "proof_receipt_ids": [17],
    }
    counter_check_path.write_text(json.dumps(counter_check), encoding="utf-8")
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "VA-2",
            "--status", "false_positive",
            "--reason", "r",
            "--counter-check-file", str(counter_check_path),
        ],
        tmp_path,
    )
    verify_finding.run(args)
    assert [ep for ep, _ in fake.posts] == ["findings/VA-1/verify", "findings/VA-2/verify"]
    assert all(
        p["verification_status"] == "false_positive"
        and p["counter_check"] == counter_check
        for _, p in fake.posts
    )
    assert "verified 2 finding(s); 0 failed" in capsys.readouterr().err


def test_update_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "VA-2", "--status", "reported", "--reason", "published"],
        tmp_path,
    )
    update_finding.run(args)
    assert [ep for ep, _ in fake.patches] == ["findings/VA-1", "findings/VA-2"]
    assert all(payload["expected_row_version"] == 7 for _, payload in fake.patches)
    assert "updated 2 finding(s); 0 failed" in capsys.readouterr().err


def test_reopen_draft_batch(tmp_path, monkeypatch, capsys):
    # reset-finding folded into `update-finding --status draft` (2026-07 CLI
    # consolidation): reopening for re-triage is a workflow_status patch.
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "VA-2", "--status", "draft", "--reason", "retest"],
        tmp_path,
    )
    update_finding.run(args)
    assert [ep for ep, _ in fake.patches] == ["findings/VA-1", "findings/VA-2"]
    assert all(p["workflow_status"] == "draft" for _, p in fake.patches)
    assert "updated 2 finding(s); 0 failed" in capsys.readouterr().err


def test_resolve_surface_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, resolve, tmp_path, fake)
    args = _parse(
        resolve,
        ["resolve", "surface", "42", "99", "17", "--status", "covered", "--rationale", "same verdict"],
        tmp_path,
    )
    resolve.run(args)
    assert [ep for ep, _ in fake.patches] == ["surfaces/42", "surfaces/99", "surfaces/17"]
    assert "resolved 3 surface(s); 0 failed" in capsys.readouterr().err


def test_resolve_coverage_item_batch(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, resolve, tmp_path, fake)
    args = _parse(
        resolve,
        ["resolve", "coverage-item", "77", "88", "--status", "covered", "--rationale", "tested both"],
        tmp_path,
    )
    resolve.run(args)
    assert [ep for ep, _ in fake.patches] == ["coverage-items/77", "coverage-items/88"]
    assert "resolved 2 item(s); 0 failed" in capsys.readouterr().err


def test_link_finding_batch_many_siblings_one_root(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, link_finding, tmp_path, fake)
    args = _parse(
        link_finding,
        ["link", "VA-2", "VA-3", "VA-4", "--root-cause", "VA-1"],
        tmp_path,
    )
    link_finding.run(args)
    assert [ep for ep, _ in fake.puts] == [
        "findings/VA-2/root-cause",
        "findings/VA-3/root-cause",
        "findings/VA-4/root-cause",
    ]
    assert all(p["root_cause_slug"] == "VA-1" for _, p in fake.puts)
    assert "linked 3 finding(s); 0 failed" in capsys.readouterr().err


# ──────────────────────────────────────────────────────────────────────────
# verify/kill/update payload-file and explicit-flag contracts
# ──────────────────────────────────────────────────────────────────────────


def test_verify_payload_file_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text(
        json.dumps(
            {
                "verification_status": "confirmed",
                "reason_text": "from file",
                "proof_receipt_ids": [17],
            }
        ),
        encoding="utf-8",
    )
    args = _parse(verify_finding, ["verify", "VA-1", "--payload-file", str(payload_path)], tmp_path)
    verify_finding.run(args)
    _, payload = fake.posts[0]
    assert payload["verification_status"] == "confirmed"
    assert payload["reason_text"] == "from file"
    assert payload["proof_receipt_ids"] == [17]


def test_verify_inline_tombstone_points_to_supported_inputs(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        ["verify", "VA-1", "--inline", '{"verification_status":"confirmed","reason_text":"inline"}'],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "--inline was removed" in err
    assert "--payload-file" in err and "--status" in err
    assert fake.posts == []


def test_verify_rejects_positional_json_blob(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(verify_finding, ["verify", "VA-1", '{"verification_status":"confirmed"}'], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "looks like a JSON payload" in err
    assert "--payload-file" in err and "--inline" not in err
    assert fake.posts == []


def test_verify_rejects_positional_json_file(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text("{}", encoding="utf-8")
    args = _parse(verify_finding, ["verify", "VA-1", str(payload_path)], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    assert "positional payload arg" in capsys.readouterr().err
    assert fake.posts == []


def test_verify_status_as_slug_hint(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(verify_finding, ["verify", "confirmed"], tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "looks like a verification status" in err and "--status confirmed" in err


def test_verify_false_positive_payload_file_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "kill.json"
    counter_check = {
        "method": "trace guarded path",
        "expected_result": "attacker input reaches the sink",
        "observed_result": "every path is rejected before the sink",
        "falsified_claim": "attacker input reaches the sink",
        "completed": True,
        "proof_receipt_ids": [17],
    }
    payload_path.write_text(
        json.dumps(
            {
                "verification_status": "false_positive",
                "reason_text": "guarded",
                "counter_check": counter_check,
            }
        ),
        encoding="utf-8",
    )
    args = _parse(verify_finding, ["verify", "VA-1", "--payload-file", str(payload_path)], tmp_path)
    verify_finding.run(args)
    assert fake.posts[0][0] == "findings/VA-1/verify"
    assert fake.posts[0][1]["counter_check"] == counter_check


def test_update_inline_tombstone_points_to_supported_inputs(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "--inline", '{"workflow_status":"draft","reason_text":"needs evidence"}'],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "--inline was removed" in err
    assert "--payload-file" in err and "explicit patch flags" in err
    assert fake.patches == []


def test_inline_tombstones_are_hidden_from_help(tmp_path, capsys):
    for module, verb in ((update_finding, "update"), (verify_finding, "verify")):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        module.register(sub)
        with pytest.raises(SystemExit) as exc:
            parser.parse_args([verb, "--help"])
        assert exc.value.code == 0
        assert "--inline" not in capsys.readouterr().out


def test_update_payload_file_is_single_slug_and_requires_row_version(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload_path = tmp_path / "patch.json"
    payload_path.write_text(json.dumps({"summary": "working copy"}), encoding="utf-8")

    args = _parse(update_finding, ["update", "VA-1", "--payload-file", str(payload_path)], tmp_path)
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    assert "expected_row_version" in capsys.readouterr().err

    payload_path.write_text(
        json.dumps({"summary": "working copy", "expected_row_version": 4}),
        encoding="utf-8",
    )
    args = _parse(
        update_finding,
        ["update", "VA-1", "VA-2", "--payload-file", str(payload_path)],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    assert "exactly one finding slug" in capsys.readouterr().err
    assert fake.patches == []


def test_update_rejects_expected_row_version_without_a_mutation(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", "--expected-row-version", "4"],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "do not update a finding" in capsys.readouterr().err
    assert fake.patches == []


@pytest.mark.parametrize(
    "payload",
    [
        {"expected_row_version": 4},
        {
            "expected_row_version": 4,
            "notes_mode": "append",
            "details_mode": "merge",
        },
    ],
)
def test_update_payload_file_rejects_only_concurrency_and_mode_controls(
    payload, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload_path = tmp_path / "patch.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    args = _parse(
        update_finding,
        ["update", "VA-1", "--payload-file", str(payload_path)],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "do not update a finding" in capsys.readouterr().err
    assert fake.patches == []


def test_update_rejects_transition_metadata_without_a_mutation(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        [
            "update",
            "VA-1",
            "--reason-code",
            "checkpoint",
            "--reason",
            "No finding field changed.",
            "--artifact-ref",
            "evidence/no-op.txt",
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "do not update a finding" in capsys.readouterr().err
    assert fake.patches == []


@pytest.mark.parametrize(
    "payload",
    [
        {
            "summary": None,
            "notes": None,
            "details": None,
            "provenance": None,
            "expected_row_version": 4,
        },
        {
            "summary": "",
            "notes": "",
            "notes_mode": "append",
            "details": {},
            "details_mode": "merge",
            "provenance": {},
            "expected_row_version": 4,
        },
    ],
)
def test_update_payload_file_rejects_null_and_empty_merge_noops(
    payload, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload_path = tmp_path / "patch.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    args = _parse(
        update_finding,
        ["update", "VA-1", "--payload-file", str(payload_path)],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "do not update a finding" in capsys.readouterr().err
    assert fake.patches == []


@pytest.mark.parametrize(
    ("clear_args", "expected_payload"),
    [
        (
            ["--notes", "", "--notes-replace"],
            {"notes": "", "notes_mode": "replace", "expected_row_version": 4},
        ),
        (
            ["--details-inline", "{}", "--details-replace"],
            {"details": {}, "details_mode": "replace", "expected_row_version": 4},
        ),
    ],
)
def test_update_allows_intentional_empty_replacements_with_cas(
    clear_args, expected_payload, tmp_path, monkeypatch
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        ["update", "VA-1", *clear_args, "--expected-row-version", "4"],
        tmp_path,
    )

    update_finding.run(args)

    assert fake.patches == [("findings/VA-1", expected_payload)]


def test_update_exposes_notes_rotation_with_cas(tmp_path, monkeypatch):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        [
            "update",
            "VA-1",
            "--notes",
            "new working notes",
            "--notes-rotate",
            "--expected-row-version",
            "4",
        ],
        tmp_path,
    )

    update_finding.run(args)

    assert fake.patches == [
        (
            "findings/VA-1",
            {
                "notes": "new working notes",
                "notes_mode": "rotate",
                "expected_row_version": 4,
            },
        )
    ]


@pytest.mark.parametrize("notes_mode", [None, "invalid"])
def test_update_payload_file_notes_require_explicit_valid_mode(
    notes_mode, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload = {"notes": "cumulative notes", "expected_row_version": 4}
    if notes_mode is not None:
        payload["notes_mode"] = notes_mode
    payload_path = tmp_path / "patch.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    args = _parse(update_finding, ["update", "VA-1", "--payload-file", str(payload_path)], tmp_path)

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "notes_mode" in capsys.readouterr().err
    assert fake.patches == []


def test_update_payload_file_preserves_iterative_patch_and_does_not_rewrite_file(
    tmp_path, monkeypatch
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload_path = tmp_path / "patch.json"
    raw = json.dumps(
        {
            "notes": "current working account",
            "notes_mode": "replace",
            "details": {"cvss_score": 7.5},
            "details_mode": "replace",
            "provenance": {"agent": "VA"},
            "expected_row_version": 4,
        },
        indent=2,
    )
    payload_path.write_text(raw, encoding="utf-8")
    args = _parse(update_finding, ["update", "VA-1", "--payload-file", str(payload_path)], tmp_path)

    update_finding.run(args)

    assert fake.patches == [("findings/VA-1", json.loads(raw))]
    assert payload_path.read_text(encoding="utf-8") == raw


@pytest.mark.parametrize(
    "replace_args",
    [
        ["--notes", "replacement notes", "--notes-replace"],
        ["--details-inline", '{"impact":"replacement"}', "--details-replace"],
    ],
)
def test_destructive_replace_flags_require_expected_row_version(
    replace_args, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(update_finding, ["update", "VA-1", *replace_args], tmp_path)

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "--expected-row-version" in capsys.readouterr().err
    assert fake.patches == []


def test_destructive_replace_flags_carry_expected_row_version(
    tmp_path, monkeypatch
):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(
        update_finding,
        [
            "update",
            "VA-1",
            "--details-inline",
            '{"impact":"replacement"}',
            "--details-replace",
            "--expected-row-version",
            "7",
        ],
        tmp_path,
    )

    update_finding.run(args)

    assert fake.patches == [
        (
            "findings/VA-1",
            {
                "details": {"impact": "replacement"},
                "details_mode": "replace",
                "expected_row_version": 7,
            },
        )
    ]


def test_update_payload_file_rejects_request_content_flags(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    payload_path = tmp_path / "patch.json"
    payload_path.write_text(json.dumps({"summary": "file", "expected_row_version": 4}), encoding="utf-8")
    args = _parse(
        update_finding,
        ["update", "VA-1", "--payload-file", str(payload_path), "--summary", "flag"],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    assert "cannot be combined" in capsys.readouterr().err
    assert fake.patches == []


@pytest.mark.parametrize(
    ("module", "content_flag"),
    [
        (update_finding, ["--summary", ""]),
        (verify_finding, ["--notes", ""]),
    ],
)
def test_payload_file_rejects_explicit_empty_content_flags(
    module, content_flag, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, module, tmp_path, fake)
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(
        json.dumps(
            {"summary": "file", "expected_row_version": 4}
            if module is update_finding
            else {
                "verification_status": "confirmed",
                "reason_text": "final",
                "proof_receipt_ids": [17],
            }
        ),
        encoding="utf-8",
    )
    action = "update" if module is update_finding else "verify"
    args = _parse(
        module,
        [action, "VA-1", "--payload-file", str(payload_path), *content_flag],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        module.run(args)

    assert exc.value.code == 1
    assert "cannot be combined" in capsys.readouterr().err
    assert fake.posts == [] and fake.patches == []


@pytest.mark.parametrize(
    ("module", "argv"),
    [
        (
            update_finding,
            ["update", "VA-1", "--payload-file", "", "--summary", "partial"],
        ),
        (
            verify_finding,
            [
                "verify",
                "VA-1",
                "--payload-file",
                "",
                "--status",
                "confirmed",
                "--reason",
                "partial",
                "--proof-receipt-id",
                "17",
            ],
        ),
    ],
)
def test_empty_payload_file_never_falls_through_to_explicit_flags(
    module, argv, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, module, tmp_path, fake)
    args = _parse(module, argv, tmp_path)

    with pytest.raises(SystemExit) as exc:
        module.run(args)

    assert exc.value.code == 1
    assert "--payload-file must not be empty" in capsys.readouterr().err
    assert fake.posts == [] and fake.patches == []


def test_verify_payload_file_rejects_content_flags_but_allows_narrative(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text(
        json.dumps(
            {
                "verification_status": "confirmed",
                "reason_text": "final",
                "proof_receipt_ids": [17],
            }
        ),
        encoding="utf-8",
    )
    narrative = tmp_path / "debate.md"
    narrative.write_text("final debate", encoding="utf-8")
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "--payload-file", str(payload_path),
            "--reason", "flag", "--narrative", str(narrative),
        ],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)
    assert exc.value.code == 1
    assert "cannot be combined" in capsys.readouterr().err
    assert fake.posts == []

    args = _parse(
        verify_finding,
        ["verify", "VA-1", "--payload-file", str(payload_path), "--narrative", str(narrative)],
        tmp_path,
    )
    verify_finding.run(args)
    assert [endpoint for endpoint, _ in fake.posts] == ["findings/VA-1/verify", "artifacts"]


def test_verify_rejects_narrative_artifact_receipt_without_canonical_identity(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    original_post = fake.post

    def post(endpoint: str, payload: dict) -> dict:
        if endpoint == "artifacts":
            fake.posts.append((endpoint, payload))
            return {"message": "accepted"}
        return original_post(endpoint, payload)

    fake.post = post
    _install(monkeypatch, verify_finding, tmp_path, fake)
    narrative = tmp_path / "debate.md"
    narrative.write_text("verified narrative", encoding="utf-8")
    args = _parse(
        verify_finding,
        [
            "verify",
            "VA-1",
            "--status",
            "confirmed",
            "--reason",
            "reproduced",
            "--proof-receipt-id",
            "17",
            "--narrative",
            str(narrative),
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    error = capsys.readouterr().err
    assert "canonical artifact" in error
    assert "do not retry automatically" in error


def test_verify_reports_committed_verification_when_narrative_registration_fails(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient(fail_on={"artifacts"})
    _install(monkeypatch, verify_finding, tmp_path, fake)
    narrative = tmp_path / "debate.md"
    narrative.write_text("verified narrative", encoding="utf-8")
    args = _parse(
        verify_finding,
        [
            "verify",
            "VA-1",
            "--status",
            "confirmed",
            "--reason",
            "reproduced",
            "--proof-receipt-id",
            "17",
            "--narrative",
            str(narrative),
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["finding"]["slug"] == "VA-1"
    assert "verification committed" in captured.err
    assert "narrative registration failed" in captured.err
    assert "do not retry the verification" in captured.err.lower()
    assert "verified 0" not in captured.err


def test_verify_payload_file_treats_proof_receipt_as_a_content_flag(
    tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    payload_path = tmp_path / "verify.json"
    payload_path.write_text(
        json.dumps(
            {
                "verification_status": "confirmed",
                "reason_text": "final",
                "proof_receipt_ids": [17],
            }
        ),
        encoding="utf-8",
    )
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "--payload-file", str(payload_path),
            "--proof-receipt-id", "18",
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    assert "--proof-receipt-id" in capsys.readouterr().err
    assert fake.posts == []


@pytest.mark.parametrize(
    ("arguments", "expected_error"),
    [
        (
            [
                "verify",
                "VA-1",
                "--status",
                "confirmed",
                "--reason",
                "reproduced",
                "--proof-receipt-id",
                "17",
                "--details-inline",
                json.dumps({"remediaton": "fix it"}),
            ],
            "details.remediaton is not allowed",
        ),
    ],
)
def test_verify_validates_details_against_the_record_contract(
    arguments, expected_error, tmp_path, monkeypatch, capsys
):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)

    args = _parse(verify_finding, arguments, tmp_path)
    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    assert expected_error in capsys.readouterr().err
    assert fake.posts == []


@pytest.mark.parametrize("command", ["verify", "update"])
def test_finding_mutations_reject_response_without_the_canonical_finding(
    command, tmp_path, monkeypatch, capsys
):
    class EmptyResponseClient(_FakeClient):
        def post(self, endpoint: str, payload: dict) -> dict:
            super().post(endpoint, payload)
            return {}

        def patch(self, endpoint: str, payload: dict) -> dict:
            super().patch(endpoint, payload)
            return {}

    fake = EmptyResponseClient()
    module = verify_finding if command == "verify" else update_finding
    _install(monkeypatch, module, tmp_path, fake)
    arguments = (
        [
            "verify", "VA-1",
            "--status", "confirmed",
            "--reason", "reproduced",
            "--proof-receipt-id", "17",
        ]
        if command == "verify"
        else ["update", "VA-1", "--summary", "corrected claim"]
    )

    with pytest.raises(SystemExit) as exc:
        module.run(_parse(module, arguments, tmp_path))

    assert exc.value.code == 1
    error = capsys.readouterr().err
    assert "canonical finding VA-1" in error
    assert "do not retry automatically" in error


def test_update_rejects_positional_json_file(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)
    args = _parse(update_finding, ["update", "VA-1", "patch.json", "--status", "reported"], tmp_path)
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    assert "looks like a JSON payload" in capsys.readouterr().err
    assert fake.patches == []


def test_update_validates_details_against_the_record_contract(
    tmp_path, monkeypatch, capsys
):
    """`finding update` checks `details` the way `finding record` does.

    Recording a finding and patching one have to agree on what a detail key is
    called and what type it holds. With only the create path checked, a mistyped
    or misspelled key patched in cleanly, persisted, and then read as absent —
    surfacing much later as an export gate naming a field the author could see
    they had written. Required fields are still skipped, because a patch
    legitimately carries a subset.
    """
    fake = _FakeClient()
    _install(monkeypatch, update_finding, tmp_path, fake)

    # A misspelled key earns a did-you-mean and writes nothing.
    args = _parse(
        update_finding,
        ["update", "VA-1", "--details-inline", json.dumps({"remediaton": "fix it"})],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "remediaton is not allowed" in err
    assert "Did you mean: remediation?" in err
    assert fake.patches == []

    # A wrong type is caught too — this is the shape mismatch that used to
    # persist and then read as an empty field at export time.
    args = _parse(
        update_finding,
        ["update", "VA-1", "--details-inline", json.dumps({"steps_to_reproduce": 42})],
        tmp_path,
    )
    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)
    assert exc.value.code == 1
    assert "steps_to_reproduce" in capsys.readouterr().err
    assert fake.patches == []

    # A partial patch of valid keys goes through: `required` is not enforced, and
    # both authored shapes of steps_to_reproduce are accepted.
    for steps in ("1. Log in\n2. GET /orders/1001", ["Log in", "GET /orders/1001"]):
        fake.patches.clear()
        args = _parse(
            update_finding,
            [
                "update",
                "VA-1",
                "--details-inline",
                json.dumps({"steps_to_reproduce": steps, "vrt_category": "broken_access_control.idor"}),
            ],
            tmp_path,
        )
        update_finding.run(args)
        capsys.readouterr()
        assert len(fake.patches) == 1


def test_verify_rejects_new_severity_outside_downgraded_before_the_post(
    tmp_path, monkeypatch, capsys
):
    """``--new-severity`` is consumed ONLY by the downgraded status; under
    any other one the backend silently dropped it and answered 200. Fail here,
    naming the verb that actually re-bands a finding, so nothing is sent."""
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1",
            "--status", "confirmed",
            "--reason", "reproduced",
            "--proof-receipt-id", "17",
            "--new-severity", "low",
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    assert fake.posts == []
    err = capsys.readouterr().err
    assert "new_severity applies only to --status downgraded" in err
    assert "finding update VA-1 --severity low" in err


def test_verify_new_severity_rejection_names_every_slug_in_the_batch(
    tmp_path, monkeypatch, capsys
):
    """The remedy has to cover the whole batch, not just its first slug.

    `finding verify A B C --new-severity low` is one intent over three findings.
    A message naming only A would be followed literally: A gets re-banded and
    B and C silently keep the old severity — the exact silent partial the
    rejection exists to prevent."""
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1", "VA-2", "VA-3",
            "--status", "confirmed",
            "--reason", "reproduced",
            "--proof-receipt-id", "17",
            "--new-severity", "low",
        ],
        tmp_path,
    )

    with pytest.raises(SystemExit) as exc:
        verify_finding.run(args)

    assert exc.value.code == 1
    assert fake.posts == []
    err = capsys.readouterr().err
    assert "finding update VA-1 VA-2 VA-3 --severity low" in err


def test_verify_downgraded_still_forwards_new_severity(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, verify_finding, tmp_path, fake)
    args = _parse(
        verify_finding,
        [
            "verify", "VA-1",
            "--status", "downgraded",
            "--reason", "over-scored",
            "--proof-receipt-id", "17",
            "--new-severity", "medium",
        ],
        tmp_path,
    )

    verify_finding.run(args)
    capsys.readouterr()

    assert fake.posts[0][1]["new_severity"] == "medium"
