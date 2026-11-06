"""What ``agent handoff`` checks about its own payload, and what it reports back.

The backend caps ``summary`` at 16384 characters on both ``HandoffCreate`` and
``HandoffUpdate``, so a specialist that writes a longer one used to learn about
it from an HTTP 422 after the request had already been built and sent. The
bound is mirrored client-side in ``_build_handoff_payload`` — the one point
every create payload and every partial-update patch passes through — so the
failure lands before the network, with the text still in the author's hands.
The same chokepoint rejects an unknown key by name (the create model forbids
extras while the patch path used to drop them silently) and carries the
``expected_handoff_version`` guard through to the update.

After the write, the receipt states every declared working artifact's on-disk
state. A ``ready`` handoff that claims a file it never wrote exits non-zero: the
row is already stored, so the exit code reports the unsubstantiated claim rather
than a failed write.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands.dispatch import agent as dispatch_agent


@pytest.fixture
def calls(monkeypatch, tmp_path):
    """Record every backend call the command makes; empty means no network."""
    recorded: list[tuple[str, object]] = []

    class _FakeClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def close(self) -> None:
            pass

        def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
            recorded.append(("record_handoff", payload))
            return {"id": 1, "agent_id": payload.get("agent_id"), "summary": payload.get("summary"), "handoff_version": 3, "last_checkpoint_at": "2026-10-23T12:00:00Z"}

        def get_handoff(self, agent_id: str) -> dict:
            recorded.append(("get_handoff", agent_id))
            return {"agent_id": agent_id, "summary": "prior"}

        def update_handoff(self, agent_id: str, patch: dict) -> dict:
            recorded.append(("update_handoff", patch))
            return {"id": 2, "agent_id": agent_id}

    monkeypatch.setattr(
        dispatch_agent, "AssessmentClient", lambda *a, **k: _FakeClient()
    )
    monkeypatch.setattr(
        dispatch_agent,
        "load_config",
        lambda *a, **k: SimpleNamespace(
            base_url="http://backend.invalid",
            engagement_key="key",
            engagement_dir=str(tmp_path),
        ),
    )
    return recorded


def _args(tmp_path, payload: dict) -> SimpleNamespace:
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return SimpleNamespace(from_json=str(path), engagement_dir=str(tmp_path), agent_id=payload.get("agent_id"))


def test_over_long_summary_on_a_create_payload_fails_before_any_request(
    tmp_path, capsys, calls
):
    args = _args(
        tmp_path,
        {
            "agent_id": "recon-1",
            "agent_role": "recon-specialist",
            "summary": "x" * 16385,
        },
    )

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "16385" in err
    assert "16384" in err
    for field in ("coverage_gaps", "next_steps", "runtime_issues"):
        assert field in err
    assert calls == []


def test_over_long_summary_on_a_partial_update_fails_before_any_request(
    tmp_path, capsys, calls
):
    # No agent_role: the patch path, which would otherwise GET the existing
    # handoff before PATCHing the summary in.
    args = _args(tmp_path, {"agent_id": "recon-1", "summary": "y" * 17000})

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "17000" in err
    assert "16384" in err
    for field in ("coverage_gaps", "next_steps", "runtime_issues"):
        assert field in err
    assert calls == []


def test_summary_exactly_at_the_cap_is_sent_unchanged(tmp_path, calls):
    summary = "z" * 16384
    args = _args(
        tmp_path,
        {
            "agent_id": "recon-1",
            "agent_role": "recon-specialist",
            "summary": summary,
        },
    )

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["record_handoff"]
    assert calls[0][1]["summary"] == summary


def test_a_payload_without_a_summary_is_unaffected(tmp_path, calls):
    args = _args(tmp_path, {"agent_id": "recon-1", "handoff_status": "ready"})

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["get_handoff", "update_handoff"]
    assert calls[1][1] == {"handoff_status": "ready"}


def test_the_mirrored_cap_still_matches_the_backend_it_mirrors():
    """The KEEP-IN-SYNC comment, made executable.

    A mirrored bound that drifts UPWARD lets the 422 back; one that drifts
    DOWNWARD is worse — the CLI refuses the specialist's own valid text on a
    stale local rule and there is no backend error to explain it. The assess
    suite runs on the backend venv, so the authority is importable here.
    """
    from app.api.assessment import HandoffCreate, HandoffUpdate

    def declared_max_length(model, field: str) -> int | None:
        return next(
            (
                meta.max_length
                for meta in model.model_fields[field].metadata
                if getattr(meta, "max_length", None) is not None
            ),
            None,
        )

    assert declared_max_length(HandoffCreate, "summary") == (
        dispatch_agent._HANDOFF_SUMMARY_MAX_CHARS
    )
    assert declared_max_length(HandoffUpdate, "summary") == (
        dispatch_agent._HANDOFF_SUMMARY_MAX_CHARS
    )

@pytest.mark.parametrize('summary', ['Acme audit complete. ' * 110, '界🙂' * 8192], ids=['ordinary-prose', 'unicode-boundary'])
def test_narrative_handoff_persists_authored_text_and_version_receipt(tmp_path, calls, capsys, summary):
    args = _args(tmp_path, {'agent_id': 'recon-1', 'agent_role': 'recon-specialist', 'summary': summary,
                            'next_steps': [{'action': 'review Acme evidence'}]})
    dispatch_agent._record_handoff(args)
    assert calls[0][1]['summary'] == summary
    assert calls[0][1]['next_steps'] == [{'action': 'review Acme evidence'}]
    receipt = json.loads(capsys.readouterr().out)
    assert receipt['handoff_version'] == 3
    assert receipt['last_checkpoint_at'] == '2026-10-23T12:00:00Z'
    assert receipt['summary_characters'] == len(summary)


def test_rejected_narrative_preserves_input_file(tmp_path, calls, capsys):
    args = _args(tmp_path, {'agent_id': 'recon-1', 'summary': '界' * 16385})
    original = open(args.from_json, 'rb').read()
    with pytest.raises(SystemExit):
        dispatch_agent._record_handoff(args)
    assert open(args.from_json, 'rb').read() == original
    assert calls == []
    assert '16385' in capsys.readouterr().err


def test_receipt_names_every_working_artifact_and_its_on_disk_state(tmp_path, calls, capsys):
    """The write path must report what it did and did not find on disk.

    A specialist can claim artifacts it never wrote; the backend already
    computes their absence while registering them and discards it, so the
    receipt is the only place the claim meets the filesystem.
    """
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "acme-written.txt").write_text("evidence", encoding="utf-8")
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme surface pass complete.",
        "working_artifacts": [
            {"path": "scans/acme-written.txt", "kind": "data"},
            {"path": "scans/acme-claimed.txt", "kind": "data"},
        ],
    })

    dispatch_agent._record_handoff(args)

    receipt = json.loads(capsys.readouterr().out)
    assert receipt["working_artifacts"] == [
        {"path": "scans/acme-written.txt", "state": "present"},
        {"path": "scans/acme-claimed.txt", "state": "missing"},
    ]


def test_checkpointed_handoff_warns_about_a_missing_artifact_without_failing(
    tmp_path, calls, capsys
):
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme pass in progress.",
        "handoff_status": "checkpointed",
        "working_artifacts": [{"path": "scans/acme-partial.txt"}],
    })

    dispatch_agent._record_handoff(args)

    captured = capsys.readouterr()
    assert json.loads(captured.out)["working_artifacts"][0]["state"] == "missing"
    assert "WARN" in captured.err
    assert "scans/acme-partial.txt" in captured.err
    assert [name for name, _ in calls] == ["record_handoff"]


def test_ready_handoff_claiming_an_unwritten_artifact_is_refused_after_the_write(
    tmp_path, calls, capsys
):
    """`ready` asserts a finished result, so an unwritten artifact is fabrication.

    The write still lands: discarding the specialist's authored summary would
    destroy durable state over a path typo. The non-zero exit reports the
    unsubstantiated claim, and the message says the row was persisted.
    """
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme pass complete; three artifacts written.",
        "handoff_status": "ready",
        "working_artifacts": [{"path": "scans/acme-never-written.txt"}],
    })

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["working_artifacts"][0]["state"] == "missing"
    assert "scans/acme-never-written.txt" in captured.err
    assert "ready" in captured.err
    assert "persisted" in captured.err
    assert [name for name, _ in calls] == ["record_handoff"]


def test_an_artifact_outside_the_engagement_is_reported_as_out_of_engagement(
    tmp_path, calls, capsys
):
    """The backend refuses to register it, so it can never render as present."""
    outside = tmp_path.parent / "acme-outside-engagement.txt"
    outside.write_text("evidence", encoding="utf-8")
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme pass complete.",
        "working_artifacts": [{"path": str(outside)}],
    })

    dispatch_agent._record_handoff(args)

    captured = capsys.readouterr()
    assert json.loads(captured.out)["working_artifacts"] == [
        {"path": str(outside), "state": "out-of-engagement"}
    ]
    assert "out-of-engagement" in captured.err


def test_unknown_handoff_keys_are_rejected_by_name_before_any_request(
    tmp_path, calls, capsys
):
    """The create path 422s an unknown key; the patch path dropped it silently."""
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme pass complete.",
        "workign_artifacts": [{"path": "scans/acme.txt"}],
        "recommneded_next_agent": "report-writer",
    })

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "workign_artifacts" in err
    assert "recommneded_next_agent" in err
    assert calls == []


def test_backend_managed_handoff_keys_are_rejected_with_the_guard_field_named(
    tmp_path, calls, capsys
):
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "handoff_status": "ready",
        "handoff_version": 4,
    })

    with pytest.raises(SystemExit) as exc:
        dispatch_agent._record_handoff(args)

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "handoff_version" in err
    assert "expected_handoff_version" in err
    assert calls == []


def test_expected_handoff_version_reaches_the_patch_as_a_guarded_write(tmp_path, calls):
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "handoff_status": "ready",
        "expected_handoff_version": 3,
    })

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["get_handoff", "update_handoff"]
    assert calls[1][1] == {"handoff_status": "ready", "expected_handoff_version": 3}


def test_a_guarded_full_checkpoint_patches_instead_of_posting(tmp_path, calls):
    """`expected_handoff_version` is forbidden on the create model, so a guarded
    write is always an update of the row the version names."""
    args = _args(tmp_path, {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "summary": "Acme pass complete.",
        "expected_handoff_version": 2,
    })

    dispatch_agent._record_handoff(args)

    assert [name for name, _ in calls] == ["get_handoff", "update_handoff"]
    assert calls[1][1]["expected_handoff_version"] == 2
    assert calls[1][1]["summary"] == "Acme pass complete."


@pytest.mark.parametrize("value", ["3", 0, -1, 1.5])
def test_a_malformed_expected_handoff_version_fails_before_the_network(
    tmp_path, calls, capsys, value
):
    args = _args(tmp_path, {"agent_id": "recon-1", "expected_handoff_version": value})

    with pytest.raises(SystemExit):
        dispatch_agent._record_handoff(args)

    assert "expected_handoff_version" in capsys.readouterr().err
    assert calls == []


def test_the_patchable_field_set_is_exactly_the_backend_update_model():
    """Any field the update model accepts must survive the patch filter.

    The filter silently dropped whatever it did not list, so a field added to
    ``HandoffUpdate`` without being added here would be accepted by the backend
    and never sent. The create-side roster is the same set minus the
    update-only version guard.
    """
    from app.api.assessment import HandoffCreate, HandoffUpdate

    assert set(dispatch_agent._HANDOFF_PATCHABLE_FIELDS) == set(HandoffUpdate.model_fields)
    assert set(dispatch_agent._HANDOFF_PAYLOAD_FIELDS) == (
        set(HandoffCreate.model_fields) | {"expected_handoff_version"}
    )


def test_every_handoff_schema_example_is_accepted_by_the_live_model():
    """The per-role examples are what specialists copy, so they must be writable.

    Blue role prompts put role-specific fields at the TOP level because the
    schema reference had no blue example to copy; every one of those keys is
    refused by name. This validates each fenced payload as DATA against the
    model that stores it, so an example can never advertise a shape the write
    door rejects.
    """
    import re
    from pathlib import Path

    from app.api.assessment import HandoffCreate

    reference = (
        Path(__file__).resolve().parents[3]
        / "references"
        / "runtime-guides"
        / "handoff-schema.md"
    )
    blocks = [
        block
        for block in re.findall(r"```json\n(.*?)\n```", reference.read_text(encoding="utf-8"), re.S)
        # Blocks carrying `...` are abbreviated CLI samples, not payloads.
        if "..." not in block
    ]
    assert len(blocks) >= 12
    for block in blocks:
        payload = json.loads(block)
        HandoffCreate.model_validate(payload)
        assert set(payload) <= set(dispatch_agent._HANDOFF_PAYLOAD_FIELDS)
