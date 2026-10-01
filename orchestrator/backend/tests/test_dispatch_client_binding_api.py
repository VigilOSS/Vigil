"""A dispatch row is bound to a live client session AFTER the client is launched.

``agent start`` writes the dispatch before the session exists, so the handle the
operator would use to message that specialist mid-flight has no home on the row.
These tests pin the post-launch binding: it is caller-asserted (never launcher- or
provider-observed), its history is append-only (a correction supersedes, it never
overwrites), and the CURRENT binding rides on every dispatch read so ``agent list``
and the resume brief show it without a second round trip.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import get_args

import pytest
from fastapi import HTTPException

from app import db as db_module


ENGAGEMENT_KEY = "2026-09-16-090000-client-bindings"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, engagements_dir: Path) -> None:
    engagement = engagements_dir / ENGAGEMENT_KEY
    engagement.mkdir(parents=True, exist_ok=True)
    (engagement / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-09-16T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _dispatch(client, agent_id: str = "code-hunter-3") -> dict:
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "code-vuln-hunter",
            "task": "Hunt deserialization sinks in the plugin tree",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _bind(client, agent_id: str, **overrides):
    payload = {
        "asserted_client": "claude",
        "asserted_session_namespace": "/Users/op/vigil/engagements/acme",
        "asserted_client_handle": "01JQZ4S8K2A0",
    }
    payload.update(overrides)
    return client.post(f"{BASE}/dispatches/{agent_id}/client-bindings", json=payload)


def test_binding_a_client_handle_is_visible_on_every_dispatch_read(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)

    created = _bind(client, "code-hunter-3")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["superseded"] is None
    binding = body["binding"]
    assert binding["agent_id"] == "code-hunter-3"
    assert binding["binding_version"] == 1
    assert binding["asserted_client"] == "claude"
    assert binding["asserted_session_namespace"] == "/Users/op/vigil/engagements/acme"
    assert binding["asserted_client_handle"] == "01JQZ4S8K2A0"
    assert binding["superseded_by_id"] is None
    assert binding["bound_at"]

    row = client.get(f"{BASE}/dispatches/code-hunter-3").json()
    assert row["client_binding_count"] == 1
    assert row["client_binding"]["asserted_client_handle"] == "01JQZ4S8K2A0"
    assert row["client_binding"]["binding_version"] == 1

    listed = client.get(f"{BASE}/dispatches").json()
    assert [entry["client_binding_count"] for entry in listed] == [1]
    assert listed[0]["client_binding"]["asserted_client"] == "claude"


def test_a_correction_supersedes_and_never_overwrites_the_prior_binding(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    first = _bind(client, "code-hunter-3").json()["binding"]

    corrected = _bind(
        client,
        "code-hunter-3",
        asserted_client="codex",
        asserted_client_handle="conv_7f31",
        note="claude session died; relaunched in codex",
    )
    assert corrected.status_code == 201, corrected.text
    body = corrected.json()
    assert body["binding"]["binding_version"] == 2
    assert body["binding"]["asserted_client_handle"] == "conv_7f31"
    assert body["binding"]["note"] == "claude session died; relaunched in codex"
    assert body["superseded"]["id"] == first["id"]
    assert body["superseded"]["superseded_by_id"] == body["binding"]["id"]

    history = client.get(f"{BASE}/dispatches/code-hunter-3/client-bindings")
    assert history.status_code == 200, history.text
    rows = history.json()
    assert [entry["binding_version"] for entry in rows] == [1, 2]
    # The first binding is still readable EXACTLY as it was asserted.
    assert rows[0]["asserted_client"] == "claude"
    assert rows[0]["asserted_client_handle"] == "01JQZ4S8K2A0"
    assert rows[0]["superseded_by_id"] == rows[1]["id"]
    assert rows[1]["superseded_by_id"] is None

    row = client.get(f"{BASE}/dispatches/code-hunter-3").json()
    assert row["client_binding_count"] == 2
    assert row["client_binding"]["binding_version"] == 2


def test_rebinding_the_identical_handle_is_refused_as_a_no_op(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    assert _bind(client, "code-hunter-3").status_code == 201

    repeat = _bind(client, "code-hunter-3")
    assert repeat.status_code == 409, repeat.text
    assert "already" in repeat.json()["detail"]

    history = client.get(f"{BASE}/dispatches/code-hunter-3/client-bindings").json()
    assert len(history) == 1


def test_a_bound_handle_never_reads_as_provider_observed(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    binding = _bind(client, "code-hunter-3").json()["binding"]

    # Same contract as the dispatch row's provider_observed_client: the field
    # exists so the ABSENCE of a measured handle is visible, and it is closed to
    # caller attestation until a client exposes a stable session id at this
    # boundary.
    assert binding["provider_observed_handle"] == "unknown"
    forged = _bind(
        client,
        "code-hunter-3",
        asserted_client_handle="other",
        provider_observed_handle="claimed-by-caller",
    )
    assert forged.status_code == 422, forged.text


def test_binding_requires_an_existing_dispatch(client, isolate_settings) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    missing = _bind(client, "never-dispatched")
    assert missing.status_code == 404, missing.text
    assert (
        client.get(f"{BASE}/dispatches/never-dispatched/client-bindings").status_code
        == 404
    )


def test_binding_rejects_an_unknown_or_empty_client(client, isolate_settings) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    # `unknown` is a legal value for a dispatch row's client_name; a binding
    # whose client is unknown identifies no session, so it is not legal here.
    assert _bind(client, "code-hunter-3", asserted_client="unknown").status_code == 422
    assert _bind(client, "code-hunter-3", asserted_client_handle="  ").status_code == 422
    assert (
        _bind(client, "code-hunter-3", asserted_session_namespace="").status_code == 422
    )


def test_binding_rows_are_append_only_in_the_schema(client, isolate_settings) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    binding = _bind(client, "code-hunter-3").json()["binding"]

    with db_module.get_connection() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE assessment_dispatch_client_bindings "
                "SET asserted_client_handle = ? WHERE id = ?",
                ("rewritten", binding["id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM assessment_dispatch_client_bindings WHERE id = ?",
                (binding["id"],),
            )


def test_the_resume_brief_carries_the_binding_on_recent_dispatches(
    client, isolate_settings
) -> None:
    """Rehydration must answer "where is this specialist reachable" from state."""
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    _bind(client, "code-hunter-3")

    brief = client.get(f"{BASE}/resume-brief")
    assert brief.status_code == 200, brief.text
    recent = brief.json()["dispatches"]["recent_dispatches"]
    assert len(recent) == 1
    assert recent[0]["client_binding"]["asserted_client"] == "claude"
    assert recent[0]["client_binding"]["asserted_client_handle"] == "01JQZ4S8K2A0"
    assert recent[0]["client_binding_count"] == 1


def test_the_bindable_client_roster_is_the_dispatch_roster_minus_unknown() -> None:
    """One roster, three spellings — pinned so they cannot drift apart."""
    from assess.lib.contracts import BINDABLE_CLIENTS
    from app.api import assessment

    assert set(get_args(assessment._DISPATCH_CLIENT)) == set(
        get_args(assessment._LAUNCHED_CLIENT)
    ) | {"unknown"}
    assert tuple(BINDABLE_CLIENTS) == get_args(assessment._LAUNCHED_CLIENT)


def test_binding_is_not_a_precondition_for_starting_a_dispatch(
    client, isolate_settings
) -> None:
    """`agent start` must keep succeeding with no handle — it does not exist yet."""
    _seed(client, isolate_settings["engagements_dir"])
    row = _dispatch(client, agent_id="unbound-1")

    assert row["status"] == "in-progress"
    assert row["client_binding"] is None
    assert row["client_binding_count"] == 0


def test_one_dispatch_can_never_hold_two_current_client_bindings(
    client, isolate_settings
) -> None:
    """The append-only trigger guards a row's CONTENT; nothing guarded the count.

    Every dispatch read LEFT JOINs the binding whose ``superseded_by_id`` is
    NULL, so a second current row does not merely duplicate the history — it
    fans the dispatch itself out into two rows in `agent list`, `agent get` and
    the resume brief. That cardinality has to be the schema's last word.
    """
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    first = _bind(client, "code-hunter-3").json()["binding"]

    forged_id: int | None = None
    with db_module.get_connection() as connection:
        engagement_id, dispatch_id = connection.execute(
            "SELECT engagement_id, dispatch_id FROM assessment_dispatch_client_bindings "
            "WHERE id = ?",
            (first["id"],),
        ).fetchone()
        try:
            cursor = connection.execute(
                """
                INSERT INTO assessment_dispatch_client_bindings (
                    engagement_id, dispatch_id, binding_version, superseded_by_id,
                    asserted_client, asserted_session_namespace,
                    asserted_client_handle, note, bound_at
                ) VALUES (?, ?, 2, NULL, 'codex', '/tmp/ns', 'conv_race', NULL, ?)
                """,
                (engagement_id, dispatch_id, first["bound_at"]),
            )
        except sqlite3.IntegrityError:
            pass
        else:
            forged_id = int(cursor.lastrowid)

    listed = client.get(f"{BASE}/dispatches").json()
    assert [entry["agent_id"] for entry in listed] == ["code-hunter-3"]
    assert (
        client.get(f"{BASE}/dispatches/code-hunter-3").json()["client_binding"][
            "asserted_client_handle"
        ]
        == "01JQZ4S8K2A0"
    )
    assert forged_id is None, "a second current binding must be refused by the schema"


def test_binding_a_client_handle_serializes_its_read_modify_write(
    client, isolate_settings
) -> None:
    """Reading the current binding, deriving the next version and writing both
    halves is one decision. Unserialized, two binds that read the same current
    row write two current rows — so this opens the same `BEGIN IMMEDIATE` its
    sibling queue and lead writers do."""
    from app.services.state_manager import dispatches as dispatches_service

    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    engagement_id = int(client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"])

    # Driven in-process, not through the TestClient: `get_connection` is
    # thread-local, and the trace callback has to sit on the connection the
    # service itself writes through.
    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
    try:
        dispatches_service.record_dispatch_client_binding(
            engagement_id,
            agent_id="code-hunter-3",
            asserted_client="claude",
            asserted_session_namespace="/Users/op/vigil/engagements/acme",
            asserted_client_handle="01JQZ4S8K2A0",
        )
    finally:
        with db_module.get_connection() as connection:
            connection.set_trace_callback(None)

    assert any(
        statement.strip().upper() == "BEGIN IMMEDIATE" for statement in statements
    )


def test_retiring_a_binding_that_is_already_superseded_is_refused(
    client, isolate_settings
) -> None:
    """Defense in depth behind the transaction: the supersede is a
    compare-and-swap on `superseded_by_id IS NULL`, and a swap that matched no
    row means someone else already retired this binding. Reporting that as a
    conflict is the difference between a refused bind and a silent second
    current row."""
    from app.services.state_manager import dispatches as dispatches_service

    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    first = _bind(client, "code-hunter-3").json()["binding"]
    second = _bind(client, "code-hunter-3", asserted_client_handle="conv_7f31").json()

    with db_module.get_connection() as connection:
        with pytest.raises(HTTPException) as refused:
            dispatches_service._retire_current_binding(
                connection,
                current_id=int(first["id"]),
                successor_id=int(second["binding"]["id"]),
            )
    assert refused.value.status_code == 409
    assert "already" in refused.value.detail


def test_a_database_that_already_fanned_out_is_collapsed_on_startup(
    client, isolate_settings
) -> None:
    """The guard cannot be built over data that already violates it.

    A database written by the unserialized binder may hold two current rows for
    one dispatch. Startup retires the older assertions to the newest one — the
    same stamp the append-only trigger permits — so no binding is rewritten or
    lost and the index can be created.
    """
    _seed(client, isolate_settings["engagements_dir"])
    _dispatch(client)
    first = _bind(client, "code-hunter-3").json()["binding"]

    with db_module.get_connection() as connection:
        engagement_id, dispatch_id = connection.execute(
            "SELECT engagement_id, dispatch_id FROM assessment_dispatch_client_bindings "
            "WHERE id = ?",
            (first["id"],),
        ).fetchone()
        connection.execute("DROP INDEX idx_dispatch_client_bindings_one_current")
        connection.execute(
            """
            INSERT INTO assessment_dispatch_client_bindings (
                engagement_id, dispatch_id, binding_version, superseded_by_id,
                asserted_client, asserted_session_namespace,
                asserted_client_handle, note, bound_at
            ) VALUES (?, ?, 2, NULL, 'codex', '/tmp/ns', 'conv_race', NULL, ?)
            """,
            (engagement_id, dispatch_id, first["bound_at"]),
        )

    db_module.init_db()

    history = client.get(f"{BASE}/dispatches/code-hunter-3/client-bindings").json()
    assert [entry["binding_version"] for entry in history] == [1, 2]
    assert history[0]["asserted_client_handle"] == "01JQZ4S8K2A0"
    assert history[0]["superseded_by_id"] == history[1]["id"]
    assert history[1]["superseded_by_id"] is None

    listed = client.get(f"{BASE}/dispatches").json()
    assert [entry["agent_id"] for entry in listed] == ["code-hunter-3"]
    assert listed[0]["client_binding"]["asserted_client_handle"] == "conv_race"


def test_pi_dispatch_identity_and_client_binding(client, isolate_settings) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    response = client.post(f"{BASE}/dispatches", json={
        "agent_id": "pi-operator", "agent_role": "operator",
        "client_name": "pi", "requested_client": "pi", "launcher_effective_client": "pi",
    })
    assert response.status_code == 201, response.text
    assert response.json()["client_name"] == "pi"
    binding = _bind(client, "pi-operator", asserted_client="pi")
    assert binding.status_code == 201, binding.text
    row = client.get(f"{BASE}/dispatches/pi-operator").json()
    assert row["requested_client"] == row["launcher_effective_client"] == "pi"
    assert row["client_binding"]["asserted_client"] == "pi"
