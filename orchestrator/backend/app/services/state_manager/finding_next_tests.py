"""Runtime proof plans (``next_test``) bound to ``pending_runtime_proof`` events.

A plan is written in the same transaction as the verification transition that
parks the finding, keyed by that transition, and never rewritten: a revised plan
is a new park. The finding's CURRENT plan is the newest one while it is still
``pending_runtime_proof``; once it leaves that status there is no current plan,
and history keeps every plan on the transition that carried it.

``create_finding`` refuses any write that ENTERS ``pending_runtime_proof``
without a plan, so the newest plan of a parked finding always belongs to its
current park. A finding parked before plans existed has none and reads null —
nothing is fabricated for it.

The current plan's ``transition_id`` names the current PARK. Proof work binds
it, so work prepared for an earlier plan stays history rather than standing in
for the proof owed now.

A merged finding keeps its ``verification_status`` as history, but ``finding
verify`` refuses it, so it owes nothing: ``owes_runtime_proof`` and
``runtime_proof_owed_sql`` are the one definition of proof owed.

The text is model-authored about a target. It is stored losslessly and is never
read as authorization: ``route_hint`` selects nothing and admits nothing.
"""
from __future__ import annotations

import sqlite3
from typing import Any

PENDING_RUNTIME_PROOF = "pending_runtime_proof"
NEXT_TEST_FIELDS = ("hypothesis", "confirm_if", "falsify_if", "route_hint", "prerequisites")


def owes_runtime_proof(finding: Any) -> bool:
    """Whether a finding row owes runtime proof now."""

    return (
        finding["verification_status"] == PENDING_RUNTIME_PROOF
        and finding["status"] != "merged"
    )


def runtime_proof_owed_sql(alias: str = "") -> str:
    """``owes_runtime_proof`` as a SQL predicate over ``assessment_findings``."""

    prefix = f"{alias}." if alias else ""
    return (
        f"({prefix}verification_status = '{PENDING_RUNTIME_PROOF}' "
        f"AND {prefix}status != 'merged')"
    )


def _serialize(row: sqlite3.Row) -> dict[str, Any]:
    return {field: str(row[field]) for field in NEXT_TEST_FIELDS}


def record_next_test(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    finding_id: int,
    transition_id: int,
    next_test: dict[str, Any],
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO assessment_finding_next_tests (
            engagement_id, finding_id, transition_id,
            hypothesis, confirm_if, falsify_if, route_hint, prerequisites
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            finding_id,
            transition_id,
            next_test["hypothesis"],
            next_test["confirm_if"],
            next_test["falsify_if"],
            next_test["route_hint"],
            next_test.get("prerequisites") or "",
        ),
    )
    return {field: str(next_test.get(field) or "") for field in NEXT_TEST_FIELDS}


def current_next_test(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
    verification_status: str,
    *,
    workflow_status: str,
) -> dict[str, Any] | None:
    """The plan for the proof a finding owes now, or None when none is owed/recorded."""

    if not owes_runtime_proof(
        {"verification_status": verification_status, "status": workflow_status}
    ):
        return None
    row = connection.execute(
        """
        SELECT * FROM assessment_finding_next_tests
        WHERE engagement_id = ? AND finding_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (engagement_id, finding_id),
    ).fetchone()
    return _serialize(row) if row is not None else None


def current_parking_transition_id(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
    verification_status: str,
) -> int | None:
    """The transition that recorded the current plan, or None when none is owed/recorded."""

    if verification_status != PENDING_RUNTIME_PROOF:
        return None
    row = connection.execute(
        """
        SELECT transition_id FROM assessment_finding_next_tests
        WHERE engagement_id = ? AND finding_id = ?
        ORDER BY id DESC LIMIT 1
        """,
        (engagement_id, finding_id),
    ).fetchone()
    return int(row["transition_id"]) if row is not None else None


def parking_transition_id_at(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
    created_at: str,
) -> int | None:
    """The plan transition that was newest when a row was written at ``created_at``.

    Projects work written before its binding named a park onto the plan it was
    prepared under. Timestamps have one-second resolution, so a revised plan
    recorded in the same second as the work counts as that work's plan.
    """

    row = connection.execute(
        """
        SELECT transition_id FROM assessment_finding_next_tests
        WHERE engagement_id = ? AND finding_id = ? AND created_at <= ?
        ORDER BY id DESC LIMIT 1
        """,
        (engagement_id, finding_id, created_at),
    ).fetchone()
    return int(row["transition_id"]) if row is not None else None


def next_tests_by_transition(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
    transition_ids: list[int],
) -> dict[int, dict[str, Any]]:
    """Attach each historical plan to the verification event that carried it."""

    unique_ids = list(dict.fromkeys(int(value) for value in transition_ids))
    if not unique_ids:
        return {}
    placeholders = ", ".join("?" for _ in unique_ids)
    rows = connection.execute(
        f"""
        SELECT * FROM assessment_finding_next_tests
        WHERE engagement_id = ? AND finding_id = ?
          AND transition_id IN ({placeholders})
        """,
        (engagement_id, finding_id, *unique_ids),
    ).fetchall()
    return {int(row["transition_id"]): _serialize(row) for row in rows}
