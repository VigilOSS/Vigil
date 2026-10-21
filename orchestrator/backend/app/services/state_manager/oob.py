from __future__ import annotations

import hashlib
import json
from typing import Any
from fastapi import HTTPException, status

from .. import activity as activity_service
from ..events import _engagement_or_404

from . import _common



# ── OAST (out-of-band) auto-correlation ──────────────────────────────────
#
# ``vigil oob mint`` records a probe (the unique ``nonce`` subdomain label is
# the correlation token). ``vigil oob poll`` parses the shared
# interactsh-client log and records each observed callback against the
# probe whose nonce appears in the callback host. See db.py
# :func:`_create_oob_correlation_tables` and src/vigil_cli/oob.py.

_OOB_PROBE_STATUSES = {"pending", "fired", "confirmed", "expired", "ignored"}

# ``fired`` = a callback arrived and no operator has reviewed it ("to review").
# An operator verdict moves a probe that called back to one of these; a later
# poll never reverts it (see ``correlate_oob_interaction``).
OOB_PROBE_VERDICTS = ("confirmed", "ignored")
_OOB_VERDICT_SOURCE_STATUSES = {"fired", *OOB_PROBE_VERDICTS}
# Audit-log title of a verdict; its metadata carries nonce/verdict/note.
# ``db.py`` builds ``idx_activity_entries_oob_verdict`` over these entries.
OOB_VERDICT_AUDIT_TITLE = "oob probe verdict"


def oob_verdict_entry(
    title: str, actor_kind: str, metadata: dict[str, Any]
) -> tuple[str, str, str] | None:
    """``(nonce, verdict, previous_status)`` when an audit entry is an OAST verdict.

    Only ``record_oob_probe_verdict`` writes this title, as an operator entry;
    a row logged under the same title by anyone else, or naming no known
    verdict, is not a verdict. The probe point read and the Activity feed both
    apply this rule.
    """

    def text(value: Any) -> str:
        return value.strip() if isinstance(value, str) else ""

    nonce, verdict = text(metadata.get("nonce")), text(metadata.get("verdict"))
    if (
        title != OOB_VERDICT_AUDIT_TITLE
        or actor_kind != "operator"
        or not nonce
        or verdict not in OOB_PROBE_VERDICTS
    ):
        return None
    return nonce, verdict, text(metadata.get("previous_status"))


# Literal title and actor kind so the planner can use the partial index.
_LATEST_OOB_VERDICT_SQL = f"""
    SELECT title, actor_kind, actor_name, occurred_at, metadata_json
    FROM activity_entries
    WHERE engagement_id = ? AND actor_kind = 'operator' AND title = '{OOB_VERDICT_AUDIT_TITLE}'
      AND json_valid(metadata_json) AND json_extract(metadata_json, '$.nonce') = ?
    ORDER BY julianday(occurred_at) DESC, id DESC
"""


def _required_client_binding(client_name: str, client_payload_host: str) -> tuple[str, str]:
    name = str(client_name or "").strip()
    payload_host = str(client_payload_host or "").strip().rstrip(".").lower()
    if not name or not payload_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="oob correlation requires client_name and client_payload_host",
        )
    return name, payload_host

def record_oob_probe(
    engagement_id: int,
    *,
    nonce: str,
    target_url: str = "",
    param: str = "",
    technique: str = "",
    probe_kind: str = "",
    request_hash: str = "",
    oob_domain: str = "",
    client_name: str,
    client_payload_host: str,
    notes: str = "",
    status_value: str = "pending",
) -> dict[str, Any]:
    """Insert (or idempotently re-fetch) an OAST probe keyed on ``nonce``.

    The nonce is globally unique (UNIQUE constraint). A repeat mint of the
    same nonce returns the existing row rather than erroring, so a retried
    CLI call is safe. Metadata fields are only filled in on the insert; an
    existing row is left untouched (the callback correlation, not the mint,
    is the mutable surface).
    """
    engagement = _engagement_or_404(engagement_id)
    nonce = str(nonce or "").strip()
    if not nonce:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="oob probe requires a non-empty nonce",
        )
    if status_value not in _OOB_PROBE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid oob probe status '{status_value}'; allowed: {sorted(_OOB_PROBE_STATUSES)}",
        )
    client_name, client_payload_host = _required_client_binding(
        client_name, client_payload_host
    )
    with _common.get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if existing is not None:
            return dict(existing)
        # Guard against a nonce already claimed by a different engagement —
        # the column is globally UNIQUE so the insert would otherwise raise
        # an opaque IntegrityError.
        collision = connection.execute(
            "SELECT engagement_id FROM assessment_oob_probes WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if collision is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"oob nonce '{nonce}' already recorded for another engagement",
            )
        connection.execute(
            """
            INSERT INTO assessment_oob_probes (
                engagement_id, nonce, target_url, param, technique,
                probe_kind, request_hash, oob_domain, client_name,
                client_payload_host, notes, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                nonce,
                target_url,
                param,
                technique,
                probe_kind,
                request_hash,
                oob_domain,
                client_name,
                client_payload_host,
                notes,
                status_value,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        assert row is not None
        return dict(row)

def list_oob_probes(engagement_id: int, *, status_value: str | None = None) -> list[dict[str, Any]]:
    """Return OAST probes for an engagement, newest first, with their
    interaction count and most recent observed callback time embedded."""
    engagement = _engagement_or_404(engagement_id)
    if status_value is not None and status_value not in _OOB_PROBE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid oob probe status '{status_value}'; allowed: {sorted(_OOB_PROBE_STATUSES)}",
        )
    with _common.get_connection() as connection:
        # Single grouped read instead of N+1 per-probe interaction counts. The
        # LEFT JOIN keeps probes with zero interactions (COUNT -> 0, MAX -> NULL).
        base_sql = """
            SELECT p.*,
                   COUNT(i.id) AS interaction_count,
                   MAX(i.observed_at) AS last_interaction_at
            FROM assessment_oob_probes p
            LEFT JOIN assessment_oob_interactions i ON i.probe_id = p.id
            WHERE p.engagement_id = ?{status_clause}
            GROUP BY p.id
            ORDER BY p.created_at DESC, p.id DESC
        """
        if status_value is not None:
            rows = connection.execute(
                base_sql.format(status_clause=" AND p.status = ?"),
                (engagement.id, status_value),
            ).fetchall()
        else:
            rows = connection.execute(
                base_sql.format(status_clause=""),
                (engagement.id,),
            ).fetchall()
        probes: list[dict[str, Any]] = []
        for row in rows:
            probe = dict(row)
            probe["interaction_count"] = int(probe["interaction_count"] or 0)
            probe["last_interaction_at"] = probe["last_interaction_at"] or ""
            probes.append(probe)
        return probes

def get_oob_probe_by_nonce(engagement_id: int, nonce: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, str(nonce or "").strip()),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"oob probe nonce='{nonce}' not found",
            )
        probe = dict(row)
        interactions = connection.execute(
            """
            SELECT * FROM assessment_oob_interactions
            WHERE probe_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (probe["id"],),
        ).fetchall()
        probe["interactions"] = [dict(item) for item in interactions]
        probe["verdict"] = _latest_verdict(connection, engagement.id, probe)
        return probe


def _latest_verdict(connection, engagement_id: int, probe: dict[str, Any]) -> dict[str, Any] | None:
    """The operator verdict entry behind the probe's current status, or None."""
    if probe.get("status") not in OOB_PROBE_VERDICTS:
        return None
    for row in connection.execute(_LATEST_OOB_VERDICT_SQL, (engagement_id, probe["nonce"])):
        metadata = json.loads(row["metadata_json"])
        if not isinstance(metadata, dict):
            continue
        entry = oob_verdict_entry(row["title"], row["actor_kind"], metadata)
        if entry is None or entry[0] != probe["nonce"] or entry[1] != probe["status"]:
            continue
        return {
            "verdict": entry[1],
            "note": metadata.get("note", ""),
            "actor": row["actor_name"],
            "recorded_at": row["occurred_at"],
        }
    return None


def record_oob_probe_verdict(
    engagement_id: int,
    nonce: str,
    *,
    verdict: str,
    note: str = "",
    actor: str = "operator",
) -> dict[str, Any]:
    """Record an operator's review of a probe that called back.

    ``verdict`` is ``confirmed`` (a real out-of-band interaction) or ``ignored``
    (noise). Only a probe with a callback (``fired``, or one already reviewed)
    takes a verdict; a pending or expired probe is a 409. The status change and
    its audit entry (actor, note, previous status) commit together. Repeating
    the current verdict without a note changes nothing and writes no entry.
    Returns the probe as ``get_oob_probe_by_nonce`` does.
    """
    engagement = _engagement_or_404(engagement_id)
    if verdict not in OOB_PROBE_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid oob verdict '{verdict}'; allowed: {list(OOB_PROBE_VERDICTS)}",
        )
    nonce = str(nonce or "").strip()
    note = str(note or "").strip()
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"oob probe nonce='{nonce}' not found",
            )
        previous = str(row["status"] or "")
        if previous not in _OOB_VERDICT_SOURCE_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"oob probe is {previous}: only a probe with a callback takes a verdict",
            )
        if previous != verdict or note:
            connection.execute(
                "UPDATE assessment_oob_probes SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (verdict, row["id"]),
            )
            activity_service.record_activity_entry(
                engagement.id,
                actor_kind="operator",
                actor_name=actor,
                title=OOB_VERDICT_AUDIT_TITLE,
                action=f"probe {nonce}: {previous} -> {verdict}",
                result=verdict,
                body_markdown=note,
                metadata={
                    "nonce": nonce,
                    "probe_id": int(row["id"]),
                    "verdict": verdict,
                    "previous_status": previous,
                    "note": note,
                    "target_url": row["target_url"],
                },
            )
    return get_oob_probe_by_nonce(engagement.id, nonce)

def correlate_oob_interaction(
    engagement_id: int,
    *,
    nonce: str,
    protocol: str = "",
    remote_address: str = "",
    query_type: str = "",
    raw_request: str = "",
    observed_at: str = "",
    client_name: str,
    client_payload_host: str,
) -> dict[str, Any]:
    """Record a single observed callback against the probe owning ``nonce``.

    Returns ``{"matched": bool, "probe": {...}|None, "interaction": {...}|None,
    "duplicate": bool}``. Unknown nonces return ``matched=False`` (the caller —
    ``vigil oob poll`` — collects those into an "unmatched interactions"
    section) rather than 404, so a single poll over a mixed log never aborts
    on the first stray callback. Recording a probe's first interaction flips
    its status ``pending`` → ``fired``. Duplicate callbacks (same
    interaction hash) are deduped via the UNIQUE(probe_id, interaction_hash)
    constraint and reported with ``duplicate=True``.
    """
    engagement = _engagement_or_404(engagement_id)
    nonce = str(nonce or "").strip()
    client_name, client_payload_host = _required_client_binding(
        client_name, client_payload_host
    )
    with _common.get_connection() as connection:
        # Serialize concurrent same-nonce polls: take the write lock up front so the
        # SELECT-check / INSERT-interaction / pending->fired UPDATE run atomically.
        # Without it, two `vigil oob poll` runs racing the same callback can both
        # pass the existing-interaction check and one then hits the
        # UNIQUE(probe_id, interaction_hash) constraint mid-write.
        connection.execute("BEGIN IMMEDIATE")
        probe_row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if probe_row is None:
            return {"matched": False, "probe": None, "interaction": None, "duplicate": False}
        probe = dict(probe_row)
        if not probe.get("client_name") or not probe.get("client_payload_host"):
            return {
                "matched": False,
                "duplicate": False,
                "probe": None,
                "interaction": None,
                "reason": "unbound_probe",
            }
        if (
            str(probe.get("client_name") or "") != str(client_name or "")
            or str(probe.get("client_payload_host") or "")
            != str(client_payload_host or "")
        ):
            return {
                "matched": False,
                "duplicate": False,
                "probe": None,
                "interaction": None,
                "reason": "client_binding_mismatch",
            }
        interaction_hash = hashlib.sha256(
            json.dumps(
                [
                    nonce,
                    str(protocol or ""),
                    str(remote_address or ""),
                    str(query_type or ""),
                    str(observed_at or ""),
                    str(raw_request or ""),
                ],
                sort_keys=False,
            ).encode("utf-8")
        ).hexdigest()
        existing = connection.execute(
            "SELECT * FROM assessment_oob_interactions WHERE probe_id = ? AND interaction_hash = ?",
            (probe["id"], interaction_hash),
        ).fetchone()
        if existing is not None:
            return {
                "matched": True,
                "duplicate": True,
                "probe": probe,
                "interaction": dict(existing),
            }
        connection.execute(
            """
            INSERT INTO assessment_oob_interactions (
                engagement_id, probe_id, protocol, remote_address,
                query_type, raw_request, interaction_hash, observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                probe["id"],
                protocol,
                remote_address,
                query_type,
                raw_request,
                interaction_hash,
                observed_at,
            ),
        )
        # First confirmed callback flips a pending probe to 'fired'. Decided
        # states (confirmed / expired / ignored) are left untouched so an
        # operator verdict is not silently reverted by a late poll.
        if str(probe["status"] or "") == "pending":
            connection.execute(
                "UPDATE assessment_oob_probes SET status = 'fired', updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?",
                (probe["id"],),
            )
        interaction_row = connection.execute(
            "SELECT * FROM assessment_oob_interactions WHERE probe_id = ? AND interaction_hash = ?",
            (probe["id"], interaction_hash),
        ).fetchone()
        probe_after = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE id = ?",
            (probe["id"],),
        ).fetchone()
        return {
            "matched": True,
            "duplicate": False,
            "probe": dict(probe_after),
            "interaction": dict(interaction_row) if interaction_row else None,
        }
