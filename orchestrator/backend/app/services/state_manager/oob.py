from __future__ import annotations

import hashlib
import json
from typing import Any
from fastapi import HTTPException, status

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
                probe_kind, request_hash, oob_domain, notes, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        if status_value is not None:
            rows = connection.execute(
                """
                SELECT * FROM assessment_oob_probes
                WHERE engagement_id = ? AND status = ?
                ORDER BY created_at DESC, id DESC
                """,
                (engagement.id, status_value),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM assessment_oob_probes
                WHERE engagement_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (engagement.id,),
            ).fetchall()
        probes: list[dict[str, Any]] = []
        for row in rows:
            probe = dict(row)
            agg = connection.execute(
                """
                SELECT COUNT(*) AS n, MAX(observed_at) AS last_seen
                FROM assessment_oob_interactions
                WHERE probe_id = ?
                """,
                (probe["id"],),
            ).fetchone()
            probe["interaction_count"] = int(agg["n"] or 0)
            probe["last_interaction_at"] = agg["last_seen"] or ""
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
        return probe

def correlate_oob_interaction(
    engagement_id: int,
    *,
    nonce: str,
    protocol: str = "",
    remote_address: str = "",
    query_type: str = "",
    raw_request: str = "",
    observed_at: str = "",
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
    with _common.get_connection() as connection:
        probe_row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if probe_row is None:
            return {"matched": False, "probe": None, "interaction": None, "duplicate": False}
        probe = dict(probe_row)
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
