"""Per-host reachability ledger and freshness projection."""

from __future__ import annotations

from typing import Any

from ..events import _engagement_or_404
from . import _common

# ── Host liveness ledger ──────────────────────────────────────────────────
# Authoritative per-host reachability, upserted from httpx probes via
# `vigil assess ingest-httpx`. A verdict older than the TTL is reported as
# 'stale' by the read projection (not stored as 'stale'), forcing a re-probe
# rather than trusting it across the shifting-egress boundary (§9).
_HOST_LIVENESS_TTL_SECONDS = 120 * 60  # 2h

_HOST_LIVENESS_DECAYS = frozenset({"live", "blackholed", "dead"})


def _normalize_liveness_host(value: str) -> str:
    """Canonical liveness key: lowercased, scheme- and port-stripped authority.

    Must stay byte-for-byte in sync with ``discovery.normalize_host`` (CLI side)
    so a GET ?host= lookup matches stored rows.
    """
    h = (value or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("["):  # [ipv6](:port)?
        end = h.find("]")
        if end != -1:
            h = h[: end + 1]
    elif h.count(":") == 1:
        # exactly one colon → host:port (a bare IPv6 has >=2 colons; leave it intact)
        h = h.split(":", 1)[0]
    return h


def _parse_probed_at(probed_at):
    """Parse an ISO probed_at into an aware UTC datetime, or None."""
    import datetime as _dt

    if not probed_at:
        return None
    raw = str(probed_at).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def _canonical_probed_at(probed_at):
    """Normalize probed_at to a single lexicographically-sortable UTC form so the
    keep-newest TEXT comparison in the upsert is correct across mixed input
    formats (fractional precision, ``+HH:MM`` offsets, naive). Returns None when
    unparseable/empty (the upsert then treats it as "no probe time")."""
    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _liveness_age_seconds(probed_at) -> float | None:
    import datetime as _dt

    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - parsed).total_seconds()


def upsert_host_liveness(
    engagement_id: int, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """Bulk-upsert host-liveness rows keyed by (engagement, host).

    The caller (ingest-httpx) supplies the already-classified ``reachability_class``
    — the backend stores it verbatim and keeps the newest probe per host (an
    incoming row with an older ``probed_at`` does not overwrite a newer one).
    """
    _engagement_or_404(engagement_id)
    upserted = 0
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for r in rows:
            host = _normalize_liveness_host(str(r.get("host", "")))
            if not host:
                continue
            connection.execute(
                """
                INSERT INTO assessment_host_liveness (
                    engagement_id, host, status_code, scheme, final_url, host_ip,
                    tech, title, webserver, tls, failed, reachability_class,
                    probed_at, source, source_run_id, source_run_uuid
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, host) DO UPDATE SET
                    status_code = excluded.status_code,
                    scheme = excluded.scheme,
                    final_url = excluded.final_url,
                    host_ip = excluded.host_ip,
                    tech = excluded.tech,
                    title = excluded.title,
                    webserver = excluded.webserver,
                    tls = excluded.tls,
                    failed = excluded.failed,
                    reachability_class = excluded.reachability_class,
                    probed_at = excluded.probed_at,
                    source = excluded.source,
                    source_run_id = excluded.source_run_id,
                    source_run_uuid = excluded.source_run_uuid,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                -- Keep the newest probe: overwrite only when the existing row has
                -- no probe time, or the incoming probe is at-or-after it. A NULL
                -- incoming probed_at must NOT clobber a real timestamped verdict.
                -- probed_at is canonicalized to one sortable UTC form on the way
                -- in, so this TEXT comparison is correct across input formats.
                WHERE assessment_host_liveness.probed_at IS NULL
                   OR (excluded.probed_at IS NOT NULL
                       AND excluded.probed_at >= assessment_host_liveness.probed_at)
                """,
                (
                    engagement_id,
                    host,
                    r.get("status_code"),
                    str(r.get("scheme") or ""),
                    str(r.get("final_url") or ""),
                    str(r.get("host_ip") or ""),
                    str(r.get("tech") or ""),
                    str(r.get("title") or ""),
                    str(r.get("webserver") or ""),
                    str(r.get("tls") or ""),
                    1 if r.get("failed") else 0,
                    str(r.get("reachability_class") or "unknown"),
                    _canonical_probed_at(r.get("probed_at")),
                    str(r.get("source") or "httpx"),
                    r.get("source_run_id"),
                    str(r.get("source_run_uuid") or ""),
                ),
            )
            upserted += 1
    return {"upserted": upserted}


def host_liveness(
    engagement_id: int,
    *,
    hosts: list[str] | None = None,
    fresh_only: bool = False,
) -> list[dict[str, Any]]:
    """Read host-liveness rows with the freshness overlay applied.

    A stored verdict older than the TTL is reported as ``reachability_class``
    'stale' (the stored value is preserved under ``stored_reachability_class``)
    and each row carries ``age_seconds``. With ``fresh_only`` the stale/unprobed
    rows are dropped.
    """
    _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        if hosts:
            norm = sorted(
                {
                    _normalize_liveness_host(h)
                    for h in hosts
                    if _normalize_liveness_host(h)
                }
            )
            if not norm:
                return []
            placeholders = ",".join("?" for _ in norm)
            cursor = connection.execute(
                f"SELECT * FROM assessment_host_liveness "
                f"WHERE engagement_id = ? AND host IN ({placeholders}) ORDER BY host",
                (engagement_id, *norm),
            )
        else:
            cursor = connection.execute(
                "SELECT * FROM assessment_host_liveness WHERE engagement_id = ? ORDER BY host",
                (engagement_id,),
            )
        rows = cursor.fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        age = _liveness_age_seconds(data.get("probed_at"))
        data["age_seconds"] = age
        stored = data.get("reachability_class") or "unknown"
        is_fresh = age is not None and age <= _HOST_LIVENESS_TTL_SECONDS
        if not is_fresh and stored in _HOST_LIVENESS_DECAYS:
            data["stored_reachability_class"] = stored
            data["reachability_class"] = "stale"
        if fresh_only and not is_fresh:
            continue
        out.append(data)
    return out
