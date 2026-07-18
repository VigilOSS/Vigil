"""Per-engagement intel ingestion + query helpers.

One ``record_*`` helper per ``intel_*`` table plus list/search helpers. Every
record helper:

1. UPSERTs on the natural key declared in ``db.py`` (mirrors
   ``upsert_engagement_session`` and ``_upsert_simple_entity``).
2. Writes a shadow row to ``intel_search_index`` so ``intel_search_fts``
   (kept in sync by triggers) returns the record for free-text queries.
3. Returns the row as a dict with ``provenance_json`` / ``tags_json``
   unpacked into real Python objects for downstream serialisation.

The shadow-table + trigger split is intentional: we do not index the intel
tables directly because FTS5 external-content tables can only bind to a
single underlying table, and we need unified cross-entity search. The
trade-off is that every mutation here must also write the shadow row —
which is why all writes go through the helpers in this module.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import fts_escape


@contextmanager
def _use_connection(existing: Any | None = None) -> Iterator[Any]:
    """Yield ``existing`` when supplied; otherwise open a fresh connection.

    Lets ``record_*`` helpers run inside a caller-managed transaction (the
    ``supersede_intel`` flow) while keeping their default standalone behaviour
    unchanged. Borrowed connections are not committed or closed here — that
    is the caller's responsibility.
    """
    if existing is not None:
        yield existing
        return
    with get_connection() as connection:
        yield connection


# ── Shared utilities ───────────────────────────────────────


def _json_text(value: Any) -> str:
    """Serialise ``value`` to compact JSON, treating ``None`` as an empty object."""
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _json_list_text(value: Any) -> str:
    return json.dumps(value if isinstance(value, list) else [], separators=(",", ":"))


def _decode_json(blob: str, default: Any) -> Any:
    if not blob:
        return default
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return default


def _row_to_dict(row: Any) -> dict[str, Any]:
    data = dict(row)
    if "provenance_json" in data:
        data["provenance"] = _decode_json(data.pop("provenance_json") or "{}", {})
    if "metadata_json" in data:
        data["metadata"] = _decode_json(data.pop("metadata_json") or "{}", {})
    if "details_json" in data:
        data["details"] = _decode_json(data.pop("details_json") or "{}", {})
    if "tags_json" in data:
        data["tags"] = _decode_json(data.pop("tags_json") or "[]", [])
    # Default ``canonical_id`` to the row's own id when ``superseded_by_id``
    # is unset — list helpers overwrite this when they walk a longer chain.
    # This keeps every returned dict carrying the field even on insert paths
    # where no chain walk happened.
    if "id" in data and "canonical_id" not in data:
        if "superseded_by_id" in data and data.get("superseded_by_id"):
            # Caller will walk; leave None so the omission is visible.
            data["canonical_id"] = None
        else:
            data["canonical_id"] = int(data["id"])
    return data


# ── Shadow FTS index ───────────────────────────────────────


def _upsert_search_index(
    connection,
    *,
    engagement_id: int,
    entity_type: str,
    source_id: int,
    key: str,
    body: str,
    source_name: str,
) -> None:
    """Write (or refresh) the shadow row that feeds ``intel_search_fts``.

    The upsert is required because every ``record_*`` helper is also an
    upsert on the natural key — a second call for the same entity must
    update the existing shadow row so FTS does not accumulate duplicates.
    """
    connection.execute(
        """
        INSERT INTO intel_search_index (
            engagement_id, entity_type, source_id, key, body, source_name
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, entity_type, source_id) DO UPDATE SET
            key = excluded.key,
            body = excluded.body,
            source_name = excluded.source_name,
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, entity_type, source_id, key or "", body or "", source_name or ""),
    )


def _compose_body(*parts: Iterable[str] | str | None) -> str:
    """Join non-empty parts with newlines for FTS indexing."""
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        if isinstance(part, str):
            out.append(part)
        else:
            out.extend(str(p) for p in part if p)
    return "\n".join(out)


def _generic_upsert(
    connection,
    *,
    table: str,
    engagement_id: int,
    conflict_columns: list[str],
    values: dict[str, Any],
) -> dict[str, Any]:
    """Run an UPSERT that matches the ``UNIQUE(engagement_id, ...)`` constraint.

    Every intel table's UNIQUE key is ``(engagement_id, <natural key…>)``.
    SQLite's ``ON CONFLICT`` needs the full constraint column list (and only
    the full list) — passing just the natural-key suffix raises
    ``OperationalError`` at runtime. ``conflict_columns`` names the natural
    key; ``engagement_id`` is prepended here so callers do not repeat it.
    """
    columns = ["engagement_id", *values.keys()]
    placeholders = ", ".join(["?"] * len(columns))
    assignments = ", ".join(
        f"{col} = excluded.{col}" for col in values.keys() if col not in conflict_columns
    )
    conflict_clause = ", ".join(["engagement_id", *conflict_columns])
    sql = (
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
        f"ON CONFLICT({conflict_clause}) DO UPDATE SET "
        f"{assignments}, updated_at = CURRENT_TIMESTAMP"
    )
    connection.execute(sql, (engagement_id, *values.values()))
    where = " AND ".join(
        [f"{col} = ?" for col in ["engagement_id", *conflict_columns]]
    )
    params: list[Any] = [engagement_id, *[values[col] for col in conflict_columns]]
    row = connection.execute(
        f"SELECT * FROM {table} WHERE {where}", tuple(params)
    ).fetchone()
    assert row is not None, f"upsert into {table} produced no row"
    return dict(row)


# ── Record helpers ─────────────────────────────────────────


def record_tech_component(
    engagement_id: int,
    *,
    component: str,
    version: str = "",
    source_name: str = "",
    confidence: str = "",
    evidence_ref: str = "",
    first_seen_at: str = "",
    last_seen_at: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values: dict[str, Any] = {
        "component": component,
        "version": version,
        "source_name": source_name,
        "confidence": confidence,
        "evidence_ref": evidence_ref,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    # Only override default CURRENT_TIMESTAMP when the caller supplied a value.
    if first_seen_at:
        values["first_seen_at"] = first_seen_at
    if last_seen_at:
        values["last_seen_at"] = last_seen_at
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_tech_components",
            engagement_id=engagement.id,
            conflict_columns=["component", "version"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="tech_component",
            source_id=int(row["id"]),
            key=f"{component} {version}".strip(),
            body=_compose_body(component, version, confidence, evidence_ref, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_person(
    engagement_id: int,
    *,
    name: str,
    role: str = "",
    organization: str = "",
    email: str = "",
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "name": name,
        "role": role,
        "organization": organization,
        "email": email,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_people",
            engagement_id=engagement.id,
            conflict_columns=["name"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="person",
            source_id=int(row["id"]),
            key=name,
            body=_compose_body(name, role, organization, email, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_email(
    engagement_id: int,
    *,
    address: str,
    role_hint: str = "",
    linked_person_id: int | None = None,
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "address": address,
        "role_hint": role_hint,
        "linked_person_id": linked_person_id,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_emails",
            engagement_id=engagement.id,
            conflict_columns=["address"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="email",
            source_id=int(row["id"]),
            key=address,
            body=_compose_body(address, role_hint, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_domain(
    engagement_id: int,
    *,
    identity: str,
    kind: str = "subdomain",
    value: str = "",
    source_name: str = "",
    live_status: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "identity": identity,
        "kind": kind,
        "value": value,
        "source_name": source_name,
        "live_status": live_status,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_domains",
            engagement_id=engagement.id,
            conflict_columns=["identity", "kind"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="domain",
            source_id=int(row["id"]),
            key=identity,
            body=_compose_body(identity, kind, value, live_status, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_cve(
    engagement_id: int,
    *,
    cve_id: str,
    affected_component: str = "",
    affected_version_range: str = "",
    cvss_score: float | None = None,
    cvss_vector: str = "",
    cwe_id: str = "",
    poc_available: bool = False,
    source_name: str = "",
    validation_status: str = "unverified",
    linked_finding_slug: str = "",
    notes: str = "",
    details: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    details_payload = _validate_cve_details(details)
    _validate_cve_attempted_blocked(
        validation_status=validation_status,
        details=details_payload,
    )
    values = {
        "cve_id": cve_id,
        "affected_component": affected_component,
        "affected_version_range": affected_version_range,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_id": cwe_id,
        "poc_available": 1 if poc_available else 0,
        "source_name": source_name,
        "validation_status": validation_status,
        "linked_finding_slug": linked_finding_slug,
        "notes": notes,
        "details_json": _json_text(details_payload),
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_cves",
            engagement_id=engagement.id,
            conflict_columns=["cve_id", "affected_component"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="cve",
            source_id=int(row["id"]),
            key=cve_id,
            body=_compose_body(
                cve_id,
                affected_component,
                affected_version_range,
                cwe_id,
                cvss_vector,
                validation_status,
                linked_finding_slug,
                notes,
            ),
            source_name=source_name,
        )
    out = _row_to_dict(row)
    out["poc_available"] = bool(out.get("poc_available"))
    return out


def record_dns_record(
    engagement_id: int,
    *,
    record_type: str,
    name: str,
    value: str = "",
    first_seen: str = "",
    last_seen: str = "",
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "record_type": record_type,
        "name": name,
        "value": value,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_dns_records",
            engagement_id=engagement.id,
            conflict_columns=["record_type", "name", "value"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="dns_record",
            source_id=int(row["id"]),
            key=f"{record_type} {name}".strip(),
            body=_compose_body(record_type, name, value, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_social_profile(
    engagement_id: int,
    *,
    subject_kind: str,
    subject_ref: str = "",
    platform: str,
    handle: str = "",
    url: str = "",
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "subject_kind": subject_kind,
        "subject_ref": subject_ref,
        "platform": platform,
        "handle": handle,
        "url": url,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_social_profiles",
            engagement_id=engagement.id,
            conflict_columns=["subject_kind", "subject_ref", "platform", "handle"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="social_profile",
            source_id=int(row["id"]),
            key=f"{platform} {handle}".strip(),
            body=_compose_body(platform, handle, url, subject_ref, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_breach_record(
    engagement_id: int,
    *,
    subject: str,
    breach_name: str,
    breach_date: str = "",
    data_types: str = "",
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "subject": subject,
        "breach_name": breach_name,
        "breach_date": breach_date,
        "data_types": data_types,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_breach_records",
            engagement_id=engagement.id,
            conflict_columns=["subject", "breach_name"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="breach_record",
            source_id=int(row["id"]),
            key=f"{subject} {breach_name}".strip(),
            body=_compose_body(subject, breach_name, breach_date, data_types, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_org_fact(
    engagement_id: int,
    *,
    fact_key: str,
    fact_value: str = "",
    source_name: str = "",
    notes: str = "",
    provenance: dict[str, Any] | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "fact_key": fact_key,
        "fact_value": fact_value,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_org_facts",
            engagement_id=engagement.id,
            conflict_columns=["fact_key"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="org_fact",
            source_id=int(row["id"]),
            key=fact_key,
            body=_compose_body(fact_key, fact_value, notes),
            source_name=source_name,
        )
    return _row_to_dict(row)


def record_note(
    engagement_id: int,
    *,
    title: str,
    body_markdown: str = "",
    source_agent: str = "",
    tags: list[str] | None = None,
    source_name: str = "",
    provenance: dict[str, Any] | None = None,
    lead_status: str | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    _validate_lead_status(lead_status)
    values: dict[str, Any] = {
        "title": title,
        "body_markdown": body_markdown,
        "source_agent": source_agent,
        "tags_json": _json_list_text(tags or []),
        "source_name": source_name,
        "provenance_json": _json_text(provenance),
    }
    # Only write lead_status when supplied, so a bare re-record of the same
    # note (UNIQUE on title) preserves an existing disposition instead of
    # clobbering it back to NULL.
    if lead_status is not None:
        values["lead_status"] = lead_status
    with _use_connection(_conn) as connection:
        row = _generic_upsert(
            connection,
            table="intel_notes",
            engagement_id=engagement.id,
            conflict_columns=["title"],
            values=values,
        )
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type="note",
            source_id=int(row["id"]),
            key=title,
            body=_compose_body(title, body_markdown, source_agent, lead_status, *(tags or [])),
            source_name=source_name,
        )
    return _row_to_dict(row)


# ── List helpers ───────────────────────────────────────────


_LIST_TABLES: dict[str, str] = {
    "tech_component": "intel_tech_components",
    "person": "intel_people",
    "email": "intel_emails",
    "domain": "intel_domains",
    "cve": "intel_cves",
    "dns_record": "intel_dns_records",
    "social_profile": "intel_social_profiles",
    "breach_record": "intel_breach_records",
    "org_fact": "intel_org_facts",
    "note": "intel_notes",
}


def _list_rows(
    engagement_id: int,
    table: str,
    *,
    include_superseded: bool = True,
) -> list[dict[str, Any]]:
    """Return every row in ``table`` for the engagement.

    ``include_superseded=True`` (the default) preserves the existing
    UI/contract: superseded rows still appear so operators can see the
    full audit trail. Report-writer flips this to False so only the
    canonical rows reach the report. Detection of the column is
    intentional — older databases that have not run the supersede
    migration still return correct results.

    Each row is decorated with ``canonical_id`` (the leaf of the
    ``superseded_by_id`` chain) so the frontend can chase to the live
    replacement in one hop instead of recursing through the list.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if not include_superseded and "superseded_by_id" in columns:
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE engagement_id = ? AND superseded_by_id IS NULL "
                f"ORDER BY updated_at DESC, id DESC",
                (engagement.id,),
            ).fetchall()
        else:
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC",
                (engagement.id,),
            ).fetchall()
        decorated: list[dict[str, Any]] = []
        has_supersede = "superseded_by_id" in columns
        for row in rows:
            data = _row_to_dict(row)
            if has_supersede:
                data["canonical_id"] = _resolve_canonical_id(
                    connection, table, engagement.id, int(data["id"])
                )
            else:
                data["canonical_id"] = int(data["id"])
            decorated.append(data)
    return decorated


# ── Update + supersede ─────────────────────────────────────


# Map intel type slug -> (table, allowed updatable columns).
# Columns marked here must already exist on the table; the helpers reject
# any field that is not in this set so misspellings surface immediately
# instead of silently no-oping.
_INTEL_TABLE_BY_TYPE: dict[str, str] = {
    "tech-component": "intel_tech_components",
    "person": "intel_people",
    "email": "intel_emails",
    "domain": "intel_domains",
    "cve": "intel_cves",
    "dns-record": "intel_dns_records",
    "social-profile": "intel_social_profiles",
    "breach-record": "intel_breach_records",
    "org-fact": "intel_org_facts",
    "note": "intel_notes",
}


# The free-text column a supersede ``--rationale`` is appended to differs by
# table: ``intel_notes`` stores prose in ``body_markdown``; every other intel
# table has a dedicated ``notes`` column. Keyed by intel_type so the append in
# ``supersede_intel`` targets the column that actually exists on each table
# (targeting ``notes`` on ``intel_notes`` raises "no such column: notes" -> 500).
_INTEL_RATIONALE_COLUMN: dict[str, str] = {
    intel_type: ("body_markdown" if intel_type == "note" else "notes")
    for intel_type in _INTEL_TABLE_BY_TYPE
}


_INTEL_UPDATABLE_FIELDS: dict[str, set[str]] = {
    "tech-component": {
        "component", "version", "source_name", "confidence", "evidence_ref",
        "first_seen_at", "last_seen_at", "notes", "provenance",
    },
    "person": {
        "name", "role", "organization", "email", "source_name", "notes",
        "provenance",
    },
    "email": {
        "address", "role_hint", "linked_person_id", "source_name", "notes",
        "provenance",
    },
    "domain": {
        "identity", "kind", "value", "source_name", "live_status", "notes",
        "provenance",
    },
    "cve": {
        "cve_id", "affected_component", "affected_version_range", "cvss_score",
        "cvss_vector", "cwe_id", "poc_available", "source_name",
        "validation_status", "linked_finding_slug", "notes", "details",
        "provenance",
    },
    "dns-record": {
        "record_type", "name", "value", "first_seen", "last_seen",
        "source_name", "notes", "provenance",
    },
    "social-profile": {
        "subject_kind", "subject_ref", "platform", "handle", "url",
        "source_name", "notes", "provenance",
    },
    "breach-record": {
        "subject", "breach_name", "breach_date", "data_types", "source_name",
        "notes", "provenance",
    },
    "org-fact": {
        "fact_key", "fact_value", "source_name", "notes", "provenance",
    },
    "note": {
        "title", "body_markdown", "source_agent", "tags", "source_name",
        "provenance", "lead_status",
    },
}


_INTEL_FTS_ENTITY_TYPE: dict[str, str] = {
    "tech-component": "tech_component",
    "person": "person",
    "email": "email",
    "domain": "domain",
    "cve": "cve",
    "dns-record": "dns_record",
    "social-profile": "social_profile",
    "breach-record": "breach_record",
    "org-fact": "org_fact",
    "note": "note",
}


# Natural-key fields per intel type. ``supersede_intel`` validates these are
# present in the new payload BEFORE invoking the corresponding ``record_*``
# helper — the helpers declare these as keyword-only required positional
# kwargs, so a missing key would otherwise raise ``TypeError`` (HTTP 500).
# Mirrors the per-table ``UNIQUE(engagement_id, …)`` constraint declared in
# ``db.py`` and the ``min_length`` Field markers in ``intel_schemas.py``.
_INTEL_NATURAL_KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "tech-component": ("component", "version"),
    "person": ("name",),
    "email": ("address",),
    "domain": ("identity", "kind"),
    "cve": ("cve_id", "affected_component"),
    "dns-record": ("record_type", "name", "value"),
    "social-profile": ("subject_kind", "subject_ref", "platform", "handle"),
    "breach-record": ("subject", "breach_name"),
    "org-fact": ("fact_key",),
    "note": ("title",),
}


def _resolve_intel_table(intel_type: str) -> str:
    table = _INTEL_TABLE_BY_TYPE.get(intel_type)
    if not table:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown intel type '{intel_type}'",
        )
    return table


def _intel_search_body(
    intel_type: str,
    row: dict[str, Any],
) -> tuple[str, str]:
    """Recompute the FTS shadow ``(key, body)`` pair for an intel row."""
    if intel_type == "tech-component":
        key = f"{row.get('component', '')} {row.get('version', '')}".strip()
        body = _compose_body(
            row.get("component"),
            row.get("version"),
            row.get("confidence"),
            row.get("evidence_ref"),
            row.get("notes"),
        )
        return key, body
    if intel_type == "person":
        return row.get("name", ""), _compose_body(
            row.get("name"),
            row.get("role"),
            row.get("organization"),
            row.get("email"),
            row.get("notes"),
        )
    if intel_type == "email":
        return row.get("address", ""), _compose_body(
            row.get("address"),
            row.get("role_hint"),
            row.get("notes"),
        )
    if intel_type == "domain":
        return row.get("identity", ""), _compose_body(
            row.get("identity"),
            row.get("kind"),
            row.get("value"),
            row.get("live_status"),
            row.get("notes"),
        )
    if intel_type == "cve":
        return row.get("cve_id", ""), _compose_body(
            row.get("cve_id"),
            row.get("affected_component"),
            row.get("affected_version_range"),
            row.get("cwe_id"),
            row.get("cvss_vector"),
            row.get("validation_status"),
            row.get("linked_finding_slug"),
            row.get("notes"),
        )
    if intel_type == "dns-record":
        key = f"{row.get('record_type', '')} {row.get('name', '')}".strip()
        return key, _compose_body(
            row.get("record_type"),
            row.get("name"),
            row.get("value"),
            row.get("notes"),
        )
    if intel_type == "social-profile":
        key = f"{row.get('platform', '')} {row.get('handle', '')}".strip()
        return key, _compose_body(
            row.get("platform"),
            row.get("handle"),
            row.get("url"),
            row.get("subject_ref"),
            row.get("notes"),
        )
    if intel_type == "breach-record":
        key = f"{row.get('subject', '')} {row.get('breach_name', '')}".strip()
        return key, _compose_body(
            row.get("subject"),
            row.get("breach_name"),
            row.get("breach_date"),
            row.get("data_types"),
            row.get("notes"),
        )
    if intel_type == "org-fact":
        return row.get("fact_key", ""), _compose_body(
            row.get("fact_key"),
            row.get("fact_value"),
            row.get("notes"),
        )
    if intel_type == "note":
        tags = row.get("tags") or []
        return row.get("title", ""), _compose_body(
            row.get("title"),
            row.get("body_markdown"),
            row.get("source_agent"),
            row.get("lead_status"),
            *(tags if isinstance(tags, list) else []),
        )
    return "", ""


def _coerce_update_values(
    intel_type: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Normalise CLI/API payload into UPDATE column values for ``intel_*``."""
    allowed = _INTEL_UPDATABLE_FIELDS[intel_type]
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"field '{key}' is not patchable on intel/{intel_type}",
            )
        cleaned[key] = value

    column_values: dict[str, Any] = {}
    for column, value in cleaned.items():
        if column == "provenance":
            column_values["provenance_json"] = _json_text(value)
        elif column == "details":
            column_values["details_json"] = _json_text(value)
        elif column == "tags":
            column_values["tags_json"] = _json_list_text(value)
        elif column == "poc_available":
            column_values["poc_available"] = 1 if value else 0
        elif column == "lead_status":
            _validate_lead_status(value)
            column_values[column] = value
        else:
            column_values[column] = value
    return column_values


def _validate_cve_details(details: Any) -> dict[str, Any]:
    if details is None:
        return {}
    if not isinstance(details, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details must be an object on intel/cve",
        )
    block_reason = details.get("block_reason")
    if block_reason is not None:
        if not isinstance(block_reason, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="details.block_reason must be a string",
            )
        if len(block_reason) > 500:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="details.block_reason exceeds 500 characters",
            )
    return details


def _validate_cve_attempted_blocked(
    *,
    validation_status: Any,
    details: Any,
) -> None:
    details_payload = _validate_cve_details(details)
    if validation_status == "attempted_blocked":
        block_reason = details_payload.get("block_reason")
        if not isinstance(block_reason, str) or not block_reason.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "details.block_reason is required when "
                    "validation_status='attempted_blocked'"
                ),
            )


def _fetch_intel_row(
    connection, table: str, engagement_id: int, intel_id: int
) -> dict[str, Any] | None:
    row = connection.execute(
        f"SELECT * FROM {table} WHERE engagement_id = ? AND id = ?",
        (engagement_id, intel_id),
    ).fetchone()
    return dict(row) if row is not None else None


def _post_process_intel_row(intel_type: str, row: dict[str, Any]) -> dict[str, Any]:
    out = _row_to_dict(row)
    if intel_type == "cve":
        out["poc_available"] = bool(out.get("poc_available"))
    return out


def _resolve_canonical_id(
    connection, table: str, engagement_id: int, intel_id: int
) -> int:
    """Walk ``superseded_by_id`` from ``intel_id`` to the leaf row.

    Returns ``intel_id`` itself when the row is current. Bounded loop —
    cycles are rejected at supersede time, but defend in depth here so a
    historical bad row can still be served. Engagement-scoped to keep a
    pathological cross-engagement reference from leaking the leaf id of an
    unrelated case.
    """
    seen: set[int] = {intel_id}
    current = intel_id
    # Cap iterations at the row count to make a hostile chain a noop, not a
    # hang. Any real chain is at most a handful long.
    for _ in range(1024):
        row = connection.execute(
            f"SELECT superseded_by_id FROM {table} WHERE engagement_id = ? AND id = ?",
            (engagement_id, current),
        ).fetchone()
        if row is None:
            return current
        next_id = row[0]
        if next_id is None:
            return current
        next_id = int(next_id)
        if next_id in seen:
            # Cycle — return where we are; supersede insertion guards against
            # cycle creation, so this is an unreachable self-defence branch.
            return current
        seen.add(next_id)
        current = next_id
    return current


def _supersede_chain_reaches(
    connection, table: str, engagement_id: int, start_id: int, target_id: int
) -> bool:
    """Return True when walking ``superseded_by_id`` from ``start_id`` lands on ``target_id``.

    Used to reject cycle creation: if the new replacement row already
    transitively supersedes back to the row we are about to mark as
    superseded, the link would close a loop.
    """
    if start_id == target_id:
        return True
    seen: set[int] = {start_id}
    current = start_id
    for _ in range(1024):
        row = connection.execute(
            f"SELECT superseded_by_id FROM {table} WHERE engagement_id = ? AND id = ?",
            (engagement_id, current),
        ).fetchone()
        if row is None:
            return False
        next_id = row[0]
        if next_id is None:
            return False
        next_id = int(next_id)
        if next_id == target_id:
            return True
        if next_id in seen:
            return False
        seen.add(next_id)
        current = next_id
    return False


def update_intel(
    engagement_id: int,
    intel_type: str,
    intel_id: int,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Patch an existing intel row by id.

    Mirrors ``update_finding``: callers supply only the columns they want to
    change, and the helper rejects unknown keys so spelling drift surfaces at
    write time. The FTS shadow row is refreshed so search reflects the new
    body.
    """
    engagement = _engagement_or_404(engagement_id)
    table = _resolve_intel_table(intel_type)
    column_values = _coerce_update_values(intel_type, payload)
    if not column_values:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="update payload must include at least one field",
        )

    with get_connection() as connection:
        existing = _fetch_intel_row(connection, table, engagement.id, intel_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"intel/{intel_type} id={intel_id} not found",
            )
        if intel_type == "cve":
            existing_payload = _post_process_intel_row("cve", existing)
            _validate_cve_attempted_blocked(
                validation_status=payload.get(
                    "validation_status",
                    existing_payload.get("validation_status", "unverified"),
                ),
                details=payload.get("details", existing_payload.get("details", {})),
            )
        assignments = ", ".join(f"{col} = ?" for col in column_values)
        params = list(column_values.values())
        params.extend([engagement.id, intel_id])
        try:
            connection.execute(
                f"UPDATE {table} SET {assignments}, updated_at = CURRENT_TIMESTAMP "
                f"WHERE engagement_id = ? AND id = ?",
                tuple(params),
            )
        except sqlite3.IntegrityError as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"intel/{intel_type} update conflicts with an existing "
                        "record's natural key"
                    ),
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid intel/{intel_type} update",
            ) from exc
        updated = _fetch_intel_row(connection, table, engagement.id, intel_id)
        assert updated is not None
        # Refresh FTS shadow row so search hits the latest body.
        normalized = _post_process_intel_row(intel_type, updated)
        key, body = _intel_search_body(intel_type, normalized)
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type=_INTEL_FTS_ENTITY_TYPE[intel_type],
            source_id=intel_id,
            key=key,
            body=body,
            source_name=str(updated.get("source_name", "")),
        )
        canonical_id = _resolve_canonical_id(connection, table, engagement.id, intel_id)
    out = _post_process_intel_row(intel_type, updated)
    out["canonical_id"] = canonical_id
    return out


def supersede_intel(
    engagement_id: int,
    intel_type: str,
    intel_id: int,
    new_payload: dict[str, Any],
    *,
    rationale: str = "",
) -> dict[str, Any]:
    """Insert a replacement intel row and mark the old row as superseded.

    The old row stays in the table for audit but gets ``superseded_by_id``
    populated so report-writer can filter it out. The three writes (existence
    check, replacement upsert, supersede UPDATE) all share a single connection
    so a mid-flight failure rolls the whole supersede back together — a
    half-applied state where the new row exists but the old row never gets
    flagged is possible only if the connection itself dies.
    """
    engagement = _engagement_or_404(engagement_id)
    table = _resolve_intel_table(intel_type)
    if not isinstance(new_payload, dict) or not new_payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="supersede payload must be a non-empty object",
        )

    # Reuse the per-type record helpers so the new row is upserted on the
    # natural key and the FTS shadow is written.
    record_dispatch: dict[str, Any] = {
        "tech-component": record_tech_component,
        "person": record_person,
        "email": record_email,
        "domain": record_domain,
        "cve": record_cve,
        "dns-record": record_dns_record,
        "social-profile": record_social_profile,
        "breach-record": record_breach_record,
        "org-fact": record_org_fact,
        "note": record_note,
    }
    record_fn = record_dispatch[intel_type]
    # Filter the payload to known kwargs to avoid TypeError on unknown
    # keys; the schema validator should already have caught this CLI-side.
    allowed = _INTEL_UPDATABLE_FIELDS[intel_type]
    kwargs = {key: value for key, value in new_payload.items() if key in allowed}
    if not kwargs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="supersede payload contains no patchable fields",
        )

    # The record helpers declare natural-key fields as required keyword-only
    # arguments — calling them without those keys raises TypeError (500). We
    # surface a structured 400 instead so a malformed payload is recoverable.
    natural_key = _INTEL_NATURAL_KEY_FIELDS[intel_type]
    missing = [
        field for field in natural_key
        if field not in kwargs or kwargs[field] in (None, "")
    ]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"supersede payload missing required field: "
                f"{', '.join(missing)}"
            ),
        )
    if intel_type == "cve":
        _validate_cve_attempted_blocked(
            validation_status=kwargs.get("validation_status", "unverified"),
            details=kwargs.get("details", {}),
        )

    with get_connection() as connection:
        existing = _fetch_intel_row(connection, table, engagement.id, intel_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"intel/{intel_type} id={intel_id} not found",
            )

        new_row = record_fn(engagement.id, _conn=connection, **kwargs)
        new_id = int(new_row["id"])

        if new_id == intel_id:
            # The natural key matched the existing row; this is an in-place
            # upsert, not a supersede. Surface it as 409 so the operator can
            # call intel update instead.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"supersede target (id={intel_id}) collided with the new payload's "
                    "natural key — use intel update for in-place edits"
                ),
            )

        # Cycle guard: if the new row already transitively supersedes back
        # to ``intel_id`` (because the operator superseded A→B and is now
        # trying to supersede B→A), the link would close a loop. Reject as
        # 409 so the operator unwinds the chain instead.
        if _supersede_chain_reaches(connection, table, engagement.id, new_id, intel_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"supersede would create a cycle: id={new_id} already "
                    f"transitively supersedes id={intel_id}"
                ),
            )

        # Capture rationale on the old row's notes when supplied so the audit
        # trail includes why supersede was issued without changing the schema.
        if rationale:
            rationale_column = _INTEL_RATIONALE_COLUMN[intel_type]
            old_notes = str(existing.get(rationale_column, "") or "")
            tag = f"[superseded-by id={new_id}] {rationale}".strip()
            new_notes = (old_notes + ("\n" if old_notes else "") + tag) if tag else old_notes
            connection.execute(
                f"UPDATE {table} SET {rationale_column} = ?, superseded_by_id = ?, "
                f"superseded_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                f"WHERE engagement_id = ? AND id = ?",
                (new_notes, new_id, engagement.id, intel_id),
            )
        else:
            connection.execute(
                f"UPDATE {table} SET superseded_by_id = ?, "
                f"superseded_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                f"WHERE engagement_id = ? AND id = ?",
                (new_id, engagement.id, intel_id),
            )
        updated_old = _fetch_intel_row(connection, table, engagement.id, intel_id)
        assert updated_old is not None

        # The notes column may have changed (rationale append) — refresh the
        # FTS shadow so the appended text becomes searchable. Without this
        # refresh, the old row keeps its pre-supersede ``body`` blob and the
        # rationale is invisible to ``intel_search``.
        normalized_old = _post_process_intel_row(intel_type, updated_old)
        old_key, old_body = _intel_search_body(intel_type, normalized_old)
        _upsert_search_index(
            connection,
            engagement_id=engagement.id,
            entity_type=_INTEL_FTS_ENTITY_TYPE[intel_type],
            source_id=intel_id,
            key=old_key,
            body=old_body,
            source_name=str(updated_old.get("source_name", "")),
        )

        canonical_id = _resolve_canonical_id(connection, table, engagement.id, intel_id)
        new_canonical = _resolve_canonical_id(connection, table, engagement.id, new_id)

    superseded_view = _post_process_intel_row(intel_type, updated_old)
    superseded_view["canonical_id"] = canonical_id
    current_view = dict(new_row)
    current_view["canonical_id"] = new_canonical
    return {
        "superseded": superseded_view,
        "current": current_view,
    }


def list_tech_components(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(
        engagement_id, "intel_tech_components", include_superseded=include_superseded
    )


def list_people(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_people", include_superseded=include_superseded)


def list_emails(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_emails", include_superseded=include_superseded)


def list_domains(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_domains", include_superseded=include_superseded)


def list_cves(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    rows = _list_rows(engagement_id, "intel_cves", include_superseded=include_superseded)
    for row in rows:
        row["poc_available"] = bool(row.get("poc_available"))
    return rows


# Terminal CVE dispositions: an open CVE is one whose validation_status is NOT
# one of these. Mirrors the {exploited, ruled_out} closed set used by the
# readiness advisory.
CVE_TERMINAL_STATUSES = frozenset({"exploited", "ruled_out"})


def list_open_high_cves(engagement_id: int) -> list[dict[str, Any]]:
    """Canonical (non-superseded) CVEs with cvss_score >= 7 and no terminal
    disposition, sorted by cvss_score descending, projected for the resume brief.

    NOTE: this predicate is intentionally LOOSER than ``intel_readiness``'s
    high-CVE check — it omits the ``poc_available`` requirement. The resume
    brief is for situational awareness ("which high CVEs still need a
    disposition"); the readiness advisory gates on the actionable PoC-backed
    subset. Do not unify the two predicates.
    """
    open_high: list[dict[str, Any]] = []
    for row in list_cves(engagement_id, include_superseded=False):
        score = row.get("cvss_score")
        if not isinstance(score, (int, float)) or score < 7.0:
            continue
        if str(row.get("validation_status") or "") in CVE_TERMINAL_STATUSES:
            continue
        open_high.append(
            {
                # Backend id so the operator can act on the exact row
                # (`vigil assess intel update cve <id>` takes the numeric id).
                "id": row.get("id"),
                "cve_id": row.get("cve_id"),
                "cvss_score": score,
                "validation_status": row.get("validation_status"),
                "linked_finding_slug": row.get("linked_finding_slug") or "",
                "affected_component": row.get("affected_component") or "",
                "updated_at": row.get("updated_at"),
            }
        )
    open_high.sort(key=lambda r: r.get("cvss_score") or 0.0, reverse=True)
    return open_high


def resolve_linked_finding(engagement_id: int, slug: str) -> dict[str, Any]:
    """Resolve a CVE's ``linked_finding_slug`` against ``assessment_findings``.

    Returns ``{"exists": bool, "workflow_status": str | None}``. The findings
    DB column is ``status`` (serialised as ``workflow_status`` elsewhere). An
    empty slug returns ``exists=False``. This is the read path for the
    otherwise write-only ``linked_finding_slug`` field; reused by the readiness
    advisory to flag dangling links.
    """
    value = (slug or "").strip()
    if not value:
        return {"exists": False, "workflow_status": None}
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT status FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, value),
        ).fetchone()
    if row is None:
        return {"exists": False, "workflow_status": None}
    return {"exists": True, "workflow_status": str(row[0] or "")}


def intel_readiness(engagement_id: int) -> dict[str, Any]:
    """Advisory (NON-gating) intel-closure view for RED engagements.

    Returns four buckets — open PoC-backed high CVEs, open leads, exploited
    CVEs with no linked finding, and dangling ``linked_finding_slug``
    references — plus an ``applicable`` flag. Blue/IR engagements do not pursue
    CVE exploitation, so they are not applicable and return empty buckets. This
    never blocks anything (report_readiness is untouched); it only surfaces
    what still needs a disposition.
    """
    engagement = _engagement_or_404(engagement_id)
    engagement_type = str(getattr(engagement, "engagement_type", "") or "red")
    if engagement_type.lower() == "blue":
        return {
            "applicable": False,
            "engagement_type": engagement_type,
            "open_high_cves": [],
            "open_leads": [],
            "exploited_unlinked_cves": [],
            "dangling_links": [],
        }

    open_high_cves: list[dict[str, Any]] = []
    exploited_unlinked_cves: list[dict[str, Any]] = []
    dangling_links: list[dict[str, Any]] = []
    for row in list_cves(engagement_id, include_superseded=False):
        status_value = str(row.get("validation_status") or "")
        score = row.get("cvss_score")
        slug = str(row.get("linked_finding_slug") or "")
        cve_id = row.get("cve_id")
        # Actionable subset: high + PoC-backed + not yet dispositioned. This is
        # STRICTER than the resume-brief surfacing (list_open_high_cves), which
        # omits the poc_available requirement — awareness vs. the actionable
        # advisory. Keep the two predicates distinct on purpose.
        if (
            isinstance(score, (int, float))
            and score >= 7.0
            and row.get("poc_available")
            and status_value not in CVE_TERMINAL_STATUSES
        ):
            open_high_cves.append(
                {
                    "id": row.get("id"),
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "validation_status": status_value,
                    "affected_component": row.get("affected_component") or "",
                }
            )
        if status_value == "exploited" and not slug:
            exploited_unlinked_cves.append(
                {
                    "id": row.get("id"),
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "affected_component": row.get("affected_component") or "",
                }
            )
        if slug:
            resolved = resolve_linked_finding(engagement_id, slug)
            reason = None
            if not resolved["exists"]:
                reason = "missing"
            elif resolved["workflow_status"] == "false_positive":
                reason = "stale"
            elif resolved["workflow_status"] == "merged":
                reason = "merged"
            if reason is not None:
                dangling_links.append(
                    {
                        "id": row.get("id"),
                        "cve_id": cve_id,
                        "linked_finding_slug": slug,
                        "reason": reason,
                        "workflow_status": resolved["workflow_status"],
                    }
                )

    # id included so the operator can disposition the exact lead row
    # (`vigil assess intel update note <id>`).
    open_leads = [
        {"id": row.get("id"), "title": row.get("title"), "lead_status": row.get("lead_status")}
        for row in list_leads(engagement_id, open_only=True)
    ]
    return {
        "applicable": True,
        "engagement_type": engagement_type,
        "open_high_cves": open_high_cves,
        "open_leads": open_leads,
        "exploited_unlinked_cves": exploited_unlinked_cves,
        "dangling_links": dangling_links,
    }


def list_dns_records(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(
        engagement_id, "intel_dns_records", include_superseded=include_superseded
    )


def list_social_profiles(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(
        engagement_id, "intel_social_profiles", include_superseded=include_superseded
    )


def list_breach_records(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(
        engagement_id, "intel_breach_records", include_superseded=include_superseded
    )


def list_org_facts(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(
        engagement_id, "intel_org_facts", include_superseded=include_superseded
    )


def list_notes(
    engagement_id: int, *, include_superseded: bool = True
) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_notes", include_superseded=include_superseded)


# Lead worklist. Kept separate from list_notes (whose contract feeds
# intel_summary and the frontend) so the open-lead query lives in one place for
# resume-brief and the readiness advisory.
LEAD_OPEN_STATUSES = frozenset({"open", "in_progress"})
# All valid lead_status values (mirrors LeadStatus in state_manager/_common.py;
# duplicated locally to avoid an import dependency on the state_manager package).
LEAD_STATUS_VALUES = frozenset({"open", "in_progress", "resolved", "ruled_out"})


def _validate_lead_status(value: Any) -> None:
    """Reject an invalid lead_status on every write path. The POST path already
    validates via the Pydantic Literal, but PATCH (_coerce_update_values) and
    supersede (record_note) bypass it — an unguarded typo would silently drop a
    lead from the open-lead worklist."""
    if value is not None and value not in LEAD_STATUS_VALUES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid lead_status: {value!r} (expected one of {sorted(LEAD_STATUS_VALUES)} or null)",
        )


def list_leads(
    engagement_id: int, *, open_only: bool = True
) -> list[dict[str, Any]]:
    """Canonical (non-superseded) notes that are tracked leads (``lead_status``
    is set). With ``open_only`` (default) only non-terminal leads are returned —
    the worklist. Already ordered ``updated_at DESC`` by ``_list_rows``."""
    leads: list[dict[str, Any]] = []
    for row in list_notes(engagement_id, include_superseded=False):
        status_value = str(row.get("lead_status") or "")
        if not status_value:
            continue
        if open_only and status_value not in LEAD_OPEN_STATUSES:
            continue
        leads.append(row)
    return leads


# ── Aggregate / search ─────────────────────────────────────


_SUMMARY_PLURAL: dict[str, str] = {
    "tech_component": "tech_components",
    "person": "people",
    "email": "emails",
    "domain": "domains",
    "cve": "cves",
    "dns_record": "dns_records",
    "social_profile": "social_profiles",
    "breach_record": "breach_records",
    "org_fact": "org_facts",
    "note": "notes",
}


def intel_summary(engagement_id: int) -> dict[str, int]:
    """Return row counts per intel entity type for the engagement.

    Keys use the plural table-family names the frontend consumes
    (``tech_components``, ``people``, …). The singular ``entity_type`` strings
    used by the FTS shadow index are kept internal to this module.
    """
    engagement = _engagement_or_404(engagement_id)
    counts: dict[str, int] = {}
    with get_connection() as connection:
        for entity_type, table in _LIST_TABLES.items():
            row = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ?",
                (engagement.id,),
            ).fetchone()
            counts[_SUMMARY_PLURAL[entity_type]] = (
                int(row[0]) if row and row[0] is not None else 0
            )
    return counts


_ENTITY_TO_TABLE = dict(_LIST_TABLES)


def _hydrate_search_record(
    connection, entity_type: str, source_id: int
) -> dict[str, Any]:
    """Fetch the full record behind a search hit so callers can render it inline."""
    table = _ENTITY_TO_TABLE.get(entity_type)
    if not table:
        return {}
    row = connection.execute(
        f"SELECT * FROM {table} WHERE id = ?", (source_id,)
    ).fetchone()
    if not row:
        return {}
    out = _row_to_dict(row)
    if entity_type == "cve":
        out["poc_available"] = bool(out.get("poc_available"))
    engagement_id = int(out.get("engagement_id") or 0)
    if engagement_id:
        out["canonical_id"] = _resolve_canonical_id(
            connection, table, engagement_id, int(out["id"])
        )
    return out


def intel_search(
    engagement_id: int,
    q: str,
    *,
    entity_type: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """FTS-backed search across every ``intel_*`` table via the shadow index.

    Returns a list of hits with ``entity_type``, ``source_id``, ``key``,
    ``body``, ``source_name``, ``rank`` (FTS5 bm25 score), and a ``record``
    dict hydrated from the underlying table. An empty ``q`` returns the most
    recently updated shadow rows so the UI can paginate without typing.
    """
    engagement = _engagement_or_404(engagement_id)
    fts_term = fts_escape(q) if q else ""
    params: list[Any] = [engagement.id]
    where = ["idx.engagement_id = ?"]
    join_sql = ""
    order_sql = "ORDER BY idx.updated_at DESC, idx.id DESC"
    select_rank = "NULL AS rank"
    if fts_term:
        join_sql = "JOIN intel_search_fts f ON f.rowid = idx.id"
        where.append("f.intel_search_fts MATCH ?")
        params.append(fts_term)
        select_rank = "f.rank AS rank"
        order_sql = "ORDER BY f.rank ASC, idx.updated_at DESC"
    if entity_type:
        where.append("idx.entity_type = ?")
        params.append(entity_type)
    params.extend([int(limit), int(offset)])
    query = (
        f"SELECT idx.entity_type, idx.source_id, idx.key, idx.body, idx.source_name, {select_rank} "
        f"FROM intel_search_index idx {join_sql} "
        f"WHERE {' AND '.join(where)} {order_sql} LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
        hits: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["record"] = _hydrate_search_record(
                connection, data["entity_type"], int(data["source_id"])
            )
            hits.append(data)
    return hits


# ── By-URL merged view ─────────────────────────────────────


def _host_from_url(url: str) -> str:
    """Best-effort extraction of the host portion of an arbitrary URL argument."""
    candidate = url.strip()
    if not candidate:
        return ""
    # urlparse needs a scheme to populate netloc; synthesise one when missing.
    if "://" not in candidate:
        candidate = "//" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ""
    host = parsed.hostname or ""
    return host.lower()


def intel_by_url(engagement_id: int, url: str) -> dict[str, Any]:
    """Return a merged view of intel records matching ``url``.

    Matches ``intel_domains.identity`` (host-level), ``assessment_services.endpoint``
    (substring), ``assessment_surfaces.target_descriptor`` (substring), and
    ``assessment_request_variants.host`` (host-level). Empty buckets are
    returned as empty lists so the frontend can render a consistent shape.
    """
    engagement = _engagement_or_404(engagement_id)
    if not url or not url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="url is required"
        )
    host = _host_from_url(url)
    url_like = f"%{url.strip()}%"
    host_like = f"%{host}%" if host else url_like
    with get_connection() as connection:
        domain_rows = connection.execute(
            "SELECT * FROM intel_domains WHERE engagement_id = ? "
            "AND (identity = ? OR identity LIKE ? OR value LIKE ?) "
            "ORDER BY updated_at DESC, id DESC",
            (engagement.id, host, host_like, url_like),
        ).fetchall()
        service_rows = connection.execute(
            "SELECT * FROM assessment_services WHERE engagement_id = ? "
            "AND endpoint LIKE ? ORDER BY updated_at DESC, id DESC",
            (engagement.id, url_like),
        ).fetchall()
        surface_rows = connection.execute(
            "SELECT * FROM assessment_surfaces WHERE engagement_id = ? "
            "AND target_descriptor LIKE ? ORDER BY updated_at DESC, id DESC",
            (engagement.id, url_like),
        ).fetchall()
        variant_rows = connection.execute(
            "SELECT * FROM assessment_request_variants WHERE engagement_id = ? "
            "AND (host = ? OR host LIKE ? OR canonical_url LIKE ?) "
            "ORDER BY last_seen_at DESC, id DESC",
            (engagement.id, host, host_like, url_like),
        ).fetchall()
    return {
        "domains": [_row_to_dict(row) for row in domain_rows],
        "services": [dict(row) for row in service_rows],
        "surfaces": [dict(row) for row in surface_rows],
        "request_variants": [dict(row) for row in variant_rows],
    }
