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
from typing import Any, Iterable
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import fts_escape


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
    if "tags_json" in data:
        data["tags"] = _decode_json(data.pop("tags_json") or "[]", [])
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
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
        "provenance_json": _json_text(provenance),
    }
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "fact_key": fact_key,
        "fact_value": fact_value,
        "source_name": source_name,
        "notes": notes,
        "provenance_json": _json_text(provenance),
    }
    with get_connection() as connection:
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
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    values = {
        "title": title,
        "body_markdown": body_markdown,
        "source_agent": source_agent,
        "tags_json": _json_list_text(tags or []),
        "source_name": source_name,
        "provenance_json": _json_text(provenance),
    }
    with get_connection() as connection:
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
            body=_compose_body(title, body_markdown, source_agent, *(tags or [])),
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


def _list_rows(engagement_id: int, table: str) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM {table} WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC",
            (engagement.id,),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def list_tech_components(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_tech_components")


def list_people(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_people")


def list_emails(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_emails")


def list_domains(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_domains")


def list_cves(engagement_id: int) -> list[dict[str, Any]]:
    rows = _list_rows(engagement_id, "intel_cves")
    for row in rows:
        row["poc_available"] = bool(row.get("poc_available"))
    return rows


def list_dns_records(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_dns_records")


def list_social_profiles(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_social_profiles")


def list_breach_records(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_breach_records")


def list_org_facts(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_org_facts")


def list_notes(engagement_id: int) -> list[dict[str, Any]]:
    return _list_rows(engagement_id, "intel_notes")


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
