"""One-shot migration: import historical ``intel.md`` and ``log.md`` files
into the per-engagement intel + activity tables.

Usage (from the repo root)::

    python -m orchestrator.backend.scripts.import_intel_md \
        [--data-dir /path/to/vigil \
        [--engagement 2026-04-12-072244-acme-info] \
        [--dry-run]

Defaults ``--data-dir`` to ``$VIGIL_INSTALL_DIR`` or
``~/vigil``. Processes every engagement whose
DB row exists AND whose filesystem folder still carries an ``intel.md`` or
``log.md``. On success, source files are renamed ``*.imported`` so the
operator can verify without them being re-read.

The script calls the ``app.services.intel`` / ``app.services.activity``
helpers directly in-process — this is an admin migration, not an agent
invocation, and going through HTTP would only add noise and flakiness.

Idempotency:
    An engagement is skipped entirely if ``intel.md.imported`` /
    ``log.md.imported`` already exists — re-running the script is a no-op.

Parsing strategy (see plan §4):
    - GFM tables drive structured imports. First row = headers, second
      row = ``|---|`` separator, remaining rows = data.
    - Section → table mapping is a static dict. Each ``## <heading>`` /
      ``### <heading>`` starts a new section scope; tables inside a
      section hit that section's target table.
    - Column-by-column best-effort mapping per target table. Columns
      that don't map cleanly fall into ``notes`` (ordered key=value).
    - Prose paragraphs between tables accumulate into the section's
      "preamble" and land as ``intel_notes`` with a hint
      (``title = <Section Preamble>``).
    - Anything we can't map at all becomes an ``intel_note`` with a
      ``"section=X row=N"`` tag — we never drop rows silently.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


# ── Bootstrap sys.path so ``app`` imports work when invoked either as a
#    module (``python -m orchestrator.backend.scripts.import_intel_md``)
#    or as a plain script. The backend root lives two levels up.
_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


def _configure_environment(install_root: Path) -> None:
    """Point ``app.config.settings`` at the installed data dir *before*
    ``app`` is imported. ``Settings`` reads env vars in its class body, so
    we set them here and only then import the db/services modules.
    """
    data_dir = install_root / "orchestrator" / "backend" / "data"
    # Accept both the new and legacy env var names; the old orchestrator
    # still checks ``REDTEAM_ORCHESTRATOR_DATA_DIR``.
    os.environ["VIGIL_DATA_DIR"] = str(data_dir)
    os.environ["REDTEAM_ORCHESTRATOR_DATA_DIR"] = str(data_dir)
    os.environ["VIGIL_INSTALL_DIR"] = str(install_root)
    # Disable the scheduled sqlite backup thread; the migration runs in a
    # CLI process that would leak the daemon thread past return.
    os.environ.setdefault("VIGIL_BACKUP_DISABLED", "1")


# ── Section → target-table mapping (plan §4). Keys are lowercased,
#    whitespace-collapsed headings stripped of trailing punctuation. Values
#    are the target-table identifiers recognised by ``_dispatch_row``.

_SECTION_TARGET: dict[str, str] = {
    "technology stack": "tech",
    "tech stack": "tech",
    "technology": "tech",
    "people & organizations": "people",
    "people": "people",
    "email addresses": "emails",
    "emails": "emails",
    "domains & infrastructure": "domains",
    "domains": "domains",
    "domains / subdomains": "domains",
    "dangling subdomains": "domains",
    "credentials & secrets": "credentials",
    "credentials": "credentials",
    "cve & known vulnerabilities": "cves",
    "cves": "cves",
    "known vulnerabilities": "cves",
    "cve validation pass": "cves",
    "breach & leak data": "breach",
    "breaches": "breach",
    "dns & certificate history": "dns",
    "dns": "dns",
    "dns / email security": "dns",
    "dns & email security": "dns",
    "dns hygiene": "dns",
    "social & osint profiles": "social",
    "social": "social",
    "organization details": "org",
    "org": "org",
}

# Friendly counter key per target type.
_COUNTER_KEY: dict[str, str] = {
    "tech": "tech",
    "people": "people",
    "emails": "emails",
    "domains": "domains",
    "credentials": "credentials",
    "cves": "cves",
    "breach": "breach",
    "dns": "dns",
    "social": "social",
    "org": "org",
    "notes": "notes",
}


# ── Column-name normalisation helpers.


def _normalise_heading(text: str) -> str:
    """Lower-case, collapse whitespace, strip surrounding punctuation."""
    cleaned = re.sub(r"\s+", " ", text).strip().strip(":").strip()
    return cleaned.lower()


def _col_key(name: str) -> str:
    """Normalise a table column header for matching."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _extract_value_preview(raw: str) -> str:
    """Pull a readable preview out of a ``| Value (preview) |`` cell.

    Strips backticks and surrounding whitespace but keeps the substance.
    """
    return raw.strip().strip("`").strip()


# ── Table parser ────────────────────────────────────────────


def _split_row(line: str) -> list[str]:
    """Return the cell values for a GFM table row.

    Leading/trailing pipes are tolerated. Escaped pipes (``\\|``) are left
    to the caller — none of the source files use them, so we treat ``|``
    as a hard separator.
    """
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _is_table_separator(line: str) -> bool:
    return bool(_SEPARATOR_RE.match(line))


def _is_table_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and stripped.count("|") >= 2


def _parse_tables_and_prose(
    lines: list[str],
) -> list[tuple[str, Any]]:
    """Walk ``lines`` and yield a sequence of segments.

    Each segment is one of:
      - ``("heading", (level, text))`` — ``##`` or ``###`` heading.
      - ``("table", (headers, rows))`` — list-of-strings headers + list
        of row-cell lists.
      - ``("prose", text)`` — non-empty, non-table, non-heading paragraph
        (multiple lines joined on newline).

    Blank lines are used only to split prose paragraphs.
    """
    segments: list[tuple[str, Any]] = []
    prose_buf: list[str] = []

    def flush_prose() -> None:
        if prose_buf:
            joined = "\n".join(prose_buf).strip()
            if joined:
                segments.append(("prose", joined))
            prose_buf.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            # blank line splits prose paragraphs but doesn't end them mid-list
            prose_buf.append("")
            i += 1
            continue
        # Heading?
        heading_match = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading_match:
            flush_prose()
            level = len(heading_match.group(1))
            text = heading_match.group(2).strip()
            segments.append(("heading", (level, text)))
            i += 1
            continue
        # Table?
        if _is_table_row(line) and i + 1 < len(lines) and _is_table_separator(lines[i + 1]):
            flush_prose()
            headers = _split_row(line)
            i += 2  # skip header + separator
            rows: list[list[str]] = []
            while i < len(lines) and _is_table_row(lines[i]) and not _is_table_separator(lines[i]):
                rows.append(_split_row(lines[i]))
                i += 1
            segments.append(("table", (headers, rows)))
            continue
        # Regular prose line
        prose_buf.append(stripped)
        i += 1

    flush_prose()
    return segments


# ── Row → helper-call dispatch ─────────────────────────────────


def _row_as_mapping(headers: list[str], row: list[str]) -> dict[str, str]:
    """Align row cells to header keys. Missing cells → empty string."""
    mapping: dict[str, str] = {}
    for idx, header in enumerate(headers):
        key = _col_key(header)
        value = row[idx].strip() if idx < len(row) else ""
        if key:
            mapping[key] = value
    return mapping


def _pick(mapping: dict[str, str], *candidates: str) -> str:
    """Return the first non-empty value whose normalised header key matches
    any of ``candidates``. Candidates are matched as prefixes so ``"value"``
    hits both ``"value"`` and ``"valuepreview"``.
    """
    for cand in candidates:
        key = _col_key(cand)
        if key in mapping and mapping[key]:
            return mapping[key]
    # Prefix fallback — handy for "Value (preview)" → "valuepreview".
    for cand in candidates:
        key = _col_key(cand)
        for k, v in mapping.items():
            if k.startswith(key) and v:
                return v
    return ""


def _remaining_notes(
    mapping: dict[str, str], headers: list[str], used: list[str]
) -> str:
    """Build a ``k=v; k=v`` string of every header→cell pair NOT in ``used``.

    Uses the original header strings (not the normalised keys) so the note
    reads naturally when rendered.
    """
    used_keys = {_col_key(u) for u in used}
    parts: list[str] = []
    for header in headers:
        key = _col_key(header)
        if not key or key in used_keys:
            continue
        value = mapping.get(key, "").strip()
        if not value:
            continue
        parts.append(f"{header.strip()}: {value}")
    return "; ".join(parts)


def _provenance(
    *, engagement_key: str, section: str, row_index: int, source_agent: str = "import_intel_md"
) -> dict[str, Any]:
    return {
        "agent_name": source_agent,
        "artifact_ref": f"{engagement_key}/intel.md",
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evidence_quote": f"section={section} row={row_index}",
    }


# Dispatch functions return (counter_key, True) on success, or
# (counter_key, False) if the row was deferred to intel_notes instead of
# its natural table. Deferrals still land as a recorded row — the counter
# key just reflects that it went to the fallback.


def _import_tech_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    component = _pick(mapping, "component", "name", "item", "tech", "technology")
    if not component:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="tech",
        )
    version = _pick(mapping, "version")
    source_name = _pick(mapping, "source", "sourcename")
    confidence = _pick(mapping, "confidence")
    evidence_ref = _pick(mapping, "evidence", "evidenceref", "ref")
    notes_extra = _remaining_notes(
        mapping, headers, ["component", "name", "item", "tech", "technology", "version", "source", "confidence", "evidence", "ref"]
    )
    record.record_tech_component(
        engagement_id,
        component=component,
        version=version,
        source_name=source_name,
        confidence=confidence,
        evidence_ref=evidence_ref,
        notes=notes_extra,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("tech", True)


def _import_person_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    name = _pick(mapping, "name", "person")
    if not name:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="people",
        )
    role = _pick(mapping, "role", "rolecontext", "context", "title")
    organization = _pick(mapping, "organization", "org", "company")
    email = _pick(mapping, "email")
    source_name = _pick(mapping, "source")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["name", "person", "role", "rolecontext", "context", "title", "organization", "org", "company", "email", "source", "notes"],
    )
    notes_cell = _pick(mapping, "notes")
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_person(
        engagement_id,
        name=name,
        role=role,
        organization=organization,
        email=email,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("people", True)


def _import_email_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    address = _pick(mapping, "email", "emailaddress", "address")
    if not address or "@" not in address:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="emails",
        )
    source_name = _pick(mapping, "source")
    role_hint = _pick(mapping, "role", "rolehint", "context")
    notes_extra = _remaining_notes(
        mapping, headers, ["email", "emailaddress", "address", "source", "role", "rolehint", "context", "notes"]
    )
    notes_cell = _pick(mapping, "notes")
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_email(
        engagement_id,
        address=address,
        role_hint=role_hint,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("emails", True)


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_ASN_RE = re.compile(r"^AS\d+", re.IGNORECASE)


def _guess_domain_kind(identity: str, declared_type: str) -> str:
    declared = declared_type.lower()
    if "asn" in declared or _ASN_RE.match(identity):
        return "asn"
    if "nameserver" in declared or "ns record" in declared or declared.startswith("ns "):
        return "nameserver"
    if "mx" in declared:
        return "mx"
    if "ptr" in declared:
        return "ptr"
    if "ip" in declared or _IP_RE.match(identity) or ":" in identity and identity.count(":") >= 2:
        return "ip"
    return "subdomain"


def _import_domain_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    identity = _pick(mapping, "item", "domain", "subdomain", "host", "identity", "name", "record")
    if not identity:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="domains",
        )
    declared_type = _pick(mapping, "type")
    kind = _guess_domain_kind(identity, declared_type)
    value = _pick(mapping, "value", "target", "ip")
    source_name = _pick(mapping, "source")
    live_status = _pick(mapping, "livestatus", "status", "live")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["item", "domain", "subdomain", "host", "identity", "name", "record", "type", "value", "target", "ip", "source", "livestatus", "status", "live", "notes"],
    )
    notes_cell = _pick(mapping, "notes")
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_domain(
        engagement_id,
        identity=identity,
        kind=kind,
        value=value,
        source_name=source_name,
        live_status=live_status,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("domains", True)


def _import_credential_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
    state_manager,
) -> tuple[str, bool]:
    kind = _pick(mapping, "type", "kind")
    value = _pick(mapping, "value", "valuepreview", "secret")
    value = _extract_value_preview(value)
    if not kind and not value:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="credentials",
        )
    ref = _pick(mapping, "ref", "reference")
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping, headers, ["type", "kind", "value", "valuepreview", "secret", "ref", "reference", "source", "notes"]
    )
    if ref and ref not in notes_cell:
        extras = [f"ref: {ref}"]
        if notes_extra:
            extras.append(notes_extra)
        notes_extra = "; ".join(extras)
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    # Credentials go into the scoped assessment_credentials table via
    # state_manager.record_credential. The natural key is credential_key —
    # we synthesise it from kind + a trimmed value preview so a repeat
    # import is an upsert.
    credential_key = f"{kind or 'credential'}::{value[:80] or f'row-{row_index}'}"
    state_manager.record_credential(
        engagement_id,
        credential_key=credential_key,
        kind=(kind or "unknown").lower().replace(" ", "_")[:60] or "unknown",
        principal="",
        secret=value,
        source_name=source_name,
        status_value="discovered",
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("credentials", True)


def _import_cve_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    cve_id = _pick(mapping, "cve", "cveid", "id")
    affected = _pick(mapping, "affected", "affectedcomponent", "component", "product")
    if not cve_id and not affected:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="cves",
        )
    if not cve_id:
        # Some rows are ``EDB-xxxx`` — keep them as the id so they still
        # land in intel_cves; validator UI will just render an EDB id.
        cve_id = affected or f"cve-row-{row_index}"
    cvss_raw = _pick(mapping, "cvss", "cvssscore", "score")
    cvss_score: float | None = None
    if cvss_raw:
        match = re.search(r"(\d+(?:\.\d+)?)", cvss_raw)
        if match:
            try:
                cvss_score = float(match.group(1))
            except ValueError:
                cvss_score = None
    poc_raw = _pick(mapping, "pocavailable", "poc", "exploit")
    poc_available = poc_raw.lower().startswith("y") if poc_raw else False
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["cve", "cveid", "id", "affected", "affectedcomponent", "component", "product", "cvss", "cvssscore", "score", "pocavailable", "poc", "exploit", "source", "notes"],
    )
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_cve(
        engagement_id,
        cve_id=cve_id,
        affected_component=affected,
        cvss_score=cvss_score,
        poc_available=poc_available,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("cves", True)


def _import_dns_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    raw_record = _pick(mapping, "record", "recordtype", "type", "kind")
    name_field = _pick(mapping, "name", "host", "domain")
    # The acme table packs the record+name into a single "Record"
    # cell like ``A tenant.acme.example``. Split on whitespace and treat the
    # first token as the record type.
    record_type = raw_record
    name = name_field
    if raw_record and not name:
        parts = raw_record.split(None, 1)
        if len(parts) == 2 and len(parts[0]) <= 8:
            record_type, name = parts[0], parts[1]
        else:
            name = raw_record
            record_type = ""
    if not record_type and not name:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="dns",
        )
    value = _pick(mapping, "value")
    first_seen = _pick(mapping, "firstseen", "first")
    last_seen = _pick(mapping, "lastseen", "last")
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["record", "recordtype", "type", "kind", "name", "host", "domain", "value", "firstseen", "first", "lastseen", "last", "source", "notes"],
    )
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_dns_record(
        engagement_id,
        record_type=(record_type or "RAW").upper()[:16],
        name=name or raw_record or f"row-{row_index}",
        value=value,
        first_seen=first_seen,
        last_seen=last_seen,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("dns", True)


def _import_social_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    subject_ref = _pick(mapping, "personorg", "person", "subject", "name")
    platform = _pick(mapping, "platform", "service")
    if not platform:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="social",
        )
    raw_link = _pick(mapping, "urlhandle", "url", "handle", "link")
    url = raw_link if raw_link.startswith(("http://", "https://")) else ""
    handle = raw_link if not url else ""
    subject_kind = "person" if subject_ref and " " in subject_ref else "org"
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["personorg", "person", "subject", "name", "platform", "service", "urlhandle", "url", "handle", "link", "source", "notes"],
    )
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_social_profile(
        engagement_id,
        subject_kind=subject_kind,
        subject_ref=subject_ref or "unknown",
        platform=platform,
        handle=handle,
        url=url,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("social", True)


def _import_breach_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    subject = _pick(mapping, "emaildomain", "email", "subject", "domain")
    breach = _pick(mapping, "breach", "breachname", "incident")
    if not subject or not breach:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="breach",
        )
    breach_date = _pick(mapping, "date")
    data_types = _pick(mapping, "datatypes", "data")
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping,
        headers,
        ["emaildomain", "email", "subject", "domain", "breach", "breachname", "incident", "date", "datatypes", "data", "source", "notes"],
    )
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_breach_record(
        engagement_id,
        subject=subject,
        breach_name=breach,
        breach_date=breach_date,
        data_types=data_types,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("breach", True)


def _import_org_row(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
) -> tuple[str, bool]:
    fact_key = _pick(mapping, "field", "key", "factkey")
    fact_value = _pick(mapping, "value", "factvalue")
    if not fact_key:
        return _fallback_note(
            record=record,
            engagement_id=engagement_id,
            headers=headers,
            mapping=mapping,
            section=section,
            row_index=row_index,
            engagement_key=engagement_key,
            counter="org",
        )
    source_name = _pick(mapping, "source")
    notes_cell = _pick(mapping, "notes")
    notes_extra = _remaining_notes(
        mapping, headers, ["field", "key", "factkey", "value", "factvalue", "source", "notes"]
    )
    notes = notes_cell if not notes_extra else (
        f"{notes_cell}; {notes_extra}" if notes_cell else notes_extra
    )
    record.record_org_fact(
        engagement_id,
        fact_key=fact_key,
        fact_value=fact_value,
        source_name=source_name,
        notes=notes,
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return ("org", True)


def _fallback_note(
    *,
    record,
    engagement_id: int,
    headers: list[str],
    mapping: dict[str, str],
    section: str,
    row_index: int,
    engagement_key: str,
    counter: str,
) -> tuple[str, bool]:
    """Last-resort dispatch: capture the raw row as an intel_note.

    ``counter`` is the natural counter this row *would* have incremented;
    it's passed through so the summary shows "deferred to intel_notes"
    accurately. Returns ``(counter, False)`` so the caller can bump both
    the natural bucket (as "attempted") and the deferred bucket.
    """
    lines = [f"{headers[i].strip()}: {row}" for i, row in enumerate([mapping.get(_col_key(h), "") for h in headers]) if row.strip()]
    body = "\n".join(lines) if lines else "(no cells)"
    # Titles must be unique per engagement (natural key). Embed the section
    # and a 1-indexed row number so re-runs UPSERT the same note.
    title = f"{section} — row {row_index} (unmapped)"
    record.record_note(
        engagement_id,
        title=title,
        body_markdown=body,
        source_agent="import_intel_md",
        tags=[f"section={section}", f"row={row_index}", "unmapped"],
        source_name=_pick(mapping, "source"),
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=row_index),
    )
    return (counter, False)


_DISPATCHERS: dict[str, Callable[..., tuple[str, bool]]] = {
    "tech": _import_tech_row,
    "people": _import_person_row,
    "emails": _import_email_row,
    "domains": _import_domain_row,
    "cves": _import_cve_row,
    "dns": _import_dns_row,
    "social": _import_social_row,
    "breach": _import_breach_row,
    "org": _import_org_row,
}


# ── Top-level intel.md importer ────────────────────────────────


def import_intel_md(
    *,
    engagement_id: int,
    engagement_key: str,
    path: Path,
    record,
    state_manager,
) -> dict[str, int]:
    """Parse ``path`` and write rows for ``engagement_id``.

    Returns a dict with per-bucket counts plus ``deferred`` — the count
    of rows that landed in ``intel_notes`` because no cleaner mapping was
    found.
    """
    counts: dict[str, int] = {
        "tech": 0,
        "people": 0,
        "emails": 0,
        "domains": 0,
        "credentials": 0,
        "cves": 0,
        "dns": 0,
        "social": 0,
        "breach": 0,
        "org": 0,
        "notes": 0,
        "deferred": 0,
    }
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    segments = _parse_tables_and_prose(text)

    # Walk segments, maintaining the current section heading. H2 starts a
    # new top-level section; H3 can further refine (e.g. "### CVE & …"
    # under "## Raw OSINT"). We pick the *most recently seen* known-heading
    # as the target.
    current_section = ""
    current_target: str | None = None
    prose_buffer: list[str] = []

    for seg_kind, payload in segments:
        if seg_kind == "heading":
            level, text_heading = payload
            # Flush any accumulated prose into the outgoing section as a note.
            if prose_buffer and current_section:
                _flush_prose_note(
                    record,
                    engagement_id=engagement_id,
                    section=current_section,
                    body="\n\n".join(prose_buffer).strip(),
                    engagement_key=engagement_key,
                    counts=counts,
                )
            prose_buffer = []
            current_section = text_heading
            target = _SECTION_TARGET.get(_normalise_heading(text_heading))
            # Only override the current target if this heading resolves.
            # Otherwise keep the outer section's target so sub-tables still
            # route correctly — but for unknown headings, later tables fall
            # into intel_notes via the "generic" path below.
            if target is not None:
                current_target = target
            elif level <= 2:
                # An unknown H1/H2 resets the target → tables go to notes.
                current_target = None
            continue
        if seg_kind == "prose":
            prose_buffer.append(payload)
            continue
        if seg_kind == "table":
            headers, rows = payload
            for row_idx, row in enumerate(rows, start=1):
                mapping = _row_as_mapping(headers, row)
                # Skip rows that are entirely blank (some source files
                # include trailing blank rows).
                if not any(v.strip() for v in mapping.values()):
                    continue
                handled = False
                if current_target == "credentials":
                    counter, ok = _import_credential_row(
                        record=record,
                        engagement_id=engagement_id,
                        headers=headers,
                        mapping=mapping,
                        section=current_section,
                        row_index=row_idx,
                        engagement_key=engagement_key,
                        state_manager=state_manager,
                    )
                    handled = True
                elif current_target and current_target in _DISPATCHERS:
                    counter, ok = _DISPATCHERS[current_target](
                        record=record,
                        engagement_id=engagement_id,
                        headers=headers,
                        mapping=mapping,
                        section=current_section,
                        row_index=row_idx,
                        engagement_key=engagement_key,
                    )
                    handled = True
                if not handled:
                    # Unknown section → raw intel_note catch-all.
                    counter, ok = _fallback_note(
                        record=record,
                        engagement_id=engagement_id,
                        headers=headers,
                        mapping=mapping,
                        section=current_section or "Unknown",
                        row_index=row_idx,
                        engagement_key=engagement_key,
                        counter="notes",
                    )
                if ok:
                    counts[_COUNTER_KEY.get(counter, "notes")] += 1
                else:
                    # row went to intel_notes instead of its natural table
                    counts["notes"] += 1
                    counts["deferred"] += 1

    # Flush any trailing prose after the final table.
    if prose_buffer and current_section:
        _flush_prose_note(
            record,
            engagement_id=engagement_id,
            section=current_section,
            body="\n\n".join(prose_buffer).strip(),
            engagement_key=engagement_key,
            counts=counts,
        )

    return counts


def _flush_prose_note(
    record,
    *,
    engagement_id: int,
    section: str,
    body: str,
    engagement_key: str,
    counts: dict[str, int],
) -> None:
    """Turn accumulated prose under a section into an ``intel_note``.

    Skips empty bodies. Uses a deterministic title so re-imports upsert.
    """
    if not body.strip():
        return
    title = f"{section} — preamble"
    record.record_note(
        engagement_id,
        title=title,
        body_markdown=body,
        source_agent="import_intel_md",
        tags=[f"section={section}", "preamble"],
        provenance=_provenance(engagement_key=engagement_key, section=section, row_index=0),
    )
    counts["notes"] += 1


# ── log.md importer ───────────────────────────────────────────

_LOG_ENTRY_HEADING_RE = re.compile(
    r"^##\s+"
    r"(?:\[(?P<time>\d{1,2}:\d{2}|\d{4}-\d{2}-\d{2})\]\s*)?"
    r"(?P<rest>.*)$"
)


def import_log_md(
    *,
    engagement_id: int,
    engagement_key: str,
    path: Path,
    activity,
) -> int:
    """Parse ``log.md`` and POST each entry to ``activity_entries``.

    Returns the number of entries written.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    entries = _split_log_entries(lines)

    if not entries:
        # No `##` structure — one big row with the whole file.
        activity.record_activity_entry(
            engagement_id,
            occurred_at=mtime.isoformat(timespec="seconds"),
            actor_kind="imported",
            actor_name="import_intel_md",
            title="Imported log.md (no structured entries)",
            action="",
            result="",
            artifact_ref=f"{engagement_key}/log.md",
            body_markdown=text.strip(),
            metadata={"import_source": "log.md", "structured": False},
        )
        return 1

    written = 0
    for offset, entry in enumerate(entries):
        occurred_at = entry["occurred_at"] or (
            mtime.replace(second=min(59, offset)).isoformat(timespec="seconds")
        )
        activity.record_activity_entry(
            engagement_id,
            occurred_at=occurred_at,
            actor_kind="imported",
            actor_name=entry["actor_name"] or "import_intel_md",
            title=entry["title"],
            action=entry["action"],
            result=entry["result"],
            artifact_ref=f"{engagement_key}/log.md",
            body_markdown=entry["body"],
            metadata={
                "import_source": "log.md",
                "heading_time": entry["raw_time"],
                "line_offset": entry["line_offset"],
            },
        )
        written += 1
    return written


def _split_log_entries(lines: list[str]) -> list[dict[str, Any]]:
    """Split ``lines`` at ``##`` headings into entry dicts.

    Returns [] if no ``##`` heading is present — callers fall back to a
    single whole-file entry in that case.
    """
    # Find indices of each H2 heading.
    heads: list[tuple[int, str]] = [
        (idx, line) for idx, line in enumerate(lines) if line.startswith("## ")
    ]
    if not heads:
        return []

    entries: list[dict[str, Any]] = []
    for head_i, (start, heading_line) in enumerate(heads):
        end = heads[head_i + 1][0] if head_i + 1 < len(heads) else len(lines)
        body_lines = lines[start:end]
        heading = heading_line[3:].strip()

        # Try to pull an `HH:MM` or `YYYY-MM-DD` out of a leading `[...]`.
        raw_time = ""
        title = heading
        match = re.match(r"^\[(?P<t>[^\]]+)\]\s*(?P<rest>.*)$", heading)
        if match:
            raw_time = match.group("t").strip()
            title = match.group("rest").strip()

        # Trailing ` — Actor` suffix (em-dash or double-dash).
        actor_name = ""
        actor_match = re.search(r"\s+[\u2014\-]{1,2}\s+([A-Za-z][A-Za-z0-9 /_\-]*)$", title)
        if actor_match:
            actor_name = actor_match.group(1).strip()
            title = title[: actor_match.start()].strip()

        # Pull **Action** and **Result** from the body block.
        action = ""
        result = ""
        body_text = "\n".join(body_lines[1:]).strip()
        action_match = re.search(r"^\*\*Action\*\*:\s*(.+)$", body_text, flags=re.MULTILINE)
        if action_match:
            action = action_match.group(1).strip()
        result_match = re.search(r"^\*\*Result\*\*:\s*(.+)$", body_text, flags=re.MULTILINE)
        if result_match:
            result = result_match.group(1).strip()

        occurred_at = _coerce_occurred_at(raw_time)
        entries.append(
            {
                "raw_time": raw_time,
                "occurred_at": occurred_at,
                "title": title[:500],
                "actor_name": actor_name[:200],
                "action": action[:2000],
                "result": result[:2000],
                "body": "\n".join(body_lines).strip(),
                "line_offset": start,
            }
        )
    return entries


def _coerce_occurred_at(raw_time: str) -> str:
    """Convert ``HH:MM`` or ``YYYY-MM-DD`` to an ISO8601 timestamp.

    ``HH:MM`` is anchored to today's date since log entries written without
    a date component are always same-day. ``YYYY-MM-DD`` entries get 00:00.
    Returns ``""`` when parsing fails so the caller can fall back.
    """
    raw = raw_time.strip()
    if not raw:
        return ""
    hhmm = re.match(r"^(\d{1,2}):(\d{2})$", raw)
    if hhmm:
        today = datetime.now(timezone.utc).replace(
            hour=int(hhmm.group(1)), minute=int(hhmm.group(2)), second=0, microsecond=0
        )
        return today.isoformat(timespec="seconds")
    ymd = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", raw)
    if ymd:
        try:
            return datetime(int(ymd.group(1)), int(ymd.group(2)), int(ymd.group(3)), tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            return ""
    return ""


# ── Driver ────────────────────────────────────────────────────


class _NoopRecord:
    """Stand-in for ``app.services.intel`` under ``--dry-run``.

    Each record_* helper returns an empty dict and performs no DB I/O, so
    the parser still walks the file (producing real counts) but nothing is
    persisted. We shadow only the helpers the importer calls.
    """

    @staticmethod
    def record_tech_component(*args, **kwargs): return {}

    @staticmethod
    def record_person(*args, **kwargs): return {}

    @staticmethod
    def record_email(*args, **kwargs): return {}

    @staticmethod
    def record_domain(*args, **kwargs): return {}

    @staticmethod
    def record_cve(*args, **kwargs): return {}

    @staticmethod
    def record_dns_record(*args, **kwargs): return {}

    @staticmethod
    def record_social_profile(*args, **kwargs): return {}

    @staticmethod
    def record_breach_record(*args, **kwargs): return {}

    @staticmethod
    def record_org_fact(*args, **kwargs): return {}

    @staticmethod
    def record_note(*args, **kwargs): return {}


class _NoopActivity:
    @staticmethod
    def record_activity_entry(*args, **kwargs): return {}


class _NoopStateManager:
    @staticmethod
    def record_credential(*args, **kwargs): return {}


def _process_engagement(
    *,
    engagement_row,
    engagements_dir: Path,
    dry_run: bool,
    db,
    record,
    activity,
    state_manager,
    log: Callable[[str], None],
) -> dict[str, int]:
    """Handle one engagement end-to-end. Returns the aggregated counts."""
    key = engagement_row.key
    folder = engagements_dir / key
    intel_path = folder / "intel.md"
    log_path = folder / "log.md"
    intel_imported = folder / "intel.md.imported"
    log_imported = folder / "log.md.imported"

    counts: dict[str, int] = {
        "tech": 0, "people": 0, "emails": 0, "domains": 0, "credentials": 0,
        "cves": 0, "dns": 0, "social": 0, "breach": 0, "org": 0, "notes": 0,
        "deferred": 0, "log_entries": 0,
    }

    processed = False

    # Under --dry-run we still walk every file so row counts are real, but
    # the record_* helpers become no-ops — nothing hits the DB or FS.
    effective_record = _NoopRecord if dry_run else record
    effective_activity = _NoopActivity if dry_run else activity
    effective_state_manager = _NoopStateManager if dry_run else state_manager

    # Intel — skip if a prior run's marker exists.
    if intel_imported.exists():
        log(f"{key}: intel.md.imported already present — skipped")
    elif intel_path.exists():
        sub = import_intel_md(
            engagement_id=engagement_row.id,
            engagement_key=key,
            path=intel_path,
            record=effective_record,
            state_manager=effective_state_manager,
        )
        for k, v in sub.items():
            counts[k] = counts.get(k, 0) + v
        processed = True
        if not dry_run:
            intel_path.rename(intel_imported)

    # Log — independent of intel success.
    if log_imported.exists():
        log(f"{key}: log.md.imported already present — skipped")
    elif log_path.exists():
        written = import_log_md(
            engagement_id=engagement_row.id,
            engagement_key=key,
            path=log_path,
            activity=effective_activity,
        )
        counts["log_entries"] = written
        processed = True
        if not dry_run:
            log_path.rename(log_imported)

    if not processed:
        log(f"{key}: no intel.md / log.md to import")
    return counts


def _format_counts(counts: dict[str, int]) -> str:
    tracked = [
        "tech", "people", "emails", "domains", "credentials", "cves", "dns",
        "social", "breach", "org", "notes",
    ]
    per_type = ", ".join(f"{k}:{counts.get(k, 0)}" for k in tracked if counts.get(k, 0))
    total_intel = sum(counts.get(k, 0) for k in tracked)
    log_entries = counts.get("log_entries", 0)
    deferred = counts.get("deferred", 0)
    return (
        f"intel +{total_intel} rows ({per_type or 'none'}), "
        f"log +{log_entries} entries, "
        f"{deferred} rows deferred to intel_notes"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("VIGIL_INSTALL_DIR", str(Path.home() / "vigil")),
        help="Install root containing agent/engagements and orchestrator/backend/data.",
    )
    parser.add_argument(
        "--engagement",
        default="",
        help="Only process this engagement key (default: all).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and report counts but do not rename source files.",
    )
    args = parser.parse_args(argv)

    install_root = Path(args.data_dir).expanduser().resolve()
    if not install_root.exists():
        print(f"ERROR: --data-dir {install_root} does not exist", file=sys.stderr)
        return 2

    _configure_environment(install_root)

    # Imports happen *after* env configuration so ``settings.data_dir``
    # resolves to the installed DB path.
    from app import db  # noqa: E402
    from app.services import intel as record  # noqa: E402
    from app.services import activity  # noqa: E402
    from app.services import state_manager  # noqa: E402

    db.init_db()

    engagements_dir = install_root / "agent" / "engagements"
    if not engagements_dir.exists():
        print(f"ERROR: engagements dir {engagements_dir} does not exist", file=sys.stderr)
        return 2

    if args.engagement:
        engagement = db.get_engagement_by_key(args.engagement)
        if engagement is None:
            print(f"ERROR: no engagement row for key {args.engagement}", file=sys.stderr)
            return 2
        targets = [engagement]
    else:
        targets = db.list_engagements()

    overall: dict[str, int] = {}

    def log(msg: str) -> None:
        print(msg, file=sys.stderr)

    banner = "DRY RUN" if args.dry_run else "LIVE RUN"
    print(f"[{banner}] install_root={install_root}", file=sys.stderr)

    for engagement in targets:
        counts = _process_engagement(
            engagement_row=engagement,
            engagements_dir=engagements_dir,
            dry_run=args.dry_run,
            db=db,
            record=record,
            activity=activity,
            state_manager=state_manager,
            log=log,
        )
        summary = _format_counts(counts)
        print(f"{engagement.key}: {summary}")
        for k, v in counts.items():
            overall[k] = overall.get(k, 0) + v

    print("—" * 40)
    print(f"TOTAL: {_format_counts(overall)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
