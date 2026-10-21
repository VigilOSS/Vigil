"""The engagement Activity feed: audit-log entries merged with structured events.

``activity_entries`` (the audit log) and ``events`` (structured state changes)
are read as one newest-first stream:

- ``activity.recorded`` events are dropped: ``vigil assess log`` writes the
  audit row first and then mirrors its title as that event.
- A ``finding.created`` / ``finding.merged`` event is dropped when the audit
  row its backend write produced (same finding, within minutes) is present;
  the audit row carries more (severity, status). Events with no such row,
  as in older engagements, stay.
- Inferred ``phase.started`` / ``task.*`` rows that ``/events`` synthesises
  are not included; their source audit rows already are.

Ordering, cursors, and time filters use ``julianday`` because stored
timestamps mix SQLite ``YYYY-MM-DD HH:MM:SS`` and ISO-8601 spellings; every
timestamp leaves as ISO-8601 UTC. Categories and the derived actor kind are
SQL expressions so filters and counts run in the database.

Search matches what the operator reads: a row matches when every query word
appears in its summary, actor, entity chips, or stored fields. Summaries are
built at read time, so a search projects each candidate row through the same
builders the page uses and hands the matching ids back to the SQL page and
count queries; the FTS index still matches stored audit fields word-wise.

Every entity chip carries ``ref``, the concrete record it opens, or an
``unlinked_reason`` saying why it opens nothing.
"""
from __future__ import annotations

import json
import math
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Literal

from fastapi import HTTPException, status

from ..db import database_path, get_connection
from .activity import _normalize_timestamp
from .artifacts import ARTIFACT_SPECS
from .events import _engagement_or_404
from .intel import _INTEL_TABLE_BY_TYPE
from .search import fts_escape
from .state_manager.oob import OOB_PROBE_VERDICTS, oob_verdict_entry
from .timestamps import iso_utc


# ── Categories ──────────────────────────────────────────────────────────
#
# One table owns every category decision. Audit rows are classified by the
# backend writer titles (``actor_kind='system'``) plus earlier spellings still
# present in stored engagements; hook rows are tool calls except the dispatch
# and session hooks; agent/operator narrative is "notes".

CATEGORIES: tuple[tuple[str, str], ...] = (
    ("decisions", "Decisions & handoffs"),
    ("findings", "Findings & chains"),
    ("knowledge", "Target knowledge"),
    ("lifecycle", "Agent lifecycle"),
    ("code", "Code review"),
    ("files", "Files & reports"),
    ("notes", "Notes & other"),
    ("tools", "Tool calls"),
)
CATEGORY_KEYS = frozenset(key for key, _ in CATEGORIES)
DEFAULT_HIDDEN_CATEGORIES = frozenset({"tools"})

_FINDING_RECORD_TITLES = ("finding-record", "record-finding")
_FINDING_MERGE_TITLES = ("merge-findings",)

_AUDIT_SYSTEM_TITLES: dict[str, tuple[str, ...]] = {
    "decisions": (
        "agent decision",
        "agent handoff",
        "operator checkpoint",
        "dispatch record-handoff",
        "dispatch update-handoff",
        "dispatch record-decision",
    ),
    "lifecycle": (
        "agent start",
        "agent done",
        "agent bind-client-handle",
        "dispatch register",
        "dispatch update-status",
    ),
    "findings": (
        *_FINDING_RECORD_TITLES,
        *_FINDING_MERGE_TITLES,
        "update-finding",
        "verify-finding",
        "link-finding",
        "unlink-finding",
    ),
}
_AUDIT_SYSTEM_PREFIXES: dict[str, tuple[str, ...]] = {
    "findings": ("finding-",),
    "code": ("code-record", "code-dispatch"),
    "files": ("artifact ", "Submission "),
}
_HOOK_LIFECYCLE_PREFIXES = ("Dispatch:",)
_HOOK_LIFECYCLE_TITLES = ("Client session ended",)

_EVENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "findings": ("finding.", "chain."),
    "knowledge": ("surface.", "intel."),
    "lifecycle": ("phase.", "task.", "agent_dispatch"),
    "decisions": ("verification_decision", "status_update"),
    "code": ("code_analysis.",),
    "files": ("artifact.", "report."),
}

# Actor names that identify Vigil itself rather than an operator or agent.
_SYSTEM_ACTOR_NAMES = ("", "vigil-assess", "web-ui", "system", "unknown")

# A mirrored event and its audit row are written by one CLI call; the window
# only bounds the index probe, the finding slug is what makes the match exact.
_MIRROR_WINDOW_DAYS = 10 / (24 * 60)


def _glob_prefix(column: str, prefixes: Iterable[str]) -> tuple[str, list[Any]]:
    """``column GLOB 'prefix*'`` terms; GLOB is exact and case-sensitive."""
    values = list(prefixes)
    return " OR ".join(f"{column} GLOB ?" for _ in values), [f"{value}*" for value in values]


def _in(column: str, values: Iterable[str]) -> tuple[str, list[Any]]:
    items = list(values)
    return f"{column} IN ({', '.join('?' for _ in items)})", items


def _audit_category_sql() -> tuple[str, list[Any]]:
    params: list[Any] = []
    hook_prefix_sql, hook_prefix_params = _glob_prefix("a.title", _HOOK_LIFECYCLE_PREFIXES)
    hook_title_sql, hook_title_params = _in("a.title", _HOOK_LIFECYCLE_TITLES)
    whens = [
        f"WHEN a.actor_kind = 'hook' AND ({hook_prefix_sql} OR {hook_title_sql}) THEN 'lifecycle'",
        "WHEN a.actor_kind = 'hook' THEN 'tools'",
        "WHEN a.actor_kind != 'system' THEN 'notes'",
    ]
    params += hook_prefix_params + hook_title_params
    for category, titles in _AUDIT_SYSTEM_TITLES.items():
        clause, values = _in("a.title", titles)
        prefix_sql, prefix_params = _glob_prefix("a.title", _AUDIT_SYSTEM_PREFIXES.get(category, ()))
        whens.append(f"WHEN {clause}{f' OR {prefix_sql}' if prefix_sql else ''} THEN '{category}'")
        params += values + prefix_params
    for category, prefixes in _AUDIT_SYSTEM_PREFIXES.items():
        if category in _AUDIT_SYSTEM_TITLES:
            continue
        prefix_sql, prefix_params = _glob_prefix("a.title", prefixes)
        whens.append(f"WHEN {prefix_sql} THEN '{category}'")
        params += prefix_params
    return f"CASE {' '.join(whens)} ELSE 'notes' END", params


def _event_category_sql() -> tuple[str, list[Any]]:
    whens = ["WHEN e.event_type = 'artifact.updated' AND e.task_name = 'log.md' THEN 'notes'"]
    params: list[Any] = []
    for category, prefixes in _EVENT_PREFIXES.items():
        prefix_sql, prefix_params = _glob_prefix("e.event_type", prefixes)
        whens.append(f"WHEN {prefix_sql} THEN '{category}'")
        params += prefix_params
    return f"CASE {' '.join(whens)} ELSE 'notes' END", params


def _audit_actor_kind_sql() -> tuple[str, list[Any]]:
    names_sql, names = _in("a.actor_name", _SYSTEM_ACTOR_NAMES)
    return (
        "CASE WHEN a.actor_name = 'operator' OR a.actor_kind = 'operator' THEN 'operator' "
        "WHEN a.actor_kind = 'agent' THEN 'agent' "
        f"WHEN a.actor_kind IN ('system', 'hook') AND NOT ({names_sql}) "
        "AND a.actor_name NOT GLOB '*-hook' THEN 'agent' "
        "ELSE 'system' END",
        names,
    )


def _event_actor_kind_sql() -> tuple[str, list[Any]]:
    names_sql, names = _in("e.agent_name", _SYSTEM_ACTOR_NAMES)
    return (
        f"CASE WHEN e.agent_name = 'operator' THEN 'operator' WHEN {names_sql} THEN 'system' "
        "ELSE 'agent' END",
        names,
    )


def _mirror_exclusion_sql() -> tuple[str, list[Any]]:
    """Exclude events whose content is already an audit row (see module doc)."""
    clauses: list[str] = []
    params: list[Any] = []
    for event_type, titles, slug_key in (
        ("finding.created", _FINDING_RECORD_TITLES, "$.finding_slug"),
        ("finding.merged", _FINDING_MERGE_TITLES, "$.source_slug"),
    ):
        titles_sql, title_params = _in("m.title", titles)
        clauses.append(
            f"""(e.event_type = ? AND EXISTS (
                SELECT 1 FROM activity_entries m
                WHERE m.engagement_id = e.engagement_id
                  AND julianday(m.occurred_at) BETWEEN julianday(e.created_at) - ? AND julianday(e.created_at) + ?
                  AND {titles_sql}
                  AND CASE WHEN json_valid(m.metadata_json)
                      THEN json_extract(m.metadata_json, ?) END = e.task_name))"""
        )
        params += [event_type, _MIRROR_WINDOW_DAYS, _MIRROR_WINDOW_DAYS, *title_params, slug_key]
    return f"NOT ({' OR '.join(clauses)})", params


# ── Cursors ─────────────────────────────────────────────────────────────
#
# The feed's total order is (instant, source, id) descending, with audit rows
# ranked above events at an identical instant. A cursor is that key; the
# julianday float round-trips exactly through ``repr``.

_SOURCE_RANK = {"audit": 1, "event": 0}


@dataclass(frozen=True, slots=True)
class FeedCursor:
    julian: float
    source: Literal["audit", "event"]
    row_id: int

    def encode(self) -> str:
        return f"{self.julian!r}~{self.source}~{self.row_id}"

    @classmethod
    def decode(cls, raw: str, *, field_name: str) -> FeedCursor:
        parts = raw.split("~")
        try:
            if len(parts) != 3 or parts[1] not in _SOURCE_RANK:
                raise ValueError(raw)
            julian = float(parts[0])
            row_id = int(parts[2])
            if not math.isfinite(julian) or row_id < 1:
                raise ValueError(raw)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{field_name} is not a cursor returned by this feed",
            ) from exc
        return cls(julian, parts[1], row_id)  # type: ignore[arg-type]

    def sort_key(self) -> tuple[float, int, int]:
        return (self.julian, _SOURCE_RANK[self.source], self.row_id)


def _cursor_sql(
    julian_sql: str, id_sql: str, source: str, cursor: FeedCursor, *, older: bool
) -> tuple[str, list[Any]]:
    """Rows strictly older (or newer) than ``cursor`` in the feed order.

    The leading ``<=``/``>=`` bound lets SQLite range-seek the julianday index;
    the disjunction then resolves rows sharing the cursor's instant.
    """
    below, bound = ("<", "<=") if older else (">", ">=")
    source_rank, cursor_rank = _SOURCE_RANK[source], _SOURCE_RANK[cursor.source]
    if source_rank == cursor_rank:
        tie = f"{id_sql} {below} ?"
        tie_params: list[Any] = [cursor.row_id]
    elif (source_rank < cursor_rank) == older:
        tie, tie_params = "1", []
    else:
        tie, tie_params = "0", []
    return (
        f"{julian_sql} {bound} ? AND ({julian_sql} {below} ? OR ({julian_sql} = ? AND {tie}))",
        [cursor.julian, cursor.julian, cursor.julian, *tie_params],
    )


# ── Query assembly ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Filters:
    actor: str
    since: str | None
    until: str | None
    fts_term: str
    text_tokens: tuple[str, ...]
    # JSON arrays of the row ids matching the search (``_search_matches``);
    # None when no search is active.
    audit_ids: str | None = None
    event_ids: str | None = None


def _audit_where(engagement_id: int, filters: _Filters) -> tuple[list[str], list[Any]]:
    where = ["a.engagement_id = ?"]
    params: list[Any] = [engagement_id]
    if filters.actor:
        kind_sql, kind_params = _audit_actor_kind_sql()
        where.append(f"({kind_sql}) = ?")
        params += [*kind_params, filters.actor]
    if filters.since:
        where.append("julianday(a.occurred_at) >= julianday(?)")
        params.append(filters.since)
    if filters.until:
        where.append("julianday(a.occurred_at) <= julianday(?)")
        params.append(filters.until)
    if filters.audit_ids is not None:
        where.append("a.id IN (SELECT value FROM json_each(?))")
        params.append(filters.audit_ids)
    return where, params


def _event_where(engagement_id: int, filters: _Filters) -> tuple[list[str], list[Any]]:
    mirror_sql, mirror_params = _mirror_exclusion_sql()
    where = ["e.engagement_id = ?", "e.event_type != 'activity.recorded'", mirror_sql]
    params: list[Any] = [engagement_id, *mirror_params]
    if filters.actor:
        kind_sql, kind_params = _event_actor_kind_sql()
        where.append(f"({kind_sql}) = ?")
        params += [*kind_params, filters.actor]
    if filters.since:
        where.append("julianday(e.created_at) >= julianday(?)")
        params.append(filters.since)
    if filters.until:
        where.append("julianday(e.created_at) <= julianday(?)")
        params.append(filters.until)
    if filters.event_ids is not None:
        where.append("e.id IN (SELECT value FROM json_each(?))")
        params.append(filters.event_ids)
    return where, params


def _category_filter(category_sql: str, category_params: list[Any], categories: frozenset[str]) -> tuple[str, list[Any]]:
    selected = sorted(categories)
    return (
        f"({category_sql}) IN ({', '.join('?' for _ in selected)})",
        [*category_params, *selected],
    )


@dataclass(frozen=True, slots=True)
class _Source:
    name: Literal["audit", "event"]
    table: str
    stamp_sql: str
    id_sql: str
    category_sql: Callable[[], tuple[str, list[Any]]]
    actor_kind_sql: Callable[[], tuple[str, list[Any]]]
    where: Callable[[int, _Filters], tuple[list[str], list[Any]]]
    item: Callable[[Any], dict[str, Any]]


def _fetch(
    connection,
    source: _Source,
    engagement_id: int,
    filters: _Filters,
    categories: frozenset[str],
    cursor: FeedCursor | None,
    *,
    older: bool,
    limit: int,
    dated: bool,
) -> list[dict[str, Any]]:
    """One source's next ``limit`` rows past ``cursor`` in feed order.

    Rows whose stored timestamp does not parse (``julianday`` is NULL) never
    come from a current writer, but they are not dropped: they sort as the
    oldest rows of the feed (instant 0) in id order. They are read separately
    (``dated=False``) so the dated read (``dated=True``) keeps its
    julianday-index range seek.
    """
    category_sql, category_params = source.category_sql()
    kind_sql, kind_params = source.actor_kind_sql()
    where, params = source.where(engagement_id, filters)
    clause, clause_params = _category_filter(category_sql, category_params, categories)
    where.append(clause)
    params += clause_params
    julian_sql = f"julianday({source.stamp_sql})" if dated else "0.0"
    where.append(f"julianday({source.stamp_sql}) IS {'NOT ' if dated else ''}NULL")
    if cursor is not None:
        cursor_clause, cursor_params = _cursor_sql(julian_sql, source.id_sql, source.name, cursor, older=older)
        where.append(cursor_clause)
        params += cursor_params
    direction = "DESC" if older else "ASC"
    order = f"{julian_sql} {direction}, {source.id_sql} {direction}" if dated else f"{source.id_sql} {direction}"
    rows = connection.execute(
        f"""
        SELECT *, {julian_sql} AS feed_julian,
               ({category_sql}) AS feed_category, ({kind_sql}) AS feed_actor_kind
        FROM {source.table}
        WHERE {' AND '.join(where)}
        ORDER BY {order}
        LIMIT ?
        """,
        (*category_params, *kind_params, *params, limit),
    ).fetchall()
    return [source.item(row) for row in rows]


def _category_counts(connection, engagement_id: int, filters: _Filters) -> dict[str, int]:
    counts = {key: 0 for key in CATEGORY_KEYS}
    audit_category_sql, audit_category_params = _audit_category_sql()
    audit_where, audit_params = _audit_where(engagement_id, filters)
    event_category_sql, event_category_params = _event_category_sql()
    event_where, event_params = _event_where(engagement_id, filters)
    for sql, params in (
        (
            f"SELECT ({audit_category_sql}) AS category, COUNT(*) AS n FROM activity_entries a "
            f"WHERE {' AND '.join(audit_where)} GROUP BY category",
            [*audit_category_params, *audit_params],
        ),
        (
            f"SELECT ({event_category_sql}) AS category, COUNT(*) AS n FROM events e "
            f"WHERE {' AND '.join(event_where)} GROUP BY category",
            [*event_category_params, *event_params],
        ),
    ):
        for row in connection.execute(sql, tuple(params)).fetchall():
            counts[str(row["category"])] += int(row["n"])
    return counts


# ── Row projection ──────────────────────────────────────────────────────

_FINDING_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEVERITY_RE = re.compile(r"\bseverity=(\S+)")


def _metadata(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _positive_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _slug(value: Any) -> str:
    text = _text(value)
    return text if _FINDING_SLUG_RE.match(text) else ""


def _entity(entity_type: str, key: str | int, label: str | None = None, **lookup: Any) -> dict[str, Any]:
    """A chip. ``lookup`` holds what ``_resolve_entity_refs`` needs to find its record."""
    return {"type": entity_type, "key": str(key), "label": label or str(key), "_lookup": lookup}


def _humanize(value: str) -> str:
    return value.replace("_", " ").strip()


def _with(prefix: str, value: str, separator: str = ": ") -> str:
    return f"{prefix}{separator}{value}" if value else prefix


def _oob_verdict_summary(nonce: str, verdict: str, previous: str) -> str:
    if previous == verdict:
        return f"Added a note to the {verdict} verdict on OAST probe {nonce}"
    if previous in OOB_PROBE_VERDICTS:
        return f"Changed OAST probe {nonce} from {previous} to {verdict}"
    if verdict == "confirmed":
        return f"Confirmed OAST probe {nonce} as a real callback"
    return f"Ignored OAST probe {nonce} as noise"


def _audit_entities(title: str, actor_kind: str, meta: dict[str, Any]) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    oob_verdict = oob_verdict_entry(title, actor_kind, meta)
    if oob_verdict:
        entities.append(_entity("oob_probe", oob_verdict[0], f"OAST probe {oob_verdict[0]}"))
    slugs: list[str] = []
    for key in ("finding_slug", "target_slug", "source_slug", "root_cause_slug"):
        slug = _slug(meta.get(key))
        if slug:
            slugs.append(slug)
    if isinstance(meta.get("finding_slugs"), list):
        slugs += [slug for slug in map(_slug, meta["finding_slugs"]) if slug]
    for slug in dict.fromkeys(slugs):
        entities.append(_entity("finding", slug))
    variant = _positive_int(meta.get("request_variant_id"))
    if variant:
        entities.append(_entity("http_variant", variant, f"Request variant #{variant}"))
    run = _positive_int(meta.get("run_id"))
    if run:
        entities.append(_entity("run", run, f"Run #{run}"))
    file_id = _positive_int(meta.get("file_id"))
    if file_id:
        entities.append(_entity(
            "code_file", file_id, f"Code file #{file_id}",
            result_id=_positive_int(meta.get("result_id")),
            queue_item_id=_positive_int(meta.get("queue_item_id")),
        ))
    path = _text(meta.get("relative_path"))
    if path:
        entities.append(_entity("file", path))
    return entities


def _audit_summary(title: str, action: str, result: str, meta: dict[str, Any], actor_kind: str) -> str:
    """One plain sentence for an audit row; the raw fields stay in ``detail``."""
    agent_id = _text(meta.get("agent_id"))
    slug = _slug(meta.get("finding_slug"))
    oob_verdict = oob_verdict_entry(title, actor_kind, meta)
    if oob_verdict:
        return _oob_verdict_summary(*oob_verdict)
    if actor_kind == "hook":
        if title == "Bash":
            return _with("Ran", action.removeprefix("bash:").strip())
        if title.startswith("Dispatch:"):
            return _with(f"Dispatched {title.removeprefix('Dispatch:').strip()}", action)
        if action.startswith("files="):
            return _with(f"{title} edited", action.removeprefix("files="))
        return _with(title, action)
    if actor_kind != "system":
        return title or _with("Note", action)
    if title == "agent start":
        return f"Started {agent_id}" if agent_id else _with("Agent started", action)
    if title == "agent done":
        slugs = [slug for slug in map(_slug, meta.get("finding_slugs") or []) if slug]
        sentence = f"{agent_id or 'Agent'} finished" + (f" ({result})" if result else "")
        return sentence + (f" · findings {', '.join(slugs)}" if slugs else "")
    if title == "agent handoff":
        return _with(f"Handoff from {agent_id or 'agent'}", result)
    if title == "agent bind-client-handle":
        client = _text(meta.get("asserted_client"))
        return f"Bound {agent_id or 'agent'} to a {client or 'client'} session"
    if title == "agent decision":
        kind = _humanize(_text(meta.get("kind")) or action.removeprefix("kind="))
        return _with("Decision", kind) + (" (shown to the user)" if meta.get("surfaced_to_user") is True else "")
    if title == "operator checkpoint":
        version = meta.get("checkpoint_version")
        return f"Operator checkpoint v{version}" + (f" · phase {result}" if result else "") if version else _with("Operator checkpoint", result)
    if title in _FINDING_RECORD_TITLES and slug:
        severity_match = _SEVERITY_RE.search(action)
        qualifiers = [value for value in (severity_match.group(1) if severity_match else "", result) if value]
        return f"Recorded finding {slug}" + (f" ({', '.join(qualifiers)})" if qualifiers else "")
    if title in ("finding-update", "update-finding") and slug:
        return _with(f"Updated finding {slug}", result)
    if title in ("finding-verify", "verify-finding") and slug:
        # Earlier engagements stored the verdict as ``disposition``.
        verification = _humanize(_text(meta.get("verification_status")) or _text(meta.get("disposition")))
        sentence = f"Set {slug} verification to {verification}" if verification else f"Updated {slug} verification"
        return _with(sentence, result)
    if title in ("finding-link", "link-finding") and slug:
        root_cause = _slug(meta.get("root_cause_slug"))
        if root_cause:
            return f"Linked {slug} to root cause {root_cause}" + (f" ({_humanize(result)})" if result else "")
        target = action.partition(" link=")[2].strip()
        return _with(f"Linked {slug}", target, " to ")
    if title in _FINDING_MERGE_TITLES and _slug(meta.get("source_slug")) and _slug(meta.get("target_slug")):
        return f"Merged {meta['source_slug']} into {meta['target_slug']}"
    if title in ("code-record analysis", "code-record-analysis") and _positive_int(meta.get("file_id")):
        disposition = _humanize(_text(meta.get("disposition")) or result)
        sentence = f"Reviewed code file #{meta['file_id']}" + (f": {disposition}" if disposition else "")
        return sentence + (f" → {slug}" if slug else "")
    if title == "code-dispatch done":
        disposition = _humanize(_text(meta.get("disposition")))
        items = meta.get("item_ids") if isinstance(meta.get("item_ids"), list) else []
        noun = "queue item" if len(items) == 1 else "queue items"
        sentence = f"Closed code {noun} {', '.join(str(item) for item in items)}".rstrip()
        return _with(sentence + (f": {disposition}" if disposition else ""), result, " — ")
    if title == "code-dispatch requeue-triggers" and _positive_int(meta.get("count")):
        count = meta["count"]
        return f"Requeued {count} code review trigger{'s' if count != 1 else ''}"
    if title == "artifact refresh" and isinstance(meta.get("present"), int) and isinstance(meta.get("missing"), int):
        return f"Refreshed the file index: {meta['present']} present, {meta['missing']} missing"
    if title == "artifact register":
        path = _text(meta.get("relative_path")) or action
        return f"Registered {result + ' ' if result else ''}file {path}".strip()
    return _with(title, action) or "(untitled entry)"


def _event_summary(event_type: str, task_name: str, summary: str) -> str:
    if event_type == "finding.created" and _slug(task_name) and summary == f"Recorded {task_name}":
        return f"Recorded finding {task_name}"
    if event_type == "surface.updated":
        head, separator, target = summary.partition(": ")
        if separator and head.startswith(f"{task_name} "):
            return f"Surface {head.removeprefix(task_name).strip()}: {target} ({_humanize(task_name)})"
    if event_type == "intel.recorded":
        return f"Recorded {_humanize(task_name.replace('-', ' '))} intel: {summary}"
    return summary or event_type


# ``vigil assess intel record`` names the record in its ``intel.recorded``
# event summary by the first identity field the backend returned
# (agent/scripts/assess/commands/record_intel.py); breach records carry none.
_INTEL_EVENT_TYPES: dict[str, tuple[str, str | None]] = {
    "tech-component": ("Tech component", "component"),
    "person": ("Person", "name"),
    "email": ("Email", "address"),
    "domain": ("Domain", "identity"),
    "cve": ("CVE", "cve_id"),
    "dns-record": ("DNS record", "name"),
    "social-profile": ("Social profile", "handle"),
    "breach-record": ("Breach record", None),
    "org-fact": ("Org fact", "fact_key"),
    "note": ("Note", "title"),
}


def _event_entities(event_type: str, task_name: str, summary: str) -> list[dict[str, Any]]:
    if event_type in ("finding.created", "finding.merged") and _slug(task_name):
        return [_entity("finding", task_name)]
    if event_type == "chain.created" and task_name:
        return [_entity("chain", task_name)]
    if event_type == "surface.updated":
        _, separator, target = summary.partition(": ")
        if separator and target:
            return [_entity("surface", target, surface_type=task_name)]
    if event_type == "intel.recorded" and task_name:
        type_label = _INTEL_EVENT_TYPES.get(task_name, (_humanize(task_name.replace("-", " ")).capitalize(), None))[0]
        named = summary if summary and summary != task_name else ""
        return [_entity("intel", f"{task_name}:{named}", _with(type_label, named), intel_type=task_name, title=named)]
    return []


def _audit_item(row: Any) -> dict[str, Any]:
    meta = _metadata(row["metadata_json"])
    title, action, result = row["title"] or "", row["action"] or "", row["result"] or ""
    cursor = FeedCursor(float(row["feed_julian"]), "audit", int(row["id"]))
    return {
        "id": f"audit:{row['id']}",
        "source": "audit",
        "source_id": int(row["id"]),
        "cursor": cursor.encode(),
        "_sort": cursor.sort_key(),
        "occurred_at": iso_utc(row["occurred_at"]),
        "actor": {"name": row["actor_name"] or "", "kind": row["feed_actor_kind"]},
        "category": row["feed_category"],
        "kind": title,
        "summary": _audit_summary(title, action, result, meta, row["actor_kind"] or ""),
        "entities": _audit_entities(title, row["actor_kind"] or "", meta),
        "dispatch": None,
        "_dispatch_candidates": [value for value in (_text(meta.get("agent_id")), row["actor_name"] or "") if value],
        "detail": {
            "actor_kind": row["actor_kind"] or "",
            "actor_name": row["actor_name"] or "",
            "title": title,
            "action": action,
            "result": result,
            "artifact_ref": row["artifact_ref"] or "",
            "body_markdown": row["body_markdown"] or "",
            "metadata": meta,
            "recorded_at": iso_utc(row["created_at"]),
        },
    }


def _event_item(row: Any) -> dict[str, Any]:
    event_type, task_name, summary = row["event_type"] or "", row["task_name"] or "", row["summary"] or ""
    cursor = FeedCursor(float(row["feed_julian"]), "event", int(row["id"]))
    return {
        "id": f"event:{row['id']}",
        "source": "event",
        "source_id": int(row["id"]),
        "cursor": cursor.encode(),
        "_sort": cursor.sort_key(),
        "occurred_at": iso_utc(row["created_at"]),
        "actor": {"name": row["agent_name"] or "", "kind": row["feed_actor_kind"]},
        "category": row["feed_category"],
        "kind": event_type,
        "summary": _event_summary(event_type, task_name, summary),
        "entities": _event_entities(event_type, task_name, summary),
        "dispatch": None,
        "_dispatch_candidates": [row["agent_name"]] if row["agent_name"] else [],
        "detail": {
            "event_type": event_type,
            "phase": row["phase"] or "",
            "task_name": task_name,
            "agent_name": row["agent_name"] or "",
            "summary": summary,
        },
    }


_DISPATCH_SQL = """
    SELECT d.agent_id, d.agent_role,
           (SELECT r.id FROM assessment_runs r
             WHERE r.engagement_id = d.engagement_id AND r.producer_dispatch_id = d.id
             ORDER BY r.created_at DESC, r.id DESC LIMIT 1) AS run_id
    FROM assessment_dispatches d
    WHERE d.engagement_id = ?
      -- A bare role name is an actor label, not one dispatch's identity.
      AND d.agent_id != d.agent_role
"""


def _dispatch_record(row: Any) -> dict[str, Any]:
    return {"agent_id": str(row["agent_id"]), "role": row["agent_role"] or "", "run_id": row["run_id"]}


def _load_dispatches(connection, engagement_id: int, names: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
    """Dispatches by ``agent_id``: the named ones, or every one when ``names`` is None."""
    if names is None:
        rows = connection.execute(_DISPATCH_SQL, (engagement_id,)).fetchall()
        return {str(row["agent_id"]): _dispatch_record(row) for row in rows}
    candidates = sorted(set(names))
    dispatches: dict[str, dict[str, Any]] = {}
    for start in range(0, len(candidates), 500):
        chunk = candidates[start:start + 500]
        rows = connection.execute(
            f"{_DISPATCH_SQL} AND d.agent_id IN ({', '.join('?' for _ in chunk)})",
            (engagement_id, *chunk),
        ).fetchall()
        dispatches.update((str(row["agent_id"]), _dispatch_record(row)) for row in rows)
    return dispatches


def _dispatch_for(candidates: Iterable[str], dispatches: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    return next((dispatches[name] for name in candidates if name in dispatches), None)


def _dispatch_run_entity(dispatch: dict[str, Any] | None, entities: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The run chip a row gains from its dispatch, unless it already names a run."""
    if dispatch is None or not dispatch["run_id"] or any(entity["type"] == "run" for entity in entities):
        return None
    return _entity("run", dispatch["run_id"], f"Run #{dispatch['run_id']}")


def _attach_dispatches(connection, engagement_id: int, items: list[dict[str, Any]]) -> None:
    """Resolve each row's dispatch (by ``agent_id``) and the run it produced."""
    names = {name for item in items for name in item["_dispatch_candidates"]}
    if not names:
        return
    dispatches = _load_dispatches(connection, engagement_id, names)
    for item in items:
        dispatch = _dispatch_for(item["_dispatch_candidates"], dispatches)
        if dispatch is None:
            continue
        item["dispatch"] = dispatch
        run = _dispatch_run_entity(dispatch, item["entities"])
        if run is not None:
            item["entities"].append(run)


# ── Entity refs ─────────────────────────────────────────────────────────
#
# ``ref`` holds the record keys the workspace deep-links by; resolution runs
# once per page with one query per entity type.

# An event is written right after the record it announces; the tolerance only
# absorbs the gap between the two writes.
_RECORD_BEFORE_EVENT_DAYS = 1 / (24 * 60)

_CODE_FILE_GONE = "This code file is no longer in the repository inventory."
_UNVIEWABLE_FILE = "Only engagement root documents open in Files; this registered file has no viewer."


def _link(entity: dict[str, Any], ref: dict[str, Any] | None, reason: str = "") -> None:
    entity["ref"] = ref
    entity["unlinked_reason"] = "" if ref is not None else reason


def _intel_record_id(candidates: list[tuple[int, float | None]], at: float) -> int:
    """The row the event announced: the newest one written by then."""
    written = [row_id for row_id, julian in candidates if julian is not None and julian <= at + _RECORD_BEFORE_EVENT_DAYS]
    return max(written) if written else max(row_id for row_id, _ in candidates)


def _chain_root_slugs(connection, chain_ids: list[int]) -> dict[int, str]:
    """Each chain's first linked finding: the record that shows the chain."""
    if not chain_ids:
        return {}
    links = connection.execute(
        f"""
        SELECT links.chain_id, links.entity_ref, findings.slug
        FROM assessment_attack_chain_links AS links
        LEFT JOIN assessment_findings AS findings
          ON findings.id = links.entity_id AND findings.engagement_id = links.engagement_id
        WHERE links.chain_id IN ({', '.join('?' for _ in chain_ids)}) AND links.entity_kind = 'finding'
        ORDER BY links.id
        """,
        chain_ids,
    ).fetchall()
    roots: dict[int, str] = {}
    for row in links:
        slug = _slug(row["entity_ref"]) or _slug(row["slug"])
        if slug:
            roots.setdefault(int(row["chain_id"]), slug)
    return roots


def _resolve_entity_refs(connection, engagement_id: int, items: list[dict[str, Any]]) -> None:
    by_type: dict[str, list[tuple[dict[str, Any], float]]] = {}
    for item in items:
        for entity in item["entities"]:
            by_type.setdefault(entity["type"], []).append((entity, item["_sort"][0]))

    for entity, _ in by_type.pop("finding", []):
        _link(entity, {"finding_slug": entity["key"]})
    for entity, _ in by_type.pop("run", []):
        _link(entity, {"run_id": int(entity["key"])})
    for entity, _ in by_type.pop("http_variant", []):
        _link(entity, {"request_variant_id": int(entity["key"])})
    for entity, _ in by_type.pop("file", []):
        if entity["key"] in ARTIFACT_SPECS:
            _link(entity, {"file_name": entity["key"]})
        else:
            _link(entity, None, _UNVIEWABLE_FILE)

    surfaces = by_type.pop("surface", [])
    if surfaces:
        targets = sorted({entity["key"] for entity, _ in surfaces})
        known: dict[tuple[str, str], int] = {}
        for start in range(0, len(targets), 500):
            chunk = targets[start:start + 500]
            for row in connection.execute(
                f"""
                SELECT id, surface_type, target_descriptor FROM assessment_surfaces
                WHERE engagement_id = ? AND target_descriptor IN ({', '.join('?' for _ in chunk)})
                """,
                (engagement_id, *chunk),
            ).fetchall():
                known[(str(row["surface_type"]), str(row["target_descriptor"]))] = int(row["id"])
        for entity, _ in surfaces:
            surface_id = known.get((entity["_lookup"]["surface_type"], entity["key"]))
            _link(entity, {"surface_id": surface_id} if surface_id else None, "This surface is no longer recorded.")

    intel = by_type.pop("intel", [])
    titles_by_type: dict[str, set[str]] = {}
    for entity, _ in intel:
        lookup = entity["_lookup"]
        if lookup["title"] and _INTEL_EVENT_TYPES.get(lookup["intel_type"], ("", None))[1]:
            titles_by_type.setdefault(lookup["intel_type"], set()).add(lookup["title"])
    intel_rows: dict[tuple[str, str], list[tuple[int, float | None]]] = {}
    for intel_type, titles in titles_by_type.items():
        column = _INTEL_EVENT_TYPES[intel_type][1]
        table = _INTEL_TABLE_BY_TYPE[intel_type]
        ordered = sorted(titles)
        for start in range(0, len(ordered), 500):
            chunk = ordered[start:start + 500]
            for row in connection.execute(
                f"""
                SELECT id, {column} AS title, julianday(created_at) AS julian FROM {table}
                WHERE engagement_id = ? AND {column} IN ({', '.join('?' for _ in chunk)})
                """,
                (engagement_id, *chunk),
            ).fetchall():
                intel_rows.setdefault((intel_type, str(row["title"])), []).append((int(row["id"]), row["julian"]))
    for entity, at in intel:
        lookup = entity["_lookup"]
        type_label = _INTEL_EVENT_TYPES.get(lookup["intel_type"], ("Intel", None))[0]
        candidates = intel_rows.get((lookup["intel_type"], lookup["title"]))
        if candidates:
            _link(entity, {
                "intel_type": lookup["intel_type"].replace("-", "_"),
                "intel_id": _intel_record_id(candidates, at),
            })
        elif lookup["intel_type"] not in titles_by_type:
            _link(entity, None, f"The event does not name which {type_label.lower()} record it recorded.")
        else:
            _link(entity, None, f"No {type_label.lower()} record with this name is recorded.")

    chains = by_type.pop("chain", [])
    if chains:
        stored = connection.execute(
            "SELECT id, chain_key FROM assessment_attack_chains WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchall()
        matches: dict[str, list[tuple[int, str]]] = {}
        for entity, _ in chains:
            key = entity["key"]
            exact = [(int(row["id"]), str(row["chain_key"])) for row in stored if row["chain_key"] == key]
            # The CLI shortens long chain keys to the event's task-name limit.
            matches[key] = exact or [
                (int(row["id"]), str(row["chain_key"])) for row in stored if str(row["chain_key"]).startswith(key)
            ]
        roots = _chain_root_slugs(connection, sorted({chain_id for found in matches.values() for chain_id, _ in found}))
        for entity, _ in chains:
            found = matches[entity["key"]]
            if not found:
                _link(entity, None, "This attack chain is no longer recorded.")
            elif len(found) > 1:
                _link(entity, None, "Several attack chains share this shortened key.")
            elif found[0][0] not in roots:
                _link(entity, None, "This attack chain has no linked finding to open.")
            else:
                _link(entity, {"chain_key": found[0][1], "finding_slug": roots[found[0][0]]})

    code_files = by_type.pop("code_file", [])
    if code_files:
        file_ids = sorted({int(entity["key"]) for entity, _ in code_files})
        queue_ids = sorted({
            entity["_lookup"]["queue_item_id"] for entity, _ in code_files
            if entity["_lookup"]["queue_item_id"] and not entity["_lookup"]["result_id"]
        })
        result_ids = sorted({entity["_lookup"]["result_id"] for entity, _ in code_files if entity["_lookup"]["result_id"]})
        files: dict[int, Any] = {}
        for start in range(0, len(file_ids), 500):
            chunk = file_ids[start:start + 500]
            files.update(
                (int(row["id"]), row)
                for row in connection.execute(
                    f"""
                    SELECT id, repo_id, file_path FROM code_files
                    WHERE engagement_id = ? AND id IN ({', '.join('?' for _ in chunk)})
                    """,
                    (engagement_id, *chunk),
                ).fetchall()
            )
        results: dict[int, list[tuple[int, int, float | None]]] = {}
        existing_results: set[int] = set()
        for column, values in (("queue_item_id", queue_ids), ("id", result_ids)):
            for start in range(0, len(values), 500):
                chunk = values[start:start + 500]
                for row in connection.execute(
                    f"""
                    SELECT id, queue_item_id, file_id, julianday(created_at) AS julian
                    FROM code_analysis_results
                    WHERE engagement_id = ? AND {column} IN ({', '.join('?' for _ in chunk)})
                    """,
                    (engagement_id, *chunk),
                ).fetchall():
                    existing_results.add(int(row["id"]))
                    if column == "queue_item_id":
                        results.setdefault(int(row["queue_item_id"]), []).append(
                            (int(row["id"]), int(row["file_id"]), row["julian"])
                        )
        for entity, at in code_files:
            row = files.get(int(entity["key"]))
            if row is None:
                _link(entity, None, _CODE_FILE_GONE)
                continue
            lookup = entity["_lookup"]
            result_id = lookup["result_id"] if lookup["result_id"] in existing_results else None
            if result_id is None and lookup["queue_item_id"] and not lookup["result_id"]:
                # Rows written before the audit named its receipt: the newest
                # receipt for the file in that attempt by the time of the row.
                written = [
                    rid for rid, file_id, julian in results.get(lookup["queue_item_id"], [])
                    if file_id == int(entity["key"]) and julian is not None
                    and julian <= at + _RECORD_BEFORE_EVENT_DAYS
                ]
                result_id = max(written) if written else None
            _link(entity, {
                "code_file_id": int(row["id"]),
                "repo_id": int(row["repo_id"]),
                "file_path": str(row["file_path"]),
                "result_id": result_id,
            })

    probes = by_type.pop("oob_probe", [])
    if probes:
        nonces = sorted({entity["key"] for entity, _ in probes})
        probe_ids: dict[str, int] = {}
        for start in range(0, len(nonces), 500):
            chunk = nonces[start:start + 500]
            probe_ids.update(
                (str(row["nonce"]), int(row["id"]))
                for row in connection.execute(
                    f"""
                    SELECT id, nonce FROM assessment_oob_probes
                    WHERE engagement_id = ? AND nonce IN ({', '.join('?' for _ in chunk)})
                    """,
                    (engagement_id, *chunk),
                ).fetchall()
            )
        for entity, _ in probes:
            probe_id = probe_ids.get(entity["key"])
            _link(entity, {"probe_id": probe_id} if probe_id else None, "This OAST probe is no longer recorded.")

    for entities in by_type.values():
        for entity, _ in entities:
            _link(entity, None, "This record type has no view in the workspace.")


# ── Search ──────────────────────────────────────────────────────────────
#
# Audit rows and events are append-only, so each engagement's projected search
# texts are cached per database, source, and engagement and extended with rows
# newer than the cached maximum id; a row count or newest-row stamp that
# disagrees with the cache rebuilds it. The run
# chip a row gains from its dispatch can appear later, so it is resolved per
# search rather than cached.

_SEARCH_CACHE_ENGAGEMENTS = 4


@dataclass(slots=True)
class _SearchTexts:
    count: int
    max_id: int
    max_stamp: str
    # row id -> (lowercased search text, dispatch candidates, names a run itself)
    rows: dict[int, tuple[str, tuple[str, ...], bool]]


_search_cache: OrderedDict[tuple[str, str, int], _SearchTexts] = OrderedDict()
_search_cache_lock = threading.Lock()


def _audit_search_row(row: Any) -> tuple[str, tuple[str, ...], bool]:
    """Everything the operator can read for an audit row, lowercased."""
    meta = _metadata(row["metadata_json"])
    title, action, result = row["title"] or "", row["action"] or "", row["result"] or ""
    entities = _audit_entities(title, row["actor_kind"] or "", meta)
    text = "\n".join((
        _audit_summary(title, action, result, meta, row["actor_kind"] or ""),
        row["actor_name"] or "", title, action, result, row["artifact_ref"] or "",
        row["body_markdown"] or "", row["metadata_json"] or "",
        *(entity["label"] for entity in entities),
    )).lower()
    candidates = tuple(value for value in (_text(meta.get("agent_id")), row["actor_name"] or "") if value)
    return text, candidates, any(entity["type"] == "run" for entity in entities)


def _event_search_row(row: Any) -> tuple[str, tuple[str, ...], bool]:
    event_type, task_name, summary = row["event_type"] or "", row["task_name"] or "", row["summary"] or ""
    entities = _event_entities(event_type, task_name, summary)
    text = "\n".join((
        _event_summary(event_type, task_name, summary),
        row["agent_name"] or "", event_type, task_name, summary,
        *(entity["label"] for entity in entities),
    )).lower()
    return text, ((row["agent_name"],) if row["agent_name"] else ()), False


_SEARCH_SOURCES: dict[str, tuple[str, str, Callable[[Any], tuple[str, tuple[str, ...], bool]]]] = {
    "audit": (
        "activity_entries",
        "title, action, result, actor_kind, actor_name, artifact_ref, body_markdown, metadata_json",
        _audit_search_row,
    ),
    "event": ("events", "event_type, task_name, agent_name, summary", _event_search_row),
}


def _search_texts(connection, source: str, engagement_id: int) -> _SearchTexts:
    table, columns, project = _SEARCH_SOURCES[source]
    scope = "engagement_id = ?" + (" AND event_type != 'activity.recorded'" if source == "event" else "")
    count, max_id = connection.execute(
        f"SELECT COUNT(*), COALESCE(MAX(id), 0) FROM {table} WHERE {scope}", (engagement_id,)
    ).fetchone()
    stamp_row = connection.execute(f"SELECT created_at FROM {table} WHERE id = ?", (max_id,)).fetchone()
    max_stamp = str(stamp_row[0]) if stamp_row else ""
    key = (str(database_path()), source, engagement_id)
    with _search_cache_lock:
        cached = _search_cache.get(key)
        if cached is not None:
            _search_cache.move_to_end(key)
            if (cached.count, cached.max_id, cached.max_stamp) == (count, max_id, max_stamp):
                return cached
            if cached.max_id >= max_id:
                cached = None
    newer_than = cached.max_id if cached is not None else 0
    fetched = {
        int(row["id"]): project(row)
        for row in connection.execute(
            f"SELECT id, {columns} FROM {table} WHERE {scope} AND id > ?", (engagement_id, newer_than)
        ).fetchall()
    }
    if cached is not None and cached.count + len(fetched) == count:
        texts = _SearchTexts(count, max_id, max_stamp, {**cached.rows, **fetched})
    elif cached is not None:
        with _search_cache_lock:
            _search_cache.pop(key, None)
        return _search_texts(connection, source, engagement_id)
    else:
        texts = _SearchTexts(count, max_id, max_stamp, fetched)
    with _search_cache_lock:
        _search_cache[key] = texts
        _search_cache.move_to_end(key)
        while len(_search_cache) > 2 * _SEARCH_CACHE_ENGAGEMENTS:
            _search_cache.popitem(last=False)
    return texts


def _matching_ids(texts: _SearchTexts, tokens: tuple[str, ...], dispatches: dict[str, dict[str, Any]]) -> list[int]:
    matched: list[int] = []
    for row_id, (text, candidates, names_run) in texts.rows.items():
        if not all(token in text for token in tokens):
            dispatch = None if names_run else _dispatch_for(candidates, dispatches)
            if dispatch is None or not dispatch["run_id"]:
                continue
            with_run = f"{text}\nrun #{dispatch['run_id']}"
            if not all(token in with_run for token in tokens):
                continue
        matched.append(row_id)
    return matched


def _search_matches(connection, engagement_id: int, filters: _Filters) -> _Filters:
    """Resolve the search to the matching row ids of each source.

    A row matches when every query word occurs in its search text, or (audit
    rows) when the FTS index matches the stored fields word-wise. The other
    filters, categories, and cursors apply to these ids in SQL.
    """
    if not filters.text_tokens:
        return filters
    dispatches = _load_dispatches(connection, engagement_id)
    audit_ids = _matching_ids(_search_texts(connection, "audit", engagement_id), filters.text_tokens, dispatches)
    if filters.fts_term:
        matched = set(audit_ids)
        audit_ids += [
            int(row[0])
            for row in connection.execute(
                """
                SELECT a.id FROM activity_entries a
                WHERE a.engagement_id = ?
                  AND a.id IN (SELECT rowid FROM activity_entries_fts WHERE activity_entries_fts MATCH ?)
                """,
                (engagement_id, filters.fts_term),
            ).fetchall()
            if int(row[0]) not in matched
        ]
    event_ids = _matching_ids(_search_texts(connection, "event", engagement_id), filters.text_tokens, dispatches)
    return replace(filters, audit_ids=json.dumps(audit_ids), event_ids=json.dumps(event_ids))


_SOURCES = (
    _Source("audit", "activity_entries a", "a.occurred_at", "a.id", _audit_category_sql, _audit_actor_kind_sql, _audit_where, _audit_item),
    _Source("event", "events e", "e.created_at", "e.id", _event_category_sql, _event_actor_kind_sql, _event_where, _event_item),
)


# ── Public API ──────────────────────────────────────────────────────────


def list_activity_feed(
    engagement_id: int,
    *,
    categories: Iterable[str] | None = None,
    actor: str = "",
    q: str = "",
    since: str | None = None,
    until: str | None = None,
    before: str | None = None,
    after: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """One page of the merged feed, newest first.

    ``before`` pages toward older rows. ``after`` returns the *oldest*
    ``limit`` rows newer than the cursor (still listed newest first) so a
    client catching up walks forward without gaps; ``has_more`` then means
    more newer rows remain. ``categories`` defaults to every category except
    tool calls; ``categories`` counts ignore the category selection.
    """
    engagement = _engagement_or_404(engagement_id)
    selected = frozenset(categories) if categories else CATEGORY_KEYS - DEFAULT_HIDDEN_CATEGORIES
    unknown = selected - CATEGORY_KEYS
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"unknown activity categories: {', '.join(sorted(unknown))}",
        )
    if actor and actor not in ("operator", "agent", "system"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="actor must be operator, agent, or system",
        )
    if before and after:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="pass before or after, not both",
        )
    query = q.strip()
    filters = _Filters(
        actor=actor,
        since=_normalize_timestamp(since, field_name="since") if since else None,
        until=_normalize_timestamp(until, field_name="until") if until else None,
        fts_term=fts_escape(query) if query else "",
        text_tokens=tuple(token.lower() for token in query.split()),
    )
    older = after is None
    cursor = (
        FeedCursor.decode(before, field_name="before") if before
        else FeedCursor.decode(after, field_name="after") if after
        else None
    )
    with get_connection() as connection:
        filters = _search_matches(connection, engagement.id, filters)
        rows = [
            row
            for source in _SOURCES
            for dated in (True, False)
            for row in _fetch(
                connection, source, engagement.id, filters, selected, cursor,
                older=older, limit=limit + 1, dated=dated,
            )
        ]
        rows.sort(key=lambda item: item["_sort"], reverse=older)
        page, has_more = rows[:limit], len(rows) > limit
        if not older:
            page.reverse()
        _attach_dispatches(connection, engagement.id, page)
        _resolve_entity_refs(connection, engagement.id, page)
        counts = _category_counts(connection, engagement.id, filters)
    for item in page:
        item.pop("_sort")
        item.pop("_dispatch_candidates")
        for entity in item["entities"]:
            entity.pop("_lookup")
    return {
        "items": page,
        "has_more": has_more,
        "total": sum(counts[key] for key in selected),
        "categories": [
            {
                "key": key,
                "label": label,
                "count": counts[key],
                "default": key not in DEFAULT_HIDDEN_CATEGORIES,
            }
            for key, label in CATEGORIES
        ],
    }
