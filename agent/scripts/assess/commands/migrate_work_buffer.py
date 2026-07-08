"""vigil assess migrate-work-buffer — one-time fold of legacy cases.db
work_items into the backend ``assessment_work_items`` ledger (ADR 0013).

Each engagement historically kept its transient triage/dispatch queue in a
per-engagement SQLite ``cases.db`` ``work_items`` table. The backend now owns
that buffer over HTTP. This one-time migration reads the legacy table
READ-ONLY — it is the single deliberate remaining reader of ``cases.db`` — and
replays every row through the idempotent ``work-items/bulk`` UPSERT so
in-flight data is preserved rather than discarded. On a verified row-count
match it archives the legacy file by *renaming* (never deleting) it to
``cases.db.migrated``.

Source-only utility: it writes to whatever backend ``load_config`` resolves
and never deploys anything. Re-running is a no-op (the backend UPSERTs on
``(engagement_id, queue_key)`` and archived files drop out of the glob).
"""
from __future__ import annotations

import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


# Columns copied straight through from a legacy work_items row to a
# work-items/bulk item. Legacy DBs vary in which columns exist (ALTER-added
# over time), so every read goes through :func:`_col`; a missing/NULL value is
# simply omitted so the backend's own field default applies.
_PASSTHROUGH_COLUMNS: tuple[str, ...] = (
    "queue_key",
    "request_variant_id",
    "service_id",
    "coverage_item_id",
    "auth_context",
    "method",
    "url",
    "url_path",
    "query_params",
    "body_params",
    "path_params",
    "cookie_params",
    "headers",
    "body",
    "content_type",
    "content_length",
    "request_body_truncated",
    "response_status",
    "response_headers",
    "response_size",
    "response_snippet",
    "response_truncated",
    "type",
    "source",
    "status",
    "params_key_sig",
    "priority_score",
    "priority_reason",
    "cluster_key",
    "terminal_reason",
    "classifier_version",
    "signals",
    "selected_by",
    "triage_rationale",
    "live_status",
)

# Chunk size for the bulk POST. The backend UPSERTs on (engagement_id,
# queue_key) so any chunking is idempotent; 500 keeps each request small.
_CHUNK_SIZE = 500


@dataclass
class _Result:
    """Per-engagement migration outcome; drives the final totals summary."""

    outcome: str  # migrated | dry-run | skipped | mismatch
    source_count: int = 0
    migrated: int = 0
    archived: bool = False


def _col(row: sqlite3.Row, name: str, default=None):
    """Return ``row[name]`` when the column is present, else ``default``.

    Legacy cases.db files differ in which columns exist (they were ALTER-added
    over successive migrations), so every column read is tolerant rather than
    assuming a fixed schema.
    """
    return row[name] if name in row.keys() else default


def _derive_host(url: str) -> str:
    """Registrable host for a URL, normalised the way the backend stores it."""
    return (urlparse(url).hostname or "").rstrip(".").lower()


def _build_item(row: sqlite3.Row) -> dict | None:
    """Build a work-items/bulk item dict from one legacy work_items row.

    Returns ``None`` for rows with no ``url`` or no ``queue_key`` — they are
    unkeyable and the backend upsert would reject them anyway. NULL/absent
    columns are omitted so the backend's field default applies instead of a
    rejected ``None`` (several bulk fields are non-optional strings/ints).
    """
    url = _col(row, "url")
    queue_key = _col(row, "queue_key")
    if not url or not queue_key:
        return None

    item: dict = {}
    for name in _PASSTHROUGH_COLUMNS:
        value = _col(row, name)
        if value is not None:
            item[name] = value

    # Derive host when the legacy row predates the host column; a stored host
    # is preserved as-is.
    stored_host = _col(row, "host")
    item["host"] = stored_host if stored_host else _derive_host(str(url))
    return item


def _read_source_rows(db_path: Path) -> list[sqlite3.Row] | None:
    """Return every ``work_items`` row, or ``None`` when the table is absent.

    Opens the legacy DB READ-ONLY via a ``file:...?mode=ro`` URI — this tool is
    the one deliberate remaining reader of ``cases.db``, so it never imports the
    (being-deleted) ``assess.lib.db`` and never mutates the source.
    """
    conn = sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        has_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='work_items'"
        ).fetchone()
        if has_table is None:
            return None
        # Do NOT touch the dead legacy `cases` table — only work_items folds in.
        return conn.execute("SELECT * FROM work_items").fetchall()
    finally:
        conn.close()


def _backend_count(client: AssessmentClient) -> int:
    """Total assessment_work_items rows the backend holds for this engagement."""
    stats = client.get("work-items/stats?by=status")
    if isinstance(stats, dict) and isinstance(stats.get("status"), list):
        return sum(int(row.get("count", 0)) for row in stats["status"])
    # Fallback: enumerate every page when the stats shape is unexpected.
    return len(client.get_all_pages("work-items"))


def _archive_source(db_path: Path) -> list[str]:
    """Rename cases.db and its -wal/-shm sidecars to ``*.migrated``.

    NEVER deletes — only renames — and is called ONLY after a verified count
    match. Returns the archived filenames for the per-engagement report.
    """
    renamed: list[str] = []
    for suffix in ("", "-wal", "-shm"):
        src = db_path.with_name(db_path.name + suffix)
        if src.exists():
            dst = src.with_name(src.name + ".migrated")
            src.rename(dst)
            renamed.append(dst.name)
    return renamed


def _migrate_one(db_path: Path, *, dry_run: bool, keep_source: bool) -> _Result:
    """Migrate one engagement's legacy work_items and report the outcome."""
    eng_key = db_path.parent.name
    rows = _read_source_rows(db_path)
    if rows is None:
        print(f"[migrate] {eng_key}: no work_items table — skipping")
        return _Result("skipped")

    source_count = len(rows)
    items = [item for item in (_build_item(row) for row in rows) if item is not None]
    unkeyable = source_count - len(items)

    if dry_run:
        extra = f" ({unkeyable} unkeyable row(s) would be skipped)" if unkeyable else ""
        print(
            f"[migrate] {eng_key}: DRY-RUN — would migrate {len(items)} of "
            f"{source_count} work_items row(s){extra}; no POST, no archive"
        )
        return _Result("dry-run", source_count=source_count)

    cfg = load_config(str(db_path.parent))
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    migrated = 0
    try:
        for start in range(0, len(items), _CHUNK_SIZE):
            chunk = items[start:start + _CHUNK_SIZE]
            if not chunk:
                continue
            response = client.post("work-items/bulk", {"items": chunk})
            if isinstance(response, dict):
                migrated += int(response.get("count", 0))
        backend_count = _backend_count(client)
    finally:
        client.close()

    # VERIFY — the source work_items count must match what the backend now
    # holds. queue_key is UNIQUE in the legacy table, so an exact match means
    # every source row landed. On any mismatch we keep the source untouched.
    if backend_count != source_count:
        print(
            f"WARN [migrate] {eng_key}: COUNT MISMATCH — source work_items="
            f"{source_count} but backend holds {backend_count} row(s) after "
            f"migrating {migrated}. KEEPING the source cases.db (NOT archived); "
            f"review before re-running.",
            file=sys.stderr,
        )
        return _Result("mismatch", source_count=source_count, migrated=migrated)

    if keep_source:
        print(
            f"[migrate] {eng_key}: migrated {migrated} row(s); backend count "
            f"matches ({backend_count}); --keep-source set, leaving cases.db in place"
        )
        return _Result("migrated", source_count=source_count, migrated=migrated)

    renamed = _archive_source(db_path)
    print(
        f"[migrate] {eng_key}: migrated {migrated} row(s); backend count matches "
        f"({backend_count}); archived source -> {', '.join(renamed)}"
    )
    return _Result("migrated", source_count=source_count, migrated=migrated, archived=True)


def _resolve_db_paths(args) -> list[Path]:
    """Return the ordered list of ``cases.db`` paths to process."""
    if getattr(args, "all", False):
        if getattr(args, "engagements_root", None):
            root = Path(args.engagements_root).expanduser()
        else:
            cfg = load_config(args.engagement_dir)
            root = Path(cfg.engagement_dir).parent
        db_paths = sorted(root.glob("*/cases.db"))
        if not db_paths:
            print(f"[migrate] No */cases.db found under {root}; nothing to migrate")
        return db_paths

    cfg = load_config(args.engagement_dir)
    db_path = Path(cfg.engagement_dir) / "cases.db"
    if not db_path.exists():
        print(f"[migrate] No cases.db in {cfg.engagement_dir}; nothing to migrate")
        return []
    return [db_path]


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "migrate-work-buffer",
        help="One-time: fold legacy cases.db work_items into the backend work buffer",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Migrate every engagement under the engagements root (default: the "
        "currently-resolved engagement only).",
    )
    p.add_argument(
        "--engagements-root",
        dest="engagements_root",
        default=None,
        help="Root scanned for <root>/*/cases.db when --all is set "
        "(default: the parent of the resolved engagement dir).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Read and count the legacy work_items only; do not POST or archive.",
    )
    p.add_argument(
        "--keep-source",
        action="store_true",
        dest="keep_source",
        help="After a verified migration, leave cases.db in place instead of "
        "renaming it to cases.db.migrated.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    dry_run = bool(getattr(args, "dry_run", False))
    keep_source = bool(getattr(args, "keep_source", False))

    db_paths = _resolve_db_paths(args)
    if not db_paths:
        return

    processed = 0
    rows_migrated = 0
    archived = 0
    skipped = 0
    mismatches = 0
    errors = 0

    for db_path in db_paths:
        processed += 1
        try:
            result = _migrate_one(db_path, dry_run=dry_run, keep_source=keep_source)
        except (Exception, SystemExit) as exc:  # noqa: BLE001 — one bad DB must not abort --all
            errors += 1
            print(
                f"WARN [migrate] {db_path.parent.name}: migration failed "
                f"({type(exc).__name__}: {exc}); leaving source untouched and continuing",
                file=sys.stderr,
            )
            continue
        rows_migrated += result.migrated
        if result.archived:
            archived += 1
        if result.outcome == "skipped":
            skipped += 1
        elif result.outcome == "mismatch":
            mismatches += 1

    print(
        "[migrate] Done — "
        f"{processed} engagement(s) processed, "
        f"{rows_migrated} row(s) migrated, "
        f"{archived} archived, "
        f"{skipped} skipped (no work_items), "
        f"{mismatches} mismatch(es), "
        f"{errors} error(s)"
    )
