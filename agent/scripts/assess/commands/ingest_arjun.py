"""vigil assess ingest-arjun — fold Arjun discovery output into the work buffer.

Host-side, idempotent enrichment step (the gau->ingest split, plan §9): the
`vigil assess kali arjun` verb produces JSON; THIS command consumes it and
writes the discovered params onto the matching work-buffer rows (or creates
candidate rows), then re-runs the EXISTING `classify_buckets.classify_from_fields`
so the now-parameterized endpoint auto-routes (url=->gf:ssrf, file=->gf:lfi,
id=->gf:idor/sqli) with no new classification logic.

For every enriched/created row this sets:
  - the discovered params into query_params (GET) or body_params (POST/XML/JSON)
  - selected_by = "arjun"  (provenance)
  - signals = the discovered param(s) + an evidence note (header-mode params,
    which Arjun cannot write to a classifier field, are kept as a signal)
  - triage_rationale = a one-line LLM-facing instruction that NAMES sqlmap when
    the row routes to a DB-backed (gf:sqli) surface (sqlmap stays operator-
    invoked, never auto-fired).

Idempotent: re-running merges params (no duplicate keys) and recomputes the
same classification, so a second pass over the same JSON changes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.arjun_enrich import (
    build_signals,
    build_triage_rationale,
    merge_params_into_field,
    parse_arjun_json,
    slot_for_method,
)
from assess.lib.auth import auth_active_context
from assess.lib.classify_buckets import classify_from_fields
from assess.lib.config import load_config
from assess.lib.db import db_init, db_insert_work_item
from assess.lib.params import extract_url_path, generate_params_sig


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "ingest-arjun",
        help="Fold Arjun hidden-parameter discovery JSON into the work buffer (idempotent).",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("json_file", help="Arjun -oJ JSON output file")
    p.add_argument(
        "--source",
        dest="source",
        default="arjun",
        help="`source` value recorded on rows CREATED by this ingest (default: arjun).",
    )
    p.add_argument(
        "--default-method",
        dest="default_method",
        default="GET",
        help="Method to assume for records whose JSON omits one (default: GET; pass the verb's -m).",
    )
    p.set_defaults(func=run)


def _match_existing_row(conn, *, method: str, url_path: str, url: str) -> dict | None:
    """Find the work-buffer row this endpoint enriches.

    Match precedence (most to least specific):
      1. exact method + url_path
      2. url_path alone (any method) — a discovered param attaches to the route
      3. exact url

    The path-template match (1/2) is what makes thousands of id-varied URLs
    collapse onto one route, mirroring arjun_select's dedup. Returns the row as
    a dict, or None when no row matches (caller then creates a candidate).
    """
    row = conn.execute(
        "SELECT * FROM work_items WHERE method = ? AND url_path = ? ORDER BY id LIMIT 1",
        (method, url_path),
    ).fetchone()
    if row is None:
        row = conn.execute(
            "SELECT * FROM work_items WHERE url_path = ? ORDER BY id LIMIT 1",
            (url_path,),
        ).fetchone()
    if row is None:
        row = conn.execute(
            "SELECT * FROM work_items WHERE url = ? ORDER BY id LIMIT 1",
            (url,),
        ).fetchone()
    return dict(row) if row is not None else None


def _enrich_existing(conn, row: dict, record: dict) -> dict:
    """Update an existing row in place with the discovered params + re-classify.

    Returns a small summary dict for the run report.
    """
    method = record["method"]
    params = record["params"]
    header_params = record.get("header_params") or []
    slot = slot_for_method(method)

    existing_query = row.get("query_params")
    existing_body = row.get("body_params")
    if slot == "query_params":
        new_query = merge_params_into_field(existing_query, params)
        new_body = existing_body if existing_body is not None else "{}"
    else:
        new_query = existing_query if existing_query is not None else "{}"
        new_body = merge_params_into_field(existing_body, params)

    case_type = row.get("type") or "unknown"
    assignment = classify_from_fields(
        case_type=case_type,
        url_path=row.get("url_path") or "",
        query_params=new_query,
        body_params=new_body,
        path_params=row.get("path_params") or "{}",
    )

    signals = build_signals(params, header_params=header_params)
    rationale = build_triage_rationale(
        method=method,
        params=params,
        url_path=row.get("url_path") or "",
        header_params=header_params,
    )
    params_sig = generate_params_sig(new_query, new_body)

    conn.execute(
        """
        UPDATE work_items
        SET query_params = ?,
            body_params = ?,
            params_key_sig = ?,
            priority_score = ?,
            priority_reason = ?,
            cluster_key = ?,
            terminal_reason = COALESCE(?, terminal_reason),
            signals = ?,
            selected_by = 'arjun',
            triage_rationale = ?,
            status = CASE WHEN status = 'skipped' THEN status ELSE 'pending' END
        WHERE id = ?
        """,
        (
            new_query,
            new_body,
            params_sig,
            assignment["priority_score"],
            assignment["priority_reason"],
            assignment["cluster_key"],
            assignment["terminal_reason"],
            json.dumps(signals, sort_keys=True),
            rationale,
            row["id"],
        ),
    )
    return {
        "endpoint": record["endpoint"],
        "action": "enriched",
        "row_id": int(row["id"]),
        "slot": slot,
        "params": params,
        "cluster_key": assignment["cluster_key"],
        "priority_score": assignment["priority_score"],
    }


def _create_candidate(db_path: str, *, conn, record: dict, source: str, auth_context: str) -> dict:
    """Create a new candidate row for an Arjun endpoint not yet in the buffer.

    Routes through the same db_insert_work_item seam ingest-candidates uses, so
    classification + dedup + the curated-metadata path stay identical. Reuses
    the OPEN connection so the whole ingest is one transaction.
    """
    method = record["method"]
    params = record["params"]
    header_params = record.get("header_params") or []
    endpoint = record["endpoint"]
    url_path = extract_url_path(endpoint)
    slot = slot_for_method(method)

    query_params = merge_params_into_field(None, params) if slot == "query_params" else "{}"
    body_params = merge_params_into_field(None, params) if slot == "body_params" else "{}"
    params_sig = generate_params_sig(query_params, body_params)

    signals = build_signals(params, header_params=header_params)
    rationale = build_triage_rationale(
        method=method,
        params=params,
        url_path=url_path,
        header_params=header_params,
    )
    queue_key = f"arjun:{method}:{url_path}:{params_sig}"

    db_insert_work_item(
        db_path,
        queue_key=queue_key,
        method=method,
        url=endpoint,
        url_path=url_path,
        query_params=query_params,
        body_params=body_params,
        case_type="unknown",
        source=source,
        params_key_sig=params_sig,
        auth_context=auth_context,
        signals=json.dumps(signals, sort_keys=True),
        selected_by="arjun",
        triage_rationale=rationale,
        curated=True,
        connection=conn,
    )
    return {
        "endpoint": endpoint,
        "action": "created",
        "slot": slot,
        "params": params,
    }


def run(args: argparse.Namespace) -> None:
    db_path = args.db_path
    json_file = args.json_file

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    if not Path(json_file).is_file():
        print(f"ERROR: arjun JSON file not found: {json_file}", file=sys.stderr)
        sys.exit(1)

    db_init(db_path)

    cfg = load_config(args.engagement_dir)
    auth_context = auth_active_context(cfg.engagement_dir)

    text = Path(json_file).read_text(encoding="utf-8")
    records = parse_arjun_json(text, default_method=args.default_method)

    results: list[dict] = []
    enriched = 0
    created = 0
    skipped_empty = 0

    from assess.lib.db import db_connect

    # One shared connection for the whole ingest. The enrich-in-place UPDATEs
    # are committed explicitly here; db_insert_work_item (candidate path) manages
    # its own commit on this same connection. There is no cross-record rollback
    # because each write is independently idempotent (merge params + recompute
    # the same classification), so a partial run is safe to re-run.
    with db_connect(db_path) as conn:
        for record in records:
            if not record["params"] and not record.get("header_params"):
                skipped_empty += 1
                continue
            endpoint = record["endpoint"]
            if not endpoint.startswith(("http://", "https://")):
                # Arjun endpoints are absolute; a relative one cannot be matched
                # to a buffered URL reliably, so skip loudly.
                print(
                    f"ingest-arjun: skipping non-absolute endpoint '{endpoint}'",
                    file=sys.stderr,
                )
                skipped_empty += 1
                continue
            url_path = extract_url_path(endpoint)
            row = _match_existing_row(
                conn, method=record["method"], url_path=url_path, url=endpoint
            )
            if row is not None:
                results.append(_enrich_existing(conn, row, record))
                conn.commit()
                enriched += 1
            else:
                results.append(
                    _create_candidate(
                        db_path,
                        conn=conn,
                        record=record,
                        source=args.source,
                        auth_context=auth_context,
                    )
                )
                created += 1

    summary = {
        "verb": "ingest-arjun",
        "json_file": json_file,
        "db_path": db_path,
        "records": len(records),
        "enriched": enriched,
        "created": created,
        "skipped_empty": skipped_empty,
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
