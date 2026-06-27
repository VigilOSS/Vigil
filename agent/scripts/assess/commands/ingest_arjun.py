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
from urllib.parse import urlparse

from assess.lib.arjun_enrich import (
    build_signals,
    build_triage_rationale,
    merge_params_into_field,
    merge_signal_lists,
    parse_arjun_json,
    slot_for_method,
)
from assess.lib.auth import auth_active_context
from assess.lib.classify_buckets import classify_from_fields
from assess.lib.config import anchor_engagement_relative, load_config
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


def _host_of(url: str) -> str:
    """Lowercased hostname of ``url`` (empty string if unparseable/absent)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _match_existing_row(conn, *, method: str, url_path: str, url: str) -> dict | None:
    """Find the work-buffer row this endpoint enriches.

    Match precedence (most to least specific):
      1. exact method + full URL (host + path) — endpoints that SHARE a path
         across hosts (e.g. `/portal/.../applications` on aps. vs elmo.) MUST NOT
         collapse onto one row, so the host-bearing full URL is tried first.
         Method is part of this match because the SAME url can exist as both a
         GET and a POST work item (no UNIQUE(url) constraint; their queue_keys
         differ by method), and a POST/JSON Arjun run must enrich the POST row's
         body surface — not the lowest-id GET row, whose query surface is wrong.
      2. method + url_path, constrained to the SAME host.
      3. url_path alone, constrained to the SAME host.

    Host equality on the fallbacks is checked in Python on the parsed hostname,
    not via a `LIKE '%host%'` substring (which would let an apex endpoint match a
    subdomain row — `acme-agency.example` vs `app.acme-agency.example` — or a substring host —
    `acme-agency.example` vs `evilacme-agency.example` — i.e. a different origin). `url_path` is selective
    enough that the candidate set per fallback is tiny. Returns the row dict, or
    None (the caller then creates a candidate).
    """
    target_host = _host_of(url)

    exact = conn.execute(
        "SELECT * FROM work_items WHERE method = ? AND url = ? ORDER BY id LIMIT 1",
        (method, url),
    ).fetchone()
    if exact is not None:
        return dict(exact)

    for sql, params in (
        ("SELECT * FROM work_items WHERE method = ? AND url_path = ? ORDER BY id", (method, url_path)),
        ("SELECT * FROM work_items WHERE url_path = ? ORDER BY id", (url_path,)),
    ):
        for row in conn.execute(sql, params).fetchall():
            if _host_of(row["url"]) == target_host:
                return dict(row)
    return None


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
    # Merge the discovered params into the right slot. If that slot's column holds
    # corrupt / non-object JSON, merging would silently overwrite (destroy) it, so
    # `merge_params_into_field` raises instead: we then PRESERVE the column verbatim
    # and still record the discovery in signals/rationale below — the finding is not
    # lost, the corrupt data is not destroyed, and the problem is logged loudly.
    malformed_field = False
    try:
        if slot == "query_params":
            new_query = merge_params_into_field(existing_query, params)
            new_body = existing_body if existing_body is not None else "{}"
        else:
            new_query = existing_query if existing_query is not None else "{}"
            new_body = merge_params_into_field(existing_body, params)
    except ValueError as exc:
        malformed_field = True
        print(
            f"ingest-arjun: row {row['id']} {slot} is malformed ({exc}); preserving it "
            f"unchanged and recording params {params} in signals only.",
            file=sys.stderr,
        )
        new_query = existing_query if existing_query is not None else "{}"
        new_body = existing_body if existing_body is not None else "{}"

    case_type = row.get("type") or "unknown"
    # Route on safe inputs only — a malformed slot is treated as empty for routing,
    # but its corrupt column value is preserved verbatim above (never rewritten).
    classify_query = "{}" if (malformed_field and slot == "query_params") else new_query
    classify_body = "{}" if (malformed_field and slot == "body_params") else new_body
    assignment = classify_from_fields(
        case_type=case_type,
        url_path=row.get("url_path") or "",
        query_params=classify_query,
        body_params=classify_body,
        path_params=row.get("path_params") or "{}",
    )

    new_signals = build_signals(params, header_params=header_params)
    if malformed_field:
        new_signals.append("arjun-param-field-malformed-preserved")
    merged_signals = merge_signal_lists(row.get("signals"), new_signals)
    rationale = build_triage_rationale(
        method=method,
        params=params,
        url_path=row.get("url_path") or "",
        header_params=header_params,
    )
    # On a malformed column we keep the existing signature (recomputing from the
    # corrupt value is meaningless); otherwise recompute from the merged columns.
    params_sig = (
        row.get("params_key_sig") if malformed_field else generate_params_sig(new_query, new_body)
    )

    # Enrichment ADDS a discovered param + signal; it must never DOWNGRADE a row
    # that already scored higher (e.g. a curated high-value cluster). Keep the
    # better classification and adopt the recomputed one only when it ranks at
    # least as high. Preserve a curated `selected_by` — arjun's contribution is
    # recorded in the signals, not by erasing provenance.
    existing_priority = int(row.get("priority_score") or 0)
    new_priority = int(assignment["priority_score"] or 0)
    if new_priority >= existing_priority:
        final_priority = new_priority
        final_cluster = assignment["cluster_key"]
        final_reason = assignment["priority_reason"]
    else:
        final_priority = existing_priority
        final_cluster = row.get("cluster_key")
        final_reason = row.get("priority_reason")
    final_selected_by = row.get("selected_by") or "arjun"

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
            selected_by = ?,
            triage_rationale = ?,
            status = CASE WHEN status = 'skipped' THEN status ELSE 'pending' END
        WHERE id = ?
        """,
        (
            new_query,
            new_body,
            params_sig,
            final_priority,
            final_reason,
            final_cluster,
            assignment["terminal_reason"],
            json.dumps(merged_signals, sort_keys=True),
            final_selected_by,
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
        "cluster_key": final_cluster,
        "priority_score": final_priority,
        "malformed_param_field": malformed_field,
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
    # Include the full host-bearing URL (not the host-stripped url_path) so the
    # same method/path/params on two in-scope hosts don't collapse to one row
    # under the UNIQUE(queue_key) dedup in db_insert_work_item.
    queue_key = f"arjun:{method}:{endpoint}:{params_sig}"

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
    # Anchor a relative cases.db to the engagement dir (not the process cwd) so a
    # subagent whose cwd drifted between bash calls can't mutate an unrelated cwd
    # database — every row write below must target the engagement's DB.
    db_path = anchor_engagement_relative(args.db_path, getattr(args, "engagement_dir", None))
    if db_path != args.db_path:
        print(
            f"ingest-arjun: anchored relative db path '{args.db_path}' -> '{db_path}'",
            file=sys.stderr,
        )
    # Anchor the Arjun artifact the SAME way as the DB. A relative `--json-file`
    # (e.g. `scans/arjun/foo.json`) resolved against a drifted subagent cwd would
    # miss the real file, and the missing-file branch below reports a CLEAN
    # zero-parameter no-op — silently dropping genuine `kali arjun` discoveries.
    # Anchoring to the engagement keeps the no-op meaning "arjun wrote nothing"
    # (its real empty-output behavior) instead of "I looked in the wrong dir".
    json_file = anchor_engagement_relative(args.json_file, getattr(args, "engagement_dir", None))
    if json_file != args.json_file:
        print(
            f"ingest-arjun: anchored relative json path '{args.json_file}' -> '{json_file}'",
            file=sys.stderr,
        )

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    if not Path(json_file).is_file():
        # Arjun writes NO -oJ file when it discovers 0 parameters (the common
        # case, confirmed against v2.2.7), so a missing file means "nothing to
        # ingest" — a clean no-op, not an error.
        print(
            json.dumps(
                {
                    "verb": "ingest-arjun",
                    "json_file": json_file,
                    "db_path": db_path,
                    "records": 0,
                    "enriched": 0,
                    "created": 0,
                    "skipped_empty": 0,
                    "note": (
                        "no arjun JSON at this path; arjun writes none when it "
                        "discovers 0 params, so there is nothing to ingest"
                    ),
                    "results": [],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

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
        # Rows whose target param column was corrupt JSON: preserved (not
        # overwritten) with the discovered params kept in signals. Non-zero here
        # means a column needs manual repair — it is surfaced, never silent.
        "malformed_preserved": sum(
            1 for r in results if r.get("malformed_param_field")
        ),
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
