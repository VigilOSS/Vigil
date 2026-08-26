"""vigil assess ingest arjun — fold Arjun discovery output into the work buffer.

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
    artifact_is_incomplete,
    build_signals,
    build_triage_rationale,
    merge_params_into_field,
    merge_signal_lists,
    parse_arjun_json,
    slot_for_method,
)
from assess.lib.auth import auth_active_context
from assess.lib.bulk_ingest import DEFAULT_BULK_WRITE_SIZE
from assess.lib.classify_buckets import CLASSIFIER_VERSION, classify_from_fields
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.params import extract_url_path, generate_params_sig


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "arjun",
        help="Fold Arjun hidden-parameter discovery JSON into the work buffer (idempotent).",
    )
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


def _match_existing_row(rows: list[dict], *, method: str, url_path: str, url: str) -> dict | None:
    """Find the work-buffer row this endpoint enriches (Python match over the
    backend-fetched rows).

    Match precedence (most to least specific):
      1. exact method + full URL (host + path) — endpoints that SHARE a path
         across hosts MUST NOT collapse onto one row, so the host-bearing full
         URL is tried first. Method is part of this match because the SAME url
         can exist as both a GET and a POST work item.
      2. method + url_path, constrained to the SAME host.
      3. url_path alone, constrained to the SAME host.

    Host equality on the fallbacks is checked on the parsed hostname (not a
    substring), so an apex endpoint never matches a subdomain / substring host.
    Rows are pre-sorted by id (ascending) so ``ORDER BY id`` ties resolve
    identically to the former SQL. Returns the row dict, or None.
    """
    target_host = _host_of(url)

    for row in rows:
        if row.get("method") == method and row.get("url") == url:
            return row

    for row in rows:
        if row.get("method") == method and row.get("url_path") == url_path \
                and _host_of(row.get("url") or "") == target_host:
            return row

    for row in rows:
        if row.get("url_path") == url_path and _host_of(row.get("url") or "") == target_host:
            return row
    return None


def _enrich_existing(row: dict, record: dict) -> tuple[dict, dict]:
    """Compute the enriched work item for an existing row + re-classify.

    Returns ``(summary, bulk_item)`` — the summary for the run report and the
    ``work-items/bulk`` upsert payload (keyed on the row's ``queue_key``) that
    the backend UPSERTs. The snapshot/identity/FK fields are carried through so
    the UPSERT's always-refresh of those columns preserves them.

    NOTE (behavioral narrowing vs the former local UPDATE): the local path reset
    a non-skipped row to ``status='pending'`` on enrich; the backend UPSERT keeps
    the existing lifecycle status (it only re-admits out-of-scope skips). In
    practice enrichment targets pending rows, so this is a no-op there.
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

    item = {
        "queue_key": row["queue_key"],
        "request_variant_id": row.get("request_variant_id"),
        "service_id": row.get("service_id"),
        "coverage_item_id": row.get("coverage_item_id"),
        "auth_context": row.get("auth_context") or "anonymous",
        "method": row.get("method") or method,
        "url": row.get("url"),
        "url_path": row.get("url_path") or "",
        "host": row.get("host") or "",
        "query_params": new_query,
        "body_params": new_body,
        "path_params": row.get("path_params") or "{}",
        "cookie_params": row.get("cookie_params") or "{}",
        # Carry the ENTIRE existing snapshot forward so the UPSERT's
        # always-refresh of these columns preserves them (omitting any would
        # reset it to the model default on re-ingest — silent data loss).
        "headers": row.get("headers") or "",
        "body": row.get("body"),
        "content_type": row.get("content_type") or "",
        "content_length": row.get("content_length") or 0,
        "request_body_truncated": row.get("request_body_truncated"),
        "response_status": row.get("response_status") or 0,
        "response_headers": row.get("response_headers") or "",
        "response_size": row.get("response_size") or 0,
        "response_snippet": row.get("response_snippet"),
        "response_truncated": row.get("response_truncated"),
        "type": case_type,
        "source": row.get("source") or "",
        "params_key_sig": params_sig,
        "priority_score": final_priority,
        "priority_reason": final_reason,
        "cluster_key": final_cluster,
        "terminal_reason": assignment["terminal_reason"] or row.get("terminal_reason"),
        "classifier_version": row.get("classifier_version") or CLASSIFIER_VERSION,
        "signals": json.dumps(merged_signals, sort_keys=True),
        "selected_by": final_selected_by,
        "triage_rationale": rationale,
    }
    summary = {
        "endpoint": record["endpoint"],
        "action": "enriched",
        "row_id": int(row["id"]),
        "slot": slot,
        "params": params,
        "cluster_key": final_cluster,
        "priority_score": final_priority,
        "malformed_param_field": malformed_field,
    }
    return summary, item


def _create_candidate(record: dict, *, source: str, auth_context: str) -> tuple[dict, dict]:
    """Build a new candidate work item for an Arjun endpoint not yet buffered.

    Classifies client-side (the classifier stays out of the backend) and returns
    ``(summary, bulk_item)`` for the ``work-items/bulk`` UPSERT.
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
    try:
        assignment = classify_from_fields(
            case_type="unknown",
            url_path=url_path,
            query_params=query_params,
            body_params=body_params,
            path_params="{}",
            url=endpoint,
            source=source,
        )
    except Exception:  # noqa: BLE001 — classification must never abort ingest
        assignment = {"priority_score": 0, "priority_reason": None, "cluster_key": None, "terminal_reason": None}

    # Include the full host-bearing URL (not the host-stripped url_path) so the
    # same method/path/params on two in-scope hosts don't collapse to one row.
    queue_key = f"arjun:{method}:{endpoint}:{params_sig}"
    item = {
        "queue_key": queue_key,
        "method": method,
        "url": endpoint,
        "url_path": url_path,
        "host": _host_of(endpoint),
        "query_params": query_params,
        "body_params": body_params,
        "type": "unknown",
        "source": source,
        "status": "pending",
        "params_key_sig": params_sig,
        "auth_context": auth_context,
        "priority_score": assignment["priority_score"],
        "priority_reason": assignment["priority_reason"] or "",
        "cluster_key": assignment["cluster_key"] or "",
        "terminal_reason": assignment["terminal_reason"] or "",
        "classifier_version": CLASSIFIER_VERSION,
        "signals": json.dumps(signals, sort_keys=True),
        "selected_by": "arjun",
        "triage_rationale": rationale,
    }
    summary = {
        "endpoint": endpoint,
        "action": "created",
        "slot": slot,
        "params": params,
    }
    return summary, item


def run(args: argparse.Namespace) -> None:
    # Anchor the Arjun artifact to the engagement dir. A relative `json_file`
    # (e.g. `scans/arjun/foo.json`) resolved against a drifted subagent cwd would
    # miss the real file, and the missing-file branch below reports a CLEAN
    # zero-parameter no-op — silently dropping genuine `kali arjun` discoveries.
    json_file = anchor_engagement_relative(args.json_file, getattr(args, "engagement_dir", None))
    if json_file != args.json_file:
        print(
            f"ingest-arjun: anchored relative json path '{args.json_file}' -> '{json_file}'",
            file=sys.stderr,
        )

    if not Path(json_file).is_file():
        # Arjun writes NO -oJ file when it discovers 0 parameters (the common
        # case, confirmed against v2.2.7), so a missing file means "nothing to
        # ingest" — a clean no-op, not an error.
        print(
            json.dumps(
                {
                    "verb": "ingest-arjun",
                    "json_file": json_file,
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

    cfg = load_config(args.engagement_dir)
    auth_context = auth_active_context(cfg.engagement_dir)

    text = Path(json_file).read_text(encoding="utf-8")
    # Finding 1: an artifact carrying the incomplete-run sentinel came from an
    # arjun run that was killed/timed out before finishing its list — its 0
    # records are NOT a "no hidden params" negative. Surface it loudly and tag the
    # summary so a reader of the ingest output alone cannot misread the empty
    # result as a clean verdict.
    run_incomplete = artifact_is_incomplete(text)
    if run_incomplete:
        print(
            "WARN ingest-arjun: this artifact is from an INCOMPLETE arjun run "
            "(timed out / killed before finishing the target list). 0 records here "
            "is NOT a negative — re-run on a smaller curated live list, sized to "
            "finish, before treating the surface as clean.",
            file=sys.stderr,
        )
    records = parse_arjun_json(text, default_method=args.default_method)

    results: list[dict] = []
    enriched = 0
    created = 0
    skipped_empty = 0

    # Idempotent: matching + UPSERT via work-items/bulk mean a second pass over
    # the same JSON re-derives the same rows and changes nothing. Fetch the
    # buffer once for matching, then bulk-upsert all enriched/created items.
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        existing_rows = client.get_all_pages("work-items")
        # Pre-sort by id so `ORDER BY id` ties resolve identically to the former SQL.
        existing_rows = sorted(existing_rows, key=lambda r: int(r.get("id") or 0))
        pending_items: list[dict] = []

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
                existing_rows, method=record["method"], url_path=url_path, url=endpoint
            )
            if row is not None:
                summary_row, item = _enrich_existing(row, record)
                results.append(summary_row)
                pending_items.append(item)
                enriched += 1
            else:
                summary_row, item = _create_candidate(
                    record, source=args.source, auth_context=auth_context
                )
                results.append(summary_row)
                pending_items.append(item)
                created += 1

        for start in range(0, len(pending_items), DEFAULT_BULK_WRITE_SIZE):
            chunk = pending_items[start:start + DEFAULT_BULK_WRITE_SIZE]
            if chunk:
                client.post("work-items/bulk", {"items": chunk})

    summary = {
        "verb": "ingest-arjun",
        "json_file": json_file,
        "records": len(records),
        "enriched": enriched,
        "created": created,
        "skipped_empty": skipped_empty,
        # True when the source artifact was the incomplete-run sentinel: 0 records
        # here is a truncated run, not a clean "no params" verdict.
        "run_incomplete": run_incomplete,
        # Rows whose target param column was corrupt JSON: preserved (not
        # overwritten) with the discovered params kept in signals. Non-zero here
        # means a column needs manual repair — it is surfaced, never silent.
        "malformed_preserved": sum(
            1 for r in results if r.get("malformed_param_field")
        ),
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
