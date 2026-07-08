"""Work-buffer verb implementations (HTTP client over the backend ledger).

The ``vigil assess work-buffer`` verbs operate on ``assessment_work_items`` in
the orchestrator backend (ADR 0013 — the former per-engagement cases.db queue
folded into the ledger). Each verb is a thin call over ``AssessmentClient`` that
prints byte-identical output to the former local-SQLite implementation, so
operator scripts and dashboards that parse this output are unaffected.

The atomic dispatch claim (``fetch`` / ``fetch-by-priority``), the type→agent
routing, and the per-fetch liveness stamp now run server-side in a single
transaction; the client just renders what the backend returns.
"""
from __future__ import annotations

import json
import sys

from assess.lib.classify_buckets import reason_tag_of

from assess.commands.dispatch._shared import _validate_id_list


# Actions the work-buffer command exposes (kept here so the CLI choices, the
# Unknown-action help text, and the operator docs stay aligned). ``migrate`` is
# gone: the backend owns the schema via init_db(), there is nothing to migrate.
_DB_ACTIONS = (
    "stats",
    "peek",
    "fetch",
    "fetch-by-priority",
    "defer-cluster",
    "defer-items",
    "mark-manual",
    "done",
    "error",
    "reset-stale",
    "retry-errors",
    "requeue",
)


def _stats(client, *, by: str = "status") -> None:
    """Print work-buffer statistics grouped by ``by`` (backend-computed).

    Output is byte-identical to the former local implementation so every
    operator script and dashboard that parses it keeps working.
    """
    data = client.get(f"work-items/stats?by={by}")

    if by == "status":
        print("--- Work Buffer Statistics ---")
        for row in data.get("status_type", []):
            print(f"{row['status']}|{row['type']}|{row['count']}")
        print()
        print("--- Summary ---")
        for row in data.get("status", []):
            print(f"{row['status']}|{row['count']}")
        print()
        print(f"TOTAL|{data.get('total', 0)}")
        return

    rows = data.get("rows", [])

    if by == "source":
        print("--- Work Buffer by Source ---")
        for row in rows:
            label = row["source"] or "(none)"
            print(f"{label}|{row['status']}|{row['count']}")
        return

    if by == "cluster":
        print("--- Work Buffer by Cluster ---")
        for row in rows:
            label = row["cluster_key"] or "(none)"
            print(f"{label}|{row['status']}|{row['count']}|max_priority={row['max_priority'] or 0}")
        return

    if by == "classifier_version":
        print("--- Work Buffer by Classifier Version ---")
        for row in rows:
            print(f"{row['classifier_version']}|{row['status']}|{row['count']}")
        return

    if by == "host":
        print("--- Work Buffer by Host ---")
        for row in rows:
            host = row["host"] or "(none)"
            print(f"{host}|{row['status']}|{row['count']}")
        return

    if by == "reason":
        # terminal_reason is free-text; the machine-readable tag is derived here
        # (classify_buckets.reason_tag_of) so the classifier stays client-side.
        print("--- Work Buffer by Reason Tag (skipped/deferred) ---")
        by_tag: dict[str, int] = {}
        for row in rows:
            tag = reason_tag_of(row["terminal_reason"]) or "none"
            by_tag[tag] = by_tag.get(tag, 0) + int(row["count"])
        for tag in sorted(by_tag):
            print(f"{tag}|{by_tag[tag]}")
        return


def _peek(client, type_val: str, limit: int) -> None:
    """Read-only preview of pending items of the given type (leaves them pending)."""
    rows = client.get(f"work-items?type={type_val}&limit={limit}")
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def _fetch(client, type_val: str, limit: int, agent: str) -> None:
    resp = client.post("work-items/fetch", {"type": type_val, "limit": limit, "agent": agent})
    print(json.dumps(resp.get("claimed", []), indent=2, ensure_ascii=False))


def _fetch_by_priority(client, limit: int, agent: str) -> None:
    """Claim the top-K pending rows by priority (routing + claim server-side)."""
    resp = client.post("work-items/fetch-by-priority", {"limit": limit, "agent": agent})
    if resp.get("error") == "not-routed-agent":
        print(
            "fetch-by-priority: agent is not a routed agent; use 'auto', "
            "'vulnerability-analyst', or 'source-analyzer'",
            file=sys.stderr,
        )
        sys.exit(1)
    claimed = resp.get("claimed", [])
    non_routable = resp.get("non_routable", [])
    if not claimed and non_routable:
        total = sum(int(pair["count"]) for pair in non_routable)
        types_summary = ", ".join(f"{pair['type']}={pair['count']}" for pair in non_routable)
        allowed = ", ".join(resp.get("allowed_types", []))
        print(
            f"WARN fetch-by-priority: queue has {total} pending item(s) "
            f"but all are in non-routable types ({types_summary}); "
            f"routable types are: {allowed}.",
            file=sys.stderr,
        )
    print(json.dumps(claimed, indent=2, ensure_ascii=False))


def _defer_items(client, id_list, reason: str) -> None:
    """Mark specific pending work-item ids skipped with a terminal reason."""
    ids = _validate_id_list(id_list)
    resp = client.post("work-items/defer", {"ids": ids, "reason": reason})
    affected = int(resp.get("affected", 0))
    ids_repr = ",".join(str(i) for i in ids)
    if affected == 0:
        print(
            f"defer-items: no pending items matched the given ids "
            f"(already processed or invalid?): {ids_repr}\n"
            f"  note: items in 'processing'/'done'/'skipped' are not affected; "
            f"run reset-stale before defer if you need to flip in-flight rows.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Deferred {affected} pending item(s): {ids_repr} (reason: {reason})")


def _mark_manual(client, id_list) -> None:
    """Stamp classifier_version='manual' on ids so --reclassify-stale skips them."""
    ids = _validate_id_list(id_list)
    resp = client.post("work-items/mark-manual", {"ids": ids})
    affected = int(resp.get("affected", 0))
    ids_repr = ",".join(str(i) for i in ids)
    if affected == 0:
        print(
            f"mark-manual: no work items matched the given ids "
            f"(invalid or already removed?): {ids_repr}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Marked {affected} item(s) manual (protected from --reclassify-stale): {ids_repr}")


def _defer_cluster(client, cluster_key: str, reason: str) -> None:
    """Mark every pending row in a cluster skipped with a terminal reason."""
    resp = client.post("work-items/defer-cluster", {"cluster_key": cluster_key, "reason": reason})
    affected = int(resp.get("affected", 0))
    print(f"Deferred {affected} pending item(s) in cluster '{cluster_key}' (reason: {reason})")


def _done(client, id_list) -> None:
    ids = _validate_id_list(id_list)
    client.post("work-items/done", {"ids": ids})
    print(f"Marked done: {','.join(str(i) for i in ids)}")


def _error(client, id_list) -> None:
    ids = _validate_id_list(id_list)
    client.post("work-items/error", {"ids": ids})
    print(f"Marked error: {','.join(str(i) for i in ids)}")


def _reset_stale(client, minutes: int) -> None:
    resp = client.post("work-items/reset-stale", {"minutes": minutes})
    print(f"Reset {int(resp.get('affected', 0))} stale work item(s) (stuck > {minutes} min)")


def _retry_errors(client, max_retries: int) -> None:
    resp = client.post("work-items/retry-errors", {"max_retries": max_retries})
    print(f"Retried {int(resp.get('affected', 0))} error work item(s) (max retries: {max_retries})")


def _requeue(client) -> None:
    """Re-admit JSONL work rows (stdin) into the backend work buffer.

    Each row is classified CLIENT-SIDE (the classifier globs the agent skills
    tree, so it stays out of the backend) and POSTed to ``work-items/bulk`` in
    one batch. Mirrors the former local requeue's scoring so re-admitted rows are
    dispatch-ranked identically.
    """
    import json as _json

    from assess.lib.classify_buckets import CLASSIFIER_VERSION, classify_from_fields
    from assess.lib.params import extract_url_path, generate_params_sig

    items: list[dict] = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        row = _json.loads(line)
        method = row.get("method") or "GET"
        url = row.get("url") or ""
        url_path_val = row.get("url_path") or ""
        case_type = row.get("type") or "unknown"
        source = row.get("source") or "requeue"
        auth_context = row.get("auth_context") or "anonymous"

        query_params = row.get("query_params") or {}
        body_params = row.get("body_params") or {}
        path_params = row.get("path_params") or {}
        cookie_params = row.get("cookie_params") or {}
        headers = row.get("headers") or ""
        body = row.get("body") or ""
        content_type = row.get("content_type") or ""
        content_length = int(row.get("content_length") or 0)
        response_status = int(row.get("response_status") or 0)
        response_headers = row.get("response_headers") or ""
        response_size = int(row.get("response_size") or 0)
        response_snippet = row.get("response_snippet") or ""
        params_key_sig = row.get("params_key_sig") or ""

        request_variant_id = row.get("request_variant_id")
        service_id = row.get("service_id")
        coverage_item_id = row.get("coverage_item_id")
        queue_key = row.get("queue_key") or ""

        if method == "null":
            method = "GET"
        if url == "null":
            url = ""
        if case_type == "null":
            case_type = "unknown"

        if not url_path_val:
            url_path_val = extract_url_path(url)

        def _to_text(value):
            return _json.dumps(value) if isinstance(value, (dict, list)) else str(value)

        qp_str = _to_text(query_params)
        bp_str = _to_text(body_params)
        pp_str = _to_text(path_params)
        cp_str = _to_text(cookie_params)
        rh_str = _to_text(response_headers)
        h_str = _to_text(headers)

        if not params_key_sig:
            params_key_sig = generate_params_sig(qp_str, bp_str)

        if not queue_key:
            if request_variant_id and str(request_variant_id).isdigit():
                queue_key = f"variant:{request_variant_id}:{case_type}"
            elif service_id and str(service_id).isdigit():
                queue_key = f"service:{service_id}:{case_type}"
            elif coverage_item_id and str(coverage_item_id).isdigit():
                queue_key = f"coverage:{coverage_item_id}:{case_type}"
            else:
                print("ERROR: requeue line missing variant/service/coverage ID for queue_key", file=sys.stderr)
                sys.exit(1)

        if not url or not url_path_val:
            print("ERROR: requeue line missing usable url/url_path", file=sys.stderr)
            sys.exit(1)

        assignment = classify_from_fields(
            case_type=case_type,
            url_path=url_path_val,
            query_params=qp_str,
            body_params=bp_str,
            path_params=pp_str,
            url=url,
            source=source,
        )
        items.append({
            "queue_key": queue_key,
            "request_variant_id": int(request_variant_id) if request_variant_id and str(request_variant_id).isdigit() else None,
            "service_id": int(service_id) if service_id and str(service_id).isdigit() else None,
            "coverage_item_id": int(coverage_item_id) if coverage_item_id and str(coverage_item_id).isdigit() else None,
            "auth_context": auth_context,
            "method": method,
            "url": url,
            "url_path": url_path_val,
            "query_params": qp_str,
            "body_params": bp_str,
            "path_params": pp_str,
            "cookie_params": cp_str,
            "headers": h_str,
            "body": body,
            "content_type": content_type,
            "content_length": content_length,
            "request_body_truncated": bool(row.get("request_body_truncated")),
            "response_status": response_status,
            "response_headers": rh_str,
            "response_size": response_size,
            "response_snippet": response_snippet,
            "response_truncated": bool(row.get("response_truncated")),
            "type": case_type,
            "source": source,
            "params_key_sig": params_key_sig,
            "priority_score": assignment["priority_score"],
            "priority_reason": assignment["priority_reason"],
            "cluster_key": assignment["cluster_key"],
            "terminal_reason": assignment["terminal_reason"],
            "classifier_version": CLASSIFIER_VERSION,
        })

    count = 0
    for start in range(0, len(items), 500):
        chunk = items[start:start + 500]
        if not chunk:
            continue
        resp = client.post("work-items/bulk", {"items": chunk})
        count += int(resp.get("count", len(chunk)))

    print(f"Requeued {count} new work item(s)")
