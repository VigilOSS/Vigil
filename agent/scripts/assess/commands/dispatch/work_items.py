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
from collections import Counter

from assess.lib.classify_buckets import reason_tag_of

from assess.commands.dispatch._shared import _validate_id_list


# Actions the work-buffer command exposes (kept here so the CLI choices, the
# Unknown-action help text, and the operator docs stay aligned). ``migrate`` is
# gone: the backend owns the schema via init_db(), there is nothing to migrate.
# ``reclassify`` and ``link-surface`` folded in the former standalone
# ``classify-work`` and ``link-surface-work-items`` verbs (both operate on
# ``assessment_work_items``).
_DB_ACTIONS = (
    "stats",
    "peek",
    "fetch",
    "fetch-by-priority",
    "fetch-by-unit",
    "defer-cluster",
    "defer-items",
    "set-rationale",
    "mark-manual",
    "done",
    "error",
    "reset-stale",
    "retry-errors",
    "requeue",
    "reclassify",
    "link-surface",
    # folded-in list-clusters (2026-07 CLI consolidation); handled in
    # work_buffer.run by delegating to commands.list_clusters, so it never
    # reaches the dispatch.run action switch.
    "clusters",
)

# Chunk size for the reclassify backend update POST.
_RECLASSIFY_CHUNK = 500


def _stats(client, *, by: str = "status", status: str = "") -> None:
    """Print work-buffer statistics grouped by ``by`` (backend-computed).

    Output is byte-identical to the former local implementation so every
    operator script and dashboard that parses it keeps working.
    """
    endpoint = f"work-items/stats?by={by}"
    if status and by == "host":
        endpoint += f"&status={status}"
    data = client.get(endpoint)

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


def _fetch_by_unit(
    client,
    *,
    unit_id: int | None,
    path: str,
    work_class: str,
    limit: int | None,
    agent: str,
) -> None:
    response = client.post(
        "work-items/fetch-by-unit",
        {
            "unit_id": unit_id,
            "path": path,
            "work_class": work_class,
            "limit": limit,
            "agent": agent,
        },
    )
    if response.get("error") in {"not-routed-agent", "class-not-routed"}:
        print(f"fetch-by-unit: {response['error']}", file=sys.stderr)
        sys.exit(1)
    print(
        json.dumps(
            {
                "unit": response.get("unit"),
                "selection": response.get("selection"),
                "effective_limit": response.get("effective_limit"),
                "effective_limit_source": response.get("effective_limit_source"),
                "recent_probe_count": response.get("recent_probe_count", 0),
                "claimed": response.get("claimed", []),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


def _defer_items(client, id_list, reason: str, *, dry_run: bool = False) -> None:
    """Mark specific pending work-item ids skipped with a terminal reason."""
    ids = _validate_id_list(id_list)
    payload = {"ids": ids, "reason": reason}
    if dry_run:
        payload["dry_run"] = True
    resp = client.post("work-items/defer", payload)
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
    verb = "Would defer" if dry_run else "Deferred"
    print(f"{verb} {affected} pending item(s): {ids_repr} (reason: {reason})")


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


def _defer_cluster(
    client, cluster_key: str, reason: str, *, dry_run: bool = False
) -> None:
    """Mark every pending row in a cluster skipped with a terminal reason."""
    payload = {"cluster_key": cluster_key, "reason": reason}
    if dry_run:
        payload["dry_run"] = True
    resp = client.post("work-items/defer-cluster", payload)
    affected = int(resp.get("affected", 0))
    verb = "Would defer" if dry_run else "Deferred"
    print(f"{verb} {affected} pending item(s) in cluster '{cluster_key}' (reason: {reason})")


def _set_rationale(client, id_list, rationale: str) -> None:
    ids = _validate_id_list(id_list)
    updates = [{"id": item_id, "triage_rationale": rationale} for item_id in ids]
    affected = 0
    for start in range(0, len(updates), _RECLASSIFY_CHUNK):
        response = client.post(
            "work-items/update",
            {"updates": updates[start:start + _RECLASSIFY_CHUNK]},
        )
        affected += int(response.get("affected", 0))
    print(f"Updated triage rationale on {affected} item(s)")


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
            # A terminal row (inert image/video/font/archive, out-of-scope) is
            # `skipped` at normal ingest; omitting status here would let the
            # backend default it to `pending`, so a skip-worthy row would show in
            # pending stats and be claimed by typed fetches. Mirror ingest.
            "status": "skipped" if assignment["terminal_reason"] else "pending",
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


# ---------------------------------------------------------------------------
# reclassify — folded-in `classify-work` (gf-style re-classification + retype)
# ---------------------------------------------------------------------------
def _reclassify_row_get(row, key, default=None):
    """Tolerant column getter for a work-item row dict.

    Returns ``default`` when the column is absent or stored NULL, so threading
    the context kwargs never breaks on a row that lacks an optional column.
    """
    try:
        value = row[key]
    except (IndexError, KeyError, TypeError):
        return default
    return value if value is not None else default


def _reclassify_matches_predicate(row, *, reclaim_skipped, reclassify_stale, reclassify_all) -> bool:
    """Replicate the classify-work WHERE predicates in Python."""
    from assess.lib.classify_buckets import (
        CLASSIFIER_VERSION,
        INERT_TYPES,
        MANUAL_CLASSIFIER_VERSION,
    )

    status = row.get("status")
    row_type = row.get("type")
    cv = _reclassify_row_get(row, "classifier_version")
    base = status == "pending" or (status == "skipped" and row_type in INERT_TYPES)

    if reclaim_skipped:
        return status == "skipped"
    if reclassify_stale:
        # stale AND not-manual; NULL cv counts as stale+not-manual (kept).
        return base and cv != CLASSIFIER_VERSION and cv != MANUAL_CLASSIFIER_VERSION
    if reclassify_all:
        return base
    # default: unscored only.
    return (
        base
        and int(row.get("priority_score") or 0) == 0
        and _reclassify_row_get(row, "cluster_key") is None
        and _reclassify_row_get(row, "terminal_reason") is None
    )


def _reclassify(client, args) -> None:
    """Re-apply gf-style priority/cluster classification to the work buffer.

    Folded-in ``classify-work``. Classification runs inline during ingest, so
    this is the maintenance path for (1) re-scoring after a `_BUCKETS` change or
    (2) re-typing an already-ingested corpus (``--retype``). Reads rows via the
    backend and writes changed fields via ``work-items/update`` (ADR 0013).
    """
    from assess.lib.classify_buckets import CLASSIFIER_VERSION, MANUAL_CLASSIFIER_VERSION  # noqa: F401
    from assess.lib.classify_buckets import classify_row as _classify_row

    batch = max(1, int(getattr(args, "batch", _RECLASSIFY_CHUNK)))
    reclassify_all = bool(getattr(args, "reclassify_all", False))
    reclassify_stale = bool(getattr(args, "reclassify_stale", False))
    reclaim_skipped = bool(getattr(args, "reclaim_skipped", False))
    retype = bool(getattr(args, "retype", False))
    retype_all = bool(getattr(args, "retype_all", False))

    # `--retype` is a distinct, opt-in pass (re-derive `type` then re-bucket only
    # rows whose type changed); it never runs implicitly with the bucket-only
    # re-classification paths. `--retype-all` implies `--retype`.
    if retype or retype_all:
        _reclassify_retype(client, batch=batch, retype_all=retype_all)
        return

    rows = client.get_all_pages("work-items")
    classified = 0
    reclaimed = 0
    cluster_counts: Counter[str] = Counter()
    from_version_counts: Counter[str] = Counter()
    updates: list[dict] = []

    for row in rows:
        if not _reclassify_matches_predicate(
            row,
            reclaim_skipped=reclaim_skipped,
            reclassify_stale=reclassify_stale,
            reclassify_all=reclassify_all,
        ):
            continue
        classified += 1
        from_version_counts[_reclassify_row_get(row, "classifier_version") or "none"] += 1
        assignment = _classify_row(
            row,
            url=_reclassify_row_get(row, "url"),
            source=_reclassify_row_get(row, "source"),
            live_status=_reclassify_row_get(row, "live_status"),
        )
        cluster_counts[assignment["cluster_key"]] += 1

        update = {
            "id": row["id"],
            "priority_score": assignment["priority_score"],
            "priority_reason": assignment["priority_reason"],
            "cluster_key": assignment["cluster_key"],
            "classifier_version": CLASSIFIER_VERSION,
        }
        if reclaim_skipped:
            # terminal_reason set directly (may clear); status derived from it.
            update["terminal_reason"] = assignment["terminal_reason"]
            update["status"] = "skipped" if assignment["terminal_reason"] is not None else "pending"
            if assignment["terminal_reason"] is None:
                reclaimed += 1
        else:
            # COALESCE-keep the existing terminal_reason; only flip to skipped when
            # a NEW terminal_reason appears (else keep the current status).
            if assignment["terminal_reason"] is not None:
                update["terminal_reason"] = assignment["terminal_reason"]
                update["status"] = "skipped"
        updates.append(update)

    updated = 0
    for start in range(0, len(updates), batch):
        chunk = updates[start:start + batch]
        if chunk:
            resp = client.post("work-items/update", {"updates": chunk})
            updated += int(resp.get("affected", 0))

    summary = {
        "classified": classified,
        "updated": updated,
        "reclaimed_to_pending": reclaimed,
        "classifier_version": CLASSIFIER_VERSION,
        "by_cluster": dict(sorted(cluster_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "from_version": dict(sorted(from_version_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def _reclassify_retype(client, *, batch: int, retype_all: bool) -> None:
    """Re-derive `type` from each in-scope row's stored fields (backend-backed).

    Feeds the typer the row's STORED `content_type` and request `body`. For every
    row whose type CHANGES, rewrites `type` (+ the type-suffixed queue_key) and
    re-applies the downstream bucket classification for the NEW type. Rows whose
    type is unchanged are left alone (idempotent). Never deletes; a queue_key
    collision on the rewrite is skipped by the backend's UPDATE OR IGNORE.
    """
    from assess.lib.classify import classify_type
    from assess.lib.classify_buckets import CLASSIFIER_VERSION
    from assess.lib.classify_buckets import classify_row as _classify_row

    rows = client.get_all_pages("work-items")
    scanned = 0
    retyped = 0
    transitions: Counter[str] = Counter()
    updates: list[dict] = []

    for row in rows:
        row_type = row.get("type") or "unknown"
        if not retype_all and row_type != "unknown":
            continue
        scanned += 1
        old_type = row_type
        method = row.get("method") or "GET"
        content_type = _reclassify_row_get(row, "content_type", "") or ""
        body_snippet = _reclassify_row_get(row, "body", "") or ""
        new_type = classify_type(method, row.get("url_path") or "", content_type, body_snippet)

        if new_type == old_type:
            continue

        retyped += 1
        transitions[f"{old_type}->{new_type}"] += 1

        mirror = {
            "type": new_type,
            "url_path": row.get("url_path"),
            "query_params": row.get("query_params"),
            "body_params": row.get("body_params"),
            "path_params": row.get("path_params"),
        }
        # Thread the same context kwargs the `_reclassify` branch passes: the
        # hand-built mirror carries only the fields the TYPER needs, so without
        # these the retype pass scored every row with the boost layer and the
        # full-URL regex buckets disabled.
        assignment = _classify_row(
            mirror,
            url=_reclassify_row_get(row, "url"),
            source=_reclassify_row_get(row, "source"),
            live_status=_reclassify_row_get(row, "live_status"),
        )

        # queue_key embeds the type only for variant:/service:/coverage: keys,
        # where it is the trailing ':'-segment. Only rewrite when the trailing
        # segment matches the OLD type; arjun:/deferred:/seed: keys carry a
        # params_sig/URL there and must NOT be rewritten.
        old_qk = row.get("queue_key") or ""
        if old_qk.startswith(("variant:", "service:", "coverage:")) and old_qk.rsplit(":", 1)[1] == old_type:
            new_qk = old_qk.rsplit(":", 1)[0] + ":" + new_type
        else:
            new_qk = old_qk

        # Retyping may reclaim a classifier-owned inert skip, but an operator's
        # skip is a separate decision. Only --reclaim-skipped may revisit it.
        preserve_skip = row.get("status") == "skipped" and row.get("terminal_reason") != "inert_type"
        terminal_reason = row.get("terminal_reason") if preserve_skip else assignment["terminal_reason"]
        update = {
            "id": row["id"],
            "type": new_type,
            "queue_key": new_qk,
            "priority_score": assignment["priority_score"],
            "priority_reason": assignment["priority_reason"],
            "cluster_key": assignment["cluster_key"],
            "terminal_reason": terminal_reason,
            "classifier_version": CLASSIFIER_VERSION,
            # Only a classifier-owned inert skip may return to pending.
            "status": (
                "skipped" if preserve_skip or terminal_reason is not None
                else ("pending" if row.get("status") == "skipped" else row.get("status"))
            ),
        }
        updates.append(update)

    applied = 0
    for start in range(0, len(updates), batch):
        chunk = updates[start:start + batch]
        if chunk:
            resp = client.post("work-items/update", {"updates": chunk})
            applied += int(resp.get("affected", 0))

    summary = {
        "scanned": scanned,
        "retyped": retyped,
        "applied": applied,
        "scope": "all" if retype_all else "unknown",
        "by_transition": dict(sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# link-surface — folded-in `link-surface-work-items`
# ---------------------------------------------------------------------------
def _parse_link_surface_ids(raw_values) -> list[int]:
    surface_ids: list[int] = []
    for raw in raw_values or []:
        for token in str(raw).split(","):
            token = token.strip()
            if not token:
                continue
            try:
                surface_id = int(token)
            except ValueError:
                print(f"ERROR: invalid --surface-id '{token}' (must be an integer)", file=sys.stderr)
                sys.exit(1)
            if surface_id not in surface_ids:
                surface_ids.append(surface_id)
    return surface_ids


def _link_surface(client, args) -> None:
    """Link backend surfaces to the request variants behind work_items.

    Folded-in ``link-surface-work-items``. Selects work items from the buffer by
    ``--cluster`` / ``--queue-key`` and links each one's durable backend
    ``request_variant_id`` to one or more surfaces. A work_item that was never
    posted to the backend has a NULL ``request_variant_id`` and is skipped with a
    warning rather than failing the whole command.
    """
    from assess.lib.surface_links import create_surface_request_variant_link

    surface_ids = _parse_link_surface_ids(getattr(args, "surface_id", []))
    if not surface_ids:
        print("ERROR: at least one --surface-id is required", file=sys.stderr)
        sys.exit(1)
    cluster = getattr(args, "cluster", []) or []
    queue_key = getattr(args, "queue_key", []) or []
    if not cluster and not queue_key:
        print("ERROR: select work_items with --cluster and/or --queue-key", file=sys.stderr)
        sys.exit(1)

    cluster_filter = set(cluster)
    queue_key_filter = set(queue_key)
    relation = getattr(args, "relation", "") or ""
    evidence_ref = getattr(args, "link_evidence_ref", "") or ""

    created = 0
    skipped_no_variant = 0
    failed = 0
    linked_variants: set[int] = set()

    rows = [
        row for row in client.get_all_pages("work-items")
        if row.get("cluster_key") in cluster_filter
        or row.get("queue_key") in queue_key_filter
    ]
    if not rows:
        print("link-surface: no matching work_items found", file=sys.stderr)
        return

    for row in rows:
        request_variant_id = row.get("request_variant_id")
        if not request_variant_id:
            skipped_no_variant += 1
            print(
                f"link-surface: work_item {row.get('queue_key')!r} "
                f"({row.get('url')}) has no request_variant_id (never posted to the "
                "backend); skipping",
                file=sys.stderr,
            )
            continue
        request_variant_id = int(request_variant_id)
        if request_variant_id in linked_variants:
            continue
        linked_variants.add(request_variant_id)
        for surface_id in surface_ids:
            try:
                create_surface_request_variant_link(
                    client,
                    surface_id=surface_id,
                    request_variant_id=request_variant_id,
                    relation=relation,
                    evidence_ref=evidence_ref,
                )
                created += 1
            except Exception as exc:  # noqa: BLE001 - one bad link must not drop the rest
                failed += 1
                print(
                    f"link-surface: failed to link surface {surface_id} to "
                    f"request_variant {request_variant_id}: {exc}; skipping this link",
                    file=sys.stderr,
                )

    print(
        f"[link] Created {created} surface link(s) across {len(linked_variants)} "
        f"request variant(s); skipped {skipped_no_variant} work_item(s) with no "
        f"request_variant_id; {failed} link(s) failed."
    )
