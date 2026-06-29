"""vigil assess ingest-endpoints — read endpoint lines, POST observations, insert work items.

Highest volume command. Key improvement: connection reuse eliminates ~3000 subprocess spawns per 500 endpoints.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib import vuln_taxonomy
from assess.lib.auth import auth_active_context
from assess.lib.bulk_ingest import (
    DEFAULT_BULK_WRITE_SIZE,
    post_coverage_items_bulk,
    post_request_observations_bulk,
)
from assess.lib.candidate_records import int_value, json_text
from assess.lib.classify import classify_type
from assess.lib.classify_buckets import classify_from_fields
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.db import db_init, db_insert_out_of_scope_work_item, db_insert_work_item
from assess.lib.params import extract_url_path, extract_query_params, extract_path_params, generate_params_sig
from assess.lib.scope import host_admitted, ingest_scope_filter


def _gf_coverage_item_payloads(
    *,
    request_variant_id: int,
    case_type: str,
    url_path: str,
    query_params,
    body_params,
    path_params,
    auth_context: str,
) -> list[dict]:
    """Return class-typed coverage_items for matched gf buckets (2b/S14).

    For a row with a resolvable ``request_variant_id`` and matched gf buckets,
    build one ``coverage_item`` per matched bucket with the canonical
    ``attack_family = GF_BUCKET_TO_CLASS[bucket]`` (skipping generic buckets
    whose map value is None). This is ADDITIVE to the generic baseline
    ``_auto_request_coverage_candidates`` (which still runs server-side) — it
    gives the depth ledger a real vuln-class obligation per endpoint, and per
    S14 it bridges EVERY matched bucket, not just the cluster winner.

    Posting is handled in batches by the caller so one endpoint corpus does not
    become one HTTP request per matched bucket.
    """
    try:
        assignment = classify_from_fields(
            case_type=case_type,
            url_path=url_path,
            query_params=json.dumps(query_params) if isinstance(query_params, dict) else str(query_params or "{}"),
            body_params=json.dumps(body_params) if isinstance(body_params, dict) else str(body_params or "{}"),
            path_params=json.dumps(path_params) if isinstance(path_params, dict) else str(path_params or "{}"),
        )
    except Exception as exc:  # noqa: BLE001 — classification must never abort ingest
        print(
            f"WARN ingest-endpoints: gf classification failed for variant "
            f"{request_variant_id}: {exc}; skipping class-typed coverage.",
            file=sys.stderr,
        )
        return []

    emitted_families: set[str] = set()
    payloads: list[dict] = []

    def _emit_coverage(bucket: str, *, weak: bool) -> None:
        attack_family = vuln_taxonomy.GF_BUCKET_TO_CLASS.get(bucket)
        if attack_family is None:
            return
        # A weak (secondary) bucket whose attack_family is already covered by a
        # primary (or earlier-emitted) bucket adds nothing — skip it so a row with
        # primary `ssrf` + secondary `webhook` (both -> class `ssrf`) does not post
        # a duplicate coverage item. Primary-vs-primary emission is left as-is
        # (pre-existing S14 behavior).
        if weak and attack_family in emitted_families:
            return
        note = (
            f"gf bucket '{bucket}' weak inner-token signal at ingest"
            if weak
            else f"gf bucket '{bucket}' matched at ingest"
        )
        payloads.append(
            {
                "request_variant_id": int(request_variant_id),
                "auth_context": auth_context or "anonymous",
                "input_slot": "endpoint",
                "attack_family": attack_family,
                "status_value": "pending",
                "notes": note,
            }
        )
        emitted_families.add(attack_family)

    # Strong matches create coverage items per attack class. Secondary (weak
    # inner-token) buckets — from compound keys like `?return_url=` on a row whose
    # cluster is owned by another bucket — ALSO create coverage items (marked
    # weak) so a cross-class surface reaches every relevant specialist, not just
    # the one that won the cluster. `matched_buckets` is byte-identical to before;
    # `secondary_buckets` is the additive cross-routing signal (Fix 4).
    primary_buckets = assignment.get("matched_buckets", [])
    for bucket in primary_buckets:
        _emit_coverage(bucket, weak=False)
    for bucket in assignment.get("secondary_buckets", []):
        if bucket not in primary_buckets:
            _emit_coverage(bucket, weak=True)
    return payloads


def register(subparsers) -> None:
    p = subparsers.add_parser("ingest-endpoints", help="Ingest endpoint lines into assessment state")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("source", help="Source name (e.g. recon, katana)")
    p.add_argument("--file", dest="input_file", default=None, help="Read endpoints from file instead of stdin")
    p.add_argument(
        "--egress-blocked-hosts",
        dest="egress_blocked_hosts",
        default=None,
        help=(
            "Path to a newline-delimited list of hosts that returned a 100%% 403 "
            "cluster from the egress reputation check. URLs whose host is in "
            "this list are deferred with cluster_key=deferred:egress-blocked "
            "rather than admitted to the work buffer."
        ),
    )
    p.set_defaults(func=run)


def _load_egress_blocked_hosts(path: str | None) -> set[str]:
    """Return the set of hosts known to be CDN-edge-blocked (100% 403).

    The egress reputation check (see
    ``agent/references/runtime-guides/cdn-ip-blocking.md``) emits a small
    list of representative hosts that responded with a 100% 403 cluster from
    the runtime egress IP. URLs targeting those hosts are deferred with
    ``cluster_key=deferred:egress-blocked`` so the operator can resolve the
    egress block (allowlisting, residential proxy, browser-based tool) once
    rather than letting specialists rediscover the failure per-URL.
    """
    if not path:
        return set()
    file_path = Path(path)
    if not file_path.is_file():
        return set()
    blocked: set[str] = set()
    for raw in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        token = raw.strip()
        if not token or token.startswith("#"):
            continue
        host = token.lower().rstrip(".")
        if host:
            blocked.add(host)
    return blocked


_FQDN_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?:[:/?#]|$)")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:[:/?#]|$)")
_LOCALHOST_RE = re.compile(r"^localhost(?:[:/?#]|$)", re.IGNORECASE)
_BRACKETED_IPV6_RE = re.compile(r"^\[[0-9A-Fa-f:]+\](?:[:/?#]|$)")


def _ensure_url_scheme(url: str) -> str | None:
    """Return ``url`` with an ``https://`` scheme prefixed when it names a host.

    Handles bare FQDNs, IPv4 literals, ``localhost``, and bracketed IPv6
    authorities (``[::1]:8080/x``). Returns the URL unchanged when it already
    carries a scheme. Returns ``None`` for a line that names no recognizable
    host (a genuinely malformed token) so the caller can WARN+skip it rather
    than passing it through to fail the POST (S12).
    """
    if not url:
        return None
    if url.startswith(("http://", "https://")):
        return url
    if (
        _FQDN_RE.match(url)
        or _IPV4_RE.match(url)
        or _LOCALHOST_RE.match(url)
        or _BRACKETED_IPV6_RE.match(url)
    ):
        return f"https://{url}"
    return None


def run(args) -> None:
    # Anchor a relative cases.db to the engagement dir (not the cwd) so the
    # is_file() check and db_init() operate on the engagement's database even
    # when invoked from a drifted cwd.
    db_path = anchor_engagement_relative(args.db_path, args.engagement_dir)
    if db_path != args.db_path:
        print(f"ingest-endpoints: anchored relative db path '{args.db_path}' -> '{db_path}'", file=sys.stderr)
    source = args.source

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db_init(db_path)

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    # Egress-blocked deferral: hosts whose representative responses returned a
    # 100% 403 cluster from the runtime egress IP get deferred at ingestion
    # rather than admitted, so specialists do not rediscover the block per-URL.
    # The earlier per-host URL budget gate was removed in the mid-engagement
    # refactor: it silently deferred 4,300+ functional URLs in a single
    # authenticated Katana crawl. Volume control now lives in inline
    # classification at insert time (low-signal types stamp `status='skipped'`).
    egress_blocked_hosts = _load_egress_blocked_hosts(getattr(args, "egress_blocked_hosts", None))
    egress_blocked_count = 0
    egress_warned_hosts: set[str] = set()

    # Scope admission gate (defense-in-depth). gau/wayback and other historical
    # URL sources surface reachable-but-out-of-scope hosts; reachability is not
    # scope (shared-constraints §1), so an out-of-scope host must never be
    # admitted as probeable work. Inactive when scope.json has no allowlist.
    scope_allow, scope_deny, scope_filter_active = ingest_scope_filter(eng_dir)
    out_of_scope_count = 0
    out_of_scope_warned_hosts: set[str] = set()

    input_path = getattr(args, "input_file", None)
    input_stream = open(input_path, "r", encoding="utf-8") if input_path else sys.stdin
    count = 0
    skipped_template = 0
    skipped_malformed = 0
    skipped_badjson = 0
    pending_rows: list[dict] = []
    pending_observations: list[dict] = []
    pending_coverage_items: list[dict] = []

    def _flush_coverage_items() -> None:
        if not pending_coverage_items:
            return
        items = list(pending_coverage_items)
        pending_coverage_items.clear()
        post_coverage_items_bulk(client, items, warn_prefix="ingest-endpoints")

    def _flush_observations() -> None:
        nonlocal count, skipped_malformed
        if not pending_observations:
            return
        rows = list(pending_rows)
        observations = list(pending_observations)
        pending_rows.clear()
        pending_observations.clear()

        responses = post_request_observations_bulk(
            client,
            observations,
            warn_prefix="ingest-endpoints",
            fallback_individual=True,
        )
        for row, response in zip(rows, responses, strict=True):
            if isinstance(response, Exception):
                skipped_malformed += 1
                print(
                    f"WARN ingest-endpoints: backend rejected {row['url']}: "
                    f"{response}; skipping this line",
                    file=sys.stderr,
                )
                continue
            request_variant_id = None
            service_id = None
            try:
                request_variant_id = response.get("request_variant", {}).get("id")
            except (AttributeError, TypeError):
                pass
            try:
                service_id = response.get("service", {}).get("id")
            except (AttributeError, TypeError):
                pass

            if not request_variant_id and not service_id:
                skipped_malformed += 1
                print(
                    f"WARN ingest-endpoints: backend response missing "
                    f"request_variant.id/service.id for {row['url']}; skipping this line",
                    file=sys.stderr,
                )
                continue

            queue_key = ""
            if request_variant_id:
                queue_key = f"variant:{request_variant_id}:{row['case_type']}"
            elif service_id:
                queue_key = f"service:{service_id}:{row['case_type']}"

            db_insert_work_item(
                db_path,
                queue_key=queue_key,
                method=row["method"],
                url=row["url"],
                url_path=row["url_path"],
                query_params=json.dumps(row["query_params"]) if isinstance(row["query_params"], dict) else str(row["query_params"]),
                body_params=json.dumps(row["body_params"]) if isinstance(row["body_params"], dict) else str(row["body_params"]),
                path_params=json.dumps(row["path_params"]) if isinstance(row["path_params"], dict) else str(row["path_params"]),
                cookie_params=json.dumps(row["cookie_params"]) if isinstance(row["cookie_params"], dict) else str(row["cookie_params"]),
                content_type=row["row_content_type"],
                response_status=row["response_status"] or 0,
                case_type=row["case_type"],
                source=source,
                params_key_sig=row["params_sig"],
                request_variant_id=int(request_variant_id) if request_variant_id else None,
                service_id=int(service_id) if service_id else None,
                auth_context=auth_context,
                signals=json_text(row["signals"]),
                live_status=row["live_status"],
            )
            if request_variant_id:
                pending_coverage_items.extend(
                    _gf_coverage_item_payloads(
                        request_variant_id=int(request_variant_id),
                        case_type=row["case_type"],
                        url_path=row["url_path"],
                        query_params=row["query_params"],
                        body_params=row["body_params"],
                        path_params=row["path_params"],
                        auth_context=auth_context,
                    )
                )
                if len(pending_coverage_items) >= DEFAULT_BULK_WRITE_SIZE:
                    _flush_coverage_items()
            count += 1
        _flush_coverage_items()

    try:
        for line in input_stream:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            method = ""
            url = ""
            url_path = ""
            override_type = ""
            row_content_type = ""
            response_status: int | None = None
            live_status: str | None = None
            signals = None
            query_params: dict = {}
            body_params: dict = {}
            path_params: dict = {}
            cookie_params: dict = {}

            if line.startswith("{"):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    skipped_badjson += 1
                    print(
                        f"WARN ingest-endpoints: skipping malformed JSON line: {line[:120]}",
                        file=sys.stderr,
                    )
                    continue
                method = row.get("method") or "GET"
                url = row.get("url") or ""
                url_path = row.get("url_path") or ""
                override_type = row.get("type") or ""
                row_content_type = row.get("content_type") or ""
                response_status = int_value(row.get("response_status"))
                live_status = (
                    str(row.get("live_status"))
                    if row.get("live_status") not in (None, "")
                    else None
                )
                signals = row.get("signals")
                query_params = row.get("query_params") or {}
                body_params = row.get("body_params") or {}
                path_params = row.get("path_params") or {}
                cookie_params = row.get("cookie_params") or {}
                if not url:
                    skipped_malformed += 1
                    print(
                        f"WARN ingest-endpoints: skipping JSON row with no 'url': {line[:120]}",
                        file=sys.stderr,
                    )
                    continue
            else:
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].upper() in (
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
                ):
                    method = parts[0].upper()
                    url = parts[1]
                else:
                    method = "GET"
                    url = line

            url = url.split()[0] if url.split() else ""  # Take first token only
            method = method.upper()

            if not url:
                skipped_template += 1
                continue
            if any(tok in url for tok in ("FUZZ", "PARAM", "{{")):
                skipped_template += 1
                print(
                    f"WARN ingest-endpoints: skipping template/fuzz-marker URL: {url[:120]}",
                    file=sys.stderr,
                )
                continue

            resolved = _ensure_url_scheme(url)
            if resolved is None:
                skipped_malformed += 1
                print(
                    f"WARN ingest-endpoints: skipping malformed endpoint line "
                    f"(no resolvable host): {url[:120]}",
                    file=sys.stderr,
                )
                continue
            url = resolved

            if not url_path or url_path == "null":
                url_path = extract_url_path(url)
            if not query_params:
                query_params = extract_query_params(url)
            if not path_params:
                path_params = extract_path_params(url_path)
            if not body_params:
                body_params = {}

            # An explicit producer `type` is authoritative ONLY when it is a real
            # type. A sentinel `type=="unknown"` is NOT authoritative — it falls
            # through to classify_type() so path/content-type shape can recover a
            # real type. Mirrors the correct guard in
            # `assess.lib.candidate_records.candidate_type()` (Issues 5/D).
            if override_type and override_type != "unknown":
                case_type = override_type
            else:
                # Thread a JSON-provided `content_type` (when present) into the
                # typer instead of the historical `""`. The dominant bare-URL-list
                # path leaves `row_content_type` empty, so the typer falls back to
                # path-shape-only classification exactly as before — no regression.
                case_type = classify_type(method, url_path, row_content_type, "")

            params_sig = generate_params_sig(query_params, body_params)

            # Build observation payload
            parsed = urlparse(url)
            apex_host = (parsed.hostname or "").rstrip(".").lower()

            # Scope admission gate (defense-in-depth) — fires BEFORE the egress
            # check because out-of-scope is the harder boundary (never test) vs
            # egress-blocked (resolve and retest). A reachable host not admitted
            # by scope.json (no allowlist match, or matched an out_of_scope
            # carve-out) is recorded as a skipped row with an auditable
            # terminal_reason rather than admitted — reversible (no deletion),
            # no request-observation POSTed (so no service/surface is created for
            # it), and surfaced by `work-buffer stats --by reason`. This catches
            # the gau/wayback historical-URL sources that bypass the recon
            # pipeline's upstream scope filter.
            if (
                scope_filter_active
                and apex_host
                and not host_admitted(apex_host, scope_allow, scope_deny)
            ):
                out_of_scope_count += 1
                if apex_host not in out_of_scope_warned_hosts:
                    out_of_scope_warned_hosts.add(apex_host)
                    print(
                        f"WARN: {apex_host} is out of scope (no scope.json allowlist "
                        f"match, or matched an out_of_scope carve-out). Recording its "
                        f"URLs as skipped (terminal_reason='out-of-scope') instead of "
                        f"admitting them to the work buffer.",
                        file=sys.stderr,
                    )
                db_insert_out_of_scope_work_item(
                    db_path,
                    method=method,
                    url=url,
                    url_path=url_path,
                    query_params=query_params,
                    body_params=body_params,
                    path_params=path_params,
                    cookie_params=cookie_params,
                    case_type=case_type,
                    source=source,
                    params_key_sig=params_sig,
                    auth_context=auth_context,
                    host=apex_host,
                )
                continue

            # Egress-blocked deferral: when the egress reputation check (see
            # cdn-ip-blocking.md) marks a host as CDN-edge-blocking the
            # runtime IP (100% 403 cluster across representative samples),
            # defer URLs to that host instead of admitting them. The work
            # item is recorded with cluster_key=deferred:egress-blocked so
            # the operator can resolve the block once rather than letting
            # specialists rediscover it per-URL.
            if apex_host and apex_host in egress_blocked_hosts:
                egress_blocked_count += 1
                if apex_host not in egress_warned_hosts:
                    egress_warned_hosts.add(apex_host)
                    print(
                        f"WARN: {apex_host} flagged egress-blocked (100% 403 cluster from runtime IP). "
                        f"Deferring URLs to this host with cluster_key='deferred:egress-blocked'. "
                        f"See agent/references/runtime-guides/cdn-ip-blocking.md.",
                        file=sys.stderr,
                    )
                _insert_egress_blocked_work_item(
                    db_path=db_path,
                    method=method,
                    url=url,
                    url_path=url_path,
                    query_params=query_params,
                    body_params=body_params,
                    path_params=path_params,
                    cookie_params=cookie_params,
                    case_type=case_type,
                    source=source,
                    params_sig=params_sig,
                    auth_context=auth_context,
                    host=apex_host,
                )
                continue

            observation = {
                "url": url,
                "method": method,
                "auth_context": auth_context,
                "content_type_family": "unknown",
                "query_schema": query_params if isinstance(query_params, dict) else json.loads(query_params),
                "body_schema": body_params if isinstance(body_params, dict) else json.loads(body_params),
                "path_schema": path_params if isinstance(path_params, dict) else json.loads(path_params),
                "cookie_schema": cookie_params if isinstance(cookie_params, dict) else json.loads(cookie_params),
                "header_schema": {},
                "path_template": "",
                "discovery_source": source,
                "notes": "",
                "response_status": response_status,
                "evidence_ref": "",
                "observation_payload": {
                    "source": source,
                    "signals": signals or [],
                    "live_status": live_status,
                },
                "target_identity": parsed.hostname or "",
                "target_kind": "host",
                "target_notes": "",
                "target_ip_address": None,
                "target_hostname": parsed.hostname,
                "banner": "",
                "coverage_candidates": [],
                "auto_generate_coverage": True,
            }

            pending_rows.append(
                {
                    "method": method,
                    "url": url,
                    "url_path": url_path,
                    "query_params": query_params,
                    "body_params": body_params,
                    "path_params": path_params,
                    "cookie_params": cookie_params,
                    "row_content_type": row_content_type,
                    "response_status": response_status,
                    "live_status": live_status,
                    "signals": signals,
                    "case_type": case_type,
                    "params_sig": params_sig,
                }
            )
            pending_observations.append(observation)
            if len(pending_observations) >= DEFAULT_BULK_WRITE_SIZE:
                _flush_observations()
        _flush_observations()
        _flush_coverage_items()
    finally:
        if input_path and input_stream is not sys.stdin:
            input_stream.close()
        client.close()

    print(f"[ingest] Ingested {count} work items from source '{source}'")
    total_skipped = skipped_template + skipped_malformed + skipped_badjson
    if total_skipped:
        print(
            f"[ingest] Skipped {total_skipped} line(s): "
            f"{skipped_template} template/fuzz/empty, "
            f"{skipped_malformed} malformed/unkeyable, "
            f"{skipped_badjson} bad-JSON (see WARN lines above).",
            file=sys.stderr,
        )
    if egress_blocked_count:
        print(
            f"[ingest] Deferred {egress_blocked_count} URL(s) to egress-blocked hosts "
            f"(cluster_key='deferred:egress-blocked'). Resolve the egress block before retesting "
            f"— see agent/references/runtime-guides/cdn-ip-blocking.md.",
            file=sys.stderr,
        )
    if out_of_scope_count:
        print(
            f"[ingest] Excluded {out_of_scope_count} URL(s) across "
            f"{len(out_of_scope_warned_hosts)} out-of-scope host(s) "
            f"(status='skipped', terminal_reason='out-of-scope'). Reachable but not "
            f"in scope.json — these never reach a specialist. Fix scope.json and "
            f"re-ingest to admit them; review with "
            f"`vigil assess work-buffer <db> stats --by reason`.",
            file=sys.stderr,
        )


def _insert_egress_blocked_work_item(
    *,
    db_path: str,
    method: str,
    url: str,
    url_path: str,
    query_params,
    body_params,
    path_params,
    cookie_params,
    case_type: str,
    source: str,
    params_sig: str,
    auth_context: str,
    host: str,
) -> None:
    """Insert a deferred work item for a URL whose host is egress-blocked.

    Coexists with the wildcard-apex rejection path: the wildcard rejection
    fires before this check, so URLs that fail BOTH gates land in the
    rejected-apex bucket (the more restrictive one). Egress-blocked rows
    use ``status='deferred'`` and a stable
    ``cluster_key='deferred:egress-blocked'`` so the operator can list and
    resolve them as one cluster after the egress reputation check is
    cleared.
    """
    queue_key = f"deferred:egress-blocked:{host}:{url}"
    qp = json.dumps(query_params) if isinstance(query_params, dict) else str(query_params)
    bp = json.dumps(body_params) if isinstance(body_params, dict) else str(body_params)
    pp = json.dumps(path_params) if isinstance(path_params, dict) else str(path_params)
    cp = json.dumps(cookie_params) if isinstance(cookie_params, dict) else str(cookie_params)
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """INSERT OR IGNORE INTO work_items (
                queue_key, auth_context, method, url, url_path,
                query_params, body_params, path_params, cookie_params,
                type, source, status, params_key_sig,
                cluster_key, terminal_reason
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )""",
            (
                queue_key, auth_context, method, url, url_path,
                qp, bp, pp, cp,
                case_type, source, "deferred", params_sig,
                "deferred:egress-blocked",
                "egress-blocked",
            ),
        )
        conn.commit()
    finally:
        conn.close()
