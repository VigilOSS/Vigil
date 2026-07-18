"""vigil assess ingest endpoints — read endpoint lines, POST observations.

Highest-volume producer. Each in-scope endpoint is POSTed once as a
request-observation carrying its work-buffer derivation block and gf-typed
coverage candidates; the backend derives the request-variant, coverage items,
and the ``assessment_work_items`` row in a single transaction (ADR 0013 — no
dual write). Out-of-scope / egress-blocked URLs are recorded directly in the
backend work buffer as skipped/deferred rows via ``work-items/bulk``.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib import vuln_taxonomy
from assess.lib.auth import auth_active_context
from assess.lib.bulk_ingest import (
    DEFAULT_BULK_WRITE_SIZE,
    post_request_observations_bulk,
)
from assess.lib.candidate_records import int_value, json_text
from assess.lib.classify import classify_type
from assess.lib.classify_buckets import (
    CLASSIFIER_VERSION,
    INERT_TYPES,
    classify_from_fields,
    tagged_terminal_reason,
    weak_tokens_for_key,
)
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.params import (
    extract_url_path,
    extract_query_params,
    extract_path_params,
    generate_params_sig,
    header_schema_from_headers,
)
from assess.lib.scope import host_admitted, ingest_scope_filter


_EMPTY_ASSIGNMENT = {
    "priority_score": 0,
    "priority_reason": None,
    "cluster_key": None,
    "terminal_reason": None,
    "matched_buckets": [],
    "secondary_buckets": [],
}


def _gf_coverage_candidates(
    assignment: dict,
    *,
    query_params,
    body_params,
    path_params,
    auth_context: str,
) -> list[dict]:
    """Return class-typed coverage candidates for matched gf buckets (2b/S14).

    Shaped for an observation's ``coverage_candidates`` (``input_slot`` /
    ``attack_family`` / ``status`` / ``notes``) so the backend links each to the
    request-variant it creates in the same transaction — no separate POST and no
    need for the (not-yet-assigned) variant id. ADDITIVE to the generic baseline
    ``auto_generate_coverage``. Per S14 it bridges EVERY matched bucket, not just
    the cluster winner.
    """
    emitted_families: set[str] = set()
    payloads: list[dict] = []
    primary_buckets = assignment.get("matched_buckets", [])

    def _iter_param_keys(value) -> list[str]:
        if isinstance(value, dict):
            return [str(k) for k in value.keys()]
        if not value:
            return []
        try:
            decoded = json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        if not isinstance(decoded, dict):
            return []
        return [str(k) for k in decoded.keys()]

    def _has_redirect_family_url_suffix() -> bool:
        redirect_family_tokens = {
            "back", "callback", "continue", "dest", "destination", "failure",
            "forward", "goto", "next", "origin", "redirect", "return", "success",
        }
        for key in (
            _iter_param_keys(query_params)
            + _iter_param_keys(body_params)
            + _iter_param_keys(path_params)
        ):
            tokens = weak_tokens_for_key(key)
            if tokens & {"url", "uri"} and tokens & redirect_family_tokens:
                return True
        return False

    def _skip_weak_secondary(bucket: str) -> bool:
        if bucket != "ssrf":
            return False
        if not ({"redirect", "oauth-oidc"} & set(primary_buckets)):
            return False
        return _has_redirect_family_url_suffix()

    def _emit_coverage(bucket: str, *, weak: bool) -> None:
        if weak and _skip_weak_secondary(bucket):
            return
        attack_family = vuln_taxonomy.GF_BUCKET_TO_CLASS.get(bucket)
        if attack_family is None:
            return
        if weak and attack_family in emitted_families:
            return
        note = (
            f"gf bucket '{bucket}' weak inner-token signal at ingest"
            if weak
            else f"gf bucket '{bucket}' matched at ingest"
        )
        payloads.append(
            {
                "auth_context": auth_context or "anonymous",
                "input_slot": "endpoint",
                "attack_family": attack_family,
                "status": "pending",
                "notes": note,
            }
        )
        emitted_families.add(attack_family)

    for bucket in primary_buckets:
        _emit_coverage(bucket, weak=False)
    for bucket in assignment.get("secondary_buckets", []):
        if bucket not in primary_buckets:
            _emit_coverage(bucket, weak=True)
    return payloads


def register(subparsers) -> None:
    p = subparsers.add_parser("endpoints", help="Ingest endpoint lines into assessment state")
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
    """Return the set of hosts known to be CDN-edge-blocked (100% 403)."""
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


# Per-URL length cap for ingestion. A URL longer than this is skipped and
# reported rather than carried into the bulk request-observation POST.
MAX_INGEST_URL_LENGTH = 4096

_FQDN_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?:[:/?#]|$)")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:[:/?#]|$)")
_LOCALHOST_RE = re.compile(r"^localhost(?:[:/?#]|$)", re.IGNORECASE)
_BRACKETED_IPV6_RE = re.compile(r"^\[[0-9A-Fa-f:]+\](?:[:/?#]|$)")


def _ensure_url_scheme(url: str) -> str | None:
    """Return ``url`` with an ``https://`` scheme prefixed when it names a host."""
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


def _payload_text(value) -> str:
    """Coerce a JSON-provided request/response payload field to storable TEXT."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _params_text(value) -> str:
    return json.dumps(value) if isinstance(value, dict) else str(value)


def run(args) -> None:
    source = args.source

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    egress_blocked_hosts = _load_egress_blocked_hosts(getattr(args, "egress_blocked_hosts", None))
    egress_blocked_count = 0
    egress_warned_hosts: set[str] = set()

    # The shared gate is inactive when scope is absent/empty or the engagement
    # explicitly enables the global bypass.
    scope_allow, scope_deny, scope_filter_active = ingest_scope_filter(eng_dir)
    out_of_scope_count = 0
    out_of_scope_warned_hosts: set[str] = set()

    input_path = getattr(args, "input_file", None)
    input_stream = open(input_path, "r", encoding="utf-8") if input_path else sys.stdin
    count = 0
    skipped_template = 0
    skipped_malformed = 0
    skipped_badjson = 0
    skipped_overlong = 0
    pending_observations: list[dict] = []
    pending_direct: list[dict] = []

    def _flush_observations() -> None:
        nonlocal count, skipped_malformed
        if not pending_observations:
            return
        observations = list(pending_observations)
        pending_observations.clear()
        responses = post_request_observations_bulk(
            client,
            observations,
            warn_prefix="ingest-endpoints",
            fallback_individual=True,
        )
        for observation, response in zip(observations, responses, strict=True):
            if isinstance(response, Exception):
                skipped_malformed += 1
                print(
                    f"WARN ingest-endpoints: backend rejected {observation['url']}: "
                    f"{response}; skipping this line",
                    file=sys.stderr,
                )
                continue
            count += 1

    def _flush_direct() -> None:
        if not pending_direct:
            return
        items = list(pending_direct)
        pending_direct.clear()
        for start in range(0, len(items), DEFAULT_BULK_WRITE_SIZE):
            chunk = items[start:start + DEFAULT_BULK_WRITE_SIZE]
            if chunk:
                client.post("work-items/bulk", {"items": chunk})

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
            headers = ""
            body = ""
            response_headers = ""
            response_snippet = ""
            header_schema: dict = {}

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
                headers = _payload_text(row.get("headers"))
                header_schema = header_schema_from_headers(row.get("headers"))
                body = _payload_text(row.get("body"))
                response_headers = _payload_text(row.get("response_headers"))
                response_snippet = _payload_text(row.get("response_snippet"))
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

            url = url.split()[0] if url.split() else ""
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

            if len(url) > MAX_INGEST_URL_LENGTH:
                skipped_overlong += 1
                print(
                    f"WARN ingest-endpoints: skipping over-long URL "
                    f"({len(url)} chars, cap {MAX_INGEST_URL_LENGTH}): {url[:120]}",
                    file=sys.stderr,
                )
                continue

            if not url_path or url_path == "null":
                url_path = extract_url_path(url)
            if not query_params:
                query_params = extract_query_params(url)
            if not path_params:
                path_params = extract_path_params(url_path)
            if not body_params:
                body_params = {}

            if override_type and override_type != "unknown":
                case_type = override_type
            else:
                case_type = classify_type(method, url_path, row_content_type, "")

            params_sig = generate_params_sig(query_params, body_params)
            qp_text = _params_text(query_params)
            bp_text = _params_text(body_params)
            pp_text = _params_text(path_params)
            cp_text = _params_text(cookie_params)

            parsed = urlparse(url)
            apex_host = (parsed.hostname or "").rstrip(".").lower()

            # Scope admission gate (defense-in-depth) — out-of-scope hosts are
            # recorded as skipped rows (no observation POST, so no service/surface
            # is created) and surfaced by `work-buffer stats --by reason`.
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
                pending_direct.append({
                    "queue_key": f"skipped:out-of-scope:{apex_host}:{url}",
                    "method": method,
                    "url": url,
                    "url_path": url_path,
                    "host": apex_host,
                    "query_params": qp_text,
                    "body_params": bp_text,
                    "path_params": pp_text,
                    "cookie_params": cp_text,
                    "type": case_type,
                    "source": source,
                    "status": "skipped",
                    "params_key_sig": params_sig,
                    "auth_context": auth_context,
                    "cluster_key": "skipped:out-of-scope",
                    "terminal_reason": tagged_terminal_reason("out-of-scope", apex_host),
                })
                if len(pending_direct) >= DEFAULT_BULK_WRITE_SIZE:
                    _flush_direct()
                continue

            # Egress-blocked deferral: hosts CDN-edge-blocking the runtime IP.
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
                pending_direct.append({
                    "queue_key": f"deferred:egress-blocked:{apex_host}:{url}",
                    "method": method,
                    "url": url,
                    "url_path": url_path,
                    "host": apex_host,
                    "query_params": qp_text,
                    "body_params": bp_text,
                    "path_params": pp_text,
                    "cookie_params": cp_text,
                    "type": case_type,
                    "source": source,
                    "status": "deferred",
                    "params_key_sig": params_sig,
                    "auth_context": auth_context,
                    "cluster_key": "deferred:egress-blocked",
                    "terminal_reason": "egress-blocked",
                })
                if len(pending_direct) >= DEFAULT_BULK_WRITE_SIZE:
                    _flush_direct()
                continue

            # Classify once; reused for the work-item scores AND the gf coverage
            # candidates (the classifier globs the agent skills tree, so it stays
            # client-side; the backend only stores the resulting facts).
            try:
                assignment = classify_from_fields(
                    case_type=case_type,
                    url_path=url_path,
                    query_params=qp_text,
                    body_params=bp_text,
                    path_params=pp_text,
                    url=url,
                    source=source,
                    live_status=live_status,
                )
            except Exception as exc:  # noqa: BLE001 — classification must never abort ingest
                print(
                    f"WARN ingest-endpoints: classification failed for {url}: {exc}",
                    file=sys.stderr,
                )
                assignment = dict(_EMPTY_ASSIGNMENT)

            gf_candidates = _gf_coverage_candidates(
                assignment,
                query_params=query_params,
                body_params=body_params,
                path_params=path_params,
                auth_context=auth_context,
            )
            wi_status = "skipped" if case_type in INERT_TYPES else "pending"

            observation = {
                "url": url,
                "method": method,
                "auth_context": auth_context,
                "content_type_family": "unknown",
                "query_schema": query_params if isinstance(query_params, dict) else json.loads(query_params),
                "body_schema": body_params if isinstance(body_params, dict) else json.loads(body_params),
                "path_schema": path_params if isinstance(path_params, dict) else json.loads(path_params),
                "cookie_schema": cookie_params if isinstance(cookie_params, dict) else json.loads(cookie_params),
                "header_schema": header_schema,
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
                "coverage_candidates": gf_candidates,
                "auto_generate_coverage": True,
                # Work-buffer derivation block — the backend derives the
                # assessment_work_items row from this in the same transaction.
                "work_item": {
                    "case_type": case_type,
                    "source": source,
                    "status": wi_status,
                    "url_path": url_path,
                    "query_params": qp_text,
                    "body_params": bp_text,
                    "path_params": pp_text,
                    "cookie_params": cp_text,
                    "headers": headers,
                    "body": body,
                    "content_type": row_content_type,
                    "response_status": response_status or 0,
                    "response_headers": response_headers,
                    "response_snippet": response_snippet,
                    "params_key_sig": params_sig,
                    "priority_score": assignment["priority_score"],
                    "priority_reason": assignment["priority_reason"] or "",
                    "cluster_key": assignment["cluster_key"] or "",
                    "terminal_reason": assignment["terminal_reason"] or "",
                    "classifier_version": CLASSIFIER_VERSION,
                    "signals": json_text(signals) if signals else "",
                    "live_status": live_status or "",
                },
            }

            pending_observations.append(observation)
            if len(pending_observations) >= DEFAULT_BULK_WRITE_SIZE:
                _flush_observations()
        _flush_observations()
        _flush_direct()
    finally:
        if input_path and input_stream is not sys.stdin:
            input_stream.close()
        client.close()

    print(f"[ingest] Ingested {count} work items from source '{source}'")
    total_skipped = skipped_template + skipped_malformed + skipped_badjson + skipped_overlong
    if total_skipped:
        print(
            f"[ingest] Skipped {total_skipped} line(s): "
            f"{skipped_template} template/fuzz/empty, "
            f"{skipped_malformed} malformed/unkeyable, "
            f"{skipped_badjson} bad-JSON, "
            f"{skipped_overlong} over-long-URL (see WARN lines above).",
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
            f"`vigil assess work-buffer stats --by reason`.",
            file=sys.stderr,
        )
