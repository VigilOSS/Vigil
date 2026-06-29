"""vigil assess ingest-candidates — ingest metadata-rich surface candidate JSONL."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.auth import auth_active_context
from assess.lib.candidate_records import candidate_metadata, candidate_type, json_text, signal_tokens
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.db import db_init, db_insert_out_of_scope_work_item, db_insert_work_item
from assess.lib.params import extract_path_params, extract_query_params, extract_url_path, generate_params_sig
from assess.lib.scope import host_admitted, ingest_scope_filter


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest-candidates",
        help="Ingest metadata-rich surface candidate JSONL into assessment state",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("source", help="Source name (e.g. surface-collector-curated)")
    p.add_argument("records_file", help="Path to candidate_records.jsonl")
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    records_file = args.records_file
    source = args.source

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    if not Path(records_file).is_file():
        print(f"ERROR: candidate records file not found: {records_file}", file=sys.stderr)
        sys.exit(1)

    db_init(db_path)

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)
    count = 0

    # Scope admission gate (defense-in-depth) — same per-URL semantics as
    # ingest-endpoints. A curated candidate row whose host is not admitted by
    # scope.json (e.g. carried through from a gau/wayback corpus) is recorded
    # skipped instead of admitted as probeable work. Inactive when scope.json has
    # no allowlist (see scope.ingest_scope_filter).
    scope_allow, scope_deny, scope_filter_active = ingest_scope_filter(eng_dir)
    out_of_scope_count = 0
    out_of_scope_warned_hosts: set[str] = set()

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        with open(records_file, "r", encoding="utf-8") as input_stream:
            for line in input_stream:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue

                method = str(record.get("method") or "GET").upper()
                url = str(record.get("url") or "").split()[0]
                if not url or any(tok in url for tok in ("FUZZ", "PARAM", "{{")):
                    continue
                if not url.startswith(("http://", "https://")):
                    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}", url):
                        url = f"https://{url}"
                if not url:
                    continue

                url_path = str(record.get("url_path") or record.get("path") or "")
                if not url_path or url_path == "null":
                    url_path = extract_url_path(url)
                query_params = record.get("query_params") or extract_query_params(url)
                body_params = record.get("body_params") or {}
                path_params = record.get("path_params") or extract_path_params(url_path)
                cookie_params = record.get("cookie_params") or {}

                signals = signal_tokens(record)
                case_type = candidate_type(record, method, url_path, signals)
                metadata = candidate_metadata(record, case_type, signals)
                params_sig = generate_params_sig(query_params, body_params)
                parsed = urlparse(url)
                cand_host = (parsed.hostname or "").rstrip(".").lower()

                # Out-of-scope candidates are recorded skipped and never POSTed as
                # observations (so no service/surface is created for an
                # out-of-scope host) — auditable + reversible, identical to the
                # ingest-endpoints gate.
                if (
                    scope_filter_active
                    and cand_host
                    and not host_admitted(cand_host, scope_allow, scope_deny)
                ):
                    out_of_scope_count += 1
                    if cand_host not in out_of_scope_warned_hosts:
                        out_of_scope_warned_hosts.add(cand_host)
                        print(
                            f"WARN: {cand_host} is out of scope (no scope.json "
                            f"allowlist match, or matched an out_of_scope carve-out). "
                            f"Recording its candidate URLs as skipped "
                            f"(terminal_reason='out-of-scope') instead of admitting them.",
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
                        host=cand_host,
                    )
                    continue

                observation_payload: dict[str, object] = {
                    "source": source,
                    "candidate_metadata": metadata,
                }
                observation = {
                    "url": url,
                    "method": method,
                    "auth_context": auth_context,
                    "content_type_family": "unknown",
                    "query_schema": query_params,
                    "body_schema": body_params,
                    "path_schema": path_params,
                    "cookie_schema": cookie_params,
                    "header_schema": {},
                    "path_template": "",
                    "discovery_source": source,
                    "notes": str(metadata.get("triage_rationale") or ""),
                    "response_status": None,
                    "evidence_ref": "",
                    "observation_payload": observation_payload,
                    "target_identity": parsed.hostname or "",
                    "target_kind": "host",
                    "target_notes": "",
                    "target_ip_address": None,
                    "target_hostname": parsed.hostname,
                    "banner": "",
                    "coverage_candidates": [],
                    "auto_generate_coverage": True,
                }

                response = client.post("request-observations", observation)
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
                    print(
                        f"ingest-candidates: backend response missing request_variant.id/service.id for {url}",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                if request_variant_id:
                    queue_key = f"variant:{request_variant_id}:{case_type}"
                else:
                    queue_key = f"service:{service_id}:{case_type}"

                db_insert_work_item(
                    db_path,
                    queue_key=queue_key,
                    method=method,
                    url=url,
                    url_path=url_path,
                    query_params=json.dumps(query_params) if isinstance(query_params, dict) else str(query_params),
                    body_params=json.dumps(body_params) if isinstance(body_params, dict) else str(body_params),
                    path_params=json.dumps(path_params) if isinstance(path_params, dict) else str(path_params),
                    cookie_params=json.dumps(cookie_params) if isinstance(cookie_params, dict) else str(cookie_params),
                    case_type=case_type,
                    source=source,
                    params_key_sig=params_sig,
                    request_variant_id=int(request_variant_id) if request_variant_id else None,
                    service_id=int(service_id) if service_id else None,
                    auth_context=auth_context,
                    priority_score=metadata.get("priority_score"),
                    priority_reason=metadata.get("priority_reason"),
                    cluster_key=metadata.get("cluster_key"),
                    signals=json_text(metadata.get("signals")),
                    selected_by=metadata.get("selected_by"),
                    triage_rationale=metadata.get("triage_rationale"),
                    live_status=metadata.get("live_status"),
                    curated=True,
                )
                count += 1

    print(f"[ingest] Ingested {count} candidate records from source '{source}'")
    if out_of_scope_count:
        print(
            f"[ingest] Excluded {out_of_scope_count} candidate(s) across "
            f"{len(out_of_scope_warned_hosts)} out-of-scope host(s) "
            f"(status='skipped', terminal_reason='out-of-scope'). Reachable but not "
            f"in scope.json — fix scope.json and re-ingest to admit them; review with "
            f"`vigil assess work-buffer <db> stats --by reason`.",
            file=sys.stderr,
        )
