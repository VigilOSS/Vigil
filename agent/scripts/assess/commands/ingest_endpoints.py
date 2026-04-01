"""assess.py ingest-endpoints — read endpoint lines, POST observations, insert work items.

Highest volume command. Key improvement: connection reuse eliminates ~3000 subprocess spawns per 500 endpoints.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.auth import auth_active_context
from assess.lib.classify import classify_type
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.db import db_init, db_insert_work_item
from assess.lib.params import extract_url_path, extract_query_params, extract_path_params, generate_params_sig


def register(subparsers) -> None:
    p = subparsers.add_parser("ingest-endpoints", help="Ingest endpoint lines into assessment state")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("source", help="Source name (e.g. recon, katana)")
    p.add_argument("--file", dest="input_file", default=None, help="Read endpoints from file instead of stdin")
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    source = args.source

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db_init(db_path)

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    input_stream = open(args.input_file, "r", encoding="utf-8") if args.input_file else sys.stdin
    count = 0

    try:
        for line in input_stream:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            method = ""
            url = ""
            url_path = ""
            override_type = ""
            query_params: dict = {}
            body_params: dict = {}
            path_params: dict = {}
            cookie_params: dict = {}

            if line.startswith("{"):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                method = row.get("method") or "GET"
                url = row.get("url") or ""
                url_path = row.get("url_path") or ""
                override_type = row.get("type") or ""
                query_params = row.get("query_params") or {}
                body_params = row.get("body_params") or {}
                path_params = row.get("path_params") or {}
                cookie_params = row.get("cookie_params") or {}
                if not url:
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

            url = url.split()[0]  # Take first token only
            method = method.upper()

            # Skip template/fuzz URLs
            if any(tok in url for tok in ("FUZZ", "PARAM", "{{")):
                continue
            if not url:
                continue

            # Ensure scheme
            if not url.startswith(("http://", "https://")):
                import re
                if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}", url):
                    url = f"https://{url}"

            if not url_path or url_path == "null":
                url_path = extract_url_path(url)
            if not query_params:
                query_params = extract_query_params(url)
            if not path_params:
                path_params = extract_path_params(url_path)
            if not body_params:
                body_params = {}

            if override_type:
                case_type = override_type
            else:
                case_type = classify_type(method, url_path, "", "")

            params_sig = generate_params_sig(query_params, body_params)

            # Build observation payload
            parsed = urlparse(url)
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
                "response_status": None,
                "evidence_ref": "",
                "observation_payload": {"source": source},
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
                print(f"ingest-endpoints: backend response missing request_variant.id/service.id for {url}", file=sys.stderr)
                sys.exit(1)

            queue_key = ""
            if request_variant_id:
                queue_key = f"variant:{request_variant_id}:{case_type}"
            elif service_id:
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
            )
            count += 1
    finally:
        if args.input_file and input_stream is not sys.stdin:
            input_stream.close()
        client.close()

    print(f"[ingest] Ingested {count} work items from source '{source}'")
