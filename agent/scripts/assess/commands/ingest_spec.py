"""assess.py ingest-spec — parse OpenAPI 3.x / Swagger 2.0 specs and generate coverage records."""
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
from assess.lib.params import extract_url_path, generate_params_sig


def register(subparsers) -> None:
    p = subparsers.add_parser("ingest-spec", help="Ingest OpenAPI/Swagger spec into assessment state")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("spec_file", help="Path to local spec file (no URLs)")
    p.set_defaults(func=run)


def run(args) -> None:
    db_path = args.db_path
    spec_file = args.spec_file

    if spec_file.startswith("http"):
        print("ERROR: ingest-spec no longer fetches target URLs directly.", file=sys.stderr)
        print("Fetch the spec through the Kali MCP command-execution tool first, save it locally, then rerun.", file=sys.stderr)
        sys.exit(1)

    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)
    if not Path(spec_file).is_file():
        print(f"ERROR: spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)

    db_init(db_path)

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)

    spec = json.loads(Path(spec_file).read_text(encoding="utf-8"))

    # Detect version
    openapi_ver = spec.get("openapi", "")
    swagger_ver = spec.get("swagger", "")
    if openapi_ver:
        spec_version = "3"
    elif swagger_ver:
        spec_version = "2"
    else:
        print("ERROR: cannot detect spec version (no .openapi or .swagger field)", file=sys.stderr)
        sys.exit(1)

    # Extract base URL
    if spec_version == "3":
        base_url = (spec.get("servers") or [{}])[0].get("url", "")
    else:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        scheme = (spec.get("schemes") or ["https"])[0]
        base_url = f"{scheme}://{host}{base_path}" if host else ""
    base_url = base_url.rstrip("/")

    paths = spec.get("paths") or {}
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    count = 0

    try:
        for path_key, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method_lower, operation in methods.items():
                if method_lower not in ("get", "post", "put", "delete", "patch"):
                    continue
                if not isinstance(operation, dict):
                    continue

                method = method_lower.upper()
                full_url = f"{base_url}{path_key}"
                parameters = operation.get("parameters") or []

                # Extract query params
                query_params = {}
                for p in parameters:
                    if isinstance(p, dict) and p.get("in") == "query":
                        query_params[p["name"]] = str(p.get("example") or p.get("default") or "")

                # Extract path params
                path_params = {}
                for p in parameters:
                    if isinstance(p, dict) and p.get("in") == "path":
                        path_params[p["name"]] = str(p.get("example") or p.get("default") or "")

                # Extract body params
                body_params = {}
                if spec_version == "3":
                    try:
                        props = operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {}).get("properties", {})
                        for k, v in props.items():
                            body_params[k] = str(v.get("example") or "")
                    except (AttributeError, TypeError):
                        pass
                else:
                    for p in parameters:
                        if isinstance(p, dict) and p.get("in") == "body":
                            try:
                                props = p.get("schema", {}).get("properties", {})
                                for k, v in props.items():
                                    body_params[k] = str(v.get("example") or "")
                            except (AttributeError, TypeError):
                                pass
                            break

                # Build URL with query params
                url_with_query = full_url
                if query_params:
                    qs = "&".join(f"{k}={v}" for k, v in query_params.items())
                    url_with_query = f"{full_url}?{qs}"

                url_path = extract_url_path(url_with_query)
                case_type = classify_type(method, url_path, "", "")
                params_sig = generate_params_sig(query_params, body_params)

                if not url_with_query.startswith(("http://", "https://")):
                    print(f"ingest-spec: endpoint {url_with_query} missing absolute http(s) URL", file=sys.stderr)
                    sys.exit(1)

                parsed = urlparse(url_with_query)
                observation = {
                    "url": url_with_query,
                    "method": method,
                    "auth_context": auth_context,
                    "content_type_family": "spec-derived",
                    "query_schema": query_params,
                    "body_schema": body_params,
                    "path_schema": path_params,
                    "cookie_schema": {},
                    "header_schema": {},
                    "path_template": parsed.path or "",
                    "discovery_source": "api-spec",
                    "notes": "Derived from accessible API specification.",
                    "response_status": None,
                    "evidence_ref": "",
                    "observation_payload": {"source": "api-spec"},
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
                    print(f"ingest-spec: backend response missing request_variant.id/service.id for {url_with_query}", file=sys.stderr)
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
                    url=url_with_query,
                    url_path=url_path,
                    query_params=json.dumps(query_params),
                    body_params=json.dumps(body_params),
                    path_params=json.dumps(path_params),
                    cookie_params="{}",
                    case_type=case_type,
                    source="api-spec",
                    params_key_sig=params_sig,
                    request_variant_id=int(request_variant_id) if request_variant_id else None,
                    service_id=int(service_id) if service_id else None,
                    auth_context=auth_context,
                )
                count += 1
    finally:
        client.close()

    print(f"[ingest] Ingested {count} endpoints from spec (version {spec_version})")
