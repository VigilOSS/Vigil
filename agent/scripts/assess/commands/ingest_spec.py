"""vigil assess ingest-spec — parse OpenAPI 3.x / Swagger 2.0 specs and generate coverage records."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from assess.lib.auth import auth_active_context
from assess.lib.bulk_ingest import DEFAULT_BULK_WRITE_SIZE, post_request_observations_bulk
from assess.lib.classify import classify_type
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.db import db_init, db_insert_work_item
from assess.lib.params import extract_url_path, generate_params_sig
from assess.lib.scope import host_admitted, ingest_scope_filter

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options", "trace")


def register(subparsers) -> None:
    p = subparsers.add_parser("ingest-spec", help="Ingest OpenAPI/Swagger spec into assessment state")
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("spec_file", help="Path to local spec file (no URLs)")
    p.set_defaults(func=run)


def _warn(message: str) -> None:
    print(f"ingest-spec: {message}", file=sys.stderr)




def _resolve_ref(node: Any, spec: dict, _seen: frozenset[str] = frozenset()) -> Any:
    """Resolve a local ``$ref`` (``#/components/...``) one hop, defensively.

    Only local JSON-pointer refs into the same document are resolved (remote
    refs and full JSON-pointer escaping are out of scope for attack-surface
    enumeration). A broken/cyclic ref WARNs and falls back to the node as-is so
    a single bad pointer never drops the whole operation — per the no-silent-
    drops doctrine, a missing param is a missing bug.
    """
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref:
        return node
    if not ref.startswith("#/"):
        _warn(f"unsupported non-local $ref '{ref}'; ignoring it (params may be incomplete)")
        return {k: v for k, v in node.items() if k != "$ref"}
    if ref in _seen:
        _warn(f"cyclic $ref '{ref}'; breaking the cycle")
        return {}
    target: Any = spec
    for token in ref.lstrip("#/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(target, dict) and token in target:
            target = target[token]
        else:
            _warn(f"could not resolve $ref '{ref}'; skipping it (params may be incomplete)")
            return {}
    return _resolve_ref(target, spec, _seen | {ref})




def _schema_property_names(schema: Any, spec: dict, _depth: int = 0) -> dict[str, str]:
    """Flatten an OpenAPI/JSON schema into ``{property_name: example_str}``.

    Handles, robustly (missing params = missing bugs):
    - ``$ref`` to ``#/components/schemas/...`` (resolved first),
    - object ``properties``,
    - array schemas (``type: array`` → recurse into ``items``),
    - composed schemas ``allOf`` / ``oneOf`` / ``anyOf`` (union of all branch
      properties so the full attack surface is enumerated, even for a oneOf
      where only one branch applies at runtime).
    Depth is bounded so a pathological self-referential schema cannot spin.
    """
    if _depth > 12 or not isinstance(schema, (dict, list)):
        return {}
    schema = _resolve_ref(schema, spec)
    if not isinstance(schema, dict):
        return {}

    props: dict[str, str] = {}

    direct = schema.get("properties")
    if isinstance(direct, dict):
        for name, prop in direct.items():
            prop = _resolve_ref(prop, spec) if isinstance(prop, dict) else prop
            example = ""
            if isinstance(prop, dict):
                example = str(prop.get("example") or prop.get("default") or "")
            props[str(name)] = example

    if schema.get("type") == "array" or "items" in schema:
        items = schema.get("items")
        if items is not None:
            props.update(_schema_property_names(items, spec, _depth + 1))

    for compose_key in ("allOf", "oneOf", "anyOf"):
        branches = schema.get(compose_key)
        if isinstance(branches, list):
            for branch in branches:
                props.update(_schema_property_names(branch, spec, _depth + 1))

    return props


def _request_body_params(operation: dict, spec: dict) -> dict[str, str]:
    """Extract body parameter names from an OpenAPI 3.x ``requestBody``.

    Covers JSON, form-urlencoded, and multipart/form-data content types (and any
    other ``*/*`` schema-bearing media type) — uploads and HTML forms are prime
    attack surface and were previously ignored. The ``requestBody`` itself may be
    a ``$ref``; each media type's schema is flattened via
    :func:`_schema_property_names` (arrays + composed schemas included).
    """
    request_body = _resolve_ref(operation.get("requestBody"), spec)
    if not isinstance(request_body, dict):
        return {}
    content = request_body.get("content")
    if not isinstance(content, dict):
        return {}
    body_params: dict[str, str] = {}
    for media_type, media_obj in content.items():
        if not isinstance(media_obj, dict):
            continue
        schema = media_obj.get("schema")
        if schema is None:
            continue
        body_params.update(_schema_property_names(schema, spec))
    return body_params




def _collect_parameters(raw_params: Any, spec: dict) -> list[dict]:
    """Resolve and normalize a ``parameters`` list ($ref entries resolved)."""
    if not isinstance(raw_params, list):
        return []
    resolved: list[dict] = []
    for param in raw_params:
        param = _resolve_ref(param, spec) if isinstance(param, dict) else param
        if isinstance(param, dict) and param.get("name"):
            resolved.append(param)
    return resolved


def _merge_parameters(path_level: list[dict], op_level: list[dict]) -> list[dict]:
    """Merge path-item parameters with operation parameters.

    Per the OpenAPI spec, operation-level parameters override path-level ones
    with the same ``(name, in)`` key; non-overridden path params still apply to
    the operation. Both used to be dropped when only operation params were read.
    """
    merged: dict[tuple[str, str], dict] = {}
    for param in path_level:
        merged[(param.get("name", ""), param.get("in", ""))] = param
    for param in op_level:
        merged[(param.get("name", ""), param.get("in", ""))] = param
    return list(merged.values())


def _param_example(param: dict) -> str:
    """Best-effort example string for a parameter (example/default/schema)."""
    if param.get("example") is not None:
        return str(param.get("example"))
    if param.get("default") is not None:
        return str(param.get("default"))
    schema = param.get("schema")
    if isinstance(schema, dict):
        return str(schema.get("example") or schema.get("default") or "")
    return ""




def _engagement_fallback_base(engagement_dir: str) -> str:
    """Derive a sensible absolute base from the engagement scope (S10 fallback).

    When a spec's ``servers`` url is relative (e.g. ``/api``) or missing, we
    resolve it against the engagement's own target host so paths still ingest
    instead of hard-exiting with zero coverage. Read-only use of the scope
    helpers; CIDR / unresolvable entries are skipped in favour of a real host.
    Returns ``""`` when no usable host can be found (caller WARNs and ingests
    paths with relative URLs rather than dropping the spec).
    """
    try:
        from assess.lib.scope import (
            host_admitted,
            load_scope,
            out_of_scope_entries,
            scope_entries,
        )
    except Exception:  # pragma: no cover - defensive
        return ""
    try:
        scope = load_scope(engagement_dir)
        entries = scope_entries(scope)
        deny = out_of_scope_entries(scope)
    except SystemExit:
        return ""
    except Exception:  # pragma: no cover - defensive
        return ""
    for kind_filter in (("bare_host", "url", "wildcard"), ("cidr",)):
        for entry in entries:
            if entry.get("entry_kind") in kind_filter:
                host = (entry.get("host") or "").strip()
                # Skip a host carved out by an out_of_scope denylist entry so the
                # fallback base never resolves to an OOS host. CIDR/wildcard
                # apexes that aren't concrete admittable hosts fall through the
                # allowlist check the same as before.
                if host and "/" not in host and host_admitted(host, entries, deny):
                    return f"https://{host}"
    return ""


def _resolve_base_url(spec: dict, spec_version: str, engagement_dir: str) -> str:
    """Resolve the spec base URL, tolerating relative/missing servers (S10).

    Never hard-exits. An absolute ``servers[0].url`` is used as-is; a RELATIVE
    one (``/api``) is joined onto the engagement target host so its paths ingest
    instead of failing the absolute-URL check and dropping the whole spec. If no
    base can be derived at all, WARNs and returns ``""`` (paths still ingest with
    relative URLs — degraded, but no silent loss of coverage).
    """
    if spec_version == "3":
        servers = spec.get("servers") or []
        raw = ""
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            raw = str(servers[0].get("url") or "")
        raw = raw.strip()
        if raw and raw.startswith(("http://", "https://")):
            return raw.rstrip("/")
        fallback = _engagement_fallback_base(engagement_dir)
        if raw:
            if fallback:
                joined = urljoin(fallback.rstrip("/") + "/", raw.lstrip("/"))
                _warn(
                    f"relative servers url '{raw}' resolved against engagement target "
                    f"-> '{joined}'"
                )
                return joined.rstrip("/")
            _warn(
                f"relative servers url '{raw}' and no engagement target host to resolve "
                "against; ingesting paths with relative URLs"
            )
            return raw.rstrip("/")
        if fallback:
            _warn(f"spec has no absolute servers url; using engagement target '{fallback}'")
            return fallback.rstrip("/")
        _warn("spec has no servers url and no engagement target host; ingesting relative URLs")
        return ""

    host = str(spec.get("host") or "").strip()
    base_path = str(spec.get("basePath") or "").strip()
    schemes = spec.get("schemes") or ["https"]
    scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
    if host:
        return f"{scheme}://{host}{base_path}".rstrip("/")
    fallback = _engagement_fallback_base(engagement_dir)
    if fallback:
        _warn(f"swagger spec has no host; using engagement target '{fallback}{base_path}'")
        return f"{fallback}{base_path}".rstrip("/")
    _warn("swagger spec has no host and no engagement target; ingesting relative URLs")
    return base_path.rstrip("/")


def run(args) -> None:
    db_path = args.db_path
    spec_file = args.spec_file

    if spec_file.startswith("http"):
        print("ERROR: ingest-spec no longer fetches target URLs directly.", file=sys.stderr)
        print("Fetch the spec through `vigil assess kali exec curl ...` first, save it locally, then rerun.", file=sys.stderr)
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

    base_url = _resolve_base_url(spec, spec_version, eng_dir)

    paths = spec.get("paths") or {}
    count = 0
    skipped = 0

    # Scope admission gate (defense-in-depth). Every operation in this spec shares
    # one base host, so a single check suffices. A spec that declares an ABSOLUTE
    # `servers`/`host` url (used as-is by _resolve_base_url) bypasses the
    # _engagement_fallback_base scope check — so an out-of-scope spec host would
    # otherwise ingest every operation as probeable work. Reachability is not
    # scope (shared-constraints §1): refuse the whole spec. Composes with the
    # relative/empty-base refusal below — spec_host is "" for a relative base, so
    # this check is skipped and that case falls through to the existing handler.
    # Inactive when scope.json has no allowlist (see scope.ingest_scope_filter).
    scope_allow, scope_deny, scope_filter_active = ingest_scope_filter(eng_dir)
    spec_host = (urlparse(base_url).hostname or "").rstrip(".").lower()
    if (
        scope_filter_active
        and spec_host
        and not host_admitted(spec_host, scope_allow, scope_deny)
    ):
        _warn(
            f"spec base host '{spec_host}' is out of scope (no scope.json allowlist "
            f"match, or matched an out_of_scope carve-out). Refusing to ingest any of "
            f"this spec's {len(paths)} path(s) — reachability is not scope. Add the "
            f"host to scope.json and re-run, or fetch a spec whose servers url is in scope."
        )
        print(
            f"[ingest] Ingested 0 endpoints from spec (version {spec_version}); "
            f"refused {len(paths)} path(s): base host out of scope (see warning above)"
        )
        return

    if not base_url.startswith(("http://", "https://")):
        _warn(
            f"spec base URL is relative/empty ('{base_url}') and no host could be "
            "resolved from scope — the backend requires ABSOLUTE request URLs, so none "
            f"of this spec's {len(paths)} path(s) can be ingested. Add a host to "
            "scope.json (or fetch the spec from a server with an absolute URL) and "
            "re-run `vigil assess ingest-spec`."
        )
        print(
            f"[ingest] Ingested 0 endpoints from spec (version {spec_version}); "
            f"skipped {len(paths)} path(s): relative/absent base URL (see warning above)"
        )
        return

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        pending_rows: list[dict] = []
        pending_observations: list[dict] = []

        def _record_response(row: dict, response: dict) -> bool:
            nonlocal count, skipped
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
                skipped += 1
                _warn(
                    f"backend response missing request_variant.id/service.id for "
                    f"{row['url']}; skipping this operation"
                )
                return False

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
                query_params=json.dumps(row["query_params"]),
                body_params=json.dumps(row["body_params"]),
                path_params=json.dumps(row["path_params"]),
                cookie_params=json.dumps(row["cookie_params"]),
                case_type=row["case_type"],
                source="api-spec",
                params_key_sig=row["params_sig"],
                request_variant_id=int(request_variant_id) if request_variant_id else None,
                service_id=int(service_id) if service_id else None,
                auth_context=auth_context,
            )
            count += 1
            return True

        def _flush_observations() -> None:
            nonlocal skipped
            if not pending_observations:
                return
            rows = list(pending_rows)
            observations = list(pending_observations)
            pending_rows.clear()
            pending_observations.clear()

            try:
                responses = post_request_observations_bulk(
                    client,
                    observations,
                    warn_prefix="ingest-spec",
                    fallback_individual=True,
                )
            except Exception as exc:  # noqa: BLE001 - preserve per-operation resilience
                _warn(
                    f"bulk backend ingest rejected {len(observations)} operation(s): "
                    f"{exc}; retrying individually"
                )
                for row, observation in zip(rows, observations, strict=True):
                    try:
                        response = client.post("request-observations", observation)
                    except Exception as row_exc:  # noqa: BLE001 - one bad op must not drop the spec
                        skipped += 1
                        _warn(f"backend rejected {row['method']} {row['url']}: {row_exc}; skipping this operation")
                        continue
                    _record_response(row, response)
                return

            for row, response in zip(rows, responses, strict=True):
                if isinstance(response, Exception):
                    skipped += 1
                    _warn(f"backend rejected {row['method']} {row['url']}: {response}; skipping this operation")
                    continue
                _record_response(row, response)

        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_item = _resolve_ref(path_item, spec)
            if not isinstance(path_item, dict):
                continue

            path_level_params = _collect_parameters(path_item.get("parameters"), spec)

            for method_lower, operation in path_item.items():
                if method_lower not in _HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    continue
                operation = _resolve_ref(operation, spec)
                if not isinstance(operation, dict):
                    continue

                method = method_lower.upper()
                full_url = f"{base_url}{path_key}"

                op_params = _collect_parameters(operation.get("parameters"), spec)
                parameters = _merge_parameters(path_level_params, op_params)

                query_params: dict[str, str] = {}
                path_params: dict[str, str] = {}
                header_params: dict[str, str] = {}
                cookie_params: dict[str, str] = {}
                for p in parameters:
                    location = p.get("in")
                    name = p.get("name")
                    if not name:
                        continue
                    example = _param_example(p)
                    if location == "query":
                        query_params[name] = example
                    elif location == "path":
                        path_params[name] = example
                    elif location == "header":
                        header_params[name] = example
                    elif location == "cookie":
                        cookie_params[name] = example

                body_params: dict[str, str] = {}
                if spec_version == "3":
                    body_params.update(_request_body_params(operation, spec))
                else:
                    for p in parameters:
                        if p.get("in") == "body":
                            schema = p.get("schema")
                            if schema is not None:
                                body_params.update(_schema_property_names(schema, spec))
                            break

                # Build URL with query params
                url_with_query = full_url
                if query_params:
                    qs = "&".join(f"{k}={v}" for k, v in query_params.items())
                    url_with_query = f"{full_url}?{qs}"

                url_path = extract_url_path(url_with_query)
                case_type = classify_type(method, url_path, "", "")
                params_sig = generate_params_sig(query_params, body_params)

                parsed = urlparse(url_with_query)
                observation = {
                    "url": url_with_query,
                    "method": method,
                    "auth_context": auth_context,
                    "content_type_family": "spec-derived",
                    "query_schema": query_params,
                    "body_schema": body_params,
                    "path_schema": path_params,
                    "cookie_schema": cookie_params,
                    "header_schema": header_params,
                    "path_template": parsed.path or path_key,
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

                pending_rows.append(
                    {
                        "method": method,
                        "url": url_with_query,
                        "url_path": url_path,
                        "query_params": query_params,
                        "body_params": body_params,
                        "path_params": path_params,
                        "cookie_params": cookie_params,
                        "case_type": case_type,
                        "params_sig": params_sig,
                    }
                )
                pending_observations.append(observation)
                if len(pending_observations) >= DEFAULT_BULK_WRITE_SIZE:
                    _flush_observations()
        _flush_observations()

    print(f"[ingest] Ingested {count} endpoints from spec (version {spec_version})")
    if skipped:
        _warn(f"skipped {skipped} operation(s) that could not be ingested (see warnings above)")
