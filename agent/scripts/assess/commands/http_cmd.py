"""vigil assess http — query, export, and configure captured full-flow HTTP traffic.

Wires the Phase-5 canonical full-flow store and per-engagement capture policy
(``/assessment/http-flows`` + ``/assessment/capture-policy``) into first-class
operator verbs so captured mitmproxy traffic is queryable and exportable without
hand-rolling ``vigil assess fetch "http-flows?..."`` query strings.

Subverbs (subparser-with-subverbs pattern, mirrors ``artifact``):
  http list          GET /http-flows with server-side filters
  http show <flow>   GET /http-flows/{flow_uid} — full metadata + body previews
  http search <q>    convenience over `list` with the text query
  http export-har    GET /http-flows/export-har → write HAR 1.2 to -o <file>
  http import-har    POST /http-flows/import-har from a HAR file
  http policy        GET /capture-policy; `http policy set ...` PUTs a partial update

Capture is a per-engagement POLICY (backend state + a `capture-policy.json`
filesystem mirror the addon reads offline), NOT a proxy start selector — the
shared selector-less proxy routes by hostname and honours this policy per host.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


# Shared server-side filter flags for list / search / export-har. Query-param
# names mirror the backend GET /http-flows signature exactly (host, method,
# response_status, content_type_family, auth_context, truncated, q, limit,
# offset) so a filter drift on either side surfaces immediately.
def _add_filter_args(sp, *, with_q: bool = True) -> None:
    sp.add_argument("--host", default="", help="Filter by request host (exact).")
    sp.add_argument("--method", default="", help="Filter by HTTP method (GET/POST/...).")
    sp.add_argument(
        "--status",
        dest="status",
        default="",
        help="Filter by response status code (maps to response_status).",
    )
    sp.add_argument(
        "--content-type",
        dest="content_type",
        default="",
        help="Filter by content_type_family (json|html|xml|form|binary|unknown|...).",
    )
    sp.add_argument(
        "--auth-context",
        dest="auth_context",
        default="",
        help="Filter by captured auth_context (anonymous|<credential/role>).",
    )
    trunc = sp.add_mutually_exclusive_group()
    trunc.add_argument(
        "--truncated",
        dest="truncated",
        action="store_true",
        default=None,
        help="Only flows whose request OR response body was truncated at capture.",
    )
    trunc.add_argument(
        "--no-truncated",
        dest="truncated",
        action="store_false",
        help="Only flows with no truncated body (either side).",
    )
    if with_q:
        sp.add_argument("--q", default="", help="LIKE text query over url/path/host.")
    sp.add_argument("--limit", type=int, default=None, help="Max rows (backend caps at 5000).")
    sp.add_argument("--offset", type=int, default=None, help="Row offset for paging.")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "http",
        help="Query, export, and configure captured full-flow HTTP traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("http"),
    )
    action_sub = p.add_subparsers(dest="http_action")
    action_sub.required = True

    # -- list -----------------------------------------------------------------
    sp_list = action_sub.add_parser("list", help="List captured HTTP flows with server-side filters.")
    _add_filter_args(sp_list, with_q=True)
    sp_list.add_argument("--json", dest="as_json", action="store_true", help="Emit raw JSON rows.")
    sp_list.set_defaults(func=_run_list)

    # -- show -----------------------------------------------------------------
    sp_show = action_sub.add_parser("show", help="Show one flow's full metadata + body previews.")
    sp_show.add_argument("flow", help="flow_uid (or numeric id) of the captured flow.")
    sp_show.add_argument("--json", dest="as_json", action="store_true", help="Emit the raw JSON row.")
    sp_show.set_defaults(func=_run_show)

    # -- search ---------------------------------------------------------------
    sp_search = action_sub.add_parser("search", help="Text search over url/path/host (convenience over list).")
    sp_search.add_argument("query", nargs="*", help="Search words (joined with spaces → the LIKE `q`).")
    _add_filter_args(sp_search, with_q=False)
    sp_search.add_argument("--json", dest="as_json", action="store_true", help="Emit raw JSON rows.")
    sp_search.set_defaults(func=_run_search)

    # -- export-har -----------------------------------------------------------
    sp_export = action_sub.add_parser("export-har", help="Export filtered flows as a HAR 1.2 file.")
    _add_filter_args(sp_export, with_q=True)
    sp_export.add_argument("-o", "--output", required=True, help="Output path for the HAR file.")
    sp_export.set_defaults(func=_run_export_har)

    # -- import-har -----------------------------------------------------------
    sp_import = action_sub.add_parser("import-har", help="Import flows from a HAR file.")
    sp_import.add_argument("file", help="Path to the HAR file to import.")
    sp_import.add_argument("--json", dest="as_json", action="store_true", help="Emit the raw JSON response.")
    sp_import.set_defaults(func=_run_import_har)

    # -- policy ---------------------------------------------------------------
    sp_policy = action_sub.add_parser("policy", help="Show (or, via `set`, update) the capture policy.")
    sp_policy.add_argument("--json", dest="as_json", action="store_true", help="Emit the raw JSON policy.")
    sp_policy.set_defaults(func=_run_policy_get)
    policy_sub = sp_policy.add_subparsers(dest="policy_action")
    policy_sub.required = False
    sp_policy_set = policy_sub.add_parser("set", help="PUT a partial capture-policy update.")
    sp_policy_set.add_argument(
        "--enabled",
        dest="enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Enable/disable full-flow metadata recording. Body sidecars remain controlled "
            "independently by --capture-request-bodies/--capture-response-bodies. Default OFF."
        ),
    )
    sp_policy_set.add_argument(
        "--capture-request-bodies",
        dest="capture_request_bodies",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="When full-flow recording is enabled, persist request bodies as engagement-local sidecars.",
    )
    sp_policy_set.add_argument(
        "--capture-response-bodies",
        dest="capture_response_bodies",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="When full-flow recording is enabled, persist response bodies as engagement-local sidecars.",
    )
    sp_policy_set.add_argument(
        "--max-body-bytes",
        dest="max_body_bytes",
        type=int,
        default=None,
        help="Per-body capture cap in bytes (0..1073741824).",
    )
    sp_policy_set.add_argument(
        "--content-type-allow",
        dest="content_type_allow",
        action="append",
        default=None,
        metavar="CTYPE",
        help="Content-type allowlist entry (repeatable; comma-separated accepted).",
    )
    sp_policy_set.add_argument(
        "--content-type-deny",
        dest="content_type_deny",
        action="append",
        default=None,
        metavar="CTYPE",
        help="Content-type denylist entry (repeatable; comma-separated accepted).",
    )
    sp_policy_set.add_argument(
        "--redaction-profile",
        dest="redaction_profile",
        default=None,
        help="Named redaction profile (default 'none').",
    )
    sp_policy_set.set_defaults(func=_run_policy_set)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _flatten_ctypes(values) -> list[str]:
    """Flatten repeated / comma-separated content-type flags into a clean list."""
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _build_flow_query(args, *, q_value: str | None = None) -> str:
    """Assemble the /http-flows query string from the shared filter flags.

    Only non-empty values are emitted so an unset filter never over-constrains
    the server-side query. ``q_value`` overrides ``args.q`` (used by `search`,
    which takes the query as a positional)."""
    params: list[tuple[str, str]] = []
    host = getattr(args, "host", "") or ""
    if host:
        params.append(("host", host))
    method = getattr(args, "method", "") or ""
    if method:
        params.append(("method", method))
    status = getattr(args, "status", "") or ""
    if status:
        params.append(("response_status", status))
    content_type = getattr(args, "content_type", "") or ""
    if content_type:
        params.append(("content_type_family", content_type))
    auth_context = getattr(args, "auth_context", "") or ""
    if auth_context:
        params.append(("auth_context", auth_context))
    truncated = getattr(args, "truncated", None)
    if truncated is not None:
        params.append(("truncated", "true" if truncated else "false"))
    q = q_value if q_value is not None else (getattr(args, "q", "") or "")
    if q:
        params.append(("q", q))
    limit = getattr(args, "limit", None)
    if limit is not None:
        params.append(("limit", str(limit)))
    offset = getattr(args, "offset", None)
    if offset is not None:
        params.append(("offset", str(offset)))
    return urlencode(params, quote_via=quote)


def _flows_endpoint(query: str) -> str:
    return "http-flows" if not query else f"http-flows?{query}"


def _truncated_flag(row: dict) -> str:
    if row.get("request_body_truncated") or row.get("response_body_truncated"):
        return "yes"
    return "no"


def _render_rows(rows: list[dict]) -> str:
    if not rows:
        return "(no flows matched)"
    header = [
        "flow_uid",
        "method",
        "status",
        "host",
        "ctype",
        "auth",
        "trunc",
        "req_b",
        "resp_b",
        "url",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        url = str(row.get("url") or row.get("path") or "").replace("\t", " ")
        if len(url) > 80:
            url = url[:77] + "..."
        lines.append(
            "\t".join(
                [
                    str(row.get("flow_uid") or row.get("id") or "-"),
                    str(row.get("method") or "-"),
                    str(row.get("response_status") if row.get("response_status") is not None else "-"),
                    str(row.get("host") or "-"),
                    str(row.get("content_type_family") or "-"),
                    str(row.get("auth_context") or "-"),
                    _truncated_flag(row),
                    str(row.get("request_body_bytes") or 0),
                    str(row.get("response_body_bytes") or 0),
                    url or "-",
                ]
            )
        )
    return "\n".join(lines)


def _run_list(args) -> None:
    client = _client(args)
    try:
        query = _build_flow_query(args)
        rows = client.get(_flows_endpoint(query))
        if not isinstance(rows, list):
            rows = []
        print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))
    finally:
        client.close()


def _run_search(args) -> None:
    client = _client(args)
    try:
        q = " ".join(args.query).strip() if args.query else ""
        query = _build_flow_query(args, q_value=q)
        rows = client.get(_flows_endpoint(query))
        if not isinstance(rows, list):
            rows = []
        print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))
    finally:
        client.close()


def _flow_text(row: dict) -> str:
    lines = [
        f"flow_uid: {row.get('flow_uid') or '-'}",
        f"id: {row.get('id') if row.get('id') is not None else '-'}",
        f"request_variant_id: {row.get('request_variant_id') if row.get('request_variant_id') is not None else '-'}",
        f"method: {row.get('method') or '-'}",
        f"url: {row.get('url') or '-'}",
        f"host: {row.get('host') or '-'}  port: {row.get('port') if row.get('port') is not None else '-'}  scheme: {row.get('scheme') or '-'}",
        f"path: {row.get('path') or '-'}",
        f"response_status: {row.get('response_status') if row.get('response_status') is not None else '-'}",
        f"content_type_family: {row.get('content_type_family') or '-'}",
        f"auth_context: {row.get('auth_context') or '-'}",
        f"request_content_type: {row.get('request_content_type') or '-'}",
        f"response_content_type: {row.get('response_content_type') or '-'}",
        f"host_mismatch: {bool(row.get('host_mismatch'))}  redaction_status: {row.get('redaction_status') or '-'}",
        f"timing_ms: {row.get('timing_ms') if row.get('timing_ms') is not None else '-'}  started_at: {row.get('started_at') or '-'}",
    ]

    def _body_block(label: str, prefix: str) -> list[str]:
        return [
            "",
            f"{label} body:",
            f"  sha256: {row.get(prefix + '_body_sha256') or '-'}",
            f"  bytes: {row.get(prefix + '_body_bytes') or 0}"
            f"  truncated: {bool(row.get(prefix + '_body_truncated'))}",
            f"  artifact: {row.get(prefix + '_body_artifact_path') or '-'}",
        ]

    lines += _body_block("request", "request")
    lines += _body_block("response", "response")

    for label, key in (("request headers", "request_headers"), ("response headers", "response_headers")):
        headers = row.get(key)
        if isinstance(headers, dict) and headers:
            lines.append("")
            lines.append(f"{label}:")
            for name, value in headers.items():
                lines.append(f"  {name}: {value}")
    return "\n".join(lines)


def _run_show(args) -> None:
    client = _client(args)
    try:
        row = client.get(f"http-flows/{quote(str(args.flow), safe='')}")
        if not isinstance(row, dict):
            print(f"http show: unexpected response for {args.flow!r}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _flow_text(row))
    finally:
        client.close()


def _run_export_har(args) -> None:
    client = _client(args)
    try:
        query = _build_flow_query(args)
        endpoint = "http-flows/export-har" if not query else f"http-flows/export-har?{query}"
        har = client.get(endpoint)
    finally:
        client.close()
    if not isinstance(har, dict):
        print("http export-har: backend did not return a HAR object", file=sys.stderr)
        sys.exit(1)
    entries = har.get("log", {}).get("entries", []) if isinstance(har.get("log"), dict) else []
    out_path = Path(args.output)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(har, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(entries)} HAR entr{'y' if len(entries) == 1 else 'ies'} to {out_path}")


def _run_import_har(args) -> None:
    fp = Path(args.file)
    if not fp.is_file():
        print(f"http import-har: HAR file not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"http import-har: could not read HAR JSON: {exc}", file=sys.stderr)
        sys.exit(1)
    if isinstance(data, dict) and "log" in data:
        payload = {"log": data["log"]}
    elif isinstance(data, dict):
        # Bare HAR `log` object handed in without the wrapper.
        payload = {"log": data}
    else:
        print("http import-har: HAR file must be a JSON object", file=sys.stderr)
        sys.exit(1)

    client = _client(args)
    try:
        result = client.post("http-flows/import-har", payload)
    finally:
        client.close()
    if getattr(args, "as_json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    count = result.get("count", 0) if isinstance(result, dict) else 0
    print(f"Imported {count} flow(s) from {fp}")


def _render_policy(policy: dict) -> str:
    keys = (
        "enabled",
        "capture_request_bodies",
        "capture_response_bodies",
        "max_body_bytes",
        "content_type_allow",
        "content_type_deny",
        "redaction_profile",
    )
    lines = ["# Capture Policy"]
    for key in keys:
        if key in policy:
            lines.append(f"- {key}: {policy[key]}")
    for key, value in policy.items():
        if key not in keys:
            lines.append(f"- {key}: {value}")
    return "\n".join(lines)


def _run_policy_get(args) -> None:
    client = _client(args)
    try:
        policy = client.get("capture-policy")
    finally:
        client.close()
    if not isinstance(policy, dict):
        policy = {}
    print(json.dumps(policy, indent=2, ensure_ascii=False) if getattr(args, "as_json", False) else _render_policy(policy))


def _run_policy_set(args) -> None:
    payload: dict = {}
    if args.enabled is not None:
        payload["enabled"] = args.enabled
    if args.capture_request_bodies is not None:
        payload["capture_request_bodies"] = args.capture_request_bodies
    if args.capture_response_bodies is not None:
        payload["capture_response_bodies"] = args.capture_response_bodies
    if args.max_body_bytes is not None:
        payload["max_body_bytes"] = args.max_body_bytes
    if args.content_type_allow is not None:
        payload["content_type_allow"] = _flatten_ctypes(args.content_type_allow)
    if args.content_type_deny is not None:
        payload["content_type_deny"] = _flatten_ctypes(args.content_type_deny)
    if args.redaction_profile is not None:
        payload["redaction_profile"] = args.redaction_profile

    if not payload:
        print(
            "http policy set: pass at least one field to update "
            "(--enabled/--no-enabled, --capture-request-bodies, --capture-response-bodies, "
            "--max-body-bytes, --content-type-allow, --content-type-deny, --redaction-profile)",
            file=sys.stderr,
        )
        sys.exit(1)

    client = _client(args)
    try:
        policy = client.put("capture-policy", payload)
    finally:
        client.close()
    if not isinstance(policy, dict):
        policy = {}
    print(_render_policy(policy))
