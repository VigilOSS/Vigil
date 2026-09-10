"""vigil assess artifact — indexed engagement artifact operations."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from urllib.parse import quote, urlencode

from assess.lib.client import (
    AssessmentClient,
    AssessError,
    require_artifact_write_response,
    require_write_result,
)
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import ListPage, lookahead_limit, page_from_backend, report_page


_MAX_SEARCH_LIMIT = 1000


class _RemovedPositionalQueryAction(argparse.Action):
    """Reject the former positional query without advertising it in help."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if values:
            parser.error(
                "artifact search: positional query was removed; "
                "use --q \"<free-text query>\""
            )


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "artifact",
        help="Search, get, register, and refresh indexed engagement artifacts.",
    )
    action_sub = p.add_subparsers(dest="action")
    action_sub.required = True

    # -- search ---------------------------------------------------------------
    sp_search = action_sub.add_parser(
        "search",
        help="Search indexed artifacts by free text and/or typed filters.",
        description=(
            "Search indexed artifacts. Use --q for free text; combine it with "
            "--finding or --kind to narrow the result."
        ),
    )
    sp_search.add_argument(
        "--q",
        dest="query",
        default="",
        metavar="QUERY",
        help="Free-text query. Quote multi-word values.",
    )
    sp_search.add_argument(
        "removed_positional_query",
        nargs="*",
        action=_RemovedPositionalQueryAction,
        help=argparse.SUPPRESS,
    )
    sp_search.add_argument("--finding", default="", help="Filter/rank by finding slug")
    sp_search.add_argument("--kind", default="", help="Filter by artifact kind")
    sp_search.add_argument("--limit", type=int, default=50)
    sp_search.add_argument("--offset", type=int, default=0)
    sp_search.add_argument(
        "--paginate",
        action="store_true",
        help="Fetch every matching artifact page from --offset.",
    )
    sp_search.add_argument("--json", dest="as_json", action="store_true")
    sp_search.set_defaults(func=_run_search)

    # -- get ------------------------------------------------------------------
    sp_get = action_sub.add_parser("get", help="Fetch a single artifact by id.")
    sp_get.add_argument("artifact_id", type=int, help="Artifact id (integer)")
    sp_get.add_argument("--json", dest="as_json", action="store_true")
    sp_get.set_defaults(func=_run_get)

    # -- register -------------------------------------------------------------
    sp_register = action_sub.add_parser("register", help="Register an engagement-local file in the artifact index.")
    sp_register.add_argument("path", help="Relative or absolute path to the file (must be inside the engagement dir)")
    sp_register.add_argument("--kind", default="")
    sp_register.add_argument("--media-type", default="")
    sp_register.add_argument("--finding", default="", help="Link to finding slug")
    sp_register.add_argument("--agent-id", default="")
    sp_register.add_argument("--agent-role", default="")
    sp_register.add_argument("--command-run-id", type=int, default=None)
    sp_register.add_argument("--sensitive", action="store_true")
    sp_register.add_argument("--json", dest="as_json", action="store_true")
    sp_register.set_defaults(func=_run_register)

    # -- refresh --------------------------------------------------------------
    sp_refresh = action_sub.add_parser(
        "refresh",
        help="Refresh presence/hash metadata for already registered artifacts.",
    )
    sp_refresh.add_argument("--json", dest="as_json", action="store_true")
    sp_refresh.set_defaults(func=_run_refresh)

    # -- mark-scratch ---------------------------------------------------------
    sp_scratch = action_sub.add_parser("mark-scratch", help="Mark an artifact as scratch (excluded from report-readiness).")
    sp_scratch.add_argument("target", nargs="?", default=None, help="Artifact id (numeric) or relative path")
    sp_scratch.add_argument(
        "--under",
        default="",
        help="Path prefix to scratch in bulk (e.g. notes/scratch/). Mutually exclusive with target.",
    )
    sp_scratch.add_argument("--json", dest="as_json", action="store_true")
    sp_scratch.set_defaults(func=_run_scratch, scratch=True)

    # -- unmark-scratch -------------------------------------------------------
    sp_unscratch = action_sub.add_parser("unmark-scratch", help="Remove scratch mark from an artifact.")
    sp_unscratch.add_argument("target", nargs="?", default=None, help="Artifact id (numeric) or relative path")
    sp_unscratch.add_argument(
        "--under",
        default="",
        help="Path prefix to unscratch in bulk (e.g. notes/scratch/). Mutually exclusive with target.",
    )
    sp_unscratch.add_argument("--json", dest="as_json", action="store_true")
    sp_unscratch.set_defaults(func=_run_scratch, scratch=False)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _render_rows(rows: list[dict]) -> str:
    if not rows:
        return "(no artifacts matched)"
    header = [
        "id",
        "present",
        "scratch",
        "kind",
        "finding",
        "bytes",
        "indexed_bytes",
        "index_status",
        "path",
        "preview",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        preview = str(row.get("preview_text") or "").replace("\t", " ").replace("\n", " ")
        if len(preview) > 80:
            preview = preview[:77] + "..."
        lines.append(
            "\t".join(
                [
                    str(row.get("id", "")),
                    "yes" if row.get("present") else "no",
                    "yes" if row.get("scratch") else "no",
                    str(row.get("kind") or "-"),
                    str(row.get("related_finding_slug") or "-"),
                    str(row.get("size_bytes") or 0),
                    str(row.get("indexed_bytes") or 0),
                    str(row.get("index_status") or "unknown"),
                    str(row.get("relative_path") or ""),
                    preview or "-",
                ]
            )
        )
    return "\n".join(lines)


def _artifact_search_endpoint(args, *, limit: int, offset: int) -> str:
    query = str(args.query or "").strip()
    params: list[tuple[str, str]] = []
    if query:
        params.append(("q", query))
    if args.finding:
        params.append(("finding", args.finding))
    if args.kind:
        params.append(("kind", args.kind))
    params.extend((('limit', str(limit)), ('offset', str(offset))))
    return "artifacts/search?" + urlencode(params, quote_via=quote)


def _require_artifact_rows(value) -> list[dict]:
    if not isinstance(value, list) or any(
        not isinstance(row, dict)
        or not isinstance(row.get("id"), int)
        or isinstance(row.get("id"), bool)
        or row["id"] < 1
        or not isinstance(row.get("relative_path"), str)
        or not row["relative_path"].strip()
        or not isinstance(row.get("indexed_bytes"), int)
        or isinstance(row.get("indexed_bytes"), bool)
        or row["indexed_bytes"] < 0
        or row.get("index_status")
        not in {"complete", "missing", "not_text", "partial"}
        for row in value
    ):
        raise AssessError("artifact search: malformed artifact search response")
    return value


def _artifact_search_continuation(args, *, offset: int) -> str:
    parts = ["vigil", "assess", "artifact", "search"]
    for flag, value in (
        ("--q", str(args.query or "").strip()),
        ("--finding", args.finding),
        ("--kind", args.kind),
    ):
        if value:
            parts.extend((flag, str(value)))
    parts.extend(("--limit", str(args.limit), "--offset", str(offset)))
    return shlex.join(parts)


def _run_search(args) -> None:
    limit = int(args.limit)
    offset = int(args.offset)
    client = _client(args)
    try:
        if getattr(args, "paginate", False):
            rows: list[dict] = []
            next_offset = offset
            while True:
                page_rows = _require_artifact_rows(
                    client.get(
                        _artifact_search_endpoint(
                            args, limit=limit, offset=next_offset
                        )
                    )
                )
                rows.extend(page_rows)
                if len(page_rows) < limit:
                    break
                next_offset += len(page_rows)
        else:
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_SEARCH_LIMIT
            )
            rows = _require_artifact_rows(
                client.get(
                    _artifact_search_endpoint(
                        args, limit=request_limit, offset=offset
                    )
                )
            )
    finally:
        client.close()

    if getattr(args, "paginate", False):
        exact_total = offset + len(rows) if rows or offset == 0 else None
        page = ListPage(
            rows=rows,
            offset=offset,
            total=exact_total,
            total_at_least=exact_total,
            has_more=False,
        )
    else:
        page = page_from_backend(
            rows,
            limit=limit,
            offset=offset,
            used_lookahead=used_lookahead,
        )
    report_page(
        page,
        noun="artifacts",
        continuation_command=_artifact_search_continuation(
            args, offset=page.offset + len(page.rows)
        ),
        point_read_hint="`vigil assess artifact get <id>`",
    )
    rows = page.rows
    if rows:
        warn_untrusted_data()
    print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))


def _run_get(args) -> None:
    client = _client(args)
    try:
        row = client.get(f"artifacts/{args.artifact_id}")
        warn_untrusted_data()
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _artifact_text(row))
    finally:
        client.close()


def _run_register(args) -> None:
    client = _client(args)
    try:
        payload = {
            "path": args.path,
            "kind": args.kind,
            "media_type": args.media_type,
            "sensitive": bool(args.sensitive),
            "producer_agent_id": args.agent_id or None,
            "producer_agent_role": args.agent_role or None,
            "producer_command_run_id": args.command_run_id,
            "related_finding_slug": args.finding or None,
        }
        row = require_artifact_write_response(
            client.post("artifacts", payload),
            artifact_path=args.path,
            operation="register artifact",
        )
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _render_rows([row]))
    finally:
        client.close()


def _run_refresh(args) -> None:
    client = _client(args)
    try:
        result = require_write_result(
            client.post("artifacts/refresh", {}),
            operation="refresh artifacts",
            nonnegative_counts=("refreshed", "present", "missing"),
        )
        print(json.dumps(result, indent=2, ensure_ascii=False) if args.as_json else _refresh_text(result))
    finally:
        client.close()


def _run_scratch(args) -> None:
    scratch = args.scratch
    action_label = "mark-scratch" if scratch else "unmark-scratch"
    client = _client(args)
    try:
        under = (args.under or "").strip()
        if under:
            result = client.post(
                "artifacts/scratch-under",
                {"prefix": under, "scratch": scratch},
            )
            result = require_write_result(
                result,
                operation=f"artifact {action_label}",
                nonnegative_counts=("matched",),
            )
            updated = result.get("updated")
            if not isinstance(updated, list) or len(updated) != result["matched"]:
                raise AssessError(
                    f"artifact {action_label}: backend response paths do not match "
                    "its count; the write may have committed, so inspect durable "
                    "state and do not retry automatically"
                )
            if args.as_json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                matched = result.get("matched", 0)
                prefix_display = result.get("prefix") or under
                print(f"matched={matched} prefix={prefix_display}")
                if matched == 0:
                    print(
                        f"  (no indexed artifacts under {prefix_display!r}; "
                        "check with `artifact search` or register them first)"
                    )
                for path in (result.get("updated") or [])[:20]:
                    print(f"  - {path}")
                if matched > 20:
                    print(f"  - … and {matched - 20} more")
            return
        if args.target is None:
            print(f"artifact {action_label}: artifact id or path is required (or pass --under <prefix>)", file=sys.stderr)
            sys.exit(1)
        target = args.target
        if target.isdigit():
            row = require_write_result(
                client.post(
                    f"artifacts/{int(target)}/scratch",
                    {"scratch": scratch},
                ),
                operation=f"artifact {action_label}",
                expected={"id": int(target), "scratch": scratch},
            )
        else:
            row = require_artifact_write_response(
                client.post(
                    "artifacts/scratch-by-path",
                    {"path": target, "scratch": scratch},
                ),
                artifact_path=target,
                operation=f"artifact {action_label}",
            )
            if row.get("scratch") is not scratch:
                raise AssessError(
                    f"artifact {action_label}: backend response did not confirm the "
                    "requested state; the write may have committed, so inspect "
                    "durable state and do not retry automatically"
                )
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _render_rows([row]))
    finally:
        client.close()


def _artifact_text(row: dict) -> str:
    lines = [
        f"id: {row.get('id')}",
        f"path: {row.get('relative_path')}",
        f"kind: {row.get('kind')}",
        f"present: {'yes' if row.get('present') else 'no'}",
        f"bytes: {row.get('size_bytes')}",
        f"sha256: {row.get('sha256')}",
        f"indexed_bytes: {row.get('indexed_bytes')}",
        f"index_status: {row.get('index_status') or 'unknown'}",
        "content_truncated: "
        + (
            "yes"
            if row.get("content_truncated") is True
            else "no"
            if row.get("content_truncated") is False
            else "unknown"
        ),
    ]
    if row.get("content"):
        lines.extend(["", str(row.get("content"))])
    elif row.get("preview_text"):
        lines.extend(["", str(row.get("preview_text"))])
    if row.get("content_truncated"):
        lines.extend(
            [
                "",
                "content is truncated; use the engagement-local path for the remainder",
            ]
        )
    return "\n".join(lines)


def _refresh_text(result: dict) -> str:
    return (
        f"refreshed={result['refreshed']} "
        f"present={result['present']} "
        f"missing={result['missing']}"
    )
