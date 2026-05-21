"""aith assess artifact — indexed engagement artifact operations."""
from __future__ import annotations

import json
import sys
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "artifact",
        help="Search, get, register, and refresh indexed engagement artifacts.",
    )
    action_sub = p.add_subparsers(dest="action")
    action_sub.required = True

    # -- search ---------------------------------------------------------------
    sp_search = action_sub.add_parser("search", help="FTS search over indexed artifacts.")
    sp_search.add_argument("query", nargs="*", help="Search query words (joined with spaces)")
    sp_search.add_argument("--finding", default="", help="Filter/rank by finding slug")
    sp_search.add_argument("--kind", default="", help="Filter by artifact kind")
    sp_search.add_argument("--limit", type=int, default=50)
    sp_search.add_argument("--offset", type=int, default=0)
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
    header = ["id", "present", "scratch", "kind", "finding", "bytes", "path", "preview"]
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
                    str(row.get("relative_path") or ""),
                    preview or "-",
                ]
            )
        )
    return "\n".join(lines)


def _run_search(args) -> None:
    client = _client(args)
    try:
        query = " ".join(args.query).strip() if args.query else ""
        params: list[tuple[str, str]] = []
        if query:
            params.append(("q", query))
        if args.finding:
            params.append(("finding", args.finding))
        if args.kind:
            params.append(("kind", args.kind))
        params.append(("limit", str(args.limit)))
        params.append(("offset", str(args.offset)))
        endpoint = "artifacts/search"
        if params:
            endpoint += "?" + urlencode(params, quote_via=quote)
        rows = client.get(endpoint)
        print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))
    finally:
        client.close()


def _run_get(args) -> None:
    client = _client(args)
    try:
        row = client.get(f"artifacts/{args.artifact_id}")
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
        row = client.post("artifacts", payload)
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _render_rows([row]))
    finally:
        client.close()


def _run_refresh(args) -> None:
    client = _client(args)
    try:
        result = client.post("artifacts/refresh", {})
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
            row = client.post(
                f"artifacts/{int(target)}/scratch",
                {"scratch": scratch},
            )
        else:
            row = client.post(
                "artifacts/scratch-by-path",
                {"path": target, "scratch": scratch},
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
    ]
    if row.get("content"):
        lines.extend(["", str(row.get("content"))])
    elif row.get("preview_text"):
        lines.extend(["", str(row.get("preview_text"))])
    elif row.get("content_truncated"):
        lines.append("content: (too large; use the engagement-local path)")
    return "\n".join(lines)


def _refresh_text(result: dict) -> str:
    return (
        f"refreshed={result.get('refreshed', 0)} "
        f"present={result.get('present', 0)} "
        f"missing={result.get('missing', 0)}"
    )
