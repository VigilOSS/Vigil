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
        help="Sync, search, get, and register indexed engagement artifacts.",
    )
    p.add_argument("action", choices=("sync", "search", "get", "register"))
    p.add_argument("extra", nargs="*", help="search query, artifact id, or path depending on action")
    p.add_argument("--kind", default="")
    p.add_argument("--media-type", default="")
    p.add_argument("--finding", default="")
    p.add_argument("--agent-id", default="")
    p.add_argument("--agent-role", default="")
    p.add_argument("--command-run-id", type=int, default=None)
    p.add_argument("--sensitive", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--json", dest="as_json", action="store_true")
    p.set_defaults(func=run)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _render_rows(rows: list[dict]) -> str:
    if not rows:
        return "(no artifacts matched)"
    header = ["id", "present", "kind", "finding", "bytes", "path", "preview"]
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
                    str(row.get("kind") or "-"),
                    str(row.get("related_finding_slug") or "-"),
                    str(row.get("size_bytes") or 0),
                    str(row.get("relative_path") or ""),
                    preview or "-",
                ]
            )
        )
    return "\n".join(lines)


def run(args) -> None:
    client = _client(args)
    try:
        if args.action == "sync":
            result = client.post("artifacts/sync", {})
            print(json.dumps(result, indent=2, ensure_ascii=False) if args.as_json else _sync_text(result))
            return
        if args.action == "search":
            query = " ".join(args.extra).strip()
            params: list[tuple[str, str]] = []
            if query:
                params.append(("q", query))
            if args.finding:
                params.append(("finding", args.finding))
            params.append(("limit", str(args.limit)))
            params.append(("offset", str(args.offset)))
            endpoint = "artifacts/search"
            if params:
                endpoint += "?" + urlencode(params, quote_via=quote)
            rows = client.get(endpoint)
            print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))
            return
        if args.action == "get":
            if not args.extra:
                print("artifact get: artifact id is required", file=sys.stderr)
                sys.exit(1)
            row = client.get(f"artifacts/{int(args.extra[0])}")
            print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _artifact_text(row))
            return
        if args.action == "register":
            if not args.extra:
                print("artifact register: path is required", file=sys.stderr)
                sys.exit(1)
            payload = {
                "path": args.extra[0],
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
            return
    finally:
        client.close()
    raise SystemExit(f"unknown artifact action: {args.action}")


def _sync_text(result: dict) -> str:
    return (
        f"registered={result.get('registered', 0)} "
        f"present={result.get('present', 0)} "
        f"missing={result.get('missing', 0)}"
    )


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
