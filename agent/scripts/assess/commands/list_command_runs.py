"""assess.py list-command-runs — search the backend command-run audit log.

Use before re-running a Kali MCP command to check whether an equivalent
command already ran in the current engagement. Filter by agent, phase,
tool, success, timed-out, or keyword (FTS5).
"""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-command-runs",
        help="List Kali MCP command-run audit records for this engagement",
    )
    p.add_argument("--q", default="", help="Keyword search (FTS5) over command, tool, previews, suppression reasons")
    p.add_argument("--agent-name", dest="agent_name", default="", help="Filter to a single dispatching agent")
    p.add_argument("--phase", default="", help="Filter to a specific engagement phase")
    p.add_argument("--tool-name", dest="tool_name", default="", help="Filter to a single MCP tool (e.g. nmap_scan, execute_command)")
    status_group = p.add_mutually_exclusive_group()
    status_group.add_argument("--success", dest="success", action="store_true", help="Only successful runs")
    status_group.add_argument("--failed", dest="failed", action="store_true", help="Only failed runs (rc != 0 and not timed out)")
    p.add_argument("--timed-out", dest="timed_out", action="store_true", help="Only runs that hit the tool timeout")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--include-output", dest="include_output", action="store_true", help="Include stdout/stderr previews in default rendering")
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit raw JSON instead of a table")
    p.set_defaults(func=run)


def _build_query(args) -> str:
    params: list[tuple[str, str]] = []
    if args.q:
        params.append(("q", args.q))
    if args.agent_name:
        params.append(("agent_name", args.agent_name))
    if args.phase:
        params.append(("phase", args.phase))
    if args.tool_name:
        params.append(("tool_name", args.tool_name))
    if args.success:
        params.append(("success", "true"))
    if args.failed:
        params.append(("success", "false"))
    if args.timed_out:
        params.append(("timed_out", "true"))
    if args.include_output:
        params.append(("include_output", "true"))
    params.append(("limit", str(args.limit)))
    params.append(("offset", str(args.offset)))
    return "command-runs?" + urlencode(params, quote_via=quote)


def _render_table(rows: list[dict]) -> str:
    if not rows:
        return "(no command runs matched)"
    header = ["id", "created_at", "phase", "agent_name", "tool", "rc", "timed_out", "command"]
    lines = ["\t".join(header)]
    for row in rows:
        rc = row.get("return_code")
        rc_str = "-" if rc is None else str(rc)
        command = (row.get("command") or "").replace("\t", " ").replace("\n", " ⏎ ")
        if len(command) > 120:
            command = command[:117] + "..."
        lines.append(
            "\t".join(
                [
                    str(row.get("id", "")),
                    str(row.get("created_at", "")),
                    str(row.get("phase", "")),
                    str(row.get("agent_name", "")),
                    str(row.get("tool_name", "")),
                    rc_str,
                    "yes" if row.get("timed_out") else "no",
                    command,
                ]
            )
        )
    return "\n".join(lines)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        rows = client.get(_build_query(args))
    finally:
        client.close()

    if not isinstance(rows, list):
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    if args.as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    print(_render_table(rows))
