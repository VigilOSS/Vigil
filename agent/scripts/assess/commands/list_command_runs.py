"""aith assess list-command-runs — search the backend command-run audit log.

Use before re-running an `aith assess kali` command to check whether an
equivalent command already ran in the current engagement. Filter by agent,
phase, tool, success, timed-out, technique, probe_kind, destructive, or
keyword (FTS5).
"""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from assess.lib.audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-command-runs",
        help="List `aith assess kali` command-run audit records for this engagement",
    )
    p.add_argument("--q", default="", help="Keyword search (FTS5) over command, tool, previews, suppression reasons")
    p.add_argument("--agent-name", dest="agent_name", default="", help="Filter to a single dispatching agent")
    p.add_argument("--phase", default="", help="Filter to a specific engagement phase")
    p.add_argument("--tool-name", dest="tool_name", default="", help="Filter to the route-derived tool label (e.g. nmap, command)")
    p.add_argument("--tool-bin", dest="tool_bin", default="", help="Filter to the argv[0] binary (e.g. curl, sqlmap) — useful for execute_command runs")
    p.add_argument(
        "--target-host",
        dest="target_host",
        default="",
        help=(
            "C30: filter to the parsed target host for httpx / nuclei / ffuf / sqlmap runs. "
            "Exact match (case-insensitive) against the target_host column. Unhandled verbs "
            "store an empty value; use --q for substring search on those rows."
        ),
    )
    p.add_argument("--audit-source", dest="audit_source", default="", choices=["", "header", "env_fallback", "mixed"], help="Filter by attribution provenance")
    p.add_argument(
        "--technique",
        dest="technique",
        default="",
        help=(
            "Filter by vulnerability-class technique (exact match; soft "
            "validation server-side). Known values: "
            + ", ".join(TECHNIQUE_ENUM)
        ),
    )
    p.add_argument(
        "--probe-kind",
        dest="probe_kind",
        default="",
        help=(
            "Filter by probe kind (exact match). Known values: "
            + ", ".join(PROBE_KIND_ENUM)
        ),
    )
    p.add_argument(
        "--intent-q",
        dest="intent_q",
        default="",
        help="FTS5 search scoped to the `intent:` column (command-metadata one-liner)",
    )
    status_group = p.add_mutually_exclusive_group()
    status_group.add_argument("--success", dest="success", action="store_true", help="Only successful runs")
    status_group.add_argument("--failed", dest="failed", action="store_true", help="Only failed runs (rc != 0 and not timed out)")
    destructive_group = p.add_mutually_exclusive_group()
    destructive_group.add_argument(
        "--destructive",
        dest="destructive",
        action="store_true",
        help="Only runs declared destructive (writes/edits/deletes on the target)",
    )
    destructive_group.add_argument(
        "--not-destructive",
        dest="not_destructive",
        action="store_true",
        help="Only runs explicitly declared non-destructive (read-only probes)",
    )
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
    if args.tool_bin:
        params.append(("tool_bin", args.tool_bin))
    if getattr(args, "target_host", ""):
        params.append(("target_host", args.target_host))
    if args.audit_source:
        params.append(("audit_source", args.audit_source))
    if getattr(args, "technique", ""):
        params.append(("technique", args.technique))
    if getattr(args, "probe_kind", ""):
        params.append(("probe_kind", args.probe_kind))
    if getattr(args, "intent_q", ""):
        params.append(("intent_q", args.intent_q))
    if args.success:
        params.append(("success", "true"))
    if args.failed:
        params.append(("success", "false"))
        if not args.timed_out:
            params.append(("timed_out", "false"))
    if getattr(args, "destructive", False):
        params.append(("destructive", "true"))
    if getattr(args, "not_destructive", False):
        params.append(("destructive", "false"))
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
    header = [
        "id",
        "created_at",
        "phase",
        "agent_name",
        "tool",
        "tech",
        "kind",
        "dest",
        "rc",
        "timed_out",
        "intent",
        "command",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        rc = row.get("return_code")
        rc_str = "-" if rc is None else str(rc)
        command = (row.get("command") or "").replace("\t", " ").replace("\n", " ⏎ ")
        if len(command) > 120:
            command = command[:117] + "..."
        intent = (row.get("intent") or "").replace("\t", " ").replace("\n", " ⏎ ")
        if len(intent) > 60:
            intent = intent[:57] + "..."
        tool_display = str(row.get("tool_bin") or row.get("tool_name") or "")
        route_tool = str(row.get("tool_name") or "")
        if tool_display and route_tool and tool_display != route_tool:
            tool_display = f"{tool_display}({route_tool})"
        destructive = row.get("destructive")
        if destructive is None:
            dest_str = "-"
        else:
            dest_str = "yes" if destructive else "no"
        lines.append(
            "\t".join(
                [
                    str(row.get("id", "")),
                    str(row.get("created_at", "")),
                    str(row.get("phase", "")),
                    str(row.get("agent_name", "")),
                    tool_display,
                    str(row.get("technique") or "-"),
                    str(row.get("probe_kind") or "-"),
                    dest_str,
                    rc_str,
                    "yes" if row.get("timed_out") else "no",
                    intent or "-",
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
