"""vigil assess command-run list — search the backend command-run audit log.

Use before re-running a `vigil assess kali` command to check whether an
equivalent command already ran in the current engagement. Filter by agent,
phase, tool, success, timed-out, technique, probe_kind, destructive, or
keyword (FTS5).
"""
from __future__ import annotations

import argparse
import json
import shlex
from urllib.parse import quote, urlencode

from assess.lib.audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import (
    ListPage,
    RemovedOptionAction,
    lookahead_limit,
    page_from_backend,
    report_page,
)


_MAX_BACKEND_LIMIT = 1000


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list",
        help="List `vigil assess kali` command-run audit records for this engagement",
    )
    p.add_argument("--q", default="", help="Fuzzy keyword search over command, tool, previews, metadata, and finding aliases")
    p.add_argument(
        "--sort",
        default="",
        choices=("", "relevance", "recent", "distant"),
        help="Sort mode. Defaults to relevance with --q and recent without --q; distant returns coverage-gap candidates.",
    )
    p.add_argument("--show-matches", action="store_true", help="Show why each row matched the query")
    p.add_argument("--exact", action="store_true", help="Disable fuzzy finding-alias expansion for --q")
    p.add_argument(
        "--all",
        action=RemovedOptionAction,
        nargs=0,
        const=(
            "command-run list --all was removed because it was ambiguous; use "
            "--match-all to require every query term or --paginate to fetch every result page"
        ),
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--match-all",
        dest="require_all",
        action="store_true",
        help=(
            "Require every term in --q to match (AND), while still expanding finding aliases. "
            "Combine `VA-047 OIDC` so rows must mention both the finding (in any alias form) "
            "and the topic. Mutually exclusive with --exact."
        ),
    )
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
    p.add_argument(
        "--audit-source",
        dest="audit_source",
        default="",
        choices=["", "header", "env_fallback", "mixed", "stdin", "argv"],
        help="Filter by attribution provenance",
    )
    p.add_argument(
        "--route",
        dest="route",
        default="",
        choices=["", "kali", "host_exec"],
        help="Filter by execution lane: host_exec = host-native recon recorded via "
             "`vigil assess host-exec`; kali = container-side. Empty = both.",
    )
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
            "Filter by tool-EXECUTION kind (fingerprint/baseline/payload/…), NOT "
            "the vuln family — so `--probe-kind sqli` correctly returns [] (sqli is "
            "an attack_family, not an execution kind). For vuln-family coverage use "
            "`fetch probe-runs?attack_family=…`. Exact match. Known values: "
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
    p.add_argument(
        "--output-attention",
        dest="output_attention",
        action="store_true",
        help=(
            "Only runs whose retained output is pending, deferred, untrusted, "
            "or failed integrity verification"
        ),
    )
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument(
        "--paginate",
        action="store_true",
        help="Fetch every result page from --offset through the final matching command run",
    )
    p.add_argument(
        "--include-output",
        dest="include_output",
        action="store_true",
        help=(
            "Ask the backend for the full stdout/stderr preview TEXT on every row. "
            "Only --json renders it — the table never has a preview column, it "
            "shows the out/err character counts instead. Listings are lightweight "
            "by default on purpose: 50 rows x 64 KiB of preview is a context bomb. "
            "For one run's output prefer `command-run get <id>`."
        ),
    )
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit raw JSON instead of a table")
    p.set_defaults(func=run)


def _build_query(
    args,
    *,
    limit: int | None = None,
    offset: int | None = None,
) -> str:
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
    if getattr(args, "route", ""):
        params.append(("route", args.route))
    if getattr(args, "technique", ""):
        params.append(("technique", args.technique))
    if getattr(args, "probe_kind", ""):
        params.append(("probe_kind", args.probe_kind))
    if getattr(args, "intent_q", ""):
        params.append(("intent_q", args.intent_q))
    if getattr(args, "sort", ""):
        params.append(("sort", args.sort))
    if getattr(args, "show_matches", False):
        params.append(("show_matches", "true"))
    if getattr(args, "exact", False):
        params.append(("exact", "true"))
    if getattr(args, "require_all", False):
        params.append(("require_all", "true"))
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
    if getattr(args, "output_attention", False):
        params.append(("output_attention", "true"))
    if args.include_output:
        params.append(("include_output", "true"))
    params.append(("limit", str(args.limit if limit is None else limit)))
    params.append(("offset", str(args.offset if offset is None else offset)))
    return "command-runs?" + urlencode(params, quote_via=quote)


def _continuation_command(args, offset: int) -> str:
    parts = ["vigil", "assess", "command-run", "list"]
    for attr, flag in (
        ("q", "--q"),
        ("sort", "--sort"),
        ("agent_name", "--agent-name"),
        ("phase", "--phase"),
        ("tool_name", "--tool-name"),
        ("tool_bin", "--tool-bin"),
        ("target_host", "--target-host"),
        ("audit_source", "--audit-source"),
        ("route", "--route"),
        ("technique", "--technique"),
        ("probe_kind", "--probe-kind"),
        ("intent_q", "--intent-q"),
    ):
        value = getattr(args, attr, "")
        if value:
            parts.extend((flag, shlex.quote(str(value))))
    for attr, flag in (
        ("show_matches", "--show-matches"),
        ("exact", "--exact"),
        ("require_all", "--match-all"),
        ("success", "--success"),
        ("failed", "--failed"),
        ("destructive", "--destructive"),
        ("not_destructive", "--not-destructive"),
        ("timed_out", "--timed-out"),
        ("output_attention", "--output-attention"),
        ("include_output", "--include-output"),
    ):
        if getattr(args, attr, False):
            parts.append(flag)
    parts.extend(("--limit", str(int(args.limit)), "--offset", str(offset)))
    return " ".join(parts)


def _preview_chars(row: dict, stream: str) -> int:
    """Characters of retained preview for ``stream`` on one listing row.

    A lightweight row carries the count in ``<stream>_preview_chars`` and an
    empty preview; a row fetched with --include-output carries the text and no
    count. Read whichever the backend sent so the column is right either way.
    """
    count = row.get(f"{stream}_preview_chars")
    if isinstance(count, int):
        return count
    return len(row.get(f"{stream}_preview") or "")


def _render_table(rows: list[dict]) -> str:
    if not rows:
        return "(no command runs matched)"
    header = [
        "id",
        "created_at",
        "phase",
        "agent_name",
        "tool",
        "route",
        "tech",
        "kind",
        "dest",
        "rc",
        "timed_out",
        # The affordance the lightweight-listing bandwidth control was designed
        # around: the preview TEXT is withheld, but its size is not, so a caller
        # can see a run DID produce output and decide whether `command-run get`
        # is worth the round-trip — instead of reading an empty preview as "no
        # output" and re-running the command.
        "out/err",
        "intent",
        "command",
    ]
    if any(row.get("matches") for row in rows):
        header.append("matches")
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
        route_raw = str(row.get("route") or "")
        if route_raw == "host_exec":
            route_display = "host"
        elif route_raw.startswith(("vigil assess kali/", "aith assess kali/")):
            # Transitional back-compat: pre-rename rows are stamped with the
            # old 'aith assess kali/<tool>' route prefix.
            route_display = "kali"
        else:
            route_display = "-"
        destructive = row.get("destructive")
        if destructive is None:
            dest_str = "-"
        else:
            dest_str = "yes" if destructive else "no"
        values = [
            str(row.get("id", "")),
            str(row.get("created_at", "")),
            str(row.get("phase", "")),
            str(row.get("agent_name", "")),
            tool_display,
            route_display,
            str(row.get("technique") or "-"),
            str(row.get("probe_kind") or "-"),
            dest_str,
            rc_str,
            "yes" if row.get("timed_out") else "no",
            f"{_preview_chars(row, 'stdout')}/{_preview_chars(row, 'stderr')}",
            intent or "-",
            command,
        ]
        if "matches" in header:
            matches = row.get("matches") or []
            values.append(",".join(str(item) for item in matches) or "-")
        lines.append("\t".join(values))
    return "\n".join(lines)


def run(args) -> None:
    limit = int(args.limit)
    offset = int(args.offset)
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if getattr(args, "paginate", False):
            rows = []
            next_offset = offset
            while True:
                result = client.get(_build_query(args, offset=next_offset))
                if not isinstance(result, list):
                    rows = result
                    break
                rows.extend(result)
                if len(result) < limit:
                    break
                next_offset += len(result)
        else:
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_BACKEND_LIMIT
            )
            rows = client.get(_build_query(args, limit=request_limit))

    if not isinstance(rows, list):
        raise AssessError("command-run list: expected a JSON array from the backend")

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
    rows = page.rows
    report_page(
        page,
        noun="command runs",
        continuation_command=_continuation_command(
            args, page.offset + len(page.rows)
        ),
        point_read_hint="`vigil assess command-run get <id>`",
    )
    if rows and args.include_output:
        warn_untrusted_data()

    if args.as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    print(_render_table(rows))
