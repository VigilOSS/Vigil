"""vigil assess list-attempts — the READ counterpart to the probe-recording verbs.

Search the backend probe-attempt ledger (``assessment_probe_runs``) for this
engagement: every COVERING probe (``record-probe`` → tested|signal) and every
NON-covering attempt (``record-attempt`` → attempted|blocked|no-signal|error),
grouped by the LENS the probe ran under × its ``result_status``, with the
finding each row is linked to. Use it to answer "what have we already tried on
this host / family / lens, and did it lead to a finding?" before dispatching
more probing — the query-side mirror of record-probe / record-attempt.

Filter by finding slug, surface id, host, attack-family, result-status, or lens.
NOTE: ``--surface`` is a surface-ID here; the host/path-prefix vocabulary lives
on `vigil assess coverage` (application-units), not on this command.
"""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-attempts",
        help=(
            "List recorded probe attempts/probes (the read side of "
            "record-probe/record-attempt), grouped by lens × result_status."
        ),
    )
    p.add_argument(
        "--finding",
        dest="finding",
        default="",
        help="Filter to attempts linked to this finding slug (e.g. VA-047 / bola-users-endpoint)",
    )
    p.add_argument(
        "--surface",
        dest="surface",
        default="",
        help=(
            "Filter to attempts under this surface id. A surface-ID — NOT a host; "
            "use --host for host filtering (and `vigil assess coverage --host` for "
            "the application-unit coverage view)."
        ),
    )
    p.add_argument(
        "--host",
        dest="host",
        default="",
        help="Filter to a target host (exact, case-insensitive) against the target_host column",
    )
    p.add_argument(
        "--attack-family",
        dest="attack_family",
        default="",
        help="Filter to a vuln-class attack_family token (e.g. idor, bola, ssrf, sqli)",
    )
    p.add_argument(
        "--result-status",
        dest="result_status",
        default="",
        help=(
            "Filter to a probe result_status: covering (tested|signal) or "
            "non-covering (attempted|blocked|no-signal|error)."
        ),
    )
    p.add_argument(
        "--lens",
        dest="lens",
        default="",
        help="Filter to the free-text lens/mindset the probe ran under (e.g. tenant-boundary, blind-oob)",
    )
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit raw JSON instead of a grouped table",
    )
    p.set_defaults(func=run)


def _build_query(args) -> str:
    params: list[tuple[str, str]] = []
    if getattr(args, "finding", ""):
        params.append(("finding", args.finding))
    if getattr(args, "surface", ""):
        params.append(("surface_id", args.surface))
    if getattr(args, "host", ""):
        params.append(("target_host", args.host))
    if getattr(args, "attack_family", ""):
        params.append(("attack_family", args.attack_family))
    if getattr(args, "result_status", ""):
        params.append(("result_status", args.result_status))
    if getattr(args, "lens", ""):
        params.append(("lens", args.lens))
    params.append(("limit", str(args.limit)))
    params.append(("offset", str(args.offset)))
    return "attempts?" + urlencode(params, quote_via=quote)


def _finding_cell(row: dict) -> str:
    """Render a row's finding linkage as ``slug (severity)`` — or ``-`` if unlinked."""
    slug = str(row.get("finding_slug") or "").strip()
    if not slug:
        return "-"
    severity = str(row.get("finding_severity") or "").strip()
    return f"{slug} ({severity})" if severity else slug


def _render_table(rows: list[dict]) -> str:
    """Render attempts as a table GROUPED by ``lens × result_status``.

    Rows with no lens group under ``(no-lens)``; each group prints a header line
    then its member rows, so "which mindset produced which verdict" reads at a
    glance. Every row carries its finding linkage (slug + severity).
    """
    if not rows:
        return "(no attempts matched)"

    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        lens = str(row.get("lens") or "").strip() or "(no-lens)"
        status = str(row.get("result_status") or "").strip() or "(no-status)"
        groups.setdefault((lens, status), []).append(row)

    header = [
        "id",
        "host",
        "path",
        "port",
        "auth_context",
        "attack_family",
        "http",
        "signal",
        "tool",
        "agent",
        "finding",
        "created_at",
    ]
    out: list[str] = []
    for (lens, status) in sorted(groups):
        members = groups[(lens, status)]
        out.append(f"== lens={lens} | result_status={status} ({len(members)}) ==")
        out.append("\t".join(header))
        for row in members:
            http = row.get("observed_http_status")
            http_str = "-" if http is None else str(http)
            values = [
                str(row.get("id", "")),
                str(row.get("target_host") or ""),
                str(row.get("target_path") or ""),
                str(row.get("target_port") or "-"),
                str(row.get("auth_context") or "-"),
                str(row.get("attack_family") or "-"),
                http_str,
                str(row.get("signal_type") or "-"),
                str(row.get("tool_name") or "-"),
                str(row.get("agent_name") or "-"),
                _finding_cell(row),
                str(row.get("created_at") or ""),
            ]
            out.append("\t".join(values))
        out.append("")
    return "\n".join(out).rstrip("\n")


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        payload = client.get(_build_query(args))

    if args.as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    # Pinned shape: {"attempts": [...], "count": N}. Tolerate a bare list too.
    if isinstance(payload, dict):
        rows = payload.get("attempts") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    rows = [r for r in rows if isinstance(r, dict)]
    print(_render_table(rows))
