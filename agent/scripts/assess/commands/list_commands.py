"""vigil assess list-commands — per-phase catalog of helper-owned assess commands.

The operator and specialists used to scan the full contract table (or the
kali-exec verb menu) just to answer "which command do I run in phase N". This
command is the commands analogue of `list-skills` / `list-references`: a compact,
grouped-by-phase index sourced from `assess.lib.contracts` (the CommandContract
registry + the kali verb table via `contracts.all_command_contracts()`), so it
never drifts from the real CLI — a new command with a `phase` tag is picked up
automatically.

Each row points at `vigil assess contract <verb>` for the FULL schema (author-
supplied fields, helper defaults, allowed fields, examples). This command is
discovery; `contract` is the detail.

Filters:
  --phase <N>   show only commands meaningful in a canonical engagement phase
                (kali_audit.ALLOWED_PHASES; the `consume` short alias for
                `consume-test` is accepted).
  --kali-only   restrict to `kali <verb>` runtime-tool wrappers.
  --grep <s>    substring filter on command name or summary.
  --json        emit the structured rows (the downstream contract) instead of
                the grouped human table.

Phase-agnostic utilities (an empty `phase` tuple — recorded/queried in any
phase, e.g. resume-brief, artifact, http) are grouped separately at the bottom
of the default view and omitted from a `--phase` filter.
"""
from __future__ import annotations

import argparse
import json

from assess.lib import contracts


# `--phase` accepts every canonical phase plus the readiness command's short
# `consume` alias (both resolve via contracts.canonical_phase).
_PHASE_CHOICES = (*contracts.CATALOG_PHASES, "consume", "consume_test")


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-commands",
        help="List helper-owned assess commands grouped by engagement phase",
        description=(
            "Per-phase catalog of `vigil assess` commands, sourced from the "
            "contract registry. Use this to find which command to run in a "
            "phase; each row points at `vigil assess contract <verb>` for the "
            "full schema. Mirrors list-skills / list-references."
        ),
    )
    p.add_argument(
        "--phase",
        dest="phase",
        choices=_PHASE_CHOICES,
        default=None,
        help=(
            "Show only commands meaningful in this phase (canonical "
            "kali_audit.ALLOWED_PHASES vocabulary; `consume` is accepted as the "
            "short alias for `consume-test`)."
        ),
    )
    p.add_argument(
        "--kali-only",
        dest="kali_only",
        action="store_true",
        help="Restrict to `kali <verb>` runtime-tool wrappers.",
    )
    p.add_argument(
        "--grep",
        dest="grep",
        default=None,
        help="Show only commands whose name or summary contains this substring.",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit JSON rows instead of the default grouped-by-phase table.",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    phase_filter = contracts.canonical_phase(args.phase) if args.phase else None

    rows = _collect_rows()
    if args.kali_only:
        rows = [r for r in rows if r["kali"]]
    if args.grep:
        term = args.grep.lower().strip()
        rows = [r for r in rows if term in f"{r['name']} {r['summary']}".lower()]
    if phase_filter:
        rows = [r for r in rows if phase_filter in r["phases"]]

    if args.as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    if not rows:
        print("(no commands found)")
        return

    _print_grouped(rows, phase_filter=phase_filter)


def _collect_rows() -> list[dict]:
    rows: list[dict] = []
    for contract in contracts.all_command_contracts():
        rows.append(
            {
                "name": contract.name,
                "summary": contract.summary,
                "phases": list(contract.phase),
                "kali": contract.name.startswith("kali "),
                "contract": f"vigil assess contract {contract.name}",
            }
        )
    return sorted(rows, key=lambda r: r["name"])


def _print_grouped(rows: list[dict], *, phase_filter: str | None) -> None:
    by_phase: dict[str, list[dict]] = {}
    agnostic: list[dict] = []
    for row in rows:
        if row["phases"]:
            for phase in row["phases"]:
                by_phase.setdefault(phase, []).append(row)
        else:
            agnostic.append(row)

    if phase_filter:
        phases = [phase_filter]
    else:
        # Canonical CATALOG_PHASES order, only phases that actually have rows.
        phases = [p for p in contracts.CATALOG_PHASES if by_phase.get(p)]

    printed = False
    for phase in phases:
        group = sorted(by_phase.get(phase, []), key=lambda r: r["name"])
        if not group:
            continue
        if printed:
            print()
        print(f"## phase: {phase}")
        _print_table(group)
        printed = True

    # Phase-agnostic utilities only in the unfiltered view.
    if not phase_filter and agnostic:
        if printed:
            print()
        print("## phase-agnostic (utilities usable in any phase)")
        _print_table(sorted(agnostic, key=lambda r: r["name"]))


def _print_table(rows: list[dict]) -> None:
    name_w = max(len("COMMAND"), max(len(r["name"]) for r in rows))
    summ_w = min(70, max(len("SUMMARY"), max(len(r["summary"]) for r in rows)))
    header = f"{'COMMAND':<{name_w}}  {'SUMMARY':<{summ_w}}  CONTRACT"
    print(header)
    print("-" * len(header))
    for row in rows:
        summary = row["summary"]
        if len(summary) > summ_w:
            summary = summary[: summ_w - 1] + "…"
        print(f"{row['name']:<{name_w}}  {summary:<{summ_w}}  {row['contract']}")
