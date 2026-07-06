"""vigil assess scope-explain — read-only scope oracle for URLs/hosts.

Answers "is this in scope, and why?" for one or more url-or-host tokens without
touching the backend or the network. Every verdict is pure composition over the
scope primitives in ``assess.lib.scope`` (``load_scope`` + ``scope_entries`` +
``out_of_scope_entries`` + ``explain_target``): it reports the admission
decision, the exact allow/deny entry that drove it, the program's attribution
headers and rate ceiling, and a vendor-SaaS warning when the host's shape
matches a known SaaS-fronted suffix. No writes, no network.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.config import resolve_engagement_dir
from assess.lib.scope import (
    explain_target,
    load_scope,
    out_of_scope_entries,
    scope_entries,
)


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "scope-explain",
        help="Explain the scope verdict for one or more URLs/hosts (read-only)",
    )
    p.add_argument(
        "targets",
        nargs="*",
        help="URLs or hosts to explain (e.g. https://api.example.com or 10.0.0.5)",
    )
    p.add_argument(
        "--input-file",
        dest="input_file",
        default=None,
        help="Read additional URLs/hosts, one per line, from this file ('-' for stdin)",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the verdict structs as JSON instead of a table",
    )
    p.set_defaults(func=run)


def _gather_tokens(args: argparse.Namespace) -> list[str]:
    """Collect tokens from positionals then the optional input file / stdin.

    Blank lines and ``#`` comments in the input file are skipped, mirroring
    ``filter-scope``. Positionals are taken verbatim.
    """
    tokens: list[str] = list(args.targets or [])
    if args.input_file:
        for line in _iter_lines(args.input_file):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            tokens.append(value)
    return tokens


def _iter_lines(input_file: str):
    """Yield raw input lines from a file path, or stdin when ``input_file`` is '-'."""
    if input_file == "-":
        yield from sys.stdin
        return
    with Path(input_file).open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle


def run(args: argparse.Namespace) -> None:
    engagement_dir = resolve_engagement_dir(args.engagement_dir)
    scope = load_scope(engagement_dir)
    allow = scope_entries(scope)
    deny = out_of_scope_entries(scope)

    tokens = _gather_tokens(args)
    if not tokens:
        print(
            "scope-explain: no targets given; pass one or more URLs/hosts or "
            "--input-file <path>.",
            file=sys.stderr,
        )
        sys.exit(2)

    results = [explain_target(token, allow, deny, scope) for token in tokens]

    if args.as_json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    for result in results:
        _print_verdict(result)


def _print_verdict(result: dict) -> None:
    """Render one verdict struct as a compact human-readable block."""
    if result["host"] is None:
        verdict = "INVALID"
    elif result["admitted"]:
        verdict = "IN SCOPE"
    else:
        verdict = "OUT OF SCOPE"
    print(f"{result['target']}: {verdict} — {result['reason']}")

    if result["deny_entry"]:
        print(f"  deny entry: {result['deny_entry']} ({result['deny_entry_kind']})")
    if result["allow_entry"]:
        print(f"  allow entry: {result['allow_entry']} ({result['allow_entry_kind']})")
    if result["required_headers"]:
        rendered = ", ".join(
            f"{name}: {value}" for name, value in result["required_headers"].items()
        )
        print(f"  required-headers: {rendered}")
    if result["rate_limit"] is not None:
        print(f"  rate-limit: {result['rate_limit']} req/s")
    if result["vendor_saas"]:
        print(
            f"  WARN: {result['host']} matches vendor SaaS pattern "
            f"'{result['vendor_saas']}'. Surface to operator before recon dispatch.",
            file=sys.stderr,
        )
