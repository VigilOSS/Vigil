"""aith assess filter-scope — filter URL/host lists to scope.json hosts."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from assess.lib.config import load_config
from assess.lib.scope import host_from_token, host_in_scope, load_scope, scope_entries


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "filter-scope",
        help="Filter a URL/host list to entries matching scope.json hosts",
    )
    p.add_argument(
        "input_file",
        nargs="?",
        default="-",
        help="Input file with one URL/host per line, or '-' for stdin",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write filtered lines to this file instead of stdout",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    entries = scope_entries(load_scope(cfg.engagement_dir))

    lines = _read_lines(args.input_file)
    kept = [
        line
        for line in lines
        if _line_in_scope(line, entries)
    ]

    rendered = "".join(kept)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def _read_lines(input_file: str) -> list[str]:
    if input_file == "-":
        return sys.stdin.readlines()
    return Path(input_file).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)


def _line_in_scope(line: str, entries: list[dict[str, str]]) -> bool:
    value = line.strip()
    if not value or value.startswith("#"):
        return False
    host = host_from_token(value)
    return host_in_scope(host, entries)
