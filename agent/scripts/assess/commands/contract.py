"""aith assess contract — print stable CLI contract details for helper commands."""
from __future__ import annotations

import argparse
import sys

from assess.lib.contracts import contract_names, render_contract


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "contract",
        help="Show schema, defaults, and examples for a helper-owned CLI contract",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  aith assess contract record-finding\n"
            "  aith assess contract verify-finding\n"
            "  aith assess contract update-finding\n"
            "  aith assess contract reset-finding\n"
            "  aith assess contract record-intel tech-component"
        ),
    )
    p.add_argument("name", help=f"Contract name ({', '.join(contract_names())})")
    p.add_argument(
        "variant",
        nargs="?",
        help="Optional contract variant, e.g. record-intel tech-component",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    name = args.name
    variant = getattr(args, "variant", None)
    if variant:
        name = f"{name} {variant}"
    try:
        print(render_contract(name))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
