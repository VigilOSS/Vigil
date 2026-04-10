"""assess.py contract — print stable CLI contract details for helper commands."""
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
            "  assess.py contract record-finding\n"
            "  assess.py contract verify-finding\n"
            "  assess.py contract update-finding\n"
            "  assess.py contract reset-finding"
        ),
    )
    p.add_argument("name", help=f"Contract name ({', '.join(contract_names())})")
    p.set_defaults(func=run)


def run(args) -> None:
    try:
        print(render_contract(args.name))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
