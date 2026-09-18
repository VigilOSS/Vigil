"""vigil assess contract — print stable CLI contract details for helper commands."""
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
            "  vigil assess contract finding record\n"
            "  vigil assess contract finding verify\n"
            "  vigil assess contract finding update\n"
            "  vigil assess contract intel record tech-component\n"
            "  vigil assess contract kali nmap-scan"
        ),
    )
    p.add_argument("name", help=f"Contract name ({', '.join(contract_names())})")
    p.add_argument(
        "variant",
        nargs="*",
        help="Optional contract variant token(s), e.g. `finding record` or `intel record tech-component`",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    name = args.name
    variant = getattr(args, "variant", None)
    if variant:
        # argparse gives `variant` as a list (nargs="*"): two tokens for
        # `finding record`, three for `intel record tech-component`. Accept a
        # bare string too, for callers that build a Namespace directly.
        parts = [variant] if isinstance(variant, str) else list(variant)
        name = " ".join([name, *parts])
    try:
        print(render_contract(name))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
