"""aith assess validate-dispatch-contract — sanity-check a Specialist Dispatch Contract.

The operator-core "Specialist Dispatch Contract" is currently enforced only by
prose; this helper turns the contract table into a runnable validator so the
operator can pipe a JSON payload through before passing it to
``aith assess dispatch register --from-json <path>``.

Usage::

    aith assess validate-dispatch-contract path/to/dispatch.json
    cat dispatch.json | aith assess validate-dispatch-contract -
    cat dispatch.json | aith assess validate-dispatch-contract
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.contracts import (
    SPECIALIST_DISPATCH_MODES,
    SPECIALIST_DISPATCH_PERMISSIONS,
    validate_specialist_dispatch_contract,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "validate-dispatch-contract",
        help="Validate a Specialist Dispatch Contract JSON payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads the contract from a file path, '-' (stdin), or stdin when no\n"
            "argument is given. Prints OK on success or a list of errors and exits\n"
            "non-zero on failure. Warnings (e.g., files_allowed/files_forbidden\n"
            "overlap) print to stderr but do not fail the validation.\n\n"
            f"Permissions: {', '.join(SPECIALIST_DISPATCH_PERMISSIONS)}\n"
            f"Dispatch modes: {', '.join(SPECIALIST_DISPATCH_MODES)}"
        ),
    )
    p.add_argument(
        "source",
        nargs="?",
        default="-",
        help="Path to dispatch JSON, or '-' / omitted to read from stdin",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    source = args.source or "-"
    if source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(source, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            print(f"validate-dispatch-contract: cannot read {source}: {exc}", file=sys.stderr)
            sys.exit(1)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(
            f"validate-dispatch-contract: invalid JSON: {exc.msg} "
            f"at line {exc.lineno} column {exc.colno}",
            file=sys.stderr,
        )
        sys.exit(1)

    errors, warnings = validate_specialist_dispatch_contract(payload)
    for warning in warnings:
        print(f"WARN {warning}", file=sys.stderr)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        sys.exit(1)
    print("OK")
