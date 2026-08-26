"""Record and resolve dynamic fixture ids for engagement PoCs.

This is intentionally a local file contract: a PoC observes its own JSON
response with ``fixture observe`` and later asks for a concrete id with
``fixture resolve``.  It does not contact the assessment backend or store
cookies and tokens.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.fixture_identity import (
    FixtureIdentityError,
    FixtureManifest,
    resolve_fixture_id,
)


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "fixture",
        help="Record or resolve rotation-safe fixture and session identifiers.",
    )
    actions = parser.add_subparsers(dest="fixture_action", required=True)

    observe = actions.add_parser(
        "observe",
        help="Extract ids from an observed JSON response and atomically save them.",
    )
    observe.add_argument("fixture_name", help="Manifest alias for this session or fixture.")
    observe.add_argument(
        "payload_file",
        nargs="?",
        default="-",
        help="JSON response path; omit or use '-' to read stdin.",
    )
    observe.add_argument("--manifest", required=True, help="Fixture manifest path.")
    observe.add_argument("--source", default="", help="Optional response/probe provenance.")
    observe.add_argument(
        "--replace",
        action="store_true",
        help="Allow an explicit id rotation for an existing alias.",
    )
    observe.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON.")
    observe.set_defaults(func=_run_observe)

    resolve = actions.add_parser("resolve", help="Resolve <fixture-name>.<field> to a concrete id.")
    resolve.add_argument("reference", help="Manifest reference, for example org3.organization_id.")
    resolve.add_argument("--manifest", required=True, help="Fixture manifest path.")
    resolve.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON.")
    resolve.set_defaults(func=_run_resolve)


def _read_payload(path: str) -> object:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _run_observe(args) -> None:
    try:
        payload = _read_payload(args.payload_file)
        manifest = FixtureManifest.load(args.manifest)
        observed = manifest.observe(
            args.fixture_name,
            payload,
            source=args.source,
            replace=args.replace,
        )
        manifest.save(args.manifest)
    except (OSError, json.JSONDecodeError, FixtureIdentityError) as exc:
        print(f"fixture observe: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if args.as_json:
        print(json.dumps({"fixture": args.fixture_name, "observed": observed}, indent=2))
    else:
        fields = ", ".join(f"{field}={value}" for field, value in sorted(observed.items()))
        print(f"fixture {args.fixture_name}: {fields or '(no ids found)'}")


def _run_resolve(args) -> None:
    try:
        manifest = FixtureManifest.load(args.manifest)
        value = resolve_fixture_id(manifest, args.reference)
    except (OSError, FixtureIdentityError, ValueError) as exc:
        print(f"fixture resolve: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if args.as_json:
        print(json.dumps({"reference": args.reference, "id": value}, indent=2))
    else:
        print(value)


def run(args) -> None:
    """Dispatch a registered fixture action (useful for direct callers/tests)."""

    args.func(args)
