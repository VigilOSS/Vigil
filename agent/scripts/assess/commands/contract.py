"""vigil assess contract — print the contract for one helper-owned command."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.contracts import (
    CONTRACT_TRACKS,
    contract_names,
    render_contract,
    render_contract_examples,
    render_contract_notes,
    render_field_sections,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "contract",
        help="Show the usage, fields and an example for a helper-owned command",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Prints the compact view: usage, the fields the engagement's tracks write\n"
            "(one line each), one example, and a header that counts what it leaves out.\n\n"
            "Examples:\n"
            "  vigil assess contract finding record\n"
            "  vigil assess contract finding record --field details.evidence\n"
            "  vigil assess contract code-dispatch done\n"
            "  vigil assess contract intel record tech-component\n"
            "  vigil assess contract kali nmap-scan --notes"
        ),
    )
    p.add_argument("name", help=f"Contract name ({', '.join(contract_names())})")
    p.add_argument(
        "variant",
        nargs="*",
        help="Action or type token(s), e.g. `finding record`, `code-dispatch done`, `intel record tech-component`",
    )
    p.add_argument(
        "--field",
        dest="fields",
        action="append",
        default=[],
        metavar="NAME",
        help="Print everything the contract says about one field or flag (repeatable; a flag may be named without its dashes)",
    )
    p.add_argument("--notes", action="store_true", help="Print the notes, common mistakes and helper defaults")
    p.add_argument("--examples", action="store_true", help="Print every example")
    p.add_argument(
        "--track",
        dest="tracks",
        action="append",
        choices=CONTRACT_TRACKS,
        default=None,
        help=(
            "Show the fields of this track (repeatable; only the blue IR fields are track-bound). "
            "Default: the tracks in the engagement's scope.json, else every track"
        ),
    )
    p.set_defaults(func=run)


def _engagement_tracks(engagement_dir: str | None) -> tuple[tuple[str, ...] | None, str]:
    """The tracks the bound engagement's scope.json declares, and why not when none.

    The contract is readable outside an engagement, so a missing binding shows
    every track rather than failing. A scope.json that cannot be read as an
    object also shows every track, which hides nothing, and the second value
    names the problem for the header.
    """
    from assess.lib.config import resolve_engagement_dir
    from assess.lib.tracks import track_phases

    try:
        root = resolve_engagement_dir(engagement_dir)
    except (SystemExit, OSError):
        return None, ""
    path = Path(root) / "scope.json"
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ""
    except (OSError, ValueError) as exc:
        return None, f"{path} could not be read as JSON: {exc}"
    if not isinstance(scope, dict):
        return None, f"{path} is not a JSON object"
    if "tracks" in scope and not isinstance(scope["tracks"], dict):
        return None, f"{path} `tracks` is not an object"
    tracks = tuple(name for name in track_phases(scope) if name in CONTRACT_TRACKS)
    return (tracks, "") if tracks else (None, f"{path} declares no track")


def run(args) -> None:
    name = args.name
    variant = getattr(args, "variant", None)
    if variant:
        # argparse gives `variant` as a list (nargs="*"): two tokens for
        # `finding record`, three for `intel record tech-component`. Accept a
        # bare string too, for callers that build a Namespace directly.
        parts = [variant] if isinstance(variant, str) else list(variant)
        name = " ".join([name, *parts])
    fields = list(getattr(args, "fields", None) or [])
    show_notes = bool(getattr(args, "notes", False))
    show_examples = bool(getattr(args, "examples", False))
    try:
        if fields or show_notes or show_examples:
            blocks = []
            if fields:
                blocks.append(render_field_sections(name, fields))
            if show_notes:
                blocks.append(render_contract_notes(name))
            if show_examples:
                blocks.append(render_contract_examples(name))
            print("\n\n".join(blocks))
            return
        tracks = getattr(args, "tracks", None)
        source, fallback = "--track", ""
        if not tracks:
            tracks, fallback = _engagement_tracks(getattr(args, "engagement_dir", None))
            source = "the engagement's scope.json"
        print(render_contract(
            name, tracks=tracks, track_source=source if tracks else "", track_fallback=fallback
        ))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
