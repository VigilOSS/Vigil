"""Advisory structural census for role prompts and mandatory standing load."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.prompt_census import collect_prompt_census


_PROMPT_ROOT = Path(__file__).resolve().parents[3]


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "prompt-census",
        help="Report advisory Load-First structure, byte cost, and partial-read visibility",
    )
    parser.add_argument(
        "--prompt-root",
        default=None,
        help="Override the agent prompt root (default: installed agent directory)",
    )
    parser.add_argument(
        "--read-bytes",
        type=int,
        default=None,
        help="Report whether this many bytes reaches all of each role's Load First section",
    )
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.set_defaults(func=run)


def run(args) -> None:
    read_bytes = args.read_bytes
    if read_bytes is not None and read_bytes < 0:
        raise SystemExit("prompt-census: --read-bytes must be zero or greater")
    prompt_root = Path(args.prompt_root) if args.prompt_root else _PROMPT_ROOT
    try:
        result = collect_prompt_census(prompt_root, read_bytes)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(f"prompt-census: {exc}") from exc

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print("ROLE  ROLE_BYTES  APPROX_STANDING_BYTES  LOAD_FIRST  READ_VISIBILITY  ADVISORIES")
    for role in result["roles"]:
        expected = role["expected_sections"]
        detected = "/".join(name for name, present in expected.items() if present) or "none"
        print(
            f"{role['role']}  {role['role_bytes']}  "
            f"{role['approximate_standing_bytes']}  {detected}  "
            f"{role['read_visibility']}  {len(role['advisories'])}"
        )
    if result["advisory_count"]:
        print(
            f"ADVISORY prompt-census: {result['advisory_count']} structural/read observation(s); "
            "this command never gates work",
            file=sys.stderr,
        )
