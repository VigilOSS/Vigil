"""Advisory structural census for prompt standing load."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.prompt_census import collect_prompt_census


_PROMPT_ROOT = Path(__file__).resolve().parents[3]
# Walking past a checkout root would report an unrelated outer repository.
_VCS_MARKERS = (".jj", ".git")


def discover_checkout_prompt_root(start: Path) -> Path | None:
    """The agent prompt tree of the source checkout `start` sits in, if any.

    `vigil assess` execs the *installed* agent tree, so running this command from
    inside a checkout measures the installed prompts, not the ones being edited.
    That is the right default for an operator, and silently switching on cwd would
    only move the ambiguity — so the census names the checkout tree instead and
    leaves selecting it to `--prompt-root`.
    """
    for candidate in (start, *start.parents):
        if not any((candidate / marker).exists() for marker in _VCS_MARKERS):
            continue
        agent_root = candidate / "agent"
        return agent_root if (agent_root / "agents").is_dir() else None
    return None


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


def _standing_cell(role) -> str:
    if role["approximate_standing_bytes"] is not None:
        return str(role["approximate_standing_bytes"])
    totals = [
        int(variant["approximate_standing_bytes"])
        for variant in role["standing_byte_variants"]
    ]
    if not totals:
        return "unresolved"
    return f"{min(totals)}-{max(totals)}"


def run(args) -> None:
    read_bytes = args.read_bytes
    if read_bytes is not None and read_bytes < 0:
        raise SystemExit("prompt-census: --read-bytes must be zero or greater")
    prompt_root = (
        Path(args.prompt_root).resolve() if args.prompt_root else _PROMPT_ROOT
    )
    try:
        result = collect_prompt_census(prompt_root, read_bytes)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(f"prompt-census: {exc}") from exc

    result["prompt_root_source"] = "flag" if args.prompt_root else "running-script"
    unmeasured = (
        None
        if args.prompt_root
        else discover_checkout_prompt_root(Path.cwd())
    )
    if unmeasured is not None and unmeasured == prompt_root:
        unmeasured = None
    result["unmeasured_checkout_prompt_root"] = (
        str(unmeasured) if unmeasured is not None else None
    )

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"PROMPT_ROOT  {result['prompt_root']}  "
            f"(source: {result['prompt_root_source']})"
        )
        print("ROLE  ROLE_BYTES  APPROX_STANDING_BYTES  LOAD_FIRST  READ_VISIBILITY  ADVISORIES")
        for role in result["roles"]:
            expected = role["expected_sections"]
            detected = "/".join(name for name, present in expected.items() if present) or "none"
            print(
                f"{role['role']}  {role['role_bytes']}  "
                f"{_standing_cell(role)}  {detected}  "
                f"{role['read_visibility']}  {len(role['advisories'])}"
            )
            for variant in role["standing_byte_variants"]:
                print(
                    f"  {role['role']} [{variant['label']}]  "
                    f"{variant['approximate_standing_bytes']}"
                )
        print()
        print("OPERATOR_CORE  BYTES  LINES")
        if not result["operator_cores"]:
            print(f"(none found under {result['prompt_root']})")
        for core in result["operator_cores"]:
            print(f"{core['core']}  {core['bytes']}  {core['lines']}")

    if unmeasured is not None:
        print(
            f"ADVISORY prompt-census: measured {result['prompt_root']}; the source "
            f"checkout you are standing in has its own prompt tree at {unmeasured}, "
            f"which was NOT measured. Re-run with --prompt-root {unmeasured} to measure it",
            file=sys.stderr,
        )
    if result["advisory_count"]:
        print(
            f"ADVISORY prompt-census: {result['advisory_count']} structural/read observation(s); "
            "this command never gates work",
            file=sys.stderr,
        )
