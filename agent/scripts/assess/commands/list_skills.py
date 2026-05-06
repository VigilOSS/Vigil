"""aith assess list-skills — compact skill index for operator dispatch.

The operator and specialists used to read the full ~300-line `agent/SKILL.md`
index just to pick a skill. That wastes context tokens for what is really a
name + one-line "Use when" lookup. This command walks `agent/skills/*/SKILL.md`,
parses the YAML frontmatter `description` field, and emits a compact table
(default) or JSON (`--json`). The emitted skill name is always the directory
under `agent/skills/` because that is what `--skills` resolves on disk.

Adding a new skill is self-registering: drop a `SKILL.md` with proper YAML
frontmatter (`description:`; `name:` is optional metadata) into a new directory
under `agent/skills/` and `list-skills` picks it up on the next run. There is no
separate index file to maintain.

If the YAML frontmatter is missing a `description`, the first `# `-heading
line of the body is used as a fallback so partial skills are still
discoverable.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# Skills directory is resolved relative to this file's location:
# agent/scripts/assess/commands/list_skills.py -> agent/skills/
_SKILLS_DIR = Path(__file__).resolve().parents[3] / "skills"


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-skills",
        help="List available skills with compact descriptions",
        description=(
            "Walk agent/skills/*/SKILL.md, parse YAML frontmatter, and emit a "
            "compact skill index. Use this in place of reading agent/SKILL.md "
            "to pick the skill(s) for a dispatch."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit JSON instead of the default human-readable table",
    )
    p.add_argument(
        "--skills-dir",
        dest="skills_dir",
        default=None,
        help="Override the skills directory (default: agent/skills relative to this script)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    skills_dir = Path(args.skills_dir) if args.skills_dir else _SKILLS_DIR
    if not skills_dir.is_dir():
        print(f"skills directory not found: {skills_dir}", file=sys.stderr)
        sys.exit(2)

    rows = _collect_skills(skills_dir)

    if args.as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    if not rows:
        print("(no skills found)")
        return

    name_w = max(len("SKILL"), max(len(r["name"]) for r in rows))
    desc_w = min(80, max(len("DESCRIPTION"), max(len(r["description"]) for r in rows)))

    header = f"{'SKILL':<{name_w}}  {'DESCRIPTION':<{desc_w}}  PATH"
    print(header)
    print("-" * len(header))
    for row in rows:
        desc = row["description"]
        if len(desc) > desc_w:
            desc = desc[: desc_w - 1] + "\u2026"
        print(f"{row['name']:<{name_w}}  {desc:<{desc_w}}  {row['path']}")


def _collect_skills(skills_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
        meta = _parse_skill(skill_md)
        rows.append(
            {
                "name": skill_md.parent.name,
                "description": meta.get("description") or "(no description)",
                "path": str(skill_md.relative_to(skills_dir.parent.parent)),
            }
        )
    return rows


def _parse_skill(path: Path) -> dict[str, str]:
    """Parse YAML frontmatter for `name` / `description`.

    We do not pull in PyYAML to keep this command zero-dep — the frontmatter
    we own is simple `key: value` lines (no nested structures, no multi-line
    values), so a hand-rolled parser is sufficient and faster than importing
    YAML.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    meta: dict[str, str] = {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        # No frontmatter — fall back to the first H1 heading as the description.
        meta["description"] = _first_heading(lines)
        return meta

    for raw in lines[1:]:
        line = raw.rstrip()
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        # Strip matching surrounding quotes if present.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key in {"name", "description"}:
            meta[key] = value

    if "description" not in meta:
        meta["description"] = _first_heading(lines)

    return meta


def _first_heading(lines: list[str]) -> str:
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return ""
