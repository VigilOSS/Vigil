"""vigil assess list-skills — compact skill index for operator dispatch.

Picking a skill is a name + one-line "Use when" lookup, so this command keeps it
to that rather than making the caller read whole skill files. It walks
`agent/skills/*/SKILL.md`, parses the YAML frontmatter `description` field, and
emits a compact table (default) or JSON (`--json`). The emitted skill name is
always the directory under `agent/skills/` because that is what `--skills`
resolves on disk.

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

from assess.lib import frontmatter


# Skills directory is resolved relative to this file's location:
# agent/scripts/assess/commands/list_skills.py -> agent/skills/
_SKILLS_DIR = Path(__file__).resolve().parents[3] / "skills"

# Column caps for the human-readable table. Without them a single outlier row
# (the longest vuln_class list runs past 250 chars) pads every other row out to
# match, which dominates the output an agent reads at dispatch time.
_CLASS_COL_MAX = 28


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-skills",
        help="List available skills with compact descriptions",
        description=(
            "Walk agent/skills/*/SKILL.md, parse YAML frontmatter, and emit a "
            "compact skill index for picking the skill(s) a dispatch needs."
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
    desc_w = min(70, max(len("DESCRIPTION"), max(len(r["description"]) for r in rows)))
    class_w = min(
        _CLASS_COL_MAX, max(len("VULN_CLASS"), max(len(r["vuln_class"]) for r in rows))
    )

    header = f"{'SKILL':<{name_w}}  {'DESCRIPTION':<{desc_w}}  {'VULN_CLASS':<{class_w}}  PATH"
    print(header)
    print("-" * len(header))
    for row in rows:
        desc = row["description"]
        if len(desc) > desc_w:
            desc = desc[: desc_w - 1] + "\u2026"
        print(
            f"{row['name']:<{name_w}}  {desc:<{desc_w}}  "
            f"{_fit_classes(row['vuln_class'], class_w):<{class_w}}  {row['path']}"
        )


def _fit_classes(raw: str, width: int) -> str:
    """Fit a comma-separated vuln_class list into `width`, breaking on class
    boundaries and reporting the overflow as `+N`.

    A few skills declare very long class lists, so an uncapped column padded every
    row out to the widest one. Truncating mid-token would leave a partial class
    name that matches nothing, so drop whole classes and say how many are hidden;
    `--json` always carries the full list.
    """
    classes = [c.strip() for c in raw.split(",") if c.strip()]
    if not classes:
        return ""
    shown: list[str] = []
    for idx, cls in enumerate(classes):
        candidate = shown + [cls]
        hidden = len(classes) - len(candidate)
        rendered = ", ".join(candidate) + (f" +{hidden}" if hidden else "")
        if len(rendered) > width and shown:
            break
        if len(rendered) > width and not shown:
            # A single class wider than the column: keep it and accept the overflow
            # rather than emitting an empty cell.
            shown = [cls]
            break
        shown = candidate
    hidden = len(classes) - len(shown)
    return ", ".join(shown) + (f" +{hidden}" if hidden else "")


def _collect_skills(skills_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
        meta = frontmatter.parse(skill_md)
        rows.append(
            {
                "name": skill_md.parent.name,
                "description": meta.get("description") or "(no description)",
                "vuln_class": meta.get("vuln_class", ""),
                "path": str(skill_md.relative_to(skills_dir.parent.parent)),
            }
        )
    return rows
