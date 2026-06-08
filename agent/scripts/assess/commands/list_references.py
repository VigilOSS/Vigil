"""vigil assess list-references — compact reference index for operator dispatch.

The reference library under `agent/references/` used to be discoverable only via
a hand-maintained `INDEX.md`, which drifted from the files it described. This
command is the references analogue of `list-skills`: it walks
`agent/references/**/*.md`, parses each file's YAML frontmatter, and emits a
compact table (default) or JSON (`--json`). There is no separate index file to
maintain — drop a `.md` with a `description:` (and, where the pairing is
unambiguous, a `skill:`) into `agent/references/` and it is picked up on the
next run.

The emitted `name` is always the path relative to `agent/references/` minus the
`.md` extension (e.g. `payloads/sqli-payloads`), and `path` is the repo-relative
path the operator loads. Category is derived from the top-level directory via
`_DIR_CATEGORY` (overridable per file with a `category:` frontmatter key); the
group-level prose that used to live in INDEX.md section headers is preserved in
`_CATEGORY_INTRO`.

Frontmatter fields the command surfaces:
  description  (required; falls back to the first H1 heading)
  skill        (optional; one name or a comma-list — the paired skill[s])
  category     (optional; overrides the directory-derived category)
  source / languages / bucket / vuln_class / weight / origin  (optional;
               type-specific, echoed in --json — `bucket` is the gf-bucket
               name, `vuln_class` the canonical taxonomy term)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib import frontmatter


# References directory is resolved relative to this file's location:
# agent/scripts/assess/commands/list_references.py -> agent/references/
_REFS_DIR = Path(__file__).resolve().parents[3] / "references"

# Type-specific frontmatter keys echoed into the JSON output (when present).
_EXTRA_KEYS = ("source", "languages", "bucket", "vuln_class", "weight", "origin")

# First path segment under references/ -> human category label.
_DIR_CATEGORY: dict[str, str] = {
    "api-security": "OWASP API Security Top 10:2023",
    "access-control": "IDOR/BOLA Deep-Dives",
    "offensive-tactics": "Red Team TTPs (ired.team)",
    "active-directory": "AD & Kerberos Attacks (ired.team)",
    "payloads": "Attack Payload Library (PayloadsAllTheThings)",
    "code-vuln-patterns": "SAST-Surviving Vulnerability Patterns",
    "finding-verification": "Finding Verification Gates",
    "mobile": "Mobile (Android / iOS / Device Labs / Fuzzing)",
    "tools": "CLI Tool Cheatsheets",
    "gf-patterns": "GF Pattern Library",
    "runtime-guides": "Shared Runtime References",
    "recon": "Shared Runtime References",
    "probe-scripts": "Reusable Probe Examples",
    "tenants": "Client Tenant Context (IR)",
    "examples": "Disclosure & Reporting Formats",
}

# Category label -> one-line intro (the group "nuggets" the old INDEX.md
# section headers carried). Printed above each group in the table view.
_CATEGORY_INTRO: dict[str, str] = {
    "OWASP API Security Top 10:2023": "API-specific testing checklists.",
    "IDOR/BOLA Deep-Dives": "In-depth IDOR/BOLA references beyond the OWASP API1 checklist.",
    "Red Team TTPs (ired.team)": "Attack techniques organized by kill-chain phase.",
    "AD & Kerberos Attacks (ired.team)": "Active Directory attack techniques.",
    "Attack Payload Library (PayloadsAllTheThings)": "Copy-pasteable payloads organized by attack type.",
    "SAST-Surviving Vulnerability Patterns": (
        "Source-code vulnerability patterns that need multi-function reasoning — bugs that "
        "survive CodeQL, Semgrep, and OSS-Fuzz (multi-function chains, combinatorial arithmetic, "
        "state-machine bugs, incomplete patches)."
    ),
    "Mobile (Android / iOS / Device Labs / Fuzzing)": (
        "Authorized mobile security references for the android-app-security, ios-app-security, "
        "mobile-lab-setup, and mobile-fuzzing skills."
    ),
    "CLI Tool Cheatsheets": "Quick-reference per tool, organized by usage phase.",
    "GF Pattern Library": (
        "Per-bucket reference files for the URL classifier, keyed to the buckets that "
        "assess.lib.classify_buckets defines (matching keys/paths, baseline priority weight, "
        "examples, false-positive surface)."
    ),
    "Finding Verification Gates": "Verify-time false-positive and severity-downgrade gates.",
    "Shared Runtime References": "Shared operator/runtime references and rate-calibration tables.",
    "Reusable Probe Examples": (
        "Validated, copy-and-parametrize single-file Python probes for the write-probe-script "
        "capability. Scaffold with `vigil assess scaffold-probe <name>`; run via `vigil assess kali exec`."
    ),
    "Client Tenant Context (IR)": (
        "Per-tenant reference files for recurring Workspace IR work — load the relevant file at "
        "the start of any alert investigation for that tenant."
    ),
    "Disclosure & Reporting Formats": "Disclosure-email / bug-bounty submission formats and worked examples.",
}

_DEFAULT_CATEGORY = "Other References"

# Display order for category groups (mirrors the old INDEX.md ordering); any
# category not listed sorts after these, alphabetically.
_CATEGORY_ORDER = [
    "OWASP API Security Top 10:2023",
    "IDOR/BOLA Deep-Dives",
    "Red Team TTPs (ired.team)",
    "AD & Kerberos Attacks (ired.team)",
    "Attack Payload Library (PayloadsAllTheThings)",
    "SAST-Surviving Vulnerability Patterns",
    "Finding Verification Gates",
    "Mobile (Android / iOS / Device Labs / Fuzzing)",
    "CLI Tool Cheatsheets",
    "GF Pattern Library",
    "Shared Runtime References",
    "Reusable Probe Examples",
    "Disclosure & Reporting Formats",
    "Client Tenant Context (IR)",
]


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-references",
        help="List available references with compact descriptions",
        description=(
            "Walk agent/references/**/*.md, parse YAML frontmatter, and emit a compact "
            "reference index. Use this in place of reading a maintained index file to find "
            "the payload libraries, checklists, and cheatsheets paired with a skill. "
            "`--skill <name>` shows only the references paired to that skill."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit JSON instead of the default human-readable table",
    )
    p.add_argument(
        "--skill",
        dest="skill",
        default=None,
        help="Show only references whose `skill:` frontmatter includes this skill name",
    )
    p.add_argument(
        "--category",
        dest="category",
        default=None,
        help="Show only references in this category label (case-insensitive)",
    )
    p.add_argument(
        "--grep",
        dest="grep",
        default=None,
        help="Show only references whose name or description contains this substring",
    )
    p.add_argument(
        "--refs-dir",
        dest="refs_dir",
        default=None,
        help="Override the references directory (default: agent/references relative to this script)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    refs_dir = Path(args.refs_dir) if args.refs_dir else _REFS_DIR
    if not refs_dir.is_dir():
        print(f"references directory not found: {refs_dir}", file=sys.stderr)
        sys.exit(2)

    rows = _collect_references(refs_dir)

    if args.skill:
        wanted = args.skill.strip().lower()
        rows = [r for r in rows if wanted in _skill_list(r["skill"])]
    if args.category:
        wanted = args.category.strip().lower()
        rows = [r for r in rows if r["category"].lower() == wanted]
    if args.grep:
        term = args.grep.lower()
        rows = [r for r in rows if term in f"{r['name']} {r['description']}".lower()]

    if args.as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    if not rows:
        print("(no references found)")
        return

    _print_grouped(rows)


def _collect_references(refs_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    repo_root = refs_dir.parent.parent
    for md in sorted(refs_dir.rglob("*.md")):
        meta = frontmatter.parse(md)
        rel = md.relative_to(refs_dir)
        row: dict[str, str] = {
            "name": rel.with_suffix("").as_posix(),
            "description": meta.get("description") or "(no description)",
            "skill": meta.get("skill", ""),
            "category": meta.get("category") or _category_for(rel),
            "path": str(md.relative_to(repo_root)),
        }
        for key in _EXTRA_KEYS:
            if meta.get(key):
                row[key] = meta[key]
        rows.append(row)
    return rows


def _category_for(rel: Path) -> str:
    parts = rel.parts
    if len(parts) > 1:
        return _DIR_CATEGORY.get(parts[0], _DEFAULT_CATEGORY)
    return _DEFAULT_CATEGORY


def _skill_list(value: str) -> list[str]:
    return [s.strip().lower() for s in value.split(",") if s.strip()]


def _category_sort_key(label: str) -> tuple[int, str]:
    try:
        return (_CATEGORY_ORDER.index(label), "")
    except ValueError:
        return (len(_CATEGORY_ORDER), label.lower())


def _print_grouped(rows: list[dict[str, str]]) -> None:
    # Column widths computed across all displayed rows for consistent alignment.
    name_w = max(len("NAME"), max(len(r["name"]) for r in rows))
    skill_w = max(len("SKILL"), max(len(r["skill"]) for r in rows))
    desc_w = min(70, max(len("DESCRIPTION"), max(len(r["description"]) for r in rows)))

    categories = sorted({r["category"] for r in rows}, key=_category_sort_key)
    for idx, category in enumerate(categories):
        if idx:
            print()
        print(f"## {category}")
        intro = _CATEGORY_INTRO.get(category)
        if intro:
            print(intro)
        print()
        header = f"{'NAME':<{name_w}}  {'DESCRIPTION':<{desc_w}}  {'SKILL':<{skill_w}}  PATH"
        print(header)
        print("-" * len(header))
        for row in sorted((r for r in rows if r["category"] == category), key=lambda r: r["name"]):
            desc = row["description"]
            if len(desc) > desc_w:
                desc = desc[: desc_w - 1] + "…"
            print(f"{row['name']:<{name_w}}  {desc:<{desc_w}}  {row['skill']:<{skill_w}}  {row['path']}")
