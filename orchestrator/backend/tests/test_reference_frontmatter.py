"""Drift guard: tool references must carry the frontmatter the discovery
pipeline keys on.

`vigil assess list-references` (agent/scripts/assess/commands/list_references.py)
finds and pairs references by parsing each file's YAML frontmatter — a `description`
and a `skill:` key. A reference that omits `skill:` is "orphaned": it never
appears under `vigil assess list-references --skill <name>`, so a threat hunter
who navigates by skill never discovers it. This test fails loudly when a new
tool reference ships without the keys (or with a `skill:` that does not resolve
to a real skill directory), so the orphaned-arjun.md class of bug cannot recur.

See the "Add a reference" recipe in the root AGENTS.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO / "agent" / "scripts"
_TOOLS = _REPO / "agent" / "references" / "tools"
_SKILLS = _REPO / "agent" / "skills"

# Tool references with no matching skill in the library yet — pairing them would
# require a skill that does not exist (online password brute, password cracking,
# capture proxy). They are intentionally unpaired until such a skill is authored.
# REMOVE an entry the moment you add its skill pairing.
_KNOWN_UNPAIRED = {
    "cracking/hashcat.md",
    "cracking/john.md",
    "exploitation/hydra.md",
    "proxy/mitmproxy.md",
}


@pytest.fixture(scope="module", autouse=True)
def _scripts_on_path():
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    yield


def _tool_refs() -> list[Path]:
    return sorted(_TOOLS.rglob("*.md"))


def _known_skill_names() -> set[str]:
    return {d.name for d in _SKILLS.iterdir() if (d / "SKILL.md").is_file()}


def test_tool_refs_exist():
    assert _tool_refs(), "no tool references found — path wrong?"


def test_every_tool_ref_has_description():
    from assess.lib import frontmatter

    missing = [
        str(p.relative_to(_TOOLS))
        for p in _tool_refs()
        if not (frontmatter.parse(p).get("description") or "").strip()
    ]
    assert not missing, f"tool refs missing a `description:` frontmatter key: {missing}"


def test_every_tool_ref_is_skill_paired():
    from assess.lib import frontmatter

    orphans = []
    for p in _tool_refs():
        rel = str(p.relative_to(_TOOLS))
        if rel in _KNOWN_UNPAIRED:
            continue
        if not (frontmatter.parse(p).get("skill") or "").strip():
            orphans.append(rel)
    assert not orphans, (
        "tool refs missing a `skill:` frontmatter key (so `list-references --skill` "
        f"never surfaces them): {orphans}. Add `skill: <name>`, or add to "
        "_KNOWN_UNPAIRED with a reason."
    )


def test_paired_skill_names_resolve_to_a_real_skill():
    from assess.lib import frontmatter

    known = _known_skill_names()
    bad: list[str] = []
    for p in _tool_refs():
        skills = (frontmatter.parse(p).get("skill") or "").strip()
        for name in (s.strip() for s in skills.split(",") if s.strip()):
            if name not in known:
                bad.append(f"{p.relative_to(_TOOLS)} -> '{name}'")
    assert not bad, f"tool refs reference a non-existent skill: {bad}"


def test_known_unpaired_allowlist_is_not_stale():
    # If an allowlisted ref has since been paired, drop it from _KNOWN_UNPAIRED.
    from assess.lib import frontmatter

    stale = []
    for rel in _KNOWN_UNPAIRED:
        p = _TOOLS / rel
        if p.is_file() and (frontmatter.parse(p).get("skill") or "").strip():
            stale.append(rel)
    assert not stale, f"these are paired now — remove from _KNOWN_UNPAIRED: {stale}"
