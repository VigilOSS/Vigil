"""Named cross-references in operator-loaded prompts resolve to their target.

Operator cores, shared constraints, phase docs, role prompts, skills, references
and rules point at each other's sections by name, e.g.
``"Runtime Identity Block" in `agent/operator-core.md``` or
```agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode"``. When a
section moves out of its file, every pointer still naming it sends the operator
to text that is not there. This guard checks that each such quoted name occurs
in the file it names.

It is a link-integrity check, not a wording test: it pins no heading or phrase
of the referencing file, and any section may be renamed or moved as long as the
pointers to it are updated with it. ``AGENTS.md`` is the rendered web operator
prompt, so a reference to it resolves against its source, ``operator-core.md``.
A path resolves from the repository root, then beside the referencing file, then
under the prompt roots, then as the one file of that name in the prompt tree; a
quote's closing sentence punctuation is not part of the section name.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AGENT = _REPO_ROOT / "agent"

_QUOTED = r'["“]([^"”\n]{3,90})["”]'
_MD_PATH = r"`((?:agent/)?[A-Za-z0-9_./-]+\.md)`"
_QUOTE_THEN_PATH = re.compile(_QUOTED + r"\s+(?:in|under|from|of)\s+" + _MD_PATH)
_PATH_THEN_QUOTE = re.compile(_MD_PATH + r"\s*[,(]?\s*" + _QUOTED)


def _referencing_files() -> list[Path]:
    return [
        _AGENT / "operator-core.md",
        _AGENT / "operator-core-code.md",
        _AGENT / "operator-core-blue.md",
        *sorted(_AGENT.glob("shared-*.md")),
        *sorted((_AGENT / "phases").glob("*.md")),
        *sorted((_AGENT / "agents").glob("*.md")),
        *sorted((_AGENT / "skills").glob("*/SKILL.md")),
        *sorted((_AGENT / "references").rglob("*.md")),
        *sorted((_AGENT / "rules").rglob("*.md")),
    ]


def _normalise(text: str) -> str:
    return re.sub(r"[`*_]", "", text).lower()


def _section_name(quote: str) -> str:
    """The quoted name without the sentence punctuation that closes it."""
    return quote.rstrip(".,;:")


# Bare names resolve the way the prompts use them: a role file, a skill directory,
# a runtime guide, a phase doc, or a rule.
_BARE_NAME_ROOTS = ("", "agents/", "skills/", "references/runtime-guides/", "phases/", "rules/")


def _in_prompt_tree(path: Path) -> bool:
    """A source file, not a rendered client wrapper tree (``.claude/``, ``.codex/`` ...)."""
    return not any(part.startswith(".") for part in path.relative_to(_AGENT).parts)


def _target(path_text: str, source: Path) -> Path | None:
    if path_text == "AGENTS.md":
        return _AGENT / "operator-core.md"
    candidates = [
        _REPO_ROOT / path_text,
        source.parent / path_text,
        *(_AGENT / f"{root}{path_text}" for root in _BARE_NAME_ROOTS),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    named = [path for path in _AGENT.rglob(path_text) if _in_prompt_tree(path)]
    return named[0] if len(named) == 1 else None


def _references(text: str) -> list[tuple[str, str]]:
    found = [(quote, path) for quote, path in _QUOTE_THEN_PATH.findall(text)]
    found += [(quote, path) for path, quote in _PATH_THEN_QUOTE.findall(text)]
    return found


def test_scanner_finds_both_reference_shapes() -> None:
    text = (
        'see "Alpha Section" in `agent/operator-core.md` and '
        '`agent/skills/nuclei-scanning/SKILL.md` "Beta Mode"'
    )
    assert sorted(_references(text)) == [
        ("Alpha Section", "agent/operator-core.md"),
        ("Beta Mode", "agent/skills/nuclei-scanning/SKILL.md"),
    ]


def test_operator_prompt_named_references_resolve() -> None:
    scanned = 0
    broken: list[str] = []
    for source in _referencing_files():
        for quote, path_text in _references(source.read_text(encoding="utf-8")):
            target = _target(path_text, source)
            if target is None:
                continue
            scanned += 1
            if _normalise(_section_name(quote)) not in _normalise(target.read_text(encoding="utf-8")):
                broken.append(f"{source.relative_to(_REPO_ROOT)}: {quote!r} not in {path_text}")
    assert scanned, "no named cross-references found; the scanner no longer matches the corpus"
    assert not broken, "named cross-references point at missing text:\n" + "\n".join(broken)
