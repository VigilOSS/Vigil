"""Referential integrity for the Dispatch-Mindset lens library.

The `agent/rules/mindsets/` library is the analytic-lens library the operator
injects into a dispatch (`mindset lens: agent/rules/mindsets/idor-bac.md —
<reason>`). That contract is prose: no `.py`/`.sh`/`.yml` in the repo parses it,
so nothing in CI could notice either half of its failure mode.

(a) DANGLING — a dispatch (or a role's Load First) that names
    `agent/rules/mindsets/typo.md` is a silent no-op: the specialist looks for
    the file, does not find it, and hunts with NO lens. Nothing errors; the
    dispatch just quietly loses the axis it was supposed to set. **Asserted
    (blocking).**

Why the split — the Markdown prompt/doc testing policy
=====================================================
`AGENTS.md` ("Markdown prompt/doc testing policy") forbids repository tests that
assert `.md` **wording, headings, or exact strings**, and Rule 10 of
`docs/prompt-authoring-standards.md` requires prompt/doc *health* signals to be
"a human authoring checklist plus, at most, an advisory WARN — never a blocking
CI wording test." The stated rationale is that wording/line-count assertions turn
normal prompt editing into fixture maintenance and reward preserving stale
phrasing. Both halves of this module were measured against that rationale:

* The DANGLING check asserts no prose at all. The only token it matches is a
  **filesystem path**, and the only thing it can assert about that path is
  `Path.is_file()`. Rewriting every sentence in the corpus never fails it;
  deleting or renaming a packet without updating its references does — which is
  a real broken link, not a phrasing preference. That is a durable contract over
  a code-owned surface (the files on disk), the exact category the policy says to
  keep. It is the same shape as `test_reference_frontmatter.py` in this
  directory, which blocks so "the orphaned-arjun.md class of bug cannot recur".
  Kept blocking.

Nothing here asserts heading text, prose wording, or a line count.

Reference corpus
================
Only the CANONICAL prompt sources count. The generated per-client mirrors
(`agent/.claude/`, `agent/.codex/`, `agent/.goose/`, `agent/.opencode/` —
rendered from `agent/agents/*.md` by `agent/scripts/render-operator-prompts.sh`)
are excluded on purpose: a mirror only ever contains a reference *because a
canonical file has one*, so counting them would let a canonical-side deletion
pass until the next render. `agent/rules/mindsets/` itself is excluded too — one
orphan packet cross-referencing another orphan packet is not "wired in".

Known limitation (documented so the next reader does not mistake it for a bug):
the advisory credits a packet for a *bare* `<name>.md` mention as well as a
full-path one, because the live corpus legitimately writes both forms. A bare
mention is only matched when it is NOT preceded by a path separator, so
`agent/agents/exploit-developer.md` never credits `developer.md`. A bare
`` `hunting.md` `` would credit a hypothetical `mindsets/hunting.md`, though — if
a future packet takes a name that collides with a top-level `agent/rules/` file,
tighten this to the full-path form for that name.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_AGENT = _REPO / "agent"
_MINDSETS = _AGENT / "rules" / "mindsets"

# Generated per-client prompt mirrors — never a source of truth for "is this
# packet wired in?". See the module docstring.
_MIRROR_DIRS = (".claude", ".codex", ".goose", ".opencode")


# --------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------
def _prompt_corpus() -> list[Path]:
    """Canonical operator/specialist prompt sources that can name a lens.

    Mirrors `test_skill_cli_sync.py::_doc_files` in spirit (the files an
    operator or specialist actually loads) but is restricted to the
    hand-authored `agent/` sources — the generated mirrors are excluded, see the
    module docstring.
    """
    files: list[Path] = []
    files += sorted(_AGENT.glob("operator-core*.md"))
    files += sorted(_AGENT.glob("shared-*.md"))
    files += sorted((_AGENT / "agents").glob("*.md"))
    files += sorted((_AGENT / "phases").glob("*.md"))
    # Top-level rules only: the mindsets/ subdirectory is the library under test.
    files += sorted((_AGENT / "rules").glob("*.md"))
    files += sorted((_AGENT / "references").rglob("*.md"))
    files += sorted((_AGENT / "skills").rglob("*.md"))
    for candidate in (
        _AGENT / "AGENTS.md",
        _AGENT / "SKILL.md",
        _REPO / "AGENTS.md",
        _REPO / "README.md",
    ):
        if candidate.is_file():
            files.append(candidate)
    return files


def _mindset_packets() -> list[Path]:
    return sorted(_MINDSETS.glob("*.md"))


# A reference to the library by path. The `agent/` prefix is optional because
# prose uses both `agent/rules/mindsets/x.md` and `rules/mindsets/x.md`.
_DIR_PREFIX = r"(?:(?:agent/)?rules/mindsets/)"
# Dangling scan: capture whatever filename follows the directory. The filename
# class deliberately excludes `<`/`>` so the template placeholders
# (`<agent/rules/mindsets/<name>.md>`, `<path under agent/rules/mindsets/>`) are
# not mistaken for a real path.
_PATH_REF_RE = re.compile(_DIR_PREFIX + r"([A-Za-z0-9][A-Za-z0-9._-]*\.md)")


def _reference_re(stem: str) -> re.Pattern[str]:
    """Match `<stem>.md`, with or without the library path prefix.

    The lookbehind rejects a bare name that is part of some *other* path
    (`agent/agents/exploit-developer.md` must not credit `developer.md`).
    """
    return re.compile(r"(?<![\w./-])" + _DIR_PREFIX + r"?" + re.escape(stem) + r"\.md\b")


@pytest.fixture(scope="module")
def corpus() -> list[tuple[str, str]]:
    """`(repo-relative path, text)` for every canonical prompt source."""
    files = _prompt_corpus()
    assert files, "prompt corpus is empty — a glob in _prompt_corpus is broken"
    # Anchor the corpus size: a glob that silently stops matching would make this
    # guard vacuously pass. The corpus is ~300 files; keep a generous floor that
    # still catches a collapse. This is a file COUNT of a directory tree, not a
    # per-file line count — it pins no prose.
    assert len(files) >= 200, (
        f"prompt corpus shrank to {len(files)} files — a glob in _prompt_corpus "
        "likely stopped matching; this guard would silently weaken."
    )
    return [
        (p.relative_to(_REPO).as_posix(), p.read_text(encoding="utf-8")) for p in files
    ]


# --------------------------------------------------------------------------
# Sanity: the guard is looking at the right tree.
# --------------------------------------------------------------------------
def test_mindset_library_is_non_empty():
    assert _MINDSETS.is_dir(), f"mindset library not found: {_MINDSETS}"
    assert _mindset_packets(), f"no mindset packets found under {_MINDSETS} — path wrong?"


def test_corpus_excludes_generated_mirrors(corpus):
    """The generated mirrors must never count as an inbound reference (they are
    derived from the canonical sources, so counting them would mask exactly the
    orphan case the advisory below reports)."""
    leaked = [
        rel
        for rel, _ in corpus
        if any(f"agent/{mirror}/" in rel for mirror in _MIRROR_DIRS)
    ]
    assert not leaked, (
        "generated prompt mirrors leaked into the reference corpus — a mirror "
        "reference only exists because a canonical file has one, so counting it "
        f"would mask an orphaned packet: {leaked}"
    )
    # And the mindset library is not its own witness.
    self_refs = [rel for rel, _ in corpus if rel.startswith("agent/rules/mindsets/")]
    assert not self_refs, (
        "mindset packets leaked into their own reference corpus — one orphan "
        f"packet citing another is not 'wired in': {self_refs}"
    )


# --------------------------------------------------------------------------
# (a) BLOCKING — every referenced packet path exists on disk.
# --------------------------------------------------------------------------
def test_every_referenced_mindset_path_exists(corpus):
    """Pure referential integrity: a path named in the corpus must resolve to a
    real file. A dispatch naming `agent/rules/mindsets/typo.md` is a silent
    no-op — the specialist finds no file and hunts with no lens, and nothing
    reports the loss.

    This asserts nothing about wording: it matches only a filesystem path and
    checks only that the file exists.
    """
    on_disk = {p.name for p in _mindset_packets()}
    dangling: list[str] = []
    for rel, text in corpus:
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _PATH_REF_RE.finditer(line):
                filename = match.group(1)
                if filename not in on_disk:
                    dangling.append(f"{rel}:{lineno}: agent/rules/mindsets/{filename}")
    assert not dangling, (
        "These prompt sources name a mindset packet that does not exist under "
        "agent/rules/mindsets/. A specialist told to load a missing lens hunts "
        "with NO lens and nothing reports the loss — fix the path, or add the "
        "packet:\n  "
        + "\n  ".join(sorted(set(dangling)))
        + "\n\nPackets that do exist: "
        + ", ".join(sorted(on_disk))
        + "\n(`vigil assess list-mindsets` enumerates them from disk.)"
    )
