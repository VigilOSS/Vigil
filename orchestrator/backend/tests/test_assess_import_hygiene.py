"""Guard: ``assess.*`` is importable under exactly one module path.

``agent/scripts`` is what goes on ``sys.path`` — by the ``assess.py`` launcher, by
``agent/scripts/assess/tests/conftest.py``, and by ``_load_assess_module`` in the
backend suite — so the canonical spelling for the agent-side packages is
``assess.lib.client``, ``assess.commands.log_entry``, and so on.

Several suites ALSO put the repo root on ``sys.path`` (to import ``tests.*`` and
``vigil_cli``). That makes ``agent.scripts.assess.lib.client`` resolve as well, via
implicit namespace packages — to a **second, independent copy** of the same source
file. Python keys module identity on the import path, not the file, so the two copies
have distinct class objects and distinct module-level singletons:

    >>> from assess.lib.client import AssessError as A
    >>> from agent.scripts.assess.lib.client import AssessError as B
    >>> A is B
    False

That is not a stylistic wart. ``except AssessError`` and ``pytest.raises(AssessError)``
both match on class *identity*, so a value raised by one copy passes straight through a
handler written against the other. This has already cost this repository three
mysteriously-failing tests in a single session, and the symptom (a raise that no
matching ``except`` catches) points nowhere near the cause (an import spelling several
thousand lines away).

The check is on source text rather than on ``sys.modules`` deliberately: a runtime check
only fires if the offending import has already executed, which makes it dependent on
test selection and ordering. Reading the sources catches a reintroduction under any
selection, including ``pytest -k`` on a single test.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

# Directories that are not this repository's source: virtualenvs, build output,
# tool caches, and the per-agent git worktrees under .claude/.
_SKIP_DIR_NAMES = {
    ".git",
    ".jj",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "third_party",
    "worktrees",
}

# `from agent.scripts... import ...` / `import agent.scripts...`, at any indent.
_ALIASED_IMPORT = re.compile(r"^\s*(?:from|import)\s+agent\.scripts\b")


def _repo_python_sources() -> list[Path]:
    sources: list[Path] = []
    for path in REPO_ROOT.rglob("*.py"):
        if _SKIP_DIR_NAMES.intersection(path.parts):
            continue
        sources.append(path)
    return sources


def test_no_source_imports_assess_under_the_repo_root_package_path() -> None:
    """No file may spell an agent-side import as ``agent.scripts.*``."""
    offenders: list[str] = []
    for path in _repo_python_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        if "agent.scripts" not in text:  # cheap reject before the per-line scan
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _ALIASED_IMPORT.match(line):
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}"
                )

    assert not offenders, (
        "These imports load a SECOND copy of an agent-side module, so its classes "
        "and module-level singletons stop comparing equal to the canonical ones "
        "(`except`/`pytest.raises` match on class identity). Spell them without the "
        "`agent.scripts.` prefix — e.g. `from assess.lib.client import AssessError` — "
        "and make sure `agent/scripts` is on sys.path:\n  " + "\n  ".join(offenders)
    )


def test_the_two_import_paths_really_would_be_distinct_modules(monkeypatch) -> None:
    """Pin the mechanism the lint exists for, so it is never 'cleaned up' as cosmetic.

    If a future Python or packaging change ever made these two spellings resolve to
    one module object, the lint above would be pure style and could be dropped. Until
    then this asserts the duplication is real and load-bearing.
    """
    import importlib.util
    scripts_root = REPO_ROOT / "agent" / "scripts"
    # pytest restores both entries after the test. Permanently inserting the
    # repo root here would create the very alternate import path this test is
    # meant to keep out of later test collection/execution.
    monkeypatch.syspath_prepend(str(scripts_root))
    monkeypatch.syspath_prepend(str(REPO_ROOT))

    canonical = importlib.util.find_spec("assess.lib.client")
    aliased = importlib.util.find_spec("agent.scripts.assess.lib.client")
    assert canonical is not None and aliased is not None
    assert canonical.origin == aliased.origin, "expected the same file on disk"
    assert canonical.name != aliased.name, (
        "the two spellings resolve to the same module name; the duplicate-copy "
        "hazard this lint guards is gone and the lint can be removed"
    )
