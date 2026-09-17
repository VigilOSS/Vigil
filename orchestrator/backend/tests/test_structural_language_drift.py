"""The backend's language lists are mirrors of the agent-side canonical set.

Both are hand-maintained frozensets that duplicate
`agent/scripts/assess/lib/code_languages.py:CANONICAL_CODE_LANGUAGES`, and
nothing made them agree. The cost is not cosmetic: `canonical_structural_language`
is called over EVERY file in a repository from `structural_input_identity_digest`,
so one file in a language the backend has never heard of makes
`vigil assess code-index sync` return 400 for the whole repository. That had
already shipped for `.ps1`, unnoticed, before FreeMarker support arrived and hit
the same wall.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT / "agent" / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "agent" / "scripts"))

from assess.lib.code_languages import (  # noqa: E402
    CANONICAL_CODE_LANGUAGES,
    CODE_LANGUAGE_ALIASES,
    STRUCTURAL_SUPPORTED_LANGUAGES,
)


def test_the_backend_accepts_every_language_the_agent_can_detect() -> None:
    """A language the agent classifies must be a language the backend will store.

    Subset, not equality: the backend also accepts spelling aliases the agent
    never emits (`c++`), and accepting more than we can produce is harmless.
    Producing more than the backend accepts is a 400 on the whole repository.
    """
    from app.services.code_analysis import _CANONICAL_STRUCTURAL_LANGUAGES

    missing = sorted(set(CANONICAL_CODE_LANGUAGES) - set(_CANONICAL_STRUCTURAL_LANGUAGES))
    assert missing == [], (
        "these languages are detectable by ingest but rejected by "
        f"canonical_structural_language, so one such file 400s code-index sync "
        f"for its entire repository: {missing}"
    )


@pytest.mark.parametrize("language", sorted(CANONICAL_CODE_LANGUAGES))
def test_canonical_structural_language_accepts_each_detectable_language(language: str) -> None:
    from app.services.code_analysis import canonical_structural_language

    assert canonical_structural_language(language) == language


def test_every_lightweight_language_earns_the_baseline_vuln_families() -> None:
    """`html`/`css`/`lua`/`shell`/`dockerfile` are all structurally analyzed.

    A language left out silently loses its `algorithmic-dos`/`error-handling`
    baseline families in vuln-class computation, which reads as "these families
    do not apply here" rather than "nobody looked".
    """
    from app.services.code_analysis import STRUCTURALLY_ANALYZED_LANGUAGES

    from assess.lib.treesitter_index import LIGHTWEIGHT_LANGUAGES

    missing = sorted(set(LIGHTWEIGHT_LANGUAGES) - set(STRUCTURALLY_ANALYZED_LANGUAGES))
    assert missing == [], f"lightweight languages missing baseline families: {missing}"


def test_every_structurally_analyzed_language_has_an_extractor() -> None:
    """The converse guard: the claim must have an analyser behind it.

    `STRUCTURALLY_ANALYZED_LANGUAGES` is what gives a file its
    `algorithmic-dos`/`error-handling` baseline, so a language listed here owes
    CWE coverage. If no extractor claims the language, `structural_language_for_file`
    returns None, the file is never indexed, and the owed coverage reads as
    "these families do not apply" instead of "nobody looked". `.ps1` shipped in
    exactly that state, added to this set by a fix that only needed the
    canonical set above.
    """
    from app.services.code_analysis import STRUCTURALLY_ANALYZED_LANGUAGES

    unanalyzed = sorted(
        language
        for language in STRUCTURALLY_ANALYZED_LANGUAGES
        # Spelling aliases resolve to a canonical language that carries the
        # extractor; only a distinct language can be uncovered.
        if CODE_LANGUAGE_ALIASES.get(language, language)
        not in STRUCTURAL_SUPPORTED_LANGUAGES
    )
    assert unanalyzed == [], (
        "these languages are promised structural analysis and its baseline vuln "
        f"families, but no extractor indexes a file in them: {unanalyzed}"
    )
