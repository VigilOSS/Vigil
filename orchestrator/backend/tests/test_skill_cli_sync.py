"""Markdown-vs-CLI sync-lint.

Operator-facing prose (skills, operator cores, agent prompts, references,
README, the generated AGENTS.md, the per-client agent files) routinely names
concrete ``vigil assess <verb>`` / ``vigil assess kali <verb>`` /
``vigil oob <verb>`` invocations. When the CLI registries drift away from that
prose — a verb renamed, removed, or never shipped — an operator copy-pastes a
command that dies with argparse's generic "invalid choice" error. This guard
catches that drift in CI, in both directions.

Assertions:

(a) docs -> CLI. Every ``vigil assess`` / ``vigil assess kali`` /
    ``vigil assess kali job`` / ``vigil oob`` / ``vigil oob client`` verb named
    in the markdown/TOML corpus resolves to a verb that the *real* CLI
    registries register. The registries are derived by importing the CLIs and
    walking the argparse subparser tree (which executes ``assess.cli``'s
    per-command ``register()`` hooks and the inline ``oob`` ``add_parser`` calls
    in ``vigil_cli.main``), so this test reflects the shipped command surface
    rather than a hand-maintained list.

(b) CLI -> docs. Every registered top-level ``vigil assess`` / ``vigil oob``
    verb, every ``vigil assess kali`` tool-wrapper subverb, and every
    ``vigil oob client`` subverb is either documented somewhere in the corpus
    or named in an explicit KNOWN_UNDOCUMENTED allowlist of advanced/internal
    plumbing. A *new* verb (top-level OR a kali / oob-client subverb) that ships
    with neither docs nor an allowlist entry fails the test. The ``kali job``
    subverbs (list/start/status/stop/tail) are forward-checked only — they are
    generic job-lifecycle verbs, not a per-tool surface, so a missing one shows
    up via assertion (a) when prose names it. See the long comment on each test
    for why the allowlists are a hard fail for new drift but tolerate the
    current (acknowledged) doc debt.

(c) Flag coverage for the highest-drift-risk verbs. The load-bearing
    operator-facing flags on ``verify-finding`` / ``eval-capture`` /
    ``scaffold-probe`` / ``check-scope-coverage`` must (1) still be real
    registered flags on that verb and (2) appear somewhere in the corpus.
    Together those two directions catch a rename on either the CLI side or the
    docs side. Internal/advanced knobs are intentionally excluded (see the
    EXPECTED_FLAGS comment).

(d) No file claims ``vigil oob client logs`` / ``vigil logs oob`` *returns
    correlated hits*. Correlation is exclusively ``vigil oob poll`` (it reads
    recorded probes from the backend and matches callbacks to nonces); the log
    tails are raw listener/FRP output for infra debugging only. This guard
    keeps any future edit from quietly reintroducing the wrong mental model.

Implementation notes:
- Verb tokens containing argparse-doc placeholders (``*``/``<``/``>``/``$``)
  or a trailing ``-`` (e.g. the glob ``vigil assess record-*``) are prose,
  not literal invocations, and are skipped.
- The corpus deliberately excludes historical/backlog/work-product files
  (CHANGELOG, TODOv2, engagement analysis state): those name verbs that were
  renamed or never shipped, and linting them would be drift in the wrong
  direction. See ``_doc_files``.
"""
from __future__ import annotations

import argparse
import importlib
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_ROOT = _REPO_ROOT / "agent" / "scripts"
_SRC_ROOT = _REPO_ROOT / "src"

for _p in (_SRC_ROOT, _SCRIPTS_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# --------------------------------------------------------------------------
# Registry extraction — build the real argparse parsers and walk subparsers.
# --------------------------------------------------------------------------
def _capture_root_parser(main_callable) -> argparse.ArgumentParser:
    """Invoke ``main_callable([])`` with ``parse_args`` stubbed so the fully
    constructed root parser is captured before argparse can exit on the
    missing subcommand. The first parser whose ``parse_args`` is called is
    the root parser (subparsers parse lazily, only once a verb is supplied).
    """
    captured: dict[str, argparse.ArgumentParser] = {}
    original = argparse.ArgumentParser.parse_args

    def _stub(self, args=None, namespace=None):  # noqa: ANN001 - argparse seam
        captured.setdefault("parser", self)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = _stub  # type: ignore[assignment]
    try:
        main_callable([])
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original  # type: ignore[assignment]

    parser = captured.get("parser")
    assert parser is not None, "failed to capture root argparse parser"
    return parser


def _subparser_choices(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:  # noqa: SLF001 - argparse has no public API for this
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _long_flags(parser: argparse.ArgumentParser) -> set[str]:
    """Every ``--flag`` registered on a (sub)parser, including SUPPRESSed ones.
    SUPPRESSed flags are still real argparse options an operator can pass, so a
    rename of one still breaks copy-pasted commands — they belong in the
    registered set even though they never appear in --help."""
    flags: set[str] = set()
    for action in parser._actions:  # noqa: SLF001
        for opt in action.option_strings:
            if opt.startswith("--") and opt != "--help":
                flags.add(opt)
    return flags


def _load_assess_registries() -> dict[str, set[str]]:
    """Return assess verb sets keyed by group from agent/scripts/assess CLI."""
    cli = importlib.import_module("assess.cli")
    root = _capture_root_parser(cli.main)
    top = _subparser_choices(root)
    assess_verbs = set(top)
    kali_verbs: set[str] = set()
    kali_job_verbs: set[str] = set()
    if "kali" in top:
        kali_sub = _subparser_choices(top["kali"])
        kali_verbs = set(kali_sub)
        if "job" in kali_sub:
            kali_job_verbs = set(_subparser_choices(kali_sub["job"]))
    return {
        "assess": assess_verbs,
        "kali": kali_verbs,
        "kali_job": kali_job_verbs,
        # Parsers retained so flag coverage can introspect specific verbs.
        "_top_parsers": top,
    }


def _load_oob_registries() -> dict[str, set[str]]:
    """Return oob verb sets keyed by group from the installable CLI."""
    main_mod = importlib.import_module("vigil_cli.main")
    root = _capture_root_parser(main_mod.main)
    top = _subparser_choices(root)
    oob_verbs: set[str] = set()
    oob_client_verbs: set[str] = set()
    if "oob" in top:
        oob_sub = _subparser_choices(top["oob"])
        oob_verbs = set(oob_sub)
        if "client" in oob_sub:
            oob_client_verbs = set(_subparser_choices(oob_sub["client"]))
    return {"oob": oob_verbs, "oob_client": oob_client_verbs}


# --------------------------------------------------------------------------
# Markdown / TOML corpus.
# --------------------------------------------------------------------------
def _doc_files() -> list[Path]:
    """Operator-facing prose that names literal CLI invocations.

    Includes everything an operator or specialist actually reads:
    - skills (SKILL.md + report templates),
    - operator cores + shared constraints,
    - the agent-prompt sources (``agent/agents/*.md``) AND the *generated*
      copies the runtime actually loads (``agent/AGENTS.md``,
      ``agent/.claude/agents/*.md``, ``agent/.codex/agents/*.toml``) — the
      generated copies are derived from the sources, but linting them too
      catches a render step that ever transforms a verb,
    - the reference library + rules,
    - the top-level user docs (README, CODE-MAP, root maintainer AGENTS.md),
    - the editor-rule pointer (.cursor) and the eval harness README.

    Deliberately EXCLUDED (these are historical / backlog / per-engagement
    work product, not living operator docs, and name verbs that were renamed
    or never shipped — e.g. TODOv2 references ``vigil assess code-audit`` and
    ``vigil assess migrate-scope``, neither a registered assess verb):
      - CHANGELOG.md
      - TODOv2.md
      - tools/analysis-state/**  (engagement analysis snapshots)
    """
    files: list[Path] = []
    files += sorted((_REPO_ROOT / "agent" / "skills").glob("*/SKILL.md"))
    files += sorted((_REPO_ROOT / "agent" / "skills").glob("*/templates/*.md"))
    files += sorted(_REPO_ROOT.glob("agent/operator-core*.md"))
    files += sorted((_REPO_ROOT / "agent" / "agents").glob("*.md"))
    files += sorted(_REPO_ROOT.glob("agent/shared-constraints*.md"))
    files += sorted((_REPO_ROOT / "agent" / "references").rglob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / "rules").glob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / ".claude" / "agents").glob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / ".codex" / "agents").glob("*.toml"))
    # Single-file additions guarded with existence checks so a future rename of
    # any one of them surfaces as a corpus-shrink (caught by the count anchor in
    # ``doc_files``) rather than a crash.
    for candidate in (
        _REPO_ROOT / "agent" / "SKILL.md",
        _REPO_ROOT / "agent" / "AGENTS.md",
        _REPO_ROOT / "README.md",
        _REPO_ROOT / "CODE-MAP.md",
        _REPO_ROOT / "AGENTS.md",
        _REPO_ROOT / ".cursor" / "rules" / "operator.md",
        _REPO_ROOT / "tests" / "eval" / "README.md",
    ):
        if candidate.exists():
            files.append(candidate)
    return files


# Match a *real* YAML frontmatter block only. The lookahead after the opening
# ``---\n`` requires at least one ``word:`` line somewhere inside the block (a
# non-empty key followed by a colon). A leading Markdown horizontal rule has
# nothing — or only prose — between its two ``---`` lines, so it fails the
# lookahead and is left intact. Without the lookahead, ``.*?`` would happily
# match from a leading horizontal rule to the next ``---``, swallowing any
# ``vigil assess`` invocations that live below that second rule. This is not a
# full YAML parser, just enough to tell frontmatter from a horizontal rule.
_FRONTMATTER_RE = re.compile(r"^---\n(?=\s*\w[\w-]*\s*:).*?\n---\n", re.DOTALL)


def _strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter so description: fields that happen to use CLI
    command patterns (e.g. 'vigil assess kali troubleshooting: ...') are not
    matched as literal invocations.

    Only a genuine frontmatter block is stripped: the regex requires a
    ``key: value`` line inside the block, so a file that opens with a Markdown
    horizontal rule (``---`` with nothing — or only prose — before the next
    ``---``) keeps its body, including any CLI invocations below the second
    rule."""
    return _FRONTMATTER_RE.sub("", text, count=1)


# A verb token is a literal CLI verb only if it is lowercase/dash/digit and
# carries no doc-placeholder punctuation. ``record-*``/``record-`` (a glob
# reference, not an invocation) is excluded by the trailing-dash guard.
_PLACEHOLDER = re.compile(r"[*<>${}]")


def _is_literal_verb(token: str) -> bool:
    return bool(token) and not _PLACEHOLDER.search(token) and not token.endswith("-")


# ``vigil assess <verb>`` and ``vigil assess kali <verb>``.
_ASSESS_RE = re.compile(r"vigil assess (kali )?([a-z][a-z0-9-]*)")
# ``vigil assess kali job <subverb>`` — the one assess path with a real
# third-level subparser group (kali_job). Other depth-3 forms after a verb
# (e.g. ``vigil assess agent done``) are positional values, not registered
# subparsers, so they can't be validated generically.
_KALI_JOB_RE = re.compile(r"vigil assess kali job ([a-z][a-z0-9-]*)")
# ``vigil oob <verb>`` (excluding the ``client`` group, handled separately) and
# the depth-3 ``vigil oob client <subverb>``.
_OOB_RE = re.compile(r"vigil oob (?!client )([a-z][a-z0-9-]*)")
_OOB_CLIENT_RE = re.compile(r"vigil oob client ([a-z][a-z0-9-]*)")


@pytest.fixture(scope="module")
def assess_registries() -> dict[str, set[str]]:
    return _load_assess_registries()


@pytest.fixture(scope="module")
def oob_registries() -> dict[str, set[str]]:
    return _load_oob_registries()


@pytest.fixture(scope="module")
def doc_files() -> list[Path]:
    files = _doc_files()
    assert files, "no markdown docs discovered — corpus glob is broken"
    # Anchor the corpus size so a glob that silently stops matching (which would
    # make the docs->CLI and CLI->docs checks vacuous) trips this instead. The
    # corpus is ~330 files (exact count varies with repo state); keep a generous
    # floor that still catches a collapse.
    assert len(files) >= 250, (
        f"doc corpus shrank to {len(files)} files — a glob in _doc_files likely "
        "stopped matching; the sync-lint would silently weaken."
    )
    return files


@pytest.fixture(scope="module")
def corpus_texts(doc_files) -> list[str]:
    """Per-file frontmatter-stripped texts. Kept separate from ``corpus_text``
    so a check can scope itself to the files that mention a particular verb
    (rather than searching the whole concatenated corpus, where a generic flag
    token like ``--json`` appears on hundreds of unrelated verbs)."""
    return [_strip_frontmatter(p.read_text(encoding="utf-8")) for p in doc_files]


@pytest.fixture(scope="module")
def corpus_text(corpus_texts) -> str:
    return "\n".join(corpus_texts)


def test_registries_are_non_trivial(assess_registries, oob_registries):
    """Guard against a silently empty registry (which would make the docs->CLI
    assertion vacuously pass and hide real drift)."""
    assess_verbs = assess_registries["assess"]
    kali_verbs = assess_registries["kali"]
    kali_job_verbs = assess_registries["kali_job"]
    oob_verbs = oob_registries["oob"]
    oob_client_verbs = oob_registries["oob_client"]
    # Anchor on a few stable verbs that must always exist.
    assert {
        "record-finding",
        "kali",
        "log",
        "transition-phase",
        "eval-capture",
        "scaffold-probe",
    } <= assess_verbs
    assert {"nmap-scan", "exec", "httpx", "job"} <= kali_verbs
    assert {"list", "start", "status", "stop", "tail"} <= kali_job_verbs
    assert {"mint", "poll", "client", "status"} <= oob_verbs
    assert {"logs", "list", "start", "stop"} <= oob_client_verbs


# --------------------------------------------------------------------------
# (a) docs -> CLI
# --------------------------------------------------------------------------
def test_documented_assess_verbs_exist(assess_registries, doc_files):
    assess_verbs = assess_registries["assess"]
    kali_verbs = assess_registries["kali"]
    kali_job_verbs = assess_registries["kali_job"]
    unknown_assess: list[str] = []
    unknown_kali: list[str] = []
    unknown_kali_job: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        text = _strip_frontmatter(path.read_text(encoding="utf-8"))
        for match in _ASSESS_RE.finditer(text):
            is_kali = bool(match.group(1))
            verb = match.group(2)
            if not _is_literal_verb(verb):
                continue
            if is_kali:
                if verb not in kali_verbs:
                    unknown_kali.append(f"{rel}: vigil assess kali {verb}")
            elif verb not in assess_verbs:
                unknown_assess.append(f"{rel}: vigil assess {verb}")
        for match in _KALI_JOB_RE.finditer(text):
            verb = match.group(1)
            if not _is_literal_verb(verb):
                continue
            if verb not in kali_job_verbs:
                unknown_kali_job.append(f"{rel}: vigil assess kali job {verb}")
    assert not unknown_assess, (
        "Markdown references `vigil assess <verb>` not registered in "
        "agent/scripts/assess/cli.py:\n  " + "\n  ".join(sorted(set(unknown_assess)))
    )
    assert not unknown_kali, (
        "Markdown references `vigil assess kali <verb>` not registered as a "
        "kali subverb (host-side tools without a wrapper run via "
        "`vigil assess kali exec -- <tool> ...`):\n  "
        + "\n  ".join(sorted(set(unknown_kali)))
    )
    assert not unknown_kali_job, (
        "Markdown references `vigil assess kali job <subverb>` not registered "
        "on the kali job parser (list/start/status/stop/tail):\n  "
        + "\n  ".join(sorted(set(unknown_kali_job)))
    )


def test_documented_oob_verbs_exist(oob_registries, doc_files):
    oob_verbs = oob_registries["oob"]
    oob_client_verbs = oob_registries["oob_client"]
    unknown: list[str] = []
    unknown_client: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        text = _strip_frontmatter(path.read_text(encoding="utf-8"))
        for match in _OOB_RE.finditer(text):
            verb = match.group(1)
            if not _is_literal_verb(verb):
                continue
            if verb not in oob_verbs:
                unknown.append(f"{rel}: vigil oob {verb}")
        for match in _OOB_CLIENT_RE.finditer(text):
            verb = match.group(1)
            if not _is_literal_verb(verb):
                continue
            if verb not in oob_client_verbs:
                unknown_client.append(f"{rel}: vigil oob client {verb}")
    assert not unknown, (
        "Markdown references `vigil oob <verb>` not registered in "
        "src/vigil_cli/main.py:\n  " + "\n  ".join(sorted(set(unknown)))
    )
    assert not unknown_client, (
        "Markdown references `vigil oob client <subverb>` not registered "
        "(list/logs/start/stop):\n  " + "\n  ".join(sorted(set(unknown_client)))
    )


# --------------------------------------------------------------------------
# (b) CLI -> docs
# --------------------------------------------------------------------------
# Verbs that are registered but intentionally not named in operator prose.
# These are orchestration/lifecycle plumbing the operator never types directly
# (the orchestrator or a hook calls them), or advanced knobs documented only by
# `--help`. Listing them here is the acknowledgement: they are *known* to be
# undocumented. The reverse-direction test below asserts
# `undocumented_verbs <= KNOWN_UNDOCUMENTED`, so a brand-new verb that ships
# with neither prose nor an allowlist entry FAILS loudly.
#
# Why a hard fail (against the allowlist) rather than a bare warning: a warning
# in a pytest run is noise nobody acts on, and "new verb shipped silently
# undocumented" is exactly the regression we want to block. Tolerating *current*
# debt while blocking *new* debt is the right default for a team tool — it keeps
# CI green today, makes the existing gap auditable in one place, and forces a
# deliberate one-line decision (document it, or allowlist it) for every future
# verb. Removing a verb from the CLI without removing its allowlist entry is
# caught by ``test_known_undocumented_allowlist_has_no_stale_entries``.
_KNOWN_UNDOCUMENTED_ASSESS = {
    "approve-exploit",            # exploit-gate plumbing; operator uses review-exploits
    "auth-status",                # internal auth probe
    "code-size-summary",          # code-track sizing helper
    "export-surfaces",            # surface export plumbing
    "launch-session",             # session bootstrap called by the orchestrator
    "record-proposal",            # exploit-proposal plumbing
    "supersede-intel",            # intel-lifecycle knob (named in prose, never invoked)
    "validate-dispatch-contract",  # dispatch contract self-check
}
_KNOWN_UNDOCUMENTED_OOB = {
    "restart",  # stop+start convenience; ops doc start/stop/status/test/mint/poll
    "stop",     # lifecycle verb; the docs lean on `vigil oob start`/`status`
}
# kali tool-wrapper subverbs (``vigil assess kali <verb>``) that are registered
# but intentionally not named in operator prose. EMPTY today: every shipped
# wrapper (alterx/asnmap/.../whatweb, plus exec/job) is named in the corpus, so
# a new wrapper that ships undocumented FAILS the reverse check below — exactly
# the drift we want to catch. The `job` group itself is documented as
# `vigil assess kali job`; its lifecycle subverbs are forward-checked by
# assertion (a) (see _KALI_JOB_RE), not here.
_KNOWN_UNDOCUMENTED_KALI: set[str] = set()
# oob client subverbs (``vigil oob client <verb>``) registered but not in prose.
# EMPTY today: list/logs/start/stop are all documented. A fifth client subverb
# that shipped without docs would FAIL the reverse check.
_KNOWN_UNDOCUMENTED_OOB_CLIENT: set[str] = set()


def _documented_verbs(corpus_text: str) -> tuple[set[str], set[str]]:
    doc_assess: set[str] = set()
    doc_oob: set[str] = set()
    for match in _ASSESS_RE.finditer(corpus_text):
        if not match.group(1):  # skip the kali-namespaced forms
            doc_assess.add(match.group(2))
    for match in _OOB_RE.finditer(corpus_text):
        doc_oob.add(match.group(1))
    return doc_assess, doc_oob


def _documented_subverbs(corpus_text: str) -> tuple[set[str], set[str]]:
    """Return ``(documented_kali, documented_oob_client)`` literal subverbs.

    Mirrors ``_documented_verbs`` but for the two depth-3 surfaces with their
    own per-item registries (kali tool wrappers + oob client). Placeholder /
    glob tokens are filtered the same way the docs->CLI checks filter them, so a
    prose ``vigil assess kali <tool>`` is not mistaken for a literal subverb."""
    doc_kali: set[str] = set()
    for match in _ASSESS_RE.finditer(corpus_text):
        if match.group(1) and _is_literal_verb(match.group(2)):  # the kali-namespaced form
            doc_kali.add(match.group(2))
    doc_oob_client: set[str] = set()
    for match in _OOB_CLIENT_RE.finditer(corpus_text):
        if _is_literal_verb(match.group(1)):
            doc_oob_client.add(match.group(1))
    return doc_kali, doc_oob_client


def test_registered_verbs_are_documented(assess_registries, oob_registries, corpus_text):
    """CLI -> docs. Every registered top-level assess/oob verb, every kali
    tool-wrapper subverb, and every oob-client subverb is either documented in
    the corpus or explicitly allowlisted as internal plumbing."""
    assess_verbs = set(assess_registries["assess"]) - {"kali"}  # kali is a group, not a verb
    oob_verbs = set(oob_registries["oob"]) - {"client"}  # client is a group
    # `job` is a kali subgroup (documented as `vigil assess kali job`), not a
    # tool wrapper — its lifecycle subverbs are forward-checked by assertion (a).
    kali_verbs = set(assess_registries["kali"]) - {"job"}
    oob_client_verbs = set(oob_registries["oob_client"])
    doc_assess, doc_oob = _documented_verbs(corpus_text)
    doc_kali, doc_oob_client = _documented_subverbs(corpus_text)

    undocumented_assess = sorted(assess_verbs - doc_assess - _KNOWN_UNDOCUMENTED_ASSESS)
    undocumented_oob = sorted(oob_verbs - doc_oob - _KNOWN_UNDOCUMENTED_OOB)
    undocumented_kali = sorted(kali_verbs - doc_kali - _KNOWN_UNDOCUMENTED_KALI)
    undocumented_oob_client = sorted(
        oob_client_verbs - doc_oob_client - _KNOWN_UNDOCUMENTED_OOB_CLIENT
    )

    assert not undocumented_assess, (
        "These `vigil assess` verbs are registered but never named in the doc "
        "corpus and are not in _KNOWN_UNDOCUMENTED_ASSESS. Document the verb in "
        "a SKILL.md / operator-core / reference, or add it to the allowlist "
        "with a one-line reason:\n  " + "\n  ".join(undocumented_assess)
    )
    assert not undocumented_oob, (
        "These `vigil oob` verbs are registered but never named in the doc "
        "corpus and are not in _KNOWN_UNDOCUMENTED_OOB. Document or "
        "allowlist:\n  " + "\n  ".join(undocumented_oob)
    )
    assert not undocumented_kali, (
        "These `vigil assess kali <tool>` wrapper subverbs are registered but "
        "never named in the doc corpus and are not in _KNOWN_UNDOCUMENTED_KALI. "
        "Document the wrapper (a SKILL.md / runtime-guide reference) or add it "
        "to the allowlist with a one-line reason:\n  "
        + "\n  ".join(undocumented_kali)
    )
    assert not undocumented_oob_client, (
        "These `vigil oob client <subverb>` verbs are registered but never "
        "named in the doc corpus and are not in _KNOWN_UNDOCUMENTED_OOB_CLIENT. "
        "Document or allowlist:\n  " + "\n  ".join(undocumented_oob_client)
    )


def test_known_undocumented_allowlist_has_no_stale_entries(assess_registries, oob_registries, corpus_text):
    """The allowlist must not rot. An entry is stale if the verb (1) no longer
    exists in the CLI or (2) actually became documented — either way it should
    leave the allowlist so the allowlist stays an honest ledger of real debt."""
    assess_verbs = set(assess_registries["assess"])
    oob_verbs = set(oob_registries["oob"])
    kali_verbs = set(assess_registries["kali"])
    oob_client_verbs = set(oob_registries["oob_client"])
    doc_assess, doc_oob = _documented_verbs(corpus_text)
    doc_kali, doc_oob_client = _documented_subverbs(corpus_text)

    stale: list[str] = []
    for verb in _KNOWN_UNDOCUMENTED_ASSESS:
        if verb not in assess_verbs:
            stale.append(f"assess `{verb}` is allowlisted but no longer registered")
        elif verb in doc_assess:
            stale.append(f"assess `{verb}` is now documented — drop it from the allowlist")
    for verb in _KNOWN_UNDOCUMENTED_OOB:
        if verb not in oob_verbs:
            stale.append(f"oob `{verb}` is allowlisted but no longer registered")
        elif verb in doc_oob:
            stale.append(f"oob `{verb}` is now documented — drop it from the allowlist")
    for verb in _KNOWN_UNDOCUMENTED_KALI:
        if verb not in kali_verbs:
            stale.append(f"kali `{verb}` is allowlisted but no longer registered")
        elif verb in doc_kali:
            stale.append(f"kali `{verb}` is now documented — drop it from the allowlist")
    for verb in _KNOWN_UNDOCUMENTED_OOB_CLIENT:
        if verb not in oob_client_verbs:
            stale.append(f"oob client `{verb}` is allowlisted but no longer registered")
        elif verb in doc_oob_client:
            stale.append(f"oob client `{verb}` is now documented — drop it from the allowlist")
    assert not stale, "Stale KNOWN_UNDOCUMENTED entries:\n  " + "\n  ".join(stale)


# --------------------------------------------------------------------------
# (c) Flag coverage for the highest-drift-risk verbs.
# --------------------------------------------------------------------------
# Per verb, the load-bearing operator-facing flags whose rename would silently
# break copy-pasted commands. These are asserted in BOTH directions: each must
# still be a registered flag on its verb (catches a CLI rename) AND appear
# somewhere in the corpus (catches a docs rename). We deliberately do NOT list
# every flag — internal/advanced knobs that are intentionally undocumented stay
# out so they don't hard-fail:
#   record-finding       — surface is positional (title/severity/...); its only
#                           flag is the internal --allow-unindexed-evidence, so
#                           there is no operator-facing flag to assert here.
#   verify-finding       — omits --reason-code/--artifact-ref/--details-inline
#                           (advanced provenance knobs, undocumented by design).
#   scaffold-probe       — omits --purpose/--no-register (advanced).
#   check-scope-coverage — omits --auto-redispatch/--max-recommendations/
#                           --include-discovered (advanced tuning, undocumented).
_EXPECTED_FLAGS = {
    "verify-finding": {
        "--disposition",
        "--reason",
        "--narrative",
        "--evidence-ref",
        "--new-severity",
        "--kill-check",
        "--inline",
    },
    "eval-capture": {
        "--definition",
        "--check",
        "--strict",
        "--severity",
        "--out",
        # The docs (tests/eval/README.md) document the list-findings filter as
        # `--workflow-status` (the canonical long form); `--status` is only a
        # registered *alias*. Curate the documented form so the verb-scoped
        # docs check tracks the prose, not the alias. (The whole-corpus search
        # this replaced passed `--status` vacuously — it matches `vigil oob
        # status`, `list-findings --status`, etc. on unrelated verbs.)
        "--workflow-status",
    },
    "scaffold-probe": {
        "--finding",
        "--force",
        "--json",
    },
    "check-scope-coverage": {
        "--require-stage",
        "--by-host",
        "--strict-vendor-saas",
        "--json",
    },
}


def test_expected_flags_are_registered(assess_registries):
    """CLI side: each curated flag is still a real argparse option on its verb.
    Catches a flag rename/removal in the command modules."""
    top = assess_registries["_top_parsers"]
    missing: list[str] = []
    for verb, flags in _EXPECTED_FLAGS.items():
        assert verb in top, f"expected verb `{verb}` not registered"
        registered = _long_flags(top[verb])
        for flag in sorted(flags):
            if flag not in registered:
                missing.append(f"vigil assess {verb} {flag}")
    assert not missing, (
        "Curated flags no longer registered on their verb (renamed/removed in "
        "agent/scripts/assess/commands/?):\n  " + "\n  ".join(missing)
    )


def test_expected_flags_are_documented(corpus_texts):
    """Docs side: each curated flag appears in the corpus *on its own verb*.
    Catches a flag rename that updated the CLI but not the prose (or
    vice-versa).

    Crucially the flag is searched only within the subset of files that
    actually mention the verb (a file "mentions" a verb when it contains the
    literal string ``vigil assess <verb>``). Searching the whole concatenated
    corpus would be vacuous for generic flags — ``--json`` / ``--status`` /
    ``--out`` appear hundreds of times on unrelated verbs, so the assertion
    would pass even if every example of the target verb were deleted. Scoping
    to the verb's own files makes "the flag is documented" mean "documented for
    this verb".

    Flags are matched as whole tokens so ``--reason`` does not spuriously
    satisfy ``--reason-code`` and similar prefixes. If the verb is documented
    nowhere (empty subset), the flag check is skipped for that verb — the
    reverse-direction ``test_registered_verbs_are_documented`` already fails on
    an entirely-undocumented verb, so there is nothing extra to assert here."""
    undocumented: list[str] = []
    for verb, flags in _EXPECTED_FLAGS.items():
        verb_mention = f"vigil assess {verb}"
        verb_files = [text for text in corpus_texts if verb_mention in text]
        if not verb_files:
            # Verb is documented nowhere — skip (the CLI->docs reverse check
            # owns this case). Without this guard the per-verb search below
            # would still be sound (empty subset -> flag absent -> reported),
            # but that would double-report the same drift the reverse check
            # already flags, so we defer to it explicitly.
            continue
        verb_corpus = "\n".join(verb_files)
        for flag in sorted(flags):
            token = re.compile(re.escape(flag) + r"(?![A-Za-z0-9-])")
            if not token.search(verb_corpus):
                undocumented.append(f"vigil assess {verb} {flag}")
    assert not undocumented, (
        "Curated operator-facing flags are registered but never named in any "
        "doc that mentions their verb (docs drifted, or the flag was renamed "
        "only on the CLI side). Document the flag alongside the verb or, if it "
        "is genuinely an internal knob, drop it from _EXPECTED_FLAGS with a "
        "note:\n  " + "\n  ".join(undocumented)
    )


# --------------------------------------------------------------------------
# (d) logs tail is not correlation.
# --------------------------------------------------------------------------
# A logs tail is named with one of these tokens.
_LOGS_VERB_RE = re.compile(r"vigil oob client logs|vigil logs oob")
# Disclaimers that correctly mark a logs tail as NON-correlation. A line that
# mentions a logs verb together with "correlat" is only acceptable when it
# carries one of these markers (case-insensitive). These keywords mirror the
# vocabulary the post-QA prose already uses to disavow correlation.
_NEGATION_MARKERS = (
    "not correlation",
    "not the correlation",
    "no correlation",
    "without correlat",
    "infra debug",
    "infra debugging",
    "debugging only",
    "for debugging",
    "raw tail",
    "raw listener",
    "raw interactsh",
    "raw server",
    "raw infra",
    "listener tail",
    "no manual log correlation",
    "not `vigil oob client logs`",
    "(not ",
)


def test_logs_tail_never_described_as_correlation(doc_files):
    """No file may assert that `vigil oob client logs` / `vigil logs oob`
    *returns correlated* hits. Correlation is exclusively `vigil oob poll`."""
    offenders: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not _LOGS_VERB_RE.search(line):
                continue
            lowered = line.lower()
            if "correlat" not in lowered:
                continue
            if any(marker in lowered for marker in _NEGATION_MARKERS):
                continue
            offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "A logs tail (`vigil oob client logs` / `vigil logs oob`) is described "
        "alongside correlation without disavowing it. Correlation is only "
        "`vigil oob poll`; the log tails are raw listener/FRP output for infra "
        "debugging:\n  " + "\n  ".join(offenders)
    )
