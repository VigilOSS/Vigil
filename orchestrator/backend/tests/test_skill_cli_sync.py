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

(c) Curated flag coverage for the highest-drift-risk verbs. The load-bearing
    operator-facing flags on ``finding verify`` / ``eval-capture`` /
    ``scaffold-probe`` / ``check-phase-readiness`` must (1) still be real
    registered flags on that verb and (2) appear somewhere in the corpus.
    Together those two directions catch a rename on either the CLI side or the
    docs side. Internal/advanced knobs are intentionally excluded (see the
    EXPECTED_FLAGS comment).

(d) Reverse flag lint. Every long ``--flag`` written against a
    ``vigil assess`` verb is one that verb actually registers. Each literal
    invocation is tokenized and walked down the live argparse tree the way
    argparse resolves argv, so the parser tree is the only source of truth and
    there is no second flag list to drift. Two corpora feed it: the markdown /
    TOML prose of (a)-(c), and the **Python string literals** of the backend
    services, the assess CLI and the installable CLI — the error and advisory
    messages an operator reads at the moment a command has already failed,
    where a wrong flag costs the most and is least likely to be questioned.

(e) No file claims ``vigil oob client logs`` / ``vigil logs oob`` *returns
    correlated hits*. Correlation is exclusively ``vigil oob poll`` (it reads
    recorded probes from the backend and matches callbacks to nonces); the log
    tails are raw listener/FRP output for infra debugging only. This guard
    keeps any future edit from quietly reintroducing the wrong mental model.

Implementation notes:
- Verb tokens containing argparse-doc placeholders (``*``/``<``/``>``/``$``)
  or a trailing ``-`` (e.g. the glob ``vigil assess record-*``) are prose,
  not literal invocations, and are skipped.
- The corpus deliberately excludes historical/backlog/work-product files
  (the changelog, retired planning notes, engagement analysis state): those name verbs that were
  renamed or never shipped, and linting them would be drift in the wrong
  direction. See ``_doc_files``.
"""
from __future__ import annotations

import argparse
import ast
import importlib
import re
import sys
from pathlib import Path
from typing import Any

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


def _load_assess_registries() -> dict[str, Any]:
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
        # Parsers retained so flag coverage can introspect specific verbs, and
        # the root so the reverse flag lint can walk the tree from the top.
        "_top_parsers": top,
        "_root_parser": root,
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
    - the ``docs/`` operator and maintainer pages that name concrete
      invocations — the assessment-CLI reference, the session-command
      reference, agent clients, authentication, blue engagements, code
      analysis, OOB routing, operations, and install integrity. These are
      living user-facing docs: a verb renamed out from under one of them is
      exactly the copy-paste failure this lint exists to catch,
    - the editor-rule pointer (.cursor) and the eval harness README.

    Deliberately EXCLUDED (historical release notes and per-engagement work
    product are not living operator docs and may name retired verbs):
      - CHANGELOG.md
      - tools/analysis-state/**  (engagement analysis snapshots)
    """
    files: list[Path] = []
    files += sorted((_REPO_ROOT / "agent" / "skills").glob("*/SKILL.md"))
    files += sorted((_REPO_ROOT / "agent" / "skills").glob("*/templates/*.md"))
    files += sorted(_REPO_ROOT.glob("agent/operator-core*.md"))
    files += sorted((_REPO_ROOT / "agent" / "phases").glob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / "agents").glob("*.md"))
    files += sorted(_REPO_ROOT.glob("agent/shared-constraints*.md"))
    files += sorted((_REPO_ROOT / "agent" / "references").rglob("*.md"))
    # rglob, not glob: `agent/rules/` has a `mindsets/` subdirectory (the
    # Dispatch-Mindset lens library) that a non-recursive glob structurally
    # excluded. Those packets are operator-facing prose the specialist loads, so
    # a `vigil assess` invocation inside one must be linted like any other rule.
    files += sorted((_REPO_ROOT / "agent" / "rules").rglob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / ".claude" / "agents").glob("*.md"))
    files += sorted((_REPO_ROOT / "agent" / ".codex" / "agents").glob("*.toml"))
    # Single-file additions guarded with existence checks so a future rename of
    # any one of them surfaces as a corpus-shrink (caught by the count anchor in
    # ``doc_files``) rather than a crash.
    for candidate in (
        _REPO_ROOT / "agent" / "SKILL.md",
        _REPO_ROOT / "agent" / "AGENTS.md",
        _REPO_ROOT / "agent" / "shared-specialist-core.md",
        _REPO_ROOT / "README.md",
        _REPO_ROOT / "docs" / "assessment-cli.md",
        _REPO_ROOT / "docs" / "session-commands.md",
        _REPO_ROOT / "docs" / "agent-clients.md",
        _REPO_ROOT / "docs" / "authentication.md",
        _REPO_ROOT / "docs" / "blue-engagements.md",
        _REPO_ROOT / "docs" / "code-analysis.md",
        _REPO_ROOT / "docs" / "oob-routing.md",
        _REPO_ROOT / "docs" / "operations.md",
        _REPO_ROOT / "docs" / "install-integrity.md",
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
def assess_registries() -> dict[str, Any]:
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
    # Anchor on a few stable verbs that must always exist. `finding` is the
    # Grouped subcommand parent (record/verify/... are its actions).
    assert {
        "finding",
        "kali",
        "log",
        "transition-phase",
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
# Grouped namespacing folded the former top-level `export-surfaces` and
# `supersede-intel` verbs under subcommand-group parents (`export surfaces`,
# `intel supersede`), so they are no longer top-level assess verbs and no longer
# belong on this top-level allowlist. The subverb doc debt is carried by the
# pending prompt sweep and surfaced by the docs<->CLI parity assertions.
_KNOWN_UNDOCUMENTED_ASSESS: set[str] = {
    # `list-mindsets` shipped as the mindsets analogue of `list-skills` /
    # `list-references` / `list-commands` (the lens library under
    # agent/rules/mindsets/ was the last discovery axis still enumerated by hand
    # in per-doc menus). Its prose wiring — replacing those hard-coded menus with
    # a pointer at the verb — belongs to the prompt sweep, not to the CLI change
    # that introduced it. This entry is temporary by construction:
    # `test_known_undocumented_allowlist_has_no_stale_entries` fails the moment
    # any operator doc names the verb, forcing the entry back out.
    "list-mindsets",
    # `code-lead` (B2) binds a tracked intel lead to a repository/file/line and
    # is fully specified by `vigil assess contract code-lead`, its own --help,
    # and the `code_leads_unresolved` readiness repair line that names it. Its
    # prose wiring belongs to the prompt sweep, not to the CLI change that
    # introduced it. Temporary by construction:
    # `test_known_undocumented_allowlist_has_no_stale_entries` fails the moment
    # any operator doc names the verb, forcing the entry back out.
    "code-lead",
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
#   finding verify       — omits --reason-code/--artifact-ref/--details-inline
#                           (advanced provenance knobs, undocumented by design).
#   scaffold-probe       — omits --purpose/--no-register (advanced).
_EXPECTED_FLAGS = {
    # `verify` is the lifecycle action under the `finding` subcommand group.
    # Verification is one status transition: terminal positive
    # outcomes cite a proof receipt, while false positives cite a completed
    # structured counter-check.
    "finding verify": {
        "--status",
        "--reason",
        "--agent-id",
        "--narrative",
        "--evidence-ref",
        "--new-severity",
        "--proof-receipt-id",
        "--counter-check-file",
        "--payload-file",
    },
    "scaffold-probe": {
        "--finding",
        "--force",
        "--json",
    },
    "check-phase-readiness": {
        "--phase",
        "--by-host",
        "--strict-vendor-saas",
        "--strict",
        "--strict-deep",
        "--json",
    },
}


def test_expected_flags_are_registered(assess_registries):
    """CLI side: each curated flag is still a real argparse option on its verb.
    Catches a flag rename/removal in the command modules."""
    top = assess_registries["_top_parsers"]
    missing: list[str] = []
    for verb, flags in _EXPECTED_FLAGS.items():
        # A verb may be a two-token group action (e.g. `finding verify`);
        # walk the parent subparser chain to reach the leaf action parser.
        parts = verb.split()
        parser = top.get(parts[0])
        assert parser is not None, f"expected verb `{verb}` not registered"
        for token in parts[1:]:
            parser = _subparser_choices(parser).get(token)
            assert parser is not None, f"expected verb `{verb}` not registered"
        registered = _long_flags(parser)
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
# (d) Reverse flag lint — every `--flag` an operator is told to run exists.
# --------------------------------------------------------------------------
# _EXPECTED_FLAGS above is a curated allowlist: it proves a handful of
# load-bearing flags still exist, but it says nothing about the thousands of
# other `vigil assess` invocations the repo hands an operator. A prompt that
# names a flag its verb never registered dies with argparse exit 2
# mid-engagement, and the verb-level checks cannot see it because the verb
# itself is real. This section walks the other direction: for EVERY literal
# invocation, resolve the verb against the live argparse tree and assert each
# long flag written against it is registered somewhere on that path.
#
# It runs over two corpora, sharing one tokenizer and one resolver:
#   * the markdown/TOML prose of (a)-(c) — what an operator reads BEFORE
#     running a command, and
#   * the Python string literals of `orchestrator/backend`, `src/vigil_cli` and
#     `agent/scripts` — what they read WHEN one fails. Runtime guidance is the
#     harsher surface of the two: the reader has just been refused, is being
#     handed the way out, and is least able to sanity-check it. Three backend
#     messages pointed at `finding link --target-finding <slug>`, a flag
#     `finding link` has never registered, and nothing caught it because the
#     corpus globbed only `.md` and `.toml`.
#
# The parser tree is the only source of truth here — there is deliberately no
# second hand-maintained flag list to drift.

# One shell token: a single-quoted run, a double-quoted run, or a bare run. The
# quoted alternatives only engage when a token STARTS with the quote, so a prose
# apostrophe ("don't") stays inside a single bare token.
_TOKEN_RE = re.compile(r"(?:[^\s'\"]+|'[^']*'|\"[^\"]*\")+")
# The well-formed long flag at the head of a token, ignoring trailing markdown
# punctuation (``--json,``) and any ``=value`` suffix. A bare ``--`` and a
# markdown ``---`` rule do not match, so neither is mistaken for a flag.
_FLAG_HEAD_RE = re.compile(r"^(--[A-Za-z0-9][A-Za-z0-9-]*)")
# Tokens that end the invocation: a shell operator, a redirect, or the bare
# ``--`` after which every argument belongs to a wrapped tool
# (``kali exec -- nmap -sV``) rather than to the vigil verb. A token opening a
# trailing ``# ...`` comment ends it too, and is handled alongside these.
_COMMAND_TERMINATORS = frozenset(
    {"|", "||", "&&", ";", "&", ">", ">>", "2>", "2>&1", "--"}
)
# Quotes that can open an embedded command span and therefore close it; see
# ``_command_tokens``.
_SPAN_QUOTES = "'\""
# Sentence punctuation immediately after an option name (``--emit-prompt,``) —
# the mark that the surrounding prose has resumed.
_TRAILING_PROSE_RE = re.compile(r"^[,.;:]")
_ASSESS_INVOCATION_RE = re.compile(r"vigil assess(?=[ \t]|$)")
_LINE_CONTINUATION_RE = re.compile(r"\\\n[ \t]*")
# A command never runs past this many characters; bounding the lookahead keeps
# the continuation join linear in corpus size rather than quadratic.
_INVOCATION_LOOKAHEAD = 4000


def _long_flag_actions(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    """Map every registered long flag on one parser to its action."""
    actions: dict[str, argparse.Action] = {}
    for action in parser._actions:  # noqa: SLF001
        for opt in action.option_strings:
            if opt.startswith("--") and opt != "--help":
                actions[opt] = action
    return actions


def _has_remainder_positional(parser: argparse.ArgumentParser) -> bool:
    """True when the verb forwards its tail to a hand-rolled sub-CLI.

    ``code-dispatch`` collects everything after its action into an
    ``argparse.REMAINDER`` positional and parses the flags itself, so its real
    flag surface is invisible to argparse introspection."""
    return any(
        action.nargs == argparse.REMAINDER
        for action in parser._actions  # noqa: SLF001
        if not action.option_strings
    )


def _command_tokens(text: str, *, closer: str = "") -> list[str]:
    """Tokenize one invocation, honouring quoted runs.

    Backslash continuations are joined first so a multi-line bash block is one
    command. The result is then cut at the first newline and at the first
    backtick: a fenced block never contains a backtick, while an inline
    ``vigil assess ...`` span ends at one, so the same cut handles both forms
    without needing to know which produced the line.

    ``closer`` is the quote that OPENED the span, when one did — a runtime
    message often names a command mid-sentence (``... so 'vigil assess
    work-buffer stats' actually decrements as probes land``). A quote cannot be
    cut unconditionally the way a backtick can, because a real command quotes
    its own argument values, so it ends the span only when the same character
    started it.

    Tokens also stop after an option written with trailing sentence punctuation
    (``--emit-prompt, or rerun with --force``): no shell spells an option that
    way, so the words after it are narration, not arguments to the verb."""
    joined = _LINE_CONTINUATION_RE.sub(" ", text[:_INVOCATION_LOOKAHEAD])
    line = joined.split("\n", 1)[0].split("`", 1)[0]
    if closer:
        line = line.split(closer, 1)[0]
    tokens: list[str] = []
    for match in _TOKEN_RE.finditer(line):
        token = match.group(0)
        tokens.append(token)
        flag = _FLAG_HEAD_RE.match(token)
        if flag is not None and _TRAILING_PROSE_RE.match(token[flag.end():]):
            break
    return tokens


def _extract_invocations(
    rel: str, text: str, *, first_line: int = 1
) -> list[tuple[str, int, list[str]]]:
    """Every literal ``vigil assess ...`` invocation in one block of text, as
    ``(path, line number, tokens following ``vigil assess``)``.

    ``first_line`` is the line the block itself begins on, so an invocation
    inside a Python string literal reports its line in the module rather than an
    offset inside the literal."""
    found: list[tuple[str, int, list[str]]] = []
    for match in _ASSESS_INVOCATION_RE.finditer(text):
        start = match.start()
        opener = text[start - 1] if start else ""
        tokens = _command_tokens(
            text[match.end():], closer=opener if opener in _SPAN_QUOTES else ""
        )
        if tokens:
            found.append((rel, first_line + text.count("\n", 0, start), tokens))
    return found


def _resolve_invocation_flags(
    root: argparse.ArgumentParser, tokens: list[str]
) -> tuple[int, tuple[str, str] | None]:
    """Return ``(flags resolved, first dangling ``(verb path, flag)`` or None)``.

    Walks the subparser tree the way argparse resolves argv, carrying the flag
    set of every parser on the path: argparse matches an option string anywhere
    in argv against the whole parser chain, so ``finding list --engagement-dir X``
    is a legitimate spelling of a root-level flag.

    At most one dangling flag per invocation. Once a flag is unresolvable the
    rest of the line cannot be attributed with confidence — the unknown flag may
    have swallowed the value that would otherwise have named the next subparser —
    so reporting stops there instead of cascading.

    The resolved count is what keeps the lint honest: it is the number of flags
    this walk actually checked against a real parser, so a regression that makes
    every invocation bail early shows up as a collapsed count rather than as a
    silently green suite."""
    parser = root
    path: list[str] = []
    known: dict[str, argparse.Action] = dict(_long_flag_actions(root))
    resolved = 0
    index = 0
    while index < len(tokens):
        if _has_remainder_positional(parser):
            # The verb hand-parses its own argv behind an argparse.REMAINDER
            # positional (`code-dispatch fetch 10 worker --repo-id 3`). Those
            # flags are real, but they are not argparse options on this parser
            # and cannot be resolved here.
            return resolved, None
        token = tokens[index]
        if token in _COMMAND_TERMINATORS or token.startswith("#"):
            # A shell operator, the wrapped-tool boundary, or the start of a
            # trailing `# ...` comment — nothing after it is an argument to this
            # verb.
            return resolved, None
        flag = _FLAG_HEAD_RE.match(token)
        if flag is not None:
            if _PLACEHOLDER.match(token[flag.end():]):
                # A placeholder interrupts the option NAME itself
                # (``--dry-run{threshold_arg}``). The spelling argparse would
                # receive is not knowable here, so neither this token nor
                # anything after it can be attributed.
                return resolved, None
            name = flag.group(1)
            if name == "--help":
                # argparse registers it on every parser; the flag-set helpers
                # deliberately omit it, so resolve it here instead.
                index += 1
                continue
            action = known.get(name)
            if action is None:
                return resolved, (" ".join(path), name)
            resolved += 1
            index += 1
            # Step over the option's value so it cannot be read as a subverb.
            if "=" not in token and action.nargs != 0:
                if index < len(tokens) and not tokens[index].startswith("-"):
                    index += 1
            continue
        if token.startswith("-"):
            # A short flag, or an option value that itself starts with a dash
            # (``--extra-args -sV``). Neither is resolvable here, and whatever
            # follows can no longer be attributed, so stop.
            return resolved, None
        choices = _subparser_choices(parser)
        if not choices:
            # A leaf verb: every remaining bare token is a positional value.
            index += 1
            continue
        if token in choices:
            parser = choices[token]
            known.update(_long_flag_actions(parser))
            path.append(token)
            index += 1
            continue
        if _PLACEHOLDER.search(token):
            # ``vigil assess kali <tool> --timeout 60`` is prose about a verb
            # family, not a literal invocation — the real flags live on whichever
            # subparser the placeholder stands in for.
            return resolved, None
        # A literal token that is not a registered subverb. The verb-level
        # docs->CLI assertions own that failure; do not double-report it, and do
        # not attribute the rest of the line to the parent group.
        return resolved, None
    return resolved, None


# The markdown corpus covers the prose an operator reads BEFORE running a
# command. This second corpus covers what they read at the moment one fails:
# the error and advisory strings the backend services, the assess CLI and the
# installable CLI build at runtime. That is the higher-stakes surface — a wrong
# flag in an error message is handed to an agent that has just been refused,
# needs the remedy, and has no reason to doubt it.
_PYTHON_GLOBS = (
    "orchestrator/backend/**/*.py",
    "src/vigil_cli/**/*.py",
    "agent/scripts/**/*.py",
)


def _python_files() -> list[Path]:
    """Every first-party Python module whose strings can reach an operator.

    Two structural exclusions. There is deliberately no per-string allowlist:
    a second hand-maintained list would drift exactly like the flag list this
    section exists to replace.

    - **Dot-prefixed path components.** ``orchestrator/backend/.venv`` alone
      carries ~900 third-party modules and ``.claude/`` holds whole extra
      checkouts. Neither is this repo's source, and whether either exists
      depends on the machine — which would make the count anchors below
      environment-dependent rather than a real corpus floor.
    - **``tests/`` directories.** A test module is fixtures and assertions, not
      operator guidance. It mirrors product strings (so one real defect would be
      reported twice, the second time at a line nobody ships) and it
      deliberately carries invocations that must NOT work —
      ``test_scaffold_probe.py`` asserts ``"vigil assess artifact register" not
      in error``. Linting the suite's own negative fixtures would fail this
      check on correct code.
    """
    files: list[Path] = []
    for pattern in _PYTHON_GLOBS:
        files += sorted(_REPO_ROOT.glob(pattern))
    return [
        path
        for path in files
        if not any(
            part.startswith(".") or part == "tests"
            for part in path.relative_to(_REPO_ROOT).parts
        )
    ]


# An f-string interpolation is a runtime VALUE, never part of the command's
# syntax. Rendering it as ``{}`` keeps the invocation a single well-formed token
# stream and reuses the placeholder handling the markdown corpus already needs:
# ``{}`` can never be read as a flag, and where a subverb belongs it stops the
# walk rather than guessing which subparser the value would have named.
_PY_INTERPOLATION = "{}"


def _fold_python_string(node: ast.AST) -> str | None:
    """Fold the static string syntax Python itself joins before execution."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fold_python_string(node.left)
        right = _fold_python_string(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                folded = _fold_python_string(part.value)
                parts.append(folded if folded is not None else _PY_INTERPOLATION)
                continue
            folded = _fold_python_string(part)
            if folded is None:
                return None
            parts.append(folded)
        return "".join(parts)
    return None


def _python_string_literals(path: Path) -> list[tuple[int, str]]:
    """``(line, text)`` for every string literal in one module.

    Literals only: a ``# vigil assess ...`` comment is a note to the next
    maintainer, not text any running command prints.

    The walk is manual because ``ast.walk`` would yield an f-string AND each of
    its literal fragments — reporting one defect from two places, and splitting
    a command apart at every interpolation it contains."""
    literals: list[tuple[int, str]] = []
    stack: list[ast.AST] = [ast.parse(path.read_text(encoding="utf-8"))]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            folded = _fold_python_string(node)
            if folded is not None:
                literals.append((node.lineno, folded))
                continue
        if isinstance(node, ast.JoinedStr):
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.append((node.lineno, node.value))
            continue
        stack.extend(ast.iter_child_nodes(node))
    return sorted(literals, key=lambda item: item[0])


def test_command_tokenizer_keeps_equals_quoted_value_in_one_token() -> None:
    tokens = _command_tokens(
        ' finding update VA-001 --summary="text containing --not-a-flag" --notes ok'
    )

    assert tokens == [
        "finding",
        "update",
        "VA-001",
        '--summary="text containing --not-a-flag"',
        "--notes",
        "ok",
    ]


def test_python_literals_fold_concatenation_and_constant_nested_fstring(
    tmp_path: Path,
) -> None:
    path = tmp_path / "commands.py"
    path.write_text(
        "A = 'vigil assess finding ' + 'list --concat-flag'\n"
        "B = f\"vigil assess finding list {f'--nested-flag'}\"\n",
        encoding="utf-8",
    )

    assert [text for _line, text in _python_string_literals(path)] == [
        "vigil assess finding list --concat-flag",
        "vigil assess finding list --nested-flag",
    ]


@pytest.fixture(scope="module")
def assess_invocations(doc_files) -> list[tuple[str, int, list[str]]]:
    """Every literal ``vigil assess ...`` invocation in the markdown/TOML
    corpus, as ``(relative path, line number, tokens following
    ``vigil assess``)``."""
    found: list[tuple[str, int, list[str]]] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        found += _extract_invocations(
            rel, _strip_frontmatter(path.read_text(encoding="utf-8"))
        )
    return found


@pytest.fixture(scope="module")
def python_files() -> list[Path]:
    files = _python_files()
    # Same anchor role as ``doc_files``: a glob that silently stops matching
    # would make the runtime-string checks vacuous rather than red. The corpus
    # is ~320 modules; keep a generous floor that still catches a collapse.
    assert len(files) >= 250, (
        f"python corpus shrank to {len(files)} modules — a glob in "
        "_python_files likely stopped matching; the runtime-string flag lint "
        "would silently weaken."
    )
    return files


@pytest.fixture(scope="module")
def python_assess_invocations(python_files) -> list[tuple[str, int, list[str]]]:
    """Every literal ``vigil assess ...`` invocation written in a Python string
    literal, in the same shape as ``assess_invocations``."""
    found: list[tuple[str, int, list[str]]] = []
    for path in python_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for lineno, text in _python_string_literals(path):
            found += _extract_invocations(rel, text, first_line=lineno)
    return found


def _scan_invocations(
    root: argparse.ArgumentParser,
    invocations: list[tuple[str, int, list[str]]],
) -> tuple[int, dict[tuple[str, str, str], str]]:
    """Return ``(flags resolved, {(source path, verb, flag): "path:line"})``."""
    resolved = 0
    found: dict[tuple[str, str, str], str] = {}
    for rel, lineno, tokens in invocations:
        count, hit = _resolve_invocation_flags(root, tokens)
        resolved += count
        if hit is not None:
            found.setdefault((rel, hit[0], hit[1]), f"{rel}:{lineno}")
    return resolved, found


def test_assess_invocation_scan_is_non_trivial(assess_registries, assess_invocations):
    """Guard against a silently weakened lint.

    Two ways this check could go vacuous: the extractor stops matching
    invocations, or the resolver starts bailing out of every invocation before it
    reaches a flag. Both are invisible in a green suite, so both are anchored
    here — the second on the count of flags actually checked against a real
    parser, which is the quantity the assertion below depends on."""
    assert len(assess_invocations) >= 2000, (
        f"only {len(assess_invocations)} `vigil assess` invocations extracted — "
        "the tokenizer or the corpus glob regressed, and the reverse flag lint "
        "would silently weaken."
    )
    resolved, _ = _scan_invocations(assess_registries["_root_parser"], assess_invocations)
    assert resolved >= 2000, (
        f"only {resolved} documented flags resolved against the live parser tree "
        "— the walk is bailing out early and the reverse flag lint is no longer "
        "checking what it claims to."
    )


def test_documented_assess_flags_are_registered(assess_registries, assess_invocations):
    """docs -> CLI at the flag level. Every long flag written against a
    ``vigil assess`` verb in the corpus is one that verb actually registers.

    This is the check whose absence let ``--verification-state`` /
    ``--verification-disposition``, ``fetch --slug``, ``agent list --json`` and
    ``kali nikto --ssl`` ship: every verb involved was real, so the verb-level
    assertions passed while the flags died at argparse exit 2 — or, for a filter
    flag, came back as a silently empty result."""
    root = assess_registries["_root_parser"]
    _resolved, located = _scan_invocations(root, assess_invocations)
    dangling = sorted(located)
    assert not dangling, (
        "Prompt/doc text names `--flag`s that are not registered on the verb they "
        "are written against. An operator copy-pasting one gets argparse exit 2. "
        "Fix the prose, or register the flag on the command module:\n  "
        + "\n  ".join(
            f"{located[entry]}: vigil assess {entry[1]} {entry[2]}".replace("  ", " ")
            for entry in dangling
        )
    )


def test_python_assess_invocation_scan_is_non_trivial(
    assess_registries, python_assess_invocations
):
    """The ``doc_files`` anchor above, for the runtime-string corpus.

    The extractor here has one extra way to go quiet: ``ast`` finds no string
    literals (a parse that silently yields nothing, or a walk that stops
    descending). Anchoring both the invocation count and the number of flags
    actually checked against a real parser makes either failure loud."""
    assert len(python_assess_invocations) >= 700, (
        f"only {len(python_assess_invocations)} `vigil assess` invocations "
        "extracted from Python string literals — the literal walk, the "
        "tokenizer or the corpus glob regressed."
    )
    resolved, _ = _scan_invocations(
        assess_registries["_root_parser"], python_assess_invocations
    )
    assert resolved >= 500, (
        f"only {resolved} runtime-string flags resolved against the live parser "
        "tree — the walk is bailing out early and this check is no longer "
        "checking what it claims to."
    )


def test_runtime_string_assess_flags_are_registered(
    assess_registries, python_assess_invocations
):
    """runtime strings -> CLI at the flag level.

    Same assertion as the markdown direction, against the surface that matters
    most: a command an operator is told to run *by a failure*. Three backend
    messages sent the operator to ``finding link --target-finding <slug>`` — a
    flag ``finding link`` has never registered — so being refused a sibling
    link handed you an argparse exit 2 as the remedy."""
    root = assess_registries["_root_parser"]
    _resolved, located = _scan_invocations(root, python_assess_invocations)
    dangling = sorted(located)
    assert not dangling, (
        "Runtime error/advisory strings name `--flag`s that are not registered "
        "on the verb they are written against. An operator copy-pasting one "
        "gets argparse exit 2 at the moment they were told how to recover. "
        "Fix the string, or register the flag on the command module:\n  "
        + "\n  ".join(
            f"{located[entry]}: vigil assess {entry[1]} {entry[2]}".replace("  ", " ")
            for entry in dangling
        )
    )


# --------------------------------------------------------------------------
# (e) logs tail is not correlation.
# --------------------------------------------------------------------------
# A logs tail is named with one of these tokens.
_LOGS_VERB_RE = re.compile(r"vigil oob client logs|vigil logs oob")
# Disclaimers that correctly mark a logs tail as NON-correlation. These name the
# "raw tail / infra debugging" framing specifically; plain grammatical negation
# is handled by _LOGS_CORRELATION_DISAVOWED_RE below, because an allowlist of
# phrasings cannot decide whether a sentence asserts correlation or denies it.
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


# The contract is about WHO correlates, so the check has to see negation, not a
# fixed set of sentences. The marker list alone flagged "`vigil oob client logs`
# does not correlate hits" and "... cannot correlate a callback to a request"
# exactly as it flagged "Use `vigil oob client logs` to correlate callbacks" —
# the two plainest ways to state the contract were indistinguishable from
# breaking it, which pushes an author toward vaguer wording to satisfy the lint.
#
# Proximity alone cannot decide it. A 60-character window that only had to avoid
# `.;:` accepted any negation that happened to be nearby, including one that
# negates a DIFFERENT clause — "should not be overlooked because it correlates
# callbacks" and "is not preferred, but it correlates each hit" both assert the
# correlation claim outright and both cleared the window. What separates a
# disavowal from a claim is GRAMMATICAL GOVERNMENT: the negator has to attach to
# the correlation verb itself, so only an adverb or two may sit between them and
# no punctuation may, because a comma or a subordinator ("because", "but") is
# precisely the boundary at which the negation stops applying.

# `\b` cannot anchor the contracted `n't` — the character before it is a word
# character — so that family gets its own alternative.
_CORRELATION_NEGATOR = r"(?:\bcannot\b|\bcan['’]?t\b|\bnever\b|\bnot?\b|\w+n['’]t\b)"

_LOGS_CORRELATION_DISAVOWED_RE = re.compile(
    rf"{_CORRELATION_NEGATOR}(?:\s+[\w'’-]+){{0,2}}\s+(?:correlat|attribut)",
    re.IGNORECASE,
)


def _logs_correlation_offence(line: str) -> bool:
    """True when a line ties a logs tail to correlation without disavowing it."""
    if not _LOGS_VERB_RE.search(line):
        return False
    lowered = line.lower()
    if "correlat" not in lowered:
        return False
    if any(marker in lowered for marker in _NEGATION_MARKERS):
        return False
    return not _LOGS_CORRELATION_DISAVOWED_RE.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "`vigil oob client logs` cannot attribute callbacks; use `vigil oob poll` to correlate them",
        "`vigil oob client logs` does not correlate hits; `vigil oob poll` does",
        "`vigil oob client logs` cannot correlate a callback to a request",
        "`vigil logs oob` is a raw tail and never correlates anything",
        # An adverb between the negator and the verb still reads as a disavowal;
        # so does the contracted form, which no `\b`-anchored token can match.
        "`vigil oob client logs` does not reliably correlate callbacks",
        "`vigil oob client logs` doesn't correlate hits",
    ],
)
def test_a_correct_disavowal_is_not_an_offence(line):
    """Stating the contract plainly must not fail the lint that guards it.

    Every line here says the logs tail does NOT correlate — which is exactly
    what the contract requires prose to say — and the keyword allowlist
    rejected the first three.
    """
    assert not _logs_correlation_offence(line)


@pytest.mark.parametrize(
    "line",
    [
        "Use `vigil oob client logs` to correlate callbacks",
        "`vigil oob client logs` correlates each hit to the request that caused it",
        "Correlate the callback with `vigil logs oob`",
        # Negation that modifies a DIFFERENT clause. Both of these assert the
        # correlation claim outright; the nearby `not` belongs to "overlooked"
        # and to "preferred", never to "correlates".
        "`vigil oob client logs` should not be overlooked because it correlates callbacks",
        "`vigil oob client logs` is not preferred, but it correlates each hit",
    ],
)
def test_claiming_a_logs_tail_correlates_is_still_an_offence(line):
    assert _logs_correlation_offence(line)


def test_logs_tail_never_described_as_correlation(doc_files):
    """No file may assert that `vigil oob client logs` / `vigil logs oob`
    *returns correlated* hits. Correlation is exclusively `vigil oob poll`."""
    offenders: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _logs_correlation_offence(line):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "A logs tail (`vigil oob client logs` / `vigil logs oob`) is described "
        "alongside correlation without disavowing it. Correlation is only "
        "`vigil oob poll`; the log tails are raw listener/FRP output for infra "
        "debugging:\n  " + "\n  ".join(offenders)
    )
