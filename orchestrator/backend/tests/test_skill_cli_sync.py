"""Markdown-vs-CLI sync-lint.

Operator-facing prose (skills, operator cores, agent prompts, shared
constraints) routinely names concrete ``vigil assess <verb>`` /
``vigil assess kali <verb>`` / ``vigil oob <verb>`` invocations. When the CLI
registries drift away from that prose — a verb renamed, removed, or never
shipped — an operator copy-pastes a command that dies with argparse's
generic "invalid choice" error. This guard catches that drift in CI.

Two assertions:

(a) Every ``vigil assess`` / ``vigil assess kali`` / ``vigil oob`` verb named in
    the markdown corpus resolves to a verb that the *real* CLI registries
    register. The registries are derived by importing the CLIs and walking
    the argparse subparser tree (which executes
    ``assess.cli``'s per-command ``register()`` hooks and the inline
    ``oob`` ``add_parser`` calls in ``vigil_cli.main``), so this
    test reflects the shipped command surface rather than a hand-maintained
    list.

(b) No file claims ``vigil oob client logs`` / ``vigil logs oob`` *returns
    correlated hits*. Correlation is exclusively ``vigil oob poll`` (it reads
    recorded probes from the backend and matches callbacks to nonces); the
    log tails are raw listener/FRP output for infra debugging only. The
    post-QA tree is careful to say "raw tail … not correlation"; this guard
    keeps any future edit from quietly reintroducing the wrong mental model.

Implementation notes:
- Verb tokens containing argparse-doc placeholders (``*``/``<``/``>``/``$``)
  or a trailing ``-`` (e.g. the glob ``vigil assess record-*``) are prose,
  not literal invocations, and are skipped.
- ``assess`` and ``oob`` themselves only have nested subparsers we do not
  enumerate beyond one level; the test validates the *first* verb after the
  top-level group, which is the level the registries define.
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


def _load_assess_registries() -> tuple[set[str], set[str]]:
    """Return ``(assess_verbs, kali_verbs)`` from agent/scripts/assess CLI."""
    cli = importlib.import_module("assess.cli")
    root = _capture_root_parser(cli.main)
    top = _subparser_choices(root)
    assess_verbs = set(top)
    kali_verbs: set[str] = set()
    if "kali" in top:
        kali_verbs = set(_subparser_choices(top["kali"]))
    return assess_verbs, kali_verbs


def _load_oob_registries() -> tuple[set[str], set[str]]:
    """Return ``(oob_verbs, oob_client_verbs)`` from the installable CLI."""
    main_mod = importlib.import_module("vigil_cli.main")
    root = _capture_root_parser(main_mod.main)
    top = _subparser_choices(root)
    oob_verbs: set[str] = set()
    oob_client_verbs: set[str] = set()
    if "oob" in top:
        oob_verbs = set(_subparser_choices(top["oob"]))
        if "client" in oob_verbs:
            oob_client_verbs = set(_subparser_choices(_subparser_choices(top["oob"])["client"]))
    return oob_verbs, oob_client_verbs


# --------------------------------------------------------------------------
# Markdown corpus.
# --------------------------------------------------------------------------
def _doc_files() -> list[Path]:
    files: list[Path] = sorted((_REPO_ROOT / "agent" / "skills").glob("*/SKILL.md"))
    files += sorted(_REPO_ROOT.glob("agent/operator-core*.md"))
    files += sorted((_REPO_ROOT / "agent" / "agents").glob("*.md"))
    files += sorted(_REPO_ROOT.glob("agent/shared-constraints*.md"))
    return files


# A verb token is a literal CLI verb only if it is lowercase/dash/digit and
# carries no doc-placeholder punctuation. ``record-*``/``record-`` (a glob
# reference, not an invocation) is excluded by the trailing-dash guard.
_PLACEHOLDER = re.compile(r"[*<>${}]")


def _is_literal_verb(token: str) -> bool:
    return bool(token) and not _PLACEHOLDER.search(token) and not token.endswith("-")


# ``vigil assess <verb>`` and ``vigil assess kali <verb>``.
_ASSESS_RE = re.compile(r"vigil assess (kali )?([a-z][a-z0-9-]*)")
# ``vigil oob <verb>``.
_OOB_RE = re.compile(r"vigil oob ([a-z][a-z0-9-]*)")


@pytest.fixture(scope="module")
def assess_registries() -> tuple[set[str], set[str]]:
    return _load_assess_registries()


@pytest.fixture(scope="module")
def oob_registries() -> tuple[set[str], set[str]]:
    return _load_oob_registries()


@pytest.fixture(scope="module")
def doc_files() -> list[Path]:
    files = _doc_files()
    assert files, "no markdown docs discovered — corpus glob is broken"
    return files


def test_registries_are_non_trivial(assess_registries, oob_registries):
    """Guard against a silently empty registry (which would make assertion
    (a) vacuously pass and hide real drift)."""
    assess_verbs, kali_verbs = assess_registries
    oob_verbs, oob_client_verbs = oob_registries
    # Anchor on a few stable verbs that must always exist.
    assert {
        "record-finding",
        "kali",
        "log",
        "transition-phase",
        "eval-capture",
        "scaffold-probe",
    } <= assess_verbs
    assert {"nmap-scan", "exec", "httpx"} <= kali_verbs
    assert {"mint", "poll", "client", "status"} <= oob_verbs
    assert {"logs", "list", "start", "stop"} <= oob_client_verbs


def test_documented_assess_verbs_exist(assess_registries, doc_files):
    assess_verbs, kali_verbs = assess_registries
    unknown_assess: list[str] = []
    unknown_kali: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
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


def test_documented_oob_verbs_exist(oob_registries, doc_files):
    oob_verbs, _oob_client_verbs = oob_registries
    unknown: list[str] = []
    for path in doc_files:
        rel = path.relative_to(_REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for match in _OOB_RE.finditer(text):
            verb = match.group(1)
            if not _is_literal_verb(verb):
                continue
            if verb not in oob_verbs:
                unknown.append(f"{rel}: vigil oob {verb}")
    assert not unknown, (
        "Markdown references `vigil oob <verb>` not registered in "
        "src/vigil_cli/main.py:\n  " + "\n  ".join(sorted(set(unknown)))
    )


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
