"""Pinned surface of the assess CLI tree, contract corpus and dispatch refusals.

The argparse signature, the rendered contract corpus, the `--engagement-dir`
prepass refusals and every `code-dispatch` option refusal are operator-visible
strings with no other direct coverage. Each test asserts what the code emits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from unittest import mock

import pytest

from assess import cli
from assess.lib import contracts
from assess.lib.contract_registry import _CONTRACTS


# --------------------------------------------------------------------------- #
# The whole `vigil assess` argparse tree, to the depth the CLI contract covers:
# every leaf path, option string, dest, nargs, const, default, type, choices,
# required flag, help text and metavar. Pinned as one digest because the tree is
# an external contract (198 leaves) whose every field is operator-visible.
# --------------------------------------------------------------------------- #

_EXPECTED_LEAF_COUNT = 198
_EXPECTED_TREE_DIGEST = "baf50b614f354c1d6671959882c71dd4b235355ded60f98fbf8cc4ed87b36ab8"


def _stable(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _stable(item) for key, item in value.items()}
    if isinstance(value, type):
        return f"type:{value.__name__}"
    if callable(value):
        return f"callable:{getattr(value, '__name__', repr(value))}"
    return repr(value)


def _action_signature(action: argparse.Action) -> dict[str, object]:
    return {
        "class": type(action).__name__,
        "option_strings": list(action.option_strings),
        "dest": action.dest,
        "nargs": _stable(action.nargs),
        "const": _stable(action.const),
        "default": _stable(action.default),
        "type": _stable(action.type),
        "choices": list(action.choices) if action.choices is not None else None,
        "required": bool(action.required),
        "help": action.help,
        "metavar": _stable(action.metavar),
    }


def _parser_signature(
    parser: argparse.ArgumentParser, path: tuple[str, ...] = ()
) -> dict[str, object]:
    children = [
        _parser_signature(subparser, path + (name,))
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
        for name, subparser in action.choices.items()
    ]
    return {
        "path": " ".join(path),
        "prog": parser.prog,
        "description": parser.description,
        "epilog": parser.epilog,
        "formatter_class": parser.formatter_class.__name__,
        "parser_class": type(parser).__name__,
        "defaults": {
            key: _stable(value) for key, value in sorted(parser._defaults.items())
        },
        "actions": [_action_signature(action) for action in parser._actions],
        "children": children,
    }


def _root_parser() -> argparse.ArgumentParser:
    """The real root parser, captured the way test_cli_canonical_shapes does."""
    captured: dict[str, argparse.ArgumentParser] = {}
    real_parse_args = argparse.ArgumentParser.parse_args

    def _capture(self, args=None, namespace=None):
        if self.prog == "vigil assess":
            captured["parser"] = self
            raise SystemExit(0)
        return real_parse_args(self, args, namespace)

    with mock.patch.object(argparse.ArgumentParser, "parse_args", _capture):
        with pytest.raises(SystemExit):
            cli.main([])

    parser = captured.get("parser")
    assert parser is not None, "failed to capture the `vigil assess` root parser"
    return parser


def _leaf_paths(signature: dict[str, object]) -> list[str]:
    children = signature["children"]
    assert isinstance(children, list)
    if not children:
        path = signature["path"]
        return [str(path)] if path else []
    leaves: list[str] = []
    for child in children:
        assert isinstance(child, dict)
        leaves.extend(_leaf_paths(child))
    return leaves


def test_assess_argparse_tree_signature_is_unchanged() -> None:
    signature = _parser_signature(_root_parser())
    assert len(_leaf_paths(signature)) == _EXPECTED_LEAF_COUNT
    blob = json.dumps(signature, sort_keys=True, ensure_ascii=False, indent=1)
    assert hashlib.sha256(blob.encode()).hexdigest() == _EXPECTED_TREE_DIGEST


# --------------------------------------------------------------------------- #
# Every contract this CLI can render, rendered. Covers the static registry, the
# namespace parents, the per-intel-type forms, the kali per-verb composition,
# the agent/work-buffer verb branches (including the four agent aliases) and
# every `contract <verb>` epilog.
# --------------------------------------------------------------------------- #

_DISPATCH_VERB_ALIASES = ("register", "update-status", "record-handoff", "record-decision")
_KALI_BESPOKE_VERBS = ("sweep-orphans", "sweep", "tool-help", "gf")
_KALI_INLINE_VERBS = ("job", "exec", "browser")
_EXPECTED_CONTRACT_NAME_COUNT = 150
_EXPECTED_EPILOG_COUNT = 88
_EXPECTED_CONTRACT_DIGEST = "b45166b9614c09f4c17f74bb8c020ce13bb9657927ecc6a49988abe2e9b3b480"


def _renderable_contract_names() -> list[str]:
    names = set(contracts.contract_names())
    names |= set(_CONTRACTS)
    names |= {f"kali {verb}" for verb in contracts.KALI_VERBS}
    names |= {f"agent {verb}" for verb in contracts.AGENT_VERBS}
    names |= {f"agent {verb}" for verb in _DISPATCH_VERB_ALIASES}
    names |= {f"work-buffer {verb}" for verb in contracts._WORK_BUFFER_VERBS}
    names |= {f"kali {verb}" for verb in _KALI_BESPOKE_VERBS + _KALI_INLINE_VERBS}
    return sorted(names)


def _rendered_corpus() -> dict[str, dict[str, str]]:
    def _render(render, name: str) -> str:
        try:
            return render(name)
        except ValueError as exc:
            return f"__RAISED__ ValueError: {exc}"

    return {
        "render": {
            name: _render(contracts.render_contract, name)
            for name in _renderable_contract_names()
        },
        "epilog": {
            name: _render(contracts.render_contract_epilog, name)
            for name in sorted(_CONTRACTS)
        },
    }


def test_contract_corpus_renders_unchanged() -> None:
    corpus = _rendered_corpus()
    assert len(corpus["render"]) == _EXPECTED_CONTRACT_NAME_COUNT
    assert len(corpus["epilog"]) == _EXPECTED_EPILOG_COUNT
    blob = json.dumps(corpus, sort_keys=True, ensure_ascii=False, indent=1)
    assert hashlib.sha256(blob.encode()).hexdigest() == _EXPECTED_CONTRACT_DIGEST


def test_every_static_contract_name_matches_its_registry_key() -> None:
    # ACC-1 derives `name` from the dict key; this is the invariant that makes
    # that derivation lossless.
    for key, contract in _CONTRACTS.items():
        assert contract.name == key


def test_unknown_contract_still_raises_with_the_available_list() -> None:
    with pytest.raises(ValueError) as excinfo:
        contracts.render_contract("definitely-not-a-verb")
    message = str(excinfo.value)
    assert message.startswith("Unknown contract 'definitely-not-a-verb'. Available contracts: ")
    assert ", ".join(contracts.contract_names()) in message

    with pytest.raises(ValueError) as epilog_excinfo:
        contracts.render_contract_epilog("definitely-not-a-verb")
    assert str(epilog_excinfo.value) == message


# --------------------------------------------------------------------------- #
# `--engagement-dir` pre-pass refusals, for both accepted spellings.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "argv, message",
    [
        (
            ["--engagement-dir", "", "fetch"],
            "--engagement-dir: value is empty; pass an absolute or relative path",
        ),
        (
            ["--engagement-dir=", "fetch"],
            "--engagement-dir: value is empty; pass an absolute or relative path",
        ),
        (
            ["--engagement-dir", "-x", "fetch"],
            "--engagement-dir: value '-x' looks like a flag; "
            "pass an absolute or relative path",
        ),
        (
            ["--engagement-dir=-x", "fetch"],
            "--engagement-dir: value '-x' looks like a flag; "
            "pass an absolute or relative path",
        ),
        (
            ["--engagement-dir", "/a", "--engagement-dir", "/b", "fetch"],
            "--engagement-dir was specified more than once",
        ),
        (
            ["--engagement-dir=/a", "--engagement-dir=/b", "fetch"],
            "--engagement-dir was specified more than once",
        ),
        (
            ["--engagement-dir", "/a", "--engagement-dir=/b", "fetch"],
            "--engagement-dir was specified more than once",
        ),
    ],
)
def test_engagement_dir_prepass_refusals(argv: list[str], message: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli._hoist_root_flags(argv)
    assert excinfo.value.code == message


def test_engagement_dir_prepass_hoists_both_spellings() -> None:
    assert cli._hoist_root_flags(["fetch", "--engagement-dir", "/a"]) == [
        "--engagement-dir",
        "/a",
        "fetch",
    ]
    assert cli._hoist_root_flags(["fetch", "--engagement-dir=/a"]) == [
        "--engagement-dir=/a",
        "fetch",
    ]


# --------------------------------------------------------------------------- #
# `code-dispatch` token walkers: every refusal sentence and every accepted
# shape, for the five verbs that parse their own option tokens.
# --------------------------------------------------------------------------- #

def _adopt_lease_required(missing: str) -> str:
    return (
        f"ERROR: code-dispatch adopt-lease requires {missing}; --from-agent and "
        "--from-lease are the exact identity `code-dispatch list` showed for the "
        "lease you are replacing, and --reason records why it is presumed dead"
    )


_ADOPT_LEASE_REQUIRED = _adopt_lease_required("--from-agent, --from-lease, --reason")
_RELEASE_REQUIRED = (
    "ERROR: code-dispatch release requires --reason TEXT; it is the only "
    "record of why this file was handed back with no verdict"
)
_SHOW_TOKENS_CONFLICT = (
    "ERROR: --show-tokens only renders the table; --json and --ids-only "
    "already carry every row value"
)


def _refusal(capsys, parser, tokens: list[str]) -> str:
    with pytest.raises(SystemExit) as excinfo:
        parser(tokens)
    assert excinfo.value.code == 1
    return capsys.readouterr().err


@pytest.mark.parametrize(
    "verb, tokens, expected",
    [
        ("reset-stale", ["--nope", "1"], "Unknown or incomplete code-dispatch reset-stale option: --nope"),
        ("reset-stale", ["--repo-id"], "Unknown or incomplete code-dispatch reset-stale option: --repo-id"),
        ("reset-stale", ["--repo-id", "0"], "ERROR: --repo-id requires an integer >= 1"),
        ("reset-stale", ["--repo-id", "x"], "ERROR: --repo-id requires an integer >= 1"),
        ("reset-stale", ["--repo-id", "-1"], "ERROR: --repo-id requires an integer >= 1"),
        ("reset-stale", ["--repo-id", "1", "--repo-id", "2"], "ERROR: --repo-id was specified more than once"),
        ("reset-stale", ["--batch-theme", " "], "ERROR: --batch-theme requires a value"),
        ("reset-stale", ["--queue-mode", ""], "ERROR: --queue-mode requires a value"),
        ("reset-stale", ["--batch-theme", "a", "--batch-theme", "b"], "ERROR: --batch-theme was specified more than once"),
        ("reset-stale", ["--path-prefix", " "], "ERROR: --path-prefix requires a value"),
        ("reset-stale", ["--path-glob", ""], "ERROR: --path-glob requires a value"),
        ("release", ["--nope", "x"], "Unknown or incomplete code-dispatch release option: --nope"),
        ("release", ["--reason"], "Unknown or incomplete code-dispatch release option: --reason"),
        ("release", ["--reason", "a", "--reason", "b"], "ERROR: --reason was specified more than once"),
        ("release", ["--reason", "  "], "ERROR: --reason requires a value"),
        ("release", [], _RELEASE_REQUIRED),
        ("adopt-lease", ["--nope", "x"], "Unknown or incomplete code-dispatch adopt-lease option: --nope"),
        ("adopt-lease", ["--path-prefix", "src"], "Unknown or incomplete code-dispatch adopt-lease option: --path-prefix"),
        ("adopt-lease", ["--reason"], "Unknown or incomplete code-dispatch adopt-lease option: --reason"),
        ("adopt-lease", ["--reason", "a", "--reason", "b"], "ERROR: --reason was specified more than once"),
        ("adopt-lease", ["--from-agent", " "], "ERROR: --from-agent requires a value"),
        ("adopt-lease", ["--stale-minutes", "0"], "ERROR: --stale-minutes requires an integer between 1 and 1440"),
        ("adopt-lease", ["--stale-minutes", "1441"], "ERROR: --stale-minutes requires an integer between 1 and 1440"),
        ("adopt-lease", ["--stale-minutes", "zz"], "ERROR: --stale-minutes requires an integer between 1 and 1440"),
        ("adopt-lease", ["--stale-minutes", "5", "--stale-minutes", "6"], "ERROR: --stale-minutes was specified more than once"),
        ("adopt-lease", [], _ADOPT_LEASE_REQUIRED),
        ("adopt-lease", ["--reason", "dead"], _adopt_lease_required("--from-agent, --from-lease")),
        ("list", ["--nope", "1"], "Unknown or incomplete code-dispatch list option: --nope"),
        ("list", ["--status"], "Unknown or incomplete code-dispatch list option: --status"),
        ("list", ["--status", "a", "--status", "b"], "ERROR: --status was specified more than once"),
        ("list", ["--status", " "], "ERROR: --status requires a value"),
        ("list", ["--repo-id", "0"], "ERROR: --repo-id requires an integer >= 1"),
        ("list", ["--stale-minutes", "0"], "ERROR: --stale-minutes requires an integer >= 1"),
        ("list", ["--limit", "x"], "ERROR: --limit requires an integer >= 1"),
        ("list", ["--offset", "-1"], "ERROR: --offset requires an integer >= 0"),
        ("list", ["--limit", "1", "--limit", "2"], "ERROR: --limit was specified more than once"),
        ("list", ["--show-tokens", "--show-tokens"], "ERROR: --show-tokens was specified more than once"),
        ("list", ["--json", "--ids-only"], "ERROR: choose either --json or --ids-only, not both"),
        ("list", ["--ids-only", "--json"], "ERROR: choose either --json or --ids-only, not both"),
        ("list", ["--json", "--show-tokens"], _SHOW_TOKENS_CONFLICT),
        ("list", ["--show-tokens", "--json"], _SHOW_TOKENS_CONFLICT),
        ("list", ["--show-tokens", "--ids-only"], _SHOW_TOKENS_CONFLICT),
        ("fetch", ["--nope", "1"], "Unknown or incomplete code-dispatch fetch option: --nope"),
        ("fetch", ["--repo-id"], "Unknown or incomplete code-dispatch fetch option: --repo-id"),
        ("fetch", ["--repo-id", "x"], "--repo-id must be an integer"),
        ("fetch", ["--path-prefix", " "], "ERROR: --path-prefix requires a value"),
    ],
)
def test_code_dispatch_option_refusals(capsys, verb: str, tokens: list[str], expected: str) -> None:
    from assess.commands import code_dispatch

    parsers = {
        "reset-stale": code_dispatch._parse_reset_stale_options,
        "release": code_dispatch._parse_release_options,
        "adopt-lease": code_dispatch._parse_adopt_lease_options,
        "list": lambda t: code_dispatch._parse_list_filters(t),
        "fetch": code_dispatch._parse_fetch_filters,
    }
    assert _refusal(capsys, parsers[verb], tokens).strip() == expected


def test_code_dispatch_reset_stale_accepts_a_full_scope() -> None:
    from assess.commands import code_dispatch

    assert code_dispatch._parse_reset_stale_options(
        [
            "--repo-id",
            "7",
            "--batch-theme",
            "auth",
            "--queue-mode",
            "depth",
            "--path-glob",
            "*.py",
            "--path-prefix",
            "src/b",
            "--path-prefix",
            "src/a",
            "--path-prefix",
            "src/a",
        ]
    ) == {
        "repo_id": 7,
        "batch_theme": "auth",
        "queue_mode": "depth",
        "path_glob": ["*.py"],
        "path_prefix": ["src/a", "src/b"],
    }
    assert code_dispatch._parse_reset_stale_options([]) == {}


def test_code_dispatch_release_returns_the_reason() -> None:
    from assess.commands import code_dispatch

    assert code_dispatch._parse_release_options(["--reason", "lane closed"]) == {
        "reason": "lane closed"
    }


def test_code_dispatch_adopt_lease_defaults_the_window() -> None:
    from assess.commands import code_dispatch

    base = ["--from-agent", "a1", "--from-lease", "tok", "--reason", "dead"]
    assert code_dispatch._parse_adopt_lease_options(base) == {
        "expected_agent": "a1",
        "expected_lease_token": "tok",
        "reason": "dead",
        "stale_minutes": 10,
    }
    assert code_dispatch._parse_adopt_lease_options(base + ["--stale-minutes", "90"])[
        "stale_minutes"
    ] == 90


def test_code_dispatch_list_filters_keep_their_canonical_order() -> None:
    from assess.commands import code_dispatch

    values, output = code_dispatch._parse_list_filters(
        [
            "--offset",
            "20",
            "--status",
            "claimed",
            "--path-glob",
            "*.py",
            "--limit",
            "5",
            "--show-tokens",
            "--repo-id",
            "3",
        ]
    )
    assert output == "table"
    # Path scopes land last: they are merged after the walk, so their key order
    # never depends on where the operator typed them.
    assert list(values) == [
        "offset",
        "status",
        "limit",
        "repo_id",
        "path_glob",
        "show_tokens",
    ]
    assert values == {
        "offset": "20",
        "status": "claimed",
        "path_glob": ["*.py"],
        "limit": "5",
        "repo_id": "3",
        "show_tokens": "1",
    }
    assert code_dispatch._parse_list_filters(["--json"]) == ({}, "json")
    assert code_dispatch._parse_list_filters(["--ids-only"]) == ({}, "ids")
    assert code_dispatch._parse_list_filters([]) == ({}, "table")


def test_code_dispatch_fetch_filters_keep_their_lenient_shape() -> None:
    from assess.commands import code_dispatch

    # `fetch` deliberately differs from the other walkers: no duplicate-flag
    # refusal, no empty-value refusal, a lenient int and a fixed path-scope
    # key order.
    assert code_dispatch._parse_fetch_filters(
        [
            "--repo-id",
            "4",
            "--repo-id",
            "5",
            "--classification",
            "",
            "--path-glob",
            "*.py",
            "--path-prefix",
            "src",
        ]
    ) == {
        "repo_id": 5,
        "classification": "",
        "path_prefix": ["src"],
        "path_glob": ["*.py"],
    }
    assert list(
        code_dispatch._parse_fetch_filters(
            ["--path-glob", "*.py", "--path-prefix", "src"]
        )
    ) == ["path_prefix", "path_glob"]


# --------------------------------------------------------------------------- #
# Path-selector resolution, for the two verbs that resolve a `file_path` (plus
# optional `repo_id`) against a fetched code/files listing.
# --------------------------------------------------------------------------- #

_CODE_FILES = [
    {"id": 1, "file_path": "src/auth/login.py", "repo_id": 1},
    {"id": 2, "file_path": "src/auth/login.py", "repo_id": 2},
    {"id": 3, "file_path": "src/api/routes.py", "repo_id": 1},
    {"id": 4, "file_path": "src/api/helpers.py", "repo_id": 2},
]


def _queue_ids(item: dict) -> list[int]:
    from assess.commands import code_dispatch

    return code_dispatch._resolve_queue_file_ids(item, _CODE_FILES)


def _classify_ids(item: dict) -> list[int]:
    from assess.commands import code_classify

    return code_classify._resolve_matching_file_ids(item, _CODE_FILES)


@pytest.mark.parametrize(
    "item, expected",
    [
        ({"file_id": 9}, [9]),
        ({"file_path": "src/api/routes.py"}, [3]),
        ({"file_path": "src/auth/login.py", "repo_id": 2}, [2]),
        ({"file_path": "src/api/*.py"}, [3, 4]),
        ({"file_path": "src/api/*.py", "repo_id": 1}, [3]),
        ({"file_path": "src/auth/*.py"}, [1, 2]),
        ({"file_path": "  src/api/routes.py  "}, [3]),
        ({"file_path": "src/nope/*.py", "file_id": ""}, None),
    ],
)
def test_path_resolution_agrees_for_both_verbs(item: dict, expected: list[int] | None) -> None:
    if expected is None:
        for resolver in (_queue_ids, _classify_ids):
            with pytest.raises(SystemExit):
                resolver(dict(item))
        return
    assert _queue_ids(dict(item)) == expected
    assert _classify_ids(dict(item)) == expected


@pytest.mark.parametrize(
    "item, expected",
    [
        ({"file_id": 0}, "Invalid queue file_id: 0"),
        ({"file_id": "7"}, "Invalid queue file_id: '7'"),
        ({"file_id": True}, "Invalid queue file_id: True"),
        ({}, "Queue item must include file_id or file_path or queue_item_id"),
        ({"file_path": "   "}, "Queue item must include file_id or file_path or queue_item_id"),
        ({"file_path": "a.py", "repo_id": 0}, "Invalid queue repo_id: 0"),
        ({"file_path": "a.py", "repo_id": "1"}, "Invalid queue repo_id: '1'"),
        ({"file_path": "src/nope.py"}, "No code file found for queue path: src/nope.py"),
        (
            {"file_path": "src/auth/login.py"},
            "Ambiguous queue path 'src/auth/login.py'; include file_id or repo_id to disambiguate",
        ),
        (
            {"file_path": "src/api/*.py", "repo_id": 7},
            "No code file found for queue path: src/api/*.py",
        ),
    ],
)
def test_queue_path_resolution_refusals(capsys, item: dict, expected: str) -> None:
    assert _refusal(capsys, _queue_ids, dict(item)).strip() == expected


@pytest.mark.parametrize(
    "item, expected",
    [
        ({"file_id": 0}, "Invalid file_id in classification item: 0"),
        ({"file_id": "7"}, "Invalid file_id in classification item: '7'"),
        ({}, "Classification item must include either 'file_id' or 'file_path'"),
        (
            {"file_path": "   "},
            "Classification item must include either 'file_id' or 'file_path'",
        ),
        ({"file_path": "a.py", "repo_id": 0}, "Invalid repo_id in classification item: 0"),
        (
            {"file_path": "a.py", "repo_id": "1"},
            "Invalid repo_id in classification item: '1'",
        ),
        (
            {"file_path": "src/nope.py"},
            "No code file found for classification path: src/nope.py",
        ),
        (
            {"file_path": "src/auth/login.py"},
            "Ambiguous classification path 'src/auth/login.py'; include file_id or "
            "repo_id to disambiguate",
        ),
    ],
)
def test_classification_path_resolution_refusals(capsys, item: dict, expected: str) -> None:
    assert _refusal(capsys, _classify_ids, dict(item)).strip() == expected


# --------------------------------------------------------------------------- #
# The two bounded `git log` history scans in code-ingest: their accumulated
# results and every warning the shared scaffold can emit.
# --------------------------------------------------------------------------- #


def _git_repo(tmp_path, monkeypatch):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "Acme Dev",
        "GIT_AUTHOR_EMAIL": "dev@acme.example",
        "GIT_COMMITTER_NAME": "Acme Dev",
        "GIT_COMMITTER_EMAIL": "dev@acme.example",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(tmp_path),
    }

    def _git(*args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=repo, check=True, env=env, capture_output=True
        )

    _git("init", "-q", "-b", "main")
    (repo / "login.py").write_text("one\ntwo\n", encoding="utf-8")
    _git("add", "login.py")
    _git("commit", "-q", "-m", "add login")
    (repo / "login.py").write_text("one\ntwo\nthree\n", encoding="utf-8")
    _git("commit", "-q", "-a", "-m", "Security fix for login")
    return repo


def test_git_history_scans_accumulate_from_a_real_repository(tmp_path, monkeypatch) -> None:
    from assess.commands import code_ingest

    repo = _git_repo(tmp_path, monkeypatch)
    churn = code_ingest._git_churn_scores(str(repo))
    assert churn == {"login.py": 3}
    assert code_ingest._git_security_files(str(repo)) == {"login.py"}
    assert code_ingest._git_security_files(str(repo), ["HEAD"]) == {"login.py"}


def test_git_history_scans_warn_once_when_git_refuses(tmp_path, capsys) -> None:
    from assess.commands import code_ingest

    plain = tmp_path / "plain"
    plain.mkdir()

    assert code_ingest._git_churn_scores(str(plain)) == {}
    churn_err = capsys.readouterr().err
    assert churn_err.startswith(f"Warning: git churn scan failed for {plain}")

    assert code_ingest._git_security_files(str(plain)) == set()
    security_err = capsys.readouterr().err
    assert security_err.startswith(
        f"Warning: git security-history scan failed for {plain}"
    )


@pytest.mark.parametrize(
    "scan, expected",
    [
        (
            "churn",
            "Warning: trusted Git executable disappeared before churn scan\n",
        ),
        (
            "security",
            "Warning: trusted Git executable disappeared before "
            "security-history scan\n",
        ),
    ],
)
def test_git_history_scans_warn_when_the_binary_is_gone(
    tmp_path, capsys, monkeypatch, scan: str, expected: str
) -> None:
    from assess.commands import code_ingest

    monkeypatch.setattr(
        code_ingest, "_resolve_trusted_tool", lambda *a, **k: None
    )
    if scan == "churn":
        assert code_ingest._git_churn_scores(str(tmp_path)) == {}
    else:
        assert code_ingest._git_security_files(str(tmp_path)) == set()
    assert capsys.readouterr().err == expected


@pytest.mark.parametrize(
    "scan, expected",
    [
        (
            "churn",
            "Warning: git churn scan timed out for {path} after 120s; "
            "git churn data will be incomplete\n",
        ),
        (
            "security",
            "Warning: git security-history scan timed out for {path} after 120s; "
            "security-history annotations will be incomplete\n",
        ),
    ],
)
def test_git_history_scans_warn_on_timeout(
    tmp_path, capsys, monkeypatch, scan: str, expected: str
) -> None:
    import subprocess

    from assess.commands import code_ingest

    monkeypatch.setattr(
        code_ingest, "_resolve_trusted_tool", lambda *a, **k: "/usr/bin/git"
    )

    def _boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=120)

    monkeypatch.setattr(code_ingest, "_run_git", _boom)
    if scan == "churn":
        assert code_ingest._git_churn_scores(str(tmp_path)) == {}
    else:
        assert code_ingest._git_security_files(str(tmp_path)) == set()
    assert capsys.readouterr().err == expected.format(path=tmp_path)


@pytest.mark.parametrize(
    "scan, expected",
    [
        ("churn", "Warning: git churn scan failed for {path}: broken\n"),
        (
            "security",
            "Warning: git security-history scan failed for {path}: broken\n",
        ),
    ],
)
def test_git_history_scans_warn_on_an_os_error(
    tmp_path, capsys, monkeypatch, scan: str, expected: str
) -> None:
    from assess.commands import code_ingest

    monkeypatch.setattr(
        code_ingest, "_resolve_trusted_tool", lambda *a, **k: "/usr/bin/git"
    )

    def _boom(*args, **kwargs):
        raise OSError("broken")

    monkeypatch.setattr(code_ingest, "_run_git", _boom)
    if scan == "churn":
        assert code_ingest._git_churn_scores(str(tmp_path)) == {}
    else:
        assert code_ingest._git_security_files(str(tmp_path)) == set()
    assert capsys.readouterr().err == expected.format(path=tmp_path)


# --------------------------------------------------------------------------- #
# The directory-pruning prologue shared by the two source-inventory passes:
# `.git`, the snapshots root, and the skip policy, in that order, with the
# excluded pass recording every directory the admitted pass silently drops.
# --------------------------------------------------------------------------- #


def _ingest_args(repo, **overrides):
    from types import SimpleNamespace

    from assess.commands import code_ingest

    base = dict(
        repo_path=str(repo),
        name=None,
        language=None,
        default_language_for_unknown=None,
        repo_key=None,
        include_minified=False,
        include_skipped=False,
        include_path=[],
        policy_preset="application",
        max_included_skipped_bytes=code_ingest.DEFAULT_MAX_INCLUDED_SKIPPED_BYTES,
        skipped_manifest=None,
        dry_run=True,
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _inventory_tree(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (repo / "node_modules" / "left-pad").mkdir(parents=True)
    (repo / "node_modules" / "left-pad" / "index.js").write_text("y\n", encoding="utf-8")
    snapshots = repo / ".vigil-snapshots" / "generation-1"
    snapshots.mkdir(parents=True)
    (snapshots / "sealed.json").write_text("{}\n", encoding="utf-8")
    return repo


def test_source_inventory_passes_partition_the_same_tree(tmp_path) -> None:
    from assess.commands import code_ingest
    from assess.lib.code_snapshot import RootedSourceTree

    repo = _inventory_tree(tmp_path)
    args = _ingest_args(repo)
    snapshots_root = repo / ".vigil-snapshots"

    with RootedSourceTree(repo) as tree:
        admitted = sorted(
            code_ingest._admitted_source_paths(tree, args, snapshots_root)
        )
    assert admitted == ["src/app.py"]

    with RootedSourceTree(repo) as tree:
        excluded = code_ingest._collect_excluded_records(tree, args, snapshots_root)

    # The snapshots root and `.git` are dropped without a record; a
    # policy-skipped directory is recorded and then enumerated.
    assert [
        (record["path"], record["kind"], record["reason"]) for record in excluded
    ] == [
        ("node_modules", "directory", "skipped_dir:node_modules"),
        ("node_modules/left-pad", "directory", "skipped_dir:node_modules"),
        ("node_modules/left-pad/index.js", "file", "skipped_dir:node_modules"),
    ]


def test_source_inventory_passes_agree_when_the_snapshots_root_is_outside(tmp_path) -> None:
    from assess.commands import code_ingest
    from assess.lib.code_snapshot import RootedSourceTree

    repo = _inventory_tree(tmp_path)
    args = _ingest_args(repo)
    outside = tmp_path / "elsewhere"

    with RootedSourceTree(repo) as tree:
        admitted = sorted(code_ingest._admitted_source_paths(tree, args, outside))
    assert admitted == [".vigil-snapshots/generation-1/sealed.json", "src/app.py"]

    with RootedSourceTree(repo) as tree:
        excluded = code_ingest._collect_excluded_records(tree, args, outside)
    assert [record["path"] for record in excluded] == [
        "node_modules",
        "node_modules/left-pad",
        "node_modules/left-pad/index.js",
    ]


# --------------------------------------------------------------------------- #
# The three bounded walks over `code/files`: the exact endpoint sequence each
# verb requests, what it accumulates, and every refusal it prints.
# --------------------------------------------------------------------------- #


class _PagingClient:
    """A stand-in for AssessmentClient that serves a canned page sequence."""

    def __init__(self, pages: list[object]) -> None:
        self.pages = list(pages)
        self.endpoints: list[str] = []

    def __call__(self, *args: object, **kwargs: object) -> "_PagingClient":
        return self

    def __enter__(self) -> "_PagingClient":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, endpoint: str) -> object:
        self.endpoints.append(endpoint)
        return self.pages.pop(0)


def _page(items: list[dict], *, offset: int, total: int) -> dict:
    return {
        "total": total,
        "offset": offset,
        "count": len(items),
        "has_more": offset + len(items) < total,
        "items": items,
    }


def _cfg():
    from types import SimpleNamespace

    return SimpleNamespace(base_url="http://backend.example", engagement_key="key")


def _rows(start: int, count: int) -> list[dict]:
    return [
        {"id": index, "file_path": f"src/f{index}.py", "repo_id": 1}
        for index in range(start, start + count)
    ]


def test_classify_code_file_walk_pages_to_the_end(monkeypatch) -> None:
    from assess.commands import code_classify

    client = _PagingClient(
        [
            _page(_rows(1, 2), offset=0, total=3),
            _page(_rows(3, 1), offset=2, total=3),
        ]
    )
    monkeypatch.setattr(code_classify, "AssessmentClient", client)
    assert code_classify._fetch_code_files(_cfg()) == _rows(1, 3)
    assert client.endpoints == [
        "code/files?limit=10000&offset=0",
        "code/files?limit=10000&offset=2",
    ]


@pytest.mark.parametrize(
    "pages",
    [
        [{"total": "x"}],
        [
            _page(_rows(1, 2), offset=0, total=3),
            _page(_rows(3, 1), offset=2, total=4),
        ],
    ],
)
def test_classify_code_file_walk_refuses(capsys, monkeypatch, pages: list[object]) -> None:
    from assess.commands import code_classify

    monkeypatch.setattr(code_classify, "AssessmentClient", _PagingClient(pages))
    with pytest.raises(SystemExit) as excinfo:
        code_classify._fetch_code_files(_cfg())
    assert excinfo.value.code == 1
    assert (
        capsys.readouterr().err.strip()
        == "Could not fetch code files for path resolution"
    )


def test_size_summary_code_file_walk_carries_the_repo_filter(monkeypatch) -> None:
    from assess.commands import code_size_summary

    client = _PagingClient([_page(_rows(1, 1), offset=0, total=1)])
    monkeypatch.setattr(code_size_summary, "AssessmentClient", client)
    assert code_size_summary._fetch_code_files(_cfg(), repo_id=7) == _rows(1, 1)
    assert client.endpoints == ["code/files?limit=10000&offset=0&repo_id=7"]

    unfiltered = _PagingClient([_page(_rows(1, 1), offset=0, total=1)])
    monkeypatch.setattr(code_size_summary, "AssessmentClient", unfiltered)
    assert code_size_summary._fetch_code_files(_cfg()) == _rows(1, 1)
    assert unfiltered.endpoints == ["code/files?limit=10000&offset=0"]


@pytest.mark.parametrize(
    "pages, expected",
    [
        ([{"total": "x"}], "code-size-summary: unexpected backend response"),
        (
            [
                _page(_rows(1, 2), offset=0, total=3),
                _page(_rows(3, 1), offset=2, total=4),
            ],
            "code-size-summary: backend total changed while paging",
        ),
    ],
)
def test_size_summary_code_file_walk_refusals(
    capsys, monkeypatch, pages: list[object], expected: str
) -> None:
    from assess.commands import code_size_summary

    monkeypatch.setattr(code_size_summary, "AssessmentClient", _PagingClient(pages))
    with pytest.raises(SystemExit) as excinfo:
        code_size_summary._fetch_code_files(_cfg())
    assert excinfo.value.code == 1
    assert capsys.readouterr().err.strip() == expected


def test_dispatch_code_file_walk_keeps_only_selector_matches(monkeypatch) -> None:
    from assess.commands import code_dispatch

    client = _PagingClient(
        [
            _page(
                [
                    {"id": 1, "file_path": "src/auth/login.py", "repo_id": 1},
                    {"id": 2, "file_path": "src/api/routes.py", "repo_id": 1},
                ],
                offset=0,
                total=3,
            ),
            _page(
                [{"id": 3, "file_path": "src/auth/token.py", "repo_id": 2}],
                offset=2,
                total=3,
            ),
        ]
    )
    monkeypatch.setattr(code_dispatch, "AssessmentClient", client)
    matched = code_dispatch._fetch_code_files(
        _cfg(), [{"file_path": "src/auth/*.py"}]
    )
    assert [row["id"] for row in matched] == [1, 3]
    assert client.endpoints == [
        "code/files?limit=10000&offset=0",
        "code/files?limit=10000&offset=2",
    ]


@pytest.mark.parametrize(
    "pages",
    [
        [{"total": "x"}],
        [
            _page(_rows(1, 2), offset=0, total=3),
            _page(_rows(3, 1), offset=2, total=4),
        ],
        [
            _page(
                [{"id": 0, "file_path": "src/f1.py", "repo_id": 1}],
                offset=0,
                total=1,
            )
        ],
    ],
)
def test_dispatch_code_file_walk_refuses(capsys, monkeypatch, pages: list[object]) -> None:
    from assess.commands import code_dispatch

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PagingClient(pages))
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._fetch_code_files(_cfg(), [{"file_path": "src/*.py"}])
    assert excinfo.value.code == 1
    assert (
        capsys.readouterr().err.strip()
        == "Could not fetch code files for queue normalization"
    )
