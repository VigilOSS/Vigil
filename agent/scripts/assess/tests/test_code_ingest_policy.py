"""I-108 / I-109 / I-115 — `code-ingest` admission policy must be honest.

Three separate ways a `code-ingest` run could measure nothing and say nothing:

* I-108 — `--include-path` is a glob matched against the full relative FILE
  path, so a bare directory could never match while the walker still descended
  into it. It is now auto-expanded, an unmatched pattern is reported, and a run
  where EVERY pattern matched nothing refuses. The repeatable-flag parse is
  pinned here too: it was reported broken and is not.
* I-109 — a 14-of-882 ingest printed `Total files: 14 (868 skipped)` and looked
  like a healthy one. The summary now carries the denominator plus a per-reason
  census, and a collapsed admission ratio warns loudly.
* I-115 — an extensionless generated symbol index (`tags`, 20.7 MB in the
  reported engagement) was admitted as first-class reviewable source.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_ingest
from assess.lib.code_snapshot import RootedSourceTree


def _args(repo: Path, **overrides) -> SimpleNamespace:
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


def _admitted(repo: Path, args) -> list[str]:
    with RootedSourceTree(repo) as tree:
        return sorted(code_ingest._admitted_source_paths(tree, args, repo / ".nonexistent"))


def _excluded(repo: Path, args) -> dict[str, str]:
    with RootedSourceTree(repo) as tree:
        return {
            str(record["path"]): str(record["reason"])
            for record in code_ingest._collect_excluded_records(
                tree, args, repo / ".nonexistent"
            )
            if record.get("kind") != "directory"
        }


def _engagement(tmp_path: Path) -> str:
    eng = tmp_path / "engagement"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text('{"hosts": []}\n', encoding="utf-8")
    return str(eng)


def _package_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "dist").mkdir()
    (repo / "node_modules" / "left-pad").mkdir(parents=True)
    (repo / "src" / "app.js").write_text("export const a = 1;\n", encoding="utf-8")
    (repo / "dist" / "bundle.js").write_text("var a=1;\n", encoding="utf-8")
    (repo / "node_modules" / "left-pad" / "index.js").write_text("x\n", encoding="utf-8")
    return repo


# --- I-115: generated symbol indexes are not source -------------------------


@pytest.mark.parametrize(
    "basename", ["tags", "TAGS", "cscope.out", "GPATH", "GTAGS", "ID"]
)
def test_generated_symbol_indexes_are_skipped_by_basename(basename):
    assert code_ingest._skip_file_reason(basename, basename) == (
        f"skipped_basename:{basename}"
    )


def test_tags_is_excluded_from_source_and_re_admissible_by_include_path(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "tags").write_text("!_TAG_FILE_FORMAT\t2\n" * 100, encoding="utf-8")

    assert _admitted(repo, _args(repo)) == ["src/app.py"]
    assert _excluded(repo, _args(repo))["tags"] == "skipped_basename:tags"
    assert "tags" in _admitted(repo, _args(repo, include_path=["tags"]))


def test_large_ordinary_source_is_admitted_and_predicates_stay_symmetric(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    huge = repo / "huge.py"
    with huge.open("wb") as handle:
        handle.seek(6 * 1024 * 1024 - 1)
        handle.write(b"\n")
    args = _args(repo)

    assert _admitted(repo, args) == ["huge.py", "small.py"]
    assert "huge.py" not in _excluded(repo, args)

    # The admitted/excluded predicates partition the tree; a disagreement makes
    # _verify_source_inventory raise on every run.
    with RootedSourceTree(repo) as tree:
        bindings = {}
        for rel_path in code_ingest._admitted_source_paths(tree, args, repo / ".none"):
            captured = tree.capture(rel_path, retain_spool=False)
            bindings[rel_path] = (captured.sha256, captured.size, captured.executable)
        excluded = code_ingest._collect_excluded_records(tree, args, repo / ".none")
        code_ingest._verify_source_inventory(tree, args, repo / ".none", bindings, excluded)


def test_ordinary_source_size_cap_is_not_a_supported_cli_option():
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="cmd"))

    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["code-ingest", "/repo", "--max-source-file-bytes", "1"])

    assert excinfo.value.code == 2


# --- I-109: policy preset + census honesty ----------------------------------


def test_package_preset_admits_dist_and_still_excludes_node_modules(tmp_path):
    repo = _package_repo(tmp_path)

    assert _admitted(repo, _args(repo)) == ["src/app.js"]
    assert _admitted(repo, _args(repo, policy_preset="package")) == [
        "dist/bundle.js",
        "src/app.js",
    ]
    excluded = _excluded(repo, _args(repo, policy_preset="package"))
    assert excluded["node_modules/left-pad/index.js"] == "skipped_dir:node_modules"


def test_preset_does_not_shift_the_module_level_policy_code_index_imports(tmp_path):
    """`code_index` re-walks with SKIP_DIRS/_should_skip_file; its view is fixed."""
    repo = _package_repo(tmp_path)
    _admitted(repo, _args(repo, policy_preset="package"))

    assert "dist" in code_ingest.SKIP_DIRS
    assert code_ingest._should_skip_file("dist/bundle.js", "bundle.js") is True


def test_summary_census_carries_the_denominator_and_per_reason_counts(capsys):
    records = [
        {"path": "dist", "kind": "directory", "reason": "skipped_dir:dist"},
        *[
            {"path": f"dist/{i}.js", "kind": "file", "reason": "skipped_dir:dist"}
            for i in range(8)
        ],
        {"path": "logo.svg", "kind": "file", "reason": "skipped_extension:.svg"},
    ]
    census = code_ingest._skip_reason_census(records)
    assert census == [("skipped_dir:dist", 8), ("skipped_extension:.svg", 1)]

    code_ingest._print_skip_census(census, 2, sys.stdout)
    out = capsys.readouterr().out
    assert "Admitted files: 2 of 11 total (9 skipped)" in out
    assert "skipped skipped_dir:dist: 8" in out


def test_collapsed_admission_ratio_warns_with_the_dominant_reason(capsys):
    census = [("skipped_dir:dist", 860), ("skipped_extension:.svg", 8)]
    code_ingest._warn_on_collapsed_admission(census, 14)
    err = capsys.readouterr().err
    assert "admitted 14 of 882 files (1.6%)" in err
    assert "skipped_dir:dist: 860" in err
    assert "--policy-preset package" in err


def test_a_healthy_ratio_stays_silent(capsys):
    code_ingest._warn_on_collapsed_admission([("skipped_dir:dist", 200)], 900)
    assert capsys.readouterr().err == ""


# --- I-108: --include-path is a glob, and says so ---------------------------


def test_repeatable_include_path_parses_in_both_flag_orderings():
    """Regression pin for the reported-but-unreproducible argparse claim."""
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="cmd"))

    trailing = parser.parse_args(
        ["code-ingest", "/repo", "--include-path", "a/dist", "--include-path", "b/dist"]
    )
    leading = parser.parse_args(
        ["code-ingest", "--include-path", "a/dist", "--include-path", "b/dist", "/repo"]
    )
    assert trailing.include_path == ["a/dist", "b/dist"] == leading.include_path
    assert trailing.repo_path == leading.repo_path == "/repo"


def test_bare_directory_include_path_is_expanded_and_admits_its_files(tmp_path, capsys):
    repo = _package_repo(tmp_path)
    args = _args(repo, include_path=["dist"])

    code_ingest._expand_directory_include_patterns(str(repo), args)

    assert args.include_path == ["dist/**"]
    assert "expanded to 'dist/**'" in capsys.readouterr().err
    assert "dist/bundle.js" in _admitted(repo, args)


def test_a_pattern_with_metacharacters_is_never_rewritten(tmp_path):
    repo = _package_repo(tmp_path)
    args = _args(repo, include_path=["dist/*.js", "src"])

    code_ingest._expand_directory_include_patterns(str(repo), args)

    assert args.include_path == ["dist/*.js", "src/**"]


def test_a_size_capped_include_is_not_reported_as_a_glob_mistake(tmp_path, capsys):
    repo = _package_repo(tmp_path)
    (repo / "dist" / "huge.js").write_text("var pad=1;\n" * 2000, encoding="utf-8")
    args = _args(repo, include_path=["dist/huge.js"], max_included_skipped_bytes=100)

    with RootedSourceTree(repo) as tree:
        records = code_ingest._collect_excluded_records(tree, args, repo / ".none")
    capped = code_ingest._size_capped_include_patterns(records)
    assert capped == {"dist/huge.js"}

    # It still refuses — nothing asked for was ingested — but names the real cause.
    assert code_ingest._report_unmatched_include_patterns(set(), capped, args) is True
    err = capsys.readouterr().err
    assert "exceeds --max-included-skipped-bytes" in err
    assert "matched 0 files" not in err
    assert "no --include-path pattern admitted a single file" in err


def test_every_pattern_matching_nothing_refuses_the_run(tmp_path, capsys):
    repo = _package_repo(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        code_ingest.run(
            _args(
                repo,
                include_path=["**/nothing-here/**"],
                engagement_dir=_engagement(tmp_path),
            )
        )
    assert excinfo.value.code == 1

    err = capsys.readouterr().err
    assert "--include-path '**/nothing-here/**' matched 0 files" in err
    assert "no --include-path pattern admitted a single file" in err


def test_one_matching_pattern_keeps_the_run_alive_but_still_warns(tmp_path, capsys):
    repo = _package_repo(tmp_path)

    posted: dict[str, object] = {}

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, path, payload):
            posted["path"] = path
            posted["files"] = payload["files"]
            return {"added": [], "unchanged": []}

    original = code_ingest.AssessmentClient
    code_ingest.AssessmentClient = _Client
    try:
        code_ingest.run(
            _args(
                repo,
                include_path=["dist/**", "**/nothing-here/**"],
                engagement_dir=_engagement(tmp_path),
            )
        )
    finally:
        code_ingest.AssessmentClient = original

    err = capsys.readouterr().err
    assert "--include-path '**/nothing-here/**' matched 0 files" in err
    assert "no --include-path pattern admitted a single file" not in err
    # A dry run reports the same census a real run does.
    assert "Admitted files: 2 of 3 total (1 skipped)" in err
    assert posted["path"] == "code/repos/refresh/preview"
    assert {str(row["file_path"]) for row in posted["files"]} == {
        "dist/bundle.js",
        "src/app.js",
    }
