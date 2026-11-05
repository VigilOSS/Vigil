"""`code-ingest` keeps vendored copies and minified bundles out of analysis.

Third-party code copied into a tree and compiled bundles carry most of a
repository's sink volume and none of its authored logic. Each rule below keeps
the bytes accountable: an excluded file is still fingerprinted in the
authenticated exclusion inventory, the admitted and excluded predicates still
partition the tree exactly, and an explicit include re-admits it.
"""
from __future__ import annotations

import json
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
        exclude_path=[],
        policy_preset="application",
        max_included_skipped_bytes=code_ingest.DEFAULT_MAX_INCLUDED_SKIPPED_BYTES,
        skipped_manifest=None,
        dry_run=True,
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _write(root: Path, rel: str, data: str | bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def _admitted(repo: Path, args) -> list[str]:
    with RootedSourceTree(repo) as tree:
        return sorted(code_ingest._admitted_source_paths(tree, args, repo / ".none"))


def _records(repo: Path, args) -> list[dict[str, object]]:
    with RootedSourceTree(repo) as tree:
        return code_ingest._collect_excluded_records(tree, args, repo / ".none")


def _excluded(repo: Path, args) -> dict[str, str]:
    return {
        str(record["path"]): str(record["reason"])
        for record in _records(repo, args)
        if record.get("kind") != "directory"
    }


def _assert_partition_verifies(repo: Path, args) -> None:
    """The admitted/excluded predicates must partition the tree exactly."""
    with RootedSourceTree(repo) as tree:
        bindings = {}
        for rel_path in code_ingest._admitted_source_paths(tree, args, repo / ".none"):
            captured = tree.capture(rel_path, retain_spool=False)
            bindings[rel_path] = (captured.sha256, captured.size, captured.executable)
        excluded = code_ingest._collect_excluded_records(tree, args, repo / ".none")
        code_ingest._verify_source_inventory(tree, args, repo / ".none", bindings, excluded)


def _minified_js(size: int = 40_000) -> str:
    body = "var a=function(b){return b+1};" * (size // 31)
    return f"/*! Acme Player v4.1.0 | (c) Acme Corp */\n{body}\n//# sourceMappingURL=player.js.map\n"


# --- vendored copies ---------------------------------------------------------


@pytest.fixture
def vendored_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    _write(repo, "src/index.php", "<?php echo 'ok';\n")
    _write(
        repo,
        "lib/AcmeMailer-master/composer.json",
        json.dumps({"name": "acme/mailer", "description": "Acme mail transport"}, indent=4) + "\n",
    )
    _write(repo, "lib/AcmeMailer-master/VERSION", "5.2.7\n")
    _write(repo, "lib/AcmeMailer-master/LICENSE", "LGPL\n")
    _write(repo, "lib/AcmeMailer-master/class.mailer.php", "<?php class Mailer {}\n")
    _write(repo, "lib/AcmeMailer-master/extras/ntlm.php", "<?php function ntlm() {}\n")
    # First-party directory that merely ends in `-master`: no package manifest
    # or licence at its root, so nothing marks it as someone else's code.
    _write(repo, "deploy/db-master/setup.sh", "#!/bin/sh\necho primary\n")
    return repo


def test_a_vendored_copy_directory_is_excluded_with_its_files_fingerprinted(vendored_repo):
    args = _args(vendored_repo)

    admitted = _admitted(vendored_repo, args)
    excluded = _excluded(vendored_repo, args)

    assert admitted == ["deploy/db-master/setup.sh", "src/index.php"]
    assert excluded == {
        "lib/AcmeMailer-master/LICENSE": "skipped_dir:vendored_copy",
        "lib/AcmeMailer-master/VERSION": "skipped_dir:vendored_copy",
        "lib/AcmeMailer-master/class.mailer.php": "skipped_dir:vendored_copy",
        "lib/AcmeMailer-master/composer.json": "skipped_dir:vendored_copy",
        "lib/AcmeMailer-master/extras/ntlm.php": "skipped_dir:vendored_copy",
    }
    _assert_partition_verifies(vendored_repo, args)


def test_the_vendored_copy_record_carries_its_package_identity_and_evidence(vendored_repo):
    directory = next(
        record
        for record in _records(vendored_repo, _args(vendored_repo))
        if record["path"] == "lib/AcmeMailer-master"
    )

    assert directory["kind"] == "directory"
    assert directory["reason"] == "skipped_dir:vendored_copy"
    copy = directory["vendored_copy"]
    assert copy["ecosystem"] == "composer"
    assert copy["coordinate"] == "acme/mailer"
    assert copy["version"] == "5.2.7"
    assert copy["version_source"] == "VERSION"
    assert {"path": "lib/AcmeMailer-master/composer.json", "line": 2,
            "text": '"name": "acme/mailer",'} in copy["evidence"]
    assert {"path": "lib/AcmeMailer-master/VERSION", "line": 1, "text": "5.2.7"} in copy["evidence"]


def test_an_ordinary_skipped_directory_record_keeps_its_existing_shape(tmp_path):
    """Exclusion records feed the review-identity digest; an unaffected repo's
    records must not change shape, or every re-ingest advances its generation."""
    repo = tmp_path / "repo"
    _write(repo, "src/app.js", "export const a = 1;\n")
    _write(repo, "node_modules/left-pad/index.js", "module.exports = 1;\n")

    directory = next(
        record for record in _records(repo, _args(repo)) if record["kind"] == "directory"
    )

    assert directory == {
        "path": "node_modules",
        "kind": "directory",
        "reason": "skipped_dir:node_modules",
    }


def test_a_vendored_copy_is_re_admitted_by_an_include_path(vendored_repo):
    args = _args(vendored_repo, include_path=["lib/AcmeMailer-master/**"])

    admitted = _admitted(vendored_repo, args)

    assert "lib/AcmeMailer-master/class.mailer.php" in admitted
    assert "lib/AcmeMailer-master/extras/ntlm.php" in admitted
    _assert_partition_verifies(vendored_repo, args)


@pytest.mark.parametrize("dirname", ["acme-sdk-main", "AcmeSDK-master"])
def test_archive_named_directories_need_a_package_marker(tmp_path, dirname):
    repo = tmp_path / "repo"
    _write(repo, f"{dirname}/package.json", json.dumps({"name": "acme-sdk", "version": "1.4.0"}) + "\n")
    _write(repo, f"{dirname}/index.js", "module.exports = {};\n")
    _write(repo, "plain-master/index.js", "module.exports = {};\n")

    assert _admitted(repo, _args(repo)) == ["plain-master/index.js"]
    copy = next(
        record["vendored_copy"]
        for record in _records(repo, _args(repo))
        if record["path"] == dirname
    )
    assert (copy["ecosystem"], copy["coordinate"], copy["version"]) == ("npm", "acme-sdk", "1.4.0")
    assert copy["version_source"] == "package.json"


# --- vendor/ casing ----------------------------------------------------------


def test_vendor_is_matched_case_insensitively_and_keeps_its_reason(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "Vendor/acme/jwt/src/JWT.php", "<?php class JWT {}\n")
    _write(repo, "src/Coverage/Report.cs", "class Report {}\n")
    _write(repo, "src/Build/Step.cs", "class Step {}\n")

    args = _args(repo)

    assert _admitted(repo, args) == ["src/Build/Step.cs", "src/Coverage/Report.cs"]
    assert _excluded(repo, args) == {"Vendor/acme/jwt/src/JWT.php": "skipped_dir:vendor"}
    assert code_ingest._skip_file_reason("Vendor/acme/a.php", "a.php") == "skipped_dir:vendor"
    _assert_partition_verifies(repo, args)


# --- hashed chunks and .phps -------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["main.3f2a1b9c.chunk.js", "2.a1b2c3d4.chunk.js", "main.0d1e2f3a4b5c6d7e.chunk.css"],
)
def test_a_hashed_chunk_is_a_bundle(name):
    assert code_ingest._skip_file_reason(f"Content/app/{name}", name) == "minified_or_bundle"


@pytest.mark.parametrize("name", ["vendors.chunk.js", "chunk.js", "app.chunked.js"])
def test_an_unhashed_chunk_name_is_not_a_bundle_by_name(name):
    assert code_ingest._skip_file_reason(f"src/{name}", name) is None


def test_a_hashed_chunk_is_re_admitted_by_include_minified(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "Content/app/main.3f2a1b9c.chunk.js", "console.log(1);\n")

    assert _admitted(repo, _args(repo)) == []
    assert _admitted(repo, _args(repo, include_minified=True)) == [
        "Content/app/main.3f2a1b9c.chunk.js"
    ]
    record = next(r for r in _records(repo, _args(repo)) if r["kind"] == "file")
    assert record["source_map_candidate"] == "Content/app/main.3f2a1b9c.chunk.js.map"


def test_a_chunk_include_pattern_descends_a_build_directory(tmp_path):
    args = _args(tmp_path, include_path=["*.chunk.js"])

    assert code_ingest._should_descend_skipped_dir("web/build", "build", args) is True


def test_a_php_source_display_copy_is_skipped_and_re_admissible(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "pages/report.phps", "<?php echo $_GET['id'];\n")

    assert _excluded(repo, _args(repo)) == {"pages/report.phps": "skipped_extension:.phps"}
    assert _admitted(repo, _args(repo, include_skipped=True)) == ["pages/report.phps"]


# --- content-based minification ----------------------------------------------


def test_an_unsuffixed_minified_library_is_excluded_by_its_line_shape(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "Content/player/acme-player.js", _minified_js())
    _write(repo, "src/app.js", "export function run() {\n  return 1;\n}\n")

    args = _args(repo)

    assert _admitted(repo, args) == ["src/app.js"]
    assert _excluded(repo, args) == {"Content/player/acme-player.js": "minified_or_bundle"}
    _assert_partition_verifies(repo, args)


def test_a_minified_library_with_a_long_licence_banner_is_still_minified(tmp_path):
    repo = tmp_path / "repo"
    banner = "".join(f"/*! Acme Player licence line {number} */\n" for number in range(30))
    _write(repo, "Content/player/acme-player.js", banner + _minified_js(200_000))

    assert _admitted(repo, _args(repo)) == []


def test_minified_content_is_re_admitted_by_include_minified(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "Content/player/acme-player.js", _minified_js())

    args = _args(repo, include_minified=True)

    assert _admitted(repo, args) == ["Content/player/acme-player.js"]
    _assert_partition_verifies(repo, args)


def test_include_minified_re_admits_a_shipped_bundle_of_any_size(tmp_path):
    """A recovered bundle repository is minified by line shape and routinely
    holds multi-megabyte chunks. The included-skipped size cap guards a
    name-skipped artifact; it must not turn `--include-minified` into a partial
    remedy for files no name rule ever skipped.
    """
    repo = tmp_path / "repo"
    _write(repo, "bundles/acme-console.js", _minified_js(64_000))
    _write(repo, "vendor-dist/acme.min.js", _minified_js(64_000))

    args = _args(repo, include_minified=True, max_included_skipped_bytes=16_000)

    assert _admitted(repo, args) == ["bundles/acme-console.js"]
    assert _excluded(repo, args) == {
        "vendor-dist/acme.min.js": (
            "minified_or_bundle; include requested by include_minified but size "
            f"{(repo / 'vendor-dist/acme.min.js').stat().st_size} exceeds max 16000"
        )
    }
    _assert_partition_verifies(repo, args)


def test_a_stylesheet_with_one_embedded_image_line_is_first_party_source(tmp_path):
    repo = tmp_path / "repo"
    rules = "".join(f".acme-rule-{n} {{ color: #{n:06x}; }}\n" for n in range(300))
    data_uri = ".logo { background: url(data:image/png;base64," + "A" * 100_000 + "); }\n"
    _write(repo, "static/site.css", rules + data_uri + rules)

    assert _admitted(repo, _args(repo)) == ["static/site.css"]


def test_a_small_one_line_script_is_not_called_minified(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "src/flags.js", "window.ACME_FLAGS={" + ",".join(f'"f{n}":1' for n in range(200)) + "};\n")

    assert _admitted(repo, _args(repo)) == ["src/flags.js"]


def test_line_shape_applies_only_to_javascript_and_css(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "data/fixture.py", "X = '" + "a" * 60_000 + "'\n")

    assert _admitted(repo, _args(repo)) == ["data/fixture.py"]


# --- collapsed-admission remedy ---------------------------------------------


def test_a_collapsed_vendored_copy_admission_names_a_working_remedy(capsys):
    code_ingest._warn_on_collapsed_admission([("skipped_dir:vendored_copy", 500)], 3)

    err = capsys.readouterr().err
    assert "vendored_copy/**" not in err
    assert "--include-path '<vendored-copy-dir>/**'" in err
