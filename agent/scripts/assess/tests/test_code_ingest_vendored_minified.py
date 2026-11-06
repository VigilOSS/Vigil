"""`code-ingest` keeps vendored copies and minified bundles out of analysis.

Third-party code copied into a tree and compiled bundles carry most of a
repository's sink volume and none of its authored logic. Each rule below keeps
the bytes accountable: an excluded file is still fingerprinted in the
authenticated exclusion inventory, the admitted and excluded predicates still
partition the tree exactly, and an explicit include re-admits it.
"""
from __future__ import annotations

import json
import re
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


@pytest.mark.parametrize("dirname", ["vendor", "Vendor"])
@pytest.mark.parametrize("marker", [
    "autoload.php", "modules.txt", "composer/installed.json", "bundle/ruby/3.3.0/gems.rb",
    "vendor.json", "github.com/acme/log/log.go", "golang.org/x/net/html.go", "gopkg.in/yaml.v3/yaml.go",
])
def test_a_vendor_dir_with_package_manager_contents_is_skipped_in_any_case(
    tmp_path, dirname, marker
):
    repo = tmp_path / "repo"
    _write(repo, f"{dirname}/{marker}", "<?php return 1;\n")
    _write(repo, f"{dirname}/acme/jwt/src/JWT.php", "<?php class JWT {}\n")
    _write(repo, "src/Coverage/Report.cs", "class Report {}\n")
    _write(repo, "src/Build/Step.cs", "class Step {}\n")

    args = _args(repo)

    assert _admitted(repo, args) == ["src/Build/Step.cs", "src/Coverage/Report.cs"]
    assert _excluded(repo, args) == {
        f"{dirname}/{marker}": "skipped_dir:vendor",
        f"{dirname}/acme/jwt/src/JWT.php": "skipped_dir:vendor",
    }
    _assert_partition_verifies(repo, args)


def test_a_vendor_or_env_dir_without_tool_output_is_first_party(tmp_path):
    """Hand-copied libraries under `vendor/` and per-environment settings under
    `env/` are code the application runs; only what Composer, Go, Bundler or a
    Python virtualenv writes there is someone else's."""
    repo = tmp_path / "repo"
    _write(repo, "vendor/acme/billing/src/Charge.php", "<?php class Charge {}\n")
    _write(repo, "env/production.php", "<?php return ['debug' => false];\n")
    _write(repo, "config/Env/staging.php", "<?php return [];\n")
    _write(repo, "env/bin/deploy.sh", "#!/bin/sh\n")
    _write(repo, "tools/env/pyvenv.cfg", "home = /usr/bin\n")
    _write(repo, "tools/env/lib/site.py", "import os\n")
    _write(repo, "legacy/env/bin/activate", "# virtualenv\n")
    _write(repo, "legacy/env/lib/site.py", "import os\n")
    _write(repo, "win/env/Scripts/activate", "# virtualenv\n")
    _write(repo, "win/env/Lib/site.py", "import os\n")
    _write(repo, "src/Vendor/Bundle/Controller/AdminController.php", "<?php class AdminController {}\n")
    _write(repo, "src/Vendor/Composer/Installer.php", "<?php class Installer {}\n")

    args = _args(repo)

    assert _admitted(repo, args) == [
        "config/Env/staging.php",
        "env/bin/deploy.sh",
        "env/production.php",
        "src/Vendor/Bundle/Controller/AdminController.php",
        "src/Vendor/Composer/Installer.php",
        "vendor/acme/billing/src/Charge.php",
    ]
    assert _excluded(repo, args) == {
        "legacy/env/bin/activate": "skipped_dir:env",
        "legacy/env/lib/site.py": "skipped_dir:env",
        "tools/env/lib/site.py": "skipped_dir:env",
        "tools/env/pyvenv.cfg": "skipped_dir:env",
        "win/env/Lib/site.py": "skipped_dir:env",
        "win/env/Scripts/activate": "skipped_dir:env",
    }
    _assert_partition_verifies(repo, args)


class _CaseFoldingTree:
    """A tree whose lookups ignore case, as APFS and NTFS do, listing exact names."""

    def __init__(self, listings: dict[str, list[str]]) -> None:
        self.listings = listings

    def walk(self, start: str = ""):
        yield SimpleNamespace(
            relative_dir=start, directories=self.listings.get(start, []),
            regular_files=[], other_entries=[],
        )

    def stat_entry(self, raw: str):
        return Path("/").stat()


def test_a_tool_marker_matches_only_its_exact_name_on_a_case_folding_filesystem():
    tree = _CaseFoldingTree({"src/Vendor": ["Bundle", "Composer"], "vendor": ["composer"]})
    policy = code_ingest._SkipPolicy(tree, _args(Path("/")))

    assert policy.tool_output_reason("src/Vendor") is None
    assert policy.tool_output_reason("vendor") == "skipped_dir:vendor"


def test_a_first_party_vendor_domain_directory_is_admitted(tmp_path):
    """`Vendor` is a business entity in marketplace and procurement code; only
    the package manager's own directory, spelled `vendor`, is skipped by name."""
    repo = tmp_path / "repo"
    _write(repo, "composer.json", json.dumps({"name": "acme/market"}) + "\n")
    _write(repo, "src/Controller/Vendor/VendorController.php", "<?php class VendorController {}\n")
    _write(repo, "src/Entity/Vendor.php", "<?php class Vendor {}\n")
    _write(repo, "vendor/autoload.php", "<?php\n")

    args = _args(repo)

    assert _admitted(repo, args) == [
        "composer.json", "src/Controller/Vendor/VendorController.php", "src/Entity/Vendor.php",
    ]
    assert _excluded(repo, args) == {"vendor/autoload.php": "skipped_dir:vendor"}
    _assert_partition_verifies(repo, args)


def test_a_workspace_package_named_like_an_archive_is_first_party(tmp_path):
    """A forge archive unpacks as `<name>-<branch>/` beside a manifest naming
    `<name>`; a package whose own name ends in `-main` is the project itself."""
    repo = tmp_path / "repo"
    _write(repo, "package.json", json.dumps({"name": "acme", "workspaces": ["packages/*"]}) + "\n")
    _write(
        repo,
        "packages/electron-main/package.json",
        json.dumps({"name": "@acme/electron-main", "version": "1.0.0"}) + "\n",
    )
    _write(repo, "packages/electron-main/index.js", "module.exports = {};\n")

    args = _args(repo)

    assert _admitted(repo, args) == [
        "package.json", "packages/electron-main/index.js", "packages/electron-main/package.json",
    ]
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


# --- ingest summary ------------------------------------------------------------


class _FakeClient:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, endpoint: str, payload: dict, **_options):
        if endpoint == "code/repos/refresh/preview":
            return {"repo_key": payload["repo_key"], "files": len(payload["files"])}
        if endpoint == "code/repos/refresh/start":
            return {"repo_id": 7, "refresh_token": "refresh-7"}
        if endpoint == "code/repos/7/refresh/files":
            return {"staged": len(payload["files"])}
        if endpoint == "code/repos/7/refresh/commit":
            return {
                "repo_id": 7,
                "repo_generation": 1,
                "repo_role": "analysis",
                "source_manifest_digest": "d" * 64,
                "retired": 0,
            }
        if endpoint == "code/repos/7/lsp-config":
            return {
                "id": 7,
                "active_generation": payload["repo_generation"],
                "source_manifest_digest": payload["source_manifest_digest"],
                "lsp_config": payload["lsp_config"],
            }
        raise AssertionError(f"Unexpected endpoint: {endpoint}")


def _offline_ingest(monkeypatch, tmp_path) -> tuple[Path, Path]:
    repo = tmp_path / "acme reports"
    _write(repo, "app.py", "print('ok')\n")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(code_ingest, "AssessmentClient", _FakeClient)
    monkeypatch.setattr(
        code_ingest,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(engagement)
        ),
    )
    monkeypatch.setattr(
        code_ingest,
        "_setup_ctags",
        lambda *_args, **kwargs: {"available": False, **kwargs},
    )
    return repo, engagement


def test_the_ingest_summary_prints_repo_id_and_the_follow_up_commands(
    monkeypatch, tmp_path, capsys
):
    repo, engagement = _offline_ingest(monkeypatch, tmp_path)

    code_ingest.run(_args(repo, name="acme-reports", dry_run=False, engagement_dir=str(engagement)))

    out = capsys.readouterr().out
    assert re.search(r"^Repository: acme-reports \(id: 7\)$", out, re.M)
    assert re.search(r"^repo_id: 7$", out, re.M)
    sealed = re.search(r"^Sealed source: (.+)$", out, re.M).group(1)
    quoted = code_ingest.shlex.quote(sealed)
    assert f"vigil assess code-index build --repo-id 7 {quoted}" in out
    assert "vigil assess code-index sync --repo-id 7" in out


def test_a_dry_run_previews_without_follow_up_commands(monkeypatch, tmp_path, capsys):
    """A preview seals nothing, so there is no repo_id or sealed path to index."""
    repo, engagement = _offline_ingest(monkeypatch, tmp_path)

    code_ingest.run(_args(repo, name="acme-reports", dry_run=True, engagement_dir=str(engagement)))

    # stdout is exactly the backend preview document.
    preview = json.loads(capsys.readouterr().out)
    assert preview["files"] == 1
