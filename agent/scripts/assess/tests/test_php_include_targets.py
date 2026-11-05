"""PHP inclusion statements are import edges, resolved from the parse tree.

`include`/`require` name the file the interpreter loads and runs next, so each
one is an `import_targets` record of kind `include`. Its argument is evaluated
statically where PHP itself would compute a fixed path (string literals,
`__DIR__`, `dirname(__FILE__)`, `dirname(__DIR__, n)`, constants `define`d in
the same file) and every record carries a status: nothing is dropped because
it could not be resolved (ADR 0015). The per-file reader cannot see the
repository, so a static path stays `unclassified` until the build resolves it
against the sealed snapshot. The streaming fallback reads lines without a
parse tree and may only ever say `dynamic` or `unclassified`.
"""
from __future__ import annotations

from assess.lib import treesitter_index
from assess.lib.treesitter_index import PhpIncludeResolver, index_file


def _includes(indexed: dict) -> list[dict]:
    return [target for target in indexed["import_targets"] if target.get("kind") == "include"]


def _by_line(indexed: dict) -> dict[int, dict]:
    return {target["line"]: target for target in _includes(indexed)}


BOOTSTRAP = b"""<?php
define('ACME_LIB', dirname(__DIR__, 2) . '/lib');
const ACME_VIEWS = __DIR__ . '/views';
require_once __DIR__ . '/config.php';
require dirname(__FILE__) . "/routes.php";
include_once ACME_LIB . '/db.php';
include ACME_VIEWS . DIRECTORY_SEPARATOR . 'header.php';
require ACME_MISSING . '/x.php';
include $_GET['page'] . '.php';
require "$theme/footer.php";
include $CFG->dirroot . '/lib/setup.php';
include 'acme/helpers.php';
require './local.php';
require_once '/etc/acme/settings.php';
include __DIR__ . '/../../../outside.php';
require_once(__DIR__ . '/absent.php');
include __DIR__ . '/notes.txt';
"""

SNAPSHOT = {
    "public/admin/index.php": "php",
    "public/admin/config.php": "php",
    "public/admin/routes.php": "php",
    "public/admin/views/header.php": "php",
    "lib/db.php": "php",
    "acme/helpers.php": "php",
    "public/admin/acme/helpers.php": "php",
    "vendor/acme/helpers.php": "php",
    "public/admin/local.php": "php",
    "public/admin/notes.txt": "text",
}


def _resolved_bootstrap() -> dict[int, dict]:
    indexed = index_file("public/admin/index.php", "php", BOOTSTRAP)
    assert indexed["analysis_status"] == "complete"
    PhpIncludeResolver(SNAPSHOT).resolve(indexed, rel_path="public/admin/index.php")
    return _by_line(indexed)


def test_every_inclusion_statement_is_an_include_record() -> None:
    indexed = index_file("public/admin/index.php", "php", BOOTSTRAP)

    includes = _includes(indexed)
    assert [target["line"] for target in includes] == list(range(4, 18))
    assert {target["construct"] for target in includes} == {
        "include", "include_once", "require", "require_once",
    }
    # `imports` and `import_targets` stay one entry per import.
    assert len(indexed["imports"]) == len(indexed["import_targets"])
    assert indexed["signal_counts"]["imports"] == len(indexed["import_targets"])


def test_the_per_file_reader_never_claims_a_snapshot_status() -> None:
    indexed = index_file("public/admin/index.php", "php", BOOTSTRAP)

    statuses = {target["status"] for target in _includes(indexed)}
    assert "resolved" not in statuses
    assert "target_unindexed" not in statuses
    assert _by_line(indexed)[4]["status"] == "unclassified"


def test_file_anchored_paths_resolve_against_the_snapshot() -> None:
    targets = _resolved_bootstrap()

    assert (targets[4]["status"], targets[4]["resolved"]) == ("resolved", "public/admin/config.php")
    assert (targets[5]["status"], targets[5]["resolved"]) == ("resolved", "public/admin/routes.php")
    assert (targets[6]["status"], targets[6]["resolved"]) == ("resolved", "lib/db.php")
    assert (targets[7]["status"], targets[7]["resolved"]) == (
        "resolved", "public/admin/views/header.php",
    )


def test_an_unknown_constant_names_itself() -> None:
    assert _resolved_bootstrap()[8]["status"] == "constant_unresolved:ACME_MISSING"


def test_a_constant_defined_differently_on_two_branches_is_dynamic() -> None:
    """The file defines the constant, so it is not unresolved; which value it
    holds is decided at run time."""
    source = b"""<?php
if (PHP_SAPI === 'cli') {
    define('ACME_ROOT', __DIR__ . '/cli');
} else {
    define('ACME_ROOT', __DIR__ . '/web');
}
include ACME_ROOT . '/boot.php';
"""
    indexed = index_file("public/index.php", "php", source)

    assert [(t["line"], t["status"]) for t in _includes(indexed)] == [(7, "dynamic")]


def test_request_and_property_rooted_paths_are_dynamic() -> None:
    targets = _resolved_bootstrap()

    assert [targets[line]["status"] for line in (9, 10, 11)] == ["dynamic"] * 3
    assert all(targets[line]["resolved"] == "" for line in (9, 10, 11))


def test_working_directory_and_include_path_targets_are_ambiguous_with_candidates() -> None:
    targets = _resolved_bootstrap()

    assert targets[12]["status"] == "ambiguous"
    assert targets[12]["candidates"] == [
        "public/admin/acme/helpers.php",
        "acme/helpers.php",
        "vendor/acme/helpers.php",
    ]
    assert targets[13]["status"] == "ambiguous"
    assert targets[13]["candidates"] == ["public/admin/local.php"]


def test_absent_escaping_and_unindexed_targets_are_kept_and_named() -> None:
    targets = _resolved_bootstrap()

    assert targets[14]["status"] == "target_absent"
    assert targets[15]["status"] == "target_absent"
    assert targets[16]["status"] == "target_absent"
    assert targets[16]["path"] == "absent.php"
    assert (targets[17]["status"], targets[17]["resolved"]) == (
        "target_unindexed", "public/admin/notes.txt",
    )


def test_includes_inside_callables_are_import_edges_too() -> None:
    source = b"""<?php
function acme_render($view) {
    require __DIR__ . '/layout.php';
    include $view;
}
"""
    indexed = index_file("src/render.php", "php", source)
    PhpIncludeResolver({"src/render.php": "php", "src/layout.php": "php"}).resolve(
        indexed, rel_path="src/render.php"
    )

    assert [(t["line"], t["status"]) for t in _includes(indexed)] == [
        (3, "resolved"),
        (4, "dynamic"),
    ]


def test_a_use_import_and_an_include_share_one_list() -> None:
    source = b"""<?php
use Acme\\Billing\\Invoice;
require __DIR__ . '/vendor/autoload.php';
"""
    indexed = index_file("index.php", "php", source)

    assert [target["kind"] for target in indexed["import_targets"]] == ["class", "include"]
    assert indexed["imports"] == ["Acme\\Billing\\Invoice", "__DIR__ . '/vendor/autoload.php'"]


STREAMED = b"""<?php
require_once __DIR__ . '/config.php';
include ACME_ROOT . '/db.php';
include $_GET['page'];
require "$theme/footer.php";
include '$literal.php';
$this->include('acme/view');
$options['require'] = true;
$include = 'header.php';
"""


def test_streaming_says_only_dynamic_or_unclassified_and_never_contradicts() -> None:
    streamed = treesitter_index._fallback_from_bytes(
        "public/index.php", "php", STREAMED, degradation_reason="test"
    )
    exact = index_file("public/index.php", "php", STREAMED)
    PhpIncludeResolver({"public/index.php": "php"}).resolve(exact, rel_path="public/index.php")

    streamed_by_line = _by_line(streamed)
    assert {target["status"] for target in streamed_by_line.values()} <= {
        "dynamic", "unclassified",
    }
    assert sorted(streamed_by_line) == [2, 3, 4, 5, 6]
    assert {line for line, target in streamed_by_line.items() if target["status"] == "dynamic"} == {4, 5}
    exact_by_line = _by_line(exact)
    assert sorted(exact_by_line) == [2, 3, 4, 5, 6]
    for line, target in streamed_by_line.items():
        if target["status"] == "dynamic":
            assert exact_by_line[line]["status"] == "dynamic"
        assert target["construct"] == exact_by_line[line]["construct"]


def _build(tmp_path, monkeypatch, request, files: dict[str, bytes], *, excluded_entries=()):
    """Seal *files* as a snapshot, run `code-index build` over it, and return
    a reader for each file's structural artifact."""
    import hashlib
    import json
    from pathlib import Path
    from types import SimpleNamespace

    from assess.commands import code_index
    from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file

    origin = tmp_path / "origin"
    builder = SnapshotBuilder(tmp_path / "snapshots", "acme")
    rows = []
    for file_id, (rel_path, raw) in enumerate(sorted(files.items()), 1):
        path = origin / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        language = "php" if rel_path.endswith((".php", ".inc")) else ""
        builder.add(rel_path, capture_regular_file(path), language=language)
        rows.append({"id": file_id, "repo_id": 7, "file_path": rel_path, "language": language,
                     "file_hash": hashlib.sha256(raw).hexdigest()})
    snapshot = builder.finish(repo_key="acme", repo_name="acme", source_origin_path=str(origin),
                              git={"head": "", "branch": "", "dirty": None},
                              excluded_entries=list(excluded_entries))

    def make_writable() -> None:
        for item in snapshot.source_path.parent.rglob("*"):
            item.chmod(0o700 if item.is_dir() else 0o600)
        snapshot.source_path.parent.chmod(0o700)

    request.addfinalizer(make_writable)
    repo = {"id": 7, "repo_key": "acme", "repo_path": str(snapshot.source_path),
            "active_generation": 1, "source_manifest_digest": "d" * 64}

    class Client:
        def __init__(self, *_args):
            pass

        def get(self, endpoint):
            if endpoint == "code/repos/7":
                return repo
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return {"items": rows, "total": len(rows), "offset": 0, "count": len(rows), "has_more": False}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(code_index, "AssessmentClient", Client)
    monkeypatch.setattr(code_index, "load_config", lambda *_: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng"))
    monkeypatch.setattr(
        code_index, "index_file",
        lambda path, language, source, **_kwargs: index_file(path, language, source),
    )
    output = tmp_path / "analysis-state"
    code_index.run(SimpleNamespace(repo_path=str(snapshot.source_path), repo_id=7, repo_key="acme",
                                   output_dir=str(output), file_list=None, engagement_dir=str(tmp_path)))

    top = json.loads((output / "structural-index-manifest.json").read_text())
    manifest = json.loads((output / top["repos"]["7"]["manifest_path"]).read_text())

    def artifact(rel_path: str) -> dict:
        index_path = manifest["files"][rel_path]["index_path"]
        return json.loads(Path(output / "structural-index" / index_path).read_text())

    return artifact


def test_the_structural_build_resolves_includes_against_the_sealed_snapshot(
    tmp_path, monkeypatch, request
) -> None:
    artifact = _build(tmp_path, monkeypatch, request, {
        "public/index.php": b"<?php\nrequire __DIR__ . '/../lib/boot.inc';\ninclude 'missing.php';\n",
        "lib/boot.inc": b"<?php\nrequire_once __DIR__ . '/README';\n",
        "lib/README": b"Acme boot notes\n",
    })

    assert [(t["line"], t["status"], t["resolved"]) for t in _includes(artifact("public/index.php"))] == [
        (2, "resolved", "lib/boot.inc"),
        (3, "ambiguous", ""),
    ]
    assert [(t["status"], t["resolved"]) for t in _includes(artifact("lib/boot.inc"))] == [
        ("target_unindexed", "lib/README"),
    ]


def test_a_target_ingest_excluded_is_named_as_excluded(tmp_path, monkeypatch, request) -> None:
    """`code-ingest` leaves `vendor/` out of the snapshot on purpose, so the
    Composer autoloader a front controller requires is not absent: the sealed
    exclusion inventory says where it went."""
    artifact = _build(
        tmp_path,
        monkeypatch,
        request,
        {"public/index.php": b"<?php\nrequire __DIR__ . '/../vendor/autoload.php';\n"
                             b"require __DIR__ . '/../missing.php';\n"
                             b"require 'vendor/autoload.php';\n"
                             b"require __DIR__ . '/../vendorx/boot.php';\n"},
        excluded_entries=[{"path": "vendor", "kind": "directory", "reason": "skipped_dir:vendor"}],
    )

    assert [
        (t["line"], t["status"], t.get("excluded_entry"))
        for t in _includes(artifact("public/index.php"))
    ] == [
        (2, "target_excluded", "vendor"),
        (3, "target_absent", None),
        (4, "ambiguous", "vendor"),
        (5, "target_absent", None),
    ]


def test_the_build_reads_each_file_at_its_repository_path(tmp_path, monkeypatch, request) -> None:
    """A name glued onto a raised directory is computed from the file's
    repository path, so the record is the one the per-file reader gives and no
    directory above the snapshot leaks into it."""
    source = b"<?php\ninclude dirname(__DIR__) . 'y.php';\ninclude __DIR__ . 'x.php';\n"
    artifact = _build(tmp_path, monkeypatch, request, {"public/index.php": source})
    exact = index_file("public/index.php", "php", source)
    PhpIncludeResolver({"public/index.php": "php"}).resolve(exact, rel_path="public/index.php")

    built = _includes(artifact("public/index.php"))
    assert [(t["status"], t["path"]) for t in built] == [
        ("target_absent", "y.php"),
        ("target_absent", "../publicx.php"),
    ]
    assert built == _includes(exact)
