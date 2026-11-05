"""The indexer's fast paths return exactly what the plain readers return.

Each test pins an equivalence the indexer relies on to skip work: the
structural path's bounded source scan runs a sources-only scanner, and the
line readers gate each pattern on a literal every match must contain. The
reference is always the unoptimised reading of the same Acme fixture.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from assess.lib.code_languages import STRUCTURAL_SUPPORTED_LANGUAGES
from assess.lib.treesitter_catalogues import (
    _ENTRY_LINE_PATTERNS,
    _GLOBAL_ENTRY_LINE_PATTERNS,
    _SINK_DEFINITIONS,
)
from assess.lib.treesitter_common import _gate_literals, _literal_gate, _required_literals
from assess.lib.treesitter_index import _function_scoped_reader_patterns, index_file
from assess.lib.treesitter_streaming import (
    StreamingSecurityScanner,
    _attach_bounded_security_sources,
    _fallback_from_bytes,
)

ACME_PHP_PAGE = b"""<?php
namespace Acme\\Billing;
use Acme\\Models\\Invoice;
use function Acme\\Support\\format_money;
// $_GET['commented'] is not read
# getenv('COMMENTED') is not read either
$invoice = $_GET['invoice'];
$token = getenv('ACME_TOKEN'); system($_POST['cmd']);
include 'acme/header.php';
""" + b"$wide = '" + b"x" * 70_000 + b"' . $_COOKIE['session'];\n" + b"""
final class InvoiceController { use Acme\\Concerns\\Loggable; }
echo $request->input('name');
"""


def test_the_structural_source_scan_reads_what_the_full_fallback_reads() -> None:
    attached = _attach_bounded_security_sources(
        {}, file_path="public/invoice.php", language="php", source=ACME_PHP_PAGE
    )
    full = _fallback_from_bytes(
        "public/invoice.php", "php", ACME_PHP_PAGE, degradation_reason="test"
    )

    assert attached["security_sources"] == full["security_sources"]
    assert attached["signal_counts"]["security_sources"] == full["signal_counts"]["security_sources"]
    assert {source["line"] for source in full["security_sources"]} == {7, 8, 10, 13}


def test_a_sources_only_scanner_keeps_the_source_signal_limit() -> None:
    source = b"".join(b"$a%d = $_GET['k'];\n" % index for index in range(12))
    scanners = [
        StreamingSecurityScanner("public/list.php", "php", signal_limit=5, sources_only=only)
        for only in (False, True)
    ]
    observed = []
    for scanner in scanners:
        scanner.feed(source)
        observed.append(scanner.finish(degradation_reason="test"))

    full, sources_only = observed
    assert sources_only["security_sources"] == full["security_sources"]
    assert sources_only["signal_counts"]["security_sources"] == 12
    assert "security_sources" in sources_only["truncated_dimensions"]
    assert re.search(r"\$_GET", sources_only["security_sources"][0]["snippet"])


@pytest.mark.parametrize(
    "pattern, expected",
    [
        (re.compile(r"(?<!->)(?<!::)\bunlink\s*\("), {"unlink"}),
        # An optional group requires nothing; the literal after it does.
        (re.compile(r"(?:ab)?cde"), {"cde"}),
        # Every branch needs one of its own, or the alternation needs none.
        (re.compile(r"->(?:(?:or)?(?:where|having)Raw|selectRaw)\s*\("), {"where", "having", "selectRaw"}),
        (re.compile(r"\$\w+->(?:query|\w+Raw)\s*\("), {"query", "Raw"}),
        (re.compile(r"(?:ab)+c"), {"ab"}),
        (re.compile(r"\b\w+\s*\("), {"("}),
        (re.compile(r"\b\w+\b"), None),
        # A case-blind str literal is not a substring test.
        (re.compile(r"(?i:exec)\s*\(\s*shell"), {"shell"}),
        (re.compile(r"shell", re.IGNORECASE), None),
        # Bytes compare lowered, matching their ASCII-only case folding.
        (re.compile(rb"(?-i:\bSTDIN\b)|php://stdin", re.IGNORECASE), {b"stdin", b"php://stdin"}),
        (re.compile(rb"\$_(?:GET|POST)\b", re.IGNORECASE), {b"get", b"post"}),
    ],
)
def test_required_literals_are_what_every_match_contains(pattern, expected) -> None:
    assert _required_literals(pattern) == (None if expected is None else frozenset(expected))


def _catalogue_patterns() -> list[re.Pattern]:
    patterns: list[re.Pattern] = [
        compiled
        for language in STRUCTURAL_SUPPORTED_LANGUAGES
        for compiled in _function_scoped_reader_patterns(language)
    ]
    patterns.extend(
        re.compile(item["pattern"])
        for table in (_ENTRY_LINE_PATTERNS, _GLOBAL_ENTRY_LINE_PATTERNS)
        for items in table.values()
        for item in items
    )
    for language in STRUCTURAL_SUPPORTED_LANGUAGES:
        scanner = StreamingSecurityScanner("acme.txt", language)
        patterns.extend(pattern for _kind, pattern, _classes in scanner._sink_patterns)
        patterns.extend(pattern for _kind, pattern in scanner._source_patterns)
        patterns.extend(pattern for _kind, pattern in scanner._entry_patterns)
        patterns.extend(scanner._import_patterns)
    return patterns


def _fixture_lines() -> list[str]:
    # The signal fixtures beside this file are a corpus written to match the
    # catalogues.
    return [
        line
        for glob in ("test_*_index_signals.py", "test_*catalogue*.py", "test_indexer_*.py")
        for path in sorted(Path(__file__).parent.glob(glob))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_no_catalogue_match_lies_on_a_line_its_gate_rejects() -> None:
    lines = _fixture_lines()
    checked = 0
    for pattern in _catalogue_patterns():
        literals = _gate_literals(pattern)
        if literals is None:
            continue
        gate = _literal_gate((pattern,))
        for line in lines:
            text = line.encode() if isinstance(pattern.pattern, bytes) else line
            if pattern.search(text):
                checked += 1
                lowered = text.lower() if isinstance(text, bytes) else text
                assert gate.search(lowered), (pattern.pattern, line)
                assert any(literal in lowered for literal in literals)
    assert checked > 500


def test_a_gated_entry_line_pattern_matches_exactly_where_it_searches() -> None:
    from assess.lib.treesitter_index import _line_pattern_matches

    lines = _fixture_lines()
    matched = 0
    for table in (_ENTRY_LINE_PATTERNS, _GLOBAL_ENTRY_LINE_PATTERNS):
        for items in table.values():
            for item in items:
                for line in lines:
                    expected = re.search(item["pattern"], line) is not None
                    matched += expected
                    assert _line_pattern_matches(item["pattern"], line) is expected
    assert matched > 100


ACME_C_TOOL = """\
#include <stdio.h>
#define RUN(cmd) system(cmd)
// system("commented out") is not read
static char banner[64];

int acme_copy(char *dst, const char *src, FILE *log) {
    fprintf(log, src); sprintf(dst, "%s", src); memcpy(dst, src, 4);
    char *buf = malloc(16); free(buf); popen(src, "r");
    return printf("%s", dst);
}
"""


def test_sinks_follow_catalogue_order_whatever_lines_the_gate_admits() -> None:
    # The reference reading: every catalogue pattern over every scannable
    # line of each scope, one record per kind and line. C applies no
    # receiver filter, so the reference is exactly the line readers' order.
    indexed = index_file("src/acme_copy.c", "c", ACME_C_TOOL.encode())
    lines = ACME_C_TOOL.splitlines()
    scopes = [
        (function["name"], range(function["line_start"] - 1, function["line_end"]))
        for function in indexed["functions"]
    ] + [("<top-level>", [1])]
    expected: list[tuple[str, int, str]] = []
    for name, indices in scopes:
        seen: set[tuple[str, int]] = set()
        for definition in _SINK_DEFINITIONS:
            for pattern in definition["patterns"].get("c", []):
                for index in indices:
                    if not lines[index].strip() or lines[index].strip().startswith("//"):
                        continue
                    if re.search(pattern, lines[index]) and (definition["kind"], index) not in seen:
                        seen.add((definition["kind"], index))
                        expected.append((definition["kind"], index + 1, name))

    assert [
        (sink["kind"], sink["line"], sink["function"]) for sink in indexed["security_sinks"]
    ] == expected
    assert len({line for _kind, line, _name in expected}) == 4


def test_callables_sharing_a_minified_line_each_read_its_registrations() -> None:
    # One line spans both callables, so the second reads the line-pattern
    # answers the first already computed for it.
    source = (
        b'function outer(){function inner(){return 1}'
        b'module.exports=inner;app.get("/acme",inner)}\n'
    )
    indexed = index_file("dist/acme.min.js", "javascript", source)

    assert [(entry["name"], entry["kind"]) for entry in indexed["entry_points"]] == [
        ("outer", "module_exports"),
        ("inner", "express_route"),
    ]


def test_only_signals_inside_code_that_could_run_open_a_segment() -> None:
    # Both declarations carry a source; the literal table is skipped without
    # walking it when no signal lies inside, and read when one does.
    source = b"""static const char *acme_help[] = {
    "usage: set ACME_HOME, read with getenv(name)",
    "done",
};
static const char *acme_home = getenv("ACME_HOME");
int acme_main(void) { return 0; }
"""
    indexed = index_file("src/acme.c", "c", source)

    assert [source["line"] for source in indexed["security_sources"]] == [2, 5]
    assert indexed["top_level_segments"] == [{"line_start": 5, "line_end": 5}]


def test_lines_framed_in_place_read_like_lines_framed_through_the_buffer() -> None:
    # A whole short line is scanned in place; a line split across chunks or
    # longer than a window goes through the buffer. Both framings, every
    # separator form and a separator split across chunks read the same.
    source = (
        b"<?php\r\n$a = $_GET['a'];\r\n// system($_GET['c']);\rsystem($b);\n"
        b"$wide = '" + b"x" * 150 + b"' . $_POST['p'] . exec($c);\r\n\r\n$e = getenv('ACME');\r"
    )
    observed = []
    for size in (3, 7, 64, len(source)):
        scanner = StreamingSecurityScanner(
            "public/acme.php", "php", window_bytes=64, overlap_bytes=16
        )
        for offset in range(0, len(source), size):
            scanner.feed(source[offset : offset + size])
        observed.append(scanner.finish(degradation_reason="test"))

    assert all(result == observed[0] for result in observed)
    assert observed[0]["total_lines"] == 7
    assert [sink["line"] for sink in observed[0]["security_sinks"]] == [4, 5]
    assert [source["line"] for source in observed[0]["security_sources"]] == [2, 5, 7]


def test_a_call_passes_caller_params_only_for_a_whole_parameter_name() -> None:
    # Parameter patterns are compiled once per name across files; a name
    # that merely starts with a parameter (`username`, `users`) is not one.
    source = b'''def acme(user, user_id, *args):
    lookup(user_id)
    render(username)
    audit(args.count, "user")
    notify(users)
'''
    indexed = index_file("acme/views.py", "python", source)

    assert [
        (call["callee"], call["passes_caller_params"]) for call in indexed["call_sites"]
    ] == [("lookup", True), ("render", False), ("audit", True), ("notify", False)]


ACME_PHP_CONTROLLER = b"""<?php
namespace Acme\\Billing;
use Acme\\Models\\Invoice;
define('ACME_ROOT', __DIR__);
const ACME_VIEWS = ACME_ROOT . '/views';
require_once ACME_ROOT . '/bootstrap.php';
final class InvoiceController extends Controller {
    public function show($id) {
        $render = function ($view) { return include ACME_VIEWS . "/$view.php"; };
        return $render(Invoice::find($id)->name);
    }
}
$controller = new InvoiceController();
echo `ls`, $controller->show($_GET['id']);
"""


def test_one_shared_pass_answers_each_query_as_its_own_cursor_would() -> None:
    from assess.lib import treesitter_index

    parser = treesitter_index._get_parser("php")
    tree = parser.parse(ACME_PHP_CONTROLLER)
    queries = treesitter_index._whole_tree_queries("php", parser.language)
    alone = {
        query: treesitter_index._ts_query_captures(parser.language, query, tree.root_node)
        for query in queries
    }
    shared = treesitter_index._SharedTreeQueries()
    shared.open(tree.root_node, parser.language, queries)

    def spans(captures):
        return {
            name: [(node.start_byte, node.end_byte, node.type) for node in nodes]
            for name, nodes in captures.items()
        }

    assert len(queries) == 9
    for query in queries:
        assert spans(shared.captures(parser.language, query, tree.root_node)) == spans(alone[query])
    assert sum(len(nodes) for captures in alone.values() for nodes in captures.values()) == 26
    # Another tree, or a query outside the family, is not this pass's to answer.
    other = parser.parse(ACME_PHP_CONTROLLER)
    assert shared.captures(parser.language, queries[0], other.root_node) is None
    assert shared.captures(parser.language, "(echo_statement) @echo", tree.root_node) is None


def test_indexing_a_file_releases_its_shared_query_pass() -> None:
    from assess.lib import treesitter_index

    indexed = index_file("src/InvoiceController.php", "php", ACME_PHP_CONTROLLER)

    assert indexed["analysis_mode"] == "tree_sitter"
    language = treesitter_index._get_parser("php").language
    assert treesitter_index._SHARED_TREE_QUERIES.captures(
        language,
        treesitter_index._whole_tree_queries("php", language)[0],
        treesitter_index._get_parser("php").parse(ACME_PHP_CONTROLLER).root_node,
    ) is None


ACME_SOURCES = {
    "c": (
        "src/acme_http.c",
        b"/* Acme */\n#include <evhttp.h>\nstatic void acme_cb(struct evhttp_request *r, void *a) {"
        b" log(r); }\nint main(void) { evhttp_set_cb(http, \"/\", acme_cb, 0); return run(main); }\n",
    ),
    "cpp": (
        "src/acme_server.cpp",
        b"#include <httplib.h>\nusing httplib::Server;\n// routes\nint main() { Server svr;\n"
        b"  svr.Get(\"/hi\", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, \"text\"); });\n"
        b"  return svr.listen(\"0.0.0.0\", 8080); }\n",
    ),
    "csharp": (
        "Acme/Program.cs",
        b"// Acme\nvar app = WebApplication.Create(args);\nstring Hello(string name) => $\"hi {name}\";\n"
        b"app.MapGet(\"/hi\", (string name) => Hello(name));\napp.MapGet(\"/named\", Hello);\napp.Run();\n",
    ),
    "javascript": (
        "src/acme.js",
        b"// Acme routes\nconst http = require('http');\nfunction handler(req, res) { res.end(req.url); }\n"
        b"/* server */ http.createServer(handler).listen(8080);\napp.get('/x', (req, res) => res.send(f(g(1))));\n",
    ),
    "php": (
        "public/acme.php",
        b"<?php\n// Acme\n$render = function ($v) { return fn($x) => $x . $v; };\n?>\n<p>Acme</p>\n<?php echo $render('a');\n",
    ),
    "python": (
        "acme/app.py",
        b'"""Acme."""\nimport os\n# config\nHOME = os.environ["ACME_HOME"]\ndef run():\n    """Run."""\n    os.system(HOME)\n',
    ),
    "ruby": (
        "app/acme.rb",
        b"# Acme\nrequire 'sinatra'\nget '/hi' do\n  erb :hi, locals: { name: params[:name] }\nend\nputs(helper(1))\n",
    ),
}


@pytest.mark.parametrize("language", sorted(ACME_SOURCES))
def test_the_shared_pass_collects_each_node_set_as_the_tree_walk_does(language) -> None:
    from assess.lib import treesitter_index

    _path, source = ACME_SOURCES[language]
    parser = treesitter_index._get_parser(language)
    tree = parser.parse(source)
    sets = [
        *treesitter_index._WHOLE_TREE_NODE_TYPES.get(language, ()),
        treesitter_index._file_scope_candidate_types(language),
    ]
    walked = [
        [
            (node.start_byte, node.end_byte, node.type)
            for node in treesitter_index._walk_named_nodes(tree.root_node)
            if node.type in types
        ]
        for types in sets
    ]
    queries = treesitter_index._whole_tree_queries(language, parser.language)
    treesitter_index._SHARED_TREE_QUERIES.open(tree.root_node, parser.language, queries)
    try:
        shared = [
            [
                (node.start_byte, node.end_byte, node.type)
                for node in treesitter_index._named_nodes_of_types(tree, types)
            ]
            for types in sets
        ]
        assert treesitter_index._SHARED_TREE_QUERIES._results is not None
    finally:
        treesitter_index._SHARED_TREE_QUERIES.close()

    assert shared == walked
    assert all(walked)


@pytest.mark.parametrize("language", sorted(ACME_SOURCES))
def test_indexing_a_parsed_file_walks_no_tree_in_python(language, monkeypatch) -> None:
    # Every whole-tree node set a reader takes is registered with the shared
    # pass; a reader that walks the tree itself is one the pass does not know.
    from assess.lib import treesitter_index

    path, source = ACME_SOURCES[language]
    expected = index_file(path, language, source)
    walk = treesitter_index._walk_named_nodes

    def no_walk(node):
        if node.parent is None:
            raise AssertionError(f"walked the whole {node.type} tree in Python")
        return walk(node)

    monkeypatch.setattr(treesitter_index, "_walk_named_nodes", no_walk)
    indexed = index_file(path, language, source)

    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed == expected
