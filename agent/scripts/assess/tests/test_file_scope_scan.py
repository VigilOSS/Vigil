"""File scope is a scan scope of its own, in every tree-sitter language.

Module-level code executes when the file is loaded or requested, so a reader
that only walks callable bodies leaves it unread -- and ADR 0015 forbids
reporting that unread scope as a clean negative. These tests pin the
``<top-level>`` scope over files with no callable at all, the grammar-labelled
content it deliberately does not read (commentary, docstrings, declarations,
inline HTML), and the file-scope entry evidence that keeps the entry-point
dimension measured: PHP request scripts and rendered pages, and Python route
tables.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


def _line_carrying(needle: str, source: bytes) -> int:
    lines = source.decode().splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _sinks(indexed: dict) -> list[tuple[str, str, int]]:
    return [
        (sink["kind"], sink["function"], sink["line"])
        for sink in indexed["security_sinks"]
    ]


def _entries(indexed: dict) -> list[tuple[str, str, int]]:
    return [
        (entry["kind"], entry["name"], entry["line"])
        for entry in indexed["entry_points"]
    ]


# --- 1. Module-level code is read without a callable -------------------------

PYTHON_SETTINGS = b"""import os

DB_HOST = os.environ.get("DB_HOST", "db.example.com")
TIMEOUT = 30
"""


def test_a_constants_module_is_a_measured_file() -> None:
    indexed = index_file("acme/settings.py", "python", PYTHON_SETTINGS)

    assert indexed["total_functions"] == 0
    assert indexed["analysis_status"] == "complete"
    assert indexed["unavailable_dimensions"] == []
    assert ("<top-level>", "os.environ.get") in {
        (call["caller"], call["callee"]) for call in indexed["call_sites"]
    }


PYTHON_SCRIPT = b"""import subprocess
import sys

subprocess.call("rotate " + sys.argv[1], shell=True)
"""


def test_a_module_level_sink_is_reported_without_a_callable() -> None:
    indexed = index_file("acme/rotate.py", "python", PYTHON_SCRIPT)

    assert ("process_exec", "<top-level>", _line_carrying("subprocess.call", PYTHON_SCRIPT)) in _sinks(indexed)
    assert indexed["analysis_status"] == "complete"


PYTHON_DOCSTRING_EXAMPLE = b'''"""Acme backup helpers.

Example::

    os.system("backup " + target)
    eval(expression)
"""

RETENTION_DAYS = 7
'''


def test_a_module_docstring_example_is_not_a_sink() -> None:
    """The docstring is a string the grammar labels; nothing in it executes."""
    indexed = index_file("acme/backup.py", "python", PYTHON_DOCSTRING_EXAMPLE)

    assert indexed["security_sinks"] == []
    assert indexed["call_sites"] == []
    assert indexed["analysis_status"] == "complete"


# --- 2. Declarations hold no executable code ---------------------------------

TYPESCRIPT_TYPES = b"""export interface UserStore {
  find(id: string): Promise<User>;
  exec(query: string): void;
}

export type Loader = { load(path: string): Buffer };
declare function spawn(cmd: string): void;
"""


def test_typescript_declarations_carry_no_call_sites() -> None:
    """A type-only module has no callable and no file-scope entry catalogue, so
    the entry dimension stays unavailable -- but the trio is measured."""
    indexed = index_file("acme/types.ts", "typescript", TYPESCRIPT_TYPES)

    assert indexed["call_sites"] == []
    assert indexed["security_sinks"] == []
    assert indexed["unavailable_dimensions"] == ["entry_points"]


GO_INTERFACE = b"""package store

type Store interface {
	Get(id string) (string, error)
	Exec(query string) error
}
"""


def test_a_go_interface_declaration_carries_no_call_sites() -> None:
    indexed = index_file("store/store.go", "go", GO_INTERFACE)

    assert indexed["call_sites"] == []
    assert indexed["unavailable_dimensions"] == ["entry_points"]


GO_PACKAGE_STATE = b"""package acme

import "os"

var target = os.Getenv("ACME_TARGET")
"""


def test_a_go_package_initializer_is_read() -> None:
    indexed = index_file("acme/state.go", "go", GO_PACKAGE_STATE)

    assert ("<top-level>", "os.Getenv") in {
        (call["caller"], call["callee"]) for call in indexed["call_sites"]
    }


C_MACRO_HEADER = b"""#include <stdio.h>
#define RUN(cmd) system(cmd)
#define FETCH(url) popen(url, "r")
"""


def test_a_c_macro_body_is_read_as_file_scope() -> None:
    """`#` opens a preprocessor directive in C, not a comment. A macro wrapping
    `system` is the wrapper every caller reaches the sink through."""
    indexed = index_file("acme/macros.h", "c", C_MACRO_HEADER)

    assert ("process_exec", "<top-level>", 2) in _sinks(indexed)


C_CONDITIONAL_HEADER = b"""#if defined(__linux__)
#define ACME_PLATFORM "linux"
#endif
"""


def test_a_preprocessor_defined_test_is_not_a_call_site() -> None:
    """Read as file scope, `#if defined(X)` is the preprocessor's operator."""
    indexed = index_file("acme/platform.h", "c", C_CONDITIONAL_HEADER)

    assert indexed["call_sites"] == []
    assert not set(indexed["unavailable_dimensions"]) & treesitter_index.FUNCTION_SCOPED_DIMENSIONS


C_PROTOTYPE_HEADER = b"""#ifndef ACME_API_H
#define ACME_API_H
int run_command(const char *cmd);
#endif
"""


def test_a_header_of_prototypes_is_measured_clean() -> None:
    """A prototype is a declaration the grammar labels, so the readers had no
    executable line left to read: the empty result is the measurement."""
    indexed = index_file("acme/api.h", "c", C_PROTOTYPE_HEADER)

    assert indexed["security_sinks"] == []
    assert indexed["call_sites"] == []
    assert indexed["analysis_status"] == "complete"
    assert indexed["unavailable_dimensions"] == []


JAVA_ONE_LINE_CLASS = b"""class Runner { static { Runtime.getRuntime().exec(System.getenv("CMD")); } }
"""


def test_a_sink_on_a_declaration_header_line_is_unread_signal() -> None:
    """The top-level scope does not read class header lines. When one carries a
    sink the readers never reported, the trio is declared, not claimed clean."""
    indexed = index_file("Runner.java", "java", JAVA_ONE_LINE_CLASS)

    assert indexed["security_sinks"] == []
    assert set(indexed["unavailable_dimensions"]) >= treesitter_index.FUNCTION_SCOPED_DIMENSIONS


def test_the_same_initializer_on_its_own_lines_is_read() -> None:
    source = b"""class Runner {
  static {
    Runtime.getRuntime().exec(System.getenv("CMD"));
  }
}
"""
    indexed = index_file("Runner.java", "java", source)

    assert _sinks(indexed) == [("process_exec", "<top-level>", 3)]


PHP_PAGE_PROSE = b"""<?php require 'header.php'; ?>
<p>Print this page, then eval(uate) the totals by hand.</p>
<?php echo htmlspecialchars($title); ?>
"""


def test_php_inline_html_is_document_text_not_php() -> None:
    """Inline HTML is what the server sends back verbatim; the words in it are
    not PHP, so `Print` and `eval(` in prose are not sinks."""
    indexed = index_file("acme/page.php", "php", PHP_PAGE_PROSE)

    assert _line_carrying("Print this page", PHP_PAGE_PROSE) not in {
        sink["line"] for sink in indexed["security_sinks"]
    }
    assert indexed["analysis_status"] == "complete"


# --- 3. PHP file scope -------------------------------------------------------

PHP_REQUEST_SCRIPT = b"""<?php
require_once 'config.php';
$id = $_GET['id'];
$db = new mysqli('db.example.com', 'acme', 'secret', 'acme');
$result = $db->query("SELECT * FROM reports WHERE id = " . $id);
"""


def test_a_php_script_reading_a_superglobal_is_an_entry_point() -> None:
    indexed = index_file("acme/report.php", "php", PHP_REQUEST_SCRIPT)

    assert _entries(indexed) == [
        ("php_script", "<top-level>", _line_carrying("$_GET", PHP_REQUEST_SCRIPT))
    ]
    assert indexed["analysis_status"] == "complete"
    assert indexed["unavailable_dimensions"] == []


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(b"$body = file_get_contents('php://input');", id="php-input"),
        pytest.param(
            b"$id = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);",
            id="filter-input",
        ),
        pytest.param(b"$headers = getallheaders();", id="getallheaders"),
    ],
)
def test_request_input_beyond_the_superglobals_is_a_source_and_an_entry(line: bytes) -> None:
    source = b"<?php\n" + line + b"\n"
    indexed = index_file("acme/hook.php", "php", source)

    assert [record["kind"] for record in indexed["security_sources"]] == [
        "http_request_input"
    ]
    assert _entries(indexed) == [("php_script", "<top-level>", 2)]


PHP_RENDERED_PAGE = b"""<?php require 'header.php'; ?>
<html>
  <body>
    <p>Print this page for your records.</p>
    <?php if ($user) { ?><b>Welcome</b><?php } ?>
  </body>
</html>
"""


def test_a_rendered_page_is_a_weaker_entry_and_its_html_is_not_php() -> None:
    """Inline HTML is what a requested page sends back, so the file is a page;
    the words in it are not PHP, so `print` in prose is not an output sink."""
    indexed = index_file("acme/welcome.php", "php", PHP_RENDERED_PAGE)

    assert _entries(indexed) == [
        ("php_rendered_page", "<top-level>", _line_carrying("<html>", PHP_RENDERED_PAGE))
    ]
    assert all(sink["kind"] != "xss_output" for sink in indexed["security_sinks"])


PHP_CLI_SCRIPT = b"""#!/usr/bin/env php
<?php
$total = count(scandir('/var/acme/reports'));
"""


def test_a_shebang_is_not_inline_html() -> None:
    indexed = index_file("bin/count.php", "php", PHP_CLI_SCRIPT)

    assert all(
        entry["kind"] not in {"php_script", "php_rendered_page"}
        for entry in indexed["entry_points"]
    )


def test_a_shebang_makes_the_file_a_cli_script() -> None:
    indexed = index_file("bin/count.php", "php", PHP_CLI_SCRIPT)

    assert [
        (entry["kind"], entry["name"], entry["line"], entry["annotation"])
        for entry in indexed["entry_points"]
    ] == [("php_cli_script", "<top-level>", 1, "shebang")]


@pytest.mark.parametrize(
    ("line", "evidence"),
    [
        pytest.param(b"if (PHP_SAPI !== 'cli') { exit(1); }", "sapi_check", id="php-sapi"),
        pytest.param(b"if (php_sapi_name() != 'cli') { exit(1); }", "sapi_check", id="sapi-name"),
        pytest.param(b"$target = $argv[1];", "argv", id="argv"),
        pytest.param(b"if ($argc < 2) { exit(1); }", "argv", id="argc"),
        pytest.param(b"$target = $_SERVER['argv'][1];", "argv", id="server-argv"),
        pytest.param(b"$options = getopt('f:');", "getopt", id="getopt"),
        pytest.param(b"$line = fgets(STDIN);", "stdin", id="stdin"),
        pytest.param(b"$answer = readline('Continue? ');", "readline", id="readline"),
    ],
)
def test_file_scope_cli_evidence_is_a_cli_entry_naming_it(line: bytes, evidence: str) -> None:
    indexed = index_file("bin/acme-sync.php", "php", b"<?php\n" + line + b"\n")

    assert [
        (entry["kind"], entry["line"], entry["annotation"])
        for entry in indexed["entry_points"]
    ] == [("php_cli_script", 2, evidence)]


def test_a_dual_mode_script_is_both_a_web_and_a_cli_entry() -> None:
    source = b"""<?php
if (PHP_SAPI === 'cli') {
    $id = $argv[1];
} else {
    $id = $_GET['id'];
}
"""
    indexed = index_file("tools/report.php", "php", source)

    assert sorted(
        (entry["kind"], entry["annotation"]) for entry in indexed["entry_points"]
    ) == [("php_cli_script", "sapi_check"), ("php_script", "request_input")]


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            b"<?php defined('_JEXEC') or die; ?>\n<h1><?php echo $this->escape($this->title); ?></h1>\n",
            id="joomla-view-this",
        ),
        pytest.param(
            b"<?php defined('C5_EXECUTE') or die('Access Denied.'); ?>\n<div class=\"acme\">Invoices</div>\n",
            id="direct-access-guard",
        ),
        pytest.param(
            b"<?php\nif (!defined('ACME_INTERNAL')) {\n    exit;\n}\n?>\n<p>Acme</p>\n",
            id="if-guard",
        ),
        pytest.param(
            b"<div class=\"acme\"><?= $this->getTitle() ?></div>\n",
            id="block-template-this",
        ),
    ],
)
def test_a_view_rendered_by_its_framework_is_not_a_requestable_page(source: bytes) -> None:
    indexed = index_file("templates/acme/view.php", "php", source)

    assert all(entry["kind"] != "php_rendered_page" for entry in indexed["entry_points"])


def test_a_superglobal_spelled_in_another_case_is_not_request_input() -> None:
    source = b"""<?php
class AcmeExtractCommand
{
    protected array $_files = [];
    protected $_request;

    public function run(): void
    {
        $this->_files[] = $this->_request;
    }
}
$_get = [];
"""
    for observed in (
        index_file("src/Command/AcmeExtractCommand.php", "php", source),
        treesitter_index._fallback_from_bytes(
            "src/Command/AcmeExtractCommand.php", "php", source, degradation_reason="test"
        ),
    ):
        assert observed["security_sources"] == []
        assert all(entry["kind"] != "php_script" for entry in observed["entry_points"])


def test_a_class_member_is_not_file_scope_entry_evidence() -> None:
    source = b"""<?php
class AcmeRuntime
{
    public string $sapi = PHP_SAPI;
    public array $query = ['source' => '$_GET'];
}
"""
    indexed = index_file("src/AcmeRuntime.php", "php", source)

    assert indexed["entry_points"] == []


@pytest.mark.parametrize(
    "line",
    [
        pytest.param(b"$_SERVER['HTTPS'] = 'on';", id="server-write"),
        pytest.param(b"$_GET['page'] = 1;", id="get-write"),
        pytest.param(b"unset($_SERVER['HTTP_PROXY'], $_GET['debug']);", id="unset"),
        pytest.param(
            b"if (isset($_SERVER['REMOTE_ADDR'])) {\n    die('Command line only');\n}", id="cli-guard"
        ),
    ],
)
def test_a_superglobal_write_or_cli_guard_is_not_request_evidence(line: bytes) -> None:
    indexed = index_file("admin/cli/acme_install.php", "php", b"<?php\n" + line + b"\n")

    assert all(entry["kind"] != "php_script" for entry in indexed["entry_points"])


def test_a_request_read_beside_a_write_is_still_evidence() -> None:
    source = b"<?php\n$_SERVER['HTTPS'] = 'on';\n$page = $_GET['page'];\n"
    indexed = index_file("public/index.php", "php", source)

    assert ("php_script", "<top-level>", 3) in _entries(indexed)


@pytest.mark.parametrize(
    "path",
    ["apps/acme/composer/autoload.php", "vendor/composer/platform_check.php"],
)
def test_a_composer_generated_sapi_check_is_not_a_cli_script(path: str) -> None:
    source = b"""<?php

// autoload.php @generated by Composer

if (PHP_VERSION_ID < 50600) {
    $err = 'Composer 2.3.0 dropped support for PHP 5.5 and lower.';
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
        fwrite(STDERR, $err);
    } elseif (!headers_sent()) {
        echo $err;
    }
    trigger_error($err, E_USER_ERROR);
}

require_once __DIR__ . '/composer/autoload_real.php';

return ComposerAutoloaderInitAcme::getLoader();
"""
    indexed = index_file(path, "php", source)

    assert all(entry["kind"] != "php_cli_script" for entry in indexed["entry_points"])


def test_cli_input_inside_a_function_does_not_make_the_file_a_cli_script() -> None:
    source = b"""<?php
function acme_main(array $argv) {
    return $argv[1];
}
"""
    indexed = index_file("src/cli.php", "php", source)

    assert all(entry["kind"] != "php_cli_script" for entry in indexed["entry_points"])


@pytest.mark.parametrize(
    "line",
    [
        b"$target = $argv[1];",
        b"$count = $argc;",
        b"$options = getopt('f:');",
        b"$line = fgets(STDIN);",
    ],
)
def test_process_arguments_and_stdin_are_process_input(line: bytes) -> None:
    source = b"<?php\n" + line + b"\n"
    for observed in (
        index_file("bin/acme-sync.php", "php", source),
        treesitter_index._fallback_from_bytes(
            "bin/acme-sync.php", "php", source, degradation_reason="test"
        ),
    ):
        assert [record["kind"] for record in observed["security_sources"]] == [
            "process_input"
        ]


PHP_ARGV_IN_A_METHOD = b"""<?php
namespace Acme\\Boot;

class EnvironmentDetector
{
    public function detect(): string
    {
        $args = $_SERVER['argv'] ?? [];
        return $args[1] ?? 'production';
    }
}
"""


def test_server_argv_is_both_process_and_request_input() -> None:
    """Under a web SAPI with `register_argc_argv` on, PHP fills
    `$_SERVER['argv']` and `argc` from the query string."""
    for observed in (
        index_file("src/EnvironmentDetector.php", "php", PHP_ARGV_IN_A_METHOD),
        treesitter_index._fallback_from_bytes(
            "src/EnvironmentDetector.php", "php", PHP_ARGV_IN_A_METHOD, degradation_reason="test"
        ),
    ):
        assert sorted(
            (record["kind"], record["line"]) for record in observed["security_sources"]
        ) == [("http_request_input", 8), ("process_input", 8)]


def test_server_argv_in_a_cli_script_is_no_request_page() -> None:
    source = b"#!/usr/bin/env php\n<?php\n$opts = $_SERVER['argv'];\n"
    indexed = index_file("bin/acme-sync.php", "php", source)

    assert [entry["kind"] for entry in indexed["entry_points"]] == ["php_cli_script"]


def test_other_server_fields_stay_request_input() -> None:
    source = b"<?php\n$ip = $_SERVER['REMOTE_ADDR'];\n"
    indexed = index_file("acme/ip.php", "php", source)

    assert [record["kind"] for record in indexed["security_sources"]] == [
        "http_request_input"
    ]


PHP_CLASS_FILE = b"""<?php

class ReportController
{
    public function show()
    {
        return $_GET['id'];
    }
}
"""


def test_request_input_inside_a_method_does_not_make_the_file_a_script() -> None:
    indexed = index_file("acme/ReportController.php", "php", PHP_CLASS_FILE)

    assert all(entry["kind"] != "php_script" for entry in indexed["entry_points"])


PHP_LIBRARY = b"""<?php

define('ACME_ROOT', __DIR__);
"""


def test_a_php_file_without_entry_evidence_still_measures_its_entries() -> None:
    """PHP has a file-scope entry catalogue, so no callable is not no measurement."""
    indexed = index_file("acme/bootstrap.php", "php", PHP_LIBRARY)

    assert indexed["entry_points"] == []
    assert indexed["analysis_status"] == "complete"


def test_the_streaming_fallback_reports_request_reads_but_classifies_no_php_script() -> None:
    """A byte-window scan has no callable spans, so it cannot tell a script's
    file scope from a controller method. It reports every request read as a
    source and leaves `php_script` to the structural reader, which can."""
    for source in (PHP_REQUEST_SCRIPT, PHP_CLASS_FILE):
        observed = treesitter_index._fallback_from_bytes(
            "acme/report.php", "php", source, degradation_reason="test"
        )

        assert [record["kind"] for record in observed["security_sources"]] == [
            "http_request_input"
        ]
        assert all(entry["kind"] != "php_script" for entry in observed["entry_points"])


# --- 4. Python route tables --------------------------------------------------

DJANGO_URLS = b"""from django.urls import path, re_path

from acme import views

urlpatterns = [
    path("reports/", views.report_list),
    re_path(r"^reports/(?P<pk>[0-9]+)/$", views.report_detail),
]
"""


def test_a_django_url_table_names_every_route() -> None:
    indexed = index_file("acme/urls.py", "python", DJANGO_URLS)

    assert _entries(indexed) == [
        ("django_route", "<top-level>", _line_carrying('path("reports/"', DJANGO_URLS)),
        ("django_route", "<top-level>", _line_carrying("re_path(", DJANGO_URLS)),
    ]
    assert indexed["analysis_status"] == "complete"


FLASK_MODULE_ROUTES = b"""from flask import Flask

from acme.views import report

app = Flask(__name__)
app.add_url_rule("/report", view_func=report)
"""


def test_a_module_level_flask_url_rule_is_an_entry_point() -> None:
    indexed = index_file("acme/app.py", "python", FLASK_MODULE_ROUTES)

    assert _entries(indexed) == [
        ("flask_url_rule", "<top-level>", _line_carrying("add_url_rule", FLASK_MODULE_ROUTES))
    ]


TORNADO_MODULE_APP = b"""import tornado.web

from acme.handlers import ReportHandler

application = tornado.web.Application([
    (r"/report", ReportHandler),
])
"""


def test_a_module_level_tornado_application_is_an_entry_point() -> None:
    indexed = index_file("acme/server.py", "python", TORNADO_MODULE_APP)

    assert _entries(indexed) == [
        ("tornado_application", "<top-level>", _line_carrying("Application(", TORNADO_MODULE_APP)),
        ("tornado_route", "<top-level>", _line_carrying('(r"/report"', TORNADO_MODULE_APP)),
    ]


# --- 5. File scope is a reviewable callable ----------------------------------

PHP_MIXED = b"""<?php
require_once __DIR__ . '/bootstrap.php';
$id = $_GET['id'];

function acme_render($id)
{
    return htmlspecialchars($id);
}

echo acme_render($id);
"""


def _segments(indexed: dict) -> list[tuple[int, int]]:
    return [(segment["line_start"], segment["line_end"]) for segment in indexed["top_level_segments"]]


def test_file_scope_segments_lie_between_the_callables() -> None:
    indexed = index_file("public/report.php", "php", PHP_MIXED)

    assert _segments(indexed) == [(2, 3), (10, 10)]
    assert indexed["total_functions"] == 1


def test_delimiter_only_lines_open_no_segment() -> None:
    source = b"""<?php
namespace Acme\\Billing;

class Invoice
{
    public function total()
    {
        return 1;
    }
}
"""
    indexed = index_file("src/Invoice.php", "php", source)

    assert _segments(indexed) == []


def test_a_decorator_is_part_of_the_declaration_it_heads() -> None:
    source = b"""from flask import Flask
app = Flask(__name__)

@app.route("/a")
def a():
    return 1

@app.route("/b")
def b():
    return 2
"""
    indexed = index_file("app.py", "python", source)

    assert _segments(indexed) == [(2, 2)]


def test_a_zero_callable_file_is_one_segment_over_its_source_lines() -> None:
    indexed = index_file("acme/report.php", "php", PHP_REQUEST_SCRIPT)

    assert indexed["total_functions"] == 0
    assert _segments(indexed) == [(2, 5)]


def test_the_top_level_scope_is_published_as_callable_records() -> None:
    from assess.lib.code_structural_metadata import validated_callable_records

    indexed = index_file("public/report.php", "php", PHP_MIXED)
    records = validated_callable_records(indexed, rel_path="public/report.php")

    assert [
        (record["name"], record["qualified_name"], record["start_line"], record["end_line"])
        for record in records
    ] == [
        ("acme_render", "acme_render", 5, 8),
        ("<top-level>", "<top-level>", 2, 3),
        ("<top-level>", "<top-level>", 10, 10),
    ]


# --- 6. File-scope statements that carry nothing to review -------------------

PHP_INVOICE_CLASS = """<?php
namespace Acme\\Billing;

class Invoice
{
    public function total(): int
    {
        return 1;
    }
}
"""


def test_a_literal_class_alias_opens_no_segment() -> None:
    source = (PHP_INVOICE_CLASS + "\nclass_alias(Invoice::class, 'Acme_Billing_Invoice');\n").encode()
    indexed = index_file("src/Invoice.php", "php", source)

    assert _segments(indexed) == []
    assert indexed["total_functions"] == 1


def test_a_class_alias_of_a_runtime_value_is_still_owed() -> None:
    source = b"<?php\nclass_alias($legacy, 'Acme_Legacy');\n"

    assert _segments(index_file("src/legacy.php", "php", source)) == [(2, 2)]


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param("defined('ACME_INTERNAL') || die();", id="or-operator"),
        pytest.param("defined('ACME_INTERNAL') or die('No direct access');", id="or-keyword"),
        pytest.param("\\defined('_JEXEC') or die;", id="qualified-die"),
        pytest.param("defined('ACME_INTERNAL') or exit;", id="or-exit"),
        pytest.param("defined('ACME_INTERNAL') || exit(1);", id="exit-call"),
        pytest.param("if (!defined('ACME_INTERNAL')) {\n    die('No direct access');\n}", id="if-die"),
        pytest.param("if (!defined('ACME_INTERNAL')) {\n    exit;\n}", id="if-exit"),
        pytest.param("if (!\\defined('ACME_INTERNAL')) die();", id="if-unbraced"),
    ],
)
def test_a_direct_access_guard_opens_no_segment(guard: str) -> None:
    source = (
        "<?php\n" + guard + "\n\nclass acme_widget\n{\n"
        "    public function render(): string\n    {\n        return 'x';\n    }\n}\n"
    ).encode()

    assert _segments(index_file("src/widget.php", "php", source)) == []


def test_a_guard_before_a_request_script_leaves_only_the_script_owed() -> None:
    source = b"<?php\ndefined('ACME_INTERNAL') || die();\n$id = $_GET['id'];\necho $id;\n"
    indexed = index_file("public/view.php", "php", source)

    assert _segments(indexed) == [(3, 4)]
    assert ("php_script", "<top-level>", 3) in _entries(indexed)


def test_a_guard_whose_exit_message_is_computed_is_still_owed() -> None:
    source = b"<?php\ndefined('ACME_INTERNAL') || die($reason);\n"

    assert _segments(index_file("src/guarded.php", "php", source)) == [(2, 2)]


def test_a_literal_constant_definition_opens_no_segment() -> None:
    source = b"""<?php
define('ACME_VERSION', '1.2.0');
define('ACME_ROOT', __DIR__ . '/..');

function acme_version(): string
{
    return ACME_VERSION;
}
"""

    assert _segments(index_file("src/version.php", "php", source)) == []


def test_a_constant_defined_from_a_call_is_still_owed() -> None:
    source = b"<?php\ndefine('ACME_HOME', getenv('ACME_HOME'));\n"

    assert _segments(index_file("src/home.php", "php", source)) == [(2, 2)]


def test_a_literal_configuration_return_is_owed_as_a_whole_file() -> None:
    source = b"""<?php
return [
    'name' => 'acme',
    'debug' => false,
    'hosts' => ['app.example.com', 'api.example.com'],
];
"""
    indexed = index_file("config/app.php", "php", source)

    assert _segments(indexed) == []
    assert indexed["total_functions"] == 0
    assert indexed["analysis_status"] == "complete"


def test_a_configuration_return_reading_the_environment_is_owed() -> None:
    source = b"""<?php
return [
    'name' => 'acme',
    'key' => getenv('ACME_KEY'),
];
"""
    indexed = index_file("config/keys.php", "php", source)

    assert _segments(indexed) == [(2, 4)]
    assert [record["kind"] for record in indexed["security_sources"]] == ["process_input"]


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(b"<?php\nreturn;\n", id="bare"),
        pytest.param(b"<?php\nreturn 'acme';\n", id="literal"),
    ],
)
def test_a_literal_file_scope_return_opens_no_segment(source: bytes) -> None:
    assert _segments(index_file("src/stop.php", "php", source)) == []


def test_an_anonymous_migration_class_owes_only_its_head() -> None:
    source = b"""<?php
use Acme\\Schema\\Migration;

return new class extends Migration {
    public function up(): void
    {
        $this->create('invoices');
    }
};
"""

    assert _segments(index_file("database/migrations/create_invoices.php", "php", source)) == [(4, 4)]


def test_blank_lines_between_anonymous_class_members_open_no_segment() -> None:
    source = b"""<?php

return new class extends Migration
{
    public function shouldRun(): bool
    {
        return false;
    }

    /**
     * Run the migration.
     */
    public function up(): void
    {
        $this->create('invoices');
    }
};
"""

    assert _segments(index_file("database/migrations/create_invoices.php", "php", source)) == [(3, 4)]


def test_a_route_group_owes_its_head_and_keeps_its_route() -> None:
    source = b"""<?php
use Illuminate\\Support\\Facades\\Route;

Route::group(
    ['prefix' => 'billing'],
    function () {
        Route::get('/invoices', [InvoiceController::class, 'index']);
    }
);
"""
    indexed = index_file("routes/web.php", "php", source)

    assert _segments(indexed) == [(4, 5)]
    assert "laravel_route" in {kind for kind, _name, _line in _entries(indexed)}


def test_a_function_exists_guard_owes_nothing_around_its_definition() -> None:
    source = b"""<?php
if (!function_exists('acme_helper')) {
    /**
     * Acme helper.
     *
     * @return int
     */
    function acme_helper(): int
    {
        return 2;
    }
}
"""
    indexed = index_file("src/helpers.php", "php", source)

    assert _segments(indexed) == []
    assert indexed["total_functions"] == 1


def test_every_branch_of_a_combined_existence_guard_is_a_container() -> None:
    source = b"""<?php
if (interface_exists(\\Acme\\Runner::class) && !class_exists('AcmeRunner')) {
    class AcmeRunner
    {
        public function run(): int
        {
            return 1;
        }
    }
} else {
    class_alias(\\Acme\\LegacyRunner::class, 'AcmeRunner');
}
"""

    assert _segments(index_file("src/runner.php", "php", source)) == []


def test_an_elseif_that_reads_a_value_makes_the_guard_ordinary_code() -> None:
    source = b"""<?php
if (!defined('ACME_ROOT')) {
    define('ACME_ROOT', __DIR__);
} elseif ($strict) {
    exit;
}
"""

    assert _segments(index_file("src/root.php", "php", source)) == [(2, 5)]


def test_code_inside_an_existence_guard_is_still_owed() -> None:
    source = b"""<?php
if (!class_exists('Acme\\\\Kernel')) {
    require __DIR__ . '/kernel.php';
}
"""

    assert _segments(index_file("src/load.php", "php", source)) == [(3, 3)]


@pytest.mark.parametrize(
    ("source", "segments"),
    [
        pytest.param(b"<?php\nrequire_once __DIR__ . '/bootstrap.php';\n", [(2, 2)], id="literal-require"),
        pytest.param(b"<h1>Acme</h1>\n", [(1, 1)], id="inline-html"),
        pytest.param(b"<?php\n$app->run();\n", [(2, 2)], id="call"),
    ],
)
def test_statements_that_run_still_open_segments(source: bytes, segments: list) -> None:
    assert _segments(index_file("public/index.php", "php", source)) == segments


def test_a_literal_module_return_opens_no_javascript_segment() -> None:
    source = b"const acme = require('./acme');\nacme.start();\nreturn;\n"

    assert _segments(index_file("bin/acme.js", "javascript", source)) == [(1, 2)]
