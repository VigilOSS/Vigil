"""PHP route and sink signals used to direct large-repository review."""

from __future__ import annotations

import time

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file
from assess.lib.treesitter_streaming import StreamingSecurityScanner


def test_laravel_controller_public_action_is_candidate_entry() -> None:
    source = b"""<?php
class FilesController extends Controller {
    public function show(Request $request) {
        return file_get_contents($request->query('path'));
    }
}
"""

    indexed = index_file("app/Http/Controllers/FilesController.php", "php", source)

    assert indexed["analysis_status"] == "complete"
    assert any(item["name"] == "show" and item["kind"] == "laravel_action"
               for item in indexed["entry_points"])
    assert any(item["kind"] == "file_path" for item in indexed["security_sinks"])


def test_php_private_controller_helper_is_not_http_entry() -> None:
    source = b"""<?php
class FilesController extends Controller {
    public function show() { return $this->helper(); }
    private function helper() { return 'ok'; }
}
"""

    indexed = index_file("app/Http/Controllers/FilesController.php", "php", source)

    assert any(item["name"] == "show" for item in indexed["entry_points"])
    assert not any(item["name"] == "helper" for item in indexed["entry_points"])


def test_plain_php_class_named_controller_is_not_laravel_entry() -> None:
    source = b"""<?php
class CacheController {
    public function flush() { return 1; }
}
"""
    indexed = index_file("src/CacheController.php", "php", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(item["kind"] == "laravel_action" for item in indexed["entry_points"])


def _laravel_actions(path: str, source: bytes) -> set[str]:
    indexed = index_file(path, "php", source)
    assert indexed["analysis_status"] == "complete"
    return {item["name"] for item in indexed["entry_points"] if item["kind"] == "laravel_action"}


@pytest.mark.parametrize("path,namespace", [
    ("app/Http/Controllers/Billing/InvoiceController.php", "namespace App\\Http\\Controllers\\Billing;"),
    ("modules/billing/InvoiceController.php", "namespace Acme\\Billing\\Http\\Controllers;"),
    ("app/Http/Controllers/Billing/InvoiceController.php", ""),
])
def test_controller_under_a_controllers_namespace_or_path_extending_a_project_base_is_entry(
    path: str, namespace: str,
) -> None:
    source = f"""<?php
{namespace}
class InvoiceController extends ApiBase {{
    public function show($id) {{ return $id; }}
}}
""".encode()

    assert _laravel_actions(path, source) == {"show"}


def test_controller_with_no_parent_under_a_controllers_namespace_is_entry() -> None:
    source = b"""<?php
namespace App\\Http\\Controllers;
class HealthController {
    public function index() { return 'ok'; }
}
"""

    assert _laravel_actions("app/Http/Controllers/HealthController.php", source) == {"index"}


@pytest.mark.parametrize("name,parent", [
    ("ProvisionServer", ""),
    ("ShowProfileController", "extends Controller"),
])
def test_invokable_controller_invoke_is_entry(name: str, parent: str) -> None:
    source = f"""<?php
namespace App\\Http\\Controllers;
class {name} {parent} {{
    public function __construct() {{}}
    public function __invoke($request) {{ return $request; }}
}}
""".encode()

    indexed = index_file(f"app/Http/Controllers/{name}.php", "php", source)

    assert {(item["name"], item["kind"]) for item in indexed["entry_points"]} == {
        ("__construct", "constructor"),
        ("__invoke", "laravel_action"),
    }


@pytest.mark.parametrize("path,declaration,action", [
    ("app/Http/Controllers/ExportReport.php", "class ExportReport { public function run() { return 2; } }", "run"),
    ("app/Http/Controllers/Requests/StoreUserRequest.php",
     "class StoreUserRequest extends FormRequest { public function rules() { return []; } }", "rules"),
])
def test_any_named_class_under_a_controllers_namespace_routes_its_public_methods(
    path: str, declaration: str, action: str,
) -> None:
    source = f"<?php\nnamespace App\\Http\\Controllers;\n{declaration}\n".encode()

    assert _laravel_actions(path, source) == {action}


def test_class_ending_in_controller_outside_a_controllers_namespace_is_not_entry() -> None:
    source = b"""<?php
namespace Acme\\Cache;
class CacheController extends Store {
    public function flush() { return 1; }
    public function __invoke() { return 2; }
}
"""

    assert _laravel_actions("src/Cache/CacheController.php", source) == set()


def test_protected_and_private_methods_of_a_controllers_namespace_class_are_not_entry() -> None:
    source = b"""<?php
namespace App\\Http\\Controllers;
class ReportController extends ApiBase {
    public function show() { return $this->load(); }
    protected function load() { return $this->format(); }
    private function format() { return 'ok'; }
    protected function __invoke() { return 1; }
}
"""

    assert _laravel_actions("app/Http/Controllers/ReportController.php", source) == {"show"}


def test_laravel_route_macro_is_not_http_route() -> None:
    source = b"""<?php
class Setup {
    function boot() { Route::macro('helper', function () {}); }
}
"""

    indexed = index_file("Setup.php", "php", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(item["kind"] == "laravel_route" for item in indexed["entry_points"])


def test_top_level_php_request_file_read_retains_sink_signal() -> None:
    source = b"""<?php
$path = $_GET['path'];
echo file_get_contents($path);
"""

    indexed = index_file("public/download.php", "php", source)

    assert any(item["kind"] == "file_path" and item["line"] == 3
               for item in indexed["security_sinks"])


def test_enum_and_anonymous_class_methods_are_qualified_by_their_class() -> None:
    source = b"""<?php
enum InvoiceStatus: string
{
    case Paid = 'paid';

    public function label(): string
    {
        return ucfirst($this->value);
    }
}

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('acme_invoices');
    }
};

$probe = fn () => new class { public function ping(): void {} };
"""

    indexed = index_file("database/migrations/acme_invoices.php", "php", source)

    assert [(item["name"], item["qualified_name"]) for item in indexed["functions"]] == [
        ("label", "InvoiceStatus.label"),
        ("up", "<anonymous@12:11>.up"),
        ("$probe", "$probe"),
        ("ping", "<anonymous@20:22>.ping"),
    ]
    assert [item["name"] for item in indexed["classes"]] == [
        "InvoiceStatus",
        "<anonymous@12:11>",
        "<anonymous@20:22>",
    ]


def test_php_database_exec_is_sql_and_json_decode_is_not_deserialization() -> None:
    source = b"""<?php
class AcmeImport {
    public function run($pdo, $cmd, $payload) {
        $pdo->exec("DELETE FROM acme_rows WHERE batch = " . $payload);
        exec($cmd);
        $rows = json_decode($payload, true);
        return unserialize($payload);
    }
}
"""

    indexed = index_file("src/AcmeImport.php", "php", source)

    assert {(item["line"], item["kind"]) for item in indexed["security_sinks"]} == {
        (4, "sql_exec"),
        (4, "process_exec"),
        (5, "process_exec"),
        (7, "deserialization"),
    }


def test_constructor_promoted_parameters_are_parameters() -> None:
    source = b"""<?php
final class InvoiceController {
    public function __construct(private readonly Request $request, string $plain, protected ?int $limit = null) {}
}
"""

    indexed = index_file("src/InvoiceController.php", "php", source)

    assert indexed["functions"][0]["params"] == [
        "private readonly Request $request",
        "string $plain",
        "protected ?int $limit = null",
    ]


def test_php_symbols_are_qualified_by_the_namespace_declared_before_them() -> None:
    source = b"""<?php
namespace Acme\\Billing;

final class InvoiceController
{
    public function show($id) { return $id; }
}

function invoice_total($rows) { return count($rows); }

namespace Acme\\Reports;

function export_csv($rows) { return $rows; }
"""

    indexed = index_file("src/billing.php", "php", source)

    assert [(item["name"], item["qualified_name"]) for item in indexed["functions"]] == [
        ("show", "Acme\\Billing\\InvoiceController.show"),
        ("invoice_total", "Acme\\Billing\\invoice_total"),
        ("export_csv", "Acme\\Reports\\export_csv"),
    ]


def test_braced_php_namespaces_qualify_only_their_own_block() -> None:
    source = b"""<?php
namespace Acme\\Ledger {
    class Journal
    {
        public function post($entry)
        {
            $format = function ($line) { return trim($line); };
            return $format($entry);
        }
    }
}

namespace {
    function acme_root() { return new Acme\\Ledger\\Journal(); }
    $probe = fn () => 1;
}
"""

    indexed = index_file("src/ledger.php", "php", source)

    assert [(item["name"], item["qualified_name"]) for item in indexed["functions"]] == [
        ("post", "Acme\\Ledger\\Journal.post"),
        ("$format", "Acme\\Ledger\\Journal.$format"),
        ("acme_root", "acme_root"),
        ("$probe", "$probe"),
    ]


PHP_USE_DECLARATIONS = b"""<?php
namespace Acme\\Billing;

use Acme\\Models\\Invoice;
use Acme\\Models\\Customer as Client, Acme\\Models\\Order;
use function Acme\\Support\\format_money;
use const Acme\\Support\\VAT_RATE;
use Acme\\Http\\{Request, Response as Reply, function respond, const STATUS_OK};
use FUNCTION Acme\\Util\\{slugify, truncate AS clip};
use \\Acme\\Contracts\\Payable;
use Acme\\Models\\{
    Ledger, // the books
    Journal as Book
};
use function Acme\\Support\\round_money, Acme\\Support\\format_tax;
use const Acme\\Support\\VAT_CAP, Acme\\Support\\VAT_FLOOR;

final class InvoiceController
{
    use Acme\\Concerns\\Loggable;

    public function show($id)
    {
        return array_map(function ($row) use ($id) { return $row; }, []);
    }
}
"""

# (kind, fully qualified name, alias, line) for every name the file imports.
PHP_USE_IMPORTS = [
    ("class", "Acme\\Models\\Invoice", "", 4),
    ("class", "Acme\\Models\\Customer", "Client", 5),
    ("class", "Acme\\Models\\Order", "", 5),
    ("function", "Acme\\Support\\format_money", "", 6),
    ("const", "Acme\\Support\\VAT_RATE", "", 7),
    ("class", "Acme\\Http\\Request", "", 8),
    ("class", "Acme\\Http\\Response", "Reply", 8),
    ("function", "Acme\\Http\\respond", "", 8),
    ("const", "Acme\\Http\\STATUS_OK", "", 8),
    ("function", "Acme\\Util\\slugify", "", 9),
    ("function", "Acme\\Util\\truncate", "clip", 9),
    ("class", "Acme\\Contracts\\Payable", "", 10),
    ("class", "Acme\\Models\\Ledger", "", 12),
    ("class", "Acme\\Models\\Journal", "Book", 13),
    ("function", "Acme\\Support\\round_money", "", 15),
    ("function", "Acme\\Support\\format_tax", "", 15),
    ("const", "Acme\\Support\\VAT_CAP", "", 16),
    ("const", "Acme\\Support\\VAT_FLOOR", "", 16),
]


def _use_imports(targets: list[dict]) -> list[tuple[str, str, str, int]]:
    return [
        (item["kind"], item["qualified_name"], item["alias"], item["line"])
        for item in targets
        if "kind" in item
    ]


def test_php_use_declarations_are_one_normalised_import_per_name() -> None:
    indexed = index_file("src/InvoiceController.php", "php", PHP_USE_DECLARATIONS)

    assert _use_imports(indexed["import_targets"]) == PHP_USE_IMPORTS
    assert indexed["imports"] == [name for _kind, name, _alias, _line in PHP_USE_IMPORTS]
    assert all(item["raw"] == item["qualified_name"] for item in indexed["import_targets"])
    assert indexed["signal_counts"]["imports"] == len(PHP_USE_IMPORTS)


def test_only_php_class_imports_resolve_to_a_namespace_path() -> None:
    indexed = index_file("src/InvoiceController.php", "php", PHP_USE_DECLARATIONS)
    resolved = {item["qualified_name"]: item["resolved"] for item in indexed["import_targets"]}

    assert resolved["Acme\\Models\\Invoice"] == "Acme/Models/Invoice"
    assert resolved["Acme\\Support\\format_money"] == ""
    assert resolved["Acme\\Http\\STATUS_OK"] == ""


def test_streaming_fallback_reads_php_use_declarations_like_the_parser() -> None:
    scanner = StreamingSecurityScanner("src/InvoiceController.php", "php")
    for offset in range(0, len(PHP_USE_DECLARATIONS), 7):
        scanner.feed(PHP_USE_DECLARATIONS[offset : offset + 7])
    observed = scanner.finish(degradation_reason="tree_sitter_syntax_error")

    assert _use_imports(observed["import_targets"]) == PHP_USE_IMPORTS
    assert [
        raw for raw, item in zip(observed["imports"], observed["import_targets"]) if "kind" in item
    ] == [name for _kind, name, _alias, _line in PHP_USE_IMPORTS]
    parsed = index_file("src/InvoiceController.php", "php", PHP_USE_DECLARATIONS)
    assert [
        {key: value for key, value in item.items() if key != "detection"}
        for item in observed["import_targets"]
        if "kind" in item
    ] == parsed["import_targets"]


def test_streaming_fallback_reads_php_use_statements_that_share_a_line() -> None:
    # Minified or generated PHP, the files that reach the streaming fallback,
    # packs several statements onto one line; each `use` still imports.
    source = (
        b"<?php declare(strict_types=1); namespace Acme\\Billing; use Acme\\Models\\Invoice; "
        b"use function Acme\\Support\\format_money; final class InvoiceController "
        b"{ use Acme\\Concerns\\Loggable; }\n"
    )
    scanner = StreamingSecurityScanner("src/InvoiceController.php", "php")
    scanner.feed(source)
    observed = scanner.finish(degradation_reason="tree_sitter_syntax_error")
    parsed = index_file("src/InvoiceController.php", "php", source)

    assert _use_imports(observed["import_targets"]) == [
        ("class", "Acme\\Models\\Invoice", "", 1),
        ("function", "Acme\\Support\\format_money", "", 1),
    ]
    assert _use_imports(observed["import_targets"]) == _use_imports(parsed["import_targets"])


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            b"<?php namespace Acme\\Billing { use Acme\\Models\\Invoice; }\n",
            [("class", "Acme\\Models\\Invoice", "", 1)],
        ),
        (
            b"<?php use Acme\\Models\\Invoice; $audit = new class { use Acme\\Concerns\\Loggable; };\n",
            [("class", "Acme\\Models\\Invoice", "", 1)],
        ),
    ],
)
def test_streaming_fallback_reads_only_top_level_php_use_on_a_shared_line(
    source: bytes, expected: list[tuple[str, str, str, int]]
) -> None:
    # A namespace block holds imports; any other block's `use` is a trait.
    scanner = StreamingSecurityScanner("src/InvoiceController.php", "php")
    scanner.feed(source)
    observed = scanner.finish(degradation_reason="tree_sitter_syntax_error")

    assert _use_imports(observed["import_targets"]) == expected
    assert expected == _use_imports(
        index_file("src/InvoiceController.php", "php", source)["import_targets"]
    )


def test_streaming_fallback_keeps_php_inclusion_imports() -> None:
    source = b"<?php\ninclude 'acme/header.php';\nrequire_once __DIR__ . '/bootstrap.php';\n"
    scanner = StreamingSecurityScanner("public/index.php", "php")
    scanner.feed(source)
    observed = scanner.finish(degradation_reason="tree_sitter_syntax_error")

    assert [item["line"] for item in observed["import_targets"]] == [2, 3]
    assert "include 'acme/header.php'" in observed["import_targets"][0]["raw"]
    assert "require_once __DIR__" in observed["import_targets"][1]["raw"]


ACME_REPOSITORY = b"""<?php
namespace Acme\\Storage;

class AcmeRepo extends BaseRepo
{
    public function __construct($x) { parent::__construct($x); }

    public function purge($id, $model)
    {
        DB::select("select 1");
        $model->delete();
        $model?->restore($id);
        $copy = new \\Acme\\Storage\\Snapshot($model);
        acme_log(1); acme_audit($id);
        $this->mailer->send(
            $id,
        );
        $format = function ($row) use ($id) { return acme_format($row); };
        $this->purge($id, $model);
        return $this->db->query($id);
    }
}

acme_boot();
"""


def _calls(indexed: dict) -> list[tuple]:
    return [
        (call["caller"], call["line"], call["callee"], call["receiver"], call["call_kind"],
         call["passes_caller_params"])
        for call in indexed["call_sites"]
    ]


def test_php_call_sites_are_read_from_the_parse_tree() -> None:
    indexed = index_file("src/AcmeRepo.php", "php", ACME_REPOSITORY)

    assert _calls(indexed) == [
        ("__construct", 6, "__construct", "parent", "static", True),
        ("purge", 10, "select", "DB", "static", False),
        ("purge", 11, "delete", "$model", "method", False),
        ("purge", 12, "restore", "$model", "nullsafe_method", True),
        ("purge", 13, "Snapshot", "", "new", True),
        ("purge", 14, "acme_log", "", "function", False),
        ("purge", 14, "acme_audit", "", "function", True),
        ("purge", 15, "send", "$this->mailer", "method", True),
        ("purge", 20, "query", "$this->db", "method", True),
        ("$format", 18, "acme_format", "", "function", True),
        ("<top-level>", 24, "acme_boot", "", "function", False),
    ]


def test_php_language_constructs_are_not_call_sites_but_methods_named_like_them_are() -> None:
    source = b"""<?php
function acme_render($doc, $printer)
{
    if (isset($doc) && !empty($doc)) { $printer->print($doc); }
    $printer->list($doc);
    eval($doc);
    $doc or exit(1);
    $doc or die("missing");
    unset($doc);
    Acme\\Shell::exit($doc);
}
"""

    indexed = index_file("src/render.php", "php", source)

    assert [(call["line"], call["callee"]) for call in indexed["call_sites"]] == [
        (4, "print"),
        (5, "list"),
        (6, "eval"),
        (10, "exit"),
    ]


def test_a_call_on_a_withheld_php_declaration_line_is_unread_signal() -> None:
    """`namespace Acme; acme_run(...)` is one line the file-scope readers hold
    back. The parse tree knows the call is real, so leaving it unread is a gap
    and not a clean measurement."""
    source = b"<?php\nnamespace Acme; acme_run($_GET['task']);\n"

    indexed = index_file("public/run.php", "php", source)

    assert indexed["call_sites"] == []
    assert indexed["analysis_status"] == "degraded"
    assert set(indexed["unavailable_dimensions"]) >= {"call_sites", "dataflow", "security_sinks"}


def test_anonymous_invokable_inside_a_controller_action_stays_an_invocation_hook() -> None:
    source = b"""<?php
namespace App\\Http\\Controllers;
class SignupController extends Controller {
    public function store($request) {
        return $request->validate(['name' => [new class {
            public function __invoke($attribute, $value, $fail) { return $fail; }
        }]]);
    }
}
"""

    indexed = index_file("app/Http/Controllers/SignupController.php", "php", source)

    assert {(item["name"], item["kind"]) for item in indexed["entry_points"]} == {
        ("store", "laravel_action"),
        ("__invoke", "invocation_hook"),
    }


@pytest.mark.parametrize("path,namespace", [
    ("app/http/controllers/HealthController.php", ""),
    ("src/HealthController.php", "namespace App\\HTTP\\controllers;"),
])
def test_controllers_segment_matches_regardless_of_case(path: str, namespace: str) -> None:
    source = f"<?php\n{namespace}\nclass HealthController {{ public function index() {{ return 1; }} }}\n".encode()

    assert _laravel_actions(path, source) == {"index"}


def test_controller_detection_stays_linear_in_a_many_class_file(monkeypatch: pytest.MonkeyPatch) -> None:
    detect = treesitter_index._detect_entry_points
    elapsed = []

    def timed(*args, **kwargs):
        started = time.perf_counter()
        result = detect(*args, **kwargs)
        elapsed.append(time.perf_counter() - started)
        return result

    monkeypatch.setattr(treesitter_index, "_detect_entry_points", timed)
    source = ("<?php\nnamespace App\\Http\\Controllers;\n" + "".join(
        f"class Acme{index}Controller extends Controller {{ public function show() {{ return {index}; }} }}\n"
        for index in range(6000)
    )).encode()

    index_file("app/Http/Controllers/AcmeControllers.php", "php", source)

    assert elapsed[0] < 0.5
