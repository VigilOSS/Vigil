"""PHP route and sink signals used to direct large-repository review."""

from __future__ import annotations

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
    assert not any(item["kind"] == "sql_exec" for item in indexed["security_sinks"])


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


def test_streaming_fallback_keeps_php_inclusion_imports() -> None:
    source = b"<?php\ninclude 'acme/header.php';\nrequire_once __DIR__ . '/bootstrap.php';\n"
    scanner = StreamingSecurityScanner("public/index.php", "php")
    scanner.feed(source)
    observed = scanner.finish(degradation_reason="tree_sitter_syntax_error")

    assert [item["line"] for item in observed["import_targets"]] == [2, 3]
    assert "include 'acme/header.php'" in observed["import_targets"][0]["raw"]
    assert "require_once __DIR__" in observed["import_targets"][1]["raw"]
