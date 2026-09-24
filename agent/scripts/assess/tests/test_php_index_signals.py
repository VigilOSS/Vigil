"""PHP route and sink signals used to direct large-repository review."""

from __future__ import annotations

from assess.lib.treesitter_index import index_file


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
