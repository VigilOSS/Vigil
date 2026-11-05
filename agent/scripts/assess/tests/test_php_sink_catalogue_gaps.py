"""PHP sinks idiomatic code reaches that the catalogue did not name, and misroutes.

Each statement sits on line 3 of a small Acme handler so a sink at that line
can only come from that statement. Some shapes are only safe to read off the
parse tree -- a backtick shell command, `mail()` with its fifth argument, a
callable chosen at run time, a Guzzle client constructed by its imported
short name -- and those are detected there; the rest are catalogue rows the
streaming fallback shares.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


def _php(statement: str, *, prelude: str = "") -> bytes:
    return (
        "<?php\n" + prelude
        + "function acme_handler($id, $q, $client, $fn, $cls, $to, $path, $data) {\n    "
        + statement + "\n}\n"
    ).encode()


def _kinds(statement: str, *, prelude: str = "") -> set[str]:
    indexed = index_file("src/acme.php", "php", _php(statement, prelude=prelude))
    assert indexed["analysis_mode"] == "tree_sitter"
    line = 3 + prelude.count("\n")
    return {sink["kind"] for sink in indexed["security_sinks"] if sink["line"] == line}


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param('$q->whereRaw("id = $id");', "sql_exec", id="where-raw"),
        pytest.param("$q->selectRaw($id);", "sql_exec", id="select-raw"),
        pytest.param("$q->orderByRaw($id);", "sql_exec", id="order-by-raw"),
        pytest.param("$q->havingRaw($id);", "sql_exec", id="having-raw"),
        pytest.param("$q->groupByRaw($id);", "sql_exec", id="group-by-raw"),
        pytest.param('DB::raw("count($id)");', "sql_exec", id="db-raw"),
        pytest.param('DB::statement("DROP TABLE $id");', "sql_exec", id="db-statement"),
        pytest.param('DB::select("select * from acme where id = $id");', "sql_exec", id="db-select"),
        pytest.param('DB::unprepared("DELETE FROM acme WHERE id = $id");', "sql_exec", id="db-unprepared"),
        pytest.param('$this->db->query("SELECT * FROM acme WHERE id = $id");', "sql_exec", id="property-query"),
        pytest.param('$wpdb->get_results("SELECT * FROM acme WHERE id = $id");', "sql_exec", id="wpdb-results"),
        pytest.param("$wpdb->get_var($q);", "sql_exec", id="wpdb-var"),
        pytest.param("$wpdb->get_row($q);", "sql_exec", id="wpdb-row"),
        pytest.param("$wpdb->get_col($q);", "sql_exec", id="wpdb-col"),
        pytest.param("Http::get($id);", "url_fetch", id="http-facade"),
        pytest.param("Http::post($id, ['a' => 1]);", "url_fetch", id="http-facade-post"),
        pytest.param("wp_remote_get($id);", "url_fetch", id="wp-remote-get"),
        pytest.param("wp_remote_request($id);", "url_fetch", id="wp-remote-request"),
        pytest.param("$c = new \\GuzzleHttp\\Client(['base_uri' => $id]);", "url_fetch", id="guzzle-qualified"),
        pytest.param("unlink($path);", "file_path", id="unlink"),
        pytest.param("copy($path, '/tmp/acme');", "file_path", id="copy"),
        pytest.param("readfile($path);", "file_path", id="readfile"),
        pytest.param("move_uploaded_file($path, $id);", "file_path", id="move-uploaded"),
        pytest.param("$out = `ls $id`;", "process_exec", id="backtick"),
        pytest.param("pcntl_exec($path, [$id]);", "process_exec", id="pcntl-exec"),
        pytest.param("mail($to, 'Acme', $data, '', '-f' . $id);", "process_exec", id="mail-fifth-arg"),
        pytest.param("extract($data);", "mass_assignment", id="extract"),
        pytest.param("call_user_func($fn, $id);", "dynamic_invocation", id="call-user-func"),
        pytest.param(
            "call_user_func_array([$client, $fn], [$id]);", "dynamic_invocation", id="call-user-func-array"
        ),
        pytest.param("$fn($id);", "dynamic_invocation", id="variable-function"),
        pytest.param("$o = new $cls($id);", "dynamic_invocation", id="variable-class"),
        pytest.param("$o = new $this->handler($id);", "dynamic_invocation", id="property-class"),
        pytest.param("assert($data);", "eval_exec", id="assert-variable"),
        pytest.param("assert('$id > 0');", "eval_exec", id="assert-string"),
        pytest.param("hash('md5', $data);", "crypto", id="hash-weak"),
        pytest.param("hash($fn, $data);", "crypto", id="hash-chosen-algorithm"),
        pytest.param("mcrypt_encrypt(MCRYPT_DES, $id, $data, 'ecb');", "crypto", id="mcrypt"),
    ],
)
def test_php_sink_catalogue_gap_is_detected(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)


def test_a_guzzle_client_built_by_its_imported_name_is_a_fetch() -> None:
    assert "url_fetch" in _kinds("$c = new Client(['base_uri' => $id]);", prelude="use GuzzleHttp\\Client;\n")
    assert "url_fetch" in _kinds("$c = new Http(['base_uri' => $id]);", prelude="use GuzzleHttp\\Client as Http;\n")


@pytest.mark.parametrize(
    ("statement", "kind", "prelude"),
    [
        pytest.param("$c = new Client($id);", "url_fetch", "use Acme\\Mail\\Client;\n", id="other-client"),
        pytest.param("mail($to, 'Acme', $data, '');", "process_exec", "", id="mail-four-args"),
        pytest.param("call_user_func('acme_render', $id);", "dynamic_invocation", "", id="literal-callable"),
        pytest.param("call_user_func([$client, 'render'], $id);", "dynamic_invocation", "", id="literal-method"),
        pytest.param(
            "call_user_func(function () { return 1; });", "dynamic_invocation", "", id="closure-callable"
        ),
        pytest.param("$fn($id);", "eval_exec", "", id="variable-function-evaluates-nothing"),
        pytest.param("$o = new $cls($id);", "eval_exec", "", id="variable-class-evaluates-nothing"),
        pytest.param("call_user_func($fn, $id);", "eval_exec", "", id="callback-evaluates-nothing"),
        pytest.param("assert($id > 0, 'positive');", "eval_exec", "", id="assert-condition"),
        pytest.param("hash('sha256', $data);", "crypto", "", id="hash-strong"),
        pytest.param("$this->query->get('id');", "sql_exec", "", id="query-bag"),
        pytest.param("$this->request->query('id');", "sql_exec", "", id="request-query"),
        pytest.param("$file->copy($path);", "file_path", "", id="copy-method"),
        pytest.param("$q->where('id', $id);", "sql_exec", "", id="bound-where"),
    ],
)
def test_lookalikes_are_not_those_sinks(statement: str, kind: str, prelude: str) -> None:
    assert kind not in _kinds(statement, prelude=prelude)


def test_ast_sinks_sit_on_their_innermost_callable() -> None:
    source = b"""<?php
$report = `cat /var/acme/report`;
function acme_run($cmd) {
    return `$cmd`;
}
"""
    indexed = index_file("bin/run.php", "php", source)

    assert sorted(
        (sink["line"], sink["function"])
        for sink in indexed["security_sinks"]
        if sink["kind"] == "process_exec"
    ) == [(2, "<top-level>"), (4, "acme_run")]


def test_streaming_reads_the_catalogue_rows_it_shares() -> None:
    source = _php('$q->whereRaw("id = $id");')
    streamed = treesitter_index._fallback_from_bytes(
        "src/acme.php", "php", source, degradation_reason="test"
    )

    assert "sql_exec" in {sink["kind"] for sink in streamed["security_sinks"] if sink["line"] == 3}


def test_a_dynamic_invocation_is_an_injection_sink_of_its_own_kind() -> None:
    """Calling a callable chosen at runtime runs code the attacker may pick
    but evaluates no source text, so it is not filed with `eval`."""
    indexed = index_file("src/acme.php", "php", _php("$fn($id);"))

    assert [
        (sink["kind"], sink["vuln_classes"], sink["function"])
        for sink in indexed["security_sinks"]
    ] == [("dynamic_invocation", ["injection"], "acme_handler")]
