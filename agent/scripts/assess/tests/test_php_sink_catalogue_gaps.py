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
        pytest.param("$o = new $classes[$mode]($id);", "dynamic_invocation", id="subscript-class"),
        pytest.param("$o = new ($factory)($id);", "dynamic_invocation", id="parenthesized-class"),
        pytest.param("$o = new $this->classes['x']($id);", "dynamic_invocation", id="property-subscript-class"),
        pytest.param("$client->$fn($id);", "dynamic_invocation", id="variable-method"),
        pytest.param("$client->{$fn}($id);", "dynamic_invocation", id="braced-variable-method"),
        pytest.param("$client?->$fn($id);", "dynamic_invocation", id="nullsafe-variable-method"),
        pytest.param("Acme::$fn($id);", "dynamic_invocation", id="variable-static-method"),
        pytest.param("[$client, $fn]($id);", "dynamic_invocation", id="array-callable"),
        pytest.param("($this->callback)($id);", "dynamic_invocation", id="property-callable"),
        pytest.param("$this->handlers[$fn]($id);", "dynamic_invocation", id="subscript-callable"),
        pytest.param("forward_static_call($fn, $id);", "dynamic_invocation", id="forward-static-call"),
        pytest.param(
            "forward_static_call_array([$cls, $fn], [$id]);", "dynamic_invocation", id="forward-static-call-array"
        ),
        pytest.param("mcrypt_encrypt(MCRYPT_DES, $id, $data, 'ecb');", "crypto", id="mcrypt"),
    ],
)
def test_php_sink_catalogue_gap_is_detected(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param("assert($data);", "eval_exec", id="assert-variable"),
        pytest.param("assert('$id > 0');", "eval_exec", id="assert-string"),
        pytest.param("assert($_POST['c']);", "eval_exec", id="assert-request"),
        pytest.param("@assert(base64_decode($_POST['c']));", "eval_exec", id="assert-decoded"),
        pytest.param("assert($o->code);", "eval_exec", id="assert-property"),
        pytest.param("assert($id > 0, 'positive');", "eval_exec", id="assert-condition"),
        pytest.param("hash('md5', $data);", "crypto", id="hash-weak"),
        pytest.param("hash($fn, $data);", "crypto", id="hash-chosen-algorithm"),
        pytest.param("hash('sha256', $pw);", "crypto", id="hash-strong"),
        pytest.param("hash(self::ALGO, $pw);", "crypto", id="hash-constant"),
    ],
)
def test_every_assert_and_hash_call_is_a_sink_on_both_readers(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)
    assert kind in _streamed_kinds(statement)


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
        pytest.param("$client->render($id);", "dynamic_invocation", "", id="named-method"),
        pytest.param("Acme::render($id);", "dynamic_invocation", "", id="named-static-method"),
        pytest.param("$client->{'render'}($id);", "dynamic_invocation", "", id="braced-literal-method"),
        pytest.param("(function ($v) { return $v; })($id);", "dynamic_invocation", "", id="immediate-closure"),
        pytest.param("(fn ($v) => $v)($id);", "dynamic_invocation", "", id="immediate-arrow"),
        pytest.param("[$client, 'render']($id);", "dynamic_invocation", "", id="literal-array-callable"),
        pytest.param("$o = new namespace\\Mailer($id);", "dynamic_invocation", "", id="relative-class-name"),
        pytest.param("$o = new (Mailer::class)($id);", "dynamic_invocation", "", id="parenthesized-class-constant"),
        pytest.param("$o = new ('Acme\\Mailer')($id);", "dynamic_invocation", "", id="parenthesized-literal"),
        pytest.param("$fn($id);", "eval_exec", "", id="variable-function-evaluates-nothing"),
        pytest.param("$o = new $cls($id);", "eval_exec", "", id="variable-class-evaluates-nothing"),
        pytest.param("call_user_func($fn, $id);", "eval_exec", "", id="callback-evaluates-nothing"),
        pytest.param("$this->query->get('id');", "sql_exec", "", id="query-bag"),
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


def _streamed_kinds(statement: str, *, prelude: str = "") -> set[str]:
    streamed = treesitter_index._fallback_from_bytes(
        "src/acme.php", "php", _php(statement, prelude=prelude), degradation_reason="test"
    )
    line = 3 + prelude.count("\n")
    return {sink["kind"] for sink in streamed["security_sinks"] if sink["line"] == line}


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("$pdo->exec($id);", id="pdo"),
        pytest.param("$this->connection->exec($id);", id="connection-property"),
        pytest.param("$db->getPdo()->exec($id);", id="pdo-getter"),
        pytest.param("static::$drv->exec($id);", id="static-driver"),
        pytest.param("$this->exec($id);", id="pdo-subclass"),
        pytest.param("$schedule->exec($cmd);", id="scheduler"),
        pytest.param("$this->schedule->exec('echo acme')->everyMinute();", id="scheduler-property"),
        pytest.param("$sshClient->exec($cmd);", id="ssh-client"),
        pytest.param("$redis->multi()->exec();", id="redis-transaction"),
        pytest.param("$this->redis->exec();", id="redis-property"),
        pytest.param("$pipeline->exec();", id="redis-pipeline"),
        pytest.param("$multi->exec();", id="redis-multi"),
        pytest.param("$this->redisClient->exec();", id="redis-client"),
        pytest.param("$queue->exec();", id="queue"),
        pytest.param("$this->hookManager->exec('actionAcmeShipping', [$id]);", id="hook-manager"),
        pytest.param("$pdo -> exec($sql);", id="spaced-arrow"),
    ],
)
def test_every_exec_method_is_a_sql_and_process_sink(statement: str) -> None:
    assert {"sql_exec", "process_exec"} <= _kinds(statement)
    assert {"sql_exec", "process_exec"} <= _streamed_kinds(statement)


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("$mysqli->query($id);", id="mysqli"),
        pytest.param("$this->db->query($id);", id="db-property"),
        pytest.param('$dbClient->query("SELECT * FROM acme WHERE id = $id");', id="db-client"),
        pytest.param("$queryBuilder->query($sql);", id="query-builder"),
        pytest.param("$xpath->query('//item');", id="xpath"),
        pytest.param("$this->xpath->query('//item');", id="xpath-property"),
        pytest.param("$this->domXPath->query($id);", id="domxpath-property"),
        pytest.param("$this->client->query('{ invoices { id } }');", id="graphql-client"),
        pytest.param("$this->request->query('id');", id="request"),
        pytest.param("$response->baseRequest->query('id');", id="request-property"),
        pytest.param("$this->urlGenerator->query('acme/invoices');", id="url-generator"),
        pytest.param("$this->getConnection()->query($sql);", id="connection-getter"),
        pytest.param("DB::connection()->getPdo()->query($sql);", id="facade-pdo"),
        pytest.param("(new PDO($dsn))->query($sql);", id="new-pdo"),
        pytest.param("$pdo?->query($sql);", id="nullsafe"),
        pytest.param("$this?->db?->query($sql);", id="nullsafe-property"),
        pytest.param("$pdo -> query($sql);", id="spaced-arrow"),
    ],
)
def test_every_query_method_is_a_sql_sink(statement: str) -> None:
    assert "sql_exec" in _kinds(statement)
    assert "sql_exec" in _streamed_kinds(statement)


def test_a_cakephp_console_test_exec_is_a_sql_and_process_sink() -> None:
    prelude = "use Cake\\Console\\TestSuite\\ConsoleIntegrationTestTrait;\n"

    assert {"sql_exec", "process_exec"} <= _kinds("$this->exec('cache clear_all');", prelude=prelude)


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("$ids = array_map(fn ($r) => $extract($r), $data);", id="closure-variable"),
        pytest.param('$sql = "SELECT EXTRACT(month FROM created_at) FROM invoices";', id="sql-string"),
        pytest.param("$this->extract($data);", id="method"),
        pytest.param("Acme\\Support\\extract($data);", id="namespaced-function"),
    ],
)
def test_an_extract_lookalike_is_not_mass_assignment(statement: str) -> None:
    assert "mass_assignment" not in _kinds(statement)


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("extract($data);", id="bare"),
        pytest.param("\\extract($data);", id="qualified"),
        pytest.param("EXTRACT($data, EXTR_SKIP);", id="case-blind"),
    ],
)
def test_the_extract_builtin_is_mass_assignment_on_both_readers(statement: str) -> None:
    assert "mass_assignment" in _kinds(statement)
    assert "mass_assignment" in _streamed_kinds(statement)


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param("System($id);", "process_exec", id="system-title"),
        pytest.param("SYSTEM($id);", "process_exec", id="system-upper"),
        pytest.param("Shell_Exec($id);", "process_exec", id="shell-exec"),
        pytest.param("Passthru($id);", "process_exec", id="passthru"),
        pytest.param("ECHO $id;", "xss_output", id="echo"),
        pytest.param('Header("Location: " . $id);', "redirect", id="header"),
        pytest.param("MySQLi_Query($q, $id);", "sql_exec", id="mysqli-query"),
        pytest.param("Unserialize($data);", "deserialization", id="unserialize"),
        pytest.param("Eval($data);", "eval_exec", id="eval"),
        pytest.param("File_Get_Contents($path);", "file_path", id="file-get-contents"),
        pytest.param("Move_Uploaded_File($path, $id);", "file_path", id="move-uploaded-file"),
    ],
)
def test_php_function_names_are_case_blind_on_both_readers(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)
    assert kind in _streamed_kinds(statement)


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param('$données->prepare("SELECT * FROM acme WHERE id = $id");', "sql_exec", id="prepare"),
        pytest.param("Auth::vérifier($id);", "auth", id="auth-facade"),
    ],
)
def test_a_non_ascii_php_identifier_is_read_on_both_readers(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)
    assert kind in _streamed_kinds(statement)


def test_only_ascii_letters_fold_in_a_php_function_name() -> None:
    assert "process_exec" not in _kinds("ſystem($id);")


def test_a_php_variable_name_stays_case_sensitive_on_both_readers() -> None:
    assert "auth" in _kinds("$_SESSION['id'] = $id;")
    assert "auth" not in _kinds("$_session['id'] = $id;")
    assert "auth" not in _streamed_kinds("$_session['id'] = $id;")
