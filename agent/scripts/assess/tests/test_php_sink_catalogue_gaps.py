"""PHP sinks idiomatic code reaches that the catalogue did not name, and misroutes.

Each statement sits on line 3 of a small Acme handler so a sink at that line
can only come from that statement. Some shapes are only safe to read off the
parse tree -- a backtick shell command, a callable chosen at run time, a
Guzzle client constructed by its imported short name -- and those are
detected there; the rest are catalogue rows the streaming fallback shares.
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
        pytest.param("$help = 'call $pdo->exec($sql) to run it';", id="single-quoted"),
        # PHP interpolates `$pdo->exec` here and renders `($sql) to run it`
        # verbatim: simple interpolation reaches a property, never a call.
        pytest.param('$help = "call $pdo->exec($sql) to run it";', id="double-quoted"),
        # `{$` is the interpolation; `{ $` is a brace in the text.
        pytest.param('$help = "see { $pdo->exec($sql) } for this";', id="brace-then-space"),
        pytest.param("$help = <<<'ACME'\ncall {$pdo->exec($sql)} to run it\nACME;", id="nowdoc"),
    ],
)
def test_a_sql_receiver_named_in_a_string_is_not_a_call(statement: str) -> None:
    assert "sql_exec" not in _kinds(statement)


@pytest.mark.parametrize(
    ("statement", "kinds"),
    [
        pytest.param('$out = "rows: {$pdo->exec($sql)}";',
                     {"sql_exec", "process_exec"}, id="braced-double-quoted"),
        pytest.param('echo "out: {$client->shell_exec($id)}";',
                     {"xss_output", "process_exec"}, id="braced-echo"),
        pytest.param('$out = "rows: {$pdo?->exec($sql)}";',
                     {"sql_exec", "process_exec"}, id="braced-nullsafe"),
        pytest.param('$out = "name: ${exec($id)}";',
                     {"process_exec"}, id="dollar-brace-variable-name"),
        # The inner literal is text inside code inside text: only the call
        # starting outside it is a call.
        pytest.param('$out = "nest {$pdo->exec("SELECT $id")} end";',
                     {"sql_exec", "process_exec"}, id="braced-nested-literal"),
    ],
)
def test_a_call_php_runs_inside_a_string_is_a_sink(statement: str, kinds: set[str]) -> None:
    """`{$...}` is a child expression the grammar resolves, not literal text.

    The quoted-span filter rejects a sink whose match starts inside a string
    literal because a line cannot tell a call from the text of one. PHP
    evaluates a braced interpolation, so the span it covers is code the file
    runs, and suppressing it loses the sink instead of a false positive.
    """
    assert kinds <= _kinds(statement)
    assert kinds <= _streamed_kinds(statement)


def test_a_call_php_runs_inside_a_heredoc_is_a_sink() -> None:
    source = b"""<?php
function acme_report($pdo, $sql) {
    return <<<ACME
rows: {$pdo->exec($sql)}
ACME;
}
"""

    indexed = index_file("src/acme.php", "php", source)

    assert {"sql_exec", "process_exec"} <= {
        sink["kind"] for sink in indexed["security_sinks"] if sink["line"] == 4
    }


def test_an_interpolated_call_spanning_lines_is_a_sink_at_its_own_line() -> None:
    """The literal covers each of its lines, and the call takes its own back."""
    source = b"""<?php
function acme_report($pdo, $sql) {
    return "rows: {$pdo->exec(
        $sql
    )} for $sql";
}
"""

    indexed = index_file("src/acme.php", "php", source)

    assert {(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]} == {
        ("sql_exec", 3), ("process_exec", 3)
    }


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


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param("mysql_query($q);", "sql_exec", id="mysql-query"),
        pytest.param("mysql_db_query('acme', $q);", "sql_exec", id="mysql-db-query"),
        pytest.param("mysql_unbuffered_query($q);", "sql_exec", id="mysql-unbuffered-query"),
        pytest.param("pg_query($client, $q);", "sql_exec", id="pg-query"),
        pytest.param("pg_query_params($client, $q, [$id]);", "sql_exec", id="pg-query-params"),
        pytest.param("pg_send_query($client, $q);", "sql_exec", id="pg-send-query"),
        pytest.param("mysqli_multi_query($client, $q);", "sql_exec", id="mysqli-multi-query"),
        pytest.param("mysqli_real_query($client, $q);", "sql_exec", id="mysqli-real-query"),
        pytest.param("$client->real_query($q);", "sql_exec", id="real-query-method"),
        pytest.param("odbc_exec($client, $q);", "sql_exec", id="odbc-exec"),
        pytest.param("sqlsrv_query($client, $q);", "sql_exec", id="sqlsrv-query"),
        pytest.param("mssql_query($q);", "sql_exec", id="mssql-query"),
        pytest.param("sqlite_query($client, $q);", "sql_exec", id="sqlite-query"),
        pytest.param("oci_parse($client, $q);", "sql_exec", id="oci-parse"),
        pytest.param("db2_exec($client, $q);", "sql_exec", id="db2-exec"),
        pytest.param("$client->Execute($q);", "sql_exec", id="adodb-execute"),
        pytest.param("print_r($data);", "xss_output", id="print-r"),
        pytest.param("vprintf($q, [$id]);", "xss_output", id="vprintf"),
        pytest.param("die($data);", "xss_output", id="die-variable"),
        pytest.param("exit('Acme: ' . $id);", "xss_output", id="exit-string"),
        pytest.param("parse_str($data);", "mass_assignment", id="parse-str-one-argument"),
        pytest.param("import_request_variables('gp');", "mass_assignment", id="import-request-variables"),
        pytest.param("$$fn = $data;", "mass_assignment", id="variable-variable"),
        pytest.param("$$clé = $data;", "mass_assignment", id="variable-variable-non-ascii"),
        pytest.param("mail($to, 'Acme', $data);", "process_exec", id="mail"),
        pytest.param("mail($to, 'Acme', $data, $q);", "process_exec", id="mail-headers"),
        pytest.param("mb_send_mail($to, 'Acme', $data, $q);", "process_exec", id="mb-send-mail"),
    ],
)
def test_legacy_php_sinks_are_detected_on_both_readers(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)
    assert kind in _streamed_kinds(statement)


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param("$stmt->execute([$id]);", "sql_exec", id="pdo-statement-execute"),
        pytest.param("die();", "xss_output", id="die-empty"),
        pytest.param("exit(1);", "xss_output", id="exit-status"),
        pytest.param("die('Acme: no direct access');", "xss_output", id="die-literal-message"),
        pytest.param('exit("Acme: done");', "xss_output", id="exit-literal-message"),
        pytest.param("parse_str($data, $out);", "mass_assignment", id="parse-str-into-array"),
        pytest.param("if ($$fn == $data) {}", "mass_assignment", id="variable-variable-comparison"),
        pytest.param("$this->mail($to);", "process_exec", id="mail-method"),
        pytest.param("$mail($to);", "process_exec", id="mail-variable"),
        pytest.param("$m = new Mail($id);", "process_exec", id="mail-class"),
    ],
)
def test_legacy_php_lookalikes_are_not_those_sinks_on_either_reader(statement: str, kind: str) -> None:
    assert kind not in _kinds(statement)
    assert kind not in _streamed_kinds(statement)


def test_a_line_of_unclosed_parse_str_calls_streams_in_linear_time() -> None:
    import time

    source = b"<?php " + b"parse_str(" * 80000 + b"\n"
    started = time.process_time()
    treesitter_index._fallback_from_bytes("legacy/acme.php", "php", source, degradation_reason="test")
    assert time.process_time() - started < 5


def test_a_short_echo_in_a_template_is_output_on_both_readers() -> None:
    source = b"""<?php $title = 'Acme'; ?>
<a href="<?= $_GET['u'] ?>">Acme</a>
"""
    indexed = index_file("views/link.php", "php", source)
    streamed = treesitter_index._fallback_from_bytes("views/link.php", "php", source, degradation_reason="test")

    for observed in (indexed, streamed):
        assert ("xss_output", 2) in {(sink["kind"], sink["line"]) for sink in observed["security_sinks"]}


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        pytest.param(b"$id = $HTTP_GET_VARS['id'];", "http_request_input", id="http-get-vars"),
        pytest.param(b"$id = $HTTP_POST_VARS['id'];", "http_request_input", id="http-post-vars"),
        pytest.param(b"$id = $HTTP_COOKIE_VARS['id'];", "http_request_input", id="http-cookie-vars"),
        pytest.param(b"$f = $HTTP_POST_FILES['upload'];", "http_request_input", id="http-post-files"),
        pytest.param(b"$ua = $HTTP_SERVER_VARS['HTTP_USER_AGENT'];", "http_request_input", id="http-server-vars"),
        pytest.param(b"$body = $HTTP_RAW_POST_DATA;", "http_request_input", id="http-raw-post-data"),
        pytest.param(b"$home = $_ENV['ACME_HOME'];", "process_input", id="env"),
    ],
)
def test_legacy_php_input_globals_are_sources_on_both_readers(line: bytes, kind: str) -> None:
    source = b"<?php\n" + line + b"\n"
    for observed in (
        index_file("legacy/acme.php", "php", source),
        treesitter_index._fallback_from_bytes("legacy/acme.php", "php", source, degradation_reason="test"),
    ):
        assert [(record["kind"], record["line"]) for record in observed["security_sources"]] == [(kind, 2)]


@pytest.mark.parametrize(
    ("statement", "kind"),
    [
        pytest.param("call_user_func('system', $_GET['c']);", "process_exec", id="call-user-func-system"),
        pytest.param("call_user_func_array('passthru', [$id]);", "process_exec", id="call-user-func-array-passthru"),
        pytest.param("array_walk($data, 'unserialize');", "deserialization", id="array-walk-unserialize"),
        pytest.param("array_map('assert', $data);", "eval_exec", id="array-map-assert"),
        pytest.param("array_map($_GET['f'], $data);", "dynamic_invocation", id="array-map"),
        pytest.param("array_filter($data, $fn);", "dynamic_invocation", id="array-filter"),
        pytest.param("array_walk($data, $fn);", "dynamic_invocation", id="array-walk"),
        pytest.param("usort($data, $fn);", "dynamic_invocation", id="usort"),
        pytest.param("uasort($data, $fn);", "dynamic_invocation", id="uasort"),
        pytest.param("uksort($data, $fn);", "dynamic_invocation", id="uksort"),
        pytest.param("preg_replace_callback('/acme/', $fn, $q);", "dynamic_invocation", id="preg-replace-callback"),
        pytest.param("register_shutdown_function($fn);", "dynamic_invocation", id="register-shutdown-function"),
        pytest.param("iterator_apply($data, $fn);", "dynamic_invocation", id="iterator-apply"),
        pytest.param("array_reduce($data, $fn, 0);", "dynamic_invocation", id="array-reduce"),
        pytest.param("array_walk_recursive($data, $fn);", "dynamic_invocation", id="array-walk-recursive"),
        pytest.param("spl_autoload_register($fn);", "dynamic_invocation", id="spl-autoload-register"),
        pytest.param("set_error_handler($fn);", "dynamic_invocation", id="set-error-handler"),
        pytest.param("set_exception_handler($fn);", "dynamic_invocation", id="set-exception-handler"),
        pytest.param("ob_start($fn);", "dynamic_invocation", id="ob-start"),
        pytest.param("preg_replace_callback_array($data, $q);", "dynamic_invocation", id="preg-replace-callback-array"),
        pytest.param(
            "preg_replace_callback_array(['/a/' => $fn], $q);",
            "dynamic_invocation",
            id="preg-replace-callback-array-value",
        ),
        pytest.param("ob_start('system');", "process_exec", id="ob-start-system"),
        pytest.param("array_map(array: $data, callback: 'system');", "process_exec", id="named-callback"),
        pytest.param("usort(callback: $fn, array: $data);", "dynamic_invocation", id="named-callback-first"),
    ],
)
def test_a_callback_builtin_hints_what_its_callback_runs(statement: str, kind: str) -> None:
    assert kind in _kinds(statement)


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("array_map('trim', $data);", id="literal-builtin"),
        pytest.param("array_filter($data);", id="no-callback"),
        pytest.param("usort($data, [$this, 'compare']);", id="literal-method"),
        pytest.param("array_map(fn ($v) => $v, $data);", id="arrow-function"),
        pytest.param("preg_replace_callback('/acme/', 'strtoupper', $q);", id="literal-function"),
        pytest.param("array_map(trim(...), $data);", id="first-class-function"),
        pytest.param("array_walk($data, $this->format(...));", id="first-class-method"),
        pytest.param("usort($data, Acme::compare(...));", id="first-class-static-method"),
        pytest.param("array_map(null, $data, $q);", id="null-callback"),
        pytest.param("set_error_handler(null);", id="null-handler"),
        pytest.param("array_map([$this, __FUNCTION__], $data);", id="magic-function-method"),
        pytest.param("array_map([$this, __METHOD__], $data);", id="magic-method-method"),
        pytest.param("ob_start();", id="no-output-callback"),
        pytest.param(
            "preg_replace_callback_array(['/a/' => fn ($m) => $m[0], '/b/' => 'strtoupper'], $q);",
            id="preg-replace-callback-array-literals",
        ),
    ],
)
def test_a_literal_callback_naming_no_sink_hints_nothing(statement: str) -> None:
    assert _kinds(statement) == set()
