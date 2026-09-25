"""PHP and Blade reachability signals: callables, entry points, taint sources.

The deterministic index decides which of thousands of files an agent opens
first, and `code_files.analysis_priority` is dominated by
`entry_point_proximity` (15 for a direct entry point, 10 one hop, 5 two hops).
A file with sinks but no source and no entry point scores 0 and sorts last.
These tests cover the three signals that let the index say "user input reaches
here" for a PHP/Laravel repository -- entry points, taint sources, and
callables -- and deliberately not the sink catalogue, which an agent can
reproduce with one `rg`.

Every fixture is reconstructed from real Laravel/Symfony source (BookStack's
`routes/web.php`, `SearchController`, and `entities/tag-manager.blade.php`
shapes), not contorted to make a pattern fire.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.code_languages import (
    STRUCTURAL_SUPPORTED_LANGUAGES,
    canonical_backend_language,
    detect_language,
)
from assess.lib.treesitter_index import index_file, language_for_file


def _index(source: str, file_path: str, language: str) -> dict:
    return index_file(file_path, language, source=source.encode("utf-8"))


def _tree_sitter(source: str, file_path: str) -> dict:
    result = _index(source, file_path, "php")
    assert result["analysis_mode"] == "tree_sitter", (
        f"{file_path} degraded to {result['analysis_mode']} "
        f"({result.get('degradation_reason')}) -- the fixture must parse cleanly"
    )
    return result


def _line_of(needle: str, source: str) -> int:
    matches = [
        number for number, line in enumerate(source.splitlines(), 1) if needle in line
    ]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _kinds(records: list[dict]) -> set[str]:
    return {record["kind"] for record in records}


# ---------------------------------------------------------------------------
# 1. Closures and arrow functions are callables
# ---------------------------------------------------------------------------

PHP_CLOSURES_SRC = """\
<?php

$formatter = function (string $raw) {
    return system($raw);
};

$slug = fn(string $title) => shell_exec($title);

class ExportController
{
    public function export(): string
    {
        $render = function (string $template) {
            return eval($template);
        };

        return $render('x');
    }
}
"""


def test_a_top_level_closure_is_a_callable_with_a_scanned_body() -> None:
    """`_FUNCTION_QUERIES["php"]` names only `function_definition` and
    `method_declaration`, so both top-level callables above used to vanish and
    their bodies were scanned by nothing. `_CALLABLE_NODE_TYPES["php"]` already
    listed `anonymous_function`/`arrow_function`, but that table only serves
    the registration walk.
    """
    result = _tree_sitter(PHP_CLOSURES_SRC, "app/Support/helpers.php")

    by_name = {func["name"]: func for func in result["functions"]}
    assert "$formatter" in by_name
    assert "$slug" in by_name
    assert by_name["$formatter"]["params"] == ["string $raw"]
    assert by_name["$slug"]["params"] == ["string $title"]

    sinks = {(sink["kind"], sink["function"]) for sink in result["security_sinks"]}
    assert ("process_exec", "$formatter") in sinks
    assert ("process_exec", "$slug") in sinks


def test_a_closure_nested_in_a_method_keeps_its_own_identity() -> None:
    """A closure inside a method is reported as its own callable as well as
    through its enclosing method -- the same double attribution
    `_extract_javascript_callables` already produces for a JS function
    expression, which is what makes the inner scope addressable.
    """
    result = _tree_sitter(PHP_CLOSURES_SRC, "app/Exports/ExportController.php")

    assert "$render" in {func["name"] for func in result["functions"]}
    assert {
        sink["function"] for sink in result["security_sinks"] if sink["kind"] == "eval_exec"
    } == {"export", "$render"}


def test_an_unnamed_closure_is_addressed_by_position() -> None:
    source = """\
<?php

array_map(function ($row) {
    return system($row);
}, $rows);
"""
    result = _tree_sitter(source, "app/Support/rows.php")

    names = [func["name"] for func in result["functions"]]
    assert names == ["<anonymous@3:10>"], names


# From laravel/framework's tests/Routing/RoutingUrlGeneratorTest.php, which
# writes this shape 27 times.
PHP_ARRAY_CLOSURE_SRC = """\
<?php

$route = new Route(['GET'], 'bar/{tenant}', ['as' => 'bar', fn () => '']);
$handlers = ['show' => function () { return 1; }];

class Registry
{
    public $callback = function () { return 2; };
}
"""


def test_a_closure_in_an_array_is_named_by_its_key_or_by_position() -> None:
    """A positional array element is not a keyed one.

    tree-sitter hands out a fresh Node object per access, so identity
    comparison between a parent's child and the node being named silently
    fails and a positional `fn () => ''` named ITSELF -- producing
    `"fn () => "`, whose trailing space `code-index sync` rejects for the
    whole repository. Only a two-child (key, value) element names its value.
    """
    result = _tree_sitter(PHP_ARRAY_CLOSURE_SRC, "tests/RoutingUrlGeneratorTest.php")

    assert [func["name"] for func in result["functions"]] == [
        "<anonymous@3:60>",
        "show",
        "$callback",
    ]
    for func in result["functions"]:
        for field in ("name", "qualified_name"):
            assert func[field] and func[field] == func[field].strip()


def test_a_closure_is_not_reported_as_an_exported_public_method() -> None:
    """`_detect_exports` treats a modifier-less PHP callable as a public
    method. A closure has no visibility modifier and is not a class member, so
    admitting it would put `$formatter` into the public API of the file.
    """
    result = _tree_sitter(PHP_CLOSURES_SRC, "app/Support/helpers.php")

    assert [export["name"] for export in result["exports"]] == ["export"]


# ---------------------------------------------------------------------------
# 2. Route files register entry points
# ---------------------------------------------------------------------------

# Reconstructed from BookStack's routes/web.php: top-level registrations plus
# a `Route::middleware(...)->group(function () { ... })` block, which is how a
# real Laravel route file nests the majority of its routes.
PHP_LARAVEL_ROUTE_FILE_SRC = """\
<?php

use Illuminate\\Support\\Facades\\Route;

Route::get('/status', [StatusController::class, 'show']);
Route::post('/search', [SearchController::class, 'searchEntities']);

Route::middleware('auth')->group(function () {
    Route::get('/books/{slug}', [BookController::class, 'show']);
    Route::delete('/books/{slug}', [BookController::class, 'destroy']);
});
"""

PHP_SLIM_ROUTE_FILE_SRC = """\
<?php

use Slim\\App;

$app->get('/users/{id}', function ($request, $response) {
    return $response->withJson($request->getQueryParams());
});

$router->post('/widgets', [WidgetController::class, 'store']);
"""


def test_a_laravel_route_file_registers_its_top_level_routes() -> None:
    """`_ENTRY_LINE_PATTERNS["php"]` already carried `Route::\\w+\\s*\\(`, but
    `_detect_entry_points` only scans a function's own span, and a route file
    has no enclosing function. `_GLOBAL_ENTRY_LINE_PATTERNS` is the mechanism
    that reads top-level statements; it had no `php` key.
    """
    result = _tree_sitter(PHP_LARAVEL_ROUTE_FILE_SRC, "routes/web.php")

    assert _kinds(result["entry_points"]) == {"laravel_route"}
    lines = {entry["line"] for entry in result["entry_points"]}
    assert _line_of("'/status'", PHP_LARAVEL_ROUTE_FILE_SRC) in lines
    assert _line_of("'/search'", PHP_LARAVEL_ROUTE_FILE_SRC) in lines
    assert _line_of("Route::middleware", PHP_LARAVEL_ROUTE_FILE_SRC) in lines


def test_a_slim_route_file_registers_both_registrar_styles() -> None:
    result = _tree_sitter(PHP_SLIM_ROUTE_FILE_SRC, "routes/slim.php")

    assert _kinds(result["entry_points"]) == {"slim_route", "framework_route"}


def test_a_route_registration_is_reported_once_for_its_own_handler() -> None:
    """The closure is the better record -- it names the handler and bounds a
    scan scope -- so the top-level pass must not add a second, nameless entry
    point for the same registration statement.
    """
    source = """\
<?php

Route::get('/run', function () {
    return system($_GET['cmd']);
});
"""
    result = _tree_sitter(source, "routes/web.php")

    assert [
        (entry["name"], entry["kind"]) for entry in result["entry_points"]
    ] == [("<anonymous@3:19>", "laravel_route")]


def test_a_route_file_is_no_longer_an_unmeasured_scope() -> None:
    """The honest-instrument path reported `degraded` /
    `unscanned_function_scope` for every route file, because no detector had a
    scope to read. With the closure callable and the top-level registration
    both measured, the same file is a real, complete measurement.
    """
    result = _tree_sitter(PHP_LARAVEL_ROUTE_FILE_SRC, "routes/web.php")

    assert result["analysis_status"] == "complete"
    assert result["unavailable_dimensions"] == []


def test_a_route_file_of_pure_controller_references_still_measures_its_entries() -> None:
    """A route registration with no closure is still a measured file scope."""
    source = """\
<?php

Route::get('/status', [StatusController::class, 'show']);
"""
    result = _tree_sitter(source, "routes/api.php")

    assert result["entry_points"]
    assert result["unavailable_dimensions"] == []


# ---------------------------------------------------------------------------
# 3. Framework request accessors are taint sources
# ---------------------------------------------------------------------------

# Reconstructed from BookStack's SearchController::search.
PHP_LARAVEL_CONTROLLER_SRC = """\
<?php

namespace BookStack\\Search;

use Illuminate\\Http\\Request;

class SearchController extends Controller
{
    public function search(Request $request, SearchResultsFormatter $formatter)
    {
        $page = intval($request->input('page', '0')) ?: 1;
        $term = $request->query('term');
        $all = $request->all();
        $filters = request()->get('filters');
        $upload = $this->request->file('avatar');

        return view('search.all', ['term' => $term, 'page' => $page]);
    }
}
"""

PHP_SYMFONY_CONTROLLER_SRC = """\
<?php

namespace App\\Controller;

use Symfony\\Component\\HttpFoundation\\Request;

class ProfileController
{
    public function update(Request $request): Response
    {
        $name = $request->request->get('name');
        $page = $request->query->getInt('page');
        $agent = $request->headers->get('User-Agent');
        $body = $request->getContent();
        $legacy = Input::get('legacy');

        return new Response($name . $page . $agent . $body . $legacy);
    }
}
"""


def test_an_injected_request_object_is_a_taint_source() -> None:
    """`_STREAM_SOURCE_PATTERNS["php"]` covered superglobals only. Idiomatic
    Laravel never touches one, so every controller had sinks with no source --
    no taint path to schedule and nothing to justify the file's rank.
    """
    result = _tree_sitter(
        PHP_LARAVEL_CONTROLLER_SRC, "app/Search/SearchController.php"
    )

    lines = {
        source["line"]
        for source in result["security_sources"]
        if source["kind"] == "http_request_input"
    }
    for needle in (
        "$request->input('page'",
        "$request->query('term')",
        "$request->all()",
        "request()->get('filters')",
        "$this->request->file('avatar')",
    ):
        assert _line_of(needle, PHP_LARAVEL_CONTROLLER_SRC) in lines, needle


def test_symfony_parameter_bags_and_the_input_facade_are_taint_sources() -> None:
    result = _tree_sitter(
        PHP_SYMFONY_CONTROLLER_SRC, "src/Controller/ProfileController.php"
    )

    lines = {
        source["line"]
        for source in result["security_sources"]
        if source["kind"] == "http_request_input"
    }
    for needle in (
        "$request->request->get('name')",
        "$request->query->getInt('page')",
        "$request->headers->get('User-Agent')",
        "$request->getContent()",
        "Input::get('legacy')",
    ):
        assert _line_of(needle, PHP_SYMFONY_CONTROLLER_SRC) in lines, needle


def test_a_request_typed_parameter_alone_is_not_a_source() -> None:
    """The signature declares where the object comes from; only a read off it
    is an input. Treating the declaration as a source would mark every
    controller action whether or not it touches the request.
    """
    source = """\
<?php

class PingController
{
    public function ping(Request $request): string
    {
        return 'pong';
    }
}
"""
    result = _tree_sitter(source, "app/Http/Controllers/PingController.php")

    assert result["security_sources"] == []


# ---------------------------------------------------------------------------
# 4. The deserialization entry surface
# ---------------------------------------------------------------------------

PHP_MAGIC_SURFACE_SRC = """\
<?php

class CacheEntry
{
    public function __wakeup()
    {
        $this->reconnect();
    }

    public function __unserialize(array $data): void
    {
        $this->path = $data['path'];
    }

    public function __serialize(): array
    {
        return ['path' => $this->path];
    }

    public function __sleep()
    {
        return ['path'];
    }

    public function __destruct()
    {
        unlink($this->path);
    }

    public function __toString(): string
    {
        return file_get_contents($this->path);
    }

    public function __invoke($argument)
    {
        return $this->render($argument);
    }

    public function __call($name, $arguments)
    {
        return $this->forward($name, $arguments);
    }

    public function __get($name)
    {
        return $this->attributes[$name];
    }

    public function __set($name, $value)
    {
        $this->attributes[$name] = $value;
    }
}
"""


@pytest.mark.parametrize(
    ("method", "kind"),
    [
        ("__wakeup", "deserialization_hook"),
        ("__unserialize", "deserialization_hook"),
        ("__serialize", "serialization_hook"),
        ("__sleep", "serialization_hook"),
        ("__destruct", "destructor"),
        ("__toString", "string_conversion_hook"),
        ("__invoke", "invocation_hook"),
        ("__call", "magic_call_hook"),
        ("__get", "property_read_hook"),
        ("__set", "property_write_hook"),
    ],
)
def test_a_php_magic_method_is_a_deserialization_entry_point(
    method: str, kind: str
) -> None:
    """These are where an attacker-controlled `unserialize()` lands. Matching
    is name equality per function: there is deliberately no chain following,
    because cross-class gadget chaining is liveness analysis.
    """
    result = _tree_sitter(PHP_MAGIC_SURFACE_SRC, "app/Cache/CacheEntry.php")

    line = _line_of(f"public function {method}(", PHP_MAGIC_SURFACE_SRC)
    assert [
        entry["kind"] for entry in result["entry_points"] if entry["line"] == line
    ] == [kind]


# ---------------------------------------------------------------------------
# 5. Blade
# ---------------------------------------------------------------------------

# Reconstructed from BookStack's resources/views/entities/tag-manager.blade.php,
# including the multi-line `{!! ... !!}` shape real translation calls use.
BLADE_TEMPLATE_SRC = """\
@extends('layouts.simple')

@section('body')
    <p class="text-muted small">
        {!! nl2br(e(trans('entities.tags_explain'))) !!} <br>
        <a href="{{ url('/tags') }}">{{ trans('entities.tags_view_existing') }}</a>
    </p>

    {!! trans('entities.meta_owned_name', [
        'user' => $ownerLink,
    ]) !!}

    {{-- {{ $notAnEcho }} is a Blade comment --}}
    <span>@{{ vueBinding }}</span>

    <form action="/tags/save" method="POST">
        @include('entities.tag-manager-list', ['tags' => $entity->tags])
    </form>
@stop

@yield('footer')
"""


def test_a_blade_template_is_its_own_language() -> None:
    """`Path("profile.blade.php").suffix` is `.php`, so Blade resolved to the
    PHP grammar, which reads every directive as inline text. A compound-suffix
    rule has to run before the single-suffix lookup.
    """
    for name in ("profile.blade.php", "resources/views/home/default.blade.php"):
        assert detect_language(name) == "blade"
        assert language_for_file(name) == "blade"
    assert detect_language("index.php") == "php"
    assert canonical_backend_language("blade") == "blade"
    assert "blade" in STRUCTURAL_SUPPORTED_LANGUAGES
    assert "blade" in treesitter_index.LIGHTWEIGHT_LANGUAGES


def test_the_raw_echo_is_distinguished_from_the_escaped_echo() -> None:
    """`{!! !!}` is the unescaped construct and the XSS-relevant one; `{{ }}`
    runs through `e()`. Reporting both the same way is the whole reason Blade
    needs an extractor rather than the PHP grammar.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    raw = [
        sink for sink in result["security_sinks"] if sink["kind"] == "unescaped_output"
    ]
    escaped = [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "template_interpolation"
    ]
    assert {sink["line"] for sink in raw} == {
        _line_of("nl2br(e(trans", BLADE_TEMPLATE_SRC),
        _line_of("{!! trans('entities.meta_owned_name'", BLADE_TEMPLATE_SRC),
    }
    assert {sink["escape_observation"] for sink in raw} == {
        "unverified_no_escape_observed"
    }
    assert all(sink["vuln_classes"] == ["xss"] for sink in raw)
    assert {sink["line"] for sink in escaped} == {
        _line_of("<a href=", BLADE_TEMPLATE_SRC)
    }
    assert {sink["escape_observation"] for sink in escaped} == {
        "unverified_escape_observed"
    }


def test_blade_reuses_the_shared_escape_observation_vocabulary() -> None:
    """One vocabulary for "what escaping did we see", not a second one per
    template language -- a reader who learned it on FreeMarker reads it here.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    observed = {
        sink["escape_observation"]
        for sink in result["security_sinks"]
        if "escape_observation" in sink
    }
    assert observed
    assert observed <= set(treesitter_index.FREEMARKER_ESCAPE_OBSERVATIONS)


def test_a_blade_comment_and_an_at_escaped_brace_are_not_echoes() -> None:
    """Both halves of the construct scan, not just the sink half.

    `_BLADE_CONSTRUCT_RE` gets this right -- one ordered alternation in which
    the comment form wins over the echo forms it can contain, plus a `(?<!@)`
    for Blade's own escape. The taint-source path used to carry a second,
    weaker regex whose `(?!--)` only rejected a match *starting* at the
    comment's `{{`: the engine advanced two characters and matched the inner
    braces, so a commented-out echo and a Vue binding both reported as
    `template_input`. Reading sinks alone could not see it.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    comment_line = _line_of("is a Blade comment", BLADE_TEMPLATE_SRC)
    escaped_line = _line_of("@{{ vueBinding }}", BLADE_TEMPLATE_SRC)
    for dimension in ("security_sinks", "security_sources"):
        reported = {record["line"] for record in result[dimension]}
        assert comment_line not in reported, (dimension, result[dimension])
        assert escaped_line not in reported, (dimension, result[dimension])


def test_every_blade_taint_source_is_an_echo_the_construct_scan_found() -> None:
    """One reading of "what is a Blade echo", shared by both dimensions.

    The sources are derived from the same scan as the sinks rather than from a
    parallel regex, so the two cannot drift: every `template_input` line is a
    line that also carries an echo sink.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    echo_lines = sorted(
        sink["line"]
        for sink in result["security_sinks"]
        if sink["kind"] in ("template_interpolation", "unescaped_output")
    )
    assert echo_lines
    assert sorted(
        source["line"] for source in result["security_sources"]
    ) == echo_lines
    assert {source["kind"] for source in result["security_sources"]} == {
        "template_input"
    }


def test_blade_composition_directives_are_template_imports() -> None:
    """`@extends`/`@include` are the edges of the view graph: which template
    pulls in which. Without them a Blade file has no outbound edge at all.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    assert "layouts.simple" in result["imports"]
    assert "entities.tag-manager-list" in result["imports"]
    assert {target["raw"] for target in result["import_targets"]} >= {
        "layouts.simple",
        "entities.tag-manager-list",
    }


def test_blade_named_slots_are_exports() -> None:
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    assert {(export["name"], export["kind"]) for export in result["exports"]} == {
        ("body", "blade_section"),
        ("footer", "blade_yield"),
    }


def test_a_blade_form_is_an_entry_point() -> None:
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    assert [
        (entry["kind"], entry["annotation"]) for entry in result["entry_points"]
    ] == [("html_form", "/tags/save")]


def test_a_blade_template_is_a_measured_file() -> None:
    """Handed to the PHP grammar a Blade template produced nothing and was
    honestly reported `degraded`/`unscanned_function_scope`. Its own extractor
    is a whole-file line reader, so nothing there depends on finding a callable.
    """
    result = _index(BLADE_TEMPLATE_SRC, "resources/views/tag-manager.blade.php", "blade")

    assert result["analysis_mode"] == "lightweight_regex"
    assert result["analysis_status"] == "complete"
    assert result["unavailable_dimensions"] == []
    assert {source["kind"] for source in result["security_sources"]} == {
        "template_input"
    }


def test_the_blade_streaming_fallback_covers_every_signal_dimension() -> None:
    """`_attach_bounded_security_sources` routes even the lightweight path's
    sources through the streaming tables, so a language missing from them
    cannot be indexed at all -- and the degraded path would report nothing
    rather than reporting a gap.
    """
    observed = treesitter_index._fallback_from_bytes(
        "resources/views/tag-manager.blade.php",
        "blade",
        BLADE_TEMPLATE_SRC.encode("utf-8"),
        degradation_reason="forced_for_test",
    )

    assert set(observed["unavailable_dimensions"]) == set(
        treesitter_index.STREAMING_FALLBACK_BASELINE_UNAVAILABLE
    )
    assert observed["security_sources"]
    assert observed["security_sinks"]
    assert observed["entry_points"]
    assert observed["imports"]
