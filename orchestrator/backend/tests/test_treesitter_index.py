"""Tests for tree-sitter structural indexing — Go, Ruby, PHP language support
plus structural enrichment (exports, import targets, passes_caller_params)."""
from __future__ import annotations

import re
import sys
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "agent" / "scripts"))

from assess.lib.treesitter_index import (
    SUPPORTED_LANGUAGES,
    _TS_AVAILABLE,
    _resolve_import_targets,
    index_file,
    language_for_file,
)

needs_treesitter = pytest.mark.skipif(
    not _TS_AVAILABLE,
    reason="tree-sitter not installed in this environment",
)

_PARSER_DISTRIBUTIONS = {
    "tree-sitter",
    "tree-sitter-c",
    "tree-sitter-c-sharp",
    "tree-sitter-cpp",
    "tree-sitter-go",
    "tree-sitter-java",
    "tree-sitter-javascript",
    "tree-sitter-php",
    "tree-sitter-python",
    "tree-sitter-ruby",
    "tree-sitter-typescript",
}


# ---------------------------------------------------------------------------
# language_for_file
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,expected", [
    ("main.go", "go"),
    ("app.rb", "ruby"),
    ("index.php", "php"),
    ("main.py", "python"),
    ("util.java", "java"),
    ("native.hh", "cpp"),
    ("module.mjs", "javascript"),
    ("legacy.cjs", "javascript"),
    ("config.mts", "typescript"),
    ("legacy.cts", "typescript"),
    # Lightweight (regex-based) extractors are now first-class languages.
    ("style.css", "css"),
    ("theme.scss", "css"),
    ("deploy.sh", "shell"),
    ("hook.bash", "shell"),
    ("script.lua", "lua"),
    ("index.html", "html"),
    ("page.htm", "html"),
    ("card.tpl", "html"),
    ("themes/base/login/login.ftl", "freemarker"),
    ("page.ftlh", "freemarker"),
    ("feed.ftlx", "freemarker"),
    # Compound suffix: `Path(...).suffix` only ever returns `.php`, so this
    # rule has to run before the single-suffix table or every Blade template
    # is handed to the PHP grammar.
    ("resources/views/home/default.blade.php", "blade"),
    ("profile.Blade.PHP", "blade"),
    ("index.php", "php"),
    # Dockerfiles are matched by basename, not extension.
    ("Dockerfile", "dockerfile"),
    ("Dockerfile.prod", "dockerfile"),
    ("path/to/Dockerfile", "dockerfile"),
    # Genuinely unsupported.
    ("notes.txt", None),
    ("data.json", None),
])
def test_language_for_file(filename, expected):
    assert language_for_file(filename) == expected


def test_supported_languages_includes_new():
    for lang in ("go", "ruby", "php"):
        assert lang in SUPPORTED_LANGUAGES


def test_supported_languages_includes_lightweight():
    for lang in ("blade", "dockerfile", "shell", "lua", "html", "css", "freemarker"):
        assert lang in SUPPORTED_LANGUAGES


def test_assess_parser_dependencies_match_ci_versions():
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    assess_script = (repo_root / "agent" / "scripts" / "assess.py").read_text()
    production_pins = dict(
        re.findall(r'^#\s+"(tree-sitter[^"=<>]*)==([^"=<>]+)",$', assess_script, re.M)
    )
    backend_config = tomllib.loads(
        (repo_root / "orchestrator" / "backend" / "pyproject.toml").read_text()
    )
    backend_pins = dict(
        dependency.split("==", 1)
        for dependency in backend_config["project"]["optional-dependencies"]["dev"]
        if dependency.startswith("tree-sitter")
    )

    assert set(production_pins) == _PARSER_DISTRIBUTIONS
    assert backend_pins == production_pins
    assert production_pins == {
        distribution: version(distribution)
        for distribution in sorted(_PARSER_DISTRIBUTIONS)
    }


# ---------------------------------------------------------------------------
# Go indexing
# ---------------------------------------------------------------------------

GO_SOURCE = b"""\
package main

import (
    "fmt"
    "net/http"
)

type Server struct {
    addr string
}

func (s *Server) Start() {
    http.HandleFunc("/", s.handler)
    http.ListenAndServe(s.addr, nil)
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "hello")
}

func main() {
    s := &Server{addr: ":8080"}
    s.Start()
}
"""


@needs_treesitter
def test_go_functions():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    assert idx["language"] == "go"
    names = {f["name"] for f in idx["functions"]}
    assert "Start" in names
    assert "handler" in names
    assert "main" in names
    assert idx["total_functions"] >= 3


@needs_treesitter
def test_go_entry_points():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    ep_names = {e["name"] for e in idx["entry_points"]}
    assert "main" in ep_names


@needs_treesitter
def test_go_sinks():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    sink_kinds = {s["kind"] for s in idx["security_sinks"]}
    assert sink_kinds == {"xss_output"}


@needs_treesitter
def test_exact_python_index_detects_security_sources_with_real_tree_sitter():
    source = b"def handler(request):\n    return request.args['name']\n"
    idx = index_file("handler.py", "python", source=source)

    assert idx["analysis_mode"] == "tree_sitter"
    assert idx["analysis_status"] == "complete"
    assert idx["signal_counts"]["security_sources"] == 1
    assert idx["security_sources"][0]["line"] == 2


@needs_treesitter
def test_go_exports():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    export_names = {e["name"] for e in idx.get("exports", [])}
    assert "Start" in export_names
    assert "Server" in export_names


@needs_treesitter
def test_go_classes():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    class_names = {c["name"] for c in idx["classes"]}
    assert "Server" in class_names


GO_IMPORT_FORMS_SOURCE = b"""\
package main

import "fmt"

import (
    "net/http"
    mux "github.com/gorilla/mux"
    _ "github.com/lib/pq"
    . "math"
    "./relative"
)
"""


@needs_treesitter
def test_go_imports():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    assert idx["imports"] == ["fmt", "net/http"]


@needs_treesitter
def test_go_imports_keep_the_path_of_aliased_and_blank_specs():
    """An import path is the spec's quoted path, not the spec minus a quote.

    A named `import_spec` (`mux "..."`, the blank `_ "..."` driver-registration
    idiom, or a dot import) has no leading quote, so trimming quotes off the
    whole spec leaves the alias welded to the path. Consumers match these
    values against declared modules, and a welded token matches nothing —
    a referenced package reported as unreferenced on a file the index calls
    complete.
    """
    idx = index_file("imports.go", "go", source=GO_IMPORT_FORMS_SOURCE)

    # `./relative` is a filesystem-relative path, not a module: still dropped.
    assert idx["imports"] == [
        "fmt",
        "net/http",
        "github.com/gorilla/mux",
        "github.com/lib/pq",
        "math",
    ]


# ---------------------------------------------------------------------------
# C++ declarations
# ---------------------------------------------------------------------------

CPP_HEADER_SOURCE = b"""\
extern "C" {
size_t sample_write_data_cb(void *ptr, size_t size);
size_t sample_read_data_cb(void *ptr, size_t size);
}

class SampleClient {
public:
    class Exception {
    public:
        Exception(const char* message) {}
        Exception(int error) {}
    };

    SampleClient(const char* url);
    ~SampleClient();
    const char* fetch();
    const char* post(const char* data);
    const char* put(const char* data);
    bool isHTTPError() const;
    size_t append_data(void* ptr, size_t size);
    size_t upload_data(void* ptr, size_t size);

private:
    SampleClient(const SampleClient&);
    void setOptions();
    void setHTTPHeaders() const;
    void curlPerform();
};
"""


@needs_treesitter
def test_cpp_header_indexes_function_and_method_declarations():
    idx = index_file("sample_client.h", "cpp", source=CPP_HEADER_SOURCE)
    functions = idx["functions"]
    names = [function["name"] for function in functions]

    assert set(names) == {
        "sample_write_data_cb",
        "sample_read_data_cb",
        "Exception",
        "SampleClient",
        "~SampleClient",
        "fetch",
        "post",
        "put",
        "isHTTPError",
        "append_data",
        "upload_data",
        "setOptions",
        "setHTTPHeaders",
        "curlPerform",
    }
    assert names.count("Exception") == 2
    assert names.count("SampleClient") == 2
    assert len(functions) == 16
    assert {
        function["qualified_name"]
        for function in functions
        if function["name"] in {"fetch", "~SampleClient", "setHTTPHeaders"}
    } == {
        "SampleClient.fetch",
        "SampleClient.~SampleClient",
        "SampleClient.setHTTPHeaders",
    }


@needs_treesitter
def test_cpp_declarations_do_not_turn_calls_or_function_pointers_into_functions():
    source = b"""\
int declared(int value);
int (*function_pointer)(int);

class Service {
public:
    void method();
    void (*callback)(int);
    int inline_method(int value) { return declared(value); }
};

int defined(int value) {
    Service service;
    service.method();
    return declared(value);
}
"""
    idx = index_file("service.hpp", "cpp", source=source)

    assert [function["name"] for function in idx["functions"]] == [
        "declared",
        "method",
        "inline_method",
        "defined",
    ]
    assert [function["qualified_name"] for function in idx["functions"]] == [
        "declared",
        "Service.method",
        "Service.inline_method",
        "defined",
    ]


@needs_treesitter
def test_cpp_declarations_preserve_overloads_and_prefer_matching_definitions():
    source = b"""\
class Left {
public:
    class Worker {
    public:
        void inspect(int value);
        void inspect(const char* value);
    };
};

class Right {
public:
    class Worker {
    public:
        void inspect(int value);
    };
};

int evaluate(int value);
int evaluate(int value) {
    return value;
}
"""
    idx = index_file("overloads.hpp", "cpp", source=source)
    functions = idx["functions"]

    inspections = [function for function in functions if function["name"] == "inspect"]
    assert [function["qualified_name"] for function in inspections] == [
        "Left.Worker.inspect",
        "Left.Worker.inspect",
        "Right.Worker.inspect",
    ]
    assert [function["params"] for function in inspections] == [
        ["int value"],
        ["const char* value"],
        ["int value"],
    ]

    evaluations = [function for function in functions if function["name"] == "evaluate"]
    assert len(evaluations) == 1
    assert evaluations[0]["is_declaration"] is False
    assert evaluations[0]["line_start"] == 19
    assert evaluations[0]["line_end"] == 21


@needs_treesitter
def test_cpp_declarator_walk_distinguishes_callable_and_pointer_objects():
    source = b"""\
int *returns_pointer(int value);
int (*pointer_object)(int value);
int (*factory())(double value);
int first() { return 1; } int second() { return 2; }
int alpha(), beta(int value);
"""
    idx = index_file("declarators.hpp", "cpp", source=source)

    assert [function["name"] for function in idx["functions"]] == [
        "returns_pointer",
        "factory",
        "first",
        "second",
        "alpha",
        "beta",
    ]


@needs_treesitter
def test_cpp_dedup_keeps_distinct_conditional_definitions():
    source = b"""\
#if USE_FIRST
int branch(int value) { return first(value); }
#else
int branch(int value) { return second(value); }
#endif
"""
    idx = index_file("conditional.cpp", "cpp", source=source)

    branches = [function for function in idx["functions"] if function["name"] == "branch"]
    assert [function["line_start"] for function in branches] == [2, 4]
    assert {call["callee"] for call in idx["call_sites"]} == {"first", "second"}


@needs_treesitter
def test_cpp_namespace_prototypes_retain_qualified_identity():
    source = b"""\
namespace left { int parse(int value); }
namespace right { int parse(int value); }
namespace outer::inner { int nested(); }
"""
    idx = index_file("namespaces.hpp", "cpp", source=source)

    assert [function["qualified_name"] for function in idx["functions"]] == [
        "left.parse",
        "right.parse",
        "outer.inner.nested",
    ]


@needs_treesitter
def test_cpp_conversion_and_operator_declarations_are_indexed():
    source = b"""\
class Value {
public:
    operator bool() const;
    operator const char*() const;
    explicit operator std::string() const;
    Value& operator=(const Value& other);
    int operator()(int value) const;
    int operator[](int index) const;
    friend Value operator+(const Value& left, const Value& right);
};
"""
    idx = index_file("operators.hpp", "cpp", source=source)

    assert [function["qualified_name"] for function in idx["functions"]] == [
        "Value.operator bool",
        "Value.operator const char*",
        "Value.operator std::string",
        "Value.operator=",
        "Value.operator()",
        "Value.operator[]",
        "operator+",
    ]
    assert all(function["is_declaration"] for function in idx["functions"])
    assert idx["call_sites"] == []


@needs_treesitter
def test_cpp_friend_operator_matches_its_namespace_definition():
    source = b"""\
namespace math {
class Value {
public:
    friend Value operator+(const Value& left, const Value& right);
};

Value operator+(const Value& lhs, const Value& rhs) {
    return lhs;
}
}
"""
    idx = index_file("friend_operator.cpp", "cpp", source=source)
    additions = [
        function for function in idx["functions"] if function["name"] == "operator+"
    ]

    assert len(additions) == 1
    assert additions[0]["qualified_name"] == "math.operator+"
    assert additions[0]["is_declaration"] is False
    assert additions[0]["line_start"] == 7


@needs_treesitter
def test_cpp_definitions_keep_canonical_leaf_and_dotted_identity():
    source = b"""\
namespace alpha {
class Value {
public:
    Value();
    ~Value();
    void run();
    Value& operator+=(const Value& other);
    operator bool() const;
    operator const char *() const;
    int operator()(int value) const;
};

Value::Value() {}
Value::~Value() {}
void Value::run() {}
Value& Value::operator+=(const Value& rhs) { return *this; }
Value::operator bool() const { return true; }
Value::operator const char*() const { return nullptr; }
int Value::operator()(int input) const { return input; }
}
"""
    idx = index_file("canonical_symbols.cpp", "cpp", source=source)

    assert [function["name"] for function in idx["functions"]] == [
        "Value",
        "~Value",
        "run",
        "operator+=",
        "operator bool",
        "operator const char*",
        "operator()",
    ]
    assert [function["qualified_name"] for function in idx["functions"]] == [
        "alpha.Value.Value",
        "alpha.Value.~Value",
        "alpha.Value.run",
        "alpha.Value.operator+=",
        "alpha.Value.operator bool",
        "alpha.Value.operator const char*",
        "alpha.Value.operator()",
    ]
    assert all(not function["is_declaration"] for function in idx["functions"])


@needs_treesitter
def test_cpp_signature_text_does_not_create_calls_or_sinks():
    source = b"""\
class Value {
public:
    ~Value();
    int operator()(int value) const;
};

Value::~Value() {}
int Value::operator()(int input) const { return input; }
void system(const char* command) {}
"""
    idx = index_file("signature_only.cpp", "cpp", source=source)

    assert idx["call_sites"] == []
    assert idx["security_sinks"] == []


@needs_treesitter
def test_cpp_same_line_body_calls_and_sinks_remain_visible():
    source = b"""\
void wrapper(const char* command) { system(command); }
"""
    idx = index_file("same_line_body.cpp", "cpp", source=source)

    assert idx["call_sites"] == [{
        "caller": "wrapper",
        "callee": "system",
        "line": 1,
        "passes_caller_params": True,
    }]
    assert [sink["kind"] for sink in idx["security_sinks"]] == ["process_exec"]
    assert idx["security_sinks"][0]["function"] == "wrapper"
    assert idx["security_sinks"][0]["line"] == 1


@needs_treesitter
def test_cpp_constructor_initializer_calls_and_sinks_remain_visible():
    source = b"""\
class Widget {
public:
    Widget(const char* command);
private:
    int member;
    int status;
};

Widget::Widget(const char* command)
    : member(transform(command)), status(system(command)) {}
"""
    idx = index_file("constructor_initializer.cpp", "cpp", source=source)

    assert {call["callee"] for call in idx["call_sites"]} == {"transform", "system"}
    assert all(call["passes_caller_params"] for call in idx["call_sites"])
    assert not {"Widget", "member", "status"} & {
        call["callee"] for call in idx["call_sites"]
    }
    assert [sink["kind"] for sink in idx["security_sinks"]] == ["process_exec"]
    assert idx["security_sinks"][0]["line"] == 10


# ---------------------------------------------------------------------------
# Ruby indexing
# ---------------------------------------------------------------------------

RUBY_SOURCE = b"""\
require 'sinatra'
require_relative 'helpers/auth'

class UserController < ApplicationController
  def index
    @users = User.all
    render json: @users
  end

  def create
    system(params[:cmd])
    redirect_to users_path
  end
end

def main_helper(input)
  eval(input)
end

if __FILE__ == $0
  puts "running"
end
"""


@needs_treesitter
def test_ruby_functions():
    idx = index_file("app.rb", "ruby", source=RUBY_SOURCE)
    assert idx["language"] == "ruby"
    names = {f["name"] for f in idx["functions"]}
    assert "index" in names
    assert "create" in names
    assert "main_helper" in names


@needs_treesitter
def test_ruby_classes():
    idx = index_file("app.rb", "ruby", source=RUBY_SOURCE)
    class_names = {c["name"] for c in idx["classes"]}
    assert "UserController" in class_names
    user_ctrl = next(c for c in idx["classes"] if c["name"] == "UserController")
    assert user_ctrl["extends"] == "ApplicationController"


@needs_treesitter
def test_ruby_imports():
    idx = index_file("app.rb", "ruby", source=RUBY_SOURCE)
    assert "sinatra" in idx["imports"]
    assert "helpers/auth" in idx["imports"]


@needs_treesitter
def test_ruby_sinks():
    idx = index_file("app.rb", "ruby", source=RUBY_SOURCE)
    sink_kinds = {s["kind"] for s in idx["security_sinks"]}
    assert "process_exec" in sink_kinds
    assert "eval_exec" in sink_kinds


@needs_treesitter
def test_ruby_entry_points():
    idx = index_file("app.rb", "ruby", source=RUBY_SOURCE)
    main_guards = [
        entry for entry in idx["entry_points"] if entry["kind"] == "main_guard"
    ]
    assert main_guards == [{
        "name": "<top-level>",
        "line": 20,
        "kind": "main_guard",
        "annotation": "",
    }]
    assert not any(entry["name"] == "main_helper" for entry in main_guards)


@needs_treesitter
def test_ruby_nested_main_guard_is_not_a_top_level_entry_point():
    source = b"""\
def helper
if __FILE__ == $0
puts "inside method"
end
end

class Runner
if $PROGRAM_NAME == __FILE__
puts "inside class"
end
end

runner = proc do
if __FILE__ == $0
puts "inside deferred block"
end
end

1.times do
if $PROGRAM_NAME == __FILE__
puts "inside iteration block"
end
end
"""
    idx = index_file("nested_guard.rb", "ruby", source=source)

    assert not any(
        entry["kind"] == "main_guard" for entry in idx["entry_points"]
    )


# ---------------------------------------------------------------------------
# PHP indexing
# ---------------------------------------------------------------------------

PHP_SOURCE = b"""\
<?php
namespace App\\Controllers;

use App\\Models\\User;
use Illuminate\\Http\\Request;

class UserController extends Controller implements AuthenticateInterface {
    public function index(Request $request) {
        $users = User::all();
        return response()->json($users);
    }

    public function execute(Request $request) {
        $cmd = $request->input('cmd');
        exec($cmd);
    }

    private function helper($data) {
        $result = unserialize($data);
        return $result;
    }
}

function standalone_func($input) {
    eval($input);
}
"""


@needs_treesitter
def test_php_functions():
    idx = index_file("app.php", "php", source=PHP_SOURCE)
    assert idx["language"] == "php"
    names = {f["name"] for f in idx["functions"]}
    assert "index" in names
    assert "execute" in names
    assert "helper" in names
    assert "standalone_func" in names


@needs_treesitter
def test_php_classes():
    idx = index_file("app.php", "php", source=PHP_SOURCE)
    class_names = {c["name"] for c in idx["classes"]}
    assert "UserController" in class_names


@needs_treesitter
def test_php_sinks():
    idx = index_file("app.php", "php", source=PHP_SOURCE)
    sink_kinds = {s["kind"] for s in idx["security_sinks"]}
    assert "process_exec" in sink_kinds
    assert "eval_exec" in sink_kinds or "deserialization" in sink_kinds


@needs_treesitter
def test_php_entry_points():
    idx = index_file("app.php", "php", source=PHP_SOURCE)
    # The fixture explicitly extends a Controller base; its public actions
    # are candidate request handlers, while its private helper is not.
    assert {(entry["name"], entry["kind"]) for entry in idx["entry_points"]} == {
        ("index", "laravel_action"),
        ("execute", "laravel_action"),
    }


# ---------------------------------------------------------------------------
# Structural enrichment (all languages)
# ---------------------------------------------------------------------------

JS_EXPORT_SOURCE = b"""\
export function publicFunc() {
    return 1;
}

export default function mainHandler() {
    return 2;
}

function privateHelper() {
    return 3;
}

export { privateHelper as helper };
"""


@needs_treesitter
def test_js_exports():
    idx = index_file("mod.js", "javascript", source=JS_EXPORT_SOURCE)
    export_names = {e["name"] for e in idx.get("exports", [])}
    assert "publicFunc" in export_names
    assert "mainHandler" in export_names


TSX_COMPONENT_SOURCE = b"""\
import { useEffect, useState } from "react";

export function DemoCard() {
    const [open, setOpen] = useState(false);

    useEffect(() => {
        const handleVisibilityChange = () => setOpen(false);
        document.addEventListener("visibilitychange", handleVisibilityChange);
        return () => document.removeEventListener("visibilitychange", handleVisibilityChange);
    }, []);

    return <button onClick={() => setOpen((current) => !current)}>{open ? "open" : "closed"}</button>;
}
"""


@needs_treesitter
def test_tsx_component_functions_are_indexed():
    idx = index_file("component.tsx", "typescript", source=TSX_COMPONENT_SOURCE)
    function_names = {f["name"] for f in idx["functions"]}
    assert "DemoCard" in function_names
    assert "handleVisibilityChange" in function_names


TS_ASYNC_AND_TIMER_SOURCE = b"""\
export function scheduleRefresh(runTask: () => void) {
    const refreshPage = useEffectEvent(async () => {
        await Promise.resolve(runTask());
    });
    window.setTimeout(() => refreshPage(), 250);
    window.setTimeout("refreshPage()", 250);
}
"""


@needs_treesitter
def test_typescript_call_sites_ignore_async_keyword():
    idx = index_file("timers.ts", "typescript", source=TS_ASYNC_AND_TIMER_SOURCE)
    callees = {call["callee"] for call in idx["call_sites"]}
    assert "async" not in callees
    assert "useEffectEvent" in callees
    assert "Promise.resolve" in callees


@needs_treesitter
def test_typescript_eval_sink_requires_string_timer_callback():
    idx = index_file("timers.ts", "typescript", source=TS_ASYNC_AND_TIMER_SOURCE)
    eval_sinks = [sink for sink in idx["security_sinks"] if sink["kind"] == "eval_exec"]
    assert len(eval_sinks) == 1
    assert eval_sinks[0]["line"] == 6
    assert "setTimeout(\"refreshPage()\"" in eval_sinks[0]["snippet"]


PYTHON_EXPORT_SOURCE = b"""\
__all__ = ['public_func', 'MyClass']

def public_func():
    pass

def _private_func():
    pass

class MyClass:
    pass
"""


@needs_treesitter
def test_python_exports_with_all():
    idx = index_file("mod.py", "python", source=PYTHON_EXPORT_SOURCE)
    export_names = {e["name"] for e in idx.get("exports", [])}
    assert "public_func" in export_names
    assert "MyClass" in export_names
    assert "_private_func" not in export_names


def test_import_targets_python():
    imports = ["from os.path import join", "import sys"]
    targets = _resolve_import_targets(imports, "python")
    resolved = {t["resolved"] for t in targets}
    assert "os/path.py" in resolved
    assert "sys.py" in resolved


def test_import_targets_go():
    imports = ["fmt", "net/http"]
    targets = _resolve_import_targets(imports, "go")
    resolved = {t["resolved"] for t in targets}
    assert "fmt" in resolved
    assert "net/http" in resolved


def test_import_targets_ruby():
    imports = ["sinatra", "helpers/auth"]
    targets = _resolve_import_targets(imports, "ruby")
    resolved = {t["resolved"] for t in targets}
    assert "sinatra" in resolved
    assert "helpers/auth.rb" in resolved


@needs_treesitter
def test_passes_caller_params():
    source = b"""\
def process(user_input, size):
    validate(user_input)
    result = transform(42)
    return result
"""
    idx = index_file("test.py", "python", source=source)
    calls = idx["call_sites"]
    validate_call = next((c for c in calls if c["callee"] == "validate"), None)
    transform_call = next((c for c in calls if c["callee"] == "transform"), None)

    if validate_call:
        assert validate_call["passes_caller_params"] is True
    if transform_call:
        assert transform_call["passes_caller_params"] is False


@needs_treesitter
def test_index_file_has_exports_and_import_targets():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    assert "exports" in idx
    assert "import_targets" in idx
    assert isinstance(idx["exports"], list)
    assert isinstance(idx["import_targets"], list)


def test_empty_index_has_exports_and_import_targets():
    idx = index_file("unknown.xyz", "unknown")
    assert idx["exports"] == []
    assert idx["import_targets"] == []


# ---------------------------------------------------------------------------
# Lightweight regex extractors (Dockerfile / shell / Lua / HTML / CSS)
#
# These run regardless of tree-sitter availability, so no needs_treesitter
# marker. They assert the security-relevant sinks each extractor is meant to
# surface and the common index shape downstream consumers rely on.
# ---------------------------------------------------------------------------

def _sink_kinds(idx) -> set[str]:
    return {s["kind"] for s in idx["security_sinks"]}


def test_lightweight_index_common_shape():
    idx = index_file("deploy.sh", "shell", source=b"#!/bin/bash\necho hi\n")
    for key in (
        "file_path", "language", "total_functions", "total_lines",
        "functions", "entry_points", "security_sinks", "call_sites",
        "imports", "import_targets", "exports", "classes",
    ):
        assert key in idx, f"lightweight index missing {key}"
    assert idx["language"] == "shell"


def test_dockerfile_extractor_flags_root_and_remote_pipe():
    source = b"""\
FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh | sh
USER root
ENV API_KEY=supersecret
EXPOSE 8080
CMD ["/bin/app"]
"""
    idx = index_file("Dockerfile", "dockerfile", source=source)
    kinds = _sink_kinds(idx)
    assert "container_runs_as_root" in kinds
    assert "remote_pipe_to_shell" in kinds
    assert "embedded_secret_env" in kinds
    assert "exposed_port" in kinds
    # CMD is an entry point and the base image is an import.
    assert any(e["kind"] == "container_cmd" for e in idx["entry_points"])
    assert "ubuntu:22.04" in idx["imports"]


def test_dockerfile_extractor_flags_missing_user_directive():
    source = b"FROM alpine:3.19\nRUN echo hello\n"
    idx = index_file("Dockerfile", "dockerfile", source=source)
    assert "missing_user_directive" in _sink_kinds(idx)


def test_shell_extractor_functions_and_sinks():
    source = b"""\
#!/bin/bash
deploy() {
    eval "$1"
    curl https://x/y | bash
}
"""
    idx = index_file("deploy.sh", "shell", source=source)
    kinds = _sink_kinds(idx)
    assert "shell_eval" in kinds
    assert "remote_pipe_to_shell" in kinds
    assert any(f["name"] == "deploy" for f in idx["functions"])
    assert any(e["kind"] == "shell_script" for e in idx["entry_points"])


def test_lua_extractor_redis_and_exec_sinks():
    source = b"""\
local function handler(key)
    redis.call('SET', KEYS[1], ARGV[1])
    os.execute('rm -rf /tmp/x')
end
"""
    idx = index_file("script.lua", "lua", source=source)
    kinds = _sink_kinds(idx)
    # A fixed Redis command with a key from KEYS is script input, not command
    # injection. Only the process execution line is an injection sink here.
    assert kinds == {"os_execute"}
    assert any(item["kind"] == "script_argument" for item in idx["security_sources"])
    assert any(f["name"] == "handler" for f in idx["functions"])


def test_html_extractor_form_and_template_sinks():
    source = b"""\
<form action="/login" method="post"></form>
<div>{{ user.name }}</div>
<img src=x onerror="alert(1)">
"""
    idx = index_file("index.html", "html", source=source)
    kinds = _sink_kinds(idx)
    assert "template_interpolation" in kinds
    assert "inline_event_handler" in kinds
    assert any(e["kind"] == "html_form" for e in idx["entry_points"])


def test_two_callables_sharing_a_name_and_line_get_distinct_identities():
    """`code-index sync` keys a callable on (qualified_name, start, end).

    Minified and obfuscated sources reuse short names across scopes and put the
    whole program on one line, so two genuinely different functions collide on
    that tuple. The sync then refuses the WHOLE repository over one file -- it
    builds a single payload per repo -- so an obfuscated vendored script blocks
    every other file's structural metadata. Observed on DVWA's
    `vulnerabilities/javascript/source/high.js`, which is not `.min.js` and sits
    in no skipped directory.
    """
    source = b"function b(c,d){function h(j){return j}return h}function k(){function h(){return 1}return h}\n"
    idx = index_file("high.js", "javascript", source=source)

    named = [f for f in idx["functions"] if f["name"] == "h"]
    assert len(named) == 2, "both nested `h` callables are still extracted"

    identities = [
        (f["qualified_name"], f["line_start"], f["line_end"]) for f in idx["functions"]
    ]
    assert len(identities) == len(set(identities)), (
        f"callable identities must be unique within a file: {identities}"
    )
    # The authored name is preserved for citation; only the identity is qualified.
    assert {f["name"] for f in named} == {"h"}


def test_commented_out_html_markup_is_not_surface():
    """A comment is dead markup, so it must not register reachability.

    An HTML comment spans lines, so the per-line prefix test the other extractors
    use cannot see it. Before the mask, a commented-out form was an `html_form`
    entry point and a commented-out remote script was a supply-chain sink with a
    phantom import -- a reachability claim on code that never runs, feeding
    `entry_point_proximity`. Blade and FreeMarker delegate here and inherit it.
    """
    source = b"""\
<!-- <form action="/legacy" method="post"></form> -->
<!--
  <script src="http://cdn.evil.example/a.js"></script>
-->
<!-- old --> <form action="/live" method="post"></form>
<div data-note="a --> b"><form action="/tricky"></form></div>
"""
    idx = index_file("page.html", "html", source=source)

    actions = sorted(e.get("annotation", "") for e in idx["entry_points"] if e["kind"] == "html_form")
    assert actions == ["/live", "/tricky"], "commented-out forms must not register"
    # The mask preserves columns, so a real tag sharing a line with a closed
    # comment is still found, and a bare `-->` inside an attribute is not a close.
    assert "external_script_load" not in _sink_kinds(idx)
    assert idx["import_targets"] == []


def test_css_extractor_external_import_and_expression():
    source = b"""\
@import url('http://evil.example/x.css');
.x { width: expression(alert(1)); }
"""
    idx = index_file("style.css", "css", source=source)
    kinds = _sink_kinds(idx)
    assert "external_css_import" in kinds
    assert "css_expression" in kinds
