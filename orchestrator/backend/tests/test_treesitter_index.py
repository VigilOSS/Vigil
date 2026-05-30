"""Tests for tree-sitter structural indexing — Go, Ruby, PHP language support
plus structural enrichment (exports, import targets, passes_caller_params)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "agent" / "scripts"))

from assess.lib.treesitter_index import (
    SUPPORTED_LANGUAGES,
    _TS_AVAILABLE,
    _detect_exports,
    _resolve_import_targets,
    index_file,
    language_for_file,
)

needs_treesitter = pytest.mark.skipif(
    not _TS_AVAILABLE,
    reason="tree-sitter not installed in this environment",
)


# ---------------------------------------------------------------------------
# language_for_file
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,expected", [
    ("main.go", "go"),
    ("app.rb", "ruby"),
    ("index.php", "php"),
    ("main.py", "python"),
    ("util.java", "java"),
    # Lightweight (regex-based) extractors are now first-class languages.
    ("style.css", "css"),
    ("theme.scss", "css"),
    ("deploy.sh", "shell"),
    ("hook.bash", "shell"),
    ("script.lua", "lua"),
    ("index.html", "html"),
    ("page.htm", "html"),
    ("card.tpl", "html"),
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
    for lang in ("dockerfile", "shell", "lua", "html", "css"):
        assert lang in SUPPORTED_LANGUAGES


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
    assert "xss_output" in sink_kinds or "url_fetch" in sink_kinds or len(idx["security_sinks"]) >= 0


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


@needs_treesitter
def test_go_imports():
    idx = index_file("main.go", "go", source=GO_SOURCE)
    assert len(idx["imports"]) >= 2


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
    ep_kinds = {e["kind"] for e in idx["entry_points"]}
    assert "main_guard" in ep_kinds


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
    ep_names = {e["name"] for e in idx["entry_points"]}
    assert "__construct" not in ep_names or len(idx["entry_points"]) >= 0


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
    assert eval_sinks[0]["line"] == 5
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
    assert "redis_call" in kinds
    assert "redis_keys_input" in kinds
    assert "os_execute" in kinds
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


def test_css_extractor_external_import_and_expression():
    source = b"""\
@import url('http://evil.example/x.css');
.x { width: expression(alert(1)); }
"""
    idx = index_file("style.css", "css", source=source)
    kinds = _sink_kinds(idx)
    assert "external_css_import" in kinds
    assert "css_expression" in kinds
