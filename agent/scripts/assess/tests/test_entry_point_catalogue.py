"""Entry-point detection catalogue: annotations, method names, line patterns.

Covers the four entry-point tables in `assess.lib.treesitter_index` that this
suite owns: ``_ENTRY_ANNOTATIONS``, ``_ENTRY_METHOD_NAMES``,
``_ENTRY_LINE_PATTERNS`` and ``_GLOBAL_ENTRY_LINE_PATTERNS`` (79 entries
total). Every pattern is classified LIVE / DEAD / REDUNDANT / OBSOLETE /
MISROUTED by executing the real indexer against idiomatic 2026 fixtures; only
LIVE patterns get a positive test here (see the DEAD/MISROUTED allow-list on
the meta-test below for the rest, with reasons and file:line).

Mechanics this suite leans on (verified against the source, not assumed):

* ``_detect_entry_points`` only ever inspects a FUNCTION's own
  annotations/name/lines and the calls that function is an argument to. A
  class-level annotation (e.g. `@WebServlet`, which the Servlet spec restricts
  to `@Target(TYPE)`) is invisible on the structural path -- `_parse_class_node`
  never captures class annotations at all.
* The same `_ENTRY_ANNOTATIONS` / `_ENTRY_LINE_PATTERNS` tables are re-used,
  verbatim, by `StreamingSecurityScanner._entry_patterns`
  (treesitter_index.py:3421-3429) -- so a pattern that is DEAD on the
  structural path can still be LIVE on the streaming-fallback path that a
  real degraded parse (`giant_line_resource_limit`, `exact_parser_source_limit`,
  a syntax error, ...) genuinely reaches in production
  (`assess/lib/parser_boundary.py:294-303`).
* This module is under active, concurrent edit by other agents auditing the
  neighbouring `_SINK_DEFINITIONS` table in the same working tree. Two
  fixes landed mid-audit and are reflected below rather than in the
  now-stale form some of this suite's design notes originally assumed:
  PHP's `_parse_function_node` now captures `#[Attribute]` groups into
  `annotations` via `_php_attributes` (treesitter_index.py:1070-1083), and
  the streaming scanner's hash-comment rule became an explicit allowlist
  (`_HASH_COMMENT_LANGUAGES` / `_HASH_CODE_PREFIXES`, treesitter_index.py
  :3641-3645) that exempts `#[` for php the same way it always exempted
  `#!` for shell. `#[Route(...)]` is therefore LIVE on both paths now,
  not dead on either -- verified by execution against the current file,
  not assumed from the brief.
* Line patterns scan `func.line_start .. func.line_end` plus the first line of
  every call the function is an argument to (`_registering_call_lines`, which
  walks up to the enclosing `call_expression` and stops at the first callable
  it crosses). Concretely: (a) a wrapped `app.get(\\n "/x",\\n cb\\n)` -- what
  Prettier's 80-column default produces for most real routes -- is attributed
  to `cb`, because the walk does not care how many argument lines separate the
  two; (b) a route registration that names an already-defined handler instead
  of taking an inline callback is still never seen: what sits inside the
  registering call is a reference to the handler, not its declaration, so the
  walk up from that declaration finds nothing -- a gap, pinned below on both JS
  orderings; (c) a function merely stacked near a registration has no enclosing
  call and so can never inherit it, at any distance -- verified below on Go and
  JS, not merely inferred.
"""
from __future__ import annotations

import json

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import (
    STREAMING_SCAN_WINDOW_BYTES,
    index_file,
    streaming_security_fallback,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _line_of(needle: str, source: str) -> int:
    """Return the 1-based line carrying *needle* (which must be unique)."""
    lines = source.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _index(source: str, file_path: str, language: str) -> dict:
    result = index_file(file_path, language, source=source.encode("utf-8"))
    assert result["analysis_mode"] == "tree_sitter", (
        f"{file_path} degraded to {result['analysis_mode']} "
        f"({result.get('degradation_reason')}) -- fixture must parse cleanly "
        "or the test is silently exercising the streaming scanner instead."
    )
    return result


def _entries_at(result: dict, line: int) -> list[dict]:
    return [ep for ep in result["entry_points"] if ep["line"] == line]


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
# Fixtures -- one source blob per language/framework grouping, reused across
# several catalogue entries. Every fixture is real, idiomatic 2026 code for
# its framework; nothing here is contorted to make a bad pattern match.
# ---------------------------------------------------------------------------

# _ENTRY_ANNOTATIONS["java"] (Spring MVC + JAX-RS + @Scheduled)
JAVA_SPRING_SRC = """\
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable String id) {
        return service.find(id);
    }

    @PostMapping("/")
    public User createUser(@RequestBody User u) {
        return service.save(u);
    }

    @PutMapping("/{id}")
    public User updateUser(@PathVariable String id, @RequestBody User u) {
        return service.update(id, u);
    }

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable String id) {
        service.delete(id);
    }

    @PatchMapping("/{id}")
    public User patchUser(@PathVariable String id) {
        return service.patch(id);
    }

    @Scheduled(fixedRate = 5000)
    public void cleanupTask() {
        service.cleanup();
    }
}

class LegacyController {
    @RequestMapping(value = "/legacy", method = RequestMethod.GET)
    public String legacy() {
        return "ok";
    }
}
"""

# _ENTRY_ANNOTATIONS["java"]["@Path"] -- JAX-RS sub-resource method, the
# idiomatic way @Path appears at method scope (class-level @Path is also
# legal but, like @WebServlet, invisible to a function-scoped detector).
# @Path listed before @GET (annotation order is compiler-irrelevant in Java)
# so the method's line_start -- which tree-sitter anchors to the FIRST
# modifier/annotation -- lands on the line this test's needle expects.
JAVA_JAXRS_SRC = """\
@Path("/widgets")
public class WidgetResource {
    @Path("/{id}")
    @GET
    public Widget get(@PathParam("id") String id) {
        return store.find(id);
    }
}
"""

# _ENTRY_ANNOTATIONS["java"]["@WebServlet"] -- the Servlet spec restricts
# @WebServlet to @Target(TYPE): it can only ever appear on the class, never
# on a method. Proven DEAD on the structural path below; proven LIVE only on
# the streaming-fallback path, which the same tables also feed.
JAVA_WEBSERVLET_SRC = """\
@WebServlet("/legacy")
public class LegacyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.getWriter().write("hi");
    }
}
"""

# _ENTRY_METHOD_NAMES["java"] -- servlet overrides + main.
# `LegacyFilter implements Filter` is deliberately included and NOT in the
# LIVE table: `javax.servlet.Filter` is an interface, so no compilable Java
# class can ever write `extends Filter` -- only `implements Filter`. The
# extends-equality gate (treesitter_index.py:1467) only accepts `extends`,
# so doFilter/filter_override is DEAD, not merely narrow. Proven below.
JAVA_SERVLET_SRC = """\
class LegacyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.getWriter().write("hi");
    }
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    }
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) {
    }
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) {
    }
}

class LegacyFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
    }
}

class Main {
    public static void main(String[] args) {
        System.out.println("start");
    }
}

class NotAnEntry {
    void main(String[] args) {
        // package-private, non-static -- must NOT become a main_method
    }
}
"""

# Coverage-gap proof: a class extending a project base servlet (not exactly
# HttpServlet/Filter/GenericServlet) never gets its doGet recognised, because
# the extends-string equality check (treesitter_index.py:1467) is exact.
JAVA_BASE_SERVLET_SRC = """\
public class ProjectServlet extends HttpServlet {
}
public class MyServlet extends ProjectServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.getWriter().write("hi");
    }
}
"""

# _ENTRY_ANNOTATIONS["python"] -- Flask app + blueprint
PY_FLASK_SRC = """\
from flask import Flask, Blueprint

app = Flask(__name__)
blueprint = Blueprint("users", __name__)

@app.route("/legacy")
def legacy():
    return "hi"

@blueprint.route("/bp-route")
def bp_route():
    return "x"

if __name__ == "__main__":
    app.run()
"""

# _ENTRY_ANNOTATIONS["python"] -- FastAPI app + APIRouter + Celery task.
# `app.get`/`app.post` require the FastAPI instance literally named `app`
# (idiomatic FastAPI convention) -- a differently-named instance does not
# match, see the coverage-gap note in the final report.
PY_FASTAPI_SRC = """\
from fastapi import FastAPI, APIRouter
import celery

app = FastAPI()
router = APIRouter()

@app.get("/items")
def get_items():
    return []

@app.post("/items")
def create_item():
    return {}

@router.get("/router-items")
def router_get():
    return []

@router.delete("/router-items/{id}")
def router_delete(id):
    return {}

@celery.task
def background_job():
    pass
"""

# _ENTRY_ANNOTATIONS["python"]["@api_view"] -- Django REST Framework
PY_DRF_SRC = """\
from rest_framework.decorators import api_view

@api_view(["GET"])
def drf_view(request):
    return None
"""

# _ENTRY_METHOD_NAMES["go"] -- main + init (idiomatic: route registration
# split into a dedicated setupRoutes/registerXxx helper, not inlined into
# main -- main() already claims itself via the method-name check before
# line patterns are even consulted, so route calls placed directly in main
# would never independently exercise the line-pattern table).
GO_SRC = """\
package main

func init() {
	setup()
}

func main() {
	setupRoutes()
}
"""

# _ENTRY_LINE_PATTERNS["go"] line-pattern cases each get their OWN fixture,
# deliberately NOT combined into one file. When this audit was written,
# `_detect_entry_points` scanned three lines ABOVE each function "for
# decorators", and that window did not stop at the previous function's
# closing brace -- short registerXxx helpers stacked within 3 lines of each
# other corrupted one another's match, and mux_handler/gorilla_router
# silently turned into http_handler when the fixtures were combined. The
# window has since been replaced by a structural walk to the enclosing call
# (see test_a_registration_is_attributed_by_enclosing_call_not_proximity
# below, and GO_STACKED_REGISTRATION_SRC). The fixtures stay separate anyway:
# one registration per file is what each row is actually about, and a combined
# file would re-hide a regression behind whichever pattern matched first.
GO_HTTP_HANDLEFUNC_SRC = """\
package main

import "net/http"

func registerStdlib() {
	http.HandleFunc("/health", healthHandler)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {}
"""

GO_HTTP_HANDLE_SRC = """\
package main

import "net/http"

func registerLegacyHandle() {
	http.Handle("/metrics", metricsHandler)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {}
"""

GO_SERVEMUX_SRC = """\
package main

import "net/http"

func registerServeMux() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", usersHandler)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {}
"""

GO_GORILLA_SRC = """\
package main

import "github.com/gorilla/mux"

func registerGorilla() {
	r := mux.NewRouter()
	r.HandleFunc("/orders/{id}", ordersHandler)
}
"""

# _ENTRY_LINE_PATTERNS["go"]["framework_route"] (`\b(?:e|g|app)\.\w+\s*\(`)
# false-positive proof: ordinary, non-web Go code using the conventional
# short names for an errgroup and a loaded config -- no HTTP framework in
# sight, yet both functions get tagged framework_route.
GO_FALSE_POSITIVE_SRC = """\
package worker

import "golang.org/x/sync/errgroup"

func processAll(items []string) error {
	var g errgroup.Group
	for _, item := range items {
		item := item
		g.Go(func() error {
			return handle(item)
		})
	}
	return g.Wait()
}

func parseConfig(path string) (*Config, error) {
	app := &Config{}
	if e := app.Load(path); e != nil {
		return nil, e
	}
	return app, nil
}
"""

# _ENTRY_LINE_PATTERNS scan-scope regression guard. `metricsHandler` sits one
# line under `registerLegacyHandle`'s `http.Handle(...)` call and contains
# nothing that matches anything. Under the old three-line lookback it
# inherited the registration and was reported as an http_handler; a match is
# now attributed only to the function that contains it or to a callable the
# matching call itself receives, and `metricsHandler` is neither.
GO_STACKED_REGISTRATION_SRC = """\
package main

import "net/http"

func registerLegacyHandle() {
	http.Handle("/metrics", metricsHandler)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {}
"""

# _ENTRY_METHOD_NAMES["ruby"]["call"] -- a Rack app/middleware
RUBY_RACK_SRC = """\
class RackApp
  def call(env)
    [200, {}, ["hi"]]
  end
end
"""

# _ENTRY_LINE_PATTERNS["ruby"] MISROUTED proof: `\bdelete\s+['"/]` fires on
# an ordinary Hash#delete / params.delete call, never on a genuine Sinatra
# route (Sinatra's top-level `delete '/x' do ... end` block produces no
# tree-sitter "method" node at all -- proven separately below).
RUBY_DELETE_FALSE_POSITIVE_SRC = """\
class WidgetsController
  def destroy_all(params)
    params.delete "confirm"
  end
end
"""

# Sinatra route blocks are top-level DSL calls, not `def` methods -- proves
# get/post/put/delete never see a function node to scan in the first place.
RUBY_SINATRA_SRC = """\
get '/users' do
  "list users"
end

post '/users' do
  "create user"
end

put '/users/:id' do
  "update user"
end
"""

# _GLOBAL_ENTRY_LINE_PATTERNS["ruby"] -- main guards
RUBY_MAIN_GUARD_1_SRC = """\
def run
  puts "hi"
end

if __FILE__ == $0
  run
end
"""

RUBY_MAIN_GUARD_2_SRC = """\
def run
  puts "hi"
end

if $PROGRAM_NAME == __FILE__
  run
end
"""

# _ENTRY_METHOD_NAMES["php"] -- magic methods. Every one of them is invoked by
# the PHP runtime rather than by the application, which is what makes the set
# the landing surface for an attacker-controlled `unserialize()`.
PHP_MAGIC_METHODS_SRC = """\
<?php
class UserValueObject
{
    public function __construct(private string $id, private string $name)
    {
    }

    public function __destruct()
    {
        $this->cleanup();
    }

    public function __wakeup()
    {
        $this->reconnect();
    }

    public function __unserialize(array $data): void
    {
        $this->id = $data['id'];
    }

    public function __serialize(): array
    {
        return ['id' => $this->id];
    }

    public function __sleep()
    {
        return ['id'];
    }

    public function __toString(): string
    {
        return $this->name;
    }

    public function __invoke($argument)
    {
        return $this->render($argument);
    }

    public function __call($method, $arguments)
    {
        return $this->forward($method, $arguments);
    }

    public function __get($property)
    {
        return $this->attributes[$property];
    }

    public function __set($property, $value)
    {
        $this->attributes[$property] = $value;
    }
}
"""

# _ENTRY_LINE_PATTERNS["php"] -- registration inside a *named* method, the
# registrar/bootstrap-class idiom. The closure-based Slim 4 idiom reaches the
# same patterns through its own callable and is proven separately below.
# Each registrar method gets its own fixture (not one class with both
# methods) for the same reason as the Go fixtures above: under the old
# three-line lookback, registerRouter's window leaked `$app->get(...)` from
# the immediately preceding method and reported slim_route instead of its own
# framework_route -- confirmed while drafting this suite. The lookback is
# gone, and the fixtures stay split so each row proves its own pattern.
PHP_APP_REGISTRAR_SRC = """\
<?php
class RouteRegistrar
{
    public function registerApp($app)
    {
        $app->get('/users', [UserController::class, 'index']);
    }
}
"""

PHP_ROUTER_REGISTRAR_SRC = """\
<?php
class RouteRegistrar
{
    public function registerRouter($router)
    {
        $router->get('/widgets', [WidgetController::class, 'index']);
    }
}
"""

# LIVE on two independent mechanisms: the inline closure handler is a callable
# whose registering call (`Route::get(`) the function-scoped pattern reaches,
# and the controller-array registration below it is a direct program child the
# _GLOBAL_ENTRY_LINE_PATTERNS pass reads. Neither fired before PHP closures
# became callables and php gained a global-pattern key.
PHP_LARAVEL_ROUTES_SRC = """\
<?php

use Illuminate\\Support\\Facades\\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/users/{id}', [UserController::class, 'show']);
"""

# The Slim 4 `return function (App $app) {...}` routes.php idiom: the returned
# closure is the callable, and `$app->get(...)` inside its own body is what the
# function-scoped line pattern scans.
PHP_SLIM_CLOSURE_ROUTES_SRC = """\
<?php

use Slim\\App;

return function (App $app) {
    $app->get('/users/{id}', \\App\\Controller\\UserController::class . ':show');
};
"""

# _GLOBAL_ENTRY_LINE_PATTERNS["php"] -- a Slim/generic bootstrap that names
# already-defined controller actions, so no callable exists anywhere for the
# function-scoped pass and only the top-level statement scan can see it.
PHP_TOP_LEVEL_REGISTRAR_SRC = """\
<?php

$app->get('/users', [UserController::class, 'index']);
$router->post('/widgets', [WidgetController::class, 'store']);
"""

# _ENTRY_ANNOTATIONS["php"]["#[Route]"] -- a PHP 8 attribute route
# (Symfony/current-era Laminas style). LIVE on both the structural and
# streaming paths as of this audit (see the module-level note above).
PHP_ATTRIBUTE_ROUTE_SRC = """\
<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

class UserController
{
    #[Route('/users/{id}', methods: ['GET'])]
    public function show(string $id): Response
    {
        return new Response($id);
    }
}
"""

# _ENTRY_LINE_PATTERNS["c"] / ["cpp"] -- functions named after the handler
# convention match on their own definition line.
C_HANDLER_SRC = """\
static void signal_handler(int sig) {
    handle(sig);
}

void timer_callback(void *data) {
    tick();
}

int main(void) {
    return 0;
}
"""

CPP_HANDLER_SRC = """\
class Server {
public:
    void connection_handler(int fd) {
        accept(fd);
    }
    static void error_callback(int code, const char* msg) {
        report(code, msg);
    }
};

int main() {
    return 0;
}
"""

# _ENTRY_LINE_PATTERNS["javascript"] / ["typescript"] -- Express, inline
# callback style (the dominant idiom).
JS_EXPRESS_SRC = """\
const express = require('express');
const app = express();
const router = express.Router();

app.get('/users', (req, res) => {
  res.json([]);
});

app.post('/users', (req, res) => {
  res.status(201).end();
});

app.put('/users/:id', (req, res) => {
  res.sendStatus(204);
});

app.delete('/users/:id', (req, res) => {
  res.sendStatus(204);
});

router.get('/widgets', (req, res) => {
  res.json([]);
});

router.post('/widgets', (req, res) => {
  res.status(201).end();
});

router.put('/widgets/:id', (req, res) => {
  res.sendStatus(204);
});

router.delete('/widgets/:id', (req, res) => {
  res.sendStatus(204);
});

app.listen(3000);
"""

TS_EXPRESS_SRC = """\
import express from 'express';
const app = express();
const router = express.Router();

app.get('/users', (req, res) => {
  res.json([]);
});

app.post('/users', (req, res) => {
  res.status(201).end();
});

app.put('/users/:id', (req, res) => {
  res.sendStatus(204);
});

app.delete('/users/:id', (req, res) => {
  res.sendStatus(204);
});

router.get('/widgets', (req, res) => {
  res.json([]);
});

router.post('/widgets', (req, res) => {
  res.status(201).end();
});

router.put('/widgets/:id', (req, res) => {
  res.sendStatus(204);
});

router.delete('/widgets/:id', (req, res) => {
  res.sendStatus(204);
});

app.listen(3000);
"""

JS_EXPORTS_SRC = """\
function helper(x) {
  return x + 1;
}

export default function handler(req, res) {
  res.status(200).json({ ok: true });
}

module.exports = function legacyHandler(req, res) {
  res.end("legacy");
};
"""

# Coverage-gap proof: registering an already-defined handler by name (very
# common in real Express apps) produces zero entry points. What sits inside
# `app.get('/users', listUsers)` is a reference to the handler, not its
# declaration, so neither the declaration's own range nor the walk up from it
# reaches the registration line. Closing this needs name resolution, which is
# a different mechanism from the enclosing-call walk.
JS_NAMED_HANDLER_GAP_SRC = """\
const express = require('express');
const app = express();

function listUsers(req, res) {
  res.json([]);
}

app.get('/users', listUsers);

app.listen(3000);
"""

# The same gap written the other way round -- registration ABOVE the handler
# it names, within the old three-line lookback. This is the shape that made
# the lookback actively wrong rather than merely useless: `handleAdmin` used
# to be reported as an express_route on the strength of a line that is not in
# it, sending a hunter at a function whose entry-point status was never
# established. The answer is the same as JS_NAMED_HANDLER_GAP_SRC's -- a
# top-level registration naming an existing handler is a coverage gap, and a
# gap is reported as nothing, not as the wrong function.
JS_REGISTRATION_ABOVE_HANDLER_SRC = """\
const express = require('express');
const app = express();

app.get('/admin', handleAdmin);

function handleAdmin(req, res) {
  res.json({ ok: true });
}

module.exports = app;
"""

# The shape the removed lookback got RIGHT, and which its removal cost: once
# the path plus the handler exceeds 80 columns, Prettier's default wrap puts
# `app.get(` on a line no callback spans. All three wrapped forms below are
# ordinary Express, not edge cases, and each must be attributed to the callback
# the call receives -- which is also the only function in the file, so a match
# landing anywhere else would be visible.
JS_WRAPPED_ARROW_ROUTE_SRC = """\
const app = require("express")();

app.get(
  "/organisations/:orgId/members/:memberId",
  async (req, res) => {
    res.json({ id: req.params.memberId });
  }
);
"""

JS_WRAPPED_NAMED_ROUTE_SRC = """\
const app = require("express")();

app.get(
  "/organisations/:orgId/members/:memberId",
  function memberHandler(req, res) {
    res.json({ id: req.params.memberId });
  }
);
"""

JS_TRAILING_MIDDLEWARE_ROUTE_SRC = """\
const app = require("express")();

app.get("/organisations/:orgId/members/:memberId", requireAuth,
  (req, res) => {
    res.json({ id: req.params.memberId });
  }
);
"""

# A callback reached only THROUGH a wrapper call. `asyncHandler` is the
# standard express-async-handler idiom; the walk must pass through it rather
# than stopping at the first call it meets.
JS_ADAPTED_ROUTE_SRC = """\
const app = require("express")();

app.get(
  "/organisations/:orgId/members/:memberId",
  asyncHandler(async (req, res) => {
    res.json({ id: req.params.memberId });
  })
);
"""

# The boundary the walk must respect: `format` is a closure inside the
# registered callback. Nothing registers it, and reporting it as a route sends
# a hunter at code no request enters directly.
JS_NESTED_CLOSURE_ROUTE_SRC = """\
const app = require("express")();

app.get(
  "/organisations/:orgId/members/:memberId",
  (req, res) => {
    const format = (member) => member.id;
    res.json({ id: format(req.params) });
  }
);
"""


# ---------------------------------------------------------------------------
# Catalogue sweep -- one row per LIVE pattern. Every row names its table,
# language and the verbatim regex/method-name it is proving live, so drift
# in the meta-test below points straight back here.
# ---------------------------------------------------------------------------
# Fields: (table, language, pattern_or_name, fixture, file_path, needle,
#          expected_kind)

LIVE_CASES: list[tuple[str, str, str, str, str, str, str]] = [
    ("annotations", "csharp", r"\[Http(?:Get|Post|Put|Patch|Delete|Head|Options)\b",
     "public class FilesController : ControllerBase {\n    [HttpGet(\"{name}\")]\n    public string Read(string name) => name;\n}\n",
     "FilesController.cs", "[HttpGet", "aspnet_action"),
    # -- _ENTRY_ANNOTATIONS["java"] (8 of 9; @WebServlet is a dedicated test) --
    ("annotations", "java", r"@RequestMapping\b", JAVA_SPRING_SRC, "Legacy.java", "@RequestMapping(value", "spring_mapping"),
    ("annotations", "java", r"@GetMapping\b", JAVA_SPRING_SRC, "UserController.java", "@GetMapping", "spring_mapping"),
    ("annotations", "java", r"@PostMapping\b", JAVA_SPRING_SRC, "UserController.java", "@PostMapping", "spring_mapping"),
    ("annotations", "java", r"@PutMapping\b", JAVA_SPRING_SRC, "UserController.java", "@PutMapping", "spring_mapping"),
    ("annotations", "java", r"@DeleteMapping\b", JAVA_SPRING_SRC, "UserController.java", "@DeleteMapping", "spring_mapping"),
    ("annotations", "java", r"@PatchMapping\b", JAVA_SPRING_SRC, "UserController.java", "@PatchMapping", "spring_mapping"),
    ("annotations", "java", r"@Path\b", JAVA_JAXRS_SRC, "Widget.java", "@Path(\"/{id}\")", "jaxrs_annotation"),
    ("annotations", "java", r"@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
     '@Path("/health") class Health { @GET public String get() { return "ok"; } }',
     "Health.java", "@GET", "jaxrs_annotation"),
    ("annotations", "java", r"@Scheduled\b", JAVA_SPRING_SRC, "UserController.java", "@Scheduled", "scheduled_task"),
    ("line_patterns", "java", r"\bRouterFunctions\.route\s*\(",
     'class Routes { Object routes() { return RouterFunctions.route().GET("/", req -> req).build(); } }',
     "Routes.java", "RouterFunctions.route()", "spring_functional_route"),
    # -- _ENTRY_ANNOTATIONS["php"] (1 of 1) --
    ("annotations", "php", r"#\[Route\b", PHP_ATTRIBUTE_ROUTE_SRC, "UserController.php", "#[Route('/users/{id}'", "symfony_route"),
    # -- _ENTRY_ANNOTATIONS["python"] (7 of 7) --
    # Needles target the `def ...` line, not the decorator line above it:
    # for python (unlike java) `_parse_function_node`'s `start_line` comes
    # from the bare `function_definition` node, which excludes the
    # decorator -- confirmed by execution while drafting this suite (the
    # entry's "line" is one past where a decorator-line needle expects).
    ("annotations", "python", r"@app\.route\b", PY_FLASK_SRC, "flask_app.py", "def legacy():", "flask_route"),
    ("annotations", "python", r"@app\.get\b", PY_FASTAPI_SRC, "fastapi_app.py", "def get_items():", "fastapi_route"),
    ("annotations", "python", r"@app\.post\b", PY_FASTAPI_SRC, "fastapi_app.py", "def create_item():", "fastapi_route"),
    ("annotations", "python", r"@blueprint\.route\b", PY_FLASK_SRC, "flask_app.py", "def bp_route():", "flask_blueprint"),
    ("annotations", "python", r"@api_view\b", PY_DRF_SRC, "views.py", "def drf_view(request):", "drf_view"),
    ("annotations", "python", r"@router\.\w+\b", PY_FASTAPI_SRC, "fastapi_app.py", "def router_get():", "fastapi_router"),
    ("annotations", "python", r"@celery\.task\b", PY_FASTAPI_SRC, "fastapi_app.py", "def background_job():", "celery_task"),
    # -- _ENTRY_METHOD_NAMES["java"] (6 of 6) --
    ("method_names", "java", "doGet", JAVA_SERVLET_SRC, "Servlet.java", "protected void doGet", "servlet_override"),
    ("method_names", "java", "doPost", JAVA_SERVLET_SRC, "Servlet.java", "protected void doPost", "servlet_override"),
    ("method_names", "java", "doFilter", JAVA_SERVLET_SRC, "Servlet.java", "public void doFilter", "filter_override"),
    ("method_names", "java", "doPut", JAVA_SERVLET_SRC, "Servlet.java", "protected void doPut", "servlet_override"),
    ("method_names", "java", "doDelete", JAVA_SERVLET_SRC, "Servlet.java", "protected void doDelete", "servlet_override"),
    ("method_names", "java", "main", JAVA_SERVLET_SRC, "Servlet.java", "public static void main", "main_method"),
    # -- _ENTRY_METHOD_NAMES["go"] (2 of 2) --
    ("method_names", "go", "main", GO_SRC, "main.go", "func main() {", "main_function"),
    ("method_names", "go", "init", GO_SRC, "main.go", "func init() {", "init_function"),
    # -- _ENTRY_METHOD_NAMES["ruby"] (1 of 1) --
    ("method_names", "ruby", "call", RUBY_RACK_SRC, "rack_app.rb", "def call(env)", "rack_call"),
    # -- _ENTRY_METHOD_NAMES["php"] (10 of 11; __construct is MISROUTED) --
    ("method_names", "php", "__destruct", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __destruct", "destructor"),
    ("method_names", "php", "__wakeup", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __wakeup", "deserialization_hook"),
    ("method_names", "php", "__unserialize", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __unserialize", "deserialization_hook"),
    ("method_names", "php", "__serialize", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __serialize", "serialization_hook"),
    ("method_names", "php", "__sleep", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __sleep", "serialization_hook"),
    ("method_names", "php", "__toString", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __toString", "string_conversion_hook"),
    ("method_names", "php", "__invoke", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __invoke", "invocation_hook"),
    ("method_names", "php", "__call", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __call", "magic_call_hook"),
    ("method_names", "php", "__get", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __get", "property_read_hook"),
    ("method_names", "php", "__set", PHP_MAGIC_METHODS_SRC, "value_object.php", "public function __set", "property_write_hook"),
    # -- _ENTRY_LINE_PATTERNS["javascript"] (10 of 10) --
    ("line_patterns", "javascript", r"\bapp\.get\s*\(", JS_EXPRESS_SRC, "server.js", "app.get('/users'", "express_route"),
    ("line_patterns", "javascript", r"\bapp\.post\s*\(", JS_EXPRESS_SRC, "server.js", "app.post('/users'", "express_route"),
    ("line_patterns", "javascript", r"\bapp\.put\s*\(", JS_EXPRESS_SRC, "server.js", "app.put('/users/:id'", "express_route"),
    ("line_patterns", "javascript", r"\bapp\.delete\s*\(", JS_EXPRESS_SRC, "server.js", "app.delete('/users/:id'", "express_route"),
    ("line_patterns", "javascript", r"\brouter\.get\s*\(", JS_EXPRESS_SRC, "server.js", "router.get('/widgets'", "express_router"),
    ("line_patterns", "javascript", r"\brouter\.post\s*\(", JS_EXPRESS_SRC, "server.js", "router.post('/widgets'", "express_router"),
    ("line_patterns", "javascript", r"\brouter\.put\s*\(", JS_EXPRESS_SRC, "server.js", "router.put('/widgets/:id'", "express_router"),
    ("line_patterns", "javascript", r"\brouter\.delete\s*\(", JS_EXPRESS_SRC, "server.js", "router.delete('/widgets/:id'", "express_router"),
    ("line_patterns", "javascript", r"\bexport\s+default\s+function\b", JS_EXPORTS_SRC, "handler.js", "export default function handler", "default_export"),
    ("line_patterns", "javascript", r"\bmodule\.exports\b", JS_EXPORTS_SRC, "handler.js", "module.exports = function legacyHandler", "module_exports"),
    # -- _ENTRY_LINE_PATTERNS["typescript"] (10 of 10) --
    ("line_patterns", "typescript", r"\bapp\.get\s*\(", TS_EXPRESS_SRC, "server.ts", "app.get('/users'", "express_route"),
    ("line_patterns", "typescript", r"\bapp\.post\s*\(", TS_EXPRESS_SRC, "server.ts", "app.post('/users'", "express_route"),
    ("line_patterns", "typescript", r"\bapp\.put\s*\(", TS_EXPRESS_SRC, "server.ts", "app.put('/users/:id'", "express_route"),
    ("line_patterns", "typescript", r"\bapp\.delete\s*\(", TS_EXPRESS_SRC, "server.ts", "app.delete('/users/:id'", "express_route"),
    ("line_patterns", "typescript", r"\brouter\.get\s*\(", TS_EXPRESS_SRC, "server.ts", "router.get('/widgets'", "express_router"),
    ("line_patterns", "typescript", r"\brouter\.post\s*\(", TS_EXPRESS_SRC, "server.ts", "router.post('/widgets'", "express_router"),
    ("line_patterns", "typescript", r"\brouter\.put\s*\(", TS_EXPRESS_SRC, "server.ts", "router.put('/widgets/:id'", "express_router"),
    ("line_patterns", "typescript", r"\brouter\.delete\s*\(", TS_EXPRESS_SRC, "server.ts", "router.delete('/widgets/:id'", "express_router"),
    # export default function / module.exports are equally reachable via
    # the TS grammar (same extraction path); JS already proves the
    # mechanism, so they are intentionally not re-proven here -- see the
    # meta-test allow-list.
    # -- _ENTRY_LINE_PATTERNS["c"] (2 of 2) --
    ("line_patterns", "c", r"\b\w+_handler\s*\(", C_HANDLER_SRC, "handlers.c", "static void signal_handler", "handler_callback"),
    ("line_patterns", "c", r"\b\w+_callback\s*\(", C_HANDLER_SRC, "handlers.c", "void timer_callback", "handler_callback"),
    # -- _ENTRY_LINE_PATTERNS["cpp"] (2 of 2) --
    ("line_patterns", "cpp", r"\b\w+_handler\s*\(", CPP_HANDLER_SRC, "handlers.cpp", "void connection_handler", "handler_callback"),
    ("line_patterns", "cpp", r"\b\w+_callback\s*\(", CPP_HANDLER_SRC, "handlers.cpp", "static void error_callback", "handler_callback"),
    # -- _ENTRY_LINE_PATTERNS["go"] (4 of 5; e|g|app is MISROUTED) --
    # Needle targets each function's own signature line: entry_points["line"]
    # is func.line_start (the enclosing `func registerXxx() {` line), not the
    # line the matching call itself sits on inside the body.
    ("line_patterns", "go", r"\bhttp\.HandleFunc\s*\(", GO_HTTP_HANDLEFUNC_SRC, "http_handlefunc.go", "func registerStdlib() {", "http_handler"),
    ("line_patterns", "go", r"\bhttp\.Handle\s*\(", GO_HTTP_HANDLE_SRC, "http_handle.go", "func registerLegacyHandle() {", "http_handler"),
    ("line_patterns", "go", r"\bmux\.HandleFunc\s*\(", GO_SERVEMUX_SRC, "servemux.go", "func registerServeMux() {", "mux_handler"),
    ("line_patterns", "go", r"\br\.HandleFunc\s*\(", GO_GORILLA_SRC, "gorilla.go", "func registerGorilla() {", "gorilla_router"),
    # -- _ENTRY_LINE_PATTERNS["ruby"] (4 of 4) --
    ("line_patterns", "ruby", r"^\s*get\s+['\"/]", "get '/x' do\n 'ok'\nend\n", "app.rb", "get '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*post\s+['\"/]", "post '/x' do\n 'ok'\nend\n", "app.rb", "post '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*put\s+['\"/]", "put '/x' do\n 'ok'\nend\n", "app.rb", "put '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*patch\s+['\"/]", "patch '/x' do\n 'ok'\nend\n", "app.rb", "patch '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*delete\s+['\"/]", "delete '/x' do\n 'ok'\nend\n", "app.rb", "delete '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*options\s+['\"/]", "options '/x' do\n 'ok'\nend\n", "app.rb", "options '/x' do", "sinatra_route"),
    ("line_patterns", "ruby", r"^\s*head\s+['\"/]", "head '/x' do\n 'ok'\nend\n", "app.rb", "head '/x' do", "sinatra_route"),
    # -- _ENTRY_LINE_PATTERNS["php"] (3 of 3) --
    # The entry's "line" is the CLOSURE's line_start: a Laravel route file's
    # handler is an anonymous function, and `_registering_call_lines` walks up
    # from it to the `Route::get(` it is an argument to.
    ("line_patterns", "php", r"\bRoute::(?:get|post|put|patch|delete|options|any|match|resource|apiResource|resources|apiResources|redirect|view|fallback)\s*\(", PHP_LARAVEL_ROUTES_SRC, "web.php", "Route::get('/', function ()", "laravel_route"),
    ("line_patterns", "php", r"\$app->\w+\s*\(", PHP_APP_REGISTRAR_SRC, "app_registrar.php", "registerApp", "slim_route"),
    ("line_patterns", "php", r"\$router->\w+\s*\(", PHP_ROUTER_REGISTRAR_SRC, "router_registrar.php", "registerRouter", "framework_route"),
    # -- _GLOBAL_ENTRY_LINE_PATTERNS (6 of 6) --
    ("global_line_patterns", "python", r"^\s*if\s+__name__\s*==\s*['\"]__main__['\"]", PY_FLASK_SRC, "flask_app.py", 'if __name__ == "__main__":', "main_guard"),
    ("global_line_patterns", "ruby", r"^\s*if\s+__FILE__\s*==\s*\$0", RUBY_MAIN_GUARD_1_SRC, "script1.rb", "if __FILE__ == $0", "main_guard"),
    ("global_line_patterns", "ruby", r"^\s*if\s+\$PROGRAM_NAME\s*==\s*__FILE__", RUBY_MAIN_GUARD_2_SRC, "script2.rb", "if $PROGRAM_NAME == __FILE__", "main_guard"),
    ("global_line_patterns", "ruby", r"^\s*Rails\.application\.routes\.draw\b", "Rails.application.routes.draw do\n get 'files', to: 'files#index'\nend\n", "config/routes.rb", "Rails.application.routes.draw do", "rails_route"),
    # php reuses the same list object as _ENTRY_LINE_PATTERNS["php"], read over
    # top-level statements instead of function spans. Each row needs a
    # registration with NO inline callable, or the function-scoped pass owns it
    # and the top-level pass deliberately stands down.
    ("global_line_patterns", "php", r"\bRoute::(?:get|post|put|patch|delete|options|any|match|resource|apiResource|resources|apiResources|redirect|view|fallback)\s*\(", PHP_LARAVEL_ROUTES_SRC, "web.php", "Route::get('/users/{id}'", "laravel_route"),
    ("global_line_patterns", "php", r"\$app->\w+\s*\(", PHP_TOP_LEVEL_REGISTRAR_SRC, "index.php", "$app->get('/users'", "slim_route"),
    ("global_line_patterns", "php", r"\$router->\w+\s*\(", PHP_TOP_LEVEL_REGISTRAR_SRC, "index.php", "$router->post('/widgets'", "framework_route"),
]


@pytest.mark.parametrize(
    ("table", "language", "pattern", "source", "file_path", "needle", "expected_kind"),
    LIVE_CASES,
    ids=[f"{c[0]}:{c[1]}:{c[2]}" for c in LIVE_CASES],
)
def test_live_entry_pattern_fires_on_idiomatic_code(
    table: str,
    language: str,
    pattern: str,
    source: str,
    file_path: str,
    needle: str,
    expected_kind: str,
) -> None:
    result = _index(source, file_path, language)
    line = _line_of(needle, source)
    matches = [ep for ep in _entries_at(result, line) if ep["kind"] == expected_kind]

    assert matches, (
        f"expected an entry_point of kind={expected_kind!r} at line {line} "
        f"(table={table}, language={language}, pattern={pattern!r}); got "
        f"{json.dumps(_entries_at(result, line))}"
    )


# ---------------------------------------------------------------------------
# @WebServlet: DEAD on the structural path, LIVE only via the streaming
# fallback the same annotation table feeds. Both halves proven here.
# ---------------------------------------------------------------------------

def test_webservlet_annotation_is_invisible_on_the_structural_path() -> None:
    """`@WebServlet` is a class-only annotation; `_parse_class_node` (java
    branch, treesitter_index.py:1148-1170) never captures class annotations,
    and `_detect_entry_points` only ever inspects a FUNCTION's own
    `annotations` list. So no realistic Java source can make this fire
    through `index_file`.
    """
    result = _index(JAVA_WEBSERVLET_SRC, "Legacy.java", "java")

    assert not any(ep["kind"] == "servlet_annotation" for ep in result["entry_points"])
    # The method-name path still finds doGet independently -- proves the
    # fixture is realistic and it is specifically @WebServlet that is dead.
    assert any(ep["kind"] == "servlet_override" for ep in result["entry_points"])


def test_webservlet_annotation_fires_once_the_file_is_streamed() -> None:
    """`StreamingSecurityScanner._entry_patterns` folds `_ENTRY_ANNOTATIONS`
    in verbatim (treesitter_index.py:3421-3424), so the same `@WebServlet`
    text a degraded parse hits (a real route: a >8MB vendored/generated
    Java file trips `exact_parser_source_limit` in
    `parser_boundary.py:298-300`, or any source with a genuine syntax
    error trips `tree_sitter_syntax_error`) is scanned as plain text
    with no class-vs-method distinction, and matches.
    """
    result = _stream(JAVA_WEBSERVLET_SRC, "Legacy.java", "java")

    assert any(
        ep["kind"] == "servlet_annotation" for ep in result["entry_points"]
    )


# ---------------------------------------------------------------------------
# Coverage-gap / precision regressions worth pinning even though they are not
# new LIVE catalogue entries -- these guard against the gaps getting *worse*
# silently, and document exactly what a real 2026 target still gets missed.
# ---------------------------------------------------------------------------

def test_servlet_override_requires_the_class_to_extend_the_literal_name() -> None:
    """Coverage gap, not a regression target: a class extending a project
    base servlet (rather than `HttpServlet` directly) is silently missed
    because the `extends` equality check (treesitter_index.py:1467) is
    exact-string, not "is-a" aware. Pinned so a future attempt to fix this
    doesn't get silently reverted.
    """
    result = _index(JAVA_BASE_SERVLET_SRC, "MyServlet.java", "java")

    assert result["entry_points"] == []


def test_main_requires_public_and_static_modifiers() -> None:
    result = _index(JAVA_SERVLET_SRC, "Servlet.java", "java")
    # 4-space indent, no `public static` -- distinguishes NotAnEntry.main
    # from the qualifying "public static void main" line elsewhere in the
    # same fixture, which contains "void main(String[] args) {" too.
    main_line = _line_of("    void main(String[] args) {", JAVA_SERVLET_SRC)

    assert not _entries_at(result, main_line)


def test_filter_implementation_is_entry_point() -> None:
    """Servlet filters implement an interface and receive HTTP requests."""
    result = _index(JAVA_SERVLET_SRC, "Servlet.java", "java")
    do_filter_line = _line_of("public void doFilter", JAVA_SERVLET_SRC)

    assert any(entry["kind"] == "filter_override"
               for entry in _entries_at(result, do_filter_line))


def test_sinatra_route_blocks_are_indexed_as_callable_entries() -> None:
    """Sinatra route blocks provide the executable scan scope."""
    result = _index(RUBY_SINATRA_SRC, "app.rb", "ruby")

    assert len(result["functions"]) == 3
    assert len([entry for entry in result["entry_points"] if entry["kind"] == "sinatra_route"]) == 3


def test_ruby_hash_delete_is_not_a_route() -> None:
    """Ordinary Hash#delete calls do not register HTTP handlers."""
    result = _index(RUBY_DELETE_FALSE_POSITIVE_SRC, "widgets_controller.rb", "ruby")
    # entry_points["line"] is the method's own def-line (func.line_start),
    # not the line the matching text sits on inside its body.
    line = _line_of("def destroy_all(params)", RUBY_DELETE_FALSE_POSITIVE_SRC)

    matches = [ep for ep in _entries_at(result, line) if ep["kind"] == "sinatra_route"]
    assert not matches


def test_go_framework_route_pattern_fires_on_ordinary_non_web_code() -> None:
    """MISROUTED, pinned as a negative: `\\b(?:e|g|app)\\.\\w+\\s*\\(` has no
    web-framework context check, so any function calling a method on a
    variable named `e`, `g`, or `app` for any reason gets tagged
    `framework_route`. Demonstrated with a pure errgroup/config-loading
    worker that never touches HTTP.
    """
    result = _index(GO_FALSE_POSITIVE_SRC, "worker.go", "go")

    kinds_by_function = {
        ep["name"]: ep["kind"]
        for ep in result["entry_points"]
        if ep["kind"] == "framework_route"
    }
    assert kinds_by_function == {
        "processAll": "framework_route",
        "parseConfig": "framework_route",
    }


def test_a_registration_is_attributed_by_enclosing_call_not_proximity() -> None:
    """Mechanism-level guard, not specific to one pattern.

    `_detect_entry_points` used to scan three lines ABOVE each function "for
    decorators", and that window did not stop at the previous function's
    closing brace, so a function stacked under a registration inherited it.
    Neither flooring the window nor deleting it is the answer: the window's
    true positives are real -- a wrapped `app.get(` sits above the callback it
    registers, which is how Prettier formats most Express routes -- and its
    false positive is real too.

    Both are answered by the same structural question, which is what
    ``_registering_call_lines`` asks: is this function an argument of the call
    that carries the matching line? A wrapped callback is; the function stacked
    below a registration is not, however few lines separate them.

    This test pins the false-positive half, in the direction that costs a
    finding: a match must stay on the function that contains it and must never
    be attributed to a neighbour. The true-positive half is pinned by
    ``test_a_wrapped_express_route_is_attributed_to_its_callback``.
    """
    result = _index(GO_STACKED_REGISTRATION_SRC, "leak.go", "go")

    registrar_line = _line_of("func registerLegacyHandle", GO_STACKED_REGISTRATION_SRC)
    neighbour_line = _line_of("func metricsHandler", GO_STACKED_REGISTRATION_SRC)

    # The registration is still seen -- removing the window must not cost the
    # true positive it was sitting next to.
    assert [
        ep for ep in _entries_at(result, registrar_line) if ep["kind"] == "http_handler"
    ], "registerLegacyHandle contains the http.Handle(...) call and must still match"

    # ...and it stays there. metricsHandler has no registration of its own.
    assert not _entries_at(result, neighbour_line), (
        "metricsHandler has no http.Handle(...) call of its own; a match "
        "inherited from the preceding function points the hunter at the "
        "wrong function, which is worse than reporting nothing"
    )
    assert len(result["entry_points"]) == 1


@pytest.mark.parametrize(
    ("source", "callback_needle"),
    [
        (JS_WRAPPED_ARROW_ROUTE_SRC, "  async (req, res) => {"),
        (JS_WRAPPED_NAMED_ROUTE_SRC, "  function memberHandler"),
        (JS_TRAILING_MIDDLEWARE_ROUTE_SRC, "  (req, res) => {"),
        (JS_ADAPTED_ROUTE_SRC, "  asyncHandler(async (req, res)"),
    ],
    ids=["arrow", "named expression", "trailing middleware", "async adapter"],
)
def test_a_wrapped_express_route_is_attributed_to_its_callback(
    source: str, callback_needle: str
) -> None:
    """The true-positive half of the same mechanism.

    The catalogue's LIVE Express rows all use the single-line idiom, where
    `app.get(` happens to sit on the callback's own first line -- so the whole
    corpus was blind to the wrapped form, and a "the lookback has no true
    positive" measurement taken against it read clean while every shape below
    silently stopped producing a request surface at all.

    Every shape here is what Prettier's 80-column default emits for an
    ordinary route, so this is the majority formatting of real Express code,
    not an edge case.
    """
    result = _index(source, "server.js", "javascript")
    callback_line = _line_of(callback_needle, source)

    assert [ep["kind"] for ep in result["entry_points"]] == ["express_route"], (
        json.dumps(result["entry_points"])
    )
    assert result["entry_points"][0]["line"] == callback_line, (
        "the route belongs to the callback the call receives, not to the line "
        "`app.get(` happens to sit on"
    )


def test_a_closure_inside_a_registered_callback_is_not_itself_the_route() -> None:
    """The walk stops at the first callable it crosses.

    Without that boundary an enclosing-call walk reaches `app.get(` from any
    depth, and every helper closure inside a handler becomes a route of its
    own -- trading the old lookback's neighbour false positive for a nesting
    one. `format` is registered by nothing and must stay unreported.
    """
    result = _index(JS_NESTED_CLOSURE_ROUTE_SRC, "server.js", "javascript")
    handler_line = _line_of("  (req, res) => {", JS_NESTED_CLOSURE_ROUTE_SRC)

    assert [ep["line"] for ep in result["entry_points"]] == [handler_line]
    assert "format" in {
        func["name"] for func in result["functions"]
    }, "fixture must still extract the nested closure"


def test_registration_above_a_named_handler_is_attributed_to_it() -> None:
    """A registration above a declaration belongs to its named handler."""
    result = _index(JS_REGISTRATION_ABOVE_HANDLER_SRC, "admin.js", "javascript")

    assert result["functions"], "fixture must still extract handleAdmin"
    assert [(entry["name"], entry["kind"]) for entry in result["entry_points"]] == [
        ("handleAdmin", "express_route")
    ]


def test_express_route_naming_an_existing_handler_is_attributed() -> None:
    """A top-level registration below a declaration still names the handler."""
    result = _index(JS_NAMED_HANDLER_GAP_SRC, "server.js", "javascript")

    assert [(entry["name"], entry["kind"]) for entry in result["entry_points"]] == [
        ("listUsers", "express_route")
    ]


def test_a_laravel_route_file_registers_every_route_exactly_once() -> None:
    """Both halves of the php entry surface, on one real route file.

    The inline-closure route is attributed to its handler (the closure, now a
    callable), and the controller-array route -- which has no callable at all
    -- is attributed to the top-level statement. The top-level pass stands
    down on the first of those, so one registration never yields two records.
    """
    result = _index(PHP_LARAVEL_ROUTES_SRC, "web.php", "php")

    assert [func["name"] for func in result["functions"]] == ["<anonymous@5:16>"]
    assert [
        (entry["name"], entry["kind"], entry["line"])
        for entry in result["entry_points"]
    ] == [
        ("<anonymous@5:16>", "laravel_route", _line_of("Route::get('/', function ()", PHP_LARAVEL_ROUTES_SRC)),
        ("<top-level>", "laravel_route", _line_of("Route::get('/users/{id}'", PHP_LARAVEL_ROUTES_SRC)),
    ]


def test_slim_closure_routes_register_through_their_returned_closure() -> None:
    """The second mechanism, independent of the top-level statement scan: the
    returned closure is the callable, and `$app->get(...)` sits inside its own
    body, which is the span the function-scoped line patterns already read.
    """
    result = _index(PHP_SLIM_CLOSURE_ROUTES_SRC, "routes.php", "php")

    assert [func["name"] for func in result["functions"]] == ["<anonymous@5:7>"]
    assert [entry["kind"] for entry in result["entry_points"]] == ["slim_route"]


def test_php_attribute_route_also_survives_the_streaming_comment_rule() -> None:
    """The structural half of this pattern is already proven live through
    LIVE_CASES; this pins the second, independent half -- that
    `#[Route(...)]` is not thrown away as a hash-comment on the streaming
    path either. `_opens_a_comment` (treesitter_index.py:3751-3756) treats
    a line starting with `#` as a comment only when the language is in
    `_HASH_COMMENT_LANGUAGES` AND the line does not start with that
    language's `_HASH_CODE_PREFIXES` entry; php's entry is `#[`, the exact
    prefix every PHP 8 attribute opens with.
    """
    streamed = _stream(PHP_ATTRIBUTE_ROUTE_SRC, "UserController.php", "php")

    assert any(ep["kind"] == "symfony_route" for ep in streamed["entry_points"])


def test_php_construct_fires_on_every_constructor_regardless_of_reachability() -> None:
    """MISROUTED, pinned as a negative: unlike `__wakeup`/`__destruct`
    (genuine PHP object-injection gadget-chain hooks -- see LIVE_CASES),
    `__construct` is never invoked by PHP's native `unserialize()`. The
    pattern still fires on every ordinary constructor, with no way to tell
    "reachable from attacker-controlled deserialization" apart from
    "any class in the codebase". No positive test is written for it.
    """
    result = _index(PHP_MAGIC_METHODS_SRC, "value_object.php", "php")
    line = _line_of("public function __construct", PHP_MAGIC_METHODS_SRC)

    matches = [ep for ep in _entries_at(result, line) if ep["kind"] == "constructor"]
    assert matches, "an ordinary value-object constructor is enough to fire this pattern"


# ---------------------------------------------------------------------------
# Meta-test: the case table above must cover every LIVE pattern in the four
# tables this suite owns, and the exclusion list must account for the rest.
# ---------------------------------------------------------------------------

# (table, language, pattern_or_name) -> reason, file:line. Anything in
# _ENTRY_ANNOTATIONS / _ENTRY_METHOD_NAMES / _ENTRY_LINE_PATTERNS /
# _GLOBAL_ENTRY_LINE_PATTERNS not in LIVE_CASES must appear here.
EXCLUDED_PATTERNS: dict[tuple[str, str, str], str] = {
    ("method_names", "php", "__construct"):
        "MISROUTED -- fires on every PHP constructor; unlike __wakeup, "
        "__construct is never invoked by PHP's native unserialize(). "
        "Verified in test_php_construct_fires_on_every_constructor_regardless_of_reachability.",
    ("line_patterns", "go", r"\b(?:e|g|app)\.\w+\s*\("):
        "MISROUTED -- no web-framework context check; fires on any method "
        "call on a variable named e/g/app for any reason (errgroup.Wait(), "
        "a loaded Config). Verified in "
        "test_go_framework_route_pattern_fires_on_ordinary_non_web_code.",
}


def _real_annotation_keys() -> set[tuple[str, str, str]]:
    return {
        ("annotations", language, entry["pattern"])
        for language, entries in treesitter_index._ENTRY_ANNOTATIONS.items()
        for entry in entries
    }


def _real_method_name_keys() -> set[tuple[str, str, str]]:
    return {
        ("method_names", language, entry["name"])
        for language, entries in treesitter_index._ENTRY_METHOD_NAMES.items()
        for entry in entries
    }


def _real_line_pattern_keys() -> set[tuple[str, str, str]]:
    return {
        ("line_patterns", language, entry["pattern"])
        for language, entries in treesitter_index._ENTRY_LINE_PATTERNS.items()
        for entry in entries
    }


def _real_global_line_pattern_keys() -> set[tuple[str, str, str]]:
    return {
        ("global_line_patterns", language, entry["pattern"])
        for language, entries in treesitter_index._GLOBAL_ENTRY_LINE_PATTERNS.items()
        for entry in entries
    }


def test_catalogue_sweep_covers_every_entry_point_pattern() -> None:
    real_keys = (
        _real_annotation_keys()
        | _real_method_name_keys()
        | _real_line_pattern_keys()
        | _real_global_line_pattern_keys()
    )
    assert len(real_keys) == 86, (
        f"expected 83 entry-point catalogue entries (19 annotations + "
        f"20 method names + 37 line patterns + 7 global line patterns), "
        f"found {len(real_keys)} -- the catalogue has drifted; update this "
        f"suite's LIVE_CASES/EXCLUDED_PATTERNS to match"
    )

    tested_keys = {(c[0], c[1], c[2]) for c in LIVE_CASES}
    # @WebServlet is LIVE but tested via a dedicated pair of tests (structural
    # DEAD + streaming LIVE), not through the uniform LIVE_CASES sweep.
    tested_keys.add(("annotations", "java", r"@WebServlet\b"))
    # export default function / module.exports fire identically on the
    # typescript grammar as on javascript (same extraction path,
    # `_extract_javascript_callables` -- treesitter_index.py:1065); proven
    # once on JS rather than duplicated verbatim on TS.
    tested_keys.add(("line_patterns", "typescript", r"\bexport\s+default\s+function\b"))
    tested_keys.add(("line_patterns", "typescript", r"\bmodule\.exports\b"))

    excluded_keys = set(EXCLUDED_PATTERNS)

    missing = real_keys - tested_keys - excluded_keys
    assert not missing, f"untriaged catalogue entries: {sorted(missing)}"

    stale = (tested_keys | excluded_keys) - real_keys
    assert not stale, f"LIVE_CASES/EXCLUDED_PATTERNS reference entries no longer in the catalogue: {sorted(stale)}"

    overlap = tested_keys & excluded_keys
    assert not overlap, f"a pattern cannot be both tested-live and excluded: {sorted(overlap)}"
