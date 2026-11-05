"""Request handlers a hand-rolled router reaches, identified structurally.

A route slice walked in a loop, a `createServer(router)` with its own path
switch, and a single catch-all Tornado handler register no framework route the
line catalogue can read. What each still has is a structural shape the runtime
dispatches on: Go's `(http.ResponseWriter, *http.Request)` handler signature,
the callable handed to Node's `http.createServer`, and the HTTP-verb methods of
a Tornado `RequestHandler` subclass.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


def _entries(indexed: dict) -> list[tuple[str, str]]:
    return [(entry["name"], entry["kind"]) for entry in indexed["entry_points"]]


def _tree_sitter(file_path: str, language: str, source: bytes) -> dict:
    indexed = index_file(file_path, language, source)
    assert indexed["analysis_mode"] == "tree_sitter", indexed.get("degradation_reason")
    return indexed


# --- Go ----------------------------------------------------------------------

GO_ROUTE_SLICE = b"""package main

import (
	"encoding/json"
	"net/http"
)

type route struct {
	path    string
	handler http.HandlerFunc
}

var routes = []route{
	{"/reports", handleReports},
	{"/health", handleHealth},
}

func handleReports(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Query().Get("id")))
}

func handleHealth(http.ResponseWriter, *http.Request) {}

func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	json.NewEncoder(w).Encode(v)
}

func main() {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.HandleFunc(rt.path, rt.handler)
	}
	http.ListenAndServe(":8080", mux)
}
"""


def test_a_go_handler_signature_is_an_entry_point() -> None:
    indexed = _tree_sitter("cmd/acme/main.go", "go", GO_ROUTE_SLICE)

    assert _entries(indexed) == [
        ("handleReports", "go_http_handler"),
        ("handleHealth", "go_http_handler"),
        ("main", "main_function"),
    ]


GO_SERVE_HTTP_ALIAS = b"""package acme

import nethttp "net/http"

type Router struct{}

func (Router) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	switch r.URL.Path {
	case "/export":
		w.WriteHeader(200)
	}
}
"""


def test_a_serve_http_method_under_an_import_alias_is_an_entry_point() -> None:
    indexed = _tree_sitter("acme/router.go", "go", GO_SERVE_HTTP_ALIAS)

    assert _entries(indexed) == [("ServeHTTP", "go_http_handler")]
    assert any(
        source["kind"] == "http_request_input" for source in indexed["security_sources"]
    )


def test_the_go_handler_signature_streams_as_an_entry_point() -> None:
    observed = treesitter_index._fallback_from_bytes(
        "cmd/acme/main.go", "go", GO_ROUTE_SLICE, degradation_reason="test"
    )

    assert [entry["kind"] for entry in observed["entry_points"]].count("go_http_handler") == 2


# --- Node --------------------------------------------------------------------

NODE_CUSTOM_ROUTER = b"""const http = require('http');
const url = require('url');

function router(req, res) {
  const { pathname } = url.parse(req.url);
  switch (pathname) {
    case '/export':
      return serveExport(req, res);
    default:
      res.statusCode = 404;
      res.end();
  }
}

function serveExport(req, res) {
  res.end(req.headers['x-id']);
}

http.createServer(router).listen(8080);
"""


def test_the_function_handed_to_create_server_is_an_entry_point() -> None:
    indexed = _tree_sitter("acme/server.js", "javascript", NODE_CUSTOM_ROUTER)

    assert _entries(indexed) == [("router", "node_http_server")]
    assert any(
        source["kind"] == "http_request_input"
        and source["line"] == 5
        for source in indexed["security_sources"]
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(
            b"const https = require('https');\n"
            b"const options = {};\n"
            b"https.createServer(options, (req, res) => res.end(req.url)).listen(443);\n",
            [("<anonymous@3:28>", "node_http_server")],
            id="https-options-first-inline",
        ),
        pytest.param(
            b"import { createServer } from 'node:http';\n"
            b"function handle(req, res) { res.end(); }\n"
            b"createServer(handle).listen(8080);\n",
            [("handle", "node_http_server")],
            id="bare-imported-create-server",
        ),
        pytest.param(
            b"const http = require('http');\n"
            b"const server = http.createServer();\n"
            b"function onRequest(req, res) { res.end(); }\n"
            b"server.on('request', onRequest);\n",
            [("onRequest", "node_http_server")],
            id="request-event",
        ),
        pytest.param(
            b"const http = require('http');\n"
            b"const app = require('./app');\n"
            b"http.createServer(app).listen(8080);\n",
            [("<top-level>", "node_http_server")],
            id="imported-handler",
        ),
    ],
)
def test_node_server_registration_shapes(source: bytes, expected: list) -> None:
    indexed = _tree_sitter("acme/server.js", "javascript", source)

    assert _entries(indexed) == expected


def test_a_tcp_server_is_not_an_http_entry_point() -> None:
    source = (
        b"const net = require('net');\n"
        b"function onSocket(socket) { socket.end(); }\n"
        b"net.createServer(onSocket).listen(9000);\n"
    )
    indexed = _tree_sitter("acme/tcp.js", "javascript", source)

    assert indexed["entry_points"] == []


def test_a_browser_automation_request_listener_is_not_an_http_entry_point() -> None:
    source = (
        b"const puppeteer = require('puppeteer');\n"
        b"function onRequest(request) { request.continue(); }\n"
        b"async function crawl() {\n"
        b"  const page = await (await puppeteer.launch()).newPage();\n"
        b"  page.on('request', onRequest);\n"
        b"}\n"
    )
    indexed = _tree_sitter("acme/crawl.js", "javascript", source)

    assert [entry for entry in indexed["entry_points"] if entry["kind"] == "node_http_server"] == []


def test_a_typescript_create_server_handler_is_an_entry_point() -> None:
    source = (
        b"import * as http from 'http';\n"
        b"const handle = (req: http.IncomingMessage, res: http.ServerResponse) => res.end();\n"
        b"http.createServer(handle).listen(8080);\n"
    )
    indexed = _tree_sitter("acme/server.ts", "typescript", source)

    assert _entries(indexed) == [("handle", "node_http_server")]


# --- Tornado -----------------------------------------------------------------

TORNADO_CATCH_ALL = b"""import tornado.web


class AuthMixin:
    def current_user_id(self):
        return self.get_secure_cookie("uid")


class BaseHandler(AuthMixin, tornado.web.RequestHandler):
    def write_error(self, status_code, **kwargs):
        self.finish()


class MainHandler(BaseHandler):
    def get(self):
        if self.request.path == "/report":
            self.write(self.get_argument("id"))

    def post(self):
        self.write(self.request.body)

    def helper(self):
        return None


def make_app():
    return tornado.web.Application([(r"/.*", MainHandler)])
"""


def test_tornado_verb_methods_resolve_through_mixins_and_in_file_bases() -> None:
    indexed = _tree_sitter("acme/app.py", "python", TORNADO_CATCH_ALL)

    assert sorted(_entries(indexed)) == [
        ("get", "tornado_handler"),
        ("make_app", "tornado_application"),
        ("post", "tornado_handler"),
    ]


def test_tornado_request_accessors_are_sources() -> None:
    indexed = _tree_sitter("acme/app.py", "python", TORNADO_CATCH_ALL)
    source_lines = {
        source["line"]
        for source in indexed["security_sources"]
        if source["kind"] == "http_request_input"
    }
    lines = TORNADO_CATCH_ALL.decode().splitlines()

    for needle in ('self.request.path', 'self.get_argument("id")', 'self.get_secure_cookie'):
        line = next(n for n, text in enumerate(lines, 1) if needle in text)
        assert line in source_lines, needle


def test_a_non_tornado_class_get_method_is_not_an_entry_point() -> None:
    source = b"class Cache:\n    def get(self, key):\n        return key\n"
    indexed = _tree_sitter("acme/cache.py", "python", source)

    assert indexed["entry_points"] == []
