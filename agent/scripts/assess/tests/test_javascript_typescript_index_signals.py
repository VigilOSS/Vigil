"""Route registrations that let agents find reachable JavaScript handlers."""

import pytest

from assess.lib.treesitter_index import index_file


@pytest.mark.parametrize(("language", "path"), [("javascript", "server.js"), ("typescript", "server.ts")])
def test_named_express_handler_registration_is_an_entry_point(language: str, path: str) -> None:
    source = """function read(req, res) {
    return res.sendFile(req.params.name);
}
app.get('/files/:name', read);
"""
    indexed = index_file(path, language, source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "express_route" and item["name"] == "read"
               for item in indexed["entry_points"])
    assert any(item["name"] == "read" and item["is_entry_point"] for item in indexed["functions"])


@pytest.mark.parametrize(("language", "path"), [("javascript", "util.js"), ("typescript", "util.ts")])
def test_unregistered_function_is_not_a_route(language: str, path: str) -> None:
    source = """function read(req, res) { return res.send(req.params.name); }
cache.get('/files/:name', read);
"""
    indexed = index_file(path, language, source.encode())
    assert indexed["analysis_status"] == "complete"
    assert indexed["entry_points"] == []


@pytest.mark.parametrize(("language", "path"), [("javascript", "server.js"), ("typescript", "server.ts")])
def test_route_setup_function_is_not_the_named_handler(language: str, path: str) -> None:
    source = """function read(req, res) { return res.send(req.params.name); }
function setup() { app.get('/files/:name', read); }
"""
    indexed = index_file(path, language, source.encode())
    assert indexed["analysis_status"] == "complete"
    route_names = [entry["name"] for entry in indexed["entry_points"]
                   if entry["kind"] == "express_route"]
    assert route_names == ["read"]


@pytest.mark.parametrize(("language", "path"), [("javascript", "server.js"), ("typescript", "server.ts")])
def test_bare_route_handler_does_not_resolve_to_class_method(language: str, path: str) -> None:
    source = """function handle(req, res) { return res.send('top'); }
class Other {
    handle(req, res) { return res.send('method'); }
}
app.get('/top', handle);
"""
    indexed = index_file(path, language, source.encode())

    assert [(entry["line"], entry["kind"]) for entry in indexed["entry_points"]] == [
        (1, "express_route")
    ]
    assert [function["line_start"] for function in indexed["functions"]
            if function["is_entry_point"]] == [1]


@pytest.mark.parametrize(("language", "path"), [("javascript", "server.js"), ("typescript", "server.ts")])
def test_bare_route_handler_uses_nearest_lexical_binding(language: str, path: str) -> None:
    source = """function handle(req, res) { return res.send('global'); }
function register() {
    function handle(req, res) { return res.send('local'); }
    app.get('/local', handle);
}
app.get('/global', handle);
"""
    indexed = index_file(path, language, source.encode())

    assert {(entry["line"], entry["kind"]) for entry in indexed["entry_points"]} == {
        (1, "express_route"), (3, "express_route")
    }
