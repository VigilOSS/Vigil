"""C++ HTTP and callback signals for large-repository agent navigation."""

import pytest

from assess.lib.treesitter_index import index_file


def test_cpp_httplib_named_handler_is_the_entry_point() -> None:
    source = b"""\
#include "httplib.h"
void serve_file(const httplib::Request& req, httplib::Response& res) {
    fopen(req.path.c_str(), "r");
}
int main() {
    httplib::Server svr;
    svr.Get("/file", serve_file);
}
"""
    indexed = index_file("server.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert ("serve_file", "http_handler") in {
        (entry["name"], entry["kind"]) for entry in indexed["entry_points"]
    }


def test_cpp_httplib_client_get_does_not_create_an_http_entry() -> None:
    source = b"""\
#include "httplib.h"
void fetch() {
    httplib::Client client("https://example.test");
    auto response = client.Get("/file");
}
"""
    indexed = index_file("client.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(entry["kind"] == "http_handler" for entry in indexed["entry_points"])


def test_cpp_httplib_server_parameter_registers_handler() -> None:
    source = b"""\
void serve(const httplib::Request& req, httplib::Response& res) { res.set_content("ok", "text/plain"); }
void configure(httplib::Server& server) { server.Get("/", serve); }
"""
    indexed = index_file("server.cpp", "cpp", source)

    assert ("serve", "http_handler") in {
        (entry["name"], entry["kind"]) for entry in indexed["entry_points"]
    }


@pytest.mark.parametrize("server_source", [
    'using httplib::Server; void configure() { Server server; server.Get("/", serve); }',
    'void configure() { auto server = httplib::Server{}; server.Get("/", serve); }',
    'class X { httplib::Server server; void configure() { server.Get("/", serve); } };',
])
def test_cpp_httplib_common_server_bindings_register_handler(server_source: str) -> None:
    source = (
        "void serve(const httplib::Request& req, httplib::Response& res) {}\n"
        f"{server_source}\n"
    ).encode()
    indexed = index_file("server.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert ("serve", "http_handler") in {
        (entry["name"], entry["kind"]) for entry in indexed["entry_points"]
    }


def test_cpp_unrelated_get_method_does_not_register_http_handler() -> None:
    source = b"""\
void serve(const Request& req, Response& res) { fopen(req.path.c_str(), "r"); }
int main() {
    Other object;
    object.Get("/file", serve);
}
"""
    indexed = index_file("other.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(entry["kind"] == "http_handler" for entry in indexed["entry_points"])


def test_cpp_main_prototype_is_not_an_executable_entry() -> None:
    indexed = index_file("api.hpp", "cpp", b"int main(void);\n")

    assert not any(entry["kind"] == "main_function" for entry in indexed["entry_points"])


def test_cpp_httplib_lambda_has_its_own_reachable_scope() -> None:
    source = b"""\
#include "httplib.h"
int main() {
    httplib::Server svr;
    svr.Get("/file", [](const httplib::Request& req, httplib::Response& res) {
        fopen(req.path.c_str(), "r");
    });
}
"""
    indexed = index_file("server.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    callback = next(function for function in indexed["functions"] if function["line_start"] == 4)
    assert any(entry["line"] == 4 and entry["kind"] == "http_handler" for entry in indexed["entry_points"])
    assert any(sink["line"] == 5 and sink["function"] == callback["name"] for sink in indexed["security_sinks"])
    assert not any(sink["line"] == 5 and sink["function"] == "main" for sink in indexed["security_sinks"])


def test_cpp_calling_callback_does_not_make_caller_an_entry_point() -> None:
    source = b"""\
void timer_callback() { tick(); }
void worker() { timer_callback(); }
"""
    indexed = index_file("worker.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert "worker" not in {entry["name"] for entry in indexed["entry_points"]}


def test_cpp_httplib_request_access_is_a_source() -> None:
    source = b"""\
void serve_file(const httplib::Request& req, httplib::Response& res) {
    auto name = req.get_param_value("name");
    auto path = req.path;
}
"""
    indexed = index_file("server.cpp", "cpp", source)

    assert {source["line"] for source in indexed["security_sources"] if source["kind"] == "http_request_input"} == {2, 3}


def test_cpp_file_stream_constructor_is_a_file_path_sink() -> None:
    source = b"""\
#include "httplib.h"
#include <fstream>
void serve(const httplib::Request& req, httplib::Response& res) {
    auto path = req.get_param_value("path");
    std::ifstream input(path);
    std::ofstream output(path);
}
"""
    indexed = index_file("server.cpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert {sink["line"] for sink in indexed["security_sinks"] if sink["kind"] == "file_path"} == {5, 6}


def test_cpp_file_stream_type_reference_is_not_a_file_path_sink() -> None:
    source = b"""\
#include <fstream>
struct Streams { std::ifstream input; std::ofstream output; };
void accept(std::ifstream *stream) { std::ifstream *next = stream; }
"""
    indexed = index_file("streams.hpp", "cpp", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(sink["kind"] == "file_path" for sink in indexed["security_sinks"])
