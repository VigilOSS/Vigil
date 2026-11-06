"""Go request and outbound HTTP signals used to route code review."""

from assess.lib.treesitter_index import index_file


def test_named_http_request_parameter_is_a_source() -> None:
    source = """package main
import "net/http"
func handler(w http.ResponseWriter, req *http.Request) {
    name := req.FormValue("name")
    _ = name
}
"""
    indexed = index_file("main.go", "go", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "http_request_input" and "req.FormValue" in item["snippet"]
               for item in indexed["security_sources"])


def test_http_client_do_is_fetch_sink_but_new_request_is_not() -> None:
    source = """package main
import "net/http"
func fetch(url string, client *http.Client) {
    req, _ := http.NewRequest("GET", url, nil)
    client.Do(req)
}
"""
    indexed = index_file("fetch.go", "go", source.encode())
    assert indexed["analysis_status"] == "complete"
    fetches = [sink for sink in indexed["security_sinks"] if sink["kind"] == "url_fetch"]
    assert len(fetches) == 1
    assert "client.Do(req)" in fetches[0]["snippet"]


def test_constructed_http_request_alone_is_not_a_fetch_sink() -> None:
    source = """package main
import "net/http"
func prepare(url string) {
    http.NewRequest("GET", url, nil)
}
"""
    indexed = index_file("prepare.go", "go", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert not any(sink["kind"] == "url_fetch" for sink in indexed["security_sinks"])


def test_aliased_net_http_client_is_a_fetch_sink() -> None:
    source = """package main
import nethttp "net/http"
func fetch(client *nethttp.Client, req *nethttp.Request) {
    client.Do(req)
}
"""
    indexed = index_file("fetch.go", "go", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(sink["kind"] == "url_fetch" and "client.Do(req)" in sink["snippet"]
               for sink in indexed["security_sinks"])


def test_reading_the_query_string_is_not_a_sql_sink_but_db_query_is() -> None:
    source = """package main
import (
    "database/sql"
    "net/http"
)
func search(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    rows, _ := db.Query("SELECT id FROM users WHERE name = '" + name + "'")
    _ = rows
}
var db *sql.DB
"""
    indexed = index_file("search.go", "go", source.encode())
    sql_lines = [sink["snippet"] for sink in indexed["security_sinks"] if sink["kind"] == "sql_exec"]
    assert sql_lines == [
        "rows, _ := db.Query(\"SELECT id FROM users WHERE name = '\" + name + \"'\")"
    ]
