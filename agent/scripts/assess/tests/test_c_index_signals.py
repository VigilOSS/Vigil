"""C structural signals that help agents find reachable code in large repos."""

from assess.lib.treesitter_index import index_file


def test_registered_c_callback_is_an_entry_point() -> None:
    source = b"""\
struct evhttp;
struct evhttp_request;
void evhttp_set_cb(struct evhttp *, const char *, void (*)(struct evhttp_request *, void *), void *);

static void serve_file(struct evhttp_request *request, void *arg) {
    open(arg, 0);
}

int main(void) {
    evhttp_set_cb(http, "/file", serve_file, 0);
}
"""
    indexed = index_file("server.c", "c", source)

    assert indexed["analysis_status"] == "complete"
    assert ("serve_file", "http_handler") in {
        (entry["name"], entry["kind"]) for entry in indexed["entry_points"]
    }


def test_registered_c_address_of_callback_is_an_entry_point() -> None:
    source = b"""\
static void serve_file(struct evhttp_request *request, void *arg) { open(arg, 0); }
void configure(void) { evhttp_set_cb(http, "/file", &serve_file, 0); }
"""
    indexed = index_file("server.c", "c", source)

    assert ("serve_file", "http_handler") in {
        (entry["name"], entry["kind"]) for entry in indexed["entry_points"]
    }


def test_c_http_registration_does_not_promote_other_arguments() -> None:
    source = b"""\
void serve_file(void) { open("file", 0); }
void unrelated(void) { tick(); }
void configure(void) { evhttp_set_cb(http, "/file", serve_file, unrelated); }
"""
    indexed = index_file("server.c", "c", source)

    assert "serve_file" in {entry["name"] for entry in indexed["entry_points"]}
    assert "unrelated" not in {entry["name"] for entry in indexed["entry_points"]}


def test_calling_a_handler_does_not_make_the_caller_an_entry_point() -> None:
    source = b"""\
void timer_callback(void *context) { tick(context); }
void worker(void *context) { timer_callback(context); }
"""
    indexed = index_file("worker.c", "c", source)

    assert indexed["analysis_status"] == "complete"
    assert "worker" not in {entry["name"] for entry in indexed["entry_points"]}


def test_c_header_declarations_are_indexed_for_navigation() -> None:
    source = b"""\
#ifndef API_H
#define API_H
int handle_request(const char *path);
char *make_response(const char *body);
void (*callback_slot)(void);
#endif
"""
    indexed = index_file("include/api.h", "c", source)

    assert {
        function["name"] for function in indexed["functions"]
    } == {"handle_request", "make_response"}
    assert all(function["is_declaration"] for function in indexed["functions"])


def test_c_external_functions_are_exported_but_static_functions_are_not() -> None:
    source = b"""\
extern int public_api(const char *path);
static int internal_api(const char *path);
int public_api(const char *path) { return open(path, 0); }
static int internal_api(const char *path) { return 0; }
"""
    indexed = index_file("api.c", "c", source)

    assert {symbol["name"] for symbol in indexed["exports"]} == {"public_api"}


def test_c_main_prototype_is_not_an_executable_entry() -> None:
    indexed = index_file("api.h", "c", b"int main(void);\n")

    assert not any(entry["kind"] == "main_function" for entry in indexed["entry_points"])


def test_distinct_c_memory_sink_locations_survive_in_one_function() -> None:
    source = b"""\
void copy_both(const char *first, const char *second) {
    char left[8], right[8];
    strcpy(left, first);
    strcpy(right, second);
}
"""
    indexed = index_file("copy.c", "c", source)

    assert {sink["line"] for sink in indexed["security_sinks"] if sink["kind"] == "memory"} == {3, 4}
