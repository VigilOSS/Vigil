"""Java signals that direct code agents toward request and outbound paths."""

from __future__ import annotations

import pytest

from assess.lib.treesitter_index import index_file


@pytest.mark.parametrize(
    ("annotation", "parameter"),
    [
        ("@GetMapping(\"/files/{name}\")", "@PathVariable String name"),
        ("@GetMapping(\"/files\")", "@RequestParam String name"),
        ("@PostMapping(\"/files\")", "@RequestBody FileRequest input"),
        ("@GET @Path(\"/{name}\")", "@PathParam(\"name\") String name"),
    ],
)
def test_bound_java_handler_parameter_is_request_source(
    annotation: str, parameter: str
) -> None:
    source = f"""\
class FilesResource {{
    {annotation}
    public String read({parameter}) {{
        return "ok";
    }}
}}
""".encode()

    indexed = index_file("FilesResource.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(entry["name"] == "read" for entry in indexed["entry_points"])
    assert any(
        item["kind"] == "http_request_input" and item["line"] == 3
        for item in indexed["security_sources"]
    )


def test_unannotated_spring_handler_argument_is_request_source() -> None:
    source = b"""\
class FilesController {
    @GetMapping("/files")
    public String read(String name) { return name; }
}
"""

    indexed = index_file("FilesController.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "http_request_input" and item["line"] == 3
               for item in indexed["security_sources"])


def test_spring_framework_injected_arguments_are_not_request_sources() -> None:
    source = b"""\
class AccountController {
    @GetMapping("/accounts/{id}")
    String get(java.security.Principal principal,
               org.springframework.ui.Model model, String id) { return id; }
}
"""

    indexed = index_file("AccountController.java", "java", source)

    bound = [item["snippet"] for item in indexed["security_sources"]
             if item["detection"] == "structural_model_binding"]
    assert bound == ["String id"]


def test_unannotated_plain_java_argument_is_not_request_source() -> None:
    source = b"""\
class Formatter {
    String format(String name) { return name; }
}
"""

    indexed = index_file("Formatter.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert not indexed["security_sources"]


@pytest.mark.parametrize("operation", ["send", "sendAsync"])
def test_java_http_client_instance_send_is_url_fetch_sink(operation: str) -> None:
    source = f"""\
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
class Fetcher {{
    private final HttpClient outbound = HttpClient.newHttpClient();
    String fetch(HttpRequest request) throws Exception {{
        return outbound.{operation}(request, HttpResponse.BodyHandlers.ofString()).toString();
    }}
}}
""".encode()

    indexed = index_file("Fetcher.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(
        item["kind"] == "url_fetch" and item["line"] == 7
        for item in indexed["security_sinks"]
    )


def test_unrelated_java_send_is_not_url_fetch_sink() -> None:
    source = b"""\
class Mailer {
    String deliver(MailSender sender, Message message) {
        return sender.send(message).toString();
    }
}
"""

    indexed = index_file("Mailer.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert not any(item["kind"] == "url_fetch" for item in indexed["security_sinks"])


def test_java_http_client_receiver_does_not_leak_to_another_class() -> None:
    source = b"""\
import java.net.http.HttpClient;
class Fetcher {
    HttpClient client;
    void fetch(HttpRequest request) throws Exception {
        client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
class Mailer {
    MailClient client;
    void deliver(Message message) { client.send(message); }
}
"""

    indexed = index_file("Services.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert [item["line"] for item in indexed["security_sinks"]
            if item["kind"] == "url_fetch"] == [5]


def test_java_url_construction_is_not_fetch_but_open_stream_is() -> None:
    source = b"""\
import java.net.URL;
class Fetcher {
    URL parse(String target) throws Exception { return new URL(target); }
    byte[] fetch(URL remote) throws Exception { return remote.openStream().readAllBytes(); }
}
"""

    indexed = index_file("Fetcher.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert [item["line"] for item in indexed["security_sinks"]
            if item["kind"] == "url_fetch"] == [4]


def test_java_http_url_connection_response_code_is_fetch_signal() -> None:
    source = b"""\
import java.net.HttpURLConnection;
class Fetcher {
    int status(HttpURLConnection connection) throws Exception {
        return connection.getResponseCode();
    }
}
"""

    indexed = index_file("Fetcher.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "url_fetch" and item["line"] == 4
               for item in indexed["security_sinks"])


def test_java_interface_and_scoped_implementation_are_navigable() -> None:
    source = b"""\
interface Parent {}
public interface Child extends Parent {}
class Repo implements java.io.Closeable {
    public void close() {}
}
"""

    indexed = index_file("Repo.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    classes = {item["name"]: item for item in indexed["classes"]}
    assert classes["Child"]["extends"] == "Parent"
    assert classes["Repo"]["implements"] == ["java.io.Closeable"]


def test_java_filter_implementation_is_entry_point() -> None:
    source = b"""\
import jakarta.servlet.Filter;
class AuditFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) {}
}
"""

    indexed = index_file("AuditFilter.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(entry["name"] == "doFilter" and entry["kind"] == "filter_override"
               for entry in indexed["entry_points"])


def test_jaxrs_http_verb_without_method_path_is_entry_point() -> None:
    source = b"""\
@Path("/health")
class HealthResource {
    @GET
    public String health() { return "ok"; }
}
"""

    indexed = index_file("HealthResource.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(entry["name"] == "health" and entry["kind"] == "jaxrs_annotation"
               for entry in indexed["entry_points"])


def test_java_exports_exclude_package_private_classes() -> None:
    source = b"""\
class Internal { void helper() {} }
public class Api { public void run() {} }
"""

    indexed = index_file("Api.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert [item["name"] for item in indexed["exports"]] == ["run", "Api"]


def test_spring_functional_route_exposes_handler_entry_point() -> None:
    source = b"""\
import org.springframework.web.servlet.function.*;
class Routes {
    RouterFunction<ServerResponse> routes() {
        return RouterFunctions.route()
            .GET("/files/{name}", request -> ServerResponse.ok()
                .body(request.pathVariable("name")))
            .build();
    }
}
"""

    indexed = index_file("Routes.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert any(entry["kind"] == "spring_functional_route" for entry in indexed["entry_points"])
    assert any(item["kind"] == "http_request_input" for item in indexed["security_sources"])


def test_unrelated_get_builder_is_not_spring_functional_route() -> None:
    source = b"""\
class CacheConfig {
    Object configure(Builder builder) {
        return builder.GET("/files", request -> request.toString());
    }
}
"""

    indexed = index_file("CacheConfig.java", "java", source)

    assert indexed["analysis_status"] == "complete"
    assert not indexed["entry_points"]
    assert not indexed["security_sources"]
