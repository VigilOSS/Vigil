"""C# signals that help agents find reachable security work in large repositories."""

from assess.lib.treesitter_index import index_file


def test_controller_action_marks_implicit_model_binding_as_request_input() -> None:
    source = """using Microsoft.AspNetCore.Mvc;
public class FilesController : ControllerBase {
    [HttpGet("{name}")]
    public IActionResult Read(string name) {
        return Content(System.IO.File.ReadAllText(name));
    }
}
"""
    indexed = index_file("FilesController.cs", "csharp", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(point["name"] == "Read" for point in indexed["entry_points"])
    assert any(source["kind"] == "http_request_input" and "string name" in source["snippet"]
               for source in indexed["security_sources"])
    assert any(sink["kind"] == "file_path" and sink["function"] == "Read"
               for sink in indexed["security_sinks"])


def test_minimal_api_route_handler_has_callable_scope_and_bound_input() -> None:
    source = """var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/files/{name}", (string name) => System.IO.File.ReadAllText(name));
"""
    indexed = index_file("Program.cs", "csharp", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert indexed["functions"]
    assert any(point["kind"] == "minimal_api_route" for point in indexed["entry_points"])
    assert any(source["kind"] == "http_request_input" and "string name" in source["snippet"]
               for source in indexed["security_sources"])
    assert any(sink["kind"] == "file_path" for sink in indexed["security_sinks"])


def test_named_minimal_api_handler_is_entry_and_binds_request_input() -> None:
    source = """var app = builder.Build();
app.MapGet("/files/{name}", ReadFile);
static string ReadFile(string name) => System.IO.File.ReadAllText(name);
class Other { static string ReadFile(string name) => "unrelated"; }
"""
    indexed = index_file("Program.cs", "csharp", source.encode())

    assert [(entry["name"], entry["line"], entry["kind"]) for entry in indexed["entry_points"]] == [
        ("ReadFile", 3, "minimal_api_route")
    ]
    assert any(item["kind"] == "http_request_input" and "string name" in item["snippet"]
               for item in indexed["security_sources"])
    assert any(item["kind"] == "file_path" and item["function"] == "ReadFile"
               for item in indexed["security_sinks"])


def test_http_client_request_is_sink_but_construction_is_not() -> None:
    source = """using System.Net.Http;
public class Fetcher {
    private readonly HttpClient client = new HttpClient();
    public Task<HttpResponseMessage> Fetch(string url) {
        return client.GetAsync(url);
    }
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    fetches = [sink for sink in indexed["security_sinks"] if sink["kind"] == "url_fetch"]
    assert len(fetches) == 1
    assert fetches[0]["function"] == "Fetch"
    assert "GetAsync(url)" in fetches[0]["snippet"]


def test_plain_method_and_injected_service_are_not_request_sources() -> None:
    source = """public class Worker {
    public string Run(string name) => name;
}
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/health", (IHealthService health) => health.Status());
"""
    indexed = index_file("Program.cs", "csharp", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert not any(point["name"] == "Run" for point in indexed["entry_points"])
    assert indexed["security_sources"] == []


def test_non_http_get_async_is_not_a_fetch_sink() -> None:
    source = """using System.Net.Http;
public class Worker {
    private readonly HttpClient http;
    private readonly CacheClient cache;
    public Task<object> Read(string key) => cache.GetAsync(key);
}
"""
    indexed = index_file("Worker.cs", "csharp", source.encode())
    assert not any(sink["kind"] == "url_fetch" for sink in indexed["security_sinks"])


def test_csharp_interface_bases_and_global_using_are_classified() -> None:
    source = """global using System.Net.Http;
public interface IRepo : IDisposable {}
public struct State : IDisposable {}
public class Repo : IRepo, IDisposable {
    public void Load() {}
}
"""
    indexed = index_file("Repo.cs", "csharp", source.encode())
    classes = {cls["name"]: cls for cls in indexed["classes"]}
    for name in ("IRepo", "State", "Repo"):
        assert classes[name]["extends"] == ""
    assert classes["IRepo"]["implements"] == ["IDisposable"]
    assert classes["State"]["implements"] == ["IDisposable"]
    assert classes["Repo"]["implements"] == ["IRepo", "IDisposable"]
    assert "System.Net.Http" in indexed["imports"]
    assert {"Repo", "Load"} <= {item["name"] for item in indexed["exports"]}


def test_external_interface_name_is_not_reported_as_class_inheritance() -> None:
    source = """public class Resource : IDisposable {
    public void Dispose() {}
}
"""
    indexed = index_file("Resource.cs", "csharp", source.encode())
    resource = next(cls for cls in indexed["classes"] if cls["name"] == "Resource")
    assert resource["extends"] == ""
    assert resource["implements"] == ["IDisposable"]


def test_i_prefixed_class_name_can_still_be_inherited() -> None:
    source = """public class IRouter {}
public class Router : IRouter {}
"""
    indexed = index_file("Router.cs", "csharp", source.encode())
    router = next(cls for cls in indexed["classes"] if cls["name"] == "Router")
    assert router["extends"] == "IRouter"
    assert router["implements"] == []


def test_chained_http_client_construction_is_a_fetch_sink() -> None:
    source = """using System.Net.Http;
public class Fetcher {
    public Task<HttpResponseMessage> Fetch(string url) => new HttpClient().GetAsync(url);
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    assert any(sink["kind"] == "url_fetch" and sink["function"] == "Fetch"
               for sink in indexed["security_sinks"])


def test_chained_http_client_factory_request_is_a_fetch_sink() -> None:
    source = """using System.Net.Http;
public class Fetcher {
    private readonly IHttpClientFactory factory;
    public Task<HttpResponseMessage> Fetch(string url) => factory.CreateClient().GetAsync(url);
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    assert any(sink["kind"] == "url_fetch" and sink["function"] == "Fetch"
               for sink in indexed["security_sinks"])


def test_chained_non_http_factory_get_async_is_not_a_fetch_sink() -> None:
    source = """using System.Net.Http;
public class Fetcher {
    private readonly IHttpClientFactory httpFactory;
    private readonly CacheFactory cacheFactory;
    public Task<object> Fetch(string key) => cacheFactory.CreateClient().GetAsync(key);
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    assert not any(sink["kind"] == "url_fetch" for sink in indexed["security_sinks"])


def test_inferred_non_http_factory_client_is_not_a_fetch_sink() -> None:
    source = """public class Fetcher {
    private readonly CacheFactory cacheFactory;
    public Task<object> Fetch(string key) {
        var client = cacheFactory.CreateClient();
        return client.GetAsync(key);
    }
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    assert not any(sink["kind"] == "url_fetch" for sink in indexed["security_sinks"])


def test_inferred_typed_http_factory_client_is_a_fetch_sink() -> None:
    source = """using System.Net.Http;
public class Fetcher {
    private readonly IHttpClientFactory factory;
    public Task<HttpResponseMessage> Fetch(string url) {
        var client = factory.CreateClient();
        return client.GetAsync(url);
    }
}
"""
    indexed = index_file("Fetcher.cs", "csharp", source.encode())
    assert any(sink["kind"] == "url_fetch" and sink["function"] == "Fetch"
               for sink in indexed["security_sinks"])


def test_public_class_with_attribute_is_exported() -> None:
    source = """[Serializable]
public class PublicApi {
    public void Run() {}
}
"""
    indexed = index_file("PublicApi.cs", "csharp", source.encode())
    assert "PublicApi" in {item["name"] for item in indexed["exports"]}


def test_public_class_with_wrapped_modifier_is_exported() -> None:
    source = """public
class PublicApi {
    public void Run() {}
}
"""
    indexed = index_file("PublicApi.cs", "csharp", source.encode())
    assert "PublicApi" in {item["name"] for item in indexed["exports"]}


def test_controller_framework_injections_are_not_request_data() -> None:
    source = """public class FilesController : ControllerBase {
    [HttpGet("{path}")]
    public IActionResult Get(CancellationToken cancellationToken, HttpContext context, string path) {
        return Content(System.IO.File.ReadAllText(path));
    }
}
"""
    indexed = index_file("FilesController.cs", "csharp", source.encode())
    snippets = [item["snippet"] for item in indexed["security_sources"]
                if item["detection"] == "structural_model_binding"]
    assert snippets == ["string path"]
