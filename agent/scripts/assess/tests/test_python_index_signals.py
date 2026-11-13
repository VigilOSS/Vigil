"""Framework input signals that direct Python code review toward reachable code."""

from assess.lib.treesitter_index import index_file


def test_fastapi_bound_scalar_parameter_is_request_source() -> None:
    source = """from fastapi import FastAPI
app = FastAPI()

@app.get("/files/{name}")
def read(name: str):
    return open(name).read()
"""
    indexed = index_file("api.py", "python", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(point["name"] == "read" for point in indexed["entry_points"])
    assert any(item["kind"] == "http_request_input" and "name: str" in item["snippet"]
               for item in indexed["security_sources"])


def test_django_request_mapping_is_request_source() -> None:
    source = """def read(request):
    name = request.GET['name']
    return open(name).read()
"""
    indexed = index_file("views.py", "python", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "http_request_input" and "request.GET" in item["snippet"]
               for item in indexed["security_sources"])


def test_fastapi_dependency_parameter_is_not_a_request_source() -> None:
    source = """from fastapi import FastAPI, Depends, Request
app = FastAPI()

@app.get("/health")
def health(request: Request, service: Service = Depends(get_service)):
    return service.status()
"""
    indexed = index_file("api.py", "python", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert indexed["security_sources"] == []


def test_flask_verb_shortcut_route_is_labelled_flask_and_binds_its_path_variable() -> None:
    """Flask 2's `@app.get` reads like FastAPI's; the file's import decides."""
    source = """from flask import Flask
app = Flask(__name__)

@app.get("/files/<name>")
def read(name):
    return open(name).read()
"""
    indexed = index_file("app.py", "python", source.encode())
    assert indexed["analysis_status"] == "complete"
    assert [(point["name"], point["kind"]) for point in indexed["entry_points"]] == [
        ("read", "flask_route")
    ]
    assert any(item["kind"] == "http_request_input" and item["snippet"] == "name"
               for item in indexed["security_sources"])


def test_streaming_fallback_labels_a_flask_verb_shortcut_route_flask() -> None:
    from assess.lib.treesitter_index import streaming_security_fallback

    source = b'from flask import Flask\napp = Flask(__name__)\n\n@app.post("/files")\ndef upload():\n    pass\n'
    indexed = streaming_security_fallback(
        "app.py", "python", iter([source]), degradation_reason="forced_for_test"
    )
    assert {point["kind"] for point in indexed["entry_points"]} == {"flask_route"}
