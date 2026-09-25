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
