import sys
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[3]
backend_root = repo_root / "orchestrator" / "backend"
sys.path.insert(0, str(backend_root))

from app.config import settings
from app.main import app


@pytest.fixture(scope="session")
def test_root():
    temp_root = Path(tempfile.mkdtemp(prefix="security-research-tests-"))
    try:
        yield temp_root
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolate_data_dir(test_root):
    original_data_dir = settings.data_dir
    original_projects_dir = settings.projects_dir
    original_auto_launch_runs = settings.auto_launch_runs
    original_frontend_dist_dir = settings.frontend_dist_dir
    data_dir = test_root / "orchestrator-data"
    projects_dir = test_root / "projects-root"
    frontend_dist_dir = test_root / "frontend-dist"
    shutil.rmtree(data_dir, ignore_errors=True)
    shutil.rmtree(projects_dir, ignore_errors=True)
    shutil.rmtree(frontend_dist_dir, ignore_errors=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    projects_dir.mkdir(parents=True, exist_ok=True)
    frontend_dist_dir.mkdir(parents=True, exist_ok=True)
    object.__setattr__(settings, "data_dir", data_dir)
    object.__setattr__(settings, "projects_dir", projects_dir)
    object.__setattr__(settings, "auto_launch_runs", False)
    object.__setattr__(settings, "frontend_dist_dir", frontend_dist_dir)
    try:
        yield test_root
    finally:
        object.__setattr__(settings, "data_dir", original_data_dir)
        object.__setattr__(settings, "projects_dir", original_projects_dir)
        object.__setattr__(settings, "auto_launch_runs", original_auto_launch_runs)
        object.__setattr__(settings, "frontend_dist_dir", original_frontend_dist_dir)


@pytest.fixture
def client(isolate_data_dir):
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        test_client.close()
