import shutil
import sys
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
def isolate_settings(test_root):
    original_data_dir = settings.data_dir
    original_frontend_dist_dir = settings.frontend_dist_dir
    original_install_dir = settings.install_dir
    data_dir = test_root / "orchestrator-data"
    frontend_dist_dir = test_root / "frontend-dist"
    install_dir = test_root / "install-root"
    engagements_dir = install_dir / "agent" / "engagements"

    shutil.rmtree(data_dir, ignore_errors=True)
    shutil.rmtree(frontend_dist_dir, ignore_errors=True)
    shutil.rmtree(install_dir, ignore_errors=True)

    data_dir.mkdir(parents=True, exist_ok=True)
    frontend_dist_dir.mkdir(parents=True, exist_ok=True)
    engagements_dir.mkdir(parents=True, exist_ok=True)

    object.__setattr__(settings, "data_dir", data_dir)
    object.__setattr__(settings, "frontend_dist_dir", frontend_dist_dir)
    object.__setattr__(settings, "install_dir", install_dir)

    try:
        yield {
            "data_dir": data_dir,
            "frontend_dist_dir": frontend_dist_dir,
            "install_dir": install_dir,
            "engagements_dir": engagements_dir,
        }
    finally:
        object.__setattr__(settings, "data_dir", original_data_dir)
        object.__setattr__(settings, "frontend_dist_dir", original_frontend_dist_dir)
        object.__setattr__(settings, "install_dir", original_install_dir)


@pytest.fixture
def client(isolate_settings):
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        test_client.close()
