import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[3]
backend_root = repo_root / "orchestrator" / "backend"
sys.path.insert(0, str(backend_root))

# Disable the scheduled backup timer for the entire test run — the timer
# is a daemon thread that would otherwise fire against test-temp data dirs
# that get torn down between tests, producing log noise and interleaved
# sqlite3 handles across fixtures.
os.environ.setdefault("AI_THREAT_HUNTING_BACKUP_DISABLED", "1")

from app.config import settings
from app import db as db_module
from app.main import app
from app.services import engagements as engagement_service


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
    original_db_fingerprint = db_module._startup_database_fingerprint
    original_sync_signature = engagement_service._last_sync_signature
    db_module._startup_database_fingerprint = None
    engagement_service._last_sync_signature = None

    try:
        yield {
            "data_dir": data_dir,
            "frontend_dist_dir": frontend_dist_dir,
            "install_dir": install_dir,
            "engagements_dir": engagements_dir,
        }
    finally:
        db_module._startup_database_fingerprint = original_db_fingerprint
        engagement_service._last_sync_signature = original_sync_signature
        object.__setattr__(settings, "data_dir", original_data_dir)
        object.__setattr__(settings, "frontend_dist_dir", original_frontend_dist_dir)
        object.__setattr__(settings, "install_dir", original_install_dir)


@pytest.fixture
def client(isolate_settings):
    with TestClient(app) as test_client:
        yield test_client
