"""Tests for /admin introspection endpoints used by the host CLI to detect
install-root drift between the running orchestrator and a freshly created
engagement directory.
"""
from __future__ import annotations

from pathlib import Path

from test_engagements_api import write_engagement


def test_get_install_root_returns_settings_install_dir(client, isolate_settings):
    """The CLI uses this value to detect install-root mismatch before its
    first `aith assess` call writes audit data to a stale engagement row."""
    response = client.get("/admin/install-root")
    assert response.status_code == 200
    payload = response.json()
    assert payload["install_root"] == str(isolate_settings["install_dir"])
    assert payload["engagements_root"] == str(isolate_settings["engagements_dir"])


def test_post_sync_engagements_force_resyncs(client, isolate_settings):
    """`aith engagement create` calls this immediately after writing the
    new engagement directory so the matching backend picks it up without
    waiting for the next implicit sync trigger."""
    response = client.post("/admin/sync-engagements")
    assert response.status_code == 200
    initial = response.json()
    assert initial["synced"] is True
    assert initial["install_root"] == str(isolate_settings["install_dir"])
    assert initial["engagement_count"] == 0

    # Drop a fresh engagement on disk and re-sync — count should reflect it.
    write_engagement(isolate_settings["engagements_dir"], key="2026-04-27-101010-admin-sync")
    response = client.post("/admin/sync-engagements")
    assert response.status_code == 200
    follow_up = response.json()
    assert follow_up["engagement_count"] == 1


def test_admin_routes_take_precedence_over_frontend_catchall(client):
    """The catchall `GET /{full_path:path}` route must not shadow /admin GETs.

    Regression guard: if admin_router is registered after the catchall, the
    catchall would intercept admin requests and return 503 (frontend missing)
    or a stale index.html. The CLI would then fall through to "older orch
    without /admin/install-root" and skip the drift check entirely.
    """
    response = client.get("/admin/install-root")
    assert response.status_code == 200
    assert "install_root" in response.json()
