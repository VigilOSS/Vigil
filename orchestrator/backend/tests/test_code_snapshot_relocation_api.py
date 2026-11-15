"""A repository refresh attests a sealed snapshot wherever its engagement now lives.

A sealed manifest records its source tree as ``"source"`` beside it, so cloning or
moving an engagement keeps every seal attestable. Manifests sealed before that
recorded the absolute path of the engagement they were sealed in; the backend keeps
attesting them while that path still names the same ``<repo_key>/<digest>/source``.
The CLI writer and the backend attestation have to agree on this binding: a fresh
seal the backend cannot attest turns every repository refresh into a 409.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app import db as db_module
from tests.test_code_analysis_api import _verified_repo_payload, write_engagement

_REPO_KEY = "acme-app"


def _engagement_root(engagement_key: str) -> Path:
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT engagement_root FROM engagements WHERE key = ?", (engagement_key,),
        ).fetchone()
    assert row is not None
    return Path(str(row["engagement_root"])).resolve()


def _snapshots(root: Path) -> Path:
    return root / "tools" / "analysis-state" / "code-snapshots"


def _refresh(client, engagement_key: str, payload: dict[str, object]):
    base = f"/engagements/{engagement_key}/assessment/code"
    started = client.post(f"{base}/repos/refresh/start", json=payload)
    assert started.status_code == 201, started.text
    return client.post(
        f"{base}/repos/{started.json()['repo_id']}/refresh/commit",
        json={"refresh_token": started.json()["refresh_token"], "manifest_complete": True},
    )


def _rewrite_source_binding(manifest_path: Path, value: str) -> None:
    manifest_path.parent.chmod(0o755)
    manifest_path.chmod(0o644)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_path"] = value
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o444)
    manifest_path.parent.chmod(0o555)


def _clone_engagement(client, isolate_settings, original: str, clone: str):
    """Seal in *original*, then copy its sealed snapshots into a fresh *clone*."""
    write_engagement(isolate_settings["engagements_dir"], original)
    write_engagement(isolate_settings["engagements_dir"], clone)
    payload = _verified_repo_payload(client, original, _REPO_KEY)
    original_root = _engagement_root(original)
    clone_root = _engagement_root(clone)
    shutil.copytree(_snapshots(original_root), _snapshots(clone_root))
    relocated = dict(payload)
    for field in ("repo_path", "snapshot_manifest_path"):
        relocated[field] = str(
            clone_root / Path(str(payload[field])).relative_to(original_root)
        )
    return payload, relocated


def test_a_fresh_seal_records_the_relative_binding_and_refreshes(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], "2026-11-15-acme-fresh-seal")
    payload = _verified_repo_payload(client, "2026-11-15-acme-fresh-seal", _REPO_KEY)
    manifest = json.loads(Path(str(payload["snapshot_manifest_path"])).read_text(encoding="utf-8"))

    committed = _refresh(client, "2026-11-15-acme-fresh-seal", payload)

    assert manifest["source_path"] == "source"
    assert committed.status_code == 200, committed.text


def test_a_cloned_engagement_refreshes_its_copied_seal(client, isolate_settings) -> None:
    _payload, relocated = _clone_engagement(
        client, isolate_settings, "2026-11-15-acme-original", "2026-11-15-acme-clone",
    )

    committed = _refresh(client, "2026-11-15-acme-clone", relocated)

    assert committed.status_code == 200, committed.text
    repo = client.get(
        f"/engagements/2026-11-15-acme-clone/assessment/code/repos/{committed.json()['repo_id']}"
    ).json()
    assert repo["repo_path"] == relocated["repo_path"]
    assert repo["snapshot_digest"] == relocated["snapshot_digest"]


def test_a_cloned_engagement_refreshes_a_seal_bound_to_the_original_absolute_path(
    client, isolate_settings,
) -> None:
    payload, relocated = _clone_engagement(
        client, isolate_settings, "2026-11-15-acme-legacy-original", "2026-11-15-acme-legacy-clone",
    )
    # Seals written before the relative binding recorded the engagement they were sealed in.
    _rewrite_source_binding(Path(str(relocated["snapshot_manifest_path"])), str(payload["repo_path"]))

    committed = _refresh(client, "2026-11-15-acme-legacy-clone", relocated)

    assert committed.status_code == 200, committed.text


@pytest.mark.parametrize(
    "binding",
    ["../source", "/srv/acme/code-snapshots/acme-app/{other}/source", "/srv/acme/{digest}/source"],
)
def test_a_cloned_seal_bound_to_another_snapshot_is_a_conflict(
    client, isolate_settings, binding: str,
) -> None:
    _payload, relocated = _clone_engagement(
        client, isolate_settings, "2026-11-15-acme-foreign-original", "2026-11-15-acme-foreign-clone",
    )
    _rewrite_source_binding(
        Path(str(relocated["snapshot_manifest_path"])),
        binding.format(digest=relocated["snapshot_digest"], other="e" * 64),
    )

    committed = _refresh(client, "2026-11-15-acme-foreign-clone", relocated)

    assert committed.status_code == 409, committed.text
    assert "source_path mismatch" in committed.json()["detail"]
    assert client.get("/engagements/2026-11-15-acme-foreign-clone/assessment/code/repos").json() == []


def _move_seeded_engagement(client, isolate_settings, request, key: str):
    """Seed one repository in *key*, then move the engagement to another root."""
    from app.config import settings
    from app.services.engagements import clear_list_engagements_cache
    from tests.test_code_analysis_api import _seed_repo

    repo = _seed_repo(client, isolate_settings, key, "acme-moved-repo")
    original_root = _engagement_root(key)
    moved_engagements = original_root.parent.parent / "moved-engagements"
    moved_engagements.mkdir()
    shutil.move(str(original_root), str(moved_engagements / key))
    original_engagements_dir = settings.engagements_dir
    object.__setattr__(settings, "engagements_dir", moved_engagements)
    request.addfinalizer(
        lambda: object.__setattr__(settings, "engagements_dir", original_engagements_dir)
    )
    clear_list_engagements_cache()
    assert client.get("/engagements").status_code == 200
    moved_root = _engagement_root(key)
    assert moved_root == (moved_engagements / key).resolve()
    return repo, moved_root


def test_a_moved_engagement_reads_its_repo_paths_under_its_own_root(
    client, isolate_settings, request
):
    """The recorded paths stay readable; the read names this engagement's sealed copy."""
    key = "2026-11-15-acme-moved-repo-paths"
    repo, moved_root = _move_seeded_engagement(client, isolate_settings, request, key)
    recorded_source, recorded_manifest = repo["repo_path"], repo["snapshot_manifest_path"]
    tail = Path(recorded_source).parts[-3:]

    base = f"/engagements/{key}/assessment/code"
    listed = client.get(f"{base}/repos").json()
    single = client.get(f"{base}/repos/{repo['id']}").json()

    snapshots = moved_root / "tools" / "analysis-state" / "code-snapshots"
    for read in (single, next(row for row in listed if row["id"] == repo["id"])):
        assert read["repo_path"] == str(snapshots.joinpath(*tail))
        assert read["snapshot_manifest_path"] == str(snapshots.joinpath(*tail[:2], "manifest.json"))
        assert read["recorded_repo_path"] == recorded_source
        assert read["recorded_snapshot_manifest_path"] == recorded_manifest
    with db_module.get_connection() as connection:
        stored = connection.execute(
            "SELECT repo_path FROM code_repos WHERE id = ?", (repo["id"],)
        ).fetchone()
    assert stored["repo_path"] == recorded_source


def test_a_finding_location_under_the_moved_snapshot_is_stored_repo_relative(
    client, isolate_settings, request
):
    """A location the author copied from the moved engagement's sealed source
    names the same file as its repo-relative form, so both normalise alike."""
    from app.services.state_manager.findings import _normalize_file_location

    key = "2026-11-15-acme-moved-finding-location"
    repo, moved_root = _move_seeded_engagement(client, isolate_settings, request, key)
    tail = Path(str(repo["repo_path"])).parts[-3:]
    moved_source = moved_root.joinpath(*_snapshots(Path()).parts, *tail)
    with db_module.get_connection() as connection:
        engagement_id = int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (key,),
        ).fetchone()["id"])
        normalised = _normalize_file_location(
            connection, engagement_id, f"file:{moved_source}/src/parser.py:12",
            repo_id=int(repo["id"]),
        )
    assert normalised == "file:src/parser.py:12"
