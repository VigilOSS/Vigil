"""`code-dispatch list` and `fetch` scope queue work to a source subtree.

Fetch claims rows with a bounded SELECT inside its serialized claim, so a path
filter applied after the claim would hand an agent rows outside the subtree it
was dispatched to. Both verbs therefore filter on the server, through one owner
of the path-scope predicate.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _classify_file,
    _create_repo,
    _publish_structural_callables,
    _refresh_repo_files,
    _source_hash,
    write_engagement,
)

_PATHS = (
    "src/auth/login.py",
    "src/auth/nested/session.py",
    "src/auth_extra/token.py",
    "src/billing/refund.py",
    "lib/auth/compat.py",
)


def _seed(client, isolate_settings, engagement_key: str) -> tuple[str, dict[str, int], dict[str, int]]:
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": path,
                "language": "python",
                "loc": 20,
                "file_hash": _source_hash(path),
                "header_snippet": "",
                "git_churn_score": 0,
                "has_past_cve_fix": False,
            }
            for path in _PATHS
        ],
    )
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    file_ids = {str(row["file_path"]): int(row["id"]) for row in files}
    for file_id in file_ids.values():
        _classify_file(client, engagement_key, file_id, "high", 50)
    base = f"/engagements/{engagement_key}/assessment/code"
    created = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_id, "priority": 50} for file_id in file_ids.values()]},
    )
    assert created.status_code == 201, created.text
    listing = client.get(f"{base}/analysis-queue").json()
    item_ids = {str(item["file_path"]): int(item["id"]) for item in listing["items"]}
    assert set(item_ids) == set(_PATHS)
    return base, file_ids, item_ids


def _paths(payload: dict) -> list[str]:
    return sorted(str(item["file_path"]) for item in payload["items"])


def test_path_prefix_is_segment_aware_and_case_sensitive(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-prefix")

    scoped = client.get(f"{base}/analysis-queue?path_prefix=src/auth")
    assert scoped.status_code == 200, scoped.text
    assert _paths(scoped.json()) == ["src/auth/login.py", "src/auth/nested/session.py"]
    assert scoped.json()["total"] == 2

    # A trailing separator names the same directory.
    assert _paths(client.get(f"{base}/analysis-queue?path_prefix=src/auth/").json()) == [
        "src/auth/login.py",
        "src/auth/nested/session.py",
    ]
    # An exact file path is its own prefix.
    assert _paths(
        client.get(f"{base}/analysis-queue?path_prefix=src/auth/login.py").json()
    ) == ["src/auth/login.py"]
    assert client.get(f"{base}/analysis-queue?path_prefix=SRC/auth").json()["total"] == 0
    assert client.get(f"{base}/analysis-queue?path_prefix=src/Auth").json()["total"] == 0
    assert client.get(f"{base}/analysis-queue?path_prefix=src/au").json()["total"] == 0


def test_path_glob_uses_the_case_sensitive_fnmatch_dialect(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-glob")

    assert _paths(client.get(f"{base}/analysis-queue?path_glob=src/*/login.py").json()) == [
        "src/auth/login.py"
    ]
    # fnmatch's `*` crosses separators, exactly as queue submission reads a glob.
    assert _paths(client.get(f"{base}/analysis-queue?path_glob=src/auth*").json()) == [
        "src/auth/login.py",
        "src/auth/nested/session.py",
        "src/auth_extra/token.py",
    ]
    assert _paths(client.get(f"{base}/analysis-queue?path_glob=*/[rt]*.py").json()) == [
        "src/auth_extra/token.py",
        "src/billing/refund.py",
    ]
    assert client.get(f"{base}/analysis-queue?path_glob=*.PY").json()["total"] == 0


def test_path_filters_or_within_a_flag_and_and_across_flags(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-combine")

    assert _paths(
        client.get(
            f"{base}/analysis-queue?path_prefix=src/billing&path_prefix=lib/auth"
        ).json()
    ) == ["lib/auth/compat.py", "src/billing/refund.py"]
    assert _paths(
        client.get(
            f"{base}/analysis-queue?path_glob=*login*&path_glob=*refund*"
        ).json()
    ) == ["src/auth/login.py", "src/billing/refund.py"]
    assert _paths(
        client.get(
            f"{base}/analysis-queue?path_prefix=src&path_glob=*/auth/*"
        ).json()
    ) == ["src/auth/login.py", "src/auth/nested/session.py"]
    assert client.get(
        f"{base}/analysis-queue?path_prefix=src/billing&status=processing"
    ).json()["total"] == 0


def test_path_filtered_total_and_has_more_describe_the_filtered_set(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-page")

    first = client.get(f"{base}/analysis-queue?path_prefix=src/auth&limit=1").json()
    assert first["total"] == 2
    assert first["count"] == 1
    assert first["has_more"] is True
    second = client.get(
        f"{base}/analysis-queue?path_prefix=src/auth&limit=1&offset=1"
    ).json()
    assert second["total"] == 2
    assert second["count"] == 1
    assert second["has_more"] is False
    assert {*first["item_ids"], *second["item_ids"]} == set(
        client.get(f"{base}/analysis-queue?path_prefix=src/auth").json()["item_ids"]
    )


def test_fetch_claims_only_matching_rows_and_leaves_the_rest_pending(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-fetch")

    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "hunter-auth", "path_prefix": ["src/auth"]},
    )
    assert claimed.status_code == 200, claimed.text
    assert sorted(row["file"]["file_path"] for row in claimed.json()) == [
        "src/auth/login.py",
        "src/auth/nested/session.py",
    ]
    pending = client.get(f"{base}/analysis-queue?status=pending").json()
    assert _paths(pending) == [
        "lib/auth/compat.py",
        "src/auth_extra/token.py",
        "src/billing/refund.py",
    ]

    globbed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "hunter-glob", "path_glob": ["*/refund.py"]},
    )
    assert globbed.status_code == 200, globbed.text
    assert [row["file"]["file_path"] for row in globbed.json()] == ["src/billing/refund.py"]


def test_fetch_path_filters_and_with_explicit_item_ids(client, isolate_settings):
    base, _file_ids, item_ids = _seed(client, isolate_settings, "2026-11-05-queue-ids")

    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={
            "limit": 10,
            "agent_name": "hunter-ids",
            "item_ids": [item_ids["src/auth/login.py"], item_ids["src/billing/refund.py"]],
            "path_prefix": ["src/auth"],
        },
    )
    assert claimed.status_code == 200, claimed.text
    assert [row["id"] for row in claimed.json()] == [item_ids["src/auth/login.py"]]
    still_pending = client.get(f"{base}/analysis-queue?status=pending").json()["item_ids"]
    assert item_ids["src/billing/refund.py"] in still_pending
    assert item_ids["src/auth/nested/session.py"] in still_pending


def test_empty_or_absolute_path_filters_are_rejected(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-05-queue-invalid")

    for query in (
        "path_prefix=",
        "path_prefix=/src/auth",
        "path_glob=",
        "path_glob=/src/*",
        "path_prefix=src&path_prefix=",
    ):
        response = client.get(f"{base}/analysis-queue?{query}")
        assert response.status_code == 400, (query, response.text)
    for payload in (
        {"path_prefix": [""]},
        {"path_prefix": ["/src"]},
        {"path_glob": [" "]},
        {"path_glob": ["/src/*"]},
    ):
        response = client.post(
            f"{base}/analysis-queue/fetch",
            json={"limit": 10, "agent_name": "hunter-invalid", **payload},
        )
        assert response.status_code == 400, (payload, response.text)
    assert client.get(f"{base}/analysis-queue?status=processing").json()["total"] == 0
