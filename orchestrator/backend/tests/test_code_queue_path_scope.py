"""`code-dispatch list` and `fetch` scope queue work to a source subtree.

Fetch claims rows with a bounded SELECT inside its serialized claim, so a path
filter applied after the claim would hand an agent rows outside the subtree it
was dispatched to. Both verbs therefore filter on the server, through one owner
of the path-scope predicate.
"""
from __future__ import annotations

from app import db as db_module

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


def _age_all_leases(engagement_key: str, *, minutes: int) -> None:
    with db_module.get_connection() as connection:
        connection.execute(
            """
            UPDATE code_analysis_queue
            SET consumed_at = datetime('now', ? || ' minutes'),
                last_heartbeat_at = datetime('now', ? || ' minutes')
            WHERE engagement_id = (SELECT id FROM engagements WHERE key = ?)
              AND status = 'processing'
            """,
            (f"-{minutes}", f"-{minutes}", engagement_key),
        )


def _processing_paths(client, base: str) -> list[str]:
    return _paths(client.get(f"{base}/analysis-queue?status=processing").json())


def test_reset_stale_takes_exactly_what_its_preview_showed(client, isolate_settings):
    """The destructive sweep must be scopable like its read-only preview.

    A single global window makes a ten-minute sweep aimed at one lane discard a
    deep-analysis lane that legitimately ran longer, superseding every receipt
    it had accumulated. `reset-stale` therefore takes the same predicates
    `list --stale-minutes N` takes, through the same `_file_path_scope_sql`
    owner, so the preview and the sweep cannot disagree.
    """
    engagement_key = "2026-11-06-queue-reset-scope"
    base, _file_ids, item_ids = _seed(client, isolate_settings, engagement_key)
    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "hunter-all"},
    )
    assert claimed.status_code == 200, claimed.text
    assert len(claimed.json()) == len(_PATHS)
    _age_all_leases(engagement_key, minutes=45)

    preview = client.get(
        f"{base}/analysis-queue?stale_minutes=30&path_prefix=src/auth"
    ).json()
    assert _paths(preview) == ["src/auth/login.py", "src/auth/nested/session.py"]

    scoped = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "path_prefix": ["src/auth"]},
    )
    assert scoped.status_code == 200, scoped.text
    assert scoped.json()["reset"] == 2
    assert _paths(client.get(f"{base}/analysis-queue?status=pending").json()) == [
        "src/auth/login.py",
        "src/auth/nested/session.py",
    ]
    assert _processing_paths(client, base) == [
        "lib/auth/compat.py",
        "src/auth_extra/token.py",
        "src/billing/refund.py",
    ]

    globbed = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "path_glob": ["*/refund.py"]},
    )
    assert globbed.status_code == 200, globbed.text
    assert globbed.json()["reset"] == 1
    assert _processing_paths(client, base) == [
        "lib/auth/compat.py",
        "src/auth_extra/token.py",
    ]

    # An unmatched scope is a no-op, never a silent global sweep.
    missed = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "path_prefix": ["src/au"]},
    )
    assert missed.status_code == 200, missed.text
    assert missed.json()["reset"] == 0
    assert len(_processing_paths(client, base)) == 2


def test_reset_stale_scopes_by_repo_theme_and_queue_mode(client, isolate_settings):
    engagement_key = "2026-11-06-queue-reset-lane"
    base, file_ids, _item_ids = _seed(client, isolate_settings, engagement_key)
    other_repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-other")
    other_files = _refresh_repo_files(
        client,
        engagement_key,
        int(other_repo["id"]),
        [
            {
                "file_path": "src/other/handler.py",
                "language": "python",
                "loc": 20,
                "file_hash": _source_hash("src/other/handler.py"),
                "header_snippet": "",
                "git_churn_score": 0,
                "has_past_cve_fix": False,
            }
        ],
    )
    _publish_structural_callables(
        client, engagement_key, int(other_repo["id"]), other_files, {}
    )
    other_id = int(other_files[0]["id"])
    _classify_file(client, engagement_key, other_id, "high", 50)
    themed = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {"file_id": other_id, "priority": 50, "batch_theme": "deep-analysis"}
            ]
        },
    )
    assert themed.status_code == 201, themed.text
    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 10, "agent_name": "hunter-all"},
    )
    assert claimed.status_code == 200, claimed.text
    _age_all_leases(engagement_key, minutes=45)

    by_theme = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "batch_theme": "deep-analysis"},
    )
    assert by_theme.status_code == 200, by_theme.text
    assert by_theme.json()["reset"] == 1
    assert _paths(client.get(f"{base}/analysis-queue?status=pending").json()) == [
        "src/other/handler.py"
    ]

    by_repo = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "repo_id": int(other_repo["id"])},
    )
    assert by_repo.status_code == 200, by_repo.text
    assert by_repo.json()["reset"] == 0

    by_mode = client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "queue_mode": "reanalysis"},
    )
    assert by_mode.status_code == 200, by_mode.text
    assert by_mode.json()["reset"] == 0
    assert len(_processing_paths(client, base)) == len(_PATHS)

    assert client.post(
        f"{base}/analysis-queue/reset-stale",
        json={"minutes": 30, "path_prefix": ["/src"]},
    ).status_code == 400


def _file_paths(payload: dict) -> list[str]:
    return [str(item["file_path"]) for item in payload["items"]]


def test_code_files_scopes_by_path_and_sorts_on_a_closed_enum(client, isolate_settings):
    """`code/files` is the inventory every lane reads before it dispatches.

    Without path scoping an operator planning a subtree wave had to page the
    whole repository and filter client-side, and `search=` is a substring match
    rather than the whole-segment predicate `fetch` claims with — so the plan
    and the claim could disagree about what "under src/auth" means. Sorting is a
    closed enum so an unknown column can never reach the ORDER BY, and unknown
    query params are refused per route rather than silently ignored.
    """
    engagement_key = "2026-11-06-code-files-scope"
    base, file_ids, _item_ids = _seed(client, isolate_settings, engagement_key)

    scoped = client.get(f"{base}/files?path_prefix=src/auth")
    assert scoped.status_code == 200, scoped.text
    assert sorted(_file_paths(scoped.json())) == [
        "src/auth/login.py",
        "src/auth/nested/session.py",
    ]
    assert scoped.json()["total"] == 2
    # Whole segments, byte-exact — the same predicate `fetch` claims with.
    assert client.get(f"{base}/files?path_prefix=src/au").json()["total"] == 0
    assert client.get(f"{base}/files?path_prefix=SRC/auth").json()["total"] == 0
    assert sorted(
        _file_paths(client.get(f"{base}/files?path_glob=*/refund.py").json())
    ) == ["src/billing/refund.py"]
    assert sorted(
        _file_paths(
            client.get(
                f"{base}/files?path_prefix=src&path_glob=*/auth/*"
            ).json()
        )
    ) == ["src/auth/login.py", "src/auth/nested/session.py"]
    assert client.get(f"{base}/files?path_prefix=/src").status_code == 400

    by_path = client.get(f"{base}/files?sort=file_path&order=asc")
    assert by_path.status_code == 200, by_path.text
    assert _file_paths(by_path.json()) == sorted(_PATHS)
    descending = client.get(f"{base}/files?sort=file_path&order=desc")
    assert _file_paths(descending.json()) == sorted(_PATHS, reverse=True)
    # One default direction for every column, so `order` never has to be
    # guessed per sort key.
    assert _file_paths(client.get(f"{base}/files?sort=file_path").json()) == sorted(
        _PATHS, reverse=True
    )
    # The default ordering is unchanged for a caller that names no sort.
    default_order = client.get(f"{base}/files").json()
    assert _file_paths(default_order) == _file_paths(
        client.get(f"{base}/files?sort=analysis_priority&order=desc").json()
    )
    assert client.get(f"{base}/files?sort=file_hash").status_code == 422
    assert client.get(f"{base}/files?order=sideways").status_code == 422

    # An unknown query param is a typo, and a silently ignored filter returns a
    # page that is wrong rather than empty.
    unknown = client.get(f"{base}/files?path_prefixes=src/auth")
    assert unknown.status_code == 400, unknown.text
    assert "path_prefixes" in unknown.json()["detail"]
    assert "path_prefix" in unknown.json()["detail"]
    assert file_ids
