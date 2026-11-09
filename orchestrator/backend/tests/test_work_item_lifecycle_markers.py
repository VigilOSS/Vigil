"""Pins the observable behaviour of the work-item lifecycle markers.

The done/error/mark-manual markers share one prologue (engagement 404, id
normalization, the empty-id envelope) and one engagement-scoped UPDATE shape,
and differ only in their SET clause. These tests pin what an operator sees from
each of them — the envelope, the SET's effect on the row, and the ``error``
marker's retry-count increment, which is observable through the bound that
``retry-errors`` compares against.
"""
import json

ENGAGEMENT_KEY = "2026-07-08-000000-pins11"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    eng = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "AcmeWorkItems", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _observe(client, *, url) -> int:
    response = client.post(
        f"{BASE}/request-observations",
        json={
            "url": url,
            "method": "GET",
            "query_schema": {"q": "string"},
            "discovery_source": "test",
            "work_item": {"case_type": "api"},
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["work_item"]["id"])


def _status_counts(client) -> dict[str, int]:
    stats = client.get(f"{BASE}/work-items/stats?by=status").json()
    return {row["status"]: row["count"] for row in stats["status"]}


def test_done_marker_envelope_and_status(client, isolate_settings):
    _seed(client, isolate_settings)
    first = _observe(client, url="https://app.example/api/done-a")
    _observe(client, url="https://app.example/api/done-b")

    empty = client.post(f"{BASE}/work-items/done", json={"ids": []})
    assert empty.status_code == 200
    assert empty.json() == {"affected": 0, "ids": []}

    marked = client.post(f"{BASE}/work-items/done", json={"ids": [first, first, -1]})
    assert marked.status_code == 200
    assert marked.json() == {"affected": 1, "ids": [first, -1]}
    assert _status_counts(client).get("done") == 1


def test_error_marker_increments_retry_count(client, isolate_settings):
    _seed(client, isolate_settings)
    item = _observe(client, url="https://app.example/api/err")

    marked = client.post(f"{BASE}/work-items/error", json={"ids": [item]})
    assert marked.status_code == 200
    assert marked.json() == {"affected": 1, "ids": [item]}
    assert _status_counts(client).get("error") == 1

    # One error leaves retry_count at 1, so a bound of 1 reclaims nothing.
    held = client.post(f"{BASE}/work-items/retry-errors", json={"max_retries": 1})
    assert held.json() == {"affected": 0, "max_retries": 1}
    assert _status_counts(client).get("error") == 1

    reclaimed = client.post(f"{BASE}/work-items/retry-errors", json={"max_retries": 2})
    assert reclaimed.json() == {"affected": 1, "max_retries": 2}
    assert _status_counts(client).get("pending") == 1


def test_manual_marker_stamps_classifier_version_only(client, isolate_settings):
    _seed(client, isolate_settings)
    item = _observe(client, url="https://app.example/api/manual")

    empty = client.post(f"{BASE}/work-items/mark-manual", json={"ids": []})
    assert empty.json() == {"affected": 0, "ids": []}

    marked = client.post(f"{BASE}/work-items/mark-manual", json={"ids": [item]})
    assert marked.status_code == 200
    assert marked.json() == {"affected": 1, "ids": [item]}

    stats = client.get(f"{BASE}/work-items/stats?by=classifier_version").json()
    assert [
        (row["classifier_version"], row["status"], row["count"]) for row in stats["rows"]
    ] == [("manual", "pending", 1)]


def test_markers_refuse_an_unknown_engagement(client, isolate_settings):
    _seed(client, isolate_settings)
    for verb in ("done", "error", "mark-manual"):
        response = client.post(
            f"/engagements/2026-07-08-000000-absent/assessment/work-items/{verb}",
            json={"ids": []},
        )
        assert response.status_code == 404, (verb, response.status_code)


# ---------------------------------------------------------------------------
# App-unit scoring: the per-signal points, evidence keys and evidence ORDER.
# `evidence_json` is stored and rendered verbatim, so the insertion order of
# both the signal keys and each signal's own flags is operator-visible.
# ---------------------------------------------------------------------------
from app.services.state_manager import app_units  # noqa: E402


def _variant(path, **over):
    row = {
        "normalized_path": path,
        "method": "GET",
        "auth_context": "anonymous",
        "query_schema_json": "{}",
        "body_schema_json": "{}",
        "path_schema_json": "{}",
        "cookie_schema_json": "{}",
        "content_type_family": "unknown",
    }
    row.update(over)
    return row


def test_structure_scoring_bands_and_evidence_order():
    low_total, low = app_units._score_structure(
        [
            _variant("/a", content_type_family="json", query_schema_json='{"q": "s"}'),
            _variant("/b", method="POST"),
        ],
        [200, 302],
        1,
    )
    assert list(low) == [
        "path_richness",
        "method_diversity",
        "param_richness",
        "dynamic_stateful",
        "framework_fingerprint",
    ]
    assert low["path_richness"] == {"points": 1, "distinct_paths": 2}
    assert low["method_diversity"] == {"points": 1, "methods": ["GET", "POST"]}
    assert low["param_richness"] == {"points": 1, "param_bearing_variants": 1}
    assert low["dynamic_stateful"] == {
        "points": 2,
        "dynamic_content_variants": 1,
        "session_cookie_variants": 0,
        "status_routing": True,
    }
    assert low["framework_fingerprint"] == {"points": 1, "framework_components": 1}
    assert list(low["dynamic_stateful"]) == [
        "points",
        "dynamic_content_variants",
        "session_cookie_variants",
        "status_routing",
    ]
    assert low_total == 6

    top_variants = [
        _variant(
            f"/p{index}",
            method="PUT",
            content_type_family="json",
            body_schema_json='{"b": "s"}',
            cookie_schema_json='{"sid": "s"}',
        )
        for index in range(20)
    ]
    top_total, top = app_units._score_structure(top_variants, [200], 2)
    assert top["path_richness"]["points"] == 3
    assert top["method_diversity"]["points"] == 2
    assert top["param_richness"] == {"points": 2, "param_bearing_variants": 20}
    assert top["dynamic_stateful"]["points"] == 2
    assert top["framework_fingerprint"] == {"points": 2, "framework_components": 2}
    assert top_total == 11

    zero_total, zero = app_units._score_structure([_variant("/only")], [], 0)
    assert [signal["points"] for signal in zero.values()] == [0, 0, 0, 0, 0]
    assert zero["path_richness"] == {"points": 0, "distinct_paths": 1}
    assert zero["method_diversity"] == {"points": 0, "methods": ["GET"]}
    assert zero_total == 0


_RISK_SIGNAL_ORDER = [
    "auth_surface",
    "auth_gated_routing",
    "object_references",
    "privileged_write",
    "api_inventory",
    "business_workflow",
    "version_skew",
    "auth_context_diversity",
    "gf_density",
]


def test_risk_scoring_signals_and_evidence_order():
    full_total, full = app_units._score_risk(
        [
            _variant("/admin/users", query_schema_json='{"user_id": "s"}'),
            _variant("/swagger", auth_context="user"),
            _variant("/checkout"),
            _variant("/login"),
        ],
        [401],
        {
            "auth_entry",
            "object_reference",
            "privileged_write",
            "api_documentation",
            "workflow_token",
        },
        {"idor", "xss", "sqli"},
        True,
    )
    assert list(full) == _RISK_SIGNAL_ORDER
    assert full["auth_surface"] == {
        "points": 3, "auth_surface": True, "auth_path": True,
    }
    assert full["auth_gated_routing"] == {"points": 2, "saw_401_403": True}
    assert full["object_references"] == {
        "points": 3, "object_surface": True, "id_like_params": True, "idor_class": True,
    }
    assert full["privileged_write"] == {
        "points": 3, "priv_surface": True, "priv_path": True,
    }
    assert full["api_inventory"] == {
        "points": 3, "api_surface": True, "api_path": True,
    }
    assert full["business_workflow"] == {
        "points": 3, "workflow_surface": True, "workflow_path": True,
    }
    assert full["version_skew"] == {"points": 2, "version_skew": True}
    assert full["auth_context_diversity"] == {
        "points": 2, "auth_contexts": ["anonymous", "user"],
    }
    assert full["gf_density"] == {
        "points": 2, "distinct_classes": ["idor", "sqli", "xss"],
    }
    assert [list(full[key]) for key in _RISK_SIGNAL_ORDER] == [
        ["points", "auth_surface", "auth_path"],
        ["points", "saw_401_403"],
        ["points", "object_surface", "id_like_params", "idor_class"],
        ["points", "priv_surface", "priv_path"],
        ["points", "api_surface", "api_path"],
        ["points", "workflow_surface", "workflow_path"],
        ["points", "version_skew"],
        ["points", "auth_contexts"],
        ["points", "distinct_classes"],
    ]
    assert full_total == 23

    surface_total, surface = app_units._score_risk(
        [_variant("/a")],
        [200],
        {"privileged_write", "api_documentation", "workflow_token"},
        set(),
        False,
    )
    assert [surface[key]["points"] for key in _RISK_SIGNAL_ORDER] == [
        0, 0, 0, 2, 2, 2, 0, 0, 0,
    ]
    assert surface["privileged_write"] == {
        "points": 2, "priv_surface": True, "priv_path": False,
    }
    assert surface_total == 6

    path_total, path_only = app_units._score_risk(
        [_variant("/admin"), _variant("/api-docs"), _variant("/billing")],
        [],
        set(),
        {"xss"},
        False,
    )
    assert [path_only[key]["points"] for key in _RISK_SIGNAL_ORDER] == [
        0, 0, 0, 1, 1, 1, 0, 0, 1,
    ]
    assert path_only["api_inventory"] == {
        "points": 1, "api_surface": False, "api_path": True,
    }
    assert path_total == 4


# ---------------------------------------------------------------------------
# The coverage list-window clamp: a second line of defence behind each route's
# own Query(le=MAX_*) bound, and therefore not observable over HTTP.
# ---------------------------------------------------------------------------
import pytest  # noqa: E402

from app.services.state_manager import coverage  # noqa: E402

_WINDOW_CASES = [
    ((100, 0), (100, 0)),
    ((0, 0), (1, 0)),
    ((-7, -3), (1, 0)),
    ((1, 25), (1, 25)),
    ((5000, 10), (5000, 10)),
    ((5001, 10), (5000, 10)),
    ((10**9, 2), (5000, 2)),
]


@pytest.mark.parametrize(
    "maximum",
    [
        coverage.MAX_REQUEST_LIST_LIMIT,
        coverage.MAX_PROBE_RUN_LIST_LIMIT,
        coverage.MAX_ASSESSMENT_LIST_LIMIT,
    ],
)
@pytest.mark.parametrize("given,expected", _WINDOW_CASES)
def test_bounded_window_clamps_limit_and_offset(maximum, given, expected):
    assert maximum == 5000
    assert coverage._bounded_window(given[0], given[1], maximum=maximum) == expected
