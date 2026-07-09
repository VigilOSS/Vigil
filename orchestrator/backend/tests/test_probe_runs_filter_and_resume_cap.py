"""Wave-0 read-path fixes:

- D1: ``GET /probe-runs`` gained optional exact-match filters
  (attack_family/target_host/target_path/auth_context/result_status). Previously
  it accepted only limit/offset, so ``fetch probe-runs?attack_family=X`` silently
  returned the full unfiltered set (a no-op filter that read as "N rows for X").
- D3: the resume-brief Per-Input Coverage grid was hard-capped at 20 cells with
  no override; ``per_input_limit`` (0 = all) now lets a caller pull every cell
  while ``cells_count`` still reports the true total.
"""
from __future__ import annotations

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-07-08-000000-probefilter"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _probe(**overrides) -> dict:
    payload = {
        "attack_family": "sqli",
        "tool_name": "sqlmap",
        "input_slot": "query",
        "payload_value": "1 OR 1=1",
        "target_host": "example.com",
        "target_path": "/x",
        "target_port": 443,
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------- #
# D1 — probe-runs filters
# --------------------------------------------------------------------------- #


def test_probe_runs_attack_family_filter_is_honored(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/probe-runs", json=_probe(attack_family="sqli", target_path="/a")).status_code == 201
    assert client.post(f"{BASE}/probe-runs", json=_probe(attack_family="ssrf", target_path="/b")).status_code == 201

    # Unfiltered still returns both.
    assert {r["attack_family"] for r in client.get(f"{BASE}/probe-runs").json()} == {"sqli", "ssrf"}

    # The filter now actually filters (was a silent no-op returning both).
    sqli = client.get(f"{BASE}/probe-runs?attack_family=sqli").json()
    assert [r["attack_family"] for r in sqli] == ["sqli"]

    # A family with no rows returns an empty list, not the full set.
    assert client.get(f"{BASE}/probe-runs?attack_family=xxe").json() == []


def test_probe_runs_filters_compose(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(
        f"{BASE}/probe-runs",
        json=_probe(attack_family="ssrf", target_host="a.example.com", target_path="/one"),
    ).status_code == 201
    assert client.post(
        f"{BASE}/probe-runs",
        json=_probe(attack_family="ssrf", target_host="b.example.com", target_path="/two"),
    ).status_code == 201

    rows = client.get(f"{BASE}/probe-runs?attack_family=ssrf&target_host=b.example.com").json()
    assert len(rows) == 1
    assert rows[0]["target_host"] == "b.example.com"
    assert rows[0]["target_path"] == "/two"


# --------------------------------------------------------------------------- #
# D3 — resume-brief per-input cell cap override
# --------------------------------------------------------------------------- #


def test_resume_brief_per_input_cells_default_cap_and_all(client, isolate_settings):
    _seed(client, isolate_settings)
    # 25 distinct cells (distinct target_path → distinct probe_key & cell key).
    for i in range(25):
        assert client.post(
            f"{BASE}/probe-runs", json=_probe(attack_family="sqli", target_path=f"/p{i}")
        ).status_code == 201

    default = client.get(f"{BASE}/resume-brief").json()["per_input_coverage"]
    assert len(default["cells"]) == 20          # default cap preserved
    assert default["cells_count"] == 25         # true total still reported

    allc = client.get(f"{BASE}/resume-brief?per_input_limit=0").json()["per_input_coverage"]
    assert len(allc["cells"]) == 25             # 0 == all
    assert allc["cells_count"] == 25

    capped = client.get(f"{BASE}/resume-brief?per_input_limit=5").json()["per_input_coverage"]
    assert len(capped["cells"]) == 5            # explicit smaller cap honored
    assert capped["cells_count"] == 25
