"""The web classifier's dependency-manifest roster comes from one source.

`classify_buckets` carried a hand-typed handful of manifest filenames
(`/package.json`, `/composer.json`, `/composer.lock`, `/yarn.lock`,
`/package-lock.json`) and knew nothing about `/pom.xml`, `/go.sum`,
`/requirements.txt` or any other ecosystem, so an exposed lockfile on a live
host scored nothing at all. The roster now lives in
`assess.lib.dependency_manifests` — the same table the code-side readers walk —
and the classifier derives its fragments from it, so adding an ecosystem is a
one-place change and the web and code tracks cannot drift apart.

The move is additive: every URL that scored `debug_logic` before still does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


def _classify_buckets():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _dependency_manifests():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.dependency_manifests as dm

    return dm


def _classify(url_path: str, *, case_type: str = "unknown"):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        url=f"https://target.example{url_path}",
        url_path=url_path,
        case_type=case_type,
        query_params=json.dumps({}),
        body_params=json.dumps({}),
    )


# The exact fragments the hand-written list carried. Each must keep its bucket
# and its score — this is the "do not break existing classification" pin.
_PREVIOUSLY_CLASSIFIED = (
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/composer.lock",
    "/yarn.lock",
    "/web-inf/web.xml",
)

# Ecosystems the hand-written list never covered. These scored nothing before.
_NEWLY_CLASSIFIED = (
    "/pom.xml",
    "/build.gradle",
    "/gradle.lockfile",
    "/go.mod",
    "/go.sum",
    "/requirements.txt",
    "/pyproject.toml",
    "/poetry.lock",
    "/gemfile.lock",
    "/cargo.lock",
    "/pnpm-lock.yaml",
)


@pytest.mark.parametrize("url_path", _PREVIOUSLY_CLASSIFIED)
def test_previously_classified_manifests_keep_their_bucket(url_path: str) -> None:
    assignment = _classify(url_path)

    assert "debug_logic" in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30


@pytest.mark.parametrize("url_path", _NEWLY_CLASSIFIED)
def test_every_rostered_ecosystem_manifest_now_scores(url_path: str) -> None:
    assignment = _classify(url_path)

    assert "debug_logic" in assignment["matched_buckets"]
    assert assignment["priority_score"] == 30


def test_the_classifier_derives_its_fragments_from_the_shared_roster() -> None:
    cb = _classify_buckets()
    dm = _dependency_manifests()

    fragments = next(
        path_fragments
        for name, _weight, _keys, path_fragments in cb._BUCKETS
        if name == "debug_logic"
    )

    assert set(dm.url_path_fragments()) <= set(fragments)


def test_boundary_precision_survives_the_roster_move() -> None:
    # `/mypom.xml` and `/vendor-requirements.txt` must NOT match: the fragments
    # stay leading-slash anchored exactly as the hand-written list was.
    for url_path in ("/mypom.xml", "/vendor-requirements.txt", "/mygo.mod"):
        assert "debug_logic" not in _classify(url_path)["matched_buckets"], url_path


def test_a_dependency_manifest_path_segment_still_matches() -> None:
    # The existing fragment semantics allow a nested path: `/static/pom.xml`
    # is the same disclosure as a root one.
    assignment = _classify("/static/pom.xml")

    assert "debug_logic" in assignment["matched_buckets"]
