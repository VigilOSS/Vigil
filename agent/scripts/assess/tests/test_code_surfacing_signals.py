"""I-110 / I-116 / I-111 / I-112 / I-122 — the code CLI must say what it measured.

Every case here is the same shape of defect: the backend already knows
something the operator needs, and the CLI drops it on the floor.

* `code-coverage` printed `by_classification` only, so "classified but never
  queued" and "queued and not yet worked" both rendered as `0 analyzed`, and a
  readiness blocker named no repo and no repair verb.
* `code-dispatch resolve-triggers` exited 0 having written nothing.
* `code-record classify` could silently clear a repo's structural-index
  binding; the CLI now folds language aliases before sending and reports the
  invalidation when the backend still returns one.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess.commands import code_classify, code_coverage, code_dispatch


# --- code-coverage surfacing -----------------------------------------------


def test_analysis_status_block_distinguishes_classified_from_queued(capsys):
    code_coverage._print_coverage(
        {
            "total_files": 5164,
            "by_classification": {"critical": {"count": 120, "analyzed": 0}},
            "by_status": {"classified": 5164, "queued": 0, "analyzed": 0},
        }
    )
    out = capsys.readouterr().out
    assert "By Analysis Status:" in out
    assert "classified    :  5164" in out
    assert "5164 file(s) classified but never queued" in out
    assert "code-dispatch queue" in out


def test_a_populated_queue_gets_the_census_without_the_hint(capsys):
    code_coverage._print_coverage(
        {"total_files": 10, "by_status": {"classified": 4, "queued": 6}}
    )
    out = capsys.readouterr().out
    assert "queued        :     6" in out
    assert "classified but never queued" not in out


def test_source_identity_block_names_an_unbound_repo_and_its_repair(capsys):
    code_coverage._print_coverage(
        {
            "total_files": 12,
            "repos": [
                {
                    "repo_id": 42,
                    "active_generation": 3,
                    "source_snapshot_quality": "verified",
                    "structural_index_bound": False,
                    "threat_model_bound": True,
                },
                {
                    "repo_id": 40,
                    "active_generation": 1,
                    "source_snapshot_quality": "verified",
                    "structural_index_bound": True,
                    "threat_model_bound": True,
                },
            ],
        }
    )
    out = capsys.readouterr().out
    assert "repo 42: generation 3 | snapshot verified | structural index UNBOUND" in out
    assert "code-index build <snapshot-dir>/source --repo-id 42" in out
    assert "code-index sync --repo-id 42" in out
    assert "neither advances it" in out
    # A bound repo is reported without a repair line.
    assert "--repo-id 40" not in out


def test_readiness_blocker_names_its_repo_and_repair_verb(capsys):
    code_coverage._print_transition_readiness(
        "verify-variant",
        {
            "target_phase": "verify-variant",
            "transition_ready": False,
            "blockers": [
                {
                    "code": "structural_index_stale",
                    "repo_id": 42,
                    "message": "Structural index is not bound to the active generation",
                    "overrideable": False,
                },
                {
                    "code": "files_unclassified",
                    "message": "12 files remain unclassified",
                    "overrideable": True,
                },
            ],
        },
    )
    out = capsys.readouterr().out
    assert "[structural_index_stale] (repo 42)" in out
    assert "[integrity; non-overrideable]" in out
    assert "repair: vigil assess code-index build <snapshot-dir>/source --repo-id 42" in out
    # A blocker with no known repair verb gets no invented one.
    assert "[files_unclassified] 12 files remain unclassified" in out


# --- code-dispatch --------------------------------------------------------


class _StubClient(StubClient):
    def __init__(self, response):
        self._response = response
        self.posts: list[tuple[str, dict]] = []

    def __call__(self, *args, **kwargs):
        return self

    def get(self, path):
        return self._response

    def post(self, path, payload):
        self.posts.append((path, payload))
        return self._response


def _resolve(monkeypatch, tmp_path: Path, response: dict, items: list[dict]):
    triggers = tmp_path / "triggers.json"
    triggers.write_text(json.dumps(items), encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _StubClient(response))
    monkeypatch.setattr(
        code_dispatch,
        "write_json_snapshot",
        lambda *args, **kwargs: SimpleNamespace(name="snapshot.json"),
    )
    cfg = SimpleNamespace(base_url="http://localhost", engagement_key="k", engagement_dir=str(tmp_path))
    code_dispatch._resolve_triggers(cfg, str(triggers), "not_applicable", "note")


def test_resolve_triggers_exits_non_zero_when_nothing_was_written(
    monkeypatch, tmp_path, capsys
):
    with pytest.raises(SystemExit) as excinfo:
        _resolve(
            monkeypatch,
            tmp_path,
            {"resolved": 0, "not_resolved": ["1120"]},
            [{"id": 1120}],
        )
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Resolved 0 of 1 trigger(s)" in captured.out
    assert "unresolved: 1120" in captured.err
    assert "resolved 0 of 1 item(s); 1 unresolved" in captured.err


def test_resolve_triggers_exits_non_zero_on_a_partial_write(
    monkeypatch, tmp_path, capsys
):
    with pytest.raises(SystemExit) as excinfo:
        _resolve(
            monkeypatch,
            tmp_path,
            {"resolved": 1, "not_resolved": ["src/b.py"]},
            [{"trigger_id": 1}, {"file_path": "src/b.py"}],
        )
    assert excinfo.value.code == 1
    assert "unresolved: src/b.py" in capsys.readouterr().err


def test_resolve_triggers_stays_quiet_when_everything_resolved(
    monkeypatch, tmp_path, capsys
):
    _resolve(monkeypatch, tmp_path, {"resolved": 2, "not_resolved": []}, [
        {"trigger_id": 1},
        {"trigger_id": 2},
    ])
    captured = capsys.readouterr()
    assert "Resolved 2 of 2 trigger(s)" in captured.out
    assert "unresolved" not in captured.err


def test_empty_queue_stats_name_the_verb_that_populates_it(monkeypatch, capsys):
    monkeypatch.setattr(
        code_dispatch,
        "AssessmentClient",
        _StubClient({"pending": 0, "processing": 0, "done": 0, "error": 0, "needs_context": 0}),
    )
    code_dispatch._stats(SimpleNamespace(base_url="http://localhost", engagement_key="k"))
    out = capsys.readouterr().out
    assert "classification does not populate it" in out
    assert "code-dispatch queue" in out


# --- code-record classify --------------------------------------------------


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("c++", "cpp"),
        ("C++", "cpp"),
        ("TypeScript", "typescript"),
        ("  python  ", "python"),
        ("", ""),
        ("mylang", "mylang"),
    ],
)
def test_language_aliases_are_folded_before_the_backend_sees_them(supplied, expected):
    assert code_classify._canonical_language(supplied) == expected


def test_canonicalization_applies_to_both_payload_shapes():
    stripped = code_classify._strip_local_fields(
        [{"file_id": 1, "classification": "high", "language": "C++", "repo_id": 42}]
    )
    assert stripped == [{"file_id": 1, "classification": "high", "language": "cpp"}]

    normalized = code_classify._normalize_classifications(
        [{"file_path": "a/b.cc", "classification": "high", "language": "C++"}],
        [{"id": 7, "file_path": "a/b.cc", "repo_id": 42}],
    )
    assert normalized == [
        {"file_id": 7, "classification": "high", "language": "cpp"}
    ]


class _ClassifyClient(StubClient):
    """Drives `code-record classify` end to end over a recorded response."""

    response: dict | None = None
    posts: list[tuple[str, dict, dict]] = []

    def post(self, endpoint: str, payload: dict, **options):
        type(self).posts.append((endpoint, payload, options))
        count = len(payload["classifications"])
        if type(self).response is not None:
            return {**type(self).response, "updated": count, "total": count}
        return {"updated": count, "total": count}


@pytest.fixture
def classify_client(monkeypatch, tmp_path):
    _ClassifyClient.posts = []
    _ClassifyClient.response = None
    monkeypatch.setattr(code_classify, "AssessmentClient", _ClassifyClient)
    monkeypatch.setattr(
        code_classify,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    return _ClassifyClient


def _classify(tmp_path: Path, items: list[dict]) -> None:
    path = tmp_path / "classifications.json"
    path.write_text(json.dumps(items), encoding="utf-8")
    code_classify.run(
        SimpleNamespace(
            classifications_json=str(path), engagement_dir=str(tmp_path)
        )
    )


def test_structural_invalidation_is_reported_with_its_repair_command(
    classify_client, tmp_path, capsys
):
    """Driven through the real response, not a hand-built dict.

    The warning read two keys the backend never emitted, and the test fed it
    those keys directly — so it passed while the feature could not fire.
    """
    classify_client.response = {
        "structural_index_invalidated_repo_ids": [42],
        "language_changes": [
            {
                "file_id": 7,
                "file_path": "a/b.cc",
                "previous_language": "cpp",
                "language": "python",
            }
        ],
    }

    _classify(
        tmp_path,
        [
            {
                "file_id": 7,
                "classification": "high",
                "slot_types": ["NETWORK-INPUT"],
                "language": "python",
                "analysis_priority": 60,
            }
        ],
    )

    err = capsys.readouterr().err
    assert "invalidated the structural-index binding for repo(s): 42" in err
    assert "a/b.cc: cpp -> python" in err
    assert "code-index sync --repo-id 42" in err


def test_a_response_without_invalidation_stays_silent(classify_client, tmp_path, capsys):
    _classify(
        tmp_path,
        [{"file_id": 7, "classification": "medium", "analysis_priority": 40}],
    )

    assert capsys.readouterr().err == ""


# --- AD2: the one uncapped, unchunked bulk assessment write ----------------


def test_classify_chunks_the_array_and_scales_each_chunk_budget(
    classify_client, tmp_path
):
    """A 28k-file pass was one POST, one transaction and a 10s budget."""
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    _classify(
        tmp_path,
        [
            {"file_id": file_id, "classification": "medium", "analysis_priority": 40}
            for file_id in range(1, size + 3)
        ],
    )

    assert [len(payload["classifications"]) for _e, payload, _o in classify_client.posts] == [
        size, 2
    ]
    assert all(endpoint == "code/files/bulk-classify" for endpoint, _p, _o in classify_client.posts)
    full_chunk_budget = classify_client.posts[0][2].get("read_timeout")
    assert full_chunk_budget is not None and full_chunk_budget > 10.0
    # A chunk that fits the default budget is sent unchanged.
    assert classify_client.posts[1][2] == {}


def test_classify_reports_the_total_across_every_chunk(classify_client, tmp_path, capsys):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    _classify(
        tmp_path,
        [
            {"file_id": file_id, "classification": "low", "analysis_priority": 10}
            for file_id in range(1, size + 4)
        ],
    )

    out = capsys.readouterr().out
    assert f"Total classified: {size + 3}" in out
    assert f"low: {size + 3}" in out


# --- D2: a classify-time skip must carry its reason ------------------------


def test_classify_refuses_a_skip_without_a_reason(classify_client, tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        _classify(
            tmp_path, [{"file_id": 7, "classification": "skip", "analysis_priority": 0}]
        )

    assert excinfo.value.code == 1
    assert "skip_reason" in capsys.readouterr().err
    assert classify_client.posts == []


def test_classify_carries_a_skip_reason_to_the_backend(classify_client, tmp_path):
    _classify(
        tmp_path,
        [
            {
                "file_id": 7,
                "classification": "skip",
                "analysis_priority": 0,
                "skip_reason": "vendored-dependency",
            }
        ],
    )

    assert classify_client.posts[0][1]["classifications"] == [
        {
            "file_id": 7,
            "classification": "skip",
            "analysis_priority": 0,
            "skip_reason": "vendored-dependency",
        }
    ]


def test_classify_refuses_a_skip_reason_on_a_reviewed_tier(classify_client, tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        _classify(
            tmp_path,
            [
                {
                    "file_id": 7,
                    "classification": "medium",
                    "analysis_priority": 40,
                    "skip_reason": "vendored-dependency",
                }
            ],
        )

    assert excinfo.value.code == 1
    assert "skip_reason" in capsys.readouterr().err
    assert classify_client.posts == []


def test_classify_resolves_a_skip_reason_through_the_path_lookup_too(
    classify_client, monkeypatch, tmp_path
):
    monkeypatch.setattr(
        code_classify,
        "_fetch_code_files",
        lambda _cfg: [{"id": 9, "repo_id": 1, "file_path": "vendor/lib.js"}],
    )

    _classify(
        tmp_path,
        [
            {
                "file_path": "vendor/lib.js",
                "classification": "skip",
                "analysis_priority": 0,
                "skip_reason": "vendored-dependency",
            }
        ],
    )

    assert classify_client.posts[0][1]["classifications"] == [
        {
            "file_id": 9,
            "classification": "skip",
            "analysis_priority": 0,
            "skip_reason": "vendored-dependency",
        }
    ]


# --- B15 / D1: planning a wave from coverage, not two queue dumps ----------


def test_by_path_renders_the_per_directory_disposition_breakdown(capsys):
    code_coverage._print_coverage_by_path(
        {
            "depth": 2,
            "total": 1,
            "offset": 0,
            "has_more": False,
            "directories": [
                {
                    "path": "src/auth",
                    "repo_key": "acme-api",
                    "files": 12,
                    "loc": 3400,
                    "uncovered_critical_high": 2,
                    "by_classification": {
                        "critical": {"count": 4, "analyzed": 3},
                        "high": {"count": 5, "analyzed": 4},
                    },
                    "by_status": {"analyzed": 7, "queued": 3, "pending": 2},
                    "by_disposition": {
                        "finding": 2, "suspicious": 1, "clean": 4, "skipped": 1
                    },
                    "structural_debt": {"count": 1},
                    "accounted_skips": 1,
                }
            ],
        }
    )

    out = capsys.readouterr().out
    assert "src/auth" in out
    # The disposition census, not just the status census.
    assert "finding" in out
    assert "suspicious" in out
    assert "clean" in out


def test_by_path_without_a_disposition_breakdown_still_renders(capsys):
    code_coverage._print_coverage_by_path(
        {
            "depth": 2, "total": 1, "offset": 0, "has_more": False,
            "directories": [
                {
                    "path": "src/auth", "repo_key": "acme-api", "files": 1,
                    "loc": 10, "uncovered_critical_high": 0,
                    "by_classification": {}, "by_status": {},
                    "structural_debt": {}, "accounted_skips": 0,
                }
            ],
        }
    )

    assert "src/auth" in capsys.readouterr().out


def test_coverage_names_by_path_as_the_wave_planning_read(capsys):
    """Planning a wave meant two `code-dispatch list` dumps; name the verb."""
    code_coverage._print_coverage(
        {
            "total_files": 5164,
            "by_classification": {"critical": {"count": 120, "analyzed": 4}},
            "by_status": {"classified": 100, "queued": 60, "analyzed": 4},
        }
    )

    assert "code-coverage --by-path" in capsys.readouterr().out


def test_inherited_from_is_a_read_labelled_as_inherited(monkeypatch, tmp_path, capsys):
    """Unchanged-hash files keep a readable prior verdict; never a currency claim."""
    requested: list[str] = []

    class _Client(StubClient):
        def get(self, endpoint: str):
            requested.append(endpoint)
            return {
                "origin_generation": 3,
                "active_generation": 4,
                "total": 2,
                "offset": 0,
                "count": 2,
                "has_more": False,
                "files": [
                    {
                        "file_id": 7,
                        "file_path": "src/auth/login.py",
                        "repo_id": 1,
                        "repo_key": "acme-api",
                        "classification": "critical",
                        "file_hash_unchanged": True,
                        "inherited": True,
                        "origin_generation": 3,
                        "disposition": "clean",
                        "recorded_at": "2026-10-01T00:00:00Z",
                    },
                    {
                        "file_id": 8,
                        "file_path": "src/auth/session.py",
                        "repo_id": 1,
                        "classification": "high",
                        "file_hash_unchanged": True,
                        "inherited": True,
                        "origin_generation": 3,
                        "disposition": "finding",
                        "recorded_at": "2026-10-02T00:00:00Z",
                    },
                ],
            }

    monkeypatch.setattr(code_coverage, "AssessmentClient", _Client)
    monkeypatch.setattr(
        code_coverage,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    code_coverage.run(
        SimpleNamespace(
            engagement_dir=str(tmp_path),
            repo_id=None,
            inherited_from=3,
            by_path=False,
            depth=None,
            path_prefix=None,
            limit=None,
            offset=None,
            as_json=False,
            cwe_matrix=False,
            require_gate_pass=False,
            require_transition_ready=None,
            debt_paths=False,
        )
    )

    assert requested == ["code/coverage/inherited?generation=3"]
    out = capsys.readouterr().out
    assert "inherited" in out.lower()
    assert "generation 3" in out
    assert "src/auth/login.py" in out and "clean" in out
    assert "src/auth/session.py" in out and "finding" in out
    # A path alone does not identify a file when several repositories are read.
    assert "acme-api" in out
    # A read, never a currency claim: it must not read as satisfying the gate.
    assert "does not satisfy" in out or "not current" in out


def test_inherited_from_cannot_combine_with_the_by_path_view(capsys):
    with pytest.raises(SystemExit) as excinfo:
        code_coverage._refuse_misplaced_by_path_options(
            SimpleNamespace(
                by_path=True, inherited_from=3, cwe_matrix=False,
                require_gate_pass=False, require_transition_ready=None,
                debt_paths=False,
            )
        )

    assert excinfo.value.code == 2
    assert "--inherited-from" in capsys.readouterr().err


def test_classify_refuses_a_skip_reason_outside_the_standard_set(
    classify_client, tmp_path, capsys
):
    """A prose reason is the one `code-dispatch done` would 400 on too."""
    with pytest.raises(SystemExit) as excinfo:
        _classify(
            tmp_path,
            [
                {
                    "file_id": 7,
                    "classification": "skip",
                    "analysis_priority": 0,
                    "skip_reason": "it looked boring",
                }
            ],
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "it looked boring" in err
    assert "vendored-dependency" in err
    assert classify_client.posts == []


def test_the_classify_skip_vocabulary_is_the_shared_mirror() -> None:
    from assess.lib.contracts import CODE_SKIP_REASONS

    assert code_classify._VALID_SKIP_REASONS == frozenset(CODE_SKIP_REASONS)
