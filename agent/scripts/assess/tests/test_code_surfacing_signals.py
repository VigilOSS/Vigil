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
    assert "code-index build <snapshot-path>/source --repo-id 42" in out
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
    assert "repair: vigil assess code-index build <snapshot-path>/source --repo-id 42" in out
    # A blocker with no known repair verb gets no invented one.
    assert "[files_unclassified] 12 files remain unclassified" in out


# --- code-dispatch --------------------------------------------------------


class _StubClient:
    def __init__(self, response):
        self._response = response
        self.posts: list[tuple[str, dict]] = []

    def __call__(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

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


def test_structural_invalidation_is_reported_with_its_repair_command(capsys):
    code_classify._warn_on_structural_invalidation(
        {
            "updated": 349,
            "total": 349,
            "structural_index_invalidated_repo_ids": [42],
            "language_changes": [
                {"file_path": "a/b.cc", "previous_language": "cpp", "language": "python"}
            ],
        }
    )
    err = capsys.readouterr().err
    assert "invalidated the structural-index binding for repo(s): 42" in err
    assert "a/b.cc: cpp -> python" in err
    assert "code-index sync --repo-id 42" in err


def test_a_response_without_invalidation_stays_silent(capsys):
    code_classify._warn_on_structural_invalidation({"updated": 349, "total": 349})
    assert capsys.readouterr().err == ""
