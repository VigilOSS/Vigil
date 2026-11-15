"""Files whose depth_floor triggers a reclassification retired are printed, never gated."""
from __future__ import annotations

from assess.commands import code_coverage, transition_phase

_RETIRED = {
    "count": 4,
    "triggers": 5,
    "by_reason": {"family_no_longer_required": 1, "tier_floor_lowered": 4},
    "sample": [
        {"file_path": "src/acme/parser.py", "classification": "medium", "families": ["ssrf"],
         "reasons": ["tier_floor_lowered"], "trigger_ids": [11]},
        {"file_path": "src/acme/upload.py", "classification": "high",
         "families": ["file-upload", "ssrf"],
         "reasons": ["family_no_longer_required", "tier_floor_lowered"], "trigger_ids": [12, 13]},
    ],
    "omitted": 2,
    "full_list": "vigil assess fetch --paginate 'code/triggers?origin=depth_floor"
                 "&supersession_reason=tier_floor_lowered'",
    "detail": "Not owed work; when the tier or tags were lowered in error, re-classify the file.",
}


def test_code_coverage_prints_each_sampled_file_the_remainder_and_the_full_list(capsys) -> None:
    code_coverage._print_depth_floor_retired_files({"gate": {"depth_floor_retired_files": _RETIRED}})

    out = capsys.readouterr().out
    assert "5 depth_floor trigger(s) on 4 file(s)" in out
    assert "tier_floor_lowered 4" in out and "family_no_longer_required 1" in out
    assert "src/acme/parser.py (now medium): ssrf [tier_floor_lowered]" in out
    assert "... +2 more file(s)" in out
    assert _RETIRED["full_list"] in out


def test_transition_phase_carries_them_as_a_non_blocking_advisory() -> None:
    (item,) = transition_phase._code_readiness_advisories({"depth_floor_retired_files": _RETIRED})

    assert item["kind"] == "code_depth_floor_retired_files"
    assert item["severity"] == "advisory"
    assert "src/acme/parser.py" in item["detail"] and "+2 more" in item["detail"]
    assert _RETIRED["full_list"] in item["detail"]
