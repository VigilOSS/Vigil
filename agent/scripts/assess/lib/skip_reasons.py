"""The standard skip vocabulary, kept apart from the contract corpus so the
hottest helper calls (`code-dispatch heartbeat`, `done`) can read it cheaply."""
from __future__ import annotations


# MIRRORS app.services.code_analysis.SKIP_REASONS, the one standard vocabulary a
# skip is accounted under. Two doors now write it — `code-dispatch done
# --skip-reason` at closeout and `code-record classify` at classification time —
# so the set is named once here instead of spelled out per contract. Agent code
# cannot import the backend; pinned in sync by
# test_the_cli_and_api_agree_on_one_closeout_vocabulary.
CODE_SKIP_REASONS: tuple[str, ...] = (
    "test-fixture",
    "generated-code",
    "minified",
    "out-of-scope-language",
    "vendored-dependency",
)
