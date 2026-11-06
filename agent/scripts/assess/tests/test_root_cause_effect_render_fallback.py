"""A sibling with no stated effect renders as the default the backend records.

`state_manager/links.py:DEFAULT_ROOT_CAUSE_EFFECT` is `eliminates_attack_path`,
so a link recorded with no `--effect` keeps the sibling's own verdict and leaves
it a residual path. Every read-side fallback has to agree with that, because the
two values carry opposite claims to a reader: `eliminates_attack_path` says this
sibling still needs its own fix, `eliminates_finding` says the root fix covers
it.

The backend always emits the key, so these fallbacks are defensive. They are
still worth pinning: the wrong one fails in the unsafe direction -- a residual
sibling labelled as resolved by the root fix is a finding an operator stops
working on.
"""
from __future__ import annotations

from assess.lib import finding_render


def test_an_export_sibling_without_an_effect_reads_as_a_residual_path() -> None:
    lines = finding_render._root_cause_lines(
        {"root_cause_role": "sibling", "root_cause_slug": "VA-001"}
    )

    rendered = "\n".join(lines)
    assert "residual" in rendered.lower(), rendered
    assert "eliminates this finding" not in rendered, rendered


def test_an_explicit_eliminates_finding_still_says_the_root_fix_covers_it() -> None:
    # The other half of the axis: the fallback must not swallow a stated effect.
    lines = finding_render._root_cause_lines(
        {
            "root_cause_role": "sibling",
            "root_cause_slug": "VA-001",
            "root_cause_effect": "eliminates_finding",
        }
    )

    assert "eliminates this finding" in "\n".join(lines)
