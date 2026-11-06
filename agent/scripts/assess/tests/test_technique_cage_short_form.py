"""The technique-cage lint sees a SHORT themed objective, not just a recipe.

The lint fired only on a STRUCTURED recipe: >=3 step-list or imperative-verb
lines whose own lines pre-named >=2 bug classes. A one-line themed objective —
"Hunt SQL injection and XSS in the billing module files" — has no list to count
and no verb the lint recognised (`hunt` was not an imperative verb), so it
passed silently. That is the shape that caps a discovery specialist at the
families the operator happened to think of, while the backend's own
`applicable_vuln_classes` for the same files keeps asking for more; in the field
it left a batch of items owing auth, redirect and data-exposure classes.

Advisory by design, exactly like the long form: the signal POINTS at the measured
coverage picture. `agent/operator-core-code.md` carries the operative
Pre-Dispatch check; nothing here may become a gate.

The existing cage tests live in `orchestrator/backend/tests/test_vigil_cli.py`
(`test_detect_technique_cage_*`); this file holds the short-form additions so the
two workstreams do not share a file.
"""
from __future__ import annotations

import pytest

from assess.lib import contracts
from assess.lib.contracts import _detect_technique_cage
from assess.lib.vuln_taxonomy import all_classes


# The objective the field failure was dispatched with.
_THEMED = "Hunt SQL injection and XSS in the billing module files"


def test_a_short_two_family_objective_warns_on_a_discovery_dispatch() -> None:
    warnings = _detect_technique_cage(_THEMED, role="code-vuln-hunter")

    assert warnings, "a short two-family objective is the cage in its compact form"
    message = warnings[0]
    assert "technique cage" in message
    assert "applicable_vuln_classes" in message, (
        "the warning must name the floor the objective caps the hunt below"
    )
    assert "--for-dispatch" in message, "it must point at the measured alternative"


def test_the_short_form_fires_without_a_role_because_absent_means_discovery() -> None:
    # `agent start`'s packet advisory restricts the lint to discovery roles
    # before it calls, and passes no role — so an absent role must not silence
    # the signal on the path that actually fires during a dispatch.
    assert _detect_technique_cage(_THEMED) == _detect_technique_cage(
        _THEMED, role="code-vuln-hunter"
    )


@pytest.mark.parametrize("role", sorted(contracts._CAGE_NON_DISCOVERY_ROLES))
def test_the_short_form_is_silent_where_naming_the_family_is_the_point(role: str) -> None:
    """A verifier, variant hunter, fuzzer, exploit developer or report writer is
    dispatched AGAINST a known family. Naming it is correct, not a cap."""
    assert _detect_technique_cage(_THEMED, role=role) == []


@pytest.mark.parametrize(
    "task",
    [
        "Verify the sqli and xss findings on the billing module",
        "Reproduce the idor and the open-redirect on the orders API",
        "Confirm the ssrf and xxe reports against the webhook handler",
        "Rehearse the sqli and csrf reproduction steps for the report",
    ],
)
def test_the_short_form_is_silent_on_a_verification_shaped_objective(task: str) -> None:
    assert _detect_technique_cage(task, role="code-vuln-hunter") == []


def test_one_incidental_family_is_not_a_cage() -> None:
    assert _detect_technique_cage(
        "Review the idor surface on the orders API", role="code-vuln-hunter"
    ) == []


def test_an_objective_long_enough_to_carry_a_surface_is_not_a_cage() -> None:
    """Length is the signal: above the threshold there is room for the surface
    and the entry chains, so a class named in passing is context, not the whole
    objective."""
    task = (
        "Hunt the refund path on app.acme.example end to end: the public refund "
        "intent endpoint, the queue worker that settles it, and the webhook that "
        "confirms it back from the payment vendor. Two tenants exist with their "
        "own orders. Earlier work on this surface found an idor and an "
        "open-redirect elsewhere in the same controller, so treat those as prior "
        "art rather than the objective, and follow whatever the request path "
        "actually lets you reach."
    )
    assert len(task.split()) > contracts._CAGE_SHORT_TASK_WORDS

    assert _detect_technique_cage(task, role="code-vuln-hunter") == []


def test_prose_spelling_reaches_the_canonical_hyphenated_class() -> None:
    """An operator writes "path traversal", the taxonomy says `path-traversal`.
    Matching only the hyphenated token made the commonest spelling invisible."""
    warnings = _detect_technique_cage(
        "Look for path traversal and open redirect in the upload handler",
        role="vulnerability-analyst",
    )

    assert warnings
    assert "path-traversal" in warnings[0]
    assert "open-redirect" in warnings[0]


def test_one_family_whose_name_contains_another_is_still_one_family() -> None:
    """`injection` is a canonical class AND a substring of `web-app-injection`.
    Counting both would read one named family as two and make the short-form
    threshold fire on a single-family objective."""
    assert _detect_technique_cage(
        "Hunt web-app-injection in the billing module", role="code-vuln-hunter"
    ) == []
    assert _detect_technique_cage(
        "Review the nosqli surface on the search API", role="code-vuln-hunter"
    ) == []


def test_hunt_is_an_imperative_verb_for_the_structured_form_too() -> None:
    """`hunt` is the verb a code dispatch is actually written with, and it was
    missing from the imperative set — so a hunt-shaped recipe escaped the LONG
    form as well."""
    assert "hunt" in contracts._CAGE_IMPERATIVE_VERBS

    recipe = (
        "Work through these in order:\n"
        "Hunt sqli on the id parameter\n"
        "Hunt xss on the name parameter\n"
        "Hunt the pricing page for stale discounts\n"
    )
    warnings = _detect_technique_cage(recipe, role="code-vuln-hunter")

    assert warnings and "imperative test-verb lines" in warnings[0]


@pytest.mark.parametrize("vuln_class", sorted(all_classes()))
def test_every_canonical_class_is_detectable(vuln_class: str) -> None:
    """Structural: the matcher is built from `vuln_taxonomy.all_classes()`, so a
    class added there is detected without touching this lint. Paired with a
    second family so the short-form threshold is reached either way.
    """
    partner = "xss" if vuln_class != "xss" else "csrf"
    if vuln_class in partner or partner in vuln_class:
        pytest.skip(f"{vuln_class} and {partner} overlap by name")

    warnings = _detect_technique_cage(
        f"Hunt {vuln_class} and {partner} in the billing module",
        role="code-vuln-hunter",
    )

    assert warnings, vuln_class


def test_the_short_form_is_advisory_and_never_an_error() -> None:
    errors, warnings = contracts.validate_specialist_dispatch_contract(
        {
            "agent_role": "code-vuln-hunter",
            "dispatch_mode": "item-iterating",
            "skills": "code-vulnerability-analysis",
            "task": _THEMED,
        }
    )

    assert errors == [], errors
    assert any("technique cage" in warning for warning in warnings), warnings
    assert not any("cage" in error.lower() for error in errors), errors


def test_two_specific_injection_families_are_two_families() -> None:
    """The collapse is positional, not by name.

    `injection` is a canonical class and a substring of `prompt-injection`, so a
    name-based collapse would read "prompt injection and SQL injection" as ONE
    family and stay quiet on a genuine two-family cage. A match only collapses
    when it is nested INSIDE another class's match.
    """
    warnings = _detect_technique_cage(
        "Hunt prompt injection and SQL injection in the model API",
        role="code-vuln-hunter",
    )

    assert warnings, "two distinct injection families are still two families"
