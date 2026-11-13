"""Structured context tags carry the families a file's job owes; paths only suggest.

Request handlers run concurrently across requests, so a refund, booking or
quota file is exactly where check-then-act races and workflow abuse live. The
architect records that as a context tag (`value-transfer`, `provider-callback`,
`one-time-secret`, ...) on the classification, and the tag makes the families
required. The free-text role label is descriptive only: no word in it is read
for an obligation. The file's own path only suggests the workflow families,
because a directory word such as `Checkout` or `credits` names whole trees of
value objects, events and helpers that never touch the workflow, and it reads
whole words, so `load_balancer` is not a balance.
"""
from __future__ import annotations

from typing import get_args

import pytest

from app.api.code_analysis import CodeContextTag
from app.services import code_analysis
from test_code_analysis_api import (
    _create_repo,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _refresh_repo_files,
    _source_hash,
    write_engagement,
)

_WORKFLOW = {"race-condition", "business-logic"}
_WORKFLOW_STATE = {"race-condition", "business-logic", "rate-limit"}


def _families(slot_types, *, language, context_tags=(), file_path=""):
    required = set(
        code_analysis._applicable_families_for_file(
            slot_types, language=language, context_tags=context_tags
        )
    )
    suggested = set(
        code_analysis._path_suggested_families_for_file(
            slot_types, language=language, context_tags=context_tags, file_path=file_path
        )
    )
    return required, suggested


def test_the_request_model_accepts_exactly_the_tags_the_family_table_maps():
    assert set(get_args(CodeContextTag)) == set(code_analysis.CONTEXT_TAG_VULN_CLASSES)


@pytest.mark.parametrize(
    ("tag", "language", "expected"),
    [
        ("crypto", "python", {"crypto-misuse"}),
        ("authentication", "python", {"auth-bypass", "web-app-auth", "rate-limit"}),
        ("authorization", "python", {"auth-bypass", "web-app-auth"}),
        ("error-handling", "c", {"error-handling", "null-dereference"}),
        ("allocator", "c", {"uninitialized-memory", "algorithmic-dos"}),
        ("parser", "python", {"algorithmic-dos"}),
        ("response-data", "python", {"web-app-data-exposure"}),
        ("ai-model", "python", {"ai-ml-security"}),
        ("value-transfer", "python", _WORKFLOW),
        ("provider-callback", "python", _WORKFLOW),
        ("one-time-secret", "ruby", {"rate-limit"}),
    ],
)
def test_each_context_tag_requires_its_families(tag, language, expected):
    required, suggested = _families(["NETWORK-INPUT"], language=language, context_tags=[tag])
    assert expected <= required
    assert not suggested & expected


def test_an_authorization_policy_point_does_not_owe_rate_limit():
    """Precision: a policy decision point is not a guessing surface."""
    required, _ = _families(["NETWORK-INPUT"], language="python", context_tags=["authorization"])
    assert "rate-limit" not in required


@pytest.mark.parametrize(
    ("file_path", "language"),
    [
        ("app/Billing/RefundController.php", "php"),
        ("app/Http/Controllers/RefundController.php", "php"),
        ("src/payments/charge.ts", "typescript"),
        ("internal/payouts/handler.go", "go"),
        ("lib/vouchers/apply.rb", "ruby"),
        ("src/main/java/com/acme/entitlement/Grants.java", "java"),
        ("includes/payment.inc", "php"),
        ("modules/acme_checkout/acme_checkout.module", "php"),
        ("src/locale/refund.py", "python"),
        ("src/i18n/checkout.ts", "typescript"),
        ("db/migrations/0042_add_wallet.py", "python"),
        ("tests/test_refund.py", "python"),
        ("spec/payments/charge.rb", "ruby"),
        ("src/__tests__/checkout.js", "javascript"),
        ("fixtures/booking.py", "python"),
        ("src/refund/refund_test.go", "go"),
        ("src/billing/test_refund.py", "python"),
        ("app/design/frontend/checkout/cart.phtml", "php"),
    ],
)
def test_transactional_paths_suggest_race_and_business_logic_review(file_path, language):
    required, suggested = _families(["NETWORK-INPUT"], language=language, file_path=file_path)
    assert not required & _WORKFLOW
    assert _WORKFLOW <= suggested


def test_a_path_hint_is_never_a_family_the_file_already_requires():
    required, suggested = _families(
        ["CALLBACK-DATA"], language="python", file_path="src/payments/charge.py"
    )
    assert "race-condition" in required
    assert suggested == {"business-logic"}


def test_a_credits_page_in_a_native_runtime_is_only_pointed_at_the_workflow():
    required, suggested = _families(
        ["NETWORK-INPUT"], language="c", file_path="ext/standard/credits.c"
    )
    assert "race-condition" not in required
    assert "race-condition" in suggested


def test_webhook_paths_suggest_race_and_business_logic_review():
    required, suggested = _families(
        ["NETWORK-INPUT"], language="python", file_path="src/integrations/paypal_ipn.py"
    )
    assert not required & _WORKFLOW
    assert _WORKFLOW <= suggested


def test_reset_paths_suggest_rate_limit_review():
    required, suggested = _families(
        ["NETWORK-INPUT"],
        language="ruby",
        file_path="app/controllers/password_resets_controller.rb",
    )
    assert "rate-limit" not in required
    assert "rate-limit" in suggested


@pytest.mark.parametrize(
    ("file_path", "language"),
    [
        ("src/ui/placeholder.ts", "typescript"),
        ("src/alerts/threshold.py", "python"),
        ("src/net/load_balancer.go", "go"),
        ("src/reports/stakeholder.py", "python"),
        ("docs/refund-policy.md", "markdown"),
        ("config/locales/refund.en.yml", "yaml"),
        ("templates/checkout.html", "html"),
        ("static/wallet.css", "css"),
        ("deploy/payments/Dockerfile", "dockerfile"),
        ("templates/emails/refund.ftl", "freemarker"),
        ("resources/views/checkout.blade.php", "blade"),
        ("templates/checkout.html.twig", "twig"),
    ],
)
def test_words_that_merely_contain_a_token_and_non_source_paths_point_at_nothing(
    file_path, language
):
    required, suggested = _families(["NETWORK-INPUT"], language=language, file_path=file_path)
    assert not required & _WORKFLOW_STATE
    assert not suggested & _WORKFLOW_STATE


def _claim_classified_file(
    client,
    isolate_settings,
    engagement_key,
    *,
    file_path,
    language,
    role,
    context_tags=(),
    classification="critical",
    priority=90,
):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    repo = _create_repo(client, engagement_key, repo_key="workflow-families")
    files = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": file_path,
                "language": language,
                "loc": 30,
                "file_hash": _source_hash(file_path),
                "header_snippet": "",
                "git_churn_score": 0,
                "has_past_cve_fix": False,
            }
        ],
    )
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    file_id = int(files[0]["id"])
    classified = client.post(
        f"{base}/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": file_id,
                    "classification": classification,
                    "role": role,
                    "context_tags": list(context_tags),
                    "slot_types": ["NETWORK-INPUT"],
                    "analysis_priority": priority,
                }
            ]
        },
    )
    assert classified.status_code == 200, classified.text
    queued = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": file_id, "priority": priority}]},
    )
    assert queued.status_code == 201, queued.text
    claim = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": "hunter"}
    ).json()[0]
    recorded = client.post(
        f"{base}/analysis-results",
        json=_owned(claim, queue_item_id=claim["id"], disposition="clean", evidence="read"),
    )
    assert recorded.status_code == 201, recorded.text
    return base, int(repo["id"]), claim


def _done(client, base, claim, cwe_coverage):
    return client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="review complete",
            cwe_coverage=cwe_coverage,
        ),
    )


def test_a_refund_path_is_a_hint_that_done_does_not_enforce(client, isolate_settings):
    base, repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-05-workflow-families-hint",
        file_path="src/billing/refund_service.py",
        language="python",
        role="parser",
    )
    assert not _WORKFLOW & set(claim["applicable_vuln_classes"])
    assert claim["path_suggested_vuln_classes"] == ["business-logic", "race-condition"]
    progress = client.get(f"{base}/analysis-queue/{claim['id']}/progress").json()
    assert progress["path_suggested_vuln_classes"] == ["business-logic", "race-condition"]
    assert not _WORKFLOW & set(progress["missing_cwe_families"])

    accepted = _done(client, base, claim, _network_input_coverage(default_effort=80))
    assert accepted.status_code == 200, accepted.text

    detail = client.get(f"{base}/coverage?repo_id={repo_id}&detail=cwe").json()
    (row,) = detail["files"]
    assert not _WORKFLOW & set(row["applicable_families"])
    assert row["path_suggested_families"] == ["business-logic", "race-condition"]


def test_done_records_the_omitted_workflow_families_of_a_value_transfer_file_at_effort_zero(
    client, isolate_settings
):
    base, repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-05-workflow-families-done",
        file_path="src/billing/refund_service.py",
        language="python",
        role="refund_service",
        context_tags=["value-transfer"],
    )
    assert _WORKFLOW <= set(claim["applicable_vuln_classes"])
    assert claim["path_suggested_vuln_classes"] == []

    closed = _done(client, base, claim, _network_input_coverage(default_effort=80))
    assert closed.status_code == 200, closed.text
    recorded = closed.json()["unreviewed_families_recorded"]
    assert {"race-condition", "business-logic"} <= set(recorded["families"])
    warnings = client.get(f"{base}/coverage?repo_id={repo_id}").json()["gate"]["effort_warnings"]
    assert any("'race-condition' effort 0 <" in warning for warning in warnings), warnings
    assert any("'business-logic' effort 0 <" in warning for warning in warnings), warnings


def test_a_checkout_value_object_closes_without_race_coverage_and_the_gate_stays_quiet(
    client, isolate_settings
):
    path = "src/Checkout/Cart/PriceStruct.php"
    base, repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-05-workflow-families-gate",
        file_path=path,
        language="php",
        role="value_object",
    )
    assert "race-condition" in claim["path_suggested_vuln_classes"]

    accepted = _done(client, base, claim, _network_input_coverage(default_effort=80))
    assert accepted.status_code == 200, accepted.text

    gate = client.get(f"{base}/coverage?repo_id={repo_id}").json()["gate"]
    assert not [reason for reason in gate["reasons"] if path in reason]


def test_a_role_label_alone_requires_no_family(client, isolate_settings):
    """The role is free text the architect writes for people; no word in it is
    read for an obligation, so `refund_service` with no tag owes nothing extra."""
    _base, _repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-14-workflow-families-role-only",
        file_path="src/acme/handler.py",
        language="python",
        role="refund_service",
    )
    assert not _WORKFLOW_STATE & set(claim["applicable_vuln_classes"])


def test_an_unknown_context_tag_is_refused(client, isolate_settings):
    engagement_key = "2026-11-14-workflow-families-unknown-tag"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="workflow-families")
    files = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [{"file_path": "src/acme/a.py", "language": "python", "loc": 3,
          "file_hash": _source_hash("src/acme/a.py"), "header_snippet": "",
          "git_churn_score": 0, "has_past_cve_fix": False}],
    )
    refused = client.post(
        f"/engagements/{engagement_key}/assessment/code/files/bulk-classify",
        json={"classifications": [{
            "file_id": int(files[0]["id"]), "classification": "high", "role": "refunds",
            "context_tags": ["refunds"], "slot_types": ["NETWORK-INPUT"],
            "analysis_priority": 60,
        }]},
    )
    assert refused.status_code == 422, refused.text
    assert "value-transfer" in refused.text


def test_a_medium_value_transfer_file_lists_the_workflow_families_as_guidance(
    client, isolate_settings
):
    """The context tag names the workflow families at every tier.

    `_applicable_families_for_file` reads the tags and never the
    classification, so a refund handler classified `medium` is pointed at the
    same check-then-act review a `critical` one is. Closeout owes an entry per
    family only on critical and high files; on a medium file the families stay
    on the claim and are measured by the effort harness.
    """
    base, repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-06-workflow-families-medium",
        file_path="src/billing/refund_service.py",
        language="python",
        role="refund_service",
        context_tags=["value-transfer"],
        classification="medium",
        priority=40,
    )
    assert _WORKFLOW <= set(claim["applicable_vuln_classes"])

    accepted = _done(client, base, claim, _network_input_coverage(default_effort=80))
    assert accepted.status_code == 200, accepted.text
    warnings = client.get(f"{base}/coverage?repo_id={repo_id}").json()["gate"]["effort_warnings"]
    assert any("'race-condition' effort 0 < 30" in warning for warning in warnings), warnings
    assert any("'business-logic' effort 0 < 30" in warning for warning in warnings), warnings
