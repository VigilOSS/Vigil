"""Transactional and one-time-code files carry race, business-logic and rate-limit review.

Request handlers run concurrently across requests, so a refund, booking or
quota file is exactly where check-then-act races and workflow abuse live, yet
no slot or role row ever required those families on the code track. The
classifier's role label makes them required: the architect read the file and
named what it moves. The file's own path only suggests them, because a
directory word such as `Checkout` or `credits` names whole trees of value
objects, events and helpers that never touch the workflow. Both read whole
words, so `load_balancer` is not a balance and a refund policy document is
pointed at nothing.
"""
from __future__ import annotations

import pytest

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


def _families(slot_types, *, language, role="", file_path=""):
    required = set(
        code_analysis._applicable_families_for_file(
            slot_types, language=language, role=role
        )
    )
    suggested = set(
        code_analysis._path_suggested_families_for_file(
            slot_types, language=language, role=role, file_path=file_path
        )
    )
    return required, suggested


@pytest.mark.parametrize(
    "role",
    [
        "refund_service",
        "booking_controller",
        "seat_hold_handler",
        "quota_manager",
        "store_credit_ledger",
        "coupon_redeem_controller",
        "WalletBalanceService",
        "checkout",
        "inventory_reservations",
    ],
)
def test_transactional_roles_require_race_and_business_logic_review(role):
    required, suggested = _families(["NETWORK-INPUT"], language="python", role=role)
    assert _WORKFLOW <= required
    assert not suggested & _WORKFLOW


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
    required, suggested = _families(
        ["NETWORK-INPUT"], language=language, role="handler", file_path=file_path
    )
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
        ["NETWORK-INPUT"], language="c", role="info_page", file_path="ext/standard/credits.c"
    )
    assert "race-condition" not in required
    assert "race-condition" in suggested


@pytest.mark.parametrize("role", ["payment_webhook", "StripeWebhookHandler"])
def test_webhook_roles_require_race_and_business_logic_review(role):
    required, _ = _families(["CALLBACK-DATA"], language="python", role=role)
    assert _WORKFLOW <= required


def test_webhook_paths_suggest_race_and_business_logic_review():
    required, suggested = _families(
        ["NETWORK-INPUT"], language="python", file_path="src/integrations/paypal_ipn.py"
    )
    assert not required & _WORKFLOW
    assert _WORKFLOW <= suggested


@pytest.mark.parametrize(
    "role",
    ["otp_verifier", "MfaChallenge", "totp_enrollment", "passcode_check", "PasswordResetService"],
)
def test_one_time_code_and_reset_roles_require_rate_limit_review(role):
    required, _ = _families(["NETWORK-INPUT"], language="ruby", role=role)
    assert "rate-limit" in required


def test_reset_paths_suggest_rate_limit_review():
    required, suggested = _families(
        ["NETWORK-INPUT"],
        language="ruby",
        file_path="app/controllers/password_resets_controller.rb",
    )
    assert "rate-limit" not in required
    assert "rate-limit" in suggested


@pytest.mark.parametrize(
    ("role", "file_path", "language"),
    [
        ("placeholder", "src/ui/placeholder.ts", "typescript"),
        ("threshold", "src/alerts/threshold.py", "python"),
        ("load_balancer", "src/net/load_balancer.go", "go"),
        ("stakeholder_report", "src/reports/stakeholder.py", "python"),
        ("", "docs/refund-policy.md", "markdown"),
        ("", "config/locales/refund.en.yml", "yaml"),
        ("", "templates/checkout.html", "html"),
        ("", "static/wallet.css", "css"),
        ("", "deploy/payments/Dockerfile", "dockerfile"),
        ("", "templates/emails/refund.ftl", "freemarker"),
        ("", "resources/views/checkout.blade.php", "blade"),
        ("", "templates/checkout.html.twig", "twig"),
    ],
)
def test_words_that_merely_contain_a_token_and_non_source_paths_point_at_nothing(
    role, file_path, language
):
    required, suggested = _families(
        ["NETWORK-INPUT"], language=language, role=role, file_path=file_path
    )
    assert not required & _WORKFLOW_STATE
    assert not suggested & _WORKFLOW_STATE


def _claim_classified_file(client, isolate_settings, engagement_key, *, file_path, language, role):
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
                    "classification": "critical",
                    "role": role,
                    "slot_types": ["NETWORK-INPUT"],
                    "analysis_priority": 90,
                }
            ]
        },
    )
    assert classified.status_code == 200, classified.text
    queued = client.post(
        f"{base}/analysis-queue", json={"items": [{"file_id": file_id, "priority": 90}]}
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


def test_done_refuses_a_refund_role_that_omits_the_workflow_families(client, isolate_settings):
    base, _repo_id, claim = _claim_classified_file(
        client,
        isolate_settings,
        "2026-11-05-workflow-families-done",
        file_path="src/billing/refund_service.py",
        language="python",
        role="refund_service",
    )
    assert _WORKFLOW <= set(claim["applicable_vuln_classes"])
    assert claim["path_suggested_vuln_classes"] == []

    refused = _done(client, base, claim, _network_input_coverage(default_effort=80))
    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "race-condition" in detail and "business-logic" in detail

    accepted = _done(
        client,
        base,
        claim,
        [
            *_network_input_coverage(default_effort=80),
            {"family": "race-condition", "effort": 80},
            {"family": "business-logic", "effort": 80},
        ],
    )
    assert accepted.status_code == 200, accepted.text


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
