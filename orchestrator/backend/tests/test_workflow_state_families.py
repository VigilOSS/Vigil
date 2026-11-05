"""Transactional and one-time-code files owe race, business-logic and rate-limit review.

Request handlers run concurrently across requests, so a refund, booking or
quota file is exactly where check-then-act races and workflow abuse live, yet
no slot or role row ever required those families on the code track. They are
derived from whole words of the classifier's role label and of the file's own
path, so `load_balancer` is not a balance and a refund policy document or a
locale file owes nothing.
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
def test_transactional_roles_owe_race_and_business_logic_review(role):
    families = set(
        code_analysis._applicable_families_for_file(
            ["NETWORK-INPUT"], language="python", role=role
        )
    )
    assert _WORKFLOW <= families


@pytest.mark.parametrize(
    ("file_path", "language"),
    [
        ("app/Http/Controllers/RefundController.php", "php"),
        ("src/payments/charge.ts", "typescript"),
        ("internal/payouts/handler.go", "go"),
        ("lib/vouchers/apply.rb", "ruby"),
        ("src/main/java/com/acme/entitlement/Grants.java", "java"),
        ("includes/payment.inc", "php"),
        ("modules/acme_checkout/acme_checkout.module", "php"),
    ],
)
def test_transactional_paths_owe_race_and_business_logic_review(file_path, language):
    families = set(
        code_analysis._applicable_families_for_file(
            ["NETWORK-INPUT"], language=language, role="handler", file_path=file_path
        )
    )
    assert _WORKFLOW <= families


@pytest.mark.parametrize(
    ("role", "file_path"),
    [
        ("payment_webhook", ""),
        ("", "src/integrations/paypal_ipn.py"),
        ("StripeWebhookHandler", ""),
    ],
)
def test_webhook_receivers_owe_race_and_business_logic_review(role, file_path):
    families = set(
        code_analysis._applicable_families_for_file(
            ["CALLBACK-DATA"], language="python", role=role, file_path=file_path
        )
    )
    assert _WORKFLOW <= families


@pytest.mark.parametrize(
    ("role", "file_path"),
    [
        ("otp_verifier", ""),
        ("MfaChallenge", ""),
        ("totp_enrollment", ""),
        ("passcode_check", ""),
        ("", "app/controllers/password_resets_controller.rb"),
        ("PasswordResetService", ""),
    ],
)
def test_one_time_code_and_reset_files_owe_rate_limit_review(role, file_path):
    families = set(
        code_analysis._applicable_families_for_file(
            ["NETWORK-INPUT"], language="ruby", role=role, file_path=file_path
        )
    )
    assert "rate-limit" in families


@pytest.mark.parametrize(
    ("role", "file_path", "language"),
    [
        ("placeholder", "src/ui/placeholder.ts", "typescript"),
        ("threshold", "src/alerts/threshold.py", "python"),
        ("load_balancer", "src/net/load_balancer.go", "go"),
        ("stakeholder_report", "src/reports/stakeholder.py", "python"),
        ("", "docs/refund-policy.md", "markdown"),
        ("", "config/locales/refund.en.yml", "yaml"),
        ("", "src/locale/refund.py", "python"),
        ("", "src/i18n/checkout.ts", "typescript"),
        ("", "db/migrations/0042_add_wallet.py", "python"),
        ("", "tests/test_refund.py", "python"),
        ("", "spec/payments/charge.rb", "ruby"),
        ("", "src/__tests__/checkout.js", "javascript"),
        ("", "fixtures/booking.py", "python"),
        ("", "src/refund/refund_test.go", "go"),
        ("", "src/billing/test_refund.py", "python"),
        ("", "templates/checkout.html", "html"),
        ("", "static/wallet.css", "css"),
        ("", "deploy/payments/Dockerfile", "dockerfile"),
        ("", "templates/emails/refund.ftl", "freemarker"),
        ("", "resources/views/checkout.blade.php", "blade"),
        ("", "templates/checkout.html.twig", "twig"),
        ("", "app/design/frontend/checkout/cart.phtml", "php"),
        ("", "ext/wallet/refund_basic.phpt", "php"),
    ],
)
def test_words_that_merely_contain_a_token_and_non_source_paths_owe_nothing_new(
    role, file_path, language
):
    families = set(
        code_analysis._applicable_families_for_file(
            ["NETWORK-INPUT"], language=language, role=role, file_path=file_path
        )
    )
    assert not families & {"race-condition", "business-logic", "rate-limit"}


def test_done_refuses_a_refund_file_that_omits_the_workflow_families(client, isolate_settings):
    engagement_key = "2026-11-05-workflow-families-done"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    repo = _create_repo(client, engagement_key, repo_key="workflow-families")
    files = _refresh_repo_files(
        client,
        engagement_key,
        int(repo["id"]),
        [
            {
                "file_path": "src/billing/refund_service.py",
                "language": "python",
                "loc": 30,
                "file_hash": _source_hash("refund"),
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
                    "role": "parser",
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
    assert _WORKFLOW <= set(claim["applicable_vuln_classes"])
    recorded = client.post(
        f"{base}/analysis-results",
        json=_owned(claim, queue_item_id=claim["id"], disposition="clean", evidence="read"),
    )
    assert recorded.status_code == 201, recorded.text

    refused = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="review complete",
            cwe_coverage=_network_input_coverage(default_effort=80),
        ),
    )
    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "race-condition" in detail and "business-logic" in detail

    accepted = client.post(
        f"{base}/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="review complete",
            cwe_coverage=[
                *_network_input_coverage(default_effort=80),
                {"family": "race-condition", "effort": 80},
                {"family": "business-logic", "effort": 80},
            ],
        ),
    )
    assert accepted.status_code == 200, accepted.text
