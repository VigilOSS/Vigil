---
description: Sensitive business flows driven straight through the API (automation without bot controls, creation loops, email/SMS bombing, scraping, transfer flows)
skill: business-logic-testing
---

# API6:2023 — Unrestricted Access to Sensitive Business Flows

Workflow, approval boundary and proof standard: `agent/skills/business-logic-testing/SKILL.md`.
Getting past the volume limits on a flow (client-IP headers by edge, path and account-input
variation): `agent/skills/rate-limit-bypass/SKILL.md` and
`agent/references/payloads/rate-limit-bypass-payloads.md`.
Concurrency (double spend, coupon or OTP redeemed in parallel, last-item inventory, idempotency-key
omission or reuse): `agent/skills/race-condition-testing/SKILL.md`.

The API-specific question is whether a flow the UI guards with a CAPTCHA, device check or
step order can be driven directly through its endpoints at volume:

- Checkout and purchase replayed without the frontend; client-supplied `price` honoured.
- Coupons and referrals at volume: short codes enumerable, circular referral chains (A refers B,
  B refers A), bonuses credited before the referred account is verified.
- Resource-creation loops: accounts per IP or device, projects/workspaces/teams per account, API
  keys per account.
- Email/SMS bombing through password reset, phone verification, invite/share and push-notification
  triggers. These reach real people: run the human-reach preflight and target only inboxes and
  numbers you own (`agent/shared-constraints.md` §2d "Side-Effect Preflight"); a handful of sends
  shows a missing limit.
- Scraping: unbounded pagination on listing/search endpoints, unauthenticated public listings,
  responses carrying more than the UI shows.
- Transfers: no second-factor or email confirmation, negative amounts reversing direction, limits
  enforced only client-side.
