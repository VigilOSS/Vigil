---
description: Missing bot detection on critical flows
skill: business-logic-testing
---

# API6:2023 — Unrestricted Access to Sensitive Business Flows

> Skill: `business-logic-testing`

## Checkout & Purchase Abuse
- [ ] Automate checkout flow via API without frontend: `curl -X POST https://api/checkout -d '{"item_id":1,"qty":1}'`
- [ ] Test for missing bot detection: can 100 purchases complete without CAPTCHA or challenge?
- [ ] Test for inventory manipulation: buy last item via race condition with concurrent requests
- [ ] Check if pricing is validated server-side: modify `price` field in checkout API call

## Coupon & Promo Code Abuse
- [ ] Test coupon reuse: apply same code multiple times across different carts/sessions
- [ ] Test coupon stacking: apply multiple codes in a single request
- [ ] Brute-force short coupon codes: `for code in $(seq -w 0000 9999); do curl -s -d "code=$code" https://api/apply-coupon; done`
- [ ] Test if expired coupons are still accepted via API (bypassing frontend date check)

## Referral & Reward Abuse
- [ ] Test self-referral: refer your own email/account
- [ ] Test circular referral chains: A refers B, B refers A
- [ ] Automate referral creation to farm rewards
- [ ] Test if referral bonuses are credited before the referred account is verified

## Resource Creation Loops
- [ ] Test unlimited account creation from same IP/device
- [ ] Test unlimited project/workspace/team creation per account
- [ ] Test unlimited API key generation
- [ ] Check for missing rate limits on resource creation endpoints

## Email / SMS Bombing
- [ ] Test email bombing via password reset: `for i in $(seq 1 100); do curl -s -X POST -d "email=victim@test.com" https://api/reset; done`
- [ ] Test SMS bombing via phone verification endpoint
- [ ] Test notification triggers: can API calls generate unlimited push notifications?
- [ ] Check for invite/share endpoints that send emails without rate limits

## Scraping & Data Harvesting
- [ ] Test if listing/search endpoints allow unbounded pagination for full data extraction
- [ ] Check for missing authentication on public listing APIs
- [ ] Test if API responses include more data than the UI shows (scraping advantage)
- [ ] Check for missing rate limits on search endpoints

## Transfer & Financial Flow Abuse
- [ ] Test fund transfer without secondary confirmation (2FA, email confirmation)
- [ ] Test for negative transfer amounts to reverse fund direction
- [ ] Check if transfer limits are enforced server-side vs client-side only

## Race Conditions on Business Flows
- [ ] Concurrent coupon redemption: send 20 parallel POST requests to apply the same coupon
- [ ] Double-spend: send 20 parallel transfer requests with the same transaction
- [ ] Inventory race: buy the last item with 10 concurrent checkout requests
- [ ] OTP/token race: validate the same OTP code in parallel before server invalidates it
- [ ] Idempotency key bypass: omit or modify the idempotency key to replay operations
- See `race-condition-testing` skill for HTTP/2 single-packet technique and Python asyncio examples

---
> Cross-reference: A06 checklist, `business-logic-testing` skill, `race-condition-testing` skill
