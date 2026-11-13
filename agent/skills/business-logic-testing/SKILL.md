---
name: business-logic-testing
description: Business logic vulnerability detection — workflow bypass, price manipulation, state abuse, and application-specific flaws
origin: Vigil
vuln_class: business-logic
---

# Business Logic Testing

## When to Activate

- Multi-step workflows (checkout, registration, KYC, approval), financial operations (payments,
  transfers, balances, discounts, coupons), state machines (pending → approved → completed), or
  server decisions driven by client-supplied values.

`--technique BUSINESS-LOGIC` (credits the `business-logic` class). Mark every write
`--destructive`; writes to your own test accounts and the objects they created need no approval.
Exploit approval is needed only when a request touches another user's or the target's real
state, triggers fulfilment (shipping, provisioning), or moves money or a real payment
(`agent/shared-constraints.md` §1). Run as named identities
(idor-testing "Vigil mechanics"); `vigil assess kali exec` without `--identity` is anonymous.

## Methodology

Standard logic-abuse families apply: price/quantity manipulation incl.
negative, zero, fractional, overflow, rounding and currency; coupon/discount reuse and stacking;
payment-flow bypass; workflow/state bypass incl. step skip, step repeat, wrong-state access and
post-approval edits; account-takeover chains; feature abuse incl. invites, self-referral,
gift-card loops and expired offers. Business-flow automation, resource-creation loops and SMS
bombing: `agent/references/api-security/API06-business-flow-abuse.md` and
`API04-resource-consumption.md`. Also try type, boolean, array and null confusion on business
fields. Related skills: `rate-limit-bypass` (abuse-prevention limits), `race-condition-testing`
(double spend, limit overrun), `mass-assignment` (privileged fields on profile updates).

Features that mail or message someone (invites, shares, SMS, notifications) run the human-reach
preflight first: target only inboxes and numbers you own, in small volume
(`agent/shared-constraints.md` §2d "Side-Effect Preflight").

Less obvious, high-yield checks:

- **Error and rollback.** Interrupt a multi-step transaction at each step and look for partial
  state that persists (payment taken, order not created; failed transactions leaving inconsistent
  records); replay a successful request to test idempotency; conflicting concurrent operations
  (update + delete of one resource).
- **Degraded mode.** With a dependent service unavailable, or a feature flag / circuit breaker
  tripped, the fallback path often skips auth, rate limiting or validation; fallback endpoints
  should match the primary's posture.
- **Webhook integrity:** missing or unchecked signatures (empty/invalid `X-Hub-Signature` or
  equivalent), weak HMAC algorithms, no replay protection.

## Proof

Expected vs actual behaviour and the state read-back that proves it (`quantity: -5` credited
the balance, confirmed by the balance API; a coupon applied twice took the total to zero). Stop at
the read-back: completing fulfilment or a payment needs explicit approval. Severity follows
`agent/references/finding-fp-and-severity-gate.md` (business impact, a state transition the
attacker should not reach). Format: `agent/references/runtime-guides/web-finding-recording.md`.
