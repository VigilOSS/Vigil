---
description: Workflow and state abuse in source, trusted amounts and quantities, one-time grants, and attempt limits on OTP, MFA and password reset
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS, PHP, Ruby, Java, Go, C#
---

# Business Logic — Workflow, Value and Attempt-Limit Flaws

> Target: Flaws where every line is memory-safe and every query is parameterized, yet
> the application does something its owner never intended: refunds more than was
> charged, skips the payment step, redeems a coupon twice, or lets a six-digit code be
> guessed. SAST has no sink to match. The defect is the gap between the invariant the
> business needs and the checks the code performs.

Read the handler against the invariant, not against a pattern list. Write the invariant
down first ("a refund never exceeds the captured amount minus earlier refunds"), then
find the code that enforces it on the server for every path that can reach the write.
For concurrent versions of the same flaws (double spend, double redeem), load
`race-condition.md` "Request-Level Concurrency in Web and API Handlers".

---

## What You're Hunting

### 1. Client-supplied values the server should derive

Price, total, discount, currency, quantity, tax, shipping, plan, role and owner id
arriving in the request and used directly.

```php
$order->total = $request->input('total');          // the client sets the price
$order->currency = $request->input('currency');    // charged in a cheaper currency
$cart->addItem($sku, (int) $request->input('qty')); // qty = -5 credits the cart
```

Check every value that reaches a charge, a credit or a grant: is it recomputed from
server-side records, or merely validated for type? Watch for negative and zero
quantities, fractional units of indivisible goods, very large values that overflow or
round, and currency or unit mismatches between the charge and the credit.

### 2. Workflow steps enforced only by the client

Multi-step flows (cart, address, payment, confirm; register, verify email, activate;
request reset, verify code, set password) where a later endpoint does not check that the
earlier step completed for this same object and user.

```python
@app.post("/orders/<order_id>/confirm")
def confirm(order_id):
    order = Order.get(order_id)
    order.status = "confirmed"          # never checks order.payment_status == "captured"
    fulfil(order)
```

For every state-changing endpoint, list the states it may legally start from and confirm
the code enforces that list on the server. A transition table in the model that one
endpoint bypasses with a direct field write is a finding candidate.

### 3. One-time and bounded grants

Coupons, vouchers, referral bonuses, trial periods, free credits, invite codes, refunds
and entitlements. Ask what bounds each grant and where the bound is stored:

- Per-user limits keyed on something the user controls (email aliases, new accounts,
  a client-supplied device id).
- Stacking: two discounts that are each valid alone but combine past the intended
  floor, or a percentage applied after a fixed discount brings the total below zero.
- Refunds or cancellations that return the benefit without revoking what it bought, or
  refund to a different instrument than the one charged.
- Partial refunds whose sum is never compared with the captured amount.
- Entitlements granted on a payment webhook without verifying the event's signature,
  amount, currency and the order it names.

### 4. Ownership versus state

An endpoint can check that the caller owns the object and still act on an object in the
wrong state, or check the state and act on another user's object. Confirm both checks
are present and that both read the same record the write uses, not an id from a
different request field.

### 5. Rounding, precision and units

Floating-point money, rounding in the customer's favour on each of many small
operations, conversions between minor and major units, and truncation when splitting a
total. Repeatable small gains are a finding when the attacker controls the repetition.

### 6. Attempt limits on OTP, MFA, passcodes and password reset

A short secret is only as strong as the limit on guessing it. A six-digit code with no
attempt limit falls to about 500,000 guesses on average.

```ruby
def verify
  user = User.find_by(email: params[:email])
  if user.otp_code == params[:code]   # no attempt counter, no expiry, no lockout
    sign_in(user)
  end
end
```

Check, in source:

- An attempt counter exists, is incremented on every failure before the comparison
  returns, and is stored server-side per account and per code, not only per IP or
  session. Per-IP limits fall to address rotation; per-session limits fall to new
  sessions.
- The increment is atomic. A read-check-increment sequence lets concurrent guesses all
  pass the check.
- The counter is not reset by requesting a new code, by a successful login elsewhere, or
  by a different endpoint that verifies the same code (API versus web, mobile versus
  web).
- Codes expire, are single-use, are invalidated when a new one is issued, and are
  compared in constant time.
- Every endpoint that accepts the secret enforces the limit: login, step-up, reset
  confirmation, email-change confirmation, recovery codes.
- Password-reset tokens are long and random, single-use, bound to the account they were
  issued for, and expire. A reset flow that accepts a short numeric code needs the same
  attempt limits as an OTP.
- Rate limiting implemented in middleware applies to the route that actually verifies
  the code, including alternate paths, trailing-slash variants and API versions.

---

## Detection Questions

1. **"What invariant does this handler exist to protect, and where is it enforced?"**
   Name it in one sentence, then find the server-side line that enforces it for every
   path that reaches the write.

2. **"Which values in this request should the server have derived instead?"**
   Any amount, quantity, price, currency, owner or role taken from the request and used
   in a charge, credit or grant.

3. **"From which states may this transition start, and is that checked here?"**
   A state-changing endpoint that does not read and verify the current state can be
   called out of order.

4. **"What bounds this grant, and can the caller reset or multiply the bound?"**
   Per-user limits keyed on attacker-controlled identity, stacking rules, and refund
   paths that return the benefit.

5. **"How many guesses does an attacker get at this secret, and across how many
   endpoints?"** Count the attempts allowed per account per code, check the counter is
   atomic and survives code reissue, and check every endpoint that verifies the secret.
