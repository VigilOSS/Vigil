---
name: race-condition-testing
description: Race condition and TOCTOU exploitation — parallel request attacks
origin: AI Threat Hunting
---

# Race Condition / TOCTOU Testing

> **Kali MCP audit header:** use `X-Technique: OTHER` (race/TOCTOU has no dedicated enum class; outcomes span double-spend, auth-bypass, and state corruption).

## When to Activate

- Application has single-use actions (coupons, vouchers, invites)
- Financial operations (transfers, purchases, withdrawals)
- Voting, rating, or counting mechanisms
- Inventory or stock management
- Any operation that should execute exactly once

## Tools

- Burp Suite Turbo Intruder
- `curl --parallel` (HTTP/2 multiplexing)
- Custom Python scripts (asyncio + aiohttp)
- Burp Repeater (send group in parallel)
- GNU parallel

For current-engagement target requests, execute `curl` through the Kali MCP
command-execution tool. Add explicit `Cookie:` or `Authorization:` headers
only when intentionally testing alternate-user races or session override
behavior.

## Methodology

### 1. Identify Race Condition Targets

- [ ] Coupon/promo code redemption
- [ ] Money transfer / payment
- [ ] Gift card activation
- [ ] Vote or like functionality
- [ ] Account creation with unique constraints (email, username)
- [ ] File operations (read-then-write sequences)
- [ ] Inventory purchase (limited stock)
- [ ] Token/OTP validation

### 2. Single-Packet Attack (HTTP/2)

- [ ] Prepare N identical requests via curl config file:
      ```bash
      # Create config file with 20 parallel POST requests
      for i in $(seq 1 20); do
        echo "url = https://target/redeem-coupon"
        echo "request = POST"
        echo "data = code=DISCOUNT50"
        echo "next"
      done > /tmp/race_config.txt

      # Send all simultaneously via HTTP/2 multiplexing
      curl --parallel --parallel-max 20 -K /tmp/race_config.txt -o /dev/null -w '%{http_code}\n'
      ```
- [ ] Alternative: Python asyncio for precise timing
      ```python
      import asyncio, aiohttp
      async def race():
          async with aiohttp.ClientSession() as s:
              tasks = [s.post('https://target/redeem-coupon', data={'code':'DISCOUNT50'}) for _ in range(20)]
              return await asyncio.gather(*tasks)
      asyncio.run(race())
      ```
- [ ] Count successful responses — more than 1 success = race condition confirmed

### 3. Turbo Intruder Script

- [ ] Use `race-single-packet-attack.py` in Turbo Intruder
- [ ] Configure: capture request, set N copies, send simultaneously
- [ ] Analyze responses: count successes vs expected single success
- [ ] Gate technique: send requests with incomplete body, release all at once

### 4. Limit Overrun Testing

- [ ] Send 20-50 identical requests in parallel
- [ ] Check if action executed more than once
- [ ] Example: redeem coupon 50 times → check if discount applied multiple times
- [ ] Transfer money: send same transfer 20 times → check total deducted vs transferred
- [ ] Vote: send 50 votes → check if count increased by >1

### 5. TOCTOU (Time-of-Check to Time-of-Use)

- [ ] Identify check-then-act sequences:
      1. Server checks balance ≥ amount
      2. Server deducts amount
- [ ] Race between check and deduction = double-spend
- [ ] File access: race between permission check and file read
- [ ] Token validation: race between check and invalidation

### 6. Multi-Endpoint Races

- [ ] Race between different endpoints:
      - Endpoint A: redeem coupon
      - Endpoint B: check coupon status
- [ ] Race between update and read operations
- [ ] Race state changes: apply coupon + checkout simultaneously
- [ ] Session race: change email + password reset at same time

### 7. Partial Construction Race

- [ ] Register user → immediately login before email verification
- [ ] Create object → access before initialization completes
- [ ] Upload file → access before antivirus scan

### 8. Detection Indicators

- [ ] Multiple 200 responses where only one expected
- [ ] Database constraint violations in some responses (duplicate key)
- [ ] Balance or counter inconsistencies after test
- [ ] Some requests succeed, others get 409/500 → partial protection

### 9. Cleanup

- [ ] Verify actual impact: check database state, balances, counts
- [ ] Document exact number of successful duplicate actions
- [ ] Revert test data if possible

## What to Record

- Endpoint and action with race condition
- Number of parallel requests sent
- Number of successful duplicate executions
- Technique used (single-packet, Turbo Intruder, curl --parallel)
- Business impact (financial loss, integrity violation, privilege escalation)
- Timing window observed
- Severity: High (financial) to Medium (logic bypass)
- Remediation: database locks, idempotency keys, atomic operations, mutex

## Extended Resources

- `agent/references/payloads/race-condition-payloads.md` — HTTP/2 single-packet, limit overrun, multi-endpoint race
