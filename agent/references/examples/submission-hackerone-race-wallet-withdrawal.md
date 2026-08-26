---
description: "Example: HackerOne submission for a race condition in a wallet withdrawal endpoint enabling balance double-spend"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Race condition in wallet withdrawal lets a user double-spend their balance

**Weakness:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')

**Severity:** MEDIUM

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (6.5)

**Asset:** POST https://pay.example.com/api/v3/wallet/withdraw
**Run:** `python3 poc-race-withdraw.py`
**Pass if:** the wallet balance is negative once both withdrawals return

---

### Summary

An authenticated wallet holder withdraws more money than the account holds by firing two withdrawal requests at once. `POST /api/v3/wallet/withdraw` reads the balance, validates the amount, then writes the debit, with no lock holding the balance steady between read and write. A solo withdrawal is validated correctly; it's only concurrent requests that beat the check. The attached PoC fires both requests at the same wallet, and the balance goes negative once they both land.

### Steps to Reproduce

1. [attacker] Fund the wallet and confirm the starting balance:
```
curl -s https://pay.example.com/api/v3/wallet/balance -H "Authorization: Bearer $TOKEN"
```
**Expect:** `{"balance_cents": 5000, "currency": "USD"}`
2. [attacker] Withdraw the full balance once by itself, before testing concurrency:
```
curl -s -X POST https://pay.example.com/api/v3/wallet/withdraw \
  -H "Authorization: Bearer $TOKEN" -d "amount_cents=5000"
```
**Expect:** 200, balance drops to `0`. The check works when the requests are serialized.
3. [attacker] Re-fund the wallet back to `5000` for the race test.
**Expect:** balance `5000` again.
4. [attacker, concurrent] Run the attached PoC to fire both withdrawal requests at the wallet at once:
```
python3 poc-race-withdraw.py
```
**Expect:** both requests return 200, each with a distinct withdrawal ID. Full output in Evidence.
5. [attacker] Query the balance once both responses have returned:
```
curl -s https://pay.example.com/api/v3/wallet/balance -H "Authorization: Bearer $TOKEN"
```
**Expect:** `balance_cents` is negative, not `0` or a rejected second withdrawal.

### Evidence

**Impossible end state.** The balance and transaction log after both withdrawals return:
```
$ curl -s https://pay.example.com/api/v3/wallet/balance -H "Authorization: Bearer $TOKEN"
{"balance_cents": -5000, "currency": "USD"}                      <-- negative balance: both withdrawals cleared

$ curl -s https://pay.example.com/api/v3/wallet/transactions?limit=2 -H "Authorization: Bearer $TOKEN"
[
  {"id": "wd_8f2a1c9d", "type": "withdrawal", "amount_cents": 5000, "status": "completed"},
  {"id": "wd_8f2a1d02", "type": "withdrawal", "amount_cents": 5000, "status": "completed"}  <-- second withdrawal the balance check should have rejected
]
```
A wallet cannot legitimately hold `-5000`; the balance check exists to prevent exactly that. Two withdrawals, both `completed`, stand against a balance that only ever held one.

**Serialized check works; concurrent check doesn't.** Step 2's solo withdrawal correctly zeroed the balance, and a solo withdrawal against a `0` balance separately returns `402 insufficient_funds`. The check itself is correct; it only fails when two requests race it, because it reads the balance before either write commits.

Neither withdrawal request carries a client-supplied idempotency token, which rules out a deduplication gap — the balance check itself has no lock between read and write.

**Why `AC:L`.** Winning the race needs nothing beyond firing two ordinary requests at once — no precise timing window, no retries, no special client. That reliability is what keeps this at `AC:L` rather than the `AC:H` a narrower race would need.

**Minimum privilege.** Both withdrawal requests used the attacker's own authenticated session — no admin, support, or elevated role.

### Impact

A double-submitted withdrawal drains more than the account holds: the platform pays out the same balance twice from one funding event. Every wallet on the platform shares the same unsynchronized check, so the exposure scales with account balance, not with any extra privilege.

### Remediation

Take a row lock on the wallet with a `SELECT FOR UPDATE` query, or the database's equivalent, before validating the withdrawal amount. Hold that lock until the balance check and the debit write commit together, so a concurrent request blocks instead of reading a stale balance. As defense-in-depth, add a database-level `CHECK (balance_cents >= 0)` constraint so a race that slips past the application layer still can't commit a negative balance.
