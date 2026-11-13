---
name: race-condition-testing
description: Race condition and TOCTOU exploitation — parallel request attacks
origin: Vigil
vuln_class: race-condition
---

# Race Condition Testing

## When to Activate

- Single-use or limited actions (coupons, gift cards, votes, invites, withdrawals, transfers),
  check-then-act flows (balance, quota, file, token), or state that settles asynchronously
  (verification, scanning, initialization).

`--technique RACE-CONDITION`. Run the burst inside one `vigil assess kali exec` call as a named
identity; for a shell-wrapped burst use `--identity-env A=user_a` and the exported
`$VIGIL_COOKIE_A`/`$VIGIL_HEADERS_A` (idor-testing "Vigil mechanics"). Techniques and the audited
burst recipe: `agent/references/payloads/race-condition-payloads.md` (HTTP/2 single-packet,
HTTP/1.1 last-byte synchronization, Turbo-Intruder-style gating, h2spacex, and the in-runtime
`curl --parallel` and asyncio bursts); load it before the first burst.

## Methodology

- **Pick the synchronization deliberately.** A curl/xargs burst spreads requests over
  milliseconds and finds wide windows only; the single-packet / last-byte techniques collapse the
  window to microseconds. A negative from a wide burst is not conclusive (`agent/rules/hunting.md`
  §13 needs the technique and a positive control).
- Standard targets: limit overrun / double spend, TOCTOU on balance, quota, file and token checks,
  OTP/2FA and rate-limit counters.
- **Multi-endpoint races:** redeem on one endpoint while checking status on another, apply a
  coupon and check out together, and **change email while requesting a password reset** (an
  account-takeover race).
- **Partial construction:** log in right after registration before verification, access an
  object before initialization completes, fetch an upload before the AV scan runs.
- **Indicators:** more than one success where one is expected; duplicate-key or constraint errors
  in some responses; a 409/500 mix (partial protection); counters or balances off afterwards.

## Proof and cleanup

Read back the state (balance, count, order total) and state how many duplicate executions
succeeded and the window observed; a small burst that shows the duplicate is enough. The strongest
proof is an impossible end state (a negative balance, two completed redemptions of a single-use
code) beside a solo-request control in which the same action sent alone is validated correctly, so
the check exists and fails only under concurrency. Revert test data with an audited
`--probe-kind cleanup` run. Severity: `agent/references/finding-fp-and-severity-gate.md`. Format:
`agent/references/runtime-guides/web-finding-recording.md`.
