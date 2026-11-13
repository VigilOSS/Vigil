---
description: Unbounded resource consumption on APIs (pagination, payload size, batch and fan-out endpoints, slow operations) and how to evidence it without a DoS
skill: business-logic-testing
---

# API4:2023 — Unrestricted Resource Consumption

Rate limits on login/OTP/coupon endpoints, limiter keying and spoofable client-IP headers:
`agent/skills/rate-limit-bypass/SKILL.md` (brute force at volume is in scope unless the VDP forbids
it, `agent/rules/hunting.md` §10). GraphQL depth, alias and batch amplification:
`agent/skills/graphql-testing/SKILL.md`.

## Evidence without a DoS

The graphql-testing "Resource exhaustion" rule applies to every API surface: exhaust only when the
ROE allows availability testing, otherwise record the missing limit with one bounded measurement
(a `?limit=` far above the UI's page size returning that many rows; a request a size step above the
documented cap accepted; response time growing with input size across two or three small steps).
Severity and the High/Critical bar for resource-limit issues: `agent/rules/reporting.md` §3.

## Surfaces

- Pagination: oversized `page_size` / `limit`, `offset` exhaustion, forged cursors, counts returned
  without a limit.
- Payload: body size, JSON nesting depth, long string fields, upload size, slow-to-process files
  (zip bombs, large PDFs) and missing timeouts on export/report generation.
- Regex-processed inputs (validation, search) where backtracking cost grows with input length.
- Batch and fan-out: bulk endpoints with no item cap, notify/invite endpoints that take a recipient
  list (human-reach preflight first, `agent/shared-constraints.md` §2d "Side-Effect Preflight"),
  batch limits that differ from the single-item limits.
