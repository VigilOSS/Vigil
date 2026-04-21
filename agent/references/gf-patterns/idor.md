---
name: gf-patterns:idor
description: Object-reference parameter patterns that signal broken object-level authorization surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
---

# gf: idor

## What this bucket classifies

Parameters that carry numeric, UUID, or name-based object references where an authenticated
attacker can swap values to reach another tenant's data. These are the primary inputs for
OWASP API1:2023 testing.

## Load this reference when

- Authenticated routes are in scope and the corpus has `?id=`, `?user=`, `?account=`, or `?order=` keys
- API spec ingestion produced numeric path parameters (`/users/{id}`, `/orders/{id}`)
- Operator wants to rank which authenticated endpoints to test first against a second account

## Parameter keys that match

`id, user, account, number, doc, email, group, profile, order, report`

## Path patterns that match

None — idor is keyed entirely off parameter names. Path-based object references surface via
`path:/<seg1>/<seg2>` cluster fallback plus API-spec ingestion.

## Weight and priority interpretation

- Baseline priority score: 35
- When combined with a nuclei match on the same URL: +10 bonus
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/v1/users/profile?id=1024` — numeric user id
- `https://target.example/orders/view?order=ORD-2024-0031` — structured order reference
- `https://target.example/reports/download?report=7f1b...-uuid-...` — UUID report handle
- `https://target.example/messages/thread?account=2110` — cross-tenant account id
- `https://target.example/api/docs?doc=internal-financials-Q3` — named document handle

## What it does NOT classify

- Path-embedded object references (e.g. `/users/1024/profile`) — those surface via API spec ingestion or the `path:` cluster fallback
- Search-style `q=` and `query=` parameters — those belong in `sqli` and `xss`
- Session-id tokens in parameters — those are `interestingparams` (credential surface) rather than object references

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [OWASP API Security Top 10:2023 — API1 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

## Related

- `agent/skills/idor-testing/SKILL.md` — the follow-up test skill
- `agent/references/api-security/API01-broken-object-level-authz.md` — IDOR checklist for API endpoints
- `agent/references/gf-patterns/sqli.md` — overlaps on `id` / `uid` keys; combined bucket often indicates both classes
