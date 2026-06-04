---
name: gf-patterns:idor
description: Object-reference parameter patterns that signal broken object-level authorization surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: idor
weight: 35
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

Object-reference keys across query, body, and path-param dicts (lowercased; compound keys like
`filter[user][id]` are split so inner tokens match):

- **Upstream slice:** `id, user, account, number, doc, email, group, profile, order, report`
- **User / identity:** `uid, userid, user_id, owner, owner_id, member, member_id, customer, customer_id, account_id, accountid`
- **Tenant / org scoping (cross-tenant BOLA):** `org, org_id, organization, organization_id, tenant, tenant_id, workspace, workspace_id`
- **Generic object handles:** `object, object_id, objectid, oid, record, record_id, ref, reference, uuid, guid, gid, node, pid`
- **Domain objects:** `order_id, orderid, invoice, invoice_id, document_id, doc_id, file_id, fileid, transaction, transaction_id, payment, payment_id, ticket, ticket_id, case_id`
- **Modern chat / agent refs:** `conversation, conversation_id, thread, thread_id, message_id, msg_id`

## Path patterns that match

Path-embedded object identifiers — a URL path segment shaped like an id: pure-numeric
(`/users/1024/profile`), a canonical UUID (`/files/550e8400-e29b-41d4-a716-446655440000`), or a
long hex string ≥24 chars / Mongo ObjectId (`/orders/65a1f4e3b9c8a7d2f01b3e00`). This is a
regex rule (`_PATH_OBJECT_REF_SEGMENT` in `classify_buckets.py`), not a fixed substring list, so
it generalizes to any collection name without enumerating routes.

## Weight and priority interpretation

- Baseline priority score: 35
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Param-key matches:

- `https://target.example/api/v1/users/profile?id=1024` — numeric user id
- `https://target.example/orders/view?order=ORD-2024-0031` — structured order reference
- `https://target.example/messages/thread?account=2110` — cross-tenant account id
- `https://target.example/api/workspaces/list?workspace_id=acme` — tenant scoping key (cross-tenant BOLA)
- `https://target.example/ai/chat?conversation_id=c-7f1b` — chat object reference

Path-embedded id matches (new — no query param needed):

- `https://target.example/api/users/1024/profile` — numeric id path segment
- `https://target.example/files/550e8400-e29b-41d4-a716-446655440000` — UUID path segment
- `https://target.example/orders/65a1f4e3b9c8a7d2f01b3e00` — Mongo ObjectId path segment

## What it does NOT classify

- Search-style `q=` and `query=` parameters — those belong in `sqli` and `xss`
- Session-id tokens in parameters — those are `interestingparams` (credential surface) rather than object references
- Bare collection roots with **no** id segment (`GET /api/users` listing, `/orders`) — no param key and no path-embedded id, so they fall to the `path:` cluster fallback (a missing-filter/bulk-BOLA surface still worth testing per the skill, just not auto-bucketed here)
- GraphQL object access — the `node(id:)` / nested-resolver surface is opaque to URL classification; route via the `idor-testing` → `graphql-testing` skills

> **False-positive surface (keep operator calibration honest).** The numeric path rule also
> matches benign non-object segments — `/2024/annual-report`, `/page/2`, `/v1/...` style year
> and pagination paths. This is accepted: idor's weight (35) only affects triage ordering, never
> skip/include, so a marginal false positive costs nothing beyond a slightly-earlier look, which
> the design notes in `classify_buckets.py` deliberately prefer over a URL drowning in a
> `path:<seg1>/<seg2>` cluster. Conversely, an opaque random id with **no** observable param or
> path id (a harvested-only UUIDv4) won't bucket here — test it per the `idor-testing` skill and
> `idor-identifier-prediction.md` regardless of bucket.

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [OWASP API Security Top 10:2023 — API1 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

## Related

- `agent/skills/idor-testing/SKILL.md` — the follow-up test skill
- `agent/references/api-security/API01-broken-object-level-authz.md` — IDOR checklist for API endpoints
- `agent/references/access-control/idor-modern-architectures.md` — architecture-specific IDOR/BOLA tactics (GraphQL, JWT claim-trust, signed refs, cloud datastores, AI/LLM, realtime, mesh, cache deception)
- `agent/references/access-control/idor-identifier-prediction.md` — object-identifier prediction and ID-harvesting techniques for the opaque-ID surfaces this bucket misses
- `agent/references/gf-patterns/sqli.md` — overlaps on `id` / `uid` keys; combined bucket often indicates both classes
