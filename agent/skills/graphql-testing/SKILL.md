---
name: graphql-testing
description: GraphQL security testing — introspection, injection, auth bypass, DoS
origin: Vigil
vuln_class: graphql-injection, bola
---

# GraphQL Security Testing

## When to Activate

- A GraphQL endpoint (`/graphql`, `/gql`, `/api/graphql`, POST, GET or WebSocket subscription
  transport), requests carrying `query`/`mutation`/`operationName`, or GraphiQL/Playground.

`--technique GRAPHQL` for schema and resolver probes (credits `graphql-injection`); switch to the
sink's class (`SQLI`, `IDOR`, `AUTH`, `SSRF`) when a resolver argument reaches that sink. Craft in
any client, replay through `vigil assess kali exec … --intent … --phase consume-test --timeout <N>`.

Payloads (endpoint discovery, introspection, partial `__type`, field suggestion, batching,
DoS shapes): `agent/references/payloads/graphql-payloads.md`. Resolver
authorization beyond `node(id:)` (Relay global-ID forging, alias/batch enumeration, mutation BOLA,
GraphQL-over-WebSocket subscriptions): `agent/references/access-control/idor-modern-architectures.md`
"GraphQL" — load it as soon as any resolver takes an ID.

## Methodology

1. **Schema.** Introspection, then partial `__type` queries and field suggestions. With
   introspection off, a "Did you mean …" suggestion still leaks the schema: rebuild it with
   clairvoyance (`clairvoyance -o schema.json -w <wordlist> -d https://target/graphql`). Map
   sensitive fields, relationships, hidden/internal and debug fields.
2. **Resolver authorization.** Authorization usually lives on resolvers, not the gateway, so it is
   commonly missed: swap IDs on every ID-taking resolver (cross-tenant included), traverse
   relationships (`order(id){ user { email } }`), request privileged fields (`role`,
   `passwordHash`), call admin mutations with a user token, and drop the auth header entirely.
   Mutation inputs that accept undocumented nested fields (`role`, `isAdmin`, `ownerId`) go to
   `agent/skills/mass-assignment/SKILL.md`.
3. **Injection through variables:** variables are not sanitised; a string argument interpolated
   into SQL/NoSQL/OS/URL sinks takes the classic payloads — hand off to `sqli-testing`,
   `nosql-injection`, `command-injection` or `ssrf-testing` for the confirmation loop (OOB via
   `agent/references/offensive-tactics/frp-tunneling.md`).
4. **Batching defeats per-request limits.** Array-body batching and alias batching
   (`a1: login(...) a2: login(...)`) put N attempts in one HTTP request: login, OTP, coupon and
   enumeration endpoints. Show the limit is bypassed with a small batch; brute force at volume
   only where the VDP permits (`agent/rules/hunting.md` §10, `agent/skills/rate-limit-bypass/SKILL.md`).
5. **Resource exhaustion** (depth, circular fragments, alias amplification, huge pagination) only
   when the ROE allows availability testing; otherwise record the missing depth/complexity limit
   with a single bounded measurement, since a DoS claim on its own is usually out of scope.

## What to Record

Endpoint and transports, the schema evidence as captured (verbatim; ADR 0019), the query or
mutation with broken access control, and the attacker outcome with one minimal sample
(`agent/rules/hunting.md` §2, §10). Format: `agent/references/runtime-guides/web-finding-recording.md`.

## Kill Signals

- Introspection off and suggestions/clairvoyance find nothing → test only query names from
  source analysis.
- Every mutation enforces authorization and resolver ID swaps return nothing foreign.
- Depth/complexity limits and per-operation rate limits are enforced.

## Escalate When

- Suggestions leak the schema → rebuild it before moving on.
- A resolver takes an ID → cross-tenant reads (modern-architectures reference).
- Batching/aliasing is accepted → stack aliases against login/OTP/coupon.
- Errors, timing or an OOB callback show a variable reaching a downstream sink → injection skill.
