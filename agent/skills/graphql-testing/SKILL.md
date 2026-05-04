---
name: graphql-testing
description: GraphQL security testing — introspection, injection, auth bypass, DoS
origin: AI Threat Hunting
---

# GraphQL Security Testing

> **`aith assess kali` audit flags:** use `--technique RECON` for introspection and schema discovery; when sending attack payloads via resolvers, switch to the matching vuln class (`SQLI` / `AUTH` / `IDOR` / `INFO-DISCLOSURE`).

## When to Activate

- Application exposes a GraphQL endpoint (`/graphql`, `/gql`, `/api/graphql`)
- Requests contain `query`, `mutation`, or `operationName` parameters
- GraphQL Playground or GraphiQL interface discovered

## Tools

- `aith assess kali exec -- curl ...` (all target-facing GraphQL requests must go through the kali exec wrapper; use `--technique RECON --probe-kind fingerprint --phase consume-test --timeout 30` for introspection, and the appropriate class (`SQLI`, `AUTH`, `IDOR`, `INFO-DISCLOSURE`) for payload probes)
- Burp Suite Repeater / Altair GraphQL Client (use to craft requests, then replay via kali exec for audit pipeline coverage)
- InQL (Burp extension for GraphQL)
- graphql-voyager (schema visualization — host-side analysis)
- BatchQL (batch query testing)
- CrackQL (brute-force via GraphQL)

## Methodology

### 1. Endpoint Discovery

- [ ] Common paths: `/graphql`, `/gql`, `/api/graphql`, `/graphql/console`
- [ ] Check for GraphiQL / Playground: `/graphiql`, `/playground`
- [ ] Look in JavaScript bundles for endpoint URLs
- [ ] Test both GET and POST methods
- [ ] Check WebSocket subscriptions: `ws://target/graphql`

### 2. Introspection Query

- [ ] Full schema dump:
      ```graphql
      { __schema { types { name fields { name type { name } } } } }
      ```
- [ ] Query types: `{ __schema { queryType { fields { name } } } }`
- [ ] Mutation types: `{ __schema { mutationType { fields { name } } } }`
- [ ] If introspection disabled, test partial: `{ __type(name: "User") { fields { name } } }`
- [ ] Field suggestion: send typo, observe "Did you mean..." errors
- [ ] If introspection fully disabled, use clairvoyance for field/type brute-forcing:
      `clairvoyance -o schema.json -w /path/to/wordlist.txt -d https://target/graphql`

### 3. Information Gathering

- [ ] Enumerate all types, queries, mutations, subscriptions
- [ ] Identify sensitive fields: password, token, secret, ssn, creditCard
- [ ] Map relationships: User→Orders→Payments
- [ ] Find hidden/internal queries not exposed in docs
- [ ] Check for debug fields: `_debug`, `__internal`

### 4. Authorization Testing

- [ ] Query other users' data via relationships:
      `{ user(id: "other-id") { email orders { total } } }`
- [ ] Access admin-only mutations with user token
- [ ] Test field-level access: can user query `user { role passwordHash }`?
- [ ] Nested IDOR: `{ order(id: 1) { user { email } } }`
- [ ] Remove or modify authorization header — test anonymous access

### 5. Injection via GraphQL

- [ ] SQLi in arguments: `{ user(name: "' OR 1=1--") { id } }`
- [ ] NoSQL injection in filters
- [ ] Variables injection: pass malicious input via `$variables`
- [ ] Stored XSS through mutations that save user content

### 6. Denial of Service

- [ ] Deeply nested queries:
      ```graphql
      { user { friends { friends { friends { friends { name } } } } } }
      ```
- [ ] Circular relationships: exploit to consume server resources
- [ ] Batch queries: send array of queries `[{query:...},{query:...},...]`
- [ ] Alias-based amplification:
      ```graphql
      { a: user(id:1){name} b: user(id:2){name} ... z: user(id:26){name} }
      ```
- [ ] Test depth limit, complexity limit, rate limit
- [ ] Fragment circular reference: `fragment A on User { friends { ...B } }` + `fragment B on User { friends { ...A } }` — causes infinite recursion
- [ ] Unbounded pagination: `{ users(first: 1000000) { id name } }` — server may attempt to load all records

### 7. Batched Query Attacks

- [ ] Array-body batching: `[{"query":"{ me { id } }"},{"query":"{ me { id } }"},...]` — many operations in single HTTP request
- [ ] Alias-based batching for rate limit bypass:
      ```graphql
      { a1: login(user:"admin",pass:"pass1"){token} a2: login(user:"admin",pass:"pass2"){token} }
      ```
      Single request, N login attempts — bypasses per-request rate limits
- [ ] Brute-force via batching: send 1000 login mutations in one request
- [ ] OTP bypass: batch OTP verification attempts
- [ ] Rate limit bypass: single HTTP request with multiple operations

### 8. Mutation Abuse

- [ ] Mass assignment: include extra fields in mutation input
- [ ] Test all mutations without auth
- [ ] Modify other users' data via mutations
- [ ] Delete/destructive mutations access control

## What to Record

- GraphQL endpoint URL and supported methods
- Schema dump or partial schema (sanitized)
- Queries/mutations with broken access control
- Injection payload and result — confirming a query returns another user's ID is not enough; you must show the **attacker outcome** (e.g., the IDOR query returned the victim's email, billing address, and payment method; the injection payload executed OS command `id` and returned `uid=0(root)`; the batched alias attack enumerated 500 valid usernames in a single HTTP request)
- DoS threshold (depth/complexity before failure)
- Severity based on impact (data leak, RCE, DoS)
- Remediation: disable introspection in prod, enforce depth/complexity limits, field-level authz

## Kill Signals — Stop Testing When
- Introspection disabled AND clairvoyance/field suggestion finds zero types → limited attack surface, test only known query names from source analysis
- All mutations require valid authorization AND no IDOR found in query resolvers → authorization is effective, move on
- Depth/complexity limits enforced AND rate limiting active → DoS not feasible, skip DoS testing

## Escalate When
- Introspection is disabled on `/graphql` but a malformed query returns a "Did you mean …" suggestion — field suggestions leak the schema, run clairvoyance/graphql-cop and rebuild the type map before moving on
- Any resolver accepts an ID, UUID, or numeric handle as an argument — test cross-tenant reads by swapping to another user's ID, GraphQL IDOR is commonly missed because authorization lives on the resolver, not the gateway
- Query batching or aliasing (`a: login(...), b: login(...), c: login(...)`) is accepted — rate limits apply per HTTP request not per operation, stack dozens of aliases against login/OTP/coupon endpoints
- A mutation's input type accepts a nested object field that was not documented or exposed by the UI — over-posting/mass-assignment (setting `role`, `isAdmin`, `ownerId`, `createdBy`) routinely bypasses field-level checks
- Query parameters are interpolated into a downstream SQL/NoSQL/OS call (visible via errors, timing, or OAST callback from a string arg) — GraphQL variables do not sanitize, classic injection works through the resolver

## Extended Resources

- `agent/references/payloads/graphql-payloads.md` — introspection, batching, field suggestion, injection in variables
- `agent/references/api-security/API05-broken-function-authz.md` — OWASP API Security: function-level authorization checklist
