---
description: Architecture-specific IDOR/BOLA tactics (GraphQL Relay-GID/batch, JWT claim-trust, signed/presigned refs, cloud datastores, AI/LLM apps, realtime/WS, microservice mesh, cache deception)
skill: idor-testing
---

# IDOR / BOLA in Modern Architectures — Escalation Tactics

Where the access-control gap sits once it leaves the `GET /users/{id}` handler: Relay node
resolvers, gateway-injected identity headers, presigned-URL signers, client-trusted datastores,
LLM/RAG retrieval, WebSocket frames, east-west mesh traffic and CDN cache keys. Each tactic carries
a Confidence label; classing (CWE, BOLA/BOPLA/BFLA) is `agent/references/api-security/API01-broken-object-level-authz.md`.

Every probe below is a request shape. Send it through `vigil assess kali exec --technique IDOR`
(`AUTH` for identity-header and token-trust probes) `--intent "<tactic>" --probe-kind payload
--phase consume-test --timeout 60 -- curl …`, as two named identities in one call where ownership
matters (`--identity-env A=user_a --identity-env B=user_b`, `agent/skills/idor-testing/SKILL.md`
"Vigil mechanics"). Generate ID variants with `vigil assess classify-payload <id> --mutations`;
rank batch responses with `vigil assess anomaly-score`.

## GraphQL (beyond `node(id:)` basics)

- **Relay global-ID decode/forge** (Confidence: High). A Relay `id` is almost always
  `base64("Type:dbid")` or `gid://service/Type/Id`, and the `node(id:)` resolver checks the type,
  not ownership: decode, increment, re-encode, refetch
  (`{ node(id:"VXNlcjoxMzM4"){ ... on User { id email } } }` for `User:1338`). Precedent:
  **CVE-2025-31481**, API Platform Core <4.0.22, where the default `node` field re-creates a Query
  operation without the configured `security` checks, so any entity is refetchable by Relay ID.
- **Batched + aliased enumeration in one HTTP request** (Confidence: High). Aliases
  (`a: order(id:1){total} b: order(id:2){total}`) and JSON-array batching
  (`[{"query":"{order(id:1){total}}"},…]`) fire N object reads per request, defeating per-request
  rate limits and per-request authz logging.
- **Operation-name / partial-field authz evasion** (Confidence: Med-High). Gateways that authorize
  on the operation-name string or only the top-level field miss
  `query GetMyProfile { aliasField: adminOnlyUser(id:"1338"){ email role } }`: the guard's pattern
  no longer matches but the resolver still runs.
- **Mutation-side BOLA** (Confidence: High). Mutations are far less tested than queries: feed a
  foreign ID to state-changing mutations (`deleteStorySnaps(id:"1338")`,
  `updateAddress(userId:"1338", …)`), and try a privileged property on the same mutation
  (`updateUser(id:"me", role:"Admin")`, BOPLA).
- **Schema mapping** for the object-bearing fields: introspection, or field suggestions with it off
  (`agent/skills/graphql-testing/SKILL.md`).
- **APQ (persisted query) as a false allowlist** (Confidence: Med). Automatic Persisted Queries is
  a performance feature: clients register arbitrary operations at runtime by sending
  `{query, extensions:{persistedQuery:{version:1, sha256Hash}}}`, so an "APQ-protected" endpoint
  still accepts attacker queries. True allowlisting is APQ disabled plus a pre-registered
  server-side hash list.

Payloads: `agent/references/payloads/graphql-payloads.md`.

## JWT / Claim-Trusting Backends

- **Gateway-set claim trusted by backend** (Confidence: High). The edge validates the JWT, then
  injects identity as a plain header (`X-User-Id`, `X-Org-Id`, `x-msft-entra-identity`). If the
  service is reachable directly (pod IP, NodePort, `hostNetwork`, SSRF, a second ingress), set the
  header yourself and no JWT is needed (`curl http://internal-svc.cluster.local/orders -H 'X-User-Id: 1002'`).
- **Audience/issuer/realm confusion cross-service replay** (Confidence: High). Sibling services
  share an issuer or secret and skip `aud` validation, so a low-privilege token is accepted by an
  admin or sibling API. Replay it verbatim against the sibling; vary `iss`/realm if rejected.
- **Valid-token + foreign-object pairing** (Confidence: High). `kid`/`jku`/`jwk` injection forges
  the principal; the IDOR variant keeps a fully valid token and pairs it with another tenant's object
  IDs. The backend authenticates correctly and never checks the object's tenant against the token's
  `org_id`.

Token forgery: `agent/skills/jwt-testing/SKILL.md`, `agent/references/payloads/jwt-payloads.md`.

## Signed / Encrypted / Opaque References

- **Reusable HMAC-signed object refs** (Confidence: High). `?doc=123&sig=HMAC(123)` where the
  signature covers the ID but not the user: request your own signed ref, then swap the ID keeping
  the sig, and replay it from a different session.
- **Presigned URL (S3/GCS/Azure Blob) key/bucket tampering & enumeration** (Confidence: High). The
  server signs whatever key the client sends. Walk `objectKey` to a neighbour (`pdfs/124/receipt.pdf`
  for `pdfs/123/…`); an empty or `/` `objectKey` returns a signed root listing; an empty
  `bucketName` enumerates all buckets; also `download?filePath=/`.
- **Upload→blob-id→download-route pivot** (Confidence: High). A write that returns a blob id is half
  a read. When an upload or create response hands back a `ContentVersion` / `068…` id, an S3 key or a
  document id, test the download route for it: ownership is frequently unchecked there even when the
  primary API exposes no read, and other users' uploaded documents are real PII. Routes: Salesforce
  `/sfc/servlet.shepherd/version/download/<id>`, `/servlet/servlet.FileDownload?file=<id>`,
  `/sfsites/c/...`; generic `/download/<id>`, `/files/<id>`, `/document/download/<id>`, presigned
  `?key=`. Salesforce paths: `agent/references/payloads/salesforce-aura-payloads.md`.
- **JWE / encrypted-ID malleability** (Confidence: Low, label it so). Homegrown "encrypt the ID"
  schemes (ECB, or CBC with no MAC) are malleable. Collect many encrypted IDs and look for repeated
  ECB blocks or reused GCM IVs; proper JOSE AEAD resists naive bit-flipping, so this is a
  low-probability lead.

## Cloud & Client-Trusted Datastores

- **Firebase / Firestore direct client access** (Confidence: High). Security rules are the only
  control; `allow read, write: if true;` or `if request.auth != null;` (authenticated, no owner
  check) lets any user read or write any document by ID. The config (`apiKey`, `projectId`) is
  public by design in the app bundle:
  `https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/users/VICTIM_UID?key=PUBLIC_API_KEY`.
- **Supabase / PostgREST RLS-off-by-default** (Confidence: High). Tables ship with Row Level
  Security disabled (**CVE-2025-48757**: 303 endpoints across 170 projects unauth-readable), so the
  public anon key reads and writes every row:
  `https://PROJECT.supabase.co/rest/v1/profiles?select=*` and `?id=eq.1002&select=*` with
  `apikey: PUBLIC_ANON_KEY`.

## AI / LLM Product APIs (2024–2026)

- **Conversation / thread / message ID enumeration** (Confidence: High). `/conversations/{id}`,
  `/threads/{id}`, `/messages/{id}` without an owner check. UUIDv7 thread IDs are time-ordered and
  window-enumerable (`idor-identifier-prediction.md`). Precedents: the OpenAI 2023 Redis bug that
  cross-leaked chat titles and messages between users; **CVE-2024-7041** (open-webui memory-edit IDOR).
- **RAG document / file-ref IDOR + cross-tenant retrieval** (Confidence: High). Two distinct bugs:
  retrieve-then-authorize, where similarity search returns top-K chunks before the ACL filter runs
  so another tenant's content surfaces in the answer (Salesforce Einstein 2024 cross-tenant KB
  snippets); and a client-supplied `namespace` / `tenant_id` in the query body, forged to hit a
  victim tenant's vector namespace.
- **Agent / tool execution acting on another user's resource** (Confidence: Med-High). An agentic
  tool call runs with broad service credentials and no per-object ownership re-check: drive the
  agent through its prompt or tool arguments onto a resource ID you do not own (`"export invoice
  1002 to my email"`, 1002 belonging to another user). Prompt-side technique:
  `agent/skills/llm-api-testing/SKILL.md`.

Headline AI-IDOR precedent: **McDonald's McHire / Paradox.ai (2025)**, an enumerable `lead_id`
(decrement from 64,185,742) plus weak admin auth exposed ~64M applicant records.

## WebSocket / gRPC / SSE / Event-Driven

- **Connect-time-only authz, no per-message check** (Confidence: High). Auth happens at the
  handshake and later frames are never re-authorized. Connect low-privilege, then send a frame for a
  foreign channel or object (`{"type":"subscribe","channel":"user:1002:notifications"}`, or a
  GraphQL-over-WS `start` with `subscription{ messages(userId:1002){ body } }`). Reported in the wild
  as a GraphQL-over-WS IDOR → SQLi → PII chain. Frame tooling: `agent/skills/websocket-testing/SKILL.md`.
- **Message-bus / pub-sub topic IDOR** (Confidence: Med). Topic names embed object IDs
  (`orders.{orgId}.events`); subscribe to a forged topic (`SUB orders.4711.events`) to receive
  another org's stream.
- **gRPC-web protobuf frame tampering** (Confidence: Med). `Content-Type:
  application/grpc-web-text` is base64-wrapped protobuf: decode the frame, edit the object-ID
  field, re-encode and replay (grpc-coder, protoscope, `buf curl --schema ./api.proto`); per-method
  object-level authz is frequently missing.

## Microservices / Service Mesh / API Gateway

- **East-west trust of caller-supplied identity headers** (Confidence: High). An internal service
  trusts the `X-User-Id` the mesh should have set, but is reachable directly, so the attacker
  supplies it (`http://orders-svc.svc.cluster.local:8080/orders/1002` with `X-User-Id: 1002`); the
  same root cause as the gateway-claim tactic, seen east-west.
- **BFF aggregation leaking sibling-service data** (Confidence: Med-High). The Backend-for-Frontend
  authorizes the aggregate request but fans a client-controlled ID out to a sibling service with no
  object-level check of its own, so the sibling's data leaks through the composed response
  (`/bff/dashboard?accountId=1002`; `agent/skills/bff-parameter-override/SKILL.md`).
- **No per-object authz on east-west traffic** (Confidence: High). The mesh enforces service
  identity (mTLS) but not object-level authz. Validate from a foothold pod with a valid service
  identity and a foreign object ID.

## Caching / CDN (Web Cache Deception × IDOR)

- **Cache key missing the auth dimension** (Confidence: High). A response varies by
  `Cookie`/`Authorization` but is served without `Vary` or `Cache-Control: private`, so one user's
  object is cached and served to the next requester (**CVE-2025-57752**: Next.js image
  optimization caches auth-varying responses cross-user). Fetch an authed object
  (`/_next/image?url=%2Fme%2Favatar&w=64&q=75`), then refetch the same URL with no credentials.
- **Path-confusion WCD to capture an authenticated object** (Confidence: High). Lure the victim to
  a crafted path; the origin serves their authenticated object while the CDN caches it under a
  static-looking key the attacker fetches unauthenticated:
  - `/account/settings/wcd.css`: appended segment the origin ignores, CDN caches as `.css`;
  - `/account/settings;wcd.css`: Spring matrix-param truncation;
  - `/account/settings%23wcd.css`: origin decodes `#` and truncates, cache keeps the `.css` suffix;
  - `/assets/..%2faccount/settings`: path-normalization mismatch between cache and origin.

  The cache stored it when the unauthenticated fetch shows `cf-cache-status: HIT` / `x-cache: HIT`
  (or `Age > 0`); play the victim with your own second identity. Cache-key technique:
  `agent/skills/cache-poisoning/SKILL.md`.

## Related

- `agent/references/access-control/idor-identifier-prediction.md`: identifier structure and
  time-window enumeration (ObjectId, UUIDv7, Snowflake layouts).
- `agent/references/api-security/API01-broken-object-level-authz.md`: classing and the 403 → IDOR
  variant ladder.

> CVE-citation caveat: product-named CVE roundups are frequently mis-attributed. State the precise
> mechanism and do not hard-code unassigned numbers — e.g., the **PraisonAI workspace IDOR is "CVE
> pending."** Verified CVEs cited above: CVE-2025-31481, CVE-2025-57752, CVE-2025-48757,
> CVE-2024-7041. Incidents without a CVE: OpenAI 2023 Redis cross-user chat leak; Salesforce Einstein
> 2024 cross-tenant RAG snippets; McDonald's McHire / Paradox.ai 2025.
