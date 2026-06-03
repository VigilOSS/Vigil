# API1:2023 — Broken Object Level Authorization

> Skill: `idor-testing`

## CWE taxonomy

Tag the finding with the most specific CWE. Default to **CWE-639**.

| CWE | IDOR sub-class it describes | Tag a finding when |
|-----|-----------------------------|--------------------|
| **CWE-639** | Authorization bypass through user-controlled key (canonical IDOR) | Default — attacker swaps an object reference to reach another principal's object |
| **CWE-566** | Authorization bypass via user-controlled SQL primary key (child of 639) | The user-controlled key lands in a SQL `WHERE` clause with **no owner predicate** |
| **CWE-862** | Missing authorization | The authz check is **ABSENT** entirely |
| **CWE-863** | Incorrect authorization | A check **exists but validates the wrong thing** (wrong role/scope, parent-not-child) |
| **CWE-284** | Improper access control (pillar) | Under-specified — treat "CWE-284-only" advisories as needing refinement to 862/863/639 |
| **CWE-602** | Client-side enforcement of server-side security | The trust sibling that often **causes** the others (client supplies the value the server trusts) |

Hierarchy: CWE-284 → {CWE-285, CWE-862, CWE-863}; CWE-639 → CWE-566; CWE-602 sits beside the tree.

## BOLA vs BOPLA vs BFLA

> File the finding in the right class:
> - **BOLA (API1)** = wrong *object* (this file)
> - **BOPLA (API3)** = wrong *property* → `agent/references/api-security/API03-broken-property-authz.md`
> - **BFLA (API5)** = wrong *function* → `agent/references/api-security/API05-broken-function-authz.md`

## Severity (BugCrowd VRT)

Iterability is the severity multiplier — predictable/enumerable IDs escalate everything.

- [ ] Iterable + sensitive + modify → **P1**
- [ ] Modify (iterable) → **P2**
- [ ] View (iterable) → **P3**
- [ ] Modify/view via complex GUID/UUID → **P4 — still in scope, NOT informational; do not drop it**
- [ ] View non-sensitive → **P5**

## REST BOLA/IDOR — CRUD Coverage
- [ ] Test every CRUD endpoint with swapped IDs — map all endpoints accepting object IDs first
- [ ] Test GET with other user's ID: `curl -H "Authorization: Bearer USER_B_TOKEN" https://api/v1/users/USER_A_ID`
- [ ] Test PUT/PATCH with other user's ID: `curl -X PUT -H "Authorization: Bearer USER_B_TOKEN" -d '{"name":"hacked"}' https://api/v1/users/USER_A_ID`
- [ ] Test DELETE with other user's ID: `curl -X DELETE -H "Authorization: Bearer USER_B_TOKEN" https://api/v1/users/USER_A_ID`
- [ ] Test nested resources: `/api/users/VICTIM_ID/orders/ORDER_ID` — both IDs must be validated
- [ ] Test batch/bulk endpoints: `POST /api/users/bulk {"ids": [1, 2, 3]}` — are all IDs authorized?

## ID Prediction & Enumeration
- [ ] Test sequential integer IDs: increment/decrement to find adjacent objects
- [ ] Harvest UUIDs from other API responses (listing endpoints, search results, shared links)
- [ ] Check for UUIDv1 which contains timestamp + MAC — predictable if generation time known
- [ ] Test ID type confusion: send string `"admin"` where numeric ID expected
- [ ] Test negative IDs, zero, `MAX_INT` values

## Parameter Injection for BOLA
- [ ] Test array injection: `?user_id[]=1&user_id[]=2` — returns data for both users?
- [ ] Test comma-separated IDs: `?ids=1,2,3`
- [ ] Test JSON array in body: `{"user_ids": [1, 2, 3]}`
- [ ] Test wildcard or glob patterns if supported: `?id=*`, `?id=1*`

## GraphQL Object Access
- [ ] Query other users' objects via nested resolution:
  ```
  query { user(id: "VICTIM_ID") { email orders { total items { name } } } }
  ```
- [ ] Test mutations with other users' object IDs
- [ ] Test node/relay-style queries: `query { node(id: "base64_VICTIM_ID") { ... on User { email } } }`
- [ ] Exploit relationship traversal: query your own object, then follow relations to others' data

## Tenant Isolation
- [ ] Swap `X-Tenant-ID`, `org_id`, or `workspace_id` headers/parameters between accounts
- [ ] Test if API keys from one tenant can access another tenant's resources
- [ ] Check if tenant context is derived from token vs. user-supplied parameter (latter is exploitable)

## API Versioning Bypass
- [ ] Test older API versions for missing auth checks: `/v1/users/ID` vs `/v2/users/ID`
- [ ] Check if deprecated endpoints still accessible and lack newer security controls

## Modern Methodology

- [ ] Per-verb authz matrix: replay GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS — authz is often wired to one verb only
- [ ] 403→IDOR bypass ladder: JSON type-confusion, array/object wrapping, path mangling (`%00` / `../` / trailing `;` / `.json` / wildcard), Content-Type swap, version-prefix swap
- [ ] Two-session differential replay with content-length/body-fingerprint oracle (Autorize / Auth-Analyzer model); caveat: request-level automation HINTS at but can't CONFIRM BOLA, and 404 ≠ safe
- [ ] ID harvesting when IDs are opaque → see `agent/references/access-control/idor-identifier-prediction.md`
- [ ] Blind-IDOR confirmation via observable side effects / OOB callback
- [ ] Second-order / workflow-resume tests + client-supplied owner/tenant field tampering
- [ ] Web-cache-deception delivery of another user's authorized response

## Modern architectures

One-line probes per architecture; full probes in `agent/references/access-control/idor-modern-architectures.md`.

- [ ] GraphQL Relay global-ID / batch — decode and swap base64 GIDs, alias-batch sibling objects
- [ ] JWT claim-trust — server trusts `sub`/`tenant`/`role` claim instead of re-checking ownership
- [ ] Presigned-URL / signed-ref — tamper the signed object reference or reuse across principals
- [ ] Cloud datastore RLS — row-level-security gaps in Firestore/Supabase/RLS-backed APIs
- [ ] AI/LLM conversation + RAG — cross-user conversation IDs, retrieved-doc references leaking other tenants
- [ ] Realtime / WebSocket — per-message authz missing after the connection handshake
- [ ] Microservice header trust — internal `X-User-Id`/`X-Tenant` headers injectable at the edge
- [ ] gRPC-web — object references in metadata/protobuf bypassing the REST authz layer

---
> Cross-reference: `idor-testing` skill, `agent/skills/split-brain-idor/SKILL.md`, `agent/references/access-control/idor-modern-architectures.md`, `agent/references/access-control/idor-identifier-prediction.md`, `agent/references/code-vuln-patterns/web-app-data-exposure.md`, `agent/references/api-security/API03-broken-property-authz.md` (BOPLA), `agent/references/api-security/API05-broken-function-authz.md` (BFLA)
