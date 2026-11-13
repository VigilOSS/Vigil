---
description: BOLA/IDOR classing (CWE, Bugcrowd VRT severity, BOLA vs BOPLA vs BFLA) and the 403-to-IDOR variant ladder
skill: idor-testing
---

# API1:2023 — Broken Object Level Authorization

The workflow is `agent/skills/idor-testing/SKILL.md`. This file holds the classing tables used
before recording and the concrete variant list the skill's 403 ladder points at.

## CWE taxonomy

Tag the finding with the most specific CWE. Default to **CWE-639**.

| CWE | IDOR sub-class it describes | Tag a finding when |
|-----|-----------------------------|--------------------|
| **CWE-639** | Authorization bypass through user-controlled key (canonical IDOR) | Default — attacker swaps an object reference to reach another principal's object |
| **CWE-566** | Authorization bypass via user-controlled SQL primary key (child of 639) | The user-controlled key lands in a SQL `WHERE` clause with **no owner predicate** |
| **CWE-862** | Missing authorization | The authz check is absent entirely |
| **CWE-863** | Incorrect authorization | A check exists but validates the wrong thing (wrong role/scope, parent-not-child) |
| **CWE-284** | Improper access control (pillar) | Under-specified — treat "CWE-284-only" advisories as needing refinement to 862/863/639 |
| **CWE-602** | Client-side enforcement of server-side security | The trust sibling that often causes the others (client supplies the value the server trusts) |

Hierarchy: CWE-284 → {CWE-285, CWE-862, CWE-863}; CWE-639 → CWE-566; CWE-602 sits beside the tree.

## BOLA vs BOPLA vs BFLA

File the finding in the right class:
- **BOLA (API1)** = wrong *object* (this file)
- **BOPLA (API3)** = wrong *property* → `agent/references/api-security/API03-broken-property-authz.md`
- **BFLA (API5)** = wrong *function* → `agent/references/api-security/API05-broken-function-authz.md`

## Severity (BugCrowd VRT)

Iterability is the severity multiplier: predictable or enumerable IDs escalate everything.

- Iterable + sensitive + modify → **P1**
- Modify (iterable) → **P2**
- View (iterable) → **P3**
- Modify/view via complex GUID/UUID → **P4**, still in scope and not informational; do not drop it
- View non-sensitive → **P5**

## Parameter Injection for BOLA

Multi-ID shapes, where one request may return several principals' objects: `?user_id[]=1&user_id[]=2`,
`?ids=1,2,3`, `{"user_ids":[1,2,3]}`, `?id=*` / `?id=1*`, bulk endpoints (`POST /bulk {"ids":[…]}`,
is every ID authorized?), and nested routes (`/users/VICTIM_ID/orders/ORDER_ID`, both IDs must be
validated).

403 → IDOR ladder, when a straight swap is refused (each passes a scalar validator at the edge but
can reach the data layer intact):
- type confusion on the ID: `[1234,1235]`, `true`, `*` / `%`, zero-pad `00001235`, `-1`,
  float `1235.0`, CSV string `"1234,1235"`, a string such as `"admin"` where a number is expected,
  `0` and `MAX_INT`;
- wrapping: `{"id":1234}`, `[1234]`, nested `[[1234]]`, `{"id":{"id":1234}}`;
- path mangling: `%00`, `/own/../victim/`, trailing `;` or `.json`, wildcard segment
  `/workspaces/*/users`;
- content-type swap (JSON ↔ form ↔ XML binders), `/v1/` ↔ `/v2/` and deprecated versions that
  predate the current authz middleware, case and trailing slash (`/API/Users/123`, `/api/users/123/`).

## Related

- **Operator workflow** → `agent/skills/idor-testing/SKILL.md`: per-verb authz matrix, two-session
  differential replay (content-length/body-fingerprint oracle; automation *hints* at BOLA but can't
  *confirm* it, 404 ≠ safe), blind-IDOR side-effect/OOB confirmation, second-order /
  workflow-resume, client-supplied owner/tenant tampering, web-cache-deception.
- **Body/route ID divergence** → `agent/skills/split-brain-idor/SKILL.md`.
- **Architecture tactics** → `agent/references/access-control/idor-modern-architectures.md`: GraphQL
  (Relay global-ID forge, batch/alias enumeration, mutation BOLA), JWT claim-trust, signed/presigned
  refs, cloud-datastore RLS (Firebase/Supabase), AI/LLM conversation+RAG, realtime/WebSocket,
  microservice header trust, gRPC-web, cache deception.
- **Opaque identifiers** → `agent/references/access-control/idor-identifier-prediction.md`: predicting
  or harvesting ids (ObjectId/UUIDv1-7/ULID/Snowflake/KSUID/NanoID/Stripe) when sequential
  enumeration is dead.
- Source-side data-exposure patterns → `agent/references/code-vuln-patterns/web-app-data-exposure.md`.
