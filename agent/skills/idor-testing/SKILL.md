---
name: idor-testing
description: Insecure direct object reference testing for broken access control
origin: Vigil
vuln_class: idor
---

# IDOR Testing (Insecure Direct Object Reference)

The **entry-point skill** for broken object-level authorization: the BOLA/IDOR workflow and
when to escalate into split-brain-idor, bff-parameter-override, mass-assignment, graphql-testing,
jwt-testing or cache-poisoning.

## When to Activate

- APIs reference objects by ID (numeric, UUID, slug, encoded), user-specific resources are
  addressable directly, or a multi-tenant app shares an API surface.

## Vigil mechanics

- Audit flags: `--technique IDOR` for object-reference probes, `AUTH` for identity/tenant
  override; `--probe-kind payload` for swaps, `exploit` for confirmed cross-user access.
  `vigil assess kali exec` also needs `--intent`, `--phase` and `--timeout` (see `--help`).
- **Named identities.** Cross-user/tenant IDOR is only real across ≥ 2 named identities. Import
  each test account (`vigil auth import [engagement] --identity user_a --source <file>`, likewise
  `user_b`, `admin`; SaaS accounts in separate tenants) and replay with `--identity <name>`, which
  stamps the probe's `auth_context`. To run **one** command as two identities, use
  `--identity-env A=user_a --identity-env B=user_b` (exports `VIGIL_COOKIE_A`, `VIGIL_HEADERS_B`,
  …); that is the cross-identity proof carrier. Prefer injectable tools (`curl`, `httpx`,
  `nuclei`, `ffuf`). A single-identity probe, a shell-wrapped probe whose identity was not
  injected, or a hand-pasted token with anonymous audit context does not count as
  access-control depth.
- `vigil assess classify-payload <id> --mutations` types an ID and emits neighbor, boundary,
  escalation, format (type-confusion) and empty variants; fire those instead of hand-picking.
  `vigil assess anomaly-score <file.jsonl> --top N` ranks a replay sweep's outliers.
- Blind-write proof over OOB: `agent/references/offensive-tactics/frp-tunneling.md`
  "OOB Procedure (mint→poll→correlate)". A callback proves the write reached the victim object
  only when the injected host is one only that object would surface.

## Methodology

Map every ID in path, query, body and headers (tenant IDs included) per object type and CRUD
operation, then:

1. **Fingerprint the identifier** — it picks the tactic and the severity (iterable IDs score
   higher). Sequential int: sweep neighbours/boundaries. UUID v1/v6: time+MAC derived, so
   timestamp-bracket ("sandwich") a victim's GUID. UUID v4: guessing is dead, harvest instead.
   UUIDv7/ULID/Snowflake/KSUID/ObjectId leak creation time: window-bounded enumeration. Scheme
   table and recipes: `agent/references/access-control/idor-identifier-prediction.md`.
2. **Swap IDs** horizontally (same tier, other tenant) and vertically (user → admin IDs and
   admin actions), on read, write, delete and on create with a foreign parent ID; include files,
   exports and downloads. Also try another user's real ID observed elsewhere; `classify-payload`
   covers structural guesses only. Array/CSV/wildcard IDs (`id[]=`, `*`, `all`) are in
   `API01-broken-object-level-authz.md`.
3. **Per-verb authorization matrix.** Authz is often wired to one verb: replay the swapped ID
   across GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. Observed: `GET /api/v4/user/1` → 403 while
   `PUT /api/v4/user/1?include=email` → 200 with the victim's PII (the write path skipped the
   read-path filter). `HEAD` often shares GET's handler but skips its authz wrapper; `OPTIONS`
   can leak the allowed verb set.
4. **Harvest, don't guess, opaque IDs.** A v4 UUID is not "safe — stop". Harvest real victim IDs
   from the app's own over-sharing (list/search/feed nesting, exports, GraphQL GID decode, JWT
   claims, mention/typeahead APIs, archives and source maps, bulk-action echoes, notifications,
   404-vs-403/length/timing oracles); the channel list is the prediction reference "Harvesting".
5. **Two-session differential replay.** Replay every owner request as the other-user identity
   and unauthenticated. Use content-length + body fingerprint as the oracle, not status. A
   200-vs-403 or length delta is a candidate: `404` ≠ safe (scoping can mask an object) and equal
   lengths can be coincidence. **Hand-verify the returned data belongs to the other account**
   (names, emails, order contents) before recording.
6. **403 → IDOR ladder** when a straight swap is refused: ID type-confusion, wrapping, path
   mangling, case/slash, content-type and API-version swaps (the variants pass a scalar
   validator at the edge but reach the data layer intact). Load the concrete variant list in
   `API01-broken-object-level-authz.md` "Parameter Injection for BOLA" when the first swap returns
   401/403/404. Most productive: **serializer/format
   twins** — `?_format=json`, `.json` or another format suffix often hits a different,
   unauthorised controller for the same object.
7. **Body/route divergence** (route ID owner-checked, body carries an ID): escalate to
   `agent/skills/split-brain-idor/SKILL.md`.
8. **Second-order / workflow rebinding.** Ownership checked at creation is often not re-checked
   later: replay the approve/resume/schedule step against a foreign object; set client-supplied
   scope fields (`owner_id`, `account_id`, `sender`, `tenant_id`) to the victim's value; test
   deactivated/archived/removed members' old sessions and tokens.
9. **Blind writes** (empty 204, `{}`): prove impact by a victim-visible side effect
   (notification, state change), a 200-vs-error/length/timing oracle, or OOB as above.
10. **Listings without a filter**, a blanked user filter, or GraphQL relationship traversal can
    return other users' objects; privileged-field binding goes to `agent/skills/mass-assignment/SKILL.md`.
11. **Web cache deception** can deliver IDOR without the victim's ID (situational): per-architecture
    probes in `agent/references/access-control/idor-modern-architectures.md`, plus `cache-poisoning`.

Proof follows `agent/references/finding-fp-and-severity-gate.md`: two contexts and a real foreign
object. A destructive demonstration needs `--destructive` and exploit approval under the ROE.

## What to Record

- Endpoint, method, parameter, the verb/variant that worked, and the **named identity** that ran
  it; the object and its owner, hand-verified; horizontal/vertical/cross-tenant.
- Class it correctly: BOLA (API1, wrong object), BOPLA (API3, wrong property), BFLA (API5, wrong
  function). Severity calibration when the program uses Bugcrowd VRT (iterability is the
  multiplier; a GUID-gated view/modify is still P4, not informational) and the CWE mapping are in
  `API01-broken-object-level-authz.md`.
- Recording format: `agent/references/runtime-guides/web-finding-recording.md`.

## Kill Signals

- Every verb, ladder variant and the unauth/other-user replays return only owner-scoped data.
- A hard 403 persists where identity is server-side session-derived and no client-controllable
  scope field exists.
- IDs are random v4 UUIDs, harvesting yields no foreign IDs, and no oracle leaks them.
- The object is confirmed absent (not merely 404-masked) across all accounts.

## Escalate When

- One swap returns another user's data → sweep all object types and endpoints; harvest at scale
  (GraphQL batching/aliasing) and size the population.
- The leak is on profile/settings/reset/password → chain to account takeover.
- A cross-user write/delete succeeds → demonstrate impact (with approval) for P1/P2.
- Body ID diverges → split-brain-idor; a client-supplied identity/scope param changes the response
  → bff-parameter-override; privileged fields bind → mass-assignment; `node(id)`/GID → graphql-testing;
  claim-derived IDs → jwt-testing.

`vigil assess list-references --skill idor-testing` lists the paired references
(`access-control/idor-modern-architectures.md` — GraphQL/JWT/signed-refs/cloud/AI/realtime/mesh/cache
probes, load when the app uses one of those architectures; `access-control/idor-identifier-prediction.md`
— load on a non-sequential ID; `api-security/API01-broken-object-level-authz.md` — load before
recording, for VRT/CWE classing).
