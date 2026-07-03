---
name: gf-patterns:privileged_action
description: State-change verb routes and dangerous-action params that signal function-level-authz (BFLA) / business-logic surfaces
origin: local overlay (classify-context-and-surface 2026-06; no upstream gf equivalent)
bucket: privileged_action
weight: 30
---

# gf: privileged_action

## What this bucket classifies

Endpoints whose path or parameters express a privileged **state-change action** — granting or
revoking access, approving/rejecting, impersonating, promoting, assuming a role — where a
lower-privileged or unauthenticated caller may be able to invoke a function reserved for
admins or another tenant. This is the function-level-authorization (BFLA) and business-logic
surface: the route exists to *do* something privileged, and the test is whether authorization
is actually enforced on the verb. Maps to canonical class `bfla` (OWASP API5:2023).

## Load this reference when

- The corpus has API routes whose trailing segment is an action verb (`/grant`, `/revoke`,
  `/approve`, `/impersonate`, `/transfer`, `/assume-role`) guarded by an `api`/`v<n>` sibling
  or sitting on an object id (`/users/1024/revoke`)
- Query/body params name a state-change action directly (`?grant=`, `?delete=`, `?disable=`)
- Operator is ranking which authenticated endpoints to test for missing function-level authz
  (invoke the privileged action as a non-admin / second account)

## Parameter keys that match

State-change action param **names** (lowercased). These match as whole keys, as inner tokens of a
`.`/`[`/`]`-delimited compound key (the strong `expand_compound_key` split), or — for a
`_`/`-`/camelCase compound such as `?grant_role=` — as a capped-weight inner-token (weak) match via
Fix 4's tiered mechanism (see `DRIFT.md` → "Fix 4"). A weak inner-token match never overrides a
stronger cluster; on a strongly-matched row it is recorded as a `secondary_bucket`.

`grant, delete, create, disable, enable, toggle, reset, rename, modify, alter, clone`

These are the state-change param NAMES distilled from upstream's catch-all "dangerous params"
list (`ssrf.json`): a `?delete=`/`?grant=` reinforces the path-based privileged-action signal.
Read-only / navigation params are deliberately excluded so ordinary CRUD reads do not flood the
bucket.

## Path patterns that match

This bucket does **not** use a literal path-fragment list (its `_BUCKETS` path-fragment tuple is
empty). The path signal is the `path_has_privileged_action()` predicate in `classify_buckets.py`,
appended in `classify_row` exactly like the `path_has_object_ref` → `idor` append. It fires on a
state-change verb that appears as a standalone path **segment**:

`grant, revoke, approve, reject, impersonate, transfer, sendotp, promote, setrole, disable,
deactivate, sudo, assume-role`

(stored as segment forms — `/assume-role/...` matches the `assume-role` segment exactly).

### Precision guard (override — documented in the `privileged_action` `_BUCKETS` comment)

A state-change verb segment alone is **not** enough to fire. The predicate requires the verb
segment to be **guarded** by one of:

- an **API/version sibling segment** in the same path — a literal `api` segment or a bare
  version segment matching `^v[0-9]+$` (`/api/users/grant`, `/v2/accounts/transfer`); or
- an embedded **object reference** elsewhere in the path (`path_has_object_ref`, the same
  context-then-id rule `idor` uses — `/users/1024/revoke`).

This stops content slugs from firing: a bare `/transfer` page (no API/version sibling, no
object-ref) and the hyphenated slug `/transfer-your-number` (whose single segment is **not** the
bare verb after the `/`-split) are both rejected. The predicate runs on the RAW lowercased url
only — cluster normalization (§5) is never consulted. The append is deduped against any
param-key match so the reason chain lists `privileged_action` at most once even when both the
path verb and a state-change param fire on the same row.

## Weight and priority interpretation

- Baseline priority score: 30
- Below the specific vulnerability buckets (`idor`=35, `ssrf`=40, `auth`=40, `graphql`=45) —
  those dominate the tie-break when they co-fire
- Equal weight to `servicenow` (30) and `devops_console` (30); `privileged_action` is **declared
  after `servicenow`** in `_BUCKETS`, so the first-at-max-weight tie-break keeps the earlier
  bucket's cluster while `privileged_action` is additively recorded in the reason chain
- The path-predicate append resolves its weight from the `_BUCKETS` table
  (`_PRIVILEGED_ACTION_WEIGHT`) so it cannot drift from the declared weight if it is ever retuned
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path verb + API/version sibling:

- `https://target.example/api/users/grant` — `grant` verb segment guarded by the `api` sibling
- `https://target.example/v2/accounts/transfer` — `transfer` verb guarded by the `v2` version segment
- `https://target.example/api/admin/impersonate` — `impersonate` admin action under `api`

Path verb + embedded object reference:

- `https://target.example/users/1024/revoke` — `revoke` verb with the `1024` object-ref sibling
- `https://target.example/orders/65a1f4e3b9c8a7d2f01b3e00/approve` — `approve` on a Mongo ObjectId

Param-key form:

- `https://target.example/admin/roles?grant=admin` — `?grant=` state-change param
- `https://target.example/account/settings?disable=true` — `?disable=` toggle

## What it does NOT classify

- `https://target.example/transfer` (bare verb page, no API/version sibling and no object-ref) —
  rejected by the precision guard; a marketing/content page, not a privileged endpoint
- `https://target.example/transfer-your-number` (content slug) — its single path segment is
  `transfer-your-number`, not the bare `transfer` verb, so the segment split rejects it
- `https://target.example/promotions/summer` — `promote`-adjacent content word, not a verb segment
- Read-only navigation params (`?view=`, `?list=`) — no state change, excluded from the param set
- Object-reference reads with no action verb (`?id=1024`) — those are `idor`, not a privileged
  action; both buckets can co-fire when a verb sits on an id (`/users/1024/revoke`)

## Attack classes

- **Broken function-level authorization (BFLA):** a non-admin (or unauthenticated) caller invokes
  an admin-only action — `POST /api/users/{id}/grant`, `/setrole`, `/promote` — because the
  server authorizes the *route* but not the *function*
- **Privilege escalation via state verbs:** `/impersonate`, `/assume-role`, `/sudo` flows that let
  a caller act as another principal when the action is not re-checked against the caller's role
- **Cross-tenant action abuse:** combining the verb with another tenant's object id
  (`/orders/{otherTenantId}/approve`) to mutate state in a tenant the caller cannot read
- **Business-logic / workflow abuse:** out-of-order or self-approval state transitions
  (`/approve` without the preceding review gate, `/sendotp` replay) — the broader API6:2023 surface

## Corpus grounding

Forward-looking coverage. The plan's Part 3 §A.9 entry records **no DB hit count** for this
bucket (unlike `dotnet_handler` ≈835, `servicenow` 877 + 2,826 `.do`, `wordpress` ≈1,512, or
`idp_admin` 130); the `auth_redirect.do` / `sysparm_url` action tail it helps recover is
attributed to the `servicenow` bucket plus the compound-key fix. `privileged_action` is a
generic, recurrence-driven BFLA surface (the roster's "write/grant/sendotp" note), not a
corpus-volume play — it exists to catch function-level-authz routes wherever they appear in
future engagements. See `docs/plans/classify-context-and-surface-buckets-2026-06.md` §A.9.

## Sources

- [OWASP API Security Top 10:2023 — API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP API Security Top 10:2023 — API6 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — top-level index

The plan cites no bucket-specific CVE for `privileged_action`: BFLA is an authorization/
business-logic class adjudicated per-application, not a single vendor CVE, so the OWASP API5/API6
editions are the authoritative references.

## Related

- `agent/skills/auth-bypass/SKILL.md` — the follow-up test skill this bucket routes to (the
  `bfla` class is one of auth-bypass's `vuln_class` values)
- `agent/references/api-security/API05-broken-function-authz.md` — OWASP BFLA checklist for API endpoints
- `agent/references/api-security/API06-business-flow-abuse.md` — business-flow / workflow-abuse surface that overlaps the state verbs
- `agent/references/gf-patterns/idor.md` — shares the `path_has_object_ref` predicate; co-fires when a verb sits on an object id (`/users/1024/revoke`)
