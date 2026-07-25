# IDOR / Broken-Access-Control Mindset

The generative layer that runs *before* `agent/agents/vulnerability-analyst.md`'s Multi-Perspective
Checklist and the `idor-testing` skill's methodology — those gate and structure the work; this
primes what to go looking for. The operator injects this lens wherever an object, a role, or a
tenant boundary is in play — which is nearly every authenticated surface. Stop reading an endpoint
as "the profile page"; read it as *whose data, reachable by what proof of ownership, checked
where.* Every ID is a hypothesis that the check is missing, misplaced, or only half-applied — not
a fixed list to swap and move past.

## 1. Every identifier is a hypothesis
A numeric ID, UUID, slug, hash, filename, S3 key, order reference — each is a claim that only the
right caller can dereference it. Don't just swap the value; ask what the *server* used to decide
it was yours. "The ID was in the URL and nothing else was checked" is not a shrug, it's the bug.

## 2. Verb, not noun
`/orders/{id}` is a noun. The real surface is that noun crossed with every verb it supports: read,
list, update, delete, share, export, duplicate, approve, comment, download, revoke. A correctly
scoped `GET` says nothing about the `DELETE`, the bulk-export, or "duplicate this for me" on the
same object — each verb is its own authorization decision until you name it and test it.

## 3. Cross-tenant is the default question, not the edge case
"Does this belong to this tenant" is a separate check from "does this belong to this user," and
routinely implemented, tested, and forgotten about separately. Don't stop at horizontal (same
tenant, different user); ask whether the object-ID space leaks across tenants at all, and whether
any check enforces the tenant edge, or only the user edge inside it.

## 4. Nested and derived objects inherit nothing
A child fetched through a parent (`/projects/{id}/tasks/{task_id}`), a computed artifact (PDF
export, cached thumbnail, webhook replay, audit-log entry), or a derived reference (presigned URL,
share token, cursor) was generated *from* an authorized object — that doesn't mean the generation
step re-checked authorization, or that the artifact carries any check once it exists. Was ownership
verified at the parent hop, the child hop, both, or only the one the developer was staring at?

## 5. Ask where the developer put the check
Route middleware, resolver, service layer, ORM query filter, UI conditional — pick the layer you'd
have put the check in if rushed, then test whether every *other* path to the same data actually
routes through it. A second entry point (admin API, batch job, mobile-only endpoint, internal
service call) is the classic way a real check exists and still gets bypassed.

## 6. GraphQL and REST are the same object model, two authz implementations
Where a backend exposes both a REST surface and a GraphQL surface (or a legacy API version behind
a new one), they were likely authorized independently, by different code. A resolver reachable via
`node(id:)`, a batched/aliased query, or a field REST never exposed can walk past a check REST
enforces cleanly. Treat each transport as a fresh hypothesis on the same object graph, not a
redundant re-test.

## 7. Two authorities, one decision — the generalization of §5 and §6
§5 asks which single layer holds the check; §6 asks what happens when REST and GraphQL each
implement authz independently. Both are one instance of a broader shape: wherever two components
independently derive the *same* access decision — a permission model and a search controller, an
API gateway and a web route, a sanitizer at write-time and a renderer at read-time, a client-side
gate and its server counterpart — one derivation is usually wrong, and the disagreement between
them is both the finding and the proof. No inference is needed beyond the two answers: if
subsystem A says a principal may not read X and subsystem B hands X over in the same window, the
target's own code has already contradicted itself. Look for the second oracle everywhere a
decision is made once and trusted everywhere else.

## 8. Revocation is a race, not an event
Deactivated account, downgraded role, revoked share link, expired invite, logged-out session — the
access decision was made once, at issuance, and may never be re-checked. Test the reference
(session token, presigned URL, cached capability, cursor, API key) *after* the state change that
should have killed it, not just before. A check that only fires at mint time is not one that holds
at use time.

## 9. Instantiate the role nobody has instantiated
A permission combination that exists in the role model but that no real grant has ever
instantiated — a tier defined in the schema with zero rows, a combination where every prior grant
hard-coded one flag off — is a testable configuration, not an absent one. Create it, then test it.
Keep this distinct from a genuine provisioning wall: "no test account in the required group" is
sometimes `agent/rules/hunting.md` §2's blocked-for-provisioning case (the precondition truly
cannot be met) and sometimes a fixture you can simply build — check which one before you record a
block.

---

This is guidance, not a cage or a checklist: it does not restrict which candidates you may pursue,
and it does not enumerate every case you will find — the sibling, variant, or adjacent case is
still yours to find.
