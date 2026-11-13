---
name: split-brain-idor
description: Test for body/route parameter divergence where the server uses a different object identifier than the one validated in the URL path
origin: Vigil
vuln_class: idor
---

# Split-Brain IDOR Testing

A supplement to `agent/skills/idor-testing/SKILL.md` (run that first): when a straight URL-ID swap
is refused, keep **your** ID in the URL (passes the ownership check) and put the **victim's** ID
in the body (used for the actual write). The app correctly checks "does this user own X?" on the
route parameter, then operates on the body ID.

## When to Activate

- PUT/PATCH/POST routes carry an ID in the path and the body repeats an ID field.
- A BFF or proxy routes and authorizes on the URL but forwards the body to the backend.
- MongoDB-backed apps (ObjectId in route and body is common; Express/Mongoose handlers that
  spread `req.body` into an update).
- A response echoes an ID that came from the body rather than the URL.

## Mechanics

- `--technique IDOR`; `--probe-kind payload` for divergence, `replay` for read-backs, `exploit`
  for a demonstrated cross-user write. `kali exec` also needs `--intent`, `--phase`, `--timeout`.
- Two named identities are required (identity rules and the `--identity-env` two-identity
  carrier: idor-testing "Vigil mechanics"). All target traffic goes through
  `vigil assess kali exec --identity <name> -- curl …`, never a hand-pasted cookie.
- No second account: `vigil assess classify-payload <your-id> --mutations` surfaces the
  well-known first/admin IDs (`1`, `00000000-…-000000000001`) for the body; its `format`
  variants (string vs number, `[id]`, `null`) test whether the guard compares scalars only — a
  type mismatch can defeat `body._id === req.params.id` while the DB still resolves the object.

## Divergence tests

Run the confirmation triad as `user_a`, then read back as `user_b`:

```bash
# 1. baseline: matching IDs (works); 2. split-brain: your URL, victim body ID;
# then read back as the victim, and 3. revert: the owner restores the victim object's value
for body in '{"_id":"OBJECT_A_ID","status":"probe"}' '{"_id":"OBJECT_B_ID","status":"probe"}'; do
  vigil assess kali exec --technique IDOR --probe-kind payload --identity user_a \
    --intent "split-brain body/route divergence" --phase consume-test --timeout 60 -- \
    curl -s -X PUT -H "Content-Type: application/json" -d "$body" https://target/api/orders/OBJECT_A_ID
done
vigil assess kali exec --technique IDOR --probe-kind replay --identity user_b \
  --intent "read back victim object after split-brain write" --phase consume-test --timeout 60 -- \
  curl -s https://target/api/orders/OBJECT_B_ID
vigil assess kali exec --technique IDOR --probe-kind cleanup --identity user_b \
  --intent "revert victim object after split-brain proof" --phase consume-test --timeout 60 -- \
  curl -s -X PUT -H "Content-Type: application/json" \
  -d '{"_id":"OBJECT_B_ID","status":"ORIGINAL_STATUS"}' https://target/api/orders/OBJECT_B_ID
```

Then vary: every body ID name the app uses (`_id`, `id`, `objectId`, `<domain>Id`, `uuid`, `pk`);
**add** a body ID where the client normally omits it (the fallback is URL-based, but an added ID
may override routing); nested sub-object IDs (`customer._id`, `items[]._id`); POST that creates an
object for or billed to a victim via body `userId`; bulk mixed IDs and GraphQL resolvers that use
an inner ID (idor-testing, graphql-testing). Sweep sibling verbs and related objects
(orders → invoices → payments) once one works.

Impact and severity follow `agent/references/finding-fp-and-severity-gate.md`: show the victim's
object changed (read back as the victim) and what that enables (sensitive read, email/password
change, financial or role field). A divergence that only touches your own data is not a finding.

## What to Record

The body field that overrides the route parameter, proof the URL-based check passed (that is what
makes it split-brain rather than plain IDOR), the victim object before/after, and the identities
that ran each step. Format: `agent/references/runtime-guides/web-finding-recording.md`.

## Kill Signals

- The server requires `body._id === req.params.id`, or returns a 400 naming an ID mismatch.
- Removing the body ID changes nothing (URL ID only).
- A straight URL swap already works: it is regular IDOR.

## Escalate When

- Profile/account-settings endpoints share the pattern → account takeover vector.
- A shared middleware/BFF fronts every endpoint → the flaw likely exists on every endpoint that
  accepts body IDs; sweep them.
- Nested array IDs are affected → batch manipulation of a victim's sub-resources.
