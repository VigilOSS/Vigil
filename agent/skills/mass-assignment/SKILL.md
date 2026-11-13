---
name: mass-assignment
description: Detect and exploit mass assignment and excessive data exposure in APIs and web applications
origin: Vigil
vuln_class: mass-assignment
---

# Mass Assignment Testing

## When to Activate

- Create/update endpoints bind request bodies to models (register, profile, settings, orders),
  responses return more fields than the UI uses, or a GraphQL mutation input takes nested objects.

`--technique MASS-ASSIGNMENT` (credits the `mass-assignment` class). Mark every write
`--destructive`. Injecting `role:admin` into your own test account's profile is a change to our
own test data and needs no approval; exploit approval is needed only when the write touches
another user's or the target's real state, triggers fulfilment, or moves money
(`agent/shared-constraints.md` §1). Run probes as named identities
(idor-testing "Vigil mechanics"). The field checklist (privilege, financial, verification and
state fields; response over-exposure; nested and GraphQL property access) is
`agent/references/api-security/API03-broken-property-authz.md`; load it for the field families.

## Methodology

1. **Collect candidate fields:** every field a GET returns, echoed back into the write; framework
   debug/schema endpoints; hidden-parameter discovery with the typed verb
   (`vigil assess kali arjun -u <url> -m JSON --technique MASS-ASSIGNMENT --intent "<purpose>"
   --probe-kind payload --phase consume-test --timeout 300`; `-m POST` for form bodies).
2. **Inject** privileged/state fields on create and update, including nested objects
   (`{"profile":{"role":"admin"}}`, `{"organization":{"owner_id":…}}`).
3. **Identifier fields** (`id`, `owner_id`, `user_id`): `vigil assess classify-payload <value>
   --mutations`; send the `escalation` variants to reassign to the first/admin object and the
   `format` variants (`"456"`, `[456]`, `{"id":456}`, `null`) because ORMs often coerce types the
   validator rejects.
4. **Content-Type divergence:** repeat the injection as JSON, form-encoded and XML; frameworks
   bind each with different rules.
5. **Framework binders:** Rails fields outside `params.permit`; DRF `fields` vs `exclude` on a
   ModelSerializer; Express body-parser output passed straight to Mongoose/Sequelize; Spring
   `@ModelAttribute` binding every request parameter.

Related: unfiltered list/search endpoints → idor-testing; client-supplied identity parameters a
BFF should have stripped → `agent/skills/bff-parameter-override/SKILL.md`; GraphQL input
over-posting → graphql-testing.

## Proof

GET before, the write with the extra field, GET after: the field changed and the change grants
something (`role: admin` reaching `/admin`, `is_verified: true` skipping confirmation, a balance
value persisted). A read-back is enough; completing a purchase or other financial action needs
explicit approval. Severity: `agent/references/finding-fp-and-severity-gate.md`. Format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- A field that is accepted but not persisted (read-back unchanged) is not a finding.
- Every binder and Content-Type ignores unknown fields → move on.
- Escalate when an identity or tenant field binds (cross-account), or a verification/approval flag
  binds (workflow bypass); combine with idor-testing or business-logic-testing.
