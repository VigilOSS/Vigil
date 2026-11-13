---
description: IDOR in ORM queries, mass assignment, serializer over-exposure, GraphQL field auth, bulk endpoints
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS/TS, Java, Ruby, Go, PHP, C#
---

# Web Application Data Exposure — IDOR in Code, Mass Assignment, and Response Over-Sharing

The query is valid and the authorization is absent, keyed on the wrong thing, or one layer away.
IDOR is semantic: `Order.find(id)` carries no tainted flow, and authorization is often spread across
middleware, services, hooks, and other files, so no single query can be judged locally.

## Root-Cause Taxonomy

Name the cause; it makes the miss obvious and the fix complete. The Detection Questions cite these
letters.

- **(a) Authenticated treated as authorized.** Logged in says who, never what they own.
- **(b) Second route, unscoped.** The HTML controller scopes; the JSON API, list endpoint, CSV/ICS/PDF
  export, webhook, or background job re-implements the lookup without the filter.
- **(c) Parent checked, child fetched by raw PK.** `require_member(workspace_id)` guards the route,
  then `Issue.find(issue_id)` has no `workspace_id` constraint.
- **(d) Client-supplied identity.** Tenant, owner, or user id read from the body, a header, a query
  parameter, or an editable JWT claim instead of the session.
- **(e) UUIDs as the control.** The ownership check is dropped because ids are random; ids still
  leak through logs, Referer headers, shared links, and related objects.
- **(f) Deny-list binding.** `$guarded = ['is_admin']`, `read_only_fields`, MVC 5
  `[Bind(Exclude=...)]` fail open on the next sensitive column.
- **(g) Horizontal and vertical checks in different layers**, one of which forgets its half.
- **(h) Resolution before authorization.** Route-model binding or a lookup runs before the policy,
  leaking a 404-versus-403 existence oracle or skipping authorization when the policy is not attached.
- **(i) Default-allow framework behavior:** auto-exported repositories, RLS-disabled tables,
  `fields = '__all__'`.
- **(j) Copy-pasted query** that dropped its `.filter(user=...)` — the most common mechanical cause.
- **(k) Object passes, property fails (BOPLA):** the right object, but the response over-exposes or
  the update over-writes properties the caller should not control.
- **(l) Write to a nonexistent parent** that returns success, producing an orphaned artifact rather
  than impact on a real record (the blob may still be downloadable; see
  `agent/references/access-control/idor-modern-architectures.md`).

**Classify correctly.** CWE-639 is canonical IDOR (a user-controlled key), CWE-566 its SQL-PK child,
CWE-862 no check at all, CWE-863 a check that validates the wrong thing (wrong privilege tier,
wrong object), CWE-602 client-side enforcement, CWE-213 property exposure. BOLA (OWASP API1, wrong
object) → `agent/references/api-security/API01-broken-object-level-authz.md`; BOPLA (API3, wrong
property) → `API03-broken-property-authz.md`; BFLA (API5, wrong function) →
`API05-broken-function-authz.md`. See also `agent/skills/idor-testing/SKILL.md` and
`agent/references/access-control/idor-identifier-prediction.md`.

**CVE citation discipline.** Product-named CVE roundups are often mislabeled (CVE-2024-13585 and
CVE-2024-13155 are stored XSS listed as IDOR; CVE-2026-1389 "Document Embedder" is a plain WordPress
IDOR, not a RAG bug). Read the NVD entry and state the precise CWE and the missing check; when a
writeup has no CVE, cite the pattern, never a made-up number.

## What You're Hunting (LLM-Advantage Patterns)

### 1. Missing or misplaced ownership filter

Primary-key lookups with no owner or tenant predicate: Django `get_object_or_404(Order, pk=id)` and a
DRF `ModelViewSet` with `queryset = Order.objects.all()` and no `get_queryset()` override
(`get_object()` reads from it); Mongoose `findById`; Spring Data `findById` returning the entity;
Rails `Order.find(params[:id])` where `current_user.orders.find(...)` is the idiomatic scope. Check
the leaf of nested routes (c), the mutation handlers alongside the read (a), and every list, search,
and export path (b): pagination and client-side filtering do not scope data the API already returned.

### 2. Mass assignment

- Spring `@ModelAttribute` binds query and form parameters, so `?role=ADMIN` sets the field even on a
  JSON-looking endpoint; bind a DTO instead.
- DRF: fields listed explicitly in `fields` are writable unless they are also in `read_only_fields`
  (`fields = ['id', 'username', 'role']` makes `role` writable).
- Mongoose `findByIdAndUpdate(id, req.body)` and Sequelize `update(req.body)`.
- Rails `params.permit!`, `params.to_unsafe_h`, or a `permit` list that includes `role`/`admin`.
- Laravel `$guarded = []`, `forceFill()`, and `Model::unguard()`; a model with neither `$fillable`
  nor `$guarded` defaults to `$guarded = ['*']`, so it is not mass-assignable.
- ASP.NET Core binding the EF entity (overposting). Core's `[Bind]` supports only `Include` and has
  no effect on `[FromBody]` JSON, which `[ApiController]` infers for complex types; use DTOs.
- `BeanUtils.copyProperties(dto, entity)` (Spring or Commons BeanUtils) copies every matching
  property.

### 3. Serializer over-exposure

The response carries fields the UI never renders. DRF `fields = '__all__'` and nested serializers
that use it; Mongoose documents returned whole (a schema `toJSON` transform strips fields, but
`lean()` returns plain objects that bypass it); Sequelize `findAll()` without `attributes`; Prisma
queries without `select`; a Spring entity serialized directly (prefer a record DTO to `@JsonIgnore`
on each field); Jackson/JAXB serializing every public getter, so adding a getter exposes a field;
a controller method missing its `@JsonView`; Next.js server components passing a whole object as
props, which serializes it to the client.

### 4. GraphQL field authorization

A resolver that returns the whole row makes every field in the SDL selectable
(`{ user(id: 1) { passwordHash ssn } }`); authorization must be per field resolver, and fields that
must never leave the server should not be in the schema.

### 5. Error responses that map the schema

DRF validation errors on an empty POST enumerate every required field, including internal ones; Spring
`server.error.include-stacktrace=always` returns SQL and table structure in 500 responses.

### 6. Framework default-behavior traps

- **Laravel route-model binding:** `SubstituteBindings` runs before `Authorize`, so the model is
  resolved (and existence leaks) before any policy; without `->middleware('can:view,order')` or
  `$this->authorize('view', $order)` there is no ownership check at all.
- **EF Core** `Find`/`FindAsync` resolves by primary key only; add the owner predicate with
  `FirstOrDefaultAsync(o => o.Id == id && o.UserId == uid)`.
- **Go:** no ORM scopes by tenant; `db.Where("id = ?", id).First(&o)` copied without
  `AND tenant_id = ?` is the bug. A reusable scope (`db.Scopes(TenantScope(ctx))`) backed by RLS is
  the robust form.
- **Prisma:** `findUnique({ where: { id: params.id } })` takes the id from the URL. Since Prisma 5,
  `findUnique` accepts non-unique filters next to the unique key (`where: { id, ownerId }`), and
  `findFirst` works on every version; on older versions `findUnique` cannot carry the owner predicate.
- **Hasura / Supabase:** a Hasura permission with `"filter": {}` or `"columns": ["*"]` leaks every
  row. Postgres tables created by SQL or migrations have RLS off, so the Supabase anon key reads and
  writes every row; the Supabase dashboard enables RLS for tables it creates. In policies, wrap
  `auth.uid()` as `(select auth.uid())` so it is evaluated once rather than per row.
- **Spring Data REST** (when on the classpath) exports every `CrudRepository`/`JpaRepository` as
  full CRUD at `/orders` and `/orders/{id}`, unauthenticated unless Spring Security covers those
  paths. Fixes: `@RepositoryRestResource(exported = false)`, `RepositoryDetectionStrategy.ANNOTATED`,
  and method-level `@PreAuthorize` on exported queries and mutations.
- **Dynamic filters:** django-filter `filterset_fields = '__all__'` exposes exact-match filtering on
  every field, a boolean oracle on sensitive columns; the dict form with `startswith`/`contains`
  lookups enables character-by-character extraction. Spring `Specification`/`Predicate` and `?filter=`
  passthroughs built from request parameters can widen a scoped query.

## Detection Questions

1. **Leaf or parent?** (c) In nested routes, find the `findById(childId)` that runs after a parent
   membership check.
2. **Session or request?** (d) Grep identity sourced from `req.body`, `req.query`, `req.headers`,
   `params`, or editable claims (`jwt.tenant`, `claims.org`) versus `req.user.id`,
   `session.user.id`, `current_user`.
3. **Raw PK lookups?** (j) `\.Find(`, `\.FindAsync(`, `findUnique\(`, `findById\(`,
   `\.find\(params\[:id\]\)`, `get_object_or_404\([A-Za-z]+, *pk=` without an owner predicate.
4. **Binding or auto-CRUD ahead of the policy?** (h, i) `Route::.*\{[a-z]+\}` without `can:` or
   `authorize`; `extends CrudRepository|JpaRepository` without `@PreAuthorize` or `exported=false`.
5. **Allow-list or deny-list binding?** (f) `$guarded`, `fields = '__all__'`, whole `req.body` into
   an update, `[Bind(` with `Exclude`, `BeanUtils.copyProperties`.
6. **RLS on every exposed table?** (i) Migrations with `create table` and no `enable row level
   security`; Hasura `filter: {}`.
7. **Whole object or selected fields?** (k) `return $model`, `res.json(doc)` without `.select`,
   `Ok(entity)`, Prisma without `select:`.
8. **Do the mutation handlers re-apply the read's scope?** `PUT`, `DELETE`, and GraphQL mutations;
   fixing only the read is the classic incomplete remediation.
9. **Do lookup misses and authorization failures deny,** rather than falling through to a
   default-allow branch (ASVS V4.1.5)?
10. **Inline privilege checks?** Scattered `if (user.isAdmin)` / `current_user.admin?` in feature
    controllers instead of one policy get forgotten on new routes (BFLA).
11. **Second route to the same object?** (b) The object's repository call in export, report, webhook,
    or batch handlers that reuse a raw call the main controller scoped.
12. **Can the caller widen a bulk filter?** (k) `filterset_fields = '__all__'`, request-built
    `Specification`/`where`, `?filter=` passthroughs.

## Real CVE Examples

- **CVE-2024-7041 (open-webui ≤ 0.3.8, CWE-639).** `PUT /api/v1/memories/{id}/update` keyed solely on
  the path id while the read was scoped (a): every mutating handler must re-derive ownership. LLM
  "memory" stores are user-scoped data like any table.
- **CVE-2024-48899 (Moodle, CWE-639).** The badge list endpoint skipped the course-access check the
  detail view applied (b).
- **CVE-2023-3219 (EventON WordPress plugin < 2.1.2, CWE-639, unauthenticated).** The
  `eventon_ics_download` AJAX action did not check that `event_id` was a valid event, so the ICS
  export returned any post's content, unpublished and protected posts included (b): export side
  channels forget the check.
- **PraisonAI workspace issues (2026, no CVE assigned).** Routes checked
  `require_workspace_member(workspace_id)`; the service fetched `issue_id` by primary key alone (c),
  and actions were logged under the attacker's workspace, evading the victim's audit trail.
- **CVE-2025-27507 (ZITADEL, CWE-639).** Admin API endpoints let authenticated users without the
  required IAM roles modify sensitive instance settings, most critically the LDAP configuration,
  which redirects LDAP logins: an admin surface that checks authentication but not the role.
- **CVE-2025-48757 (Lovable-generated Supabase apps).** 303 endpoints across 170 projects had RLS
  disabled, so the anon key read and often wrote every row (i): the audit question is whether RLS is
  on for every exposed table.
- **McHire / Paradox.ai (2025, no CVE).** An admin console with password `123456` plus
  `/api/lead/cem-xhr` serving applicants by sequential `lead_id` exposed about 64M records:
  enumerable ids, no object check, and weak admin auth stacked. Rate limits and audit logs are not
  authorization.
- **CVE-2023-23752 (Joomla 4.0-4.2.7).** A `public=true` request parameter overrode the API's access
  check, so `/api/index.php/v1/config/application?public=true` returned configuration including
  database credentials without authentication.

## Remediation Notes

- Owner-scoped queries are the baseline but are dropped on copy-paste (j); a reusable scope (Rails
  `current_user.orders`, GORM scopes, a base queryset) makes the safe path the easy one.
- Spring `@PostAuthorize` runs after the query (the row is loaded and any side effect has happened);
  prefer `@PreAuthorize` or scoped queries. Laravel policies fire only when attached and after
  binding. OPA/Rego and Cedar decide nothing unless fed `resource.owner`.
- RLS is a backstop that must be enabled per table.
- DTOs for reads and writes stop new columns being auto-exposed or auto-bound, but a handler still
  binding the entity silently keeps the old behavior.
- UUIDs and indirect reference maps are defense in depth, never the fix (OWASP IDOR cheat sheet).
- Apply the fix to every path that touches the object: read, write, export, webhook, batch, GraphQL
  mutation.
- Report against ASVS V4.2.1 and API1 (BOLA), API3 (BOPLA), or API5 (BFLA).
