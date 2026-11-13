---
name: vendor-platform-enum
description: Deep enumeration of vendor multi-tenant platforms after one read primitive surfaces (Salesforce Aura/Lightning, ServiceNow GlideRecord, Drupal JSON:API, Pexip admin API)
origin: Vigil
---

# Vendor-Platform Deep Enumeration

## When to Activate

- One anonymous or low-privilege read returned data from a vendor multi-tenant platform: a
  Salesforce SObject via Aura `getRecordWithFields`, a ServiceNow `/api/now/v1/table/<table>` row,
  a Drupal `/jsonapi/<entity>/<bundle>` collection, a Pexip
  `/api/admin/configuration/v1/<namespace>/` endpoint.
- Or the site fingerprints as one of these platforms and no anonymous read has been tested yet.

When one primitive surfaces, **this dispatch** enumerates the whole namespace and walks every
adjacent object the leak points at. The defaults are permissive (one mis-set Site Guest profile,
wide ACL row, missing JSON:API access rule or anonymous admin namespace exposes dozens of
objects), and the verifier and report-writer cannot reconstruct the graph after the dispatch ends.

`--technique INFO-DISCLOSURE` for object/table/entity reads; `AUTH` when probing the
anonymous-vs-authenticated boundary of an admin namespace.

## Per-vendor payloads (load the matching one when the fingerprint fires)

`vigil assess list-references --skill vendor-platform-enum` lists them; each carries the
fingerprint markers, probe lists, chain-walk fields, the boundedness test and rate notes:

- `agent/references/payloads/salesforce-aura-payloads.md` — Aura envelope, SObject list,
  tenant-singleton Id prefixes (`00D` Organization, `00e` Profile, `0DB` Network, …), chain-walk
  fields, managed-package (`<PKG>__`) fingerprint, ContentVersion servlets, `executeAction`.
- `agent/references/payloads/servicenow-glide-payloads.md` — table list, `sysparm_query`
  (including `javascript:` queries), `sysparm_display_value=true` walks, aggregate API,
  operator-gated default credentials.
- `agent/references/payloads/drupal-jsonapi-payloads.md` — entity/bundle pairs, sparse
  fieldsets, `filter[]`, `?include` traversal, webform submissions.
- `agent/references/payloads/pexip-admin-api-payloads.md` — namespace list, the
  anonymous/default/operator reachability triad, configuration-leak chain.

## Method (same five steps for every vendor)

1. **Enumerate the namespace** (describe/list every object type the caller can see).
2. **Describe** each readable entity (fields, relationships).
3. **Read the tenant singleton** records (organization, guest profile, site/network), which
   guests often read when neighbours are protected.
4. **Walk leaked IDs** (`CreatedById`, `LastModifiedById`, `OwnerId`, reference fields,
   `display_value` links): 3-5 hops is normal; stop on 401/403 or when the walk loops.
5. **Bounded vs systemic.** Test enumerability with a real second record: an unfiltered list
   (`sysparm_limit`, `page[limit]`, an Aura list action) or another harvested ID. Never by
   mutating an ID: Salesforce Ids end in a checksum and Sys IDs/UUIDs are random, so a mutated
   ID fails by construction and would always read as "bounded". Pexip's sequential IDs are the
   exception, where walking the integer range is the test.

Rate: about 4 requests/s per dispatch, 1/s on 429/`Retry-After`/rate-limit headers; batch Aura
actions in one envelope where the schema allows (`agent/references/runtime-guides/dispatch-resource-policy.md`
Vendor SaaS row). Trying the vendor's documented default credentials (a handful of requests) is
not brute force; credential brute force is in scope unless the VDP forbids it
(`agent/rules/hunting.md` §10).

## Recording

- One finding per root-cause misconfiguration (the anonymous-read primitive, with its chain-walk
  graph as evidence; a systemic result raises its severity rather than adding a second finding),
  plus a separate finding for a distinct root cause such as Pexip default credentials.
- `details.bounded_or_systemic` carries the step-5 verdict. Vendor class, counts probed vs
  readable, chain depth and installed packages/table prefixes/bundles/namespaces go in
  `details.evidence` (they have no dedicated keys).
- Adjacent assets the walk surfaced (internal users, hostnames, DNS) → `vigil assess intel record`.
- Coverage gaps: probes not run because of credentials, rate limits or scope.

Vendor-template CSP/CORS defaults on the same site: `agent/references/payloads/csp-default-grep.md`.
