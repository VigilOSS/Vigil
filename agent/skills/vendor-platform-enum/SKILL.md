---
name: vendor-platform-enum
description: Deep enumeration of vendor multi-tenant platforms after one read primitive surfaces (Salesforce Aura/Lightning, ServiceNow GlideRecord, Drupal JSON:API, Pexip admin API)
origin: Vigil
---

# Vendor-Platform Deep Enumeration

> **`vigil assess kali` audit flags:** use `--technique INFO-DISCLOSURE` for SObject / table / entity reads; `--technique AUTH` when probing the anonymous-vs-authenticated boundary on the admin namespace.

## When to Activate

Activate this skill the moment any of the following triggers fires:

- A single Salesforce SObject (e.g., `User`, `Account`, `Network`) returned non-empty fields to an anonymous Aura `getRecordWithFields` request.
- A single ServiceNow `/api/now/v1/table/<table>` row returned non-empty data to an anonymous or low-privilege caller.
- A single Drupal `/jsonapi/<entity>/<bundle>` collection returned non-empty rows to an anonymous caller.
- A single Pexip `/api/admin/configuration/v1/<namespace>/` endpoint returned non-empty configuration data.
- The site fingerprint matches one of the four vendor classes (markers in §"Fingerprint triggers" below) AND no anonymous read primitive has been tested yet.

The pattern is consistent across all four classes: when one read primitive surfaces, the **same dispatch** must enumerate the full namespace and chain-disclose every adjacent object the leaked primitive points at. Stopping at the first leak misses the entire root cause — the anonymous-readable surface is rarely a single object.

## Why deep enumeration matters

Vendor multi-tenant platforms expose a wide namespace by default. The owning tenant administrator restricts that namespace via per-object / per-table / per-entity permission rules. The defaults are permissive enough that one mis-set Site Guest profile, one wide ACL row, one omitted `Access` annotation on a JSON:API resource, or one anonymous-allowed admin API namespace exposes dozens of objects, not one.

A finding that says "anonymous read on `User`" understates the impact when the same anonymous identity also reads `Account`, `Profile`, `Organization`, `Network`, and walks `LastModifiedById` chains into internal user records. The verifier and the report-writer cannot reconstruct that chain after the dispatch ends — the deep-enum playbook is the only place where the full graph of anonymous-readable objects gets recorded.

## Fingerprint triggers (per vendor class)

### Salesforce Aura / Lightning Communities

Site fingerprint markers:

- Static-asset prefix `/_slds/` (Salesforce Lightning Design System).
- Inline tag attributes `data-aura-rendered-by`, `data-aura-class`, `data-aura-namespace`.
- Script src includes `s.cdn.salesforce.com`, `lightning.force.com`, `force.com`.
- HTML form fields named `aura.token`, `aura.context`, or `aura.pageURI`.
- Path elements `/s/`, `/communities/`, `/sfsites/c/aura`, or `/aura?...`.
- Headers `X-SFDC-Request-Id`, `X-Sfdc-Page-Cache-Fingerprint`.

Trigger: any one marker plus a 200 response from `/aura?aura.ApexAction=...` or `/aura?other.aura.token=...`.

### ServiceNow GlideRecord

Site fingerprint markers:

- Static path `/scripts/sn_*.js`, `/styles/*.css?v=...` with `Server: ServiceNow`.
- HTML body includes `g_form`, `g_user`, `g_navigation`, or `var NOW = ...`.
- Cookie names `glide_user`, `glide_session_store`, `JSESSIONID` paired with `Server: ServiceNow`.
- Path element `/now/nav/ui/`, `/api/now/`, or `/sys_db_object_list.do`.

Trigger: any one marker plus a 200 from `/api/now/v1/table/sys_user?sysparm_limit=1`.

### Drupal JSON:API

Site fingerprint markers:

- HTTP header `X-Generator: Drupal X (https://www.drupal.org)`.
- `Server: Apache` or nginx with cookies named `SESS<hash>` or `Drupal.visitor.*`.
- Path element `/sites/default/files/`, `/core/misc/`, or `/themes/<name>/css/`.
- 200 response from `/jsonapi/` returning `{"jsonapi":{"version":"1.0"},...}`.

Trigger: a 200 response from `/jsonapi/` exposing the entity-type root.

### Pexip Infinity admin / management

Site fingerprint markers:

- Path element `/admin/`, `/api/admin/`, `/api/admin/configuration/`, `/admin/platform/`.
- Server banner `nginx` plus `pexipadmin` cookie OR a JSON 200 from `/api/admin/configuration/v1/`.
- Body includes references to `conferencing_node`, `worker_vm`, or `upgrade_package`.
- Title tag `Pexip Infinity Administrator interface`.

Trigger: a 200 (or even 401 with body) from `/api/admin/configuration/v1/`.

## Methodology

The four playbooks share a five-step shape: enumerate the namespace, describe each entity, read the tenant-singleton record, mine the leaked record for adjacent IDs, then test bounded-vs-systemic. Apply the steps in order — each step's output is the input for the next.

### 1. Salesforce Aura / Lightning playbook

#### 1.1 — Namespace enumeration via `getObjectInfos`

The Aura client sends a single `getObjectInfos` action that returns describe metadata (fields, relationships, picklist values) for any SObject the caller can describe. Anonymous Site Guest sessions can usually describe the standard namespace plus most installed managed-package SObjects.

Probe SObject names from this 30+ list (see also `agent/references/payloads/salesforce-aura-payloads.md` for the full standard + custom set and the Aura POST envelope shape):

`Account`, `Contact`, `Lead`, `Opportunity`, `User`, `UserRole`, `Profile`, `Organization`, `Network`, `NetworkMember`, `Case`, `CaseComment`, `Knowledge__kav`, `KnowledgeArticleVersion`, `Topic`, `TopicAssignment`, `FlowDefinition`, `FlowDefinitionView`, `StaticResource`, `ContentVersion`, `ContentDocument`, `ContentDocumentLink`, `FeedItem`, `FeedComment`, `ProcessDefinition`, `ProcessNode`, `Holiday`, `Translation`, `BusinessHours`, `RecordType`, `Group`, `GroupMember`, `Pricebook2`, `Product2`, `OpportunityLineItem`, `EmailMessage`, `Attachment`, `Document`, `Folder`, `LoginHistory`, `LoginGeo`.

Probe per-SObject describe results — anything that returns a non-empty `defaultRecordTypeId`, `urls.sobject`, or `fields[]` array is anonymous-describable.

#### 1.2 — Tenant-singleton reads via `getRecordWithFields`

For each describable SObject, read the **organization-wide singleton record** using its tenant-prefix Id pattern. Anonymous guests sometimes read these even when adjacent records require authentication.

Tenant-singleton Id prefixes:

- `00D...` — `Organization` (one per tenant)
- `00e...` — `Profile` (Site Guest profile is one of these; reading it leaks the FLS / object permissions of the guest user)
- `0DB...` — `Network` (one per Experience Cloud site)
- `00G...` — `Group` (queues, public groups)
- `00E...` — `UserRole`
- `0Pc...` — `BusinessHours`

Send one `getRecordWithFields` per singleton. Record every non-error response, even when the body looks like an empty stub — a 200 with `recordId` echo confirms the SObject is anonymous-readable; field values follow once the request asks for the right field set.

#### 1.3 — Chain-disclosure via leaked Id walks

Every leaked record carries audit fields that point at internal users:

- `LastModifiedById`, `CreatedById` — user Id of the writer
- `OwnerId` — user, queue, or group that owns the record
- `RecordTypeId` — record type metadata
- `<lookup-field>__c` — custom lookup fields point at adjacent SObjects

Walk each Id with another `getRecordWithFields` call. A leaked `User` record from one walk seeds the next walk via its `ManagerId`, `ProfileId`, `UserRoleId` — chain depth of 3-5 hops is normal. Stop the walk when (a) a hop returns 401/403, or (b) the walk loops back to an Id you have already enumerated.

#### 1.4 — Managed-package fingerprint via `__<Field>` patterns

Salesforce managed packages namespace their custom fields and SObjects with a `<PKG>__<Field>` pattern (e.g., `npe01__SystemAccountProcessor__c`, `npsp__Batch_Number__c`, `FF__Transaction_Type__c`). Search every leaked `ContentVersion`, `StaticResource`, `Document`, and `Attachment` body for the `<PKG>__` pattern — installed package detection lets the operator pull the package's known-issue list and seed Phase 5 exploit hypotheses.

#### 1.5 — Adjacent-record IDOR boundedness test

Flip the last character of one leaked recordId and re-issue `getRecordWithFields`. Two outcomes:

- **Bounded leak:** the adjacent Id returns 404 / 401 / "Insufficient access" — the anonymous-readable surface is the org-wide singleton plus its chain-walk graph; no systemic IDOR is present.
- **Systemic leak:** the adjacent Id returns 200 with a different record's data — the entire SObject is anonymous-enumerable, and the finding severity escalates from "single-record disclosure" to "tenant-wide enumeration".

Record the outcome — the bounded-vs-systemic distinction is what drives the verifier's severity decision.

#### 1.6 — Rate-limit discipline for the Aura playbook

A single Aura POST is cheap, but the playbook's full first pass sends **30+ POST requests** in one dispatch (namespace enumeration + singleton reads + chain walks). Rate-limit accordingly:

- Default to 1 request / 250ms (4 RPS) per dispatch.
- If the target sits behind a vendor edge with rate-limit signals (429, `X-RateLimit-Remaining`, `Retry-After`), drop to 1 request / 1000ms.
- Send the namespace enumeration in a single batched POST when the Aura schema supports it (one envelope, multiple actions) rather than 30 separate requests.

`agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy" defaults the Vendor SaaS row to 60 RPS aggregate; the Aura playbook is well under that, but operator opt-in should still gate the deep-enum dispatch when the target's policy is unknown.

### 2. ServiceNow GlideRecord playbook

#### 2.1 — Table namespace enumeration

ServiceNow exposes per-table REST endpoints at `/api/now/v1/table/<table_name>`. Anonymous (no `Authorization` header) and low-priv (`itil_user`, `snc_internal`) callers sometimes read tables when the per-table ACL is misconfigured.

Probe these well-known tables (full list in `agent/references/payloads/servicenow-glide-payloads.md`):

`sys_user`, `sys_user_group`, `sys_user_grmember`, `sys_user_role`, `sys_user_has_role`, `sys_db_object`, `sys_dictionary`, `sys_choice`, `sys_properties`, `sys_security_acl`, `incident`, `change_request`, `problem`, `cmdb_ci`, `cmdb_ci_computer`, `cmdb_ci_server`, `cmdb_rel_ci`, `kb_knowledge`, `sc_cat_item`, `sc_request`, `sc_req_item`, `sys_attachment`, `sys_email`, `sysapproval_approver`, `sysauto_script`, `sys_script`, `sys_script_include`, `sys_script_action`, `sys_audit`, `sys_history_set`, `sys_log`, `sys_metadata`, `task`, `cmn_location`, `core_company`.

For each table, send `GET /api/now/v1/table/<table>?sysparm_limit=1` and record the response code and shape.

#### 2.2 — Row-level read with `sysparm_query` and `sysparm_display_value`

Once a table responds 200, pull a sample with the display-value variant — display values resolve referenced Sys IDs to human-readable strings, which makes the chain-disclosure walk in step 2.3 trivial:

```
GET /api/now/v1/table/<table>?sysparm_limit=10&sysparm_display_value=true&sysparm_exclude_reference_link=false
```

The `sysparm_query=` parameter accepts encoded queries — `?sysparm_query=active=true^ORDERBYsys_created_on` walks recent records first.

#### 2.3 — Chain-disclosure via reference fields

GlideRecord rows carry reference fields that point at adjacent tables (`assigned_to` → `sys_user`, `cmdb_ci` → `cmdb_ci`, `parent` → same table). Walk each reference with another `/api/now/v1/table/<ref-table>/<sys_id>` read. Same termination rules as the Salesforce playbook: stop at 401/403/loop.

#### 2.4 — Bounded-vs-systemic test

Flip the last character of one leaked `sys_id` and re-issue. Same bounded-vs-systemic interpretation as §1.5.

### 3. Drupal JSON:API playbook

#### 3.1 — Entity-type enumeration

`GET /jsonapi/` returns the full set of entity-type / bundle pairs the API exposes. Anonymous callers typically receive the same root document that authenticated callers do — the access decision happens per-resource, not at the root.

Common entity-type / bundle pairs to enumerate (full list in `agent/references/payloads/drupal-jsonapi-payloads.md`):

`node/article`, `node/page`, `node/<custom-bundle>`, `user/user`, `taxonomy_term/<vocab>`, `file/file`, `media/<bundle>`, `block_content/<type>`, `comment/<type>`, `menu_link_content/menu_link_content`, `paragraph/<bundle>`, `commerce_product/<type>`, `commerce_order/<type>`, `webform_submission/<webform>`, `eck_entity/<bundle>`.

For each pair, send `GET /jsonapi/<type>/<bundle>?page[limit]=1` and record the response code.

#### 3.2 — Sparse-fieldset abuse

Drupal JSON:API supports sparse fieldsets (`?fields[<type>--<bundle>]=field_a,field_b`). The default field set sometimes hides sensitive fields (e.g., `mail`, `roles`, `field_internal_note`); the sparse fieldset parameter forces the response to include them when the per-field access check is missing or misconfigured:

```
GET /jsonapi/user/user?page[limit]=1&fields[user--user]=mail,name,roles,field_phone,field_internal_note
```

#### 3.3 — `filter[]` query and includes

`?filter[<field>]=<value>` and `?filter[<group>][<field>][value]=<value>` query rows server-side. Combined with `?include=<related-resource>`, one request returns the row plus its referenced resources — the JSON:API equivalent of the chain walk:

```
GET /jsonapi/node/article?filter[uid.id]=<user-uuid>&include=uid,field_attachment
```

#### 3.4 — Bounded-vs-systemic test

Replace the UUID in a `?filter[uid.id]=<uuid>` query with a different UUID. Same interpretation as §1.5.

### 4. Pexip admin / management API playbook

#### 4.1 — Namespace enumeration

Pexip Infinity exposes a configuration API at `/api/admin/configuration/v1/<namespace>/`. The namespaces are documented (admin-API guide); when the front-end auth control is misconfigured (e.g., the `pexipadmin` cookie check is missing or the path is exposed without auth on a backup management VLAN), anonymous callers can read configuration namespaces directly.

Namespaces to probe (full list in `agent/references/payloads/pexip-admin-api-payloads.md`):

`conference`, `conferencing_node`, `worker_vm`, `system_location`, `mssip_proxy`, `h323_gatekeeper`, `gms_access_token`, `automatic_participant`, `end_user`, `event_sink`, `external_participant`, `gateway_routing_rule`, `global_configuration`, `media_server`, `policy_server`, `recurring_conference`, `registration`, `role`, `sip_proxy`, `sso_profile`, `static_route`, `syslog_server`, `system_tuneable`, `tls_certificate`, `upgrade_package`, `web_app_alias`.

For each namespace, send `GET /api/admin/configuration/v1/<namespace>/?limit=1` and record the response code.

#### 4.2 — Admin-token vs anonymous reachability

A Pexip-managed deployment uses `Authorization: Basic <base64(admin:password)>` for the admin API. Test three reachability profiles per namespace:

- **Anonymous** — no Authorization header. A 200 here is the high-impact finding (the anonymous-readable surface).
- **Default-admin guess** — `admin:admin`, `admin:pexip`, `admin:Password1`. A 200 here is a separate finding (default credentials, not a no-auth misconfig).
- **Operator-supplied credentials** — only when the engagement has explicit credentials. Distinguishes "low-priv operator can read the upgrade package list" from "anonymous can read it".

#### 4.3 — Configuration-leak chain

A leaked `conferencing_node` row exposes the FQDN of every conferencing node, its IP, its TLS cert fingerprint, its system_location, and its event_sink target. Each of these is an adjacent finding seed:

- FQDN → DNS-record intel + subdomain-enumeration cross-feed.
- system_location → `/api/admin/configuration/v1/system_location/<id>/` → DNS / NTP / syslog server addresses.
- event_sink → external monitoring URL + bearer-token if exposed.

#### 4.4 — Rate-limit discipline

Pexip configuration namespaces are admin-tier endpoints — assume the management plane runs on lower-spec hardware than the conferencing plane. Default to 1 request / 500ms (2 RPS) and step down on the first 5xx.

## Recording the deep-enum result

For each vendor class, record one or more findings via `vigil assess finding record <agent> <finding-json-file>`:

- One finding per **bounded** anonymous-read primitive (org-singleton + chain-walk graph of length ≥ 1).
- One finding per **systemic** anonymous-read primitive (the bounded-vs-systemic test returned 200 on adjacent IDs).
- One finding per **default-credential** discovery on Pexip namespaces (separate from the anonymous-read finding).
- One finding per **chain-disclosure** that pulls in ≥ 3 unique objects from the namespace (the chain itself is the high-severity finding, separate from the per-primitive read).

The `details` block should include:

- `vendor_class` — `salesforce-aura | servicenow-glide | drupal-jsonapi | pexip-admin-api`.
- `namespace_enumerated_count` — number of objects probed.
- `namespace_readable_count` — number that returned 200 to the anonymous probe.
- `chain_walk_depth` — number of hops in the longest chain walk.
- `bounded_or_systemic` — verdict from §1.5 / §2.4 / §3.4.
- `installed_packages_or_namespaces` — for Salesforce, the `<PKG>__` set fingerprinted in §1.4; for ServiceNow, the table-prefix set; for Drupal, the bundle-prefix set; for Pexip, the namespaces returning 200.

Record intelligence rows for adjacent assets the chain walk surfaced (DNS records, internal user names, internal hostnames) via `vigil assess intel record`.

## What to Record

- Per-vendor-class fingerprint markers that fired
- Full namespace probe results (count probed, count readable)
- Chain-walk graph (which Ids hopped to which, terminating reasons)
- Bounded-vs-systemic verdict and the IDOR-flip test evidence
- Rate-limit / 429 / 5xx events that bounded the dispatch
- Installed managed packages (Salesforce) or table prefixes (ServiceNow) or bundle prefixes (Drupal) or readable namespaces (Pexip)
- Coverage gaps (probes that the dispatch could not run because of credential gaps, rate limits, or scope)

## Extended Resources

- `agent/references/payloads/salesforce-aura-payloads.md` — Aura POST envelope shape, full SObject probe list, tenant-singleton Id prefix table, chain-walk reference-field map.
- `agent/references/payloads/servicenow-glide-payloads.md` — table probe list, `sysparm_query` syntax, `sysparm_display_value=true` chain-walk pattern.
- `agent/references/payloads/drupal-jsonapi-payloads.md` — entity-type / bundle list, sparse-fieldset abuse, `filter[]` query DSL.
- `agent/references/payloads/pexip-admin-api-payloads.md` — admin-API namespace list, anonymous-vs-admin reachability triad, configuration-leak chain seeds.
- `agent/references/payloads/csp-default-grep.md` — placeholder-literal grep pattern for vendor-template CSP/CORS re-baseline (see web-recon vendor-template step).
- `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy" — Vendor SaaS row carries the rate ceiling for the deep-enum dispatch.
