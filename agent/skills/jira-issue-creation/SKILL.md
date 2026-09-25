---
name: jira-issue-creation
description: Create or mirror a Jira issue with the right type, fields, labels, priority, and custom fields for the target instance. Auth is pluggable (Atlassian MCP tools or REST API v3 curl; basic / bearer / OAuth all valid) and the field payload is the reusable core. Use when delivering a finding or record into a Jira instance, especially when told to match an example ticket.
origin: Vigil
---

# Jira Issue Creation

Create a Jira issue that matches the target instance's own conventions. The
transport (MCP tools vs REST) and the auth method are interchangeable; the field
payload — type, fields, labels, priority, custom fields, description — is the
reusable core and the part worth getting right.

The ADF payload template, field/label/priority tables, response codes, and the
worked example live in `agent/references/tools/reporting/jira-api.md`. This skill
is the workflow around that reference; push long payloads there, keep this
skimmable.

## When to Activate

- A finding or record is being delivered as a Jira ticket.
- You are handed an example ticket and told to file "one like this."
- Any Jira create/update where the project's field, type, label, priority, and
  custom-field conventions must be matched exactly.

Not this skill: choosing a bug-bounty platform or drafting the submission prose —
that is `report-generation` (submission-first closeout). This skill starts once
the destination is a Jira instance.

For a Vigil finding, finish its report-writer QA, current reproduction check, and
applicable blind triage before creating the Jira issue. Run the final
`vigil assess export submission <slug> --platform direct --overwrite` gate and
use its reviewed external body as the issue description. If the ticket is an
ordinary non-finding record, this finding gate does not apply.

## Auth is pluggable; the payload is not

The `fields` object you send is identical no matter how you authenticate or which
transport carries it. Pick the transport by what is available; never let the auth
method leak into the payload design.

| Transport | Auth options | `description` format |
|---|---|---|
| Atlassian MCP tools | Handled by the connector session (already authenticated) | markdown (`createJiraIssue` converts to ADF) |
| REST API v3 (`curl`) | Basic (`user:api_token`, base64) **is one option**; bearer token / OAuth 2.0 are equally valid — set the `Authorization` header to match | ADF (see `jira-api.md`) |

Basic auth is not the assumed method — it is one of three. Whichever you use, the
issue payload below does not change.

## Transport A — Atlassian MCP tools (prefer when present)

Concrete tools, in the order you normally use them:

| Tool | Use |
|---|---|
| `getAccessibleAtlassianResources` | Get the `cloudId` **once**, reuse it for every later call. |
| `atlassianUserInfo` | Current `accountId` — for `assignee`/`reporter` when the instance requires one. |
| `searchJiraIssuesUsingJql` | Find the example ticket and any sibling/duplicate issues (JQL). |
| `getJiraIssue` | Read an issue. Pass `view: "evidence"` to see the **mapped custom fields** on an example issue (the compact default omits them). |
| `getJiraIssueTypeMetaWithFields` / `listJiraProjectIssueTypesMetadata` (via `executeRead`) | Read the create-screen field metadata: allowed values and required fields per issue type. |
| `createJiraIssue` | Create. Takes a **markdown** `description` (auto-converted to ADF). Custom fields go in `additional_fields`, keyed by field **name** or `customfield_*`. |
| `editJiraIssue` | Update fields after creation. |

`createJiraIssue` authoring markdown is the main reason to prefer MCP: you skip
hand-building ADF. The one gotcha that still bites (below) does not apply to
markdown you hand `createJiraIssue`, only to ADF you build yourself.

## Transport B — REST API v3 (`curl`, when MCP is absent)

Endpoints, the ADF `description` structure, and response codes are in
`jira-api.md`. In short: `POST /rest/api/3/issue` returns **201** with the new
key; `PUT` returns **204**; the create-screen metadata is
`GET /rest/api/3/issue/createmeta`. Set the `Authorization` header per the auth
option you are using — basic, bearer, or OAuth. The `description` here is ADF, not
markdown.

## Given an example issue, check these places

This is the core of mirroring a ticket. Every value below is **instance-specific**
— read it off the example and the create metadata; never carry a value over from
another Jira site.

| Check | Where to read it | Why it bites |
|---|---|---|
| Issue **type** + its **id** | Example issue `fields.issuetype`; `listJiraProjectIssueTypesMetadata` | Types expose *different* create-screen fields. A "Severity" select may exist on **Bug** but not **Task** — file under the wrong type and the field silently does not exist. |
| **Custom field IDs + allowed values** | `getJiraIssueTypeMetaWithFields` (create meta); or read the example in `view: "evidence"` | IDs differ per instance. A "Security Severity" field that is `customfield_10850` on one site is a different ID — or absent — on another. A hardcoded ID sets the wrong field or 400s. |
| **Labels** convention | Example issue `fields.labels` | Copy the project's actual label scheme; do not invent one. |
| **Priority** allowed values | Create meta `priority.allowedValues` | A project may offer only Urgent / High / Medium / Low and **not** Highest / Lowest. Read the real set — do not assume the standard five. |
| **Description** structure + format | Example issue body | Match section headings and their order. Author markdown for `createJiraIssue`; author ADF for REST v3. |
| Severity ↔ priority ↔ security-severity **mapping** | Derive from the example | Read how the example maps its severity onto priority and any security field. Do not assume a mapping. |

### The hardcoded-field-ID failure mode

An ID that is correct on one site is wrong on another. A doc (or a copied
payload) that hardcodes `customfield_XXXXX` as if canonical will, on a different
instance, either write to the wrong field or fail with a `400`. Always rediscover
the ID for the instance you are filing into. Ways to find an unknown ID:

1. **Create metadata** — `getJiraIssueTypeMetaWithFields` (MCP) or
   `GET /rest/api/3/issue/createmeta` (REST): lists every field on the create
   screen for that project + type, with `required` and `allowedValues`.
2. **Read an example issue** in `view: "evidence"` (MCP) — shows mapped custom
   fields and their current values.
3. **`GET /rest/api/3/field`** (REST) — the full field catalog; search it for the
   field's display name (e.g. "Security Severity") to get its `customfield_*` id.

## Confirm before creating (required)

Assemble the full proposed issue and show it to the user for sign-off **before**
the create call. The proposal must include:

- summary, issue type (and id), project
- labels, priority
- severity / security-severity (and the field each maps to)
- the rendered description (markdown for `createJiraIssue`, ADF for REST)

Only create after the user approves. If the create is rejected, a rejected
`createJiraIssue` returns the required fields plus their `allowedValues` — use
that response to self-correct the payload, then re-confirm.

## After creation — persist the local → Jira mapping

Record the created key against the local finding/record so the mapping is durable
and queryable; keep it out of the ticket body.

```bash
vigil assess finding update <slug> \
  --submission-status submitted \
  --submission-platform jira \
  --submission-ref <ISSUE-KEY> \
  --submission-url <issue url> \
  --reason "Filed as Jira issue <ISSUE-KEY>"
```

Keep internal cross-reference IDs **out** of the ticket. Describe sibling findings
by their outcome or code path, and express cross-ticket relationships with Jira's
native issue links (Linked Issues / Blocks / Epic) referencing the sibling by its
Jira key. This mirrors Rule 17 in `jira-api.md` ("Standalone-ticket rule") — see
it there rather than restating it.

## ADF gotcha (REST / hand-built ADF only)

The ADF `code` mark cannot be combined with `strong` or `em` on the same text
node — the v3 API rejects it. To get bold + inline-code, split the run into two
adjacent text nodes, one per mark. Full detail and example in `jira-api.md`
("Inline Marks"). Does not apply to markdown handed to `createJiraIssue`.

## Reference

- `agent/references/tools/reporting/jira-api.md` — ADF node/mark tables, the
  field / label / priority template, the `code`-mark gotcha, a full worked
  payload, and response codes. Treat every concrete ID/key/label in it as an
  example to rediscover per instance, not a canonical value.
