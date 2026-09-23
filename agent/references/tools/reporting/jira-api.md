---
description: "Jira REST API v3 payload reference: issue CRUD, ADF formatting, field/label/priority template, response codes"
skill: jira-issue-creation, report-generation
---

# Jira API (v3)

**Purpose:** The ADF payload and field reference for creating, updating, and
querying issues in Jira via the REST API v3. This is the payload core behind the
`jira-issue-creation` skill — the workflow (pluggable auth, MCP vs REST, mirroring
an example ticket, confirm-before-create) lives in that skill; the concrete
payload shapes live here.

Jira v3 uses **Atlassian Document Format (ADF)** for rich-text fields — not markdown.
All `description` payloads sent to the REST API must be valid ADF documents. (The
Atlassian MCP `createJiraIssue` tool instead takes markdown and converts it for
you — see the `jira-issue-creation` skill.)

> **Every concrete value below is an instance-specific EXAMPLE, not a canonical
> constant.** Instance base URL, project key, issue type id, custom field ids,
> label scheme, and the priority set all differ per Jira site. Rediscover them for
> the instance you are filing into (create metadata / `GET /rest/api/3/field` /
> read an example issue) — never copy an id or key from here or from another site.
> Placeholders used in the examples below: `YOUR_ORG` (instance base URL), `SEC`
> (an example security-project key, with keys like `SEC-1234`), and `10013` (an
> example issue type id). Substitute your instance's real values.

---

## Authentication

Auth is **pluggable** — pick whichever the environment provides and set the
`Authorization` header to match. The payload does not change with the auth method.

- **Basic** (one option): base64-encoded `user:api_token`.
- **Bearer / OAuth 2.0**: `Authorization: Bearer <token>` — equally valid.
- **Atlassian MCP tools**: the connector session is already authenticated; no
  header to build. Prefer this when present (see the `jira-issue-creation` skill).

Basic-auth example (substitute the Jira email and an Atlassian API token):

```bash
AUTH="Authorization: Basic $(echo -n 'USER:API_TOKEN' | base64)"
```

---

## Common Operations

### List issues (JQL search)

```bash
curl -s "https://YOUR_ORG.atlassian.net/rest/api/3/search?jql=project=SEC&maxResults=50" \
  -H "$AUTH"
```

### Get a specific issue

```bash
curl -s "https://YOUR_ORG.atlassian.net/rest/api/3/issue/SEC-1234?fields=summary,description,status,priority" \
  -H "$AUTH"
```

### Update an existing issue (PUT)

```bash
curl -s -w "\n%{http_code}" -X PUT \
  "https://YOUR_ORG.atlassian.net/rest/api/3/issue/SEC-1234" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

Returns **204** (no body) on success.

### Create a new issue (POST)

```bash
curl -s -w "\n%{http_code}" -X POST \
  "https://YOUR_ORG.atlassian.net/rest/api/3/issue" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d @payload.json
```

Returns **201** with the new issue key on success.

---

## ADF (Atlassian Document Format) Reference

Every `description` field is an ADF document:

```json
{
  "type": "doc",
  "version": 1,
  "content": [ ... ]
}
```

### Node Types

| ADF Node | Usage | Structure |
|----------|-------|-----------|
| `heading` | Section headers | `{"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "..."}]}` |
| `paragraph` | Body text | `{"type": "paragraph", "content": [{"type": "text", "text": "..."}]}` |
| `orderedList` | Numbered steps | `{"type": "orderedList", "content": [{"type": "listItem", ...}]}` |
| `bulletList` | Bullet points | `{"type": "bulletList", "content": [{"type": "listItem", ...}]}` |
| `listItem` | List entry | `{"type": "listItem", "content": [{"type": "paragraph", ...}]}` |
| `codeBlock` | Code/HTTP evidence | `{"type": "codeBlock", "attrs": {"language": "http"}, "content": [{"type": "text", "text": "..."}]}` |
| `table` | Metadata tables | `{"type": "table", "attrs": {"isNumberColumnEnabled": false, "layout": "default"}, "content": [...]}` |
| `tableRow` | Table row | Contains `tableHeader` or `tableCell` children |
| `tableHeader` | Header cell | `{"type": "tableHeader", "content": [{"type": "paragraph", ...}]}` |
| `tableCell` | Data cell | `{"type": "tableCell", "content": [{"type": "paragraph", ...}]}` |

### Inline Marks

| Mark | Usage | Syntax |
|------|-------|--------|
| `code` | Inline code | `"marks": [{"type": "code"}]` |
| `strong` | Bold | `"marks": [{"type": "strong"}]` |
| `em` | Italic | `"marks": [{"type": "em"}]` |
| `link` | Hyperlink | `"marks": [{"type": "link", "attrs": {"href": "https://..."}}]` |

**Gotcha — the `code` mark is exclusive.** It cannot be combined with `strong` or `em` on the same text node. A node with `"marks": [{"type": "code"}, {"type": "strong"}]` is rejected by the v3 API with a top-level `INVALID_INPUT` and an empty `errors` object (no per-field diagnostic). To get bold + inline-code visually, split the run into two adjacent text nodes — one with `code`, one with `strong`. Same applies to bold-italic-code combinations.

---

## Security Finding Issue Template

Standard structure for SEC project findings. All sections are H2 headings.

### Required Sections (in order)

1. **Description** — What the vulnerability is, what data/access it exposes
2. **Steps to Reproduce** — Numbered list, each step with inline code for endpoints/params. Each step that sends a request includes the request and response excerpt (5-15 lines, proof annotated) inline as `codeBlock` nodes (language: `http`).
3. **Impact** — Concrete harm statement (proved attacker outcome, quantified where possible)
4. **Remediation** — Specific fix with inline code for function/attribute names. When remediation involves multiple files or call sites, enumerate them as a bullet list with full path + line ranges + the specific pattern at each site. The ticket must stand alone for a developer who has never seen the engagement backend.
5. **Metadata** — Table with: Report ID, OWASP, CWE, CVSS (score + vector), Severity, Affected Host/Path. Internal cross-reference (CH-XXX, EX-XXX, etc.) belongs in the engagement backend (`vigil assess agent done --finding-slugs ...`), not in the Jira ticket body — see Rule 17 of `agent/rules/reporting.md`.

### Standalone-ticket rule (Rule 17 enforcement)

Every Jira issue must be readable by a developer who has zero context on the engagement, zero access to the orchestrator backend, and zero familiarity with internal slugs. Concretely:

- Describe related findings by their attacker outcome or code path: `"the same unparameterized mysql_query pattern appears across the Service.*.php delivery classes — see file list in Remediation"`, not `"(CH-043, CH-044, CH-045, CH-049, CH-070)"`.
- Use Jira's native `Linked Issues` / `Epic` / `Blocks` relationships to express cross-ticket dependencies — reference sibling tickets by SEC-XXXX key.
- Keep the orchestrator-to-Jira mapping in the engagement backend via `vigil assess agent done --finding-slugs <slugs>` after the ticket is created. The mapping table is operator-internal and stays in the engagement directory.

### Priority Mapping (example — derive the real mapping from the instance)

An example mapping of finding severity to Jira priority and a Security Severity
custom field. Both the priority names and the custom field are instance-specific:

| Finding Severity | Jira Priority (`priority.name`) | Security Severity (`customfield_10850` — example id) |
|---|---|---|
| Critical | Highest | Critical |
| High | High | High |
| Medium | Medium | Medium |
| Low | Low | Low |
| Info | Lowest | Low |

> **Priorities are not universal.** A project may offer only Urgent / High /
> Medium / Low and **not** Highest / Lowest — read `priority.allowedValues` from
> the create metadata (`GET /rest/api/3/issue/createmeta`, or the MCP
> `getJiraIssueTypeMetaWithFields` tool) and map onto the set that actually exists.
> Do not assume the standard five.
>
> **The custom field id is an example, not a constant.** `customfield_10850` is
> what a Security Severity field happened to be on one instance; the same field is
> a different id — or absent — elsewhere, and a hardcoded id will set the wrong
> field or `400`. Rediscover it per instance: `GET /rest/api/3/field` (search for
> "Security Severity" / "Severity"), the create metadata, or read an example issue
> (MCP `getJiraIssue` with `view: "evidence"`).

### Labels

This is the default label scheme for issues created by this system. If you were
handed an example ticket to mirror, copy that project's actual label convention
off it instead. Two labels by default:

1. **`ai-red-team-scanning`** — always present, used to filter all issues created by this system
2. **OWASP category** — kebab-case slug matching the finding's OWASP Top 10 category

| OWASP Category | Label |
|---|---|
| A01:2021 Broken Access Control | `owasp-a01-broken-access-control` |
| A02:2021 Cryptographic Failures | `owasp-a02-cryptographic-failures` |
| A03:2021 Injection | `owasp-a03-injection` |
| A04:2021 Insecure Design | `owasp-a04-insecure-design` |
| A05:2021 Security Misconfiguration | `owasp-a05-security-misconfiguration` |
| A06:2021 Vulnerable and Outdated Components | `owasp-a06-vulnerable-outdated-components` |
| A07:2021 Identification and Authentication Failures | `owasp-a07-auth-failures` |
| A08:2021 Software and Data Integrity Failures | `owasp-a08-integrity-failures` |
| A09:2021 Security Logging and Monitoring Failures | `owasp-a09-logging-monitoring-failures` |
| A10:2021 Server-Side Request Forgery | `owasp-a10-ssrf` |

### Summary Format

```
XXX: <concise vulnerability title describing the defect and impact>
```

### Full Payload Example

Structure to copy; **values to rediscover.** The project key (`SEC`), issue type
id (`10013`), custom field id (`customfield_10850`), priority name, and labels are
all instance-specific examples — replace each with the target instance's real
value before sending.

```json
{
  "fields": {
    "project": {"key": "SEC"},
    "issuetype": {"id": "10013"},
    "priority": {"name": "Highest"},
    "customfield_10850": {"value": "Critical"},
    "labels": ["ai-red-team-scanning", "owasp-a01-broken-access-control"],
    "summary": "001: Missing Authorization in /api/v1/records/getbyid Allows Unauthenticated Attacker to Retrieve Sensitive Documents for Any User",
    "description": {
      "type": "doc",
      "version": 1,
      "content": [
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Description"}]},
        {"type": "paragraph", "content": [
          {"type": "text", "text": "An unauthenticated attacker retrieves complete PDF documents containing PII, internal identifiers, and financial data by enumerating sequential "},
          {"type": "text", "text": "recordId", "marks": [{"type": "code"}]},
          {"type": "text", "text": " values. The "},
          {"type": "text", "text": "[InternalOnly]", "marks": [{"type": "code"}]},
          {"type": "text", "text": " attribute is non-enforcing in production. IDs 1 through 500 all return distinct PDFs (~1MB each)."}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Steps to Reproduce"}]},
        {"type": "orderedList", "content": [
          {"type": "listItem", "content": [
            {"type": "paragraph", "content": [
              {"type": "text", "text": "Send the following request (no authentication):"}
            ]},
            {"type": "codeBlock", "attrs": {"language": "http"}, "content": [{"type": "text", "text": "POST /api/v1/records/getbyid HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"recordId\":1}"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": "Response:", "marks": [{"type": "strong"}]}]},
            {"type": "codeBlock", "attrs": {"language": "http"}, "content": [{"type": "text", "text": "HTTP/1.1 200 OK\nContent-Type: application/pdf\nContent-Length: 1048576\n\n%PDF-1.4 ...  ← sensitive document returned without authentication"}]}
          ]},
          {"type": "listItem", "content": [{"type": "paragraph", "content": [
            {"type": "text", "text": "Send with "},
            {"type": "text", "text": "{\"recordId\":2}", "marks": [{"type": "code"}]},
            {"type": "text", "text": " — returns different PDF (distinct MD5 hash), confirming per-user documents are exposed"}
          ]}]},
          {"type": "listItem", "content": [{"type": "paragraph", "content": [
            {"type": "text", "text": "Enumerate IDs 1-500 — all return HTTP 200 with PDF content (500+ distinct documents)"}
          ]}]}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Impact"}]},
        {"type": "paragraph", "content": [
          {"type": "text", "text": "Anonymous retrieval of sensitive documents containing PII, internal identifiers, and financial data for any user by incrementing sequential IDs. 500+ documents confirmed accessible."}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Remediation"}]},
        {"type": "paragraph", "content": [
          {"type": "text", "text": "Add "},
          {"type": "text", "text": "[Authorize]", "marks": [{"type": "code"}]},
          {"type": "text", "text": " with appropriate role requirements to "},
          {"type": "text", "text": "GetRecordById", "marks": [{"type": "code"}]},
          {"type": "text", "text": " and enforce tenant ownership checks on the "},
          {"type": "text", "text": "recordId", "marks": [{"type": "code"}]},
          {"type": "text", "text": " parameter before returning data."}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Metadata"}]},
        {"type": "table", "attrs": {"isNumberColumnEnabled": false, "layout": "default"}, "content": [
          {"type": "tableRow", "content": [
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Field"}]}]},
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Value"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Report ID"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "001"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "OWASP"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "A01:2021 Broken Access Control"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CWE"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CWE-862"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CVSS"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Critical"}]}]}
          ]}
        ]}
      ]
    }
  }
}
```

---

## Response Codes

| Method | Success | Notes |
|--------|---------|-------|
| GET (search) | 200 | Returns `issues[]` array |
| GET (issue) | 200 | Returns single issue object |
| POST (create) | 201 | Returns `{"id": "...", "key": "SEC-XXXX", "self": "..."}` |
| PUT (update) | 204 | No response body |
