---
description: "Jira REST API v3 delivery facts for Vigil findings: auth, endpoints and codes, the ADF code-mark quirk, the standalone-ticket rule, the default label and priority scheme, and a payload skeleton"
skill: jira-issue-creation, report-generation
---

# Jira API (v3)

The `jira-issue-creation` skill owns the workflow (MCP versus REST, mirroring an example ticket,
confirm-before-create, recording the issue key on the finding). This file holds the REST payload
facts behind it.

Every concrete value here is an instance-specific example: base URL, project key, issue type id,
custom field ids, label scheme and priority set all differ per Jira site. Rediscover them for the
instance you are filing into (create metadata, `GET /rest/api/3/field`, or an example issue); never
copy an id from here or from another site. Placeholders: `YOUR_ORG` (base URL), `SEC` (project
key), `10013` (issue type id), `customfield_10850` (a Security Severity field).

## Authentication and endpoints

Auth is pluggable and never changes the payload: Basic (`base64(email:api_token)`), Bearer/OAuth
2.0, or an already-authenticated Atlassian MCP session (preferred when present; `createJiraIssue`
takes markdown and converts it to ADF).

| Call | Endpoint | Success |
|---|---|---|
| Create | `POST https://YOUR_ORG.atlassian.net/rest/api/3/issue` | 201, `{"id", "key", "self"}` |
| Update | `PUT .../rest/api/3/issue/SEC-1234` | 204, no body |
| Read | `GET .../rest/api/3/issue/SEC-1234?fields=summary,description,status,priority` | 200 |
| Create-screen fields, allowed values | `GET .../rest/api/3/issue/createmeta` | 200 |
| Field catalog (find a `customfield_*` id by name) | `GET .../rest/api/3/field` | 200 |

REST v3 rich-text fields (`description`) take an ADF document (`{"type": "doc", "version": 1,
"content": [...]}`), not markdown.

### Inline Marks

The ADF `code` mark is exclusive: it cannot share a text node with `strong` or `em`. A node with
`"marks": [{"type": "code"}, {"type": "strong"}]` is rejected with a top-level `INVALID_INPUT` and
an empty `errors` object, with no per-field diagnostic to point at it. For bold inline code, split
the run into two adjacent text nodes, one per mark; the same applies to bold-italic-code. Markdown
handed to MCP `createJiraIssue` is not affected.

## Security Finding Issue Template

For a Vigil finding, the issue body is the reviewed external body from
`vigil assess export submission <slug> --platform direct` (the skill's gate). Laid out in Jira, the
sections are H2 headings in this order: Description, Steps to Reproduce (numbered; each request step
carries the request and a 5–15 line annotated response excerpt as `codeBlock` nodes with language
`http`), Impact, Remediation (every affected file or call site with path, line range and the pattern
at each), and a Metadata table (Report ID, OWASP, CWE, CVSS score and vector, Severity, affected
host/path).

### Standalone-ticket rule

A Jira issue must read cleanly for a developer with no engagement context, no backend access and no
knowledge of internal slugs (`agent/rules/reporting.md` §17). Describe related findings by attacker
outcome or code path ("the same unparameterized `mysql_query` pattern appears across the
`Service.*.php` delivery classes; see Remediation"), never by internal ids such as `CH-043`.
Express cross-ticket dependencies with Jira's native Linked Issues / Blocks / Epic relations by
issue key. The finding-to-issue mapping lives in the backend
(`agent/skills/jira-issue-creation/SKILL.md` "After creation — persist the local → Jira mapping").

### Priority Mapping (example — derive the real mapping from the instance)

| Finding severity | `priority.name` | Security Severity (`customfield_10850`) |
|---|---|---|
| Critical | Highest | Critical |
| High | High | High |
| Medium | Medium | Medium |
| Low | Low | Low |
| Info | Lowest | Low |

A project may offer only Urgent / High / Medium / Low; read `priority.allowedValues` from the create
metadata and map onto the set that exists. A hardcoded custom field id sets the wrong field or
returns 400 on another instance.

### Labels

Default scheme when no example ticket sets one (mirror the example's labels when there is one):
`ai-red-team-scanning` on every issue this system creates, plus the finding's OWASP Top 10 label.

| OWASP category | Label |
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

Summary format: `NNN: <concise title naming the defect and its impact>`.

### Payload skeleton

Structure to copy, values to rediscover. The description shows the split code/strong run, an
`http` code block and one metadata row; extend each section the same way.

```json
{
  "fields": {
    "project": {"key": "SEC"},
    "issuetype": {"id": "10013"},
    "priority": {"name": "Highest"},
    "customfield_10850": {"value": "Critical"},
    "labels": ["ai-red-team-scanning", "owasp-a01-broken-access-control"],
    "summary": "001: Missing Authorization in /api/v1/records/getbyid Lets an Unauthenticated Attacker Read Any User's Documents",
    "description": {
      "type": "doc",
      "version": 1,
      "content": [
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Steps to Reproduce"}]},
        {"type": "orderedList", "content": [
          {"type": "listItem", "content": [
            {"type": "paragraph", "content": [
              {"type": "text", "text": "Send "},
              {"type": "text", "text": "recordId", "marks": [{"type": "code"}]},
              {"type": "text", "text": " with no authentication:", "marks": [{"type": "strong"}]}
            ]},
            {"type": "codeBlock", "attrs": {"language": "http"}, "content": [{"type": "text", "text": "POST /api/v1/records/getbyid HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"recordId\":1}"}]}
          ]}
        ]},
        {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Metadata"}]},
        {"type": "table", "attrs": {"isNumberColumnEnabled": false, "layout": "default"}, "content": [
          {"type": "tableRow", "content": [
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Field"}]}]},
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Value"}]}]}
          ]},
          {"type": "tableRow", "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "CVSS"}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"}]}]}
          ]}
        ]}
      ]
    }
  }
}
```
