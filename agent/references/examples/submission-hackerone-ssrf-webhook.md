---
description: "Example: HackerOne submission for SSRF via webhook test-send stealing cloud IAM credentials"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** SSRF in webhook config allows org admin to steal IAM credentials

**Weakness:** CWE-918: Server-Side Request Forgery (SSRF)

**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N (7.1)

**Run:** `python3 poc-ssrf-webhook.py`
**Pass if:** the script prints the stolen `AccessKeyId`/`SecretAccessKey` pair

---

### Summary

An org admin points the outgoing-webhook URL at the instance metadata service and reads the response back through the app's own "test connection" feature. `POST /api/integrations/webhooks/test` fetches the configured URL server-side and returns the response body verbatim. It exists to preview what the receiving endpoint would get, but nothing restricts the URL to the tenant's own domain or filters link-local ranges. I noticed the response carries the full body rather than a pass/fail status, which turns a blind SSRF into a direct credential read.

**Exploit flow**
1. The PoC configures the webhook target as the instance metadata address and calls test-connection to read back the response body.
2. It re-targets the same URL, appending `iam/security-credentials/` to enumerate the attached role's name.
3. It re-targets the endpoint a second time with that role name appended.
4. The server fetches the final URL and returns the role's live `AccessKeyId`, `SecretAccessKey`, and `Token` in the response body.

### Steps to Reproduce

1. [attacker] Authenticate as any user with webhook-config permission (a role many orgs hand to non-admin integration owners) and run it:
```
export SESSION_COOKIE="<value from an authenticated browser session>"
python3 poc-ssrf-webhook.py
```
**Expect:** the script prints the stolen `AccessKeyId`/`SecretAccessKey` pair. Full output in Evidence.

### Evidence

```
[*] role name discovered via metadata SSRF: app-prod-ec2-role
[*] fetching http://169.254.169.254/latest/meta-data/iam/security-credentials/app-prod-ec2-role
AccessKeyId:     ASIAABCDEFGHIJKLMNOP                              <-- proof: live temporary credential
SecretAccessKey: wJalrXUt********************EXAMPLEKEY            <-- masked here, full value in script output
Token:           IQoJb3JpZ2luX2Vj... (truncated)
Expiration:      2026-07-06T21:00:00Z
```

### Impact

Read access to the EC2 instance profile's live temporary AWS credentials, valid until the printed expiration and scoped to whatever policy the instance role carries. Those credentials work against the AWS API from anywhere until they expire; the blast radius is the role's full policy, not just the app's functionality.

### Remediation

Block outbound requests from the webhook-fetch path to RFC 1918 ranges, `169.254.169.254`, and other link-local/metadata addresses. Enforce it with a network-level egress rule or a fetch proxy, not just app-layer URL parsing that a redirect can bypass. As defense-in-depth, move the instance to IMDSv2 with a hop limit of 1 so a single-hop SSRF can't reach the credentials endpoint despite bypassed filtering.
