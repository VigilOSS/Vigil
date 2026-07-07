---
description: "Example: HackerOne submission for SSRF via webhook test-send stealing cloud IAM credentials"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** SSRF in webhook config allows org admin to steal IAM credentials

**Weakness:** CWE-918: Server-Side Request Forgery (SSRF)

**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N (7.1)

**POC:** `poc-ssrf-webhook.py` — attach
**Run:** `python3 poc-ssrf-webhook.py`
**Pass if:** the script prints the stolen `AccessKeyId`/`SecretAccessKey` pair

---

### Summary

An org admin points the outgoing-webhook URL at the instance metadata service and reads the response back through the app's own "test connection" feature. `POST /api/integrations/webhooks/test` fetches the configured URL server-side and returns the body verbatim in the response — it exists to show a preview of what the receiving endpoint would get, but nothing restricts the URL to the tenant's own domain or filters link-local ranges. I noticed the test-connection button shows the full response body in the UI, not just a pass/fail status, which is what turns this from a blind SSRF into a direct credential leak.

### Steps to Reproduce

1. Authenticate as any user with webhook-config permission and run the PoC:
```
export SESSION_COOKIE="<value from an authenticated browser session>"
python3 poc-ssrf-webhook.py
```
2. The script configures a webhook pointing at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, calls the test-connection endpoint to enumerate the role name, then re-targets the same endpoint with the role name appended.
3. The server fetches the URL and returns the metadata response body inside the test-connection JSON payload.
4. The script parses `AccessKeyId`, `SecretAccessKey`, and `Token` out of that body and prints them.

### Evidence

```
[*] role name discovered via metadata SSRF: app-prod-ec2-role
[*] fetching http://169.254.169.254/latest/meta-data/iam/security-credentials/app-prod-ec2-role
AccessKeyId:     ASIAABCDEFGHIJKLMNOP                              <-- proof: live temporary credential
SecretAccessKey: wJalrXUt********************EXAMPLEKEY            <-- masked here, full value in script output
Token:           IQoJb3JpZ2luX2Vj... (truncated)
Expiration:      2026-07-06T21:00:00Z
```

### Attack Scenario

An authenticated user with permission to configure outgoing webhooks (a role many orgs hand to non-admin integration owners) sets the webhook target to the metadata service instead of a real endpoint. The test-connection feature dutifully fetches it and echoes the body back, handing the attacker the EC2 instance role's live temporary AWS credentials.

### Impact

Grants read of the EC2 instance profile's temporary AWS credentials, valid until the printed expiration and scoped to whatever policy the instance role carries. Anyone who can reach the webhook-config screen — not just tenant admins — can pull this without needing any other foothold in the AWS account.

### Remediation

Block outbound requests from the webhook-fetch path to RFC 1918 ranges, `169.254.169.254`, and other link-local/metadata addresses — enforce it with a network-level egress rule or a fetch proxy, not just app-layer URL parsing that a redirect can bypass. As defense-in-depth, move the instance to IMDSv2 with a hop limit of 1 so a single-hop SSRF can't reach the credentials endpoint even if the URL filter is bypassed.
