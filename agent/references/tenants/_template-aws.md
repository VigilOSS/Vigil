---
description: Scaffold tenant reference for AWS Organization alert investigations (account topology, aws/Athena/Detective IR context)
skill: aws-cloudtrail-investigation
---

# <CUSTOMER> — AWS Organization Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `vigil blue tenant init --customer <slug> --platform aws`,
> which writes to `agent/references/tenants/<slug>-aws.md` (per
> `PLATFORM_TO_TENANT_SUFFIX["aws"] = "aws"` in
> `src/vigil_cli/blue.py`).
>
> Before this file is loaded into a real engagement:
>
> 1. Replace every `<PLACEHOLDER>` (search for `<`). Remaining placeholders
>    cause the L1 `alert-triage-specialist` to halt with a `blocked`
>    handoff.
> 2. Populate the "Known benign patterns" register. Empty/placeholder rows
>    mean L1 cannot auto-close anything — every alert escalates to L2.
>    Promote rows from L3-verified `false_positive` findings only
>    (`agent/rules/triage.md` rule 5).
> 3. The tenant ref is operator-curated and authoritative. If the tenant
>    deviates, update the ref first, then re-dispatch.
>
> Platform-neutral sections (identity, on-call, change log, OOS artifacts)
> are mirrored across the `_template-<p>.md` family. Keep structure stable
> so cross-platform diffs stay readable.

Operator context for AWS alert investigations on the `<CUSTOMER>` AWS
Organization. Load this before running any `aws`, Athena, or Detective
command so you do not spend time rediscovering account topology.

---

## Tenant Identity

| Field | Value |
|---|---|
| Organization name | `<CUSTOMER>` |
| Organization ID | `<o-xxxxxxxxxx>` |
| Organization root ID | `<r-xxxx>` |
| Payer (management) account ID | `<123456789012>` |
| IAM Identity Center instance ARN | `<arn:aws:sso:::instance/ssoins-xxxxxxxxxxxx>` |
| IAM Identity Center home region | `<us-east-1>` |
| Organization created | `<YYYY-MM-DD>` |
| Total active accounts | `<count>` (as of `<YYYY-MM-DD>`) |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

### Member accounts

| Account ID | Account name | OU | Purpose |
|---|---|---|---|
| `<123456789012>` | `<management>` | `Root` | Payer; Organizations control plane only |
| `<123456789013>` | `<log-archive>` | `Security` | Centralized CloudTrail S3 bucket, Config aggregator |
| `<123456789014>` | `<audit>` | `Security` | Security Hub delegated admin, GuardDuty delegated admin |
| `<123456789015>` | `<prod-app>` | `Workloads/Prod` | Production workload |
| `<123456789016>` | `<dev-app>` | `Workloads/Dev` | Development workload |

---

## Tool Configuration

### AWS CLI v2

```
Binary:   <path-to-aws-binary>
Config:   ~/.aws/config, ~/.aws/credentials
Profiles: <profile-name-1> (account <id>, role <role>)
          <profile-name-2> (account <id>, role <role>)
Default region: <us-east-1>
```

Investigator entry: assume role via IAM Identity Center —
`aws sso login --profile <ir-profile>`. Direct IAM users are NOT used for
investigation (cross-account hops require the cross-account role
documented below).

### Cross-account investigator role

```
Role name: <IRInvestigatorRole>
Trust:     <ir-identity-center-permission-set> from audit account <123456789014>
Deployed:  every member account via <CloudFormation StackSet name>
Session:   max 1 hour, MFA required on assumption
```

### CloudTrail / Athena

```
Org-trail name:    <org-cloudtrail-name>
S3 bucket:         s3://<cloudtrail-log-bucket>/AWSLogs/<o-id>/
KMS key for trail: <arn:aws:kms:...>
Athena workgroup:  <ir-workgroup>
Athena database:   <ir_db>
Athena table:      cloudtrail_logs (partitioned by account_id, region, year, month, day)
```

### GuardDuty

```
Delegated admin account: <123456789014>
Detector IDs per region: <us-east-1: ...>, <us-west-2: ...>, <eu-west-1: ...>
```

### Detective (if licensed)

```
Graph ARN: <arn:aws:detective:us-east-1:123456789014:graph:...>
Region:    <us-east-1>
```

### Security Hub

```
Delegated admin account: <123456789014>
Aggregation region:      <us-east-1>
Enabled standards:       <AWS Foundational, CIS, PCI-DSS, NIST-800-53>
```

---

## IAM permissions scope reality

The investigator role `<IRInvestigatorRole>` is authorized for the
following AWS managed and custom policies. **The operator must verify
each row against the live role in IAM after `tenant init`.** Drift here
is the most common cause of `AccessDenied` mid-incident.

| Policy / scope | Status | Notes |
|---|---|---|
| `arn:aws:iam::aws:policy/SecurityAudit` | `<verified ✅ / not attached ❌>` | Broad read across most services |
| `arn:aws:iam::aws:policy/ViewOnlyAccess` | `<verified ✅ / not attached ❌>` | Generic read; complements SecurityAudit |
| `arn:aws:iam::aws:policy/job-function/SupportUser` | `<verified ✅ / not attached ❌>` | Support API read for case visibility |
| Custom: `<IRAdditionalReads>` | `<verified ✅ / not attached ❌>` | `s3:GetObject` on CloudTrail bucket, `athena:*` on `<ir-workgroup>`, `detective:GetGraph*` |
| Permissions boundary `<IRBoundary>` | `<verified ✅ / not attached ❌>` | Denies all `Action: *:Write*`, `iam:Create*`, `iam:Attach*` |
| SCP intersection | `<denies / allows>` | List SCPs that restrict the investigator role |

Write actions (`iam:CreatePolicy`, `s3:DeleteObject`, etc.) are
intentionally **not** granted — IR here is read-only by design.
Containment writes escalate to the break-glass IAM Identity Center
group below; the L2 investigator does not invoke writes directly.

For ambiguous denials, decode the failure message:

```bash
aws sts decode-authorization-message --encoded-message <encoded-message>
```

---

## Critical Identities

### Root credentials (per account)

| Account ID | Account name | Storage location of root credentials | Last rotation | Hardware MFA on root |
|---|---|---|---|---|
| `<123456789012>` | `<management>` | `<password manager / safe / vault reference>` | `<YYYY-MM-DD>` | `<yes — serial: ...>` |
| `<123456789013>` | `<log-archive>` | `<location>` | `<YYYY-MM-DD>` | `<yes>` |

Root sign-in is **a documented event the IR lead triggers**, not
adversarial activity. Cross-check root sign-ins against the change log
before treating them as findings.

### IAM Identity Center groups (privileged)

| Group | Permission set | Member count | Notes |
|---|---|---|---|
| `<aws-admins>` | `AdministratorAccess` | `<count>` | Full admin across member accounts |
| `<aws-security-admins>` | `<SecurityAuditPlus>` | `<count>` | Security team — read + select writes |
| `<aws-break-glass>` | `AdministratorAccess` (named restriction) | `<count>` | Emergency-only; MFA hardware key required; activity wired to PagerDuty alert |

### OrganizationAccountAccessRole

```
Role:     OrganizationAccountAccessRole (every member account)
Trusts:   <123456789012> (management account)
Use case: Bootstrap / break-glass cross-account hop from payer
```

Use of `OrganizationAccountAccessRole` outside of bootstrap is
investigation-worthy by default — cross-check against the change log.

### Service-linked roles + automation principals

| Role / principal | Account | Purpose | Notes |
|---|---|---|---|
| `<arn:aws:iam::<acct>:role/<github-actions-deploy>>` | `<prod-app>` | CI/CD deploy from GitHub Actions | OIDC federation to GitHub org `<org>` |
| `<arn:aws:iam::<acct>:role/<terraform-runner>>` | `<all>` | Terraform Cloud apply role | OIDC federation to TFC workspace `<ws>` |

### SCP administrators

| Principal | Notes |
|---|---|
| `<sso-group:aws-admins>` | Can attach/detach SCPs at the Root, Security, and Workloads OUs |

---

## MFA Posture

| Field | Value |
|---|---|
| Hardware MFA on every root account? | `<yes / no — list exceptions>` |
| MFA required for IAM Identity Center sign-in? | `<yes / no>` |
| MFA enforced for IAM users with `Action: *:Write*`? | `<yes / no — list exception users>` |
| IAM Identity Center MFA mode | `<context-aware / always-on>` |
| Allowed MFA factors (IAM Identity Center) | `<FIDO2, virtual TOTP, built-in authenticator>` |
| Known posture gaps | `<list>` |

Posture gaps here are *known conditions, not findings unique to a
specific alert*. Document them in the IR report posture section.

---

## Known benign patterns (false-positive register)

> **The L1 `alert-triage-specialist` reads this table to decide whether an
> alert may be auto-closed without an L2 pull.** Schema is fixed — do not
> rename columns; the consumers (`agent/skills/alert-triage/SKILL.md`
> Mechanical-FP screen and the `alert-triage-specialist` agent prompt)
> match on these exact field names.

Column schema:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|

Conventions follow `_template-gws.md`. Highlights:

- `pattern_id` — short kebab-case slug, unique within this file.
- `actor` — explicit IAM principal ARN or assumed-role ARN. Wildcards
  (`arn:aws:iam::*:role/*`) are NOT mechanical-eligible.
- `action_verb` — CloudTrail `eventName` exactly (e.g.
  `AssumeRole`, `CreateAccessKey`, `PutBucketPolicy`).
- `time_pattern` — concrete schedule.
- `source_signal` — GuardDuty finding type, Security Hub finding type,
  or custom SIEM rule identity.
- `mechanical` — `true` when L1 may auto-close.
- `rationale` — one sentence + citation of the L3 finding that promoted
  the entry.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<expected-role-assumers>` | `<arn:aws:sts::123456789015:assumed-role/CI/github-actions>` | `AssumeRole` | `weekdays 14:00-22:00 UTC, deploy cadence` | `guardduty / Recon:IAMUser/AnomalousBehavior / rule-id <rid>` | `true` | `CI deploy role; promoted from finding <slug> after L3 verified benign` |
| `<cloudformation-stack-roles>` | `<arn:aws:iam::123456789015:role/cloudformation-execution>` | `CreateRole` | `business hours during change windows` | `guardduty / IAMUser/ConsoleLogin / rule-id <rid>` | `false` | `CFN execution role creates other roles; L2 must verify stack name + template each time` |
| `<ecs-task-role-baseline>` | `<arn:aws:iam::123456789015:role/ecs-task-payments>` | `AssumeRole` | `continuous, container lifecycle` | `cloudtrail-siem / Anomalous AssumeRole / rule-id <rid>` | `true` | `ECS task role baseline; appears thousands of times per day during normal operation` |
| `<imdsv1-legacy-hosts>` | `<arn:aws:iam::123456789015:role/legacy-app-ec2>` | `GetInstanceMetadata` (v1) | `any` | `guardduty / UnauthorizedAccess:EC2/MetadataDNSRebind / rule-id <rid>` | `false` | `Known IMDSv1 legacy hosts pending migration; L2 verifies instance-id is on the allowlist, not auto-close` |
| `<external-account-trusted>` | `<arn:aws:iam::987654321098:role/partner-data-feed>` | `AssumeRole` | `daily 06:00 UTC ± 30 min` | `cloudtrail-siem / Cross-account access / rule-id <rid>` | `true` | `Documented partner cross-account role (acct 987654321098); trust policy pinned; promoted from finding <slug>` |

**Promotion rule** — only an L3 verifier who has confirmed
`false_positive` with cited evidence may seed a new mechanical row. New
`mechanical: false` rows can be added by the IR lead with a one-paragraph
rationale. Record changes in the **Tenant change log reference** below.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

```bash
# CloudTrail lookup (recent, per-account, console-bounded)
aws cloudtrail lookup-events \
  --profile <ir-profile> --region <region> \
  --lookup-attributes AttributeKey=Username,AttributeValue=<user> \
  --start-time <YYYY-MM-DDTHH:MM:SSZ> --end-time <YYYY-MM-DDTHH:MM:SSZ> \
  --max-results 50

# IAM access keys for a user, including last-used metadata
aws iam list-access-keys --user-name <u> --profile <ir-profile>
aws iam get-access-key-last-used --access-key-id <AKIAxxxxxxxxxxxxxxxx> --profile <ir-profile>

# GuardDuty findings (delegated admin account)
aws guardduty finding list \
  --profile <audit-profile> --region <region> \
  --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}'

# Decode an authorization message from an AccessDenied error
aws sts decode-authorization-message --encoded-message <encoded-message>

# Detective (if licensed) — pivot URL for an IP / principal
echo "https://console.aws.amazon.com/detective/home?region=<region>#entities/<resource-arn-or-ip>"
```

```sql
-- Athena: all CloudTrail events for a principal across all member accounts (30 days)
SELECT
  eventtime,
  eventname,
  awsregion,
  sourceipaddress,
  useragent,
  useridentity.arn AS principal_arn,
  errorcode,
  errormessage,
  resources
FROM <ir_db>.cloudtrail_logs
WHERE
  year = '<YYYY>' AND month = '<MM>'
  AND useridentity.arn = '<arn:aws:sts::123456789015:assumed-role/<role>/<session>>'
  AND from_iso8601_timestamp(eventtime) BETWEEN
      from_iso8601_timestamp('<YYYY-MM-DDTHH:MM:SSZ>')
      AND from_iso8601_timestamp('<YYYY-MM-DDTHH:MM:SSZ>')
ORDER BY eventtime DESC
LIMIT 500;
```

---

## On-call calendar reference

| Field | Value |
|---|---|
| On-call rotation tool | `<PagerDuty / Opsgenie / GCal / other>` |
| Lookup URL | `<URL to on-call schedule>` |
| Look-up SLA | `<seconds to identify on-call for a given UTC timestamp>` |

The L3 verifier's devil's-advocate step (`alert-fp-verification` Check 5)
requires identifying who was on-call during the alert's time window.

---

## Vendor maintenance windows reference

| Source | URL | Notes |
|---|---|---|
| AWS Service Health Dashboard | https://health.aws.amazon.com/health/status | Cross-check before treating a service-anomalous event as adversarial |
| AWS Personal Health Dashboard | (via account) | Account-specific events not on public dashboard |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Account moves, SCP changes, OU migrations, Identity Center cutovers |
| Identity provider status (if federated) | `<URL>` | Federation breaks present as `AssumeRoleWithSAML` failures |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| AWS change tickets | `<Jira project URL / change ticketing>` | IAM changes, SCP edits, OU moves, new accounts, federation changes |
| CloudTrail org-trail | `s3://<cloudtrail-log-bucket>/AWSLogs/<o-id>/` | Source of truth for AWS-side admin actions |
| Terraform / IaC repo | `<repo URL>` | Infrastructure changes ride through PRs here first |
| This file's git history | `git log -- agent/references/tenants/<customer>-aws.md` | Tenant ref changes themselves are part of the change log |

---

## Recent red team / authorized testing windows

> **Update this section at engagement start.** Empty or stale entries here
> are how the L3 verifier accidentally promotes a red-team artifact to a
> real finding during the devil's-advocate step.

| Start (UTC) | End (UTC) | Scope | Authorization reference |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<account / role / region scope>` | `<authorization letter / Jira ticket / RoE doc>` |

If no authorized testing is active during the engagement window, write a
single row with both timestamps set to the engagement start and
`scope: none`.

---

## Out-of-scope artifacts

- **Other AWS Organizations the operator has access to** — only this
  Organization's `<o-xxxxxxxxxx>` is in scope.
- **Partner / managed-customer AWS accounts** — `<list any accounts this
  Org's payer is billing-attached to but does not own>`.
- **Cross-account roles to third-party SaaS** (Datadog, Snyk, etc.) —
  trust direction matters; if our org trusts an external account, that
  external account's activity is out of scope past the role boundary.
- **AWS Marketplace AMIs and vendor IaaS** — vendor-managed instances
  in our accounts may have telemetry the vendor owns; do not pull
  vendor-only logs without authorization.
- **Tenant secrets** — root passwords, IAM secret access keys, MFA
  device serials. This file references them by *location* only.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<AWS IR / IAM ATO / S3 exposure / GuardDuty triage>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-aws.md`; modeled on
  `agent/references/tenants/_template-gws.md` for cross-platform parity.
- Alias: `vigil blue tenant init --platform aws` writes to
  `<customer>-aws.md` per `PLATFORM_TO_TENANT_SUFFIX["aws"] = "aws"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/aws-cloudtrail-investigation/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
