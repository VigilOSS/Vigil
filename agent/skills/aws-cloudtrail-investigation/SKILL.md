---
name: aws-cloudtrail-investigation
description: L2 AWS CloudTrail event hunting + IAM credential abuse investigation. STS AssumeRole chain traversal, IMDSv1/v2 access pattern, GuardDuty correlation, Athena query templates against CloudTrail-in-S3, S3 + Lambda + ECS task-role abuse.
origin: Vigil
---

# AWS CloudTrail Investigation (L2)

L2 platform investigator for AWS dispatches. Pairs with
`athena-log-investigation` when the look-back exceeds the 90-day
`cloudtrail lookup-events` ceiling. Federated compromise (SAML, IAM
Identity Center) hands off to `m365-signin-investigation` or
`okta-investigation` rather than resolving IdP state from CloudTrail.

## When to Activate

- L1 `alert-triage` dispatches `platform=aws` with category
  `iam-anomaly`, `credential-abuse`, `s3-exfil`, `guardduty-finding`,
  `root-use`, `imds-abuse`, `secrets-access`, or `role-trust-mod`.
- A GuardDuty finding lands in `scope.json:alert_metadata` (e.g.
  `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`,
  `Recon:IAMUser/UserPermissions`,
  `Stealth:IAMUser/CloudTrailLoggingDisabled`) and needs CloudTrail
  correlation.
- `m365-signin-investigation` confirmed a federated SAML compromise
  that pivoted via `AssumeRoleWithSAML`; the AWS blast radius needs
  scoping.
- `okta-investigation` confirmed Okta compromise → AWS via SAML.
- `alert-fp-verification` routed a Check 4 reproduction needing
  cross-source CloudTrail lookup against a non-AWS-feed alert (e.g.,
  a CASB alert on `sts:AssumeRoleWithWebIdentity`).

## Operating Rules

Apply before any command runs.

- `agent/rules/triage.md` — disposition vocabulary (rule 3), symmetric
  evidence bar (rule 4), severity ↔ MITRE (rules 2, 16), look-back
  (rule 6), UTC (rule 7), tenant-ref first (rule 12), confidence
  (rule 9).
- `agent/shared-constraints-blue.md` — tenant-not-host scope, read-only
  default, artifact chain of custody, handoff schema, resume-brief
  hydration, host-exec audit envelope.
- `agent/rules/ir-evidence.md` — attribution gates, multi-signal
  corroboration, source-file citation conventions.
- Tenant ref(s) in `scope.json:tenant_reference_paths[]` — AWS
  known-benign register (`expected_role_assumers`, `cloudformation_stack_roles`, `ecs_task_role_baseline`, `imdsv1_legacy_hosts`, `external_account_trusted`), IAM identities, break-glass roster, change-ticket index, methodology overrides.

Missing tenant ref for the target `aws_account_id` → halt and return
a `blocked` handoff naming the path. Improvising AWS calls without it
turns trusted external accounts, expected role assumers, and IMDSv1
legacy-host exemptions into findings.

## Tools

| Task | Tool | Why |
|---|---|---|
| Identity context | `aws sts get-caller-identity`, `aws iam list-access-keys --user-name <u>`, `aws iam get-access-key-last-used --access-key-id <k>`, `aws iam get-account-summary`, `aws iam get-user --user-name <u>` | Resolve the alert's principal to a concrete identity; verify key age and last-use region before treating the key as live or stale |
| Direct event lookup (≤90 days) | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<actor>` (also `AttributeKey=AccessKeyId`, `EventName`, `ResourceName`, `ResourceType`) | Fast for narrow actor/event slices; bounded to 90 days of management events, severe per-region rate cap — not a bulk tool |
| Bulk Athena query | `aws athena start-query-execution` against partitioned `cloudtrail_logs` table; status via `aws athena get-query-execution`, results via `aws athena get-query-results` | Cross-link `agent/skills/athena-log-investigation/SKILL.md`. Required whenever the time window exceeds the lookup-events 90-day ceiling, when the alert needs grouping over millions of events, or when the L1 dispatch flagged a 30–60d look-back |
| GuardDuty correlation | `aws guardduty list-detectors`, `aws guardduty finding list --detector-id <id> --finding-criteria <json>`, `aws guardduty get-findings --detector-id <id> --finding-ids <ids>` | Pull every GuardDuty finding tied to the alerted principal and the time window; severity / confidence fields feed Check 2 corroboration |
| Detective entity profile (where licensed) | `aws detective list-graphs`, then `aws detective list-members --graph-arn <arn>` and the graph-scoped entity-profile APIs | Pre-baked timeline view of the principal across CloudTrail + VPC Flow + GuardDuty; only available where the customer has paid for Detective and the engagement scope includes the graph account |
| Auth-message decode | `aws sts decode-authorization-message --encoded-message <m>` | Decodes the encoded `AccessDenied` payload that surfaces in policy-simulator runs and some SDK exception traces; produces the exact evaluated context that explains why a call was allowed or denied |
| VPC Flow Logs | Athena against `vpc_flow_logs` (cross-link `agent/skills/athena-log-investigation/SKILL.md`) | Confirms egress/ingress for compromised instances when CloudTrail data events are off; load-bearing on Step 6 |
| S3 access logs | Athena against `s3_access_logs` (object-level) when S3 data events are not on in CloudTrail | Object-level GET / PUT / DELETE attribution for the bucket(s) the alert touches |
| IAM policy evaluation | `aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <verbs> --resource-arns <arns>`, `aws iam simulate-custom-policy` | Reproduces the deny/allow decision for a principal against the policy state at the moment you run it (TOCTOU caveat — see Common Failure Modes) |
| Lookalike domain | `dnstwist <legit-domain>` for AWS-console phishing variants (`signin.aws.amazon.com` typo-squats often surface in initial access) | Phish ↔ console-login correlation, especially with `m365-signin-investigation` handoffs |
| Offline parse | `jq`, `python3` (pandas / pyarrow for parquet) | Every Athena result lands as JSON or parquet; offline analysis avoids re-running expensive queries |

All target-facing CLI is wrapped through `vigil assess host-exec`:

```bash
vigil assess host-exec \
  --tool aws \
  --intent "<one-line purpose>" \
  --technique <T-id> \
  --phase investigate \
  --scope-host <aws-account-id-or-org-slug> \
  -- aws <verb> ...
```

`--scope-host` takes the 12-digit account ID or the org slug from the
tenant ref (`scope.json:platforms[].account_id` or
`tenant_ref:org_slug`); never a hostname — AWS scope is the account
boundary.

Forbidden from L2 AWS dispatches: `vigil assess kali` (red-only),
direct WRITE-class IAM (`iam:CreateAccessKey`, `iam:DetachUserPolicy`,
role deletion, `iam:DeleteAccessKey`) — those surface as
`vigil blue propose-contain` entries for L4 `ir-lead`. Even an "obvious"
stolen-key rotation goes through the proposal queue.

## Methodology

The seven steps below run in order on a fresh dispatch. On
continuation (resume-brief returned prior pulls), skip steps whose
artifacts are registered and resume at the first unsatisfied
evidence demand.

### Step 1 — Identity resolution + decision tree

**Purpose.** Scope the principal universe. `userIdentity`
deterministically tells you the credential family (long-term key,
assumed role, federated, root) and the containment vocabulary that
follows. Conflating `IAMUser` with `AssumedRole` drags onto the wrong
control plane.

**Action.** Extract `userIdentity` from the alerting event (canonical
ref: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>).
Apply the decision tree:

- `type=Root` — instant high severity. Cross-check the break-glass
  ticket index in the tenant ref; if no ticket covers the window,
  `verified`-direction and route to L3 immediately. Absence of a
  ticket IS the finding.
- `type=IAMUser` with `accessKeyId` — long-term key path. Run
  `aws iam list-access-keys --user-name <u>` and
  `aws iam get-access-key-last-used --access-key-id <k>`. Step 3
  expands on dormant-then-active.
- `type=AssumedRole` — traverse `sessionContext.sessionIssuer.arn`
  recursively (role chaining, T1078.004). Stop at the first
  non-`AssumedRole` issuer; that is the originating principal. Extract
  `sessionContext.sourceIdentity` when `sts:SourceIdentity` was
  enforced — that field carries the original federated user (e.g.,
  the Entra UPN or Okta login).
- `type=SAMLUser` / `type=WebIdentityUser` — federated. Pivot to the
  IdP skill (`m365-signin-investigation` for Entra,
  `okta-investigation` for Okta). Do not resolve federated-side
  attribution from CloudTrail alone.
- `additionalEventData.MFAUsed=No` on a privileged action — T1556
  signal. Step 3 / Step 4 resolve whether the gap is policy or
  compromise.
- `userIdentity.invokedBy=<service>.amazonaws.com` — the call was
  made by an AWS service on the principal's behalf (CloudFormation,
  Auto Scaling). Step 4's CloudFormation-stack-applied FP pivots
  off this.
- `ec2RoleDelivery=1.0` — IMDSv1 (T1552.005). Cross-reference the
  instance ID against `imdsv1_legacy_hosts`; undocumented IMDSv1
  is a finding.

**Evidence.** Identity tree as JSON; actor's attached + inline IAM
policies as JSON dumps; role-trust policies in the chain. All land
under `$ENGAGEMENT_DIR/ir/reports/identity_<actor-slug>_<window>.json`
and register as `--kind ir_log`.

**Common-FP.** Cross-account role assumed by a trusted CI account in
the `external_account_trusted` register — the most frequent benign
cause of "unfamiliar assumed-role principal" alerts. Kill match
requires source account ID + role ARN + documented purpose; two of
three is not a kill-citation.

### Step 2 — Athena window pull (CloudTrail-in-S3)

**Purpose.** Bulk evidence base. `cloudtrail lookup-events` is
rate-limited and capped at 90 days; Athena over CloudTrail-in-S3 is
the only practical path for the 30-day default look-back (`triage.md`
rule 6), data-event correlation, historic key-age work, and
multi-region rollups.

**Action.** Use the partitioned query shape; an unpartitioned scan of
CloudTrail-in-S3 swamps Athena's per-query cap.

```sql
SELECT
  eventtime,
  eventname,
  eventsource,
  useridentity.arn AS actor_arn,
  useridentity.type AS actor_type,
  useridentity.accesskeyid AS access_key_id,
  useridentity.sessioncontext.sessionissuer.arn AS issuer_arn,
  sourceipaddress,
  useragent,
  recipientaccountid,
  awsregion,
  errorcode,
  errormessage,
  requestparameters,
  resources
FROM cloudtrail_logs
WHERE year='YYYY'
  AND month='MM'
  AND day BETWEEN 'DD1' AND 'DD2'
  AND (useridentity.arn LIKE '%<role-or-user>%'
       OR useridentity.accesskeyid = '<access-key-id>'
       OR useridentity.sessioncontext.sessionissuer.arn LIKE '%<role-or-user>%')
ORDER BY eventtime ASC
```

Start the window at the earliest plausible trigger minus 7 days;
expand to T-30d if anomalous events still cluster at the boundary
(rule 6). Output via Athena's
`--result-configuration OutputLocation=...` to the customer-controlled
results bucket the tenant ref documents, then materialize locally as
parquet:

```bash
vigil assess host-exec --tool aws --intent "athena pull for <actor>" \
  --technique T1078.004 --phase investigate \
  --scope-host <aws-account-id> \
  -- aws s3 cp s3://<results-bucket>/<query-id>.csv \
       $ENGAGEMENT_DIR/ir/reports/ct_<actor-slug>_<window>.csv

python3 -c "import pandas as pd; \
  pd.read_csv('$ENGAGEMENT_DIR/ir/reports/ct_<actor-slug>_<window>.csv') \
    .to_parquet('$ENGAGEMENT_DIR/ir/reports/ct_<actor-slug>_<window>.parquet')"
```

Register both CSV (unmodified Athena export) and parquet (downstream
read).

**Evidence.** Parquet artifact ID, the SQL text, the Athena
`QueryExecutionId`, bytes-scanned from `aws athena
get-query-execution`, and the row count.

**Common-FP.** Too narrow misses lateral (the principal stayed quiet
for two weeks before the alerted action); too wide swamps with
routine activity. Anchor start to L1 handoff's
`alert_normalized.time_window_utc[0]`, not "when the alert fired."

### Step 3 — Long-term key vs STS chain decision

**Purpose.** Separate stolen-key paths from federated-compromise
paths. Containment differs (key rotation vs IdP token revoke),
blast-radius differs (account-local vs tenant-wide), and the
downstream skill differs (`incident-containment` vs an IdP skill).
Misclassifying here drags the rest of the methodology onto the wrong
control plane.

**Action.** Branch on the Step 1 identity type:

- **`IAMUser` + `accessKeyId`.** Check the key's creation date and
  last-used metadata:

  ```bash
  aws iam list-access-keys --user-name <user>
  aws iam get-access-key-last-used --access-key-id <key>
  ```

  Anomaly markers — **dormant-then-active** (`LastUsedDate` >30d
  followed by alert-window activity; record `dormant_days` in
  metadata); **region drift** (`LastUsedDate.Region` ≠ alert
  `awsregion`); **service drift** (`LastUsedDate.ServiceName` ≠
  alert `eventSource`).

- **`AssumedRole`.** Pull every `sts:AssumeRole` /
  `sts:AssumeRoleWithSAML` / `sts:AssumeRoleWithWebIdentity` whose
  response produced a session matching the alerted principal's
  `sessionContext.attributes.creationDate`. The chain terminates at a
  federated principal; capture the IdP type and `principalId` for the
  IdP-skill handoff.

- **`Root`.** No chain; disposition is the break-glass-or-finding
  decision from Step 1.

**Evidence.** Key branch — metadata table (creation, dormant days,
baseline region, baseline service) + alert-window diff. AssumedRole
branch — role-chain JSON (`{role_arn, assumed_at, assumed_by}`
ordered federated-root → alerted action), registered
`--kind ir_evidence`.

**Common-FP.** A developer's IDE-cached short-term key returning to
use after the laptop comes off vacation: the session expired but the
long-term key it derives from is still valid, and the IDE re-pulls.
Kill citation requires HR record + MDM check-in for the same window
+ absence of any privileged write actions in Step 4. Two of three is
not enough.

### Step 4 — Action enumeration

**Purpose.** Classify the principal's window activity into discovery
/ persistence / privesc / impact / lateral buckets. Grouping is
`eventSource × eventName`; count and first-seen / last-seen are
load-bearing.

**Action.** Run an Athena rollup over the parquet from Step 2:

```sql
SELECT
  eventsource,
  eventname,
  COUNT(*) AS event_count,
  MIN(eventtime) AS first_seen,
  MAX(eventtime) AS last_seen,
  COUNT(DISTINCT awsregion) AS region_fanout,
  COUNT(DISTINCT sourceipaddress) AS ip_fanout
FROM cloudtrail_logs
WHERE <Step 2 predicates>
GROUP BY eventsource, eventname
ORDER BY event_count DESC
```

Privilege-escalation indicators to highlight (each gets a finding row
in the timeline; severity recompute per `triage.md` rule 2):

| Event | Technique | Notes |
|-------|-----------|-------|
| `iam:CreateAccessKey` against another user | T1098.001 | New cloud credential for a non-self principal |
| `iam:PutUserPolicy` / `iam:AttachUserPolicy` | T1098 | Inline / managed admin attach to self or other |
| `iam:CreateLoginProfile` | T1136.003 | Set console password on a programmatic-only user |
| `iam:UpdateAssumeRolePolicy` | T1098 | Role-trust modification — opens chain pathway |
| `iam:PutRolePolicy` / `iam:AttachRolePolicy` | T1098 | Role permissions expansion |
| `iam:CreateUser` | T1136.003 | New cloud account |
| `sts:AssumeRole` into a privileged new role | T1078.004 | Chain advancement |
| `sts:GetFederationToken` | T1550.001 | Federation-token forge for a stolen long-term key |
| `lambda:UpdateFunctionCode` | T1525 | Implant on an internally-trusted compute path |
| `lambda:CreateFunction` with admin role | T1525 + T1098 | Implant + privesc combo |
| `ec2:RunInstances` with unusual type/region | T1525 + T1496 | Cryptomining shape (large GPU instance in a never-used region) |
| `ec2:RunInstances` with attacker AMI | T1525 | Implant via public-AMI launch |
| `secretsmanager:GetSecretValue` outside baseline | T1552.001 | Credentials in code/files-equivalent access |
| `ssm:GetParameter(s)` on `/secure/*` outside baseline | T1552.001 | SSM parameter-store secret read |
| `kms:Decrypt` from a new principal | T1552.001 | Decrypted ciphertext access via stolen role |
| `cloudtrail:StopLogging` / `cloudtrail:DeleteTrail` / `cloudtrail:PutEventSelectors` (downgrading scope) | T1562.008 | Defense evasion — disable audit logging |
| `guardduty:DeleteDetector` / `guardduty:UpdateDetector --no-enable` | T1562.001 | Disable cloud detection |
| `config:DeleteConfigurationRecorder` / `config:StopConfigurationRecorder` | T1562.001 | Disable AWS Config |
| `iam:ListUsers` / `iam:ListAccessKeys` / `iam:ListRoles` bursts | T1580 | Cloud infra discovery |
| `organizations:ListAccounts` from an unknown role | T1538 + T1580 | Org-level discovery |

**Evidence.** Event-count rollup table registered as `--kind ir_evidence`
(markdown with the SQL embedded), and an event-by-event timeline for
the highlighted-technique rows (each row carries `event_id`,
`event_time_utc`, `event_name`, `request_parameters_excerpt`,
`response_excerpt`, `source_ip`, `user_agent`).

**Common-FP.** CloudFormation stack-applied role changes —
`userIdentity.invokedBy=cloudformation.amazonaws.com` + role ARN in
the `cloudformation_stack_roles` register. Both fields are required;
one is a coverage gap, not a kill. Terraform Cloud / Atlantis runs
from a documented CI account match similarly:
`sourceipaddress` in Terraform Cloud's egress range +
Terraform-version `userAgent` + tenant-ref documented entry.

### Step 5 — Resource access pattern

**Purpose.** Data-plane impact scoping. Step 4 covered control-plane
verbs; Step 5 asks what they touched. For S3, ECS task roles, Lambda,
KMS this is where the alert moves from "compromise" to "compromise
with proved data impact" (`high` → `critical` per `triage.md` rule 2).

**Action.** Three parallel sub-queries, each gated on whether the
customer has data-event logging on for the affected service:

**(a) S3.** If CloudTrail data events are on for the bucket(s) in
question:

```sql
SELECT
  eventtime,
  eventname,
  requestparameters,
  responseelements,
  sourceipaddress,
  useragent,
  SUM(CAST(json_extract_scalar(requestparameters, '$.bytesTransferredOut') AS BIGINT)) OVER () AS total_bytes_out
FROM cloudtrail_logs
WHERE <Step 2 predicates>
  AND eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'CopyObject', 'PutObject',
                     'PutBucketPolicy', 'PutBucketAcl',
                     'DeleteBucketPolicy', 'DeletePublicAccessBlock',
                     'PutBucketPublicAccessBlock')
ORDER BY eventtime ASC
```

If S3 data events are off, fall back to S3 server access logs over
Athena (`s3_access_logs` table; cross-link
`agent/skills/athena-log-investigation/SKILL.md`). Either way, classify
into:

- `GetObject` burst from new ASN → data exfiltration signal
- `PutBucketPolicy` / `PutBucketAcl` mutation → public-exposure signal
- `DeletePublicAccessBlock` / `PutBucketPublicAccessBlock --no-enable`
  → public-exposure prep (T1213.002 / T1485)
- `DeleteObject` / `DeleteBucket` → destruction (T1485)

**(b) KMS.** Any key-policy or key-state mutation is high-severity:

```sql
SELECT eventtime, eventname, requestparameters, responseelements
FROM cloudtrail_logs
WHERE <Step 2 predicates>
  AND eventsource = 'kms.amazonaws.com'
  AND eventname IN ('ScheduleKeyDeletion', 'DisableKey',
                    'PutKeyPolicy', 'CreateGrant',
                    'RetireGrant', 'CancelKeyDeletion')
```

`ScheduleKeyDeletion` on a production-data key is T1485 with a 7-30
day fuse — L4 may want a containment proposal to cancel before the fuse
elapses.

**(c) Lambda / ECS task-role abuse.** Cross-reference Step 4's
`lambda:UpdateFunctionCode` events with the function's
`secretsmanager:GetSecretValue` / `ssm:GetParameter` calls in the
same chain — code change + out-of-baseline secret read is T1525 +
T1552.001 chained.

**Evidence.** Byte-count by destination ASN, bucket-policy
`Statement` diff, KMS key-policy diff, pre/post Lambda code SHA-256
if available. Each diff registers as `--kind ir_evidence` with the
source CloudTrail event IDs embedded.

**Common-FP.** Scheduled backup / replication jobs surface as
`GetObject` bursts with `sourceipaddress` from a documented NAT or
AWS-service IP, `userAgent` matching the backup tool's version, and
schedule alignment to `documented_outbound_jobs`. ECS task roles
calling `secretsmanager:GetSecretValue` on a fixed schedule match
`ecs_task_role_baseline` — kill requires register entry AND schedule
alignment.

### Step 6 — Network plane pivot (VPC Flow Logs)

**Purpose.** Confirm reachability and exfil destination. When the
alerted principal is an EC2 instance role and Step 4 flagged
`lambda:UpdateFunctionCode` or `ec2:RunInstances`, CloudTrail tells
you what was launched; VPC Flow Logs tell you where the launched
compute talked to.

**Action.** Athena over `vpc_flow_logs` for the Step 4 instance IDs
(partitioned query shape per `athena-log-investigation`).

```sql
SELECT
  start_time,
  end_time,
  srcaddr,
  dstaddr,
  srcport,
  dstport,
  protocol,
  bytes,
  packets,
  action
FROM vpc_flow_logs
WHERE year='YYYY' AND month='MM' AND day BETWEEN 'DD1' AND 'DD2'
  AND (srcaddr IN (<instance-private-ips>) OR dstaddr IN (<instance-private-ips>))
  AND action = 'ACCEPT'
ORDER BY bytes DESC
LIMIT 1000
```

Group by `dstaddr`, resolve non-RFC1918 destinations to ASN (via
`ioc-enrichment`), and cross-reference with Step 4's
`ec2:RunInstances` rows to confirm cryptomining shape (T1496).

**Evidence.** Flow records (CSV, `--kind ir_log`); destination ASN
histogram + top-N narrative (`--kind ir_evidence`).

**Common-FP.** Egress to AWS-service VPC endpoints (S3 Gateway,
Secrets Manager Interface, KMS Interface) surfaces as ACCEPT rows to
AWS-service IPs and is not internet traffic. Kill requires
tenant-ref-documented endpoint AND destination IP in the AWS service
range at <https://ip-ranges.amazonaws.com/ip-ranges.json>. "Looks
like AWS" without the range lookup is not a kill.

### Step 7 — GuardDuty + Detective cross-ref

**Purpose.** Corroborate CloudTrail findings with AWS managed
detections. The verifier's Check 2 (detection-control corroboration)
asks whether an independent control fired on the same actor / window;
GuardDuty is the AWS-internal independent control, and Detective
combines CloudTrail + VPC Flow + GuardDuty into one entity-profile
view.

**Action.** Pull every GuardDuty finding whose
`resource.accessKeyDetails.principalId` or
`resource.instanceDetails.iamInstanceProfile.id` matches the alerted
principal, over the same window as Step 2:

```bash
vigil assess host-exec --tool aws --intent "guardduty correlation" \
  --technique T1078.004 --phase investigate \
  --scope-host <aws-account-id> \
  -- aws guardduty finding list --detector-id <detector-id> \
       --finding-criteria '{
         "Criterion": {
           "resource.accessKeyDetails.principalId": {"Eq": ["<principal-id>"]},
           "updatedAt": {"Gte": <epoch-ms>, "Lte": <epoch-ms>}
         }
       }'
```

Then `aws guardduty get-findings --detector-id <id> --finding-ids <ids>`
materializes the finding bodies. Each carries `type`, `severity`
(numeric 1.0-8.9; convert via documented thresholds), `confidence`,
and `service.action`.

If the customer licenses Detective AND the engagement scope includes
the Detective graph account, list the graphs and request an entity
profile for the principal:

```bash
aws detective list-graphs
aws detective list-members --graph-arn <graph-arn>
# Then use the graph-scoped entity-profile API for the principal ARN
```

Detective is opt-in and graph-licensed per account; if the tenant ref
does not document the graph ARN, skip the Detective branch and record
the gap in `coverage_gaps`.

**Evidence.** GuardDuty finding IDs (registered as `--kind ir_log` —
the raw `get-findings` JSON), GuardDuty severity / confidence summary
(`--kind ir_evidence`), and if Detective is in play, the Detective
entity-profile screenshot or JSON dump.

**Common-FP.** Stale GuardDuty findings from prior incidents never
archived — an unrelated three-month-old finding surfaces in the
time-window filter. Kill requires `service.eventLastSeen` outside the
window AND a tenant-ref or activity-log entry recording the prior
incident's closure. Stale findings go in `coverage_gaps`, not
silently dropped.

## MITRE Technique Mapping

The techniques below are the ones this skill is expected to recognize
and assign on findings. Sub-technique IDs are used where applicable
(`triage.md` rule 11).

| Technique | Name | AWS signal |
|-----------|------|------------|
| `T1078.004` | Valid Accounts: Cloud Accounts | Long-term key / role abuse from a new ASN; assumed-role chain to an unknown federated source |
| `T1098.001` | Account Manipulation: Additional Cloud Credentials | `iam:CreateAccessKey` on another user; `iam:CreateLoginProfile` (combined with T1136.003) |
| `T1098` | Account Manipulation (broader) | `iam:PutUserPolicy` / `iam:AttachUserPolicy` / `iam:PutRolePolicy` / `iam:AttachRolePolicy` / `iam:UpdateAssumeRolePolicy` |
| `T1136.003` | Create Account: Cloud Account | `iam:CreateUser`, `iam:CreateLoginProfile` |
| `T1213.002` | Data from Information Repositories: SharePoint/S3 | `s3:GetObject` burst from new ASN against documented data buckets |
| `T1485` | Data Destruction | `kms:ScheduleKeyDeletion`, `s3:DeleteObject` / `s3:DeleteBucket` against backup or production buckets |
| `T1496` | Resource Hijacking | `ec2:RunInstances` with cryptomining-shape instance type (large GPU / many-CPU) in a never-used region |
| `T1525` | Implant Internal Image | `lambda:UpdateFunctionCode`, `lambda:CreateFunction` with admin role, `ec2:RunInstances` from an attacker AMI |
| `T1538` | Cloud Service Dashboard | `ConsoleLogin` from a federated session whose IdP context is unusual; `organizations:ListAccounts` |
| `T1550.001` | Use Alternate Authentication Material: Application Access Token | `sts:GetFederationToken` forge from a stolen long-term key |
| `T1552.001` | Unsecured Credentials: Credentials In Files | `secretsmanager:GetSecretValue` / `ssm:GetParameter` outside the role's baseline access pattern |
| `T1552.005` | Unsecured Credentials: Cloud Instance Metadata API | `ec2RoleDelivery=1.0` (IMDSv1) on an instance whose ID is not in the legacy register |
| `T1556` | Modify Authentication Process | `additionalEventData.MFAUsed=No` on a privileged action where policy would normally require MFA |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | `guardduty:DeleteDetector` / `UpdateDetector --no-enable`, `config:StopConfigurationRecorder` |
| `T1562.008` | Impair Defenses: Disable Cloud Logs | `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:PutEventSelectors` (narrowing scope) |
| `T1580` | Cloud Infrastructure Discovery | `iam:ListUsers` / `iam:ListAccessKeys` / `iam:ListRoles` / `sts:GetCallerIdentity` bursts |

## Known-benign register additions

When the dispatch surfaces a benign-looking pattern the tenant ref's
known-benign register does not yet cover, propose an addition via the
handoff's `tenant_ref_proposals` array. Fields for AWS-platform
additions (merged into `_template-aws.md` by the operator):

- `expected_role_assumers` — `(source_account_id, source_role_arn, target_role_arn, purpose, owner)` tuples. CI deployment roles, audit roles, Terraform Cloud runners. Required for Step 1's cross-account FP.
- `cloudformation_stack_roles` — `(stack_name, role_arn, account_id, owner)`. Stack-managed roles whose privesc-looking IAM mutations are stack updates. Required for Step 4's CFN FP.
- `ecs_task_role_baseline` — `(task_role_arn, baseline_actions, baseline_resources, schedule)`. Task roles legitimately calling SecretsManager / SSM on schedule. Required for Step 5's ECS FP.
- `imdsv1_legacy_hosts` — `(instance_id, account_id, owner, deprecation_target_date)`. Instances pinned to IMDSv1 with migration timelines. Required for Step 1's IMDSv1 FP.
- `external_account_trusted` — `(external_account_id, purpose, owner, trust_basis)`. Vendor SaaS, partner integrations, parent-org accounts. Required for Step 1's cross-account FP.
- `documented_outbound_jobs` — `(source, destination, schedule, byte_budget, owner)`. Scheduled backup / replication / analytics jobs. Required for Step 5's S3 FP.

Proposals are candidates; the operator confirms after the verifier
closes the disposition.

## Disposition heuristics

The verifier owns disposition; the heuristics below are L2's
first-pass recommendation. The verifier may overturn after the
five-check protocol runs.

- **`verified`** — long-term key used from a new ASN AND a privesc
  API call in the same session; OR a root sign-in without a
  break-glass ticket; OR a new role chain whose federated source
  identity is unknown to the IdP skill that owns it; OR a
  `cloudtrail:StopLogging` event from a non-baseline principal; OR
  `kms:ScheduleKeyDeletion` against a documented production-data key.
- **`false_positive`** — `expected_role_assumers` register match
  with all three fields (source account, source role, target role),
  the schedule alignment, AND identical API surface as documented
  prior runs of the same job; OR `imdsv1_legacy_hosts` register
  match with a current-date deprecation target (expired deprecation
  targets do not kill — they escalate); OR
  `cloudformation_stack_roles` match with the `invokedBy` field
  confirming the stack origin.
- **`downgraded`** — anomalous discovery activity (`iam:ListUsers`,
  `iam:ListAccessKeys` bursts) without any write action in the
  window; reproduction is partial (CloudTrail shows the recon, but
  the alleged impact action did not land in the same window).
  Severity drops by one tier (`high` → `medium`, `medium` → `low`);
  the finding remains live in case Step 6's network pivot or
  Step 7's GuardDuty pull surfaces the next escalation step.
- **`escalated`** — new role chain terminates at an unknown
  federated source identity (need IdP skill to resolve before
  disposition can land); contested coverage in Step 2's Athena pull
  (the look-back boundary still has anomalous events at T-30d); a
  GuardDuty finding's `service.action` contradicts the CloudTrail
  view (the two independent controls disagree on what happened).

A finding L2 cannot disposition without an IdP-side pull is
`escalated`, never `verified-pending`. Voting in
`alert-fp-verification` resolves escalations; L2 marks and routes.

## Activity Log Convention

Every `vigil assess log` row carries the following `metadata_json`
fields. FTS over `metadata_json` is how the report-writer assembles
the per-platform narrative.

```json
{
  "tier": "L2",
  "alert_external_id": "<SIEM-or-GuardDuty-finding-id>",
  "platform": "aws",
  "skill_loaded": "aws-cloudtrail-investigation",
  "disposition": "verified|false_positive|downgraded|escalated",
  "confidence": "low|medium|high",
  "confidence_rationale": "<one-line citation>",
  "mitre_techniques": ["T1078.004", "T1098.001"],
  "aws_account_id": "<12-digit-account-id>",
  "principal_arn": "<arn:aws:iam::...:user|role/...>",
  "federated_source": "entra|okta|iam-identity-center|null",
  "imdsv1_detected": false,
  "key_dormant_days": 47,
  "athena_query_id": "<QueryExecutionId>",
  "athena_bytes_scanned": 12345678,
  "time_window_utc": ["2026-05-01T00:00:00Z", "2026-05-15T23:59:59Z"]
}
```

The activity entries themselves run through:

```bash
vigil assess log <agent-name> \
  "<short title — Step N for <finding-slug>>" \
  investigation_step \
  "<one-line result summary>" \
  --actor-kind agent \
  --metadata-file metadata.json
```

The CLI verb is `vigil assess log`. The legacy shorthand (`log` with
a trailing `-entry`) does not route and entries that use it never
land in `activity_entries`.

## Output Contract

L2 dispatch closes with a handoff JSON at
`$ENGAGEMENT_DIR/ir/handoffs/<dispatch-id>.json` submitted via
`vigil assess agent handoff --from-json <path>`. Required shape:

```json
{
  "from_agent": "<agent-name>",
  "to_role": "incident-verifier",
  "finding_slug": "<finding-slug>",
  "platform": "aws",
  "aws_account_id": "<12-digit>",
  "principal_arn": "<arn>",
  "disposition_recommendation": "verified|false_positive|downgraded|escalated",
  "confidence": "low|medium|high",
  "confidence_rationale": "<one-line>",
  "mitre_techniques": ["T1078.004", "..."],
  "time_window_utc": ["<iso>", "<iso>"],
  "evidence_refs": [
    {"artifact_id": "<id>", "kind": "ir_log", "produced_by": "Step 1"},
    {"artifact_id": "<id>", "kind": "ir_log", "produced_by": "Step 2"},
    {"artifact_id": "<id>", "kind": "ir_evidence", "produced_by": "Step 4"}
  ],
  "coverage_gaps": [
    "S3 data events not enabled on bucket <name>; Step 5 fell back to s3_access_logs",
    "Detective not licensed; Step 7 GuardDuty-only"
  ],
  "tenant_ref_proposals": [
    {"register": "external_account_trusted", "entry": {"...": "..."}}
  ],
  "downstream_dispatches": [
    {"to_role": "platform-specialist", "skill": "m365-signin-investigation", "reason": "federated source resolves to Entra; need IdP-side pull"}
  ],
  "cross_source_timeline_path": "$ENGAGEMENT_DIR/ir/evidence/<finding>_timeline.md"
}
```

`cross_source_timeline_path` is required on multi-platform findings
(`triage.md` rule 14); a handoff without the timeline blocks
`verified` disposition at the verifier.

## Closing Sequence

Run in order before emitting the handoff. Skipping any step produces
a malformed dispatch the verifier rejects.

1. **Register every raw pull as an artifact.** CloudTrail exports,
   Athena results (CSV + parquet), GuardDuty finding JSON, IAM policy
   dumps, role-trust documents.

   ```bash
   vigil assess artifact register <path> --kind ir_log
   ```

2. **Register derived evidence as `ir_evidence`.** Role-chain
   diagrams, key-dormancy calculations, event-count rollup
   markdowns, bucket-policy diffs, KMS key-policy diffs, byte-count
   ASN histograms, cross-source timelines.

   ```bash
   vigil assess artifact register <path> --kind ir_evidence
   ```

3. **Mark scratch on transient notes** that no longer carry
   investigation value (the first-pass Athena pull that was
   superseded by the corrected partitioned version; the JSON
   scratch buffer used to draft the timeline).

   ```bash
   vigil assess artifact mark-scratch <artifact-id>
   ```

4. **Log the handoff entry.** Use the verb `vigil assess log` (the
   legacy shorthand with a trailing `-entry` does not route).

   ```bash
   vigil assess log <agent-name> "aws-cloudtrail-handoff" \
     handoff \
     "L2 AWS CloudTrail investigation closed: <one-line summary>" \
     --actor-kind agent \
     --metadata-file metadata.json
   ```

5. **Emit the handoff JSON.**

   ```bash
   vigil assess agent handoff --from-json $ENGAGEMENT_DIR/ir/handoffs/<dispatch-id>.json
   ```

If the dispatch is `blocked` (missing tenant ref, missing Athena
catalog, missing CloudTrail trail), submit the blocked-shape handoff
with `disposition_recommendation` omitted and the blocker named in
`coverage_gaps`.

## Common Failure Modes

Recurring mistakes on AWS CloudTrail dispatches. Each is named so the
verifier can flag it in Check 5 (devil's advocate) when L2 evidence
does not address it.

- **Not traversing the AssumedRole chain.** Stopping at the first
  `sessionContext.sessionIssuer` misses the federated origin. Step 1's
  recursive walk is the gate; the evidence file must show every step
  back to the first non-`AssumedRole` issuer.
- **Athena query without partition pruning.** Missing `year` /
  `month` / `day` filters full-scans the bucket — bill spike,
  multi-minute latency, workgroup rate-cap hit. Every query in
  Steps 2 / 4 / 5 has the partition filter; do not strip it.
- **Trusting `sourceIPAddress` blindly.** A VPC Gateway Endpoint call
  shows the endpoint IP, not the instance IP. Confirm against VPC
  Flow Logs (Step 6) before treating an "AWS-IP source" as
  suspicious or an "external-IP source" as confirmed external (a
  PrivateLink endpoint may be in play).
- **Confusing CI `sts:AssumeRole` with attacker assume-role.**
  Terraform / Atlantis / Spacelift / Drone CI assumes deployment
  roles all day. Kill requires `external_account_trusted` entry +
  `sourceipaddress` in the CI provider's documented egress +
  matching userAgent. Two of three escalates.
- **Missing `recipientAccountId` for cross-account events.**
  CloudTrail in account A may surface an actor from account B
  (assumed role A from credentials in B). `recipientAccountId` is
  the trail's account; `userIdentity` is the actor's home account.
  Step 2's query selects both.
- **TOCTOU on `iam:simulate-principal-policy`.** The simulator
  evaluates current policy, not policy at the alert moment. When
  the simulator is cited as a Check 4 constraint, also cite the
  policy's `LastModifiedDate` and confirm it predates the alert.
- **GuardDuty stale-finding contamination.** Filtering by principal
  without `updatedAt` surfaces unrelated prior incidents. Step 7's
  template includes the `updatedAt` filter.
- **Treating data-event absence as benign.** If S3 data events are
  off for the bucket, the lack of `GetObject` rows is NOT evidence
  the bucket was not read. Fall back to `s3_access_logs` over
  Athena or record the gap in `coverage_gaps`.

## Reference Block

- `agent/skills/alert-triage/SKILL.md` — L1 origin; the dispatch
  handoff this skill consumes.
- `agent/skills/athena-log-investigation/SKILL.md` — paired skill;
  Steps 2 / 4 / 5 / 6 use its query shape and result-bucket
  discipline.
- `agent/skills/m365-signin-investigation/SKILL.md` — federated
  handoff when the IdP is Entra.
- `agent/skills/okta-investigation/SKILL.md` — federated handoff
  when the IdP is Okta.
- `agent/skills/ioc-enrichment/SKILL.md` — ASN / GeoIP /
  threat-intel enrichment for `sourceipaddress`.
- `agent/skills/incident-containment/SKILL.md` — owns key rotation,
  role-policy detach, session revoke; consumes containment proposal
  entries.
- `agent/skills/alert-fp-verification/SKILL.md` — L3 verifier owns
  the final disposition write.
- AWS CloudTrail user-identity reference:
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>
- AWS CloudTrail event reference (record contents):
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
- MITRE T1078.004 (Cloud Accounts):
  <https://attack.mitre.org/techniques/T1078/004/>
- MITRE T1552.005 (Cloud Instance Metadata API):
  <https://attack.mitre.org/techniques/T1552/005/>
- AWS GuardDuty finding-type reference:
  <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html>
- AWS IP-ranges JSON (for Step 6 service-IP attribution):
  <https://ip-ranges.amazonaws.com/ip-ranges.json>
