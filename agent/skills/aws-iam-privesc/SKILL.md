---
name: aws-iam-privesc
description: Enumerate and exploit AWS IAM privilege escalation paths — dangerous policy combinations, role chaining, and credential abuse
origin: Vigil
vuln_class: bfla
---

# AWS IAM Privilege Escalation

> **Audit flags:** use `--technique AUTH` (cloud IAM privesc maps to the auth/authorization class in this taxonomy) on both execution routes. On `kali exec`, set `--destructive` whenever the call mutates IAM state (`iam create-*`, `iam attach-*`, `iam put-*`, `iam set-default-policy-version`, or a `sts assume-role` that activates a broader session); the `host-exec` equivalent is `--allow-destructive` (see Tools for exactly when it is required).

## When to Activate

- AWS credentials obtained (access key, session token, role assumption) or IAM is in scope.

## Tools

**Signed AWS calls run on the HOST, not in the Kali container.** The runtime image ships the `aws`
binary, but the container holds no credentials — its only bind mount is `/engagements`, and nothing
injects `~/.aws`, `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID` into it, so every SigV4-signed call there
dies with `NoCredentials`. `vigil assess host-exec` writes the same `assessment_command_runs` audit
row as `kali exec` (`route='host_exec'`), so the host route is audited, not a bypass.

- **Authenticated `aws` CLI — IAM, STS, and every signed service call — via `host-exec`:**
  ```bash
  vigil assess host-exec --tool aws --intent "caller identity for <principal>" \
    --technique AUTH --phase consume-test -- aws sts get-caller-identity
  ```
  Point it at a host profile with `aws --profile <name> ...`, or, for keys captured during the
  engagement, prefix the argv with `env`: `-- env AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
  AWS_SESSION_TOKEN=... aws iam list-attached-user-policies --user-name <u>` (the wrapper never
  invokes a shell, so an inline `VAR=... cmd` prefix would not expand). `host-exec` refuses argv
  carrying a screened destructive token (`delete`, `--force`, `rm -r`, …) unless you pass
  `--allow-destructive`, so `aws iam delete-*` needs it; a `create-*`/`attach-*`/`put-*` call does
  not trip the screen but is still a target-state mutation — say so in `--intent`.
- **boto3 for signed SDK flows** — same route: `vigil assess host-exec --tool python3 --technique AUTH
  ... -- python3 <script>`. boto3 *is* installed in the runtime image, but in-container it has no
  credentials to sign with, so there it is only good for unsigned calls.
- **Unauthenticated AWS calls and all target-facing HTTP — `vigil assess kali exec`**, which is
  where they belong: the container is the isolation envelope for target traffic and none of these
  need credentials. Covers `aws ... --no-sign-request`, Cognito Identity Pool
  `GetId`/`GetCredentialsForIdentity` against a pool that allows unauthenticated identities (no
  SigV4 signing at all — a plain `curl -X POST` to `cognito-identity.<region>.amazonaws.com` works).
  Use `--technique AUTH --probe-kind fingerprint --phase consume-test
  --timeout 60`, `--probe-kind exploit --destructive` when the call writes.
- **Pacu, enumerate-iam, Cloudsplaining, Principal Mapper (pmapper)** — none of these ship in the
  runtime image or the host toolchain; check with `command -v` before planning around one. Install
  what the engagement needs on the host and drive it through `host-exec`. Cloudsplaining and pmapper
  are offline analyzers over downloaded IAM JSON and never need target network access anyway.

## Methodology

The `aws` calls below are signed, so each runs wrapped in `vigil assess host-exec --tool aws
--intent "<why>" --technique AUTH --phase <phase> -- …` (Tools above). Captured keys go in the
`env AWS_ACCESS_KEY_ID=… aws …` argv prefix; use the user name from `get-caller-identity`, not a
shell variable.

1. **Enumerate:** `sts get-caller-identity`, attached and inline user/role policies, policy
   versions, and `iam get-account-authorization-details` saved locally; feed that JSON to
   Cloudsplaining or pmapper offline when installed.
2. **Map permissions to escalation paths.** The standard privesc catalogue applies (Rhino
   Security Labs' method list, HackTricks): policy-version and attach/put-policy self-grants,
   access-key and login-profile creation, `iam:PassRole` + a compute service
   (`lambda:CreateFunction`, `ec2:RunInstances`, `glue:CreateDevEndpoint`,
   `cloudformation:CreateStack`, `datapipeline:*`, `sagemaker:CreateNotebookInstance`,
   `codebuild:CreateProject`), `lambda:UpdateFunctionCode`, `iam:UpdateAssumeRolePolicy`,
   `sts:AssumeRole`, wildcard actions/resources. Walk the whole catalogue even after one path
   works: defenders patch one and miss siblings.
3. **Cross-account trust:** find roles trusting external accounts in the saved dump
   (`jq '.RoleDetailList[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS | strings | test("arn:aws:iam::[0-9]+:root"))'`)
   and read trust-policy conditions you might satisfy (session tags, leaked external IDs,
   `aws:userid` patterns).
4. **Instance metadata** is reachable only from the target's side: through an SSRF
   (`agent/skills/ssrf-testing/SKILL.md`) or a command channel on a compromised target host under
   exploit approval. An IMDS request from `kali exec` reaches the runtime's own host, not the
   target.
5. **Mutations** (`create-*`, `attach-*`, `put-*`, `set-default-policy-version`, assuming a
   broader role) change target state: they need `--destructive` / `--allow-destructive`, a
   reason in `--intent`, and exploit approval. Persistence (backdoor users or keys) and detection
   evasion are not assessment objectives; a demonstrated escalation path is the proof.

## What to Record

Caller identity, the policies involved, the escalation path and each command with its output,
wildcard scopes, cross-account trusts, and the attacker outcome with one minimal proof
(`agent/rules/hunting.md` §2, §10): e.g. the assumed `Admin` role's `get-caller-identity`, or one
object read from the production secrets bucket. Severity:
`agent/references/finding-fp-and-severity-gate.md`. Format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- AccessDenied on all enumeration → verify the credentials are live, then move on.
- SCPs block `iam:*` and `sts:AssumeRole` → record as hardened at org level.
- Every catalogue path lacks a required permission → record as least-privilege.
- Escalate when: `iam:PassRole` is allowed on any role (its target is the new boundary); compute
  resources carry roles more privileged than the principal (resource hijack via code, userdata or
  container overrides works where direct IAM writes do not); Secrets Manager, SSM Parameter Store,
  S3 or CodeCommit are readable (grep for SecureString, access keys and API tokens before
  concluding least-privilege).

External references: Rhino Security Labs privesc methods, Pacu wiki, Principal Mapper,
Cloudsplaining, HackTricks AWS IAM privesc.
