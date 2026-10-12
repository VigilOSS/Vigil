# Remediation workspace

Vigil provides intake, investigation, fix planning, independent code workspaces, verification,
approval, draft PRs, and development deployment records. The repository's `PROJECT.md` selects ticket
readers, MCPs, skills, coding instructions, checks, and publishing policy. A ticket or direct report
is sufficient; no prior assessment engagement is required.

Use one long-lived remediation engagement per repository. Each case owns its source snapshot,
evidence, approval history, and a registered Git worktree or JJ workspace. Several assessment findings
can link to one case when they share the same fix.

## First ticket, end to end

1. Configure the profile below and confirm the referenced skills, MCP authentication,
   shared test environment, PR template, and deployment workflow.
2. Create the engagement once:

   ```bash
   vigil engagement create --type remediation --name Acme \
     --repo /absolute/path/to/acme-app --project-config /absolute/path/to/PROJECT.md --no-prompt
   vigil engagement list --json
   ```

3. Use its key to open repository context:

   ```bash
   vigil remediation -k <key> start
   ```

4. In Claude, run `/vigil-remediate SEC-123` with a real ticket ID or URL. The agent
   retrieves the report, creates the case/workspace/handoff, and proposes its fix
   and verification plan. Check the diagnosis and scope, then approve the plan.
5. The agent implements the fix, runs checks against case source, records proof,
   and presents the diff and human Prep/Test steps. For the first pilot, test
   `join <case-id>` from another terminal and confirm it opens this conversation.
6. Ask to publish when ready. Vigil checks the reviewed revision and opens a draft.
   Choose deployment and optional suites separately. Follow the developer's
   Prep/Test, confirm the served revision, and record development verification.

The agent performs the case CLI steps. You supply the ticket, review the plan and
diff, authorize publication/deployment, and run the human checks. Start with one
ticket before trying a batch. Native Claude attachment, live MCP authentication,
and repository runtime behavior need this pilot even when automated tests pass.

## Configure the repository

```bash
vigil engagement create --type remediation --name Acme \
  --repo /absolute/path/to/acme-app --no-prompt
```

Creation preserves or scaffolds a repository-owned `PROJECT.md` and links the engagement to it.
TOML frontmatter holds configuration; Markdown holds project instructions. Select another shared file
with `--project-config /path/to/PROJECT.md`. Fill observed facts or owner-supplied values; leave unknown
values blank and ask only when the next operation needs them.

The default file is `<repository>/PROJECT.md`. An existing `PROJECT.md` can also
live in a gitignored private directory or elsewhere on your machine: pass its
absolute path with `--project-config` during creation. Vigil links
`<engagement>/PROJECT.md` to that file. Edit the source file; keep one canonical
profile rather than another editable copy in the engagement. Relative references
resolve from the source file's directory, so a private profile needs the correct
relative `repository` and instruction paths. Native Claude still starts in the
repository root, wherever the profile lives.

```toml
+++
repository = "."
base_branch = "develop"
workspace_directory = "worktrees"
development_url = "https://dev.example.com"
test_url = ""
production_url = ""
browser_cdp_url = ""
deployment_workflow = "development.yml"

[remediation]
source_reader = "Use the approved issue-reader MCP to retrieve the original report and attachments."
mcps = ["issue-reader"]
skills = ["fix-security-issue", "write-test-plan"]
instruction_files = ["AGENTS.md"]
hook_policy = "disabled"
pr_template = ".github/pull_request_template.md"
pr_guidance = ["docs/development/pr-writing.md"]
development_ticket_required = false
shared_environment = "acme-local"
borrowed_dependency_manifests = ["package-lock.json"]
check_commands = [
  { name = "lint", command = "npm run lint", directory = "." },
  { name = "tests", command = "npm test", directory = "." },
]
deployment_test_inputs = ["run_extended_tests"]

[remediation.deployment_inputs]
run_extended_tests = false

[stagehand]
model = ""
approved_account = ""
api_key_env = ""
+++
# Acme remediation

Use existing repository instructions. Keep PRs concise and QA-facing.
Document shared runtime setup, allowed accounts, fixtures, and cleanup here.
```

These names are placeholders: select the actual MCP, skills, commands, template, and workflow inputs
available in your repository. Profile references do not install plugins, enable disabled MCPs,
supply authentication, or bypass workspace trust. Personal and nested repository instructions still
apply. Surface conflicting requirements with their sources before dependent work.

`repository`, instruction files, PR guidance, and template references resolve relative to `PROJECT.md`.
`workspace_directory` resolves inside the repository; a branch such as `fix/SEC-123` produces
`<repository>/worktrees/fix/SEC-123`. Without it, the workspace stays under the case directory.
`base_branch` defaults to `main`, but each case records its selected branch and base commit for review
and PR creation. Existing cases retain their registered workspace and review policy; later profile
changes cannot silently retarget them. Referenced guidance changes invalidate approval.
New workspaces prefer the already-fetched origin branch/bookmark tip, then the local
base when no origin ref exists. Refresh origin before creating a case workspace.

Top-level machine overrides use `VIGIL_REMEDIATION_<FIELD>`; Stagehand overrides use
`VIGIL_REMEDIATION_STAGEHAND_<FIELD>`. Legacy JSON can be imported explicitly once with
`--project-config project.json` on creation; a conflicting repository profile is rejected. Do not
maintain a second editable JSON configuration beside the shared file.

## Start and supply tickets

```bash
vigil remediation -k <engagement-key> start
```

Vigil launches and attaches to a full native Claude conversation in the repository root, preserving
native settings, ignored skills, private runbooks, project plugins, and MCP discovery. Its additional
context exposes the remediation command and case artifacts without loading the hunting operator.
Then use the command in Claude:

```text
/vigil-remediate SEC-123
/vigil-remediate SEC-123 https://jira.example.com/browse/SEC-124
```

One normalized bug keeps this conversation as its developer. Several select a coordinator that
starts separate full developer conversations through Vigil. The command announces its role and loads
only relevant profile and role guidance. A key and its `/browse/` URL count as one input; the reader
must still establish canonical identity. Arguments remain untrusted input data.

Vigil starts and records native sessions; Claude retrieves tickets through profile-selected tools
and investigates code. References remain pending until retrieval succeeds. Source resolution detects
an existing case and requires deliberate reuse rather than silently merging reports. When a reader
is unavailable, retain pending input rather than inventing descriptions or remediation claims.

Claude validates the report against current code and proposes the fix and meaningful verification
before editing. It waits for owner plan approval. An inaccurate, already fixed, or unproven report
is reported with evidence. Include approved siblings sharing the root cause; use separate cases for
unrelated issues. A profile can require a linked development ticket for publishing without making
that universal or creating a ticket automatically.

Claude Code 2.1.257 or newer and native session hosting are required for launch and attachment.
`start` launches a hosted conversation before attaching, keeping the exact conversation joinable.
Vigil records the native host's actual conversation UUID. If startup exits before attachment,
inspect `claude agents --json --all` and the engagement's `remediation/sessions/` receipts.
Recover a recorded launch using its receipt UUID; this never starts another conversation:

```bash
vigil remediation -k <engagement-key> start --session-id <recorded-launch-uuid>
```

The session's context root stays the main repository; all code edits belong in the case's registered
workspace. Native background isolation is disabled only for these sessions to avoid a second workspace.
For an existing case:

```bash
vigil remediation -k <engagement-key> session <case-id>
vigil remediation -k <engagement-key> join <case-id>
```

`session` launches a worker only when no binding exists. For one case, the agent binds its existing
UUID with `session --bind --session-id <uuid>`. `join` attaches to the recorded conversation; missing
or mismatched identities require recovery rather than replacement. The repository-context command, native binding, worker launch, and joining currently support
Claude only.

### Hook policy

`hook_policy = "inherit"` keeps configured hooks. `"disabled"` disables non-managed hooks only in
the remediation session. Vigil announces it before launch and in developer context. Managed policy
hooks remain active. Repository files and ordinary sessions are unchanged. Vigil's non-managed hooks
are also disabled, so case/session recording uses explicit commands instead of hook receipts.

With hooks disabled, the agent runs profile checks automatically during verification and publishing:
required formatting, lint, analysis, and tests. The user need not replay hook commands. Existing
helpers may be used only when they operate on case source. No repository hook edits are needed.

A future alternative is a Vigil-owned remediation hook that schedules the same profile checks.
It would need case workspace identity, shared environment ownership, and hook-independent session
recording. The explicit check path keeps this iteration simple and leaves company hooks intact.

## Intake and generated handoff

The agent imports the actual retrieved snapshot, then Vigil generates
`<engagement>/remediation/cases/<case-id>/handoff.md`. It includes current case state, source snapshot,
profile/workspace references, verification, evidence, and approval state. It is a readable projection,
not another ledger. Proposed remediation remains a hypothesis separate from the original report.
Import and finding intake return its absolute path; regenerate it with `handoff`.

For the remaining examples, use this optional shell shortcut:

```bash
rem() { vigil remediation -k '<engagement-key>' "$@"; }

rem import --source jira --source-key SEC-123 --title 'Account authorization failure' \
  --snapshot-file issue.json --attachment report.pdf
rem worktree <case-id> --branch fix/SEC-123
rem handoff <case-id>
rem show <case-id>
```

`import` stores a JSON object supplied by the existing source reader; it does not fetch tickets.
Preserve retrieval provenance, original report, analysis, and attachment references. Direct reports
can use `--source report`. Attachments are copied and indexed as untrusted source evidence. Partial
registration prints the case ID: retry with `--resume-case-id <id>` and the same files. No
organization-side export utility or handoff skill is required.

For a Vigil finding, reuse the linked-case path:

```bash
rem from-finding --finding-engagement <assessment-key> --finding <finding-slug>
```

This captures the full intake finding and keeps assessment history separate. The Findings UI's
**Create remediation case** offers the same operation. Several findings can share a case; external
intake accepts repeatable `--finding-id <canonical-id>`. Overview shows current linked findings and
exact source links. Changing the identity set invalidates approval. Finding and submission exports
remain available; a portable remediation package is not required.

## Workspaces, checks, and shared runtime

Both Git and JJ use registered independent case source. JJ creates a workspace and bookmark,
snapshots edits, and rejects conflicts. Git requires a clean worktree for revision-bound review.
Evidence uses immutable commit IDs, never JJ change IDs; an empty single-parent JJ child retains its
parent's tested identity. New content invalidates approval. Vigil never automatically discards
scratch changes. Foreign or unregistered replacement repositories at the recorded path are rejected.

Commit the relevant changes, then synchronize and check:

```bash
rem sync-revision <case-id>
rem checks <case-id> --actor <owner>
rem checks <case-id> --actor <owner> --name tests
```

Checks use the case's saved review policy. Each runs in its workspace-relative `directory`, with
`VIGIL_CASE_WORKTREE`, `VIGIL_REPOSITORY`, and `VIGIL_CASE_REVISION` available to the command.
`VIGIL_CASE_BASE_REVISION` supplies the captured base for checks scoped to committed case changes.
Vigil records output, exit status, source identity, and execution directory. A check that edits source
is not a pass at the old revision: inspect, commit/sync, and rerun. All configured checks are required
for review and rerun before publishing; named execution is useful during development.

An isolated runner can mount case source while borrowing shared services/dependencies; there is no
full environment per worktree. Configured `borrowed_dependency_manifests` must exist and match the
shared repository before checks borrow dependencies. Prepare matching dependencies when a lockfile
differs rather than testing against the wrong packages.

Configured shared checks acquire exclusive case/revision-bound ownership and release it afterward.
Browser access additionally needs confirmed served identity. Coding and review can overlap; only one
case tests or changes a particular shared environment at a time.

```bash
rem environment acquire <case-id> --name acme-local --actor <owner>
# Retain the returned token and arrange for the runtime to serve case source.
rem runtime-identity <case-id> --compose-file /path/to/compose.yml --service web --container-path /app \
  --shared-environment acme-local --environment-token <token> --actor <owner>
# Perform approved runtime checks, then release ownership.
rem environment release <case-id> --name acme-local --token <token> --actor <owner>
```

Identity matches only when the inspected running service serves case source through its mount or a
matching revision-labelled image. A temporary command runner mounting case source does not prove the
shared browser application serves it. `runtime-identity` confirms the lease only on a match. Released
lease history retains evidence provenance.

## Select verification for the case

Use an explicit verification plan rather than imposing a framework or browser on every fix. Native,
API, frontend/Playwright, SQL, static analysis, caller analysis, and optional browser proof may be
appropriate. Prefer meaningful red/green regressions and legitimate controls when useful. A deletion
may need caller tracing and behavioral checks rather than a test asserting deleted code is absent.
Recommend independent QC when risk warrants it; it is not a universal gate.

Save the human preparation/testing brief and a nonempty JSON list of requirements. For example,
`requirements.json` for a native API test:

```json
[
  {
    "kind": "api-test",
    "methods": ["pytest"],
    "outcome": "passed",
    "revision": "current",
    "execution": "executed"
  }
]
```

```bash
rem plan <case-id> --file human-plan.md --requirements-file requirements.json \
  --alternatives-reason 'Native API tests cover both account controls; no UI path changes'
rem evidence <case-id> --kind api-test --method pytest --environment local --outcome passed \
  --command 'pytest tests/test_accounts.py' --observed 'Both account controls passed' \
  --proved 'Cross-account writes fail while authorized writes succeed' --revision <commit> \
  --executed-revision <commit> --executed-directory /path/to/case/workspace \
  --artifact /absolute/path/to/<engagement>/remediation/cases/<case-id>/tests/api.txt
rem baseline <case-id> --outcome runtime_reproduced --method pytest \
  --proved 'The original account boundary failure was reproduced'
```

Requirements select evidence kind, allowed methods, outcome, current/ancestor revision, and
executed/reasoned status. Runtime requirements may also set `shared_environment` and
`runtime_identity_required`. Explain the alternatives; an empty list cannot waive verification.
The backend checks matching evidence and case-source profile checks before approval. Static reasoning
uses `--execution reasoned`; unavailable checks use `--execution unavailable` and do not become
executed proof. Runtime evidence carries its lease token and confirmed identity where required.

For a code/test-confirmed baseline without safe runtime reproduction, `baseline` needs the explicit
owner decision: `--owner-decision proceed --owner-actor <owner> --owner-reason <reason>`. Cases without
explicit requirements retain historical Laravel red/green and browser gates; a new plan changes the
case contract deliberately rather than reinterpreting old evidence.

### Optional browser proof

Recommend browser/Stagehand work for uncertain UI behavior, role-dependent navigation, frontend side
effects, or screenshots that improve QA instructions. Explain the use and ask first. Trace labels
and navigation from frontend code when sufficient, distinguishing them from rehearsed steps.
Declining browser proof does not block sufficient explicit alternatives.

For browser requirements, select `browser_purpose: "happy-path"|"bad-path"|"other"`.
Omitting it keeps the happy-path gate. Bad-path and other runs need a passing result, recorded
steps, script, and confirmed served revision; screenshots are optional. Every browser plan must
also require a passing legitimate-use control at the current revision. Use a happy-path browser
requirement, or mark an executed API/native requirement `legitimate_use_control: true` and explain
the permitted operation in its `rationale`. The control must pass before approval.

The default `browse` driver uses an isolated browser and the supported `browse@0.11.1` package.
Inspect `browse skills show` for its contract. Scripts expose `async def run(browser, output_dir)`
and call `await browser.command(...)`. Return `observed`, `proved`, and a `served_revision` measured
from the application. A happy-path pass needs `status: passed`, nonempty action/observation steps,
and a valid screenshot directly in `output_dir`. The runner retains script, result, transcript, and
screenshots. Failed commands cannot claim a pass. It closes its own browser and rejects
`browser_cdp_url` for this driver to avoid closing an existing user browser.

```bash
rem browser <case-id> --script happy_path.py --purpose happy-path --environment local \
  --revision <served-commit> --shared-environment acme-local --environment-token <token>
```

The optional Stagehand SDK uses `async def run(stagehand, output_dir)` and `--driver stagehand`;
`stagehand` remains supported. Configure dedicated loopback CDP, an approved model/account, and
`api_key_env` naming the approved provider key. A client subscription does not authenticate the SDK.
Preserve account/browser restrictions. Production runs need separate `--production-decision` and
`--production-evidence-policy retain-screenshots|no-screenshots`; production happy-path proof requires
screenshot retention.

## Review and publish the draft

Present the diff, baseline, verification, human brief, and limits. Approval binds code, applicable
policy/guidance, linked findings, plan, and evidence. Approve in Vigil's UI or give an explicit
instruction for CLI approval. Development verification must match the current approved revision;
old deployments and tests remain history after changes.

```bash
rem release-plan <case-id> --production-canary not_required \
  --rationale 'Native boundary checks and development verification cover this change' \
  --monitoring 'Watch authorization failures and application error rates'
rem transition <case-id> review --actor <owner> --reason 'Diff and verification ready'
rem approve <case-id> --reviewer <owner> --review-digest <digest-shown-in-Vigil> \
  --owner-instruction 'Approve the reviewed code and verification plan for draft publication'
rem prepare-pr <case-id> --output pr-body.md --body-file template-body.md \
  --root-cause 'The update handler trusted an unscoped record identifier' \
  --fix-summary 'The handler now loads records through the authorized account scope'
rem create-pr <case-id> --body-file pr-body.md --template-mapped --actor <owner> \
  --title 'SEC-123 Scope account updates'
```

Use the profile's actual template and writing skill, preserving headings and comments. Explicit-plan
cases can use short QA-facing bodies without literal digests or full evidence ledgers. Prepared root
cause and fix explanation must be present. Full review content stays case-local. Historical cases
without explicit requirements retain detailed-body requirements.

Initial publication approval covers the reviewed patch and draft. The configured base is used for
review and creation. `create-pr` reruns profile checks, pushes the approved Git branch or JJ bookmark,
and records verified remote body/head. If a draft exists but state recording failed, retry with the
same body to reconcile instead of duplicating it.

For an owner-requested update, fix/check the same case, refresh review/approval and prepared content,
then publish to the same draft:

```bash
rem create-pr <case-id> --update --owner-instruction 'Publish the requested correction and update this draft' \
  --body-file pr-body.md --template-mapped --actor <owner>
```

Local edits alone do not authorize publication. Updates require the remote head to match Vigil's
last recorded publication and push with that exact lease; other remote changes need reconciliation.
Explain repository-configured automatic redeployment from a push before publishing updates.

## Deploy and verify

Ask separately about development deployment and configured optional suites. Inspect actual workflow
inputs and profile guidance. `deployment-run` uses GitHub CLI after explicit owner consent and records
the request and any identifiable run. It does not claim the revision is already serving traffic.

```bash
rem deployment-run <case-id> --actor <owner> --owner-instruction 'Deploy this reviewed branch to development' \
  --additional-tests-decision skip
rem deployment <case-id> --workflow development.yml --run-id <run-id> \
  --expected-revision <commit> --observed-revision <deployed-commit> --actor <owner>
rem human-verification <case-id> --actor <owner> --result passed --observed-revision <deployed-commit> \
  --notes 'Approved account operations and cleanup completed'
```

Use `--additional-tests-decision run` when approved, with appropriate `--input KEY=VALUE` flags.
Record the suite choice separately from deployment consent. Dispatch is not deployment proof: observe
and record served revision before claiming verification. For an external trigger,
`development-handoff` records the handoff and `deployment` records its actual run/revision.

Ticket integration is read-only: Vigil performs no direct Jira writes. Existing deployment/test
workflows may post ticket comments themselves; disclose that effect when requesting deployment.
Production replay, canary use, and monitoring follow the case release decision and project guidance.
