# Remediation workspace

Vigil's remediation workflow takes a security ticket or report from investigation to a draft PR.
For each ticket it keeps a case: the original report, a separate copy of the code to fix it in (a
Git worktree or JJ workspace), the agreed verification plan, the evidence that the fix works, and
your approvals. The repository's `PROJECT.md` profile says how to read tickets, which tools and
instructions to use, which checks must pass, and how to publish. A ticket or a written report is
enough; no earlier Vigil assessment is required.

Create one remediation engagement per repository and keep using it. Several assessment findings can
share one case when one fix covers them.

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

   `start` launches Claude and attaches automatically. It displays the repository,
   profile, and configured check names; no Continue confirmation is needed.

4. Give Claude the ticket IDs or URLs and ask it to use the remediation workflow,
   or explicitly invoke `/vigil-remediate SEC-123`. The agent
   retrieves the report, creates the case/workspace/handoff, and proposes its fix
   and verification plan. Check the diagnosis and scope, then approve the plan.
5. The agent implements the fix, runs checks against the case's copy of the code, records proof,
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
hook_policy = "inherit"
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
changes cannot silently retarget them.
New workspaces prefer the already-fetched origin branch/bookmark tip, then the local
base when no origin ref exists. Refresh origin before creating a case workspace.

Top-level machine overrides use `VIGIL_REMEDIATION_<FIELD>`; Stagehand overrides use
`VIGIL_REMEDIATION_STAGEHAND_<FIELD>`.

## Start and supply tickets

```bash
vigil remediation -k <engagement-key> start
```

Vigil opens a full Claude conversation in the repository root and attaches you to it, so Claude
sees the repository's own settings, skills, plugins, MCP servers, and any private (gitignored)
runbooks. Vigil adds only the remediation command and the case files, not its assessment
instructions. Then use the command in Claude:

```text
/vigil-remediate SEC-123
/vigil-remediate SEC-123 https://jira.example.com/browse/SEC-124
```

### Where the session runs

Every case conversation starts in the repository root, even when several cases run at once. Claude
Code reads project settings, hooks, skills, and project MCP servers from the directory a session
starts in ([settings](https://code.claude.com/docs/en/settings),
[skills](https://code.claude.com/docs/en/skills), [mcp](https://code.claude.com/docs/en/mcp)), and
gitignored files such as local settings and private runbooks exist only in the main checkout. Each
case edits only its own registered workspace through absolute paths; the root checkout is not case
source.

With `workspace_directory` inside the repository, the workspace sits under the session directory:

- Instruction files inside the workspace load on demand when Claude reads files there. Claude Code
  loads a subdirectory's `CLAUDE.md`, or its `AGENTS.md` when no `CLAUDE.md` applies, the first time
  it opens a file in that subdirectory ([memory](https://code.claude.com/docs/en/memory)).
  Instructions from the root checkout load at launch, so a root file that differs from the case base
  is read from the root checkout.
- A Bash `cd` into the workspace persists between commands because it stays inside the project
  directory ([tools reference](https://code.claude.com/docs/en/tools-reference)). Commands without
  an explicit path or directory run wherever the shell currently is.
- Hooks receive `CLAUDE_PROJECT_DIR` as the root checkout
  ([hooks](https://code.claude.com/docs/en/hooks)). Inspect how a hook maps edited paths before
  relying on it; one that assumes the root checkout may act on the wrong copy of a file.

Vigil's own gates do not depend on where the shell is: checks, diffs, review digests, and evidence
always use the registered workspace and its recorded revision.

With one ticket, this conversation becomes the case's developer. With several, it becomes a
coordinator that starts a separate Claude conversation for each case and shows you each diagnosis,
proposed fix, verification requirements, approval status, and `join` command. Approve each plan
inside that case's own conversation; one case's approval never covers another. A ticket key and its
`/browse/` URL count as one ticket. Ticket text is treated as untrusted data, never as instructions.

Claude fetches each ticket with the tools the profile names. A ticket stays pending until it has
actually been retrieved; if the reader is unavailable, it stays pending rather than Claude guessing
its contents. When a case already exists for the same ticket, Vigil says so instead of quietly
merging the two.

Before editing anything, Claude checks the report against the current code, proposes the fix and how
to verify it, and waits for your approval. If the report is wrong, already fixed, or unproven, Claude
says so with evidence. Bugs with the same root cause can share a case; unrelated issues get their
own. A profile can require a linked development ticket before publishing; Vigil never creates one.

Launching and attaching need Claude Code 2.1.257 or newer. `start` runs the conversation in the
background and attaches you to it, so you can always rejoin the same conversation. Ctrl-D detaches
without stopping it; reopening it from the agents view reattaches the same conversation with its
original settings. To pick up changed profile settings, stop it with `claude stop <id>` and run
`start` again. If startup exits before attaching, look in `claude agents --json --all` and the
engagement's `remediation/sessions/` receipts, then recover the recorded launch by its receipt UUID;
this never starts another conversation:

```bash
vigil remediation -k <engagement-key> start --session-id <recorded-launch-uuid>
```

Claude Code's own background worktree isolation is turned off for these sessions, because each case
already has its own workspace. For an existing case:

```bash
vigil remediation -k <engagement-key> session <case-id>
vigil remediation -k <engagement-key> join <case-id>
```

`session` launches a worker only when no binding exists. For one case, the agent binds its existing
UUID with `session --bind --session-id <uuid>`. `join` attaches to the recorded conversation; missing
or mismatched identities require recovery rather than replacement. When the recorded conversation has
stopped, `session --bind --session-id <uuid> --replace-stopped` binds the new one and keeps the old
UUID as `replaced_session_id`; a running conversation is never replaced. Native
binding, hosted worker launch, and exact joining currently support Claude only.

### OpenCode and ZCode repository context

For a single case, OpenCode and ZCode can open repository context and use the
same defensive remediation role, case handoff, verification requirements, and
approval gates:

```bash
vigil remediation -k <key> start --client opencode
vigil remediation -k <key> start --client zcode
```

OpenCode uses its native TUI and receives the release's `/vigil-remediate`
command through session configuration. Stable 1.x, at least 1.18.10, and the
native `--prompt` option are required. Choose Z.AI Coding Plan with `/connect`
and your entitled model with `/models`. Vigil preserves native authentication,
selected models, permissions, project configuration, and existing plugins.
An existing inline command named `vigil-remediate` is a reported collision.

ZCode workspace opening currently targets macOS and candidate releases 3.14.3
through 3.x. This version gate is based on the released interface, not a native
GUI certification. Install the desktop application
in `/Applications` or your user Applications directory, and have `node` available
for the plugin hook. Startup prints the prepared local marketplace, plugin name,
and opening instructions. In ZCode, add that marketplace under Settings → Plugins,
install and enable its plugin, open the printed repository, and create a new task.
Review the plugin hooks before enabling them. Choose Z.AI GLM Coding Plan and the
model in ZCode. Keep only the matching remediation context plugin enabled for
this repository, and follow the new plugin instructions when the profile or
application release changes. Merely writing project hook configuration does not
enable ZCode hooks. See [ZCode plugin setup](https://zcode.z.ai/en/docs/plugin)
and [hook configuration](https://zcode.z.ai/en/docs/hooks).

The prepared plugin contains `/vigil-remediate` and a repository-bound
`SessionStart` context hook. Startup, clear, and post-compaction events
point back to the selected profile and authoritative case records. The hook
requires a matching repository and active remediation engagement. It neither
steers ZCode's pre-compaction summary nor produces a session-end receipt.

These entrypoints retain native approvals and support `hook_policy = "inherit"`.
They reject `hook_policy = "disabled"` because a corresponding session-scoped
override has not been verified. Choose Claude when that policy is required;
changing the profile to inherit is an explicit owner decision.

Vigil-native `session`, binding, `join`, and `start --session-id` recovery remain
Claude-only. For OpenCode or ZCode, work on one case per native conversation and
resume it in that client. The command routes with an explicit client identity;
several distinct cases require separate native conversations rather than silently
launching Claude workers. A successful desktop open command does not establish
that a conversation started or that hooks were enabled.

Before relying on the integration, verify these native behaviors on your machine:

- Select the intended provider/model and invoke `/vigil-remediate` with an Acme
  fixture report. Confirm the correct profile, repository, and case workspace.
- Confirm approvals and native project plugins remain active, and fix-plan
  approval precedes edits. Record the structured verification requirements.
- For ZCode, confirm the enabled plugin's hook is visible, its `node` subprocess
  runs, and both manual and automatic compaction restore the selected case's
  authoritative state without injecting another engagement's context.
- Resume through the native client and verify case revision, evidence, approvals,
  and handoff continuity. After a Vigil upgrade, prepare and enable the new
  matching context plugin. ZCode conversations have no Vigil release-ownership
  receipt; do not assume retained helper paths survive release cleanup, or treat
  this as a Vigil exact-join test.

Automated tests exercise generation, packaging, launch arguments, policy errors,
context isolation, and the hook subprocess protocol. Native authentication,
desktop window reuse, provider execution, plugin activation, and vendor-driven
compaction require this end-to-end verification.

### Hook policy

Claude Code hooks are automatic actions such as formatting after an edit or logging a session.
`hook_policy = "inherit"`, the default, keeps them. `"disabled"` turns off personal, repository,
local, and ordinary plugin hooks for the session; organization-managed hooks stay on, and Claude Code
also hides any custom status line. Git hooks such as pre-commit are never affected. Reattaching
reports the policy the session started with.

Because the session starts in the repository root while edits happen in the case workspace, check
what each repository hook acts on before relying on it (see [Where the session runs](#where-the-session-runs)).
Hooks are a convenience, not proof: Vigil does not copy hook commands into `check_commands`. Before
editing, Claude works out which checks the repository requires from its instructions and hook
configuration, makes sure the profile's check commands or the case plan cover them, and asks you
when unclear. Startup says when no profile checks are configured. Put checks every case needs in
`PROJECT.md` and case-specific ones in the case plan. Every profile check must pass before approval
and publishing.

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

Each case has its own workspace: a separate checkout created with `jj workspace add` (plus a
bookmark) or `git worktree add`. It shares the repository's history but has its own files, so cases
never edit each other's code. Gitignored files such as installed dependencies and local
configuration are not copied into it.

Evidence is recorded against commit IDs, never JJ change IDs. With JJ, Vigil snapshots the workspace
and refuses conflicts; with Git, everything must be committed. An empty JJ child commit counts as its
parent. Any new content after approval makes the approval stale. Vigil never discards uncommitted or
scratch changes for you, and refuses a different repository found at a case's recorded path. With JJ
on a case-insensitive filesystem, tracked paths that differ only in letter case show up as renames in
every snapshot and land in the case commit; remove them before review.

Commit the relevant changes, record the commit, then run checks:

```bash
rem sync-revision <case-id>
rem checks <case-id> --actor <owner>
rem checks <case-id> --actor <owner> --name tests
```

Checks use the profile settings the case started with. Each runs from its `directory` inside the
workspace with `VIGIL_CASE_WORKTREE`, `VIGIL_REPOSITORY`, `VIGIL_CASE_REVISION`, and
`VIGIL_CASE_BASE_REVISION` set. The base revision is the case's merge base with its base branch;
`sync-revision` moves it forward when the case is rebased onto a newer base, never backwards, and it
cannot be set directly. Vigil saves each check's output, exit code, commit, and directory. A check
that changes files, such as a formatter, does not count as a pass: commit the change, sync, and
rerun. All profile checks must pass for review and again before publishing; `--name` runs a single
check during development.

There is one shared local environment, not one per workspace. A check can run in a throwaway
container that mounts the case workspace and borrows dependencies installed in the main checkout.
`borrowed_dependency_manifests` lists the files that must match for that to be safe, such as a
lockfile. If the case's copy differs from the main checkout's, Vigil refuses rather than test
against the wrong packages: update the main checkout's dependencies, or base the case on a commit
whose manifests match.

Only one case at a time may use a shared environment, and Vigil tracks this with a lease. `checks`
takes and releases it automatically. Coding and review can overlap freely. For browser or runtime
testing, take the lease yourself, point the environment at the case workspace, confirm what it
serves, test, point it back, and release:

```bash
rem environment acquire <case-id> --name acme-local --actor <owner>
# Retain the returned token and arrange for the runtime to serve case source.
rem runtime-identity <case-id> --compose-file /path/to/compose.yml --service web --container-path /app \
  --shared-environment acme-local --environment-token <token> --actor <owner>
# Perform approved runtime checks, then release ownership.
rem environment release <case-id> --name acme-local --token <token> --actor <owner>
```

`runtime-identity` reports `matched` only when the running service serves the case workspace,
through a mount or an image labelled with the case commit, and only then confirms the lease. Choose a
`--container-path` that holds only case code: anything under it mounted from elsewhere, such as
dependencies borrowed from the main checkout, makes the result `unproven`. A throwaway container that
mounts the case does not prove what the shared application serves. Released leases stay in the case
history.

Leases never expire, so release before waiting on owner input unless background work still uses the
environment. Releasing only records ownership: point the environment back at its default source
first. If a conversation ends while holding a lease, `rem show <case-id>` lists its token so you can
release it.

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

Each requirement names the evidence kind, the allowed methods, the expected outcome, whether the
evidence must be from the current commit or may come from an earlier one (`ancestor`), and whether it
must actually run (`executed`) or may be reasoned from code (`reasoned`). Runtime requirements can
also name a `shared_environment` and set `runtime_identity_required`. Explain your choice of methods
with `--alternatives-reason`; an empty list cannot waive verification. Before approval, Vigil checks
that every requirement and every profile check has matching evidence. Evidence recorded with
`--execution reasoned` or `--execution unavailable` never satisfies an executed requirement. The
first plan must include both the readable brief and the requirements file; a later text-only update
keeps the recorded requirements, and a new requirements file replaces them.

For a code/test-confirmed baseline without safe runtime reproduction, `baseline` needs the explicit
owner decision: `--owner-decision proceed --owner-actor <owner> --owner-reason <reason>`. Existing case
plans and evidence remain recorded; changing requirements does not reinterpret prior evidence.

### Optional browser proof

Recommend browser work for uncertain UI behavior, role-dependent navigation, frontend side
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

Playwright or another browser test runner works too. Run it against the served case while holding
the lease, save its output and screenshots under the case directory, and record it with
`rem evidence --method playwright --shared-environment <name> --environment-token <token>` against
an executed requirement that sets `runtime_identity_required`. The `browser` command's own checks
(recorded steps, screenshot, legitimate-use control) do not apply to these runs, so plan the
legitimate-use run as its own requirement.

The optional Stagehand SDK uses `async def run(stagehand, output_dir)` with `--driver stagehand`
or the `stagehand` command. Configure dedicated loopback CDP, an approved model/account, and
`api_key_env` naming the approved provider key. A client subscription does not authenticate the SDK.
Preserve account/browser restrictions. Production runs need separate `--production-decision` and
`--production-evidence-policy retain-screenshots|no-screenshots`; production happy-path proof requires
screenshot retention.

## Review and publish the draft

Before approving, review the diff, baseline, verification, human brief, and limits. Approval
records the code, the case's profile settings, linked findings, plan, and evidence. Changing any of
them makes the approval stale, which blocks the PR and deployment until you approve again; editing
instruction or template files does not. Approve in Vigil's UI or tell Claude explicitly to approve
through the CLI. Development verification must match the current approved commit; earlier
deployments and tests stay as history.

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
