# Remediation operator pilot

Use one long-lived engagement per repo (Acme here). Each Jira issue/direct bounty report gets its own
case, worktree, and evidence under `<engagement>/remediation/cases/<id>/`.

## 1. Configure

```bash
vigil engagement create --type remediation --name Acme \
  --repo /absolute/path/to/Acme --no-prompt
```

Creation scaffolds the repository's shared `PROJECT.md` and links the engagement to it.
Commit and share this single file: TOML frontmatter holds configuration, Markdown holds instructions.
Existing files are preserved. Pass `--project-config /path/to/PROJECT.md` to select another shared file.
Claude Code/Codex fill facts observed in the repo or supplied by the owner and ask about missing values;
unknown values stay blank. Only operations needing those fields wait for answers.

```toml
+++
repository = "."
development_url = ""
test_url = ""
production_url = ""
browser_cdp_url = ""
deployment_workflow = ""
[stagehand]
model = ""
approved_account = ""
api_key_env = ""
+++
# Acme remediation
# Add account, fixture, setup, and release instructions here.
```

| Prerequisite | Requirement |
|---|---|
| Default browser | Install `browse@0.11.1` with `npm install -g browse@0.11.1`; Claude Code (primary) or Codex supplies reasoning through its existing session. No separate model API key. The runner owns an isolated local browser; authenticate there during the rehearsal. |
| Optional SDK | Stagehand v4 attaches to dedicated Chromium via loopback CDP. Install `uv tool install --editable . --with stagehand==4.1.0`. Configure model/account approval and an `api_key_env` variable name whose value holds the provider key; a Claude/Codex subscription does not authenticate this SDK. |

Repository paths are relative to the shared file. Machine overrides use `VIGIL_REMEDIATION_<FIELD>`
or `VIGIL_REMEDIATION_STAGEHAND_<FIELD>`; there is no second editable config. Legacy JSON can be
imported once with `--project-config project.json` on creation; a conflicting repository file is rejected.
For an existing engagement, preserve the old notes/JSON, convert them into a shared TOML `PROJECT.md`,
then replace the engagement's old `PROJECT.md` with a link to that file. Case history stays in place.

See Stagehand's [browser configuration](https://docs.stagehand.dev/v4/configuration/browser) and
[installation](https://docs.stagehand.dev/v4/first-steps/installation).

For the commands below, replace the engagement key once:

```bash
rem() { vigil remediation -k '<engagement-key>' "$@"; }
```

`rem` is only a shell shortcut for `vigil remediation -k <engagement-key>`.

## 2. Import

Import a prepared JSON issue snapshot (report text and relevant metadata) from an authorized Jira MCP/export;
this command does not fetch Jira/bounty data. Attachments are copied into the case and indexed as untrusted
source evidence. Without Jira access, record a precise pending handoff, not an import/update claim.

```bash
rem import --source jira --source-key SEC-123 --title 'Issue title' --snapshot-file issue.json --attachment report.pdf
rem worktree <case-id> --base main
rem show <case-id>
```

Failed registration prints the created case ID: retry that import with `--resume-case-id <id>` to finish files
without another case. Link only an existing Finding with `--finding <slug> --finding-engagement <key>`. Check
Vigil's duplicate hints before deciding cases describe the same report.

## 3. Reproduce and fix

| Gate | Requirement |
|---|---|
| Red test | Commit the failing regression on the case branch before red evidence; its pre-fix revision must be an ancestor of the fixed revision. |
| Fixed revision | Commit the fix; `sync-revision` records its immutable commit ID before green evidence, browser rehearsal, or review. Git requires a clean worktree; JJ snapshots edits and rejects conflicts or files it cannot snapshot. |
| Worktree | Stay registered to the configured repo and on the branch recorded at `worktree` through sync, approval, PR creation, and development handoff. Retries/sync reject foreign repos at the same path/branch; approved operations recheck registration. |

When `.jj` exists, `worktree` creates a JJ workspace and case bookmark; `create-pr` moves and pushes
that bookmark to the approved commit with `jj git push`. Git repos retain their existing path.
Evidence uses immutable commit IDs, never mutable JJ change IDs. An empty single-parent child keeps
its parent's tested identity; new content invalidates approval.

Record actual method, environment (`local`, `development`, `test`, `production`), command, observation, claim,
revision, and optional case-local artifact file for each reproduction/test. Imported source/PR text use
`not_applicable`; missing historical environments stay visibly unknown.

```bash
rem evidence <case-id> --kind baseline --method laravel_test --environment local --command 'php artisan test ...' \
  --observed 'test failed with 403' --proved 'reported boundary is reproducible' --revision <commit>
rem evidence <case-id> --kind red-test --method Laravel --environment local --outcome failed_as_expected \
  --command 'php artisan test --filter AuthorizationRegression' \
  --observed 'Regression failed before the fix' --proved 'The vulnerable boundary was exercised' \
  --revision <pre-fix-commit> --artifact /absolute/path/to/<engagement>/remediation/cases/<case-id>/tests/red.txt
rem sync-revision <case-id>
rem evidence <case-id> --kind green-test --method Laravel --environment local --outcome passed \
  --command 'php artisan test --filter AuthorizationRegression' \
  --observed 'Regression and positive control passed after the fix' \
  --proved 'The boundary and legitimate path now behave as expected' --revision <fixed-commit> \
  --artifact /absolute/path/to/<engagement>/remediation/cases/<case-id>/tests/green.txt
rem baseline <case-id> --outcome runtime_reproduced --method laravel_test \
  --proved 'Test reproduces the reported authorization failure'
rem runtime-identity <case-id> --compose-file /path/to/compose.yml --service web --container-path /app
```

For code-and-test-supported reports without safe runtime reproduction, use `--outcome code_test_confirmed
--owner-decision proceed --owner-actor <owner> --owner-reason <reason>` only after the case owner's decision.
Runtime identity is `matched` only when a running container serves the case worktree via bind mount or carries
a matching image revision label; otherwise `unproven`, with container, image, mount, and worktree details.

## 4. Rehearse in the browser

The default script exposes `async def run(browser, output_dir)` and calls `await browser.command(...)`
with `browse` arguments, such as `("open", application_url)`, `("snapshot",)`, and
`("screenshot", "--path", str(output_dir / "screen.png"))`. Inspect `browse skills show` for its installed
command contract. Return a JSON object with `observed`, `proved`, and the observed `served_revision`
matching `--revision`; derive that revision from the served app/runtime, not the checkout alone.
Happy-path results require `"status": "passed"`, a nonempty `steps` list
of `{ "action": "...", "observation": "..." }` objects, and at least one valid screenshot written directly
into `output_dir`. The runner preserves script, result, command transcript, and screenshots as case evidence;
failed commands invalidate a claimed pass. Its named local browser closes after the run.
`browse` 0.11.1 closes attached Chrome on shutdown, so this driver rejects `browser_cdp_url` rather
than closing a user's browser; leave it blank for the default driver.

```bash
rem browser <case-id> --script happy_path.py --purpose happy-path --environment local --revision <served-revision>
```

For optional SDK scripts, expose `async def run(stagehand, output_dir)`, use Stagehand APIs, and run
`rem browser ... --driver stagehand`; the existing `rem stagehand ...` spelling remains supported.

Separately approved production runs require both `--production-decision '<case-owner decision>'` and
`--production-evidence-policy retain-screenshots|no-screenshots`, recorded in the result. Unexpected
screenshots under `no-screenshots` fail the run; the failed run is retained for review. Production happy-path
runs require screenshot retention.

## 5. Review and draft PR

Write the human plan from the engagement's `cases/verification-plan.template.md`, using only UI steps
rehearsed in a running environment. Save it, enter `review`, and present local diff, baseline, red/green
tests, browser results, screenshots, and plan in Vigil. A case-owner Security Developer may approve in UI; CLI
approval requires their explicit instruction.

```bash
rem plan <case-id> --file human-plan.md
rem release-plan <case-id> --production-canary required --rationale 'Infrastructure behavior' \
  --safe-procedure 'Use a designated account and isolated data' \
  --coralogix-monitoring 'Watch request failures and authorization errors'
rem transition <case-id> review --actor <owner> --reason 'Diff and evidence ready for review'
rem approve <case-id> --reviewer <owner> --review-digest <digest-shown-in-Vigil> \
  --owner-instruction 'Approve the reviewed code and verification plan'
```

Approval binds worktree revision, shared project configuration, plan, and evidence; changes require review again. Development verification
must match the latest approval and revision; earlier deployment/human results cannot verify a revised fix or
newly approved plan. Map structured PR content to the repo's actual template; open a draft against `main`.
Prepared/final bodies remain case-local and indexed in Vigil. Preserve the exact reviewed human plan and
red/green/browser evidence summary in the final body. The PR must state `required` or `not_required` for a
human production canary (`defer` only during planning), why, the safe verified procedure, and Coralogix
signals.

```bash
rem prepare-pr <case-id> --output pr-body.md --root-cause 'The controller trusted an unscoped record ID during update' \
  --fix-summary 'The update now loads records through the authorized tenant scope'
rem create-pr <case-id> --body-file pr-body.md --template-mapped --actor <owner>
```

| Recovery/state rule | Action |
|---|---|
| Draft exists, Vigil transition failed | Retry `create-pr` with the same body file: it finds the open draft and records state without pushing/duplicating the PR. Remote head/live body must match approved revision/reviewed body. Inspect and restore edited body content before retrying. |
| PR/development state | Only `create-pr` enters `pr_draft`; only `development-handoff` enters `development`, not generic `transition`. |

## 6. Deploy and verify

For the first case, a human triggers the existing GitHub Actions development workflow; inspect actual inputs
before setting `deployment_workflow`. Handoff records development state and prints expected revision;
deployment requires matching expected/observed revisions.

```bash
rem development-handoff <case-id> --actor <owner>
rem deployment <case-id> --workflow <workflow> --run-id <run-id> --expected-revision <commit> \
  --observed-revision <deployed-commit> --actor <owner>
rem human-verification <case-id> --actor <owner> --result passed --observed-revision <deployed-commit> \
  --notes 'Exact rehearsed observations and cleanup completed'
```

Production exploit replay and Stagehand remain case-specific human decisions. Permanent production Playwright
happy-path tests omit screenshots by default. Monitor Coralogix after release even if replay is waived. After
human development verification, comment only verification state to Jira; without access, record the exact
pending comment handoff.
