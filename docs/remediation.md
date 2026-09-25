# Remediation operator pilot

Create one long-lived Acme engagement. Each Jira issue or direct bounty
report is a separate case; cases keep separate worktrees and evidence under
`<engagement>/remediation/cases/<id>/`.

```bash
vigil engagement create --type remediation --name Acme \
  --repo /absolute/path/to/Acme --project-config project.json --no-prompt
```

`project.json` holds project configuration, not credentials:

```json
{
  "development_url": "https://development.example.invalid",
  "test_url": "https://test.example.invalid",
  "browser_cdp_url": "http://127.0.0.1:9222",
  "stagehand": {
    "model": "openai/<company-approved-model>",
    "approved_account": "<company-approved-account>",
    "api_key_env": "COMPANY_STAGEHAND_MODEL_KEY"
  },
  "deployment_workflow": "<observed GitHub Actions workflow filename>"
}
```

The model and account must be approved by the company before project pages
are shown to Stagehand. Keep the provider key in the named environment
variable, and keep browser login state in a dedicated local Chrome profile.
The CDP endpoint must be on loopback. The runner attaches to that existing
Chromium session using Stagehand v4; it never starts a remote browser. Install
the tested host SDK alongside the editable CLI with
`uv tool install --editable . --with stagehand==4.1.0` from the Vigil checkout
before running browser scripts. See the [Stagehand browser
configuration](https://docs.stagehand.dev/v4/configuration/browser) and
[installation](https://docs.stagehand.dev/v4/first-steps/installation).

Use an authorized Jira MCP or export to prepare the issue snapshot. Import a
JSON issue snapshot with the report text and relevant metadata.
Attachments are copied into the case directory and indexed as untrusted source
evidence. This command consumes a prepared snapshot file; it does not fetch
Jira or bounty data itself. If Jira access is unavailable, record a precise
pending handoff rather than claiming that the issue was imported or updated.
If registration fails after case creation, the error prints the case ID; rerun
the same import with `--resume-case-id <id>` to complete the files without
creating a second case.

```bash
vigil remediation -k <engagement-key> import --source jira \
  --source-key SEC-123 --title 'Issue title' \
  --snapshot-file issue.json --attachment report.pdf
vigil remediation -k <engagement-key> worktree <case-id> --base main
vigil remediation -k <engagement-key> show <case-id>
```

Commit the failing regression on the case branch before recording red-test
evidence. Commit the fix, then run `sync-revision` before recording green-test
evidence, rehearsing the fixed browser path, or requesting review. The command
requires a clean case worktree and updates the recorded case revision to its
current HEAD. The red-test revision must be a pre-fix commit in the fixed
revision's ancestry. Any earlier approval becomes stale when the revision
changes. A worktree retry and `sync-revision` accept only a worktree still
registered to the configured repository, not an unrelated repository at the
same path or with the same branch name. The branch chosen at `worktree`
registration is recorded on the case. Keep the case worktree on that branch
through `sync-revision`, approval, PR creation, and development handoff;
approved operations recheck repository registration. Development verification
must match the latest approval and its revision. An earlier deployment and
human result cannot verify a revised fix or a newly approved plan.

Add a Finding link with `--finding <slug> --finding-engagement <key>` only if
one already exists. Review duplicate hints in Vigil before deciding whether
two case records describe the same report.

Record each reproduction or test with its actual method, environment
(`local`, `development`, `test`, or `production`), command, observation, claim,
revision, and optional artifact file inside this case directory. Imported
source files and PR text have `not_applicable` environment; historical records
without one remain visibly unknown.

```bash
vigil remediation -k <key> evidence <case-id> --kind baseline \
  --method laravel_test --environment local --command 'php artisan test ...' \
  --observed 'test failed with 403' --proved 'reported boundary is reproducible' \
  --revision <commit>
vigil remediation -k <key> evidence <case-id> --kind red-test \
  --method Laravel --environment local --outcome failed_as_expected \
  --command 'php artisan test --filter AuthorizationRegression' \
  --observed 'Regression failed before the fix' \
  --proved 'The vulnerable boundary was exercised' \
  --revision <pre-fix-commit> \
  --artifact /absolute/path/to/<engagement>/remediation/cases/<case-id>/tests/red.txt
vigil remediation -k <key> sync-revision <case-id>
vigil remediation -k <key> evidence <case-id> --kind green-test \
  --method Laravel --environment local --outcome passed \
  --command 'php artisan test --filter AuthorizationRegression' \
  --observed 'Regression and positive control passed after the fix' \
  --proved 'The boundary and legitimate path now behave as expected' \
  --revision <fixed-commit> \
  --artifact /absolute/path/to/<engagement>/remediation/cases/<case-id>/tests/green.txt
vigil remediation -k <key> baseline <case-id> \
  --outcome runtime_reproduced --method laravel_test \
  --proved 'Test reproduces the reported authorization failure'
vigil remediation -k <key> runtime-identity <case-id> \
  --compose-file /path/to/compose.yml --service web --container-path /app
```

For a code-and-test-supported report without safe runtime reproduction, use
`--outcome code_test_confirmed --owner-decision proceed --owner-actor <owner>
--owner-reason <reason>` only after the case owner decides. The runtime identity
command reports `matched` only when a running container serves the case
worktree via a bind mount or carries a matching image revision label; otherwise
it reports `unproven` with container, image, mount, and worktree details.

Stagehand scripts expose `async def run(stagehand, output_dir)` and return a
JSON object with `observed` and `proved` fields. A happy-path result also needs
`steps`, a nonempty list of `{ "action": "...", "observation": "..." }`
objects, an explicit `"status": "passed"`, and at least one valid screenshot.
Write screenshots directly
into `output_dir`; the runner preserves the script, result, and screenshot
files, then registers each with the case API. Use Stagehand's browser APIs
directly. Do not record credentials or session tokens.

```bash
vigil remediation -k <key> stagehand <case-id> \
  --script happy_path.py --purpose happy-path --environment local \
  --revision <served-revision>
```

For a separately approved production run, supply both
`--production-decision '<case-owner decision>'` and
`--production-evidence-policy retain-screenshots|no-screenshots`. The chosen
policy is recorded in the result. The runner refuses an unexpected screenshot
under `no-screenshots` and retains that failed run for review. A production
happy-path run requires screenshot retention.

Write the human plan using the engagement's
`cases/verification-plan.template.md`. Include only UI steps rehearsed in a
running environment. Save the plan, transition the case to `review`, and
present the local diff, baseline, red/green tests, browser results, screenshots,
and plan in Vigil. A case-owner Security Developer may approve in the UI. The
CLI approval path requires their explicit instruction:

```bash
vigil remediation -k <key> plan <case-id> --file human-plan.md
vigil remediation -k <key> release-plan <case-id> \
  --production-canary required --rationale 'Infrastructure behavior' \
  --safe-procedure 'Use a designated account and isolated data' \
  --coralogix-monitoring 'Watch request failures and authorization errors'
vigil remediation -k <key> transition <case-id> review \
  --actor <owner> --reason 'Diff and evidence ready for review'
vigil remediation -k <key> approve <case-id> --reviewer <owner> \
  --review-digest <digest-shown-in-Vigil> \
  --owner-instruction 'Approve the reviewed code and verification plan'
```

Approval is bound to the reviewed worktree revision, plan, and evidence. If
any of those change, repeat the review. Generate structured PR content, map it
to the repository's actual PR template, then open a draft PR against `main`. The
prepared and final PR bodies are retained under the case and indexed in Vigil.
The final body must keep the exact reviewed human plan and red/green/Stagehand
evidence summary. A `defer` canary decision may be saved during planning, but
the PR requires a final `required` or `not_required` decision:

```bash
vigil remediation -k <key> prepare-pr <case-id> --output pr-body.md \
  --root-cause 'The controller trusted an unscoped record ID during update' \
  --fix-summary 'The update now loads records through the authorized tenant scope'
vigil remediation -k <key> create-pr <case-id> --body-file pr-body.md \
  --template-mapped --actor <owner>
```

If the external draft PR exists but Vigil's transition fails, rerun `create-pr`
with the same body file. It discovers the existing open draft and records the
transition without pushing or creating a second PR. The draft's remote head
and live body must match the approved revision and reviewed body before the
transition is recorded. If someone edited the draft body, inspect and restore
the reviewed content before retrying.
Use `create-pr` and `development-handoff` to enter `pr_draft` and `development`;
the generic `transition` command does not claim those states.

For the first case, a human triggers the existing GitHub Actions development
workflow. Inspect its actual inputs before setting `deployment_workflow` in
the project configuration. The handoff command records the development state
and prints the expected revision; the deployment record accepts only matching
expected and observed revisions:

```bash
vigil remediation -k <key> development-handoff <case-id> --actor <owner>
vigil remediation -k <key> deployment <case-id> --workflow <workflow> \
  --run-id <run-id> --expected-revision <commit> \
  --observed-revision <deployed-commit> --actor <owner>
vigil remediation -k <key> human-verification <case-id> --actor <owner> \
  --result passed --observed-revision <deployed-commit> \
  --notes 'Exact rehearsed observations and cleanup completed'
```

The PR should state whether a human production canary is needed, why, the safe
verified procedure, and Coralogix signals to monitor. Production exploit
replay and production Stagehand remain case-specific human decisions. Permanent
production Playwright happy-path tests do not capture screenshots by default.
Monitor Coralogix after release even if exploit replay is waived. Comment only
the verification state back to Jira after human development verification; if
Jira access is unavailable, record the exact pending comment handoff.
