---
name: cicd-security
description: GitHub Actions and CI/CD pipeline security testing — expression injection, untrusted checkout, artifact/cache poisoning, supply chain, self-hosted runner exploitation, AI agent security
origin: Vigil
---

# CI/CD Pipeline Security Testing

## When to Activate

- The target has public repositories with `.github/workflows/`, recon ties a GitHub org to
  in-scope domains, or source/code analysis meets CI configuration (GitHub Actions, GitLab CI,
  Jenkins).

`--technique CMDI`/`RCE` when a step takes attacker-controlled shell input, `AUTH` for token or
secret exposure that grants further access, `INFO-DISCLOSURE` for build-log exposure, `OTHER`
for other pipeline abuse.

**Track.** On the code track, record the static proof (trigger, taint path, reachable secrets
and permissions); a live PoC belongs to the live track with approval. Precedents and paid-report
case studies for severity and shape matching: `agent/references/cicd/github-actions-precedents.md`
(load when a workflow matches a known exploitable shape, or before sizing severity or citing precedent).

## Recon and triage

Fetch the workflows (clone or `gh api`) and scan with `sisakulint scan .github/workflows/` or
`sisakulint scan --remote owner/repo` (taint across steps, jobs and reusable workflows; install it
if missing). sisakulint findings are leads, not bugs: verify each by answering, in order,
(a) can an external user trigger it (fork PR, issue, comment; check `if:` actor/association
filters), (b) which secrets and token permissions are reachable (`permissions:` at workflow and
job level; none set means the repo default, often write-all; `env:` secrets; `secrets: inherit`),
(c) what is the blast radius (repo secrets → deploy keys → cloud).

## Bug classes

Standard GitHub Actions classes apply; the less obvious checks are inline.

- **Expression injection:** attacker-controlled `github.event.*` (issue/PR/comment/review
  title and body, `head.ref`/`github.head_ref`, commit messages and author names, page names,
  `workflow_run.head_branch`) interpolated into `run:` or into an AI-agent prompt. Branch names
  cannot contain spaces: payloads use `${IFS}` and brace expansion (`{curl,-sSfL,URL}`). Booleans
  from `contains()`/`startsWith()` are not injectable.
- **`$GITHUB_ENV` / `$GITHUB_PATH` / `$GITHUB_OUTPUT` injection** (no heredoc delimiter),
  argument injection into CLI calls, attacker-controlled URLs (SSRF from the runner).
- **Pwn request:** `pull_request_target`, `workflow_run` or `issue_comment` (base-repo context
  with secrets, checking out `refs/pull/<n>/head`) runs attacker code, explicitly or implicitly
  through build config the tool evaluates. Label-gated approval with a mutable ref is a TOCTOU.
- **Artifact poisoning:** only the two-stage shape is poisonable (a `pull_request` upload consumed
  by a separate `workflow_run` with secrets; same-run `needs:` is not). `download-artifact` with
  `path: .` can overwrite source and scripts; check the consumer validates
  `workflow_run.head_repository.full_name`. **ArtiPACKED:** `persist-credentials: true` (the
  default) writes the token to `.git/config`, which leaks if the upload includes `.git/`.
- **Cache poisoning:** a fork PR's caches are scoped to its PR ref and are not restored by the
  default branch, so the real vector is attacker code running in a default-branch context
  (`pull_request_target`, `issue_comment`, `workflow_run`, an AI agent) writing a predictable key
  (`hashFiles(...)` with no `github.sha`/`run_id`), or eviction pressure that replaces entries.
  A privileged `push`/`schedule` workflow then restores it. Entries live 7 days.
- **Supply chain:** unpinned actions and container images, impostor commits from the fork
  network, ref confusion, RepoJacking after an org rename, archived or known-vulnerable actions.
- **Secrets:** exfiltration paths, secrets in artifacts, `fromJson()`-derived values that escape
  automatic masking, over-broad `secrets: inherit`, hardcoded credentials, OIDC tokens granting
  cloud access.
- **Triggers and permissions:** dangerous triggers without `permissions: {}` or approval; label
  checks; **bot spoofing** — `if: github.actor == 'dependabot[bot]'` trusts whoever triggered the
  latest event; write-all tokens. `GITHUB_TOKEN` cannot write `.github/workflows/` (it never has
  the `workflows` scope); CVE-2022-46258 was a GitHub Enterprise Server bypass of that rule, so
  check the GHES version on self-hosted instances.
- **Self-hosted runners in public repos:** first-time-contributor approval is lifted after one
  merged PR; non-ephemeral runners keep state; Docker-group membership means host root. Show the
  reachable condition; installing a second runner agent or escaping to the host changes target
  infrastructure and needs explicit approval.
- **AI agents in workflows:** `allowed_non_write_users: "*"`, Bash/Write/Edit tool grants in
  untrusted trigger contexts, and HTML comments (invisible in the UI, present in the API body)
  carrying injected instructions.

Permissions and secret hygiene are force multipliers, not standalone bugs: the same injection is
Critical with write-all and limited with `contents: read`.

## PoC and proof

Creating an issue, PR or comment on a target repository is a persistent, human-visible write:
it needs the side-effect preflight and operator approval (`agent/shared-constraints.md` §2d)
before `vigil assess kali exec --destructive … -- gh issue create …`. Prove execution with a
benign marker and a minted OOB host (`agent/references/offensive-tactics/frp-tunneling.md`
"OOB Procedure (mint→poll→correlate)"), e.g. a step that requests `http://$OOB_HOST/` with
`id` output; never exfiltrate real secrets or tokens (proof-not-collection,
`agent/rules/hunting.md` §10). Severity: `agent/references/finding-fp-and-severity-gate.md`.

## Kill and escalate

- Kills: `if: "!github.event.pull_request.head.repo.fork"`; `permissions: {}` with job-level
  `contents: read`; ephemeral runners; full 40-character SHA pins with Dependabot for actions;
  an org action allowlist; `author_association` checks before AI processing; `cache/restore`
  (read-only) in PR workflows; keys containing `github.sha`/`run_id`.
- Chains worth walking: injection → secret → cloud account; untrusted checkout → build RCE →
  deploy key → repository takeover; artifact poisoning → tampered release; cache poisoning →
  backdoored deploy; impostor commit → every downstream repo; OIDC → cloud metadata → storage;
  self-hosted runner → internal network.

Payloads: `agent/references/payloads/command-injection-payloads.md`; source patterns:
`agent/references/code-vuln-patterns/injection.md`.
