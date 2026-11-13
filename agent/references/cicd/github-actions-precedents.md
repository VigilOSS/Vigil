---
description: GitHub Actions precedent library — advisory table and paid-report case studies (composite-action taint, implicit build-config execution, self-hosted runner escalation, cache-poisoning and supply-chain chains) for sizing severity and recognising exploitable shapes
skill: cicd-security
---

# GitHub Actions precedents

Load when sizing a CI/CD finding's severity, citing precedent in a submission, or deciding
whether a sisakulint lead matches a shape that has paid before. Methodology and gates live in
`agent/skills/cicd-security/SKILL.md`.

## Advisories

| GHSA | Action | Bug class | Severity |
|---|---|---|---|
| GHSA-gq52-6phf-x2r6 | tj-actions/branch-names | Expression injection via branch name | Critical |
| GHSA-4xqx-pqpj-9fqw | atlassian/gajira-create | Code injection in privileged trigger | Critical |
| GHSA-g86g-chm8-7r2p | check-spelling/check-spelling | Secret exposure in build logs | Critical |
| GHSA-cxww-7g56-2vh6 | actions/download-artifact | Artifact poisoning (official action) | High |
| GHSA-h3qr-39j9-4r5v | gradle/gradle-build-action | Cache poisoning via untrusted checkout | High |
| GHSA-mrrh-fwg8-r2c3 | tj-actions/changed-files | Supply chain — version tags repointed to a malicious commit with a compromised token | High |
| GHSA-phf6-hm3h-x8qp | broadinstitute/cromwell | Token exposure via code injection | Critical |
| GHSA-qmg3-hpqr-gqvc | reviewdog/action-setup | Time bomb via tag pinning | High |
| GHSA-vqf5-2xx6-9wfm | github/codeql-action | Known vulnerable official action | High |
| GHSA-hw6r-g8gj-2987 | pytorch/pytorch | Argument injection in build workflow | Moderate |

The sisakulint advisory index maps 38 GHSAs to its rules
(<https://sisaku-security.github.io/lint/docs/advisory/>).

## Case studies

- **Transitive taint through a composite action (Bazel).** `cherry-picker.yml` looked safe but
  passed `${{ github.event.issue.title }}` via `with:` to a composite action in another repository
  whose `action.yml` ran `TITLE="${{ inputs.issue-title }}"`. Issue-title injection reached a
  shell with `BAZEL_IO_TOKEN` and a write-all `GITHUB_TOKEN`. Always fetch and read every called
  composite action.
- **Implicit execution through build config (Flank).** `gh pr checkout` followed by
  `gradle/gradle-build-action`: Gradle evaluates `settings.gradle.kts` as Kotlin, so the checkout
  alone was code execution. Any build tool that reads repository config executes it (`Makefile`,
  `package.json` lifecycle scripts, `setup.py`, `build.gradle.kts`, `.cargo/config.toml`,
  `Gemfile`).
- **Self-hosted runner escalation (PyTorch).** A merged typo-fix made the attacker a
  "contributor", so later PRs ran without approval on a non-ephemeral self-hosted runner;
  `RUNNER_TRACKING_ID=0` kept a process alive across jobs and a second runner agent waited for
  privileged workflows to harvest PATs (Runner-on-Runner, with GitHub itself as the C2).
- **Tag repointing at scale (tj-actions/changed-files).** Every version tag moved to a commit that
  dumped runner memory; about 23K repositories were exposed and 218 confirmed secret leaks
  followed. SHA pinning was the only reliable defence.
- **Cache poisoning via an AI agent (Clinejection).** Prompt injection made a triage agent run
  `npm install` from an attacker commit in a default-branch context; a self-perpetuating payload
  (Cacheract) entered the npm cache; the nightly publish workflow restored it and leaked
  `VSCE_PAT`, `OVSX_PAT` and `NPM_RELEASE_TOKEN`.

Talks and series: DEF CON 32 "Grand Theft Actions" (Khan & Stawinski, self-hosted runner bugs);
Synacktiv's GitHub Actions exploitation series.
