# Contributing to Vigil

Vigil is production offensive-security tooling. Contributions must preserve precision, deep
coverage, explicit authorization, and trustworthy evidence.

Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md). Security vulnerabilities go
through [SECURITY.md](SECURITY.md#reporting-a-vulnerability), never a pull request or public issue.

## Before opening a change

1. Read `AGENTS.md` and `CODE-MAP.md`.
2. Open an issue for substantial behavior or architecture changes so the contract can be agreed
   before implementation. `.github/ISSUE_TEMPLATE/` has a bug-report and a feature-request form;
   blank issues are disabled.
3. Never commit customer data, real engagement output, credentials, private target corpora, or
   target-specific exploit material.

## Version control

Fork the repository and work in your fork with whatever tooling you prefer — plain Git is fine, and
your pull request arrives as Git commits either way:

```bash
git clone https://github.com/<your-username>/vigil.git
cd vigil
```

This repository itself is a colocated Jujutsu repository. If you work in a checkout that has a
`.jj/` directory — a maintainer clone, or your own fork after `jj git init --colocate` — use `jj`
for commits, bookmarks, conflict resolution, and pushes, and keep Git for read-only inspection.
Mixing raw `git commit` into a colocated checkout desynchronizes the two repositories.

There is no commit-message convention. Write a message that says what changed and why.

## Development and verification

Use the setup and complete verification matrix in `AGENTS.md`.

New Python behavior and bug fixes start with a focused failing regression: write a test that fails
against the current tree for the exact reason you are about to fix, watch it fail, then make the
production change and watch it pass. Run the impacted suites afterwards. A change that arrives with
no test that would have caught the defect is not finished.

Prompt changes require regeneration and direct diff review; do not add tests that pin Markdown
wording.

Code style is `ruff` with `select = ["E4", "E7", "E9", "F"]` (see `pyproject.toml`) — correctness
rules only. There is no formatter and no broader style gate; match the surrounding code.

Keep each change coherent, update every contract registration/sync point, and update `CODE-MAP.md`
when ownership or a stable entrypoint changes. Do not weaken tests, hide failures, add speculative
compatibility shims, or mask operator-visible engagement data.

## Pull requests

Describe the operator-visible outcome, why it matters, validation performed, migrations or
compatibility effects, and any remaining limitations. A pull request must pass every blocking CI
gate and resolve review threads with evidence before merge.

There is no CLA and no DCO sign-off requirement. By contributing, you agree that your contribution
is licensed under [Apache License 2.0](LICENSE).
