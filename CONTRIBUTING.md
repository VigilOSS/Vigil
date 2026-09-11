# Contributing to Vigil

Vigil is production offensive-security tooling. Contributions must preserve precision, deep
coverage, explicit authorization, and trustworthy evidence.

## Before opening a change

1. Read `AGENTS.md` and `CODE-MAP.md`.
2. Open an issue for substantial behavior or architecture changes so the contract can be agreed
   before implementation.
3. Never commit customer data, real engagement output, credentials, private target corpora, or
   target-specific exploit material.
4. Use Jujutsu in this colocated repository; do not create commits or branches with raw Git.

For a public clone, initialize Jujutsu's colocated metadata before making changes:

```bash
git clone https://github.com/vigil-oss/vigil.git
cd vigil
jj git init --colocate
```

Git remains available for read-only inspection, but use `jj` for commits, bookmarks, conflict
resolution, and pushes so the colocated repositories stay synchronized.

## Development and verification

Use the setup and complete verification matrix in `AGENTS.md`. New Python behavior and bug fixes
require a focused failing regression before production changes, followed by the impacted suites.
Prompt changes require regeneration and direct diff review; do not add tests that pin Markdown
wording.

Keep each change coherent, update every contract registration/sync point, and update `CODE-MAP.md`
when ownership or a stable entrypoint changes. Do not weaken tests, hide failures, add speculative
compatibility shims, or mask operator-visible engagement data.

## Pull requests

Describe the operator-visible outcome, why it matters, validation performed, migrations or
compatibility effects, and any remaining limitations. A pull request must pass every blocking CI
gate and resolve review threads with evidence before merge.

By contributing, you agree that your contribution is licensed under Apache License 2.0.
