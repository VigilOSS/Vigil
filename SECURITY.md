# Security policy

## Authorized use

Vigil is offensive-security and incident-response tooling. Use it only on systems and accounts you
own or are explicitly authorized to assess. You are responsible for engagement scope, rules of
engagement, legal review, operator credentials, and the effects of commands launched through Vigil.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that would expose users, credentials, private
engagement data, or a working exploit before remediation.

Report security issues privately through GitHub's private vulnerability reporting feature for this
repository. Include the affected revision, impact, reproduction steps, and any suggested mitigation.
If private reporting is unavailable, open a minimal issue asking the maintainer to establish a
private channel; do not include exploit details in that issue.

The maintainer will acknowledge a complete report, validate it against the current supported
revision, and coordinate disclosure after a fix is available. No response-time or bounty commitment
is implied.

## Supported versions

Until tagged public releases are available, only the current default branch is supported. Historical
commits, private forks, modified runtime images, and third-party distributions are not covered by
this policy.

## Operator-data boundary

Vigil intentionally renders the authorized operator's credentials and evidence verbatim on that
operator's machine. This is documented in ADR 0019 and is not a vulnerability by itself. Reports
remain welcome for actual cross-user exposure, unintended external transmission, scope/ROE bypass,
benchmark answer-key leakage, or evidence/proof-integrity failures.
