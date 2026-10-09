# Security policy

## Authorized use

Vigil is offensive-security and incident-response tooling. Use it only on systems and accounts you
own or are explicitly authorized to assess. You are responsible for engagement scope, rules of
engagement, legal review, operator credentials, and the effects of commands launched through Vigil.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that would expose users, credentials, private
engagement data, or a working exploit before remediation.

Report security issues privately through
[GitHub private vulnerability reporting](https://github.com/vigil-oss/vigil/security/advisories/new)
for this repository. Include the affected revision, impact, reproduction steps, and any suggested
mitigation.

If that form is temporarily unavailable, retry it later rather than disclosing the issue publicly.
Public issues are not a fallback: blank issues are disabled and both issue
templates are for non-sensitive defects and feature requests, so there is no way to file a minimal
security placeholder there. Do not put exploit details in any public issue.

The advisory form is for vulnerabilities only — it opens a draft security advisory, which is the
wrong artifact for anything else. Follow the private contact instructions in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md#enforcement) for conduct reports instead.

The maintainer will acknowledge a complete report, validate it against a supported version, and
coordinate disclosure after a fix is available. No response-time or bounty commitment is implied.

## Supported versions

Security fixes are made against the latest released version and the default branch. Older releases,
historical commits, forks, modified runtime images, and third-party distributions are not covered by
this policy. If you are running something other than the latest release, upgrade before reporting.

## Operator-data boundary

Vigil intentionally renders the authorized operator's credentials and evidence verbatim on that
operator's machine. This is documented in
[ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md) and is not a
vulnerability by itself. Reports remain welcome for actual cross-user exposure, unintended external
transmission, scope/ROE bypass, or evidence/proof-integrity failures.
