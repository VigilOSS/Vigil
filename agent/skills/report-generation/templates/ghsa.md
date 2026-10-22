---
description: "GitHub private advisory form metadata and recipient-specific body capture"
skill: report-generation
category: Disclosure & Reporting Formats
---

# GitHub Private Advisory

Use `export submission <slug> --platform ghsa`. Record structured form metadata in `details.ghsa`:

```json
{
  "ecosystem": "Composer",
  "package_name": "acme/example",
  "affected_versions": "< 2.0.1",
  "patched_versions": "2.0.1",
  "cwe_ids": ["CWE-639"],
  "vulnerable_functions": ["Acme.authorize"],
  "request_cve": false
}
```

Ecosystem, package name, affected versions, and an explicit CVE-request choice are required. Record
unknown patched versions as unknown; never invent a fix or version range. Credits are maintainer-owned.
The renderer emits a form field block and captures the metadata in the submission context. With an
operator-authored `--body`, use the structured context for the form fields and the captured body for
the advisory description. Do not assume the initial private-report form offers attachment upload;
select external attachments only when the chosen delivery workflow supports them.

Read the selected recipient's reporting policy. When it requests a different section shape or a short
reproducer, author that body from canonical verified claims and use `--body` and `--guidance` as
specified in `agent/references/submission-format.md` "Recipient-specific outgoing body". The guidance
is presentation data; evidence, independent review, and exact-byte publication checks still apply.
Do not request a CVE if the operator-selected recipient policy instructs the researcher not to do so.
