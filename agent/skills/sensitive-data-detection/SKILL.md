---
name: sensitive-data-detection
description: Detect PII, credentials, and corporate sensitive data in API responses, source code, files, headers, and database extracts
origin: Vigil
vuln_class: secrets-exposure, source-disclosure
---

# Sensitive Data Detection

## When to Activate

- API responses carry user objects or more fields than the UI uses; source or config files may
  hold hardcoded data; downloaded files (CSV, SQL dumps, backups, logs) or SQLi extraction output
  need classifying; headers or cookies carry encoded data.

Classification runs on the local copy of captured data, not as target traffic. One response or
bundle belongs here; hundreds of stored bodies go through `agent/skills/gau-triage/SKILL.md`.

## Method

1. **Secrets first:** `trufflehog` (800+ detectors, verification; `agent/references/tools/recon/trufflehog.md`)
   beats hand regex for keys, tokens, connection strings and webhooks.
2. **Typed PII and infrastructure identifiers:** the regex catalogue in
   `agent/references/payloads/pii-regex-catalogue.md` (national IDs, financial, contact,
   infrastructure, medical); load it when classifying a corpus by data type. Broad patterns are
   candidates until context and a check digit confirm them.
3. **JSON responses:** scan key paths rather than values; it is faster and catches fields the
   UI never shows:
   `jq -r '[paths(scalars)] | .[] | join(".")' resp.json | rg -i 'ssn|national.?id|passport|card|cvv|iban|password|secret|token|hash|salt|phone|email|birth|dob|salary|address|diagnosis|biometric|employee.?id|latitude|ip.?addr'`
4. **Headers and cookies:** base64/URL-decode cookie and custom-header values (`x-user`,
   `x-account`, `x-debug`, `x-internal`).
5. **Files and dumps:** classify by structure before rows (CSV header, `CREATE TABLE` columns,
   JSON key paths, XML element names); triage hash shapes (32/64-hex, `$2[aby]$` bcrypt) to say
   what was exposed.
6. **Cards:** Luhn-validate before claiming card exposure; an invalid number is test data.

Priority when several types appear: credentials and keys, Luhn-valid financial data, identity
documents, infrastructure details, medical/biometric data, bulk contact data, individual fields.

## Recording

- Evidence keeps the detected values verbatim (ADR 0019; `agent/shared-constraints.md`
  "Credentials and Local State Are Self-Owned"); one minimal sample proves exposure
  (`agent/rules/hunting.md` §10).
- Emails → `vigil assess intel record email`; people and roles → `intel record person`; internal
  IPs/domains → `intel record domain` (with the right `kind`); credentials →
  `vigil assess post credentials <file>` (the assessment credential store, not intel); exposure
  of other users' data → `vigil assess finding record`, severity per
  `agent/references/finding-fp-and-severity-gate.md` (internal IPs alone are informational).
- Weak randomness, hashing or key management seen in the data go to the owning class
  (auth-bypass for session/reset tokens, jwt-testing for signing keys). The checks worth naming:
  exposed key material (paths in `agent/references/payloads/info-disclosure-probes.md`), old or
  rotated keys still accepted, one key used for both signing and encryption, and an exposed
  bcrypt hash whose cost factor is below 12.
