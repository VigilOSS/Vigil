# <CUSTOMER> — Generic Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `aith blue tenant init --customer <slug> --platform generic`,
> which writes to `agent/references/tenants/<slug>-generic.md`.
>
> Before this file is loaded into a real engagement:
>
> 1. Replace every `<PLACEHOLDER>` (search for `<`).
> 2. Populate the "Known benign patterns" register.
> 3. Document which consoles and CLIs are approved for read-only IR pulls.

Operator context for alert investigations on a tenant or platform that does
not yet have a dedicated template. Use this to capture the minimum facts that
L1, L2, L3, and L4 need without inventing platform-specific command shapes.

---

## Tenant Identity

| Field | Value |
|---|---|
| Organization name | `<CUSTOMER>` |
| Primary platform / product | `<platform-name>` |
| Tenant / account id | `<tenant-id>` |
| Primary domains | `<domains>` |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

---

## Tool Configuration

| Tool / console | Access path | Auth principal | Notes |
|---|---|---|---|
| `<console-or-cli>` | `<url-or-command>` | `<principal>` | `<read-only scope / retention / limits>` |

Every tenant-facing command must run through `aith assess host-exec` with
`--tool`, `--intent`, `--technique`, and `--phase`. Do not paste API keys,
tokens, secrets, or raw credential material into this file.

---

## Scope Reality

| Capability | Status | Notes |
|---|---|---|
| Read alerts | `<verified / not assigned>` | `<which API/table>` |
| Read audit events | `<verified / not assigned>` | `<retention>` |
| Read identity / asset context | `<verified / not assigned>` | `<source of truth>` |
| Execute containment writes | `not granted by default` | Propose through L4; operator executes approved action separately. |

---

## Known Benign Patterns

| Pattern id | Condition | Evidence | Last reviewed |
|---|---|---|---|
| `<pattern-id>` | `<specific condition>` | `<artifact / ticket / owner>` | `<YYYY-MM-DD>` |

---

## Escalation Contacts

| Role | Contact | Hours | Notes |
|---|---|---|---|
| Incident commander | `<name / alias>` | `<coverage>` | `<handoff channel>` |
| Platform owner | `<name / alias>` | `<coverage>` | `<approval path>` |

---

## Change Log

| Date | Change | Owner |
|---|---|---|
| `<YYYY-MM-DD>` | `<tenant-ref initialized>` | `<operator>` |
