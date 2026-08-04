---
description: "Example: Bugcrowd submission for cross-tenant IDOR on an invoice PDF endpoint"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** IDOR in invoice PDF endpoint allows customers to read other tenants' invoices

**VRT:** Broken Access Control (BAC) > Insecure Direct Object References (IDOR) > View Sensitive Information(Iterable Object Identifiers)

**Severity:** MEDIUM

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)

---

### Summary

A customer of the billing platform reads any other tenant's invoice PDF by changing the numeric ID in the download URL. `GET /api/v2/invoices/{invoice_id}/pdf` checks only that the caller holds a valid session, not that `invoice_id` belongs to the caller's tenant. I found the ID space is sequential across the whole platform, not per-tenant, while diffing two invoice URLs pulled from the same account minutes apart. The PoC below fetches an invoice ID one below the attacker's own range and returns a second tenant's billing data.

### Steps to Reproduce

1. [attacker] Log in as a normal customer (Tenant A) and open any invoice to capture its ID, e.g. `41207`.
2. [attacker] Request the tenant's own invoice, to fix the baseline response shape:
```
curl -s -D - -H "Authorization: Bearer $TENANT_A_TOKEN" \
  https://billing.example.com/api/v2/invoices/41207/pdf -o own-invoice.pdf
```
**Expect:** 200, Tenant A's own invoice.
3. [attacker] Request an adjacent ID outside the sequence the UI ever shows Tenant A:
```
curl -s -D - -H "Authorization: Bearer $TENANT_A_TOKEN" \
  https://billing.example.com/api/v2/invoices/41198/pdf -o other-invoice.pdf
```
**Expect:** 200, but `other-invoice.pdf` is a different company's invoice — Tenant A never had access to this account.

### Evidence

**Cross-tenant read.** Step 3's downloaded PDF, rendered to text:
```
$ pdftotext other-invoice.pdf - | head -5
Northwind Fixtures LLC                                           <-- not Tenant A's company
Invoice #41198  —  Due 2026-06-30
Bill To: accounts@northwindfixtures.example
Line 1: Annual platform license — $18,400.00                    <-- proof of cross-tenant read
Line 2: Overage — API calls (Q2)  — $2,150.00
```

**Identifier enumerability.** Tenant A's own invoice is `41207`; `41198` belongs to another company. The IDs are sequential integers from one platform-wide range, not a per-tenant sequence. An attacker walks the range rather than guessing it.

**Minimum privilege.** Both requests used an ordinary paid customer session. No admin, billing-manager, or support permission was held or needed.

### Attack Scenario

A competitor or disgruntled customer works from an ordinary paid account with no elevated role. They enumerate the invoice ID space sequentially from their own known IDs. Each request for an ID outside their own range returns another tenant's invoice PDF with company name, billing contact, and full line-item pricing.

### Impact

Every tenant's billing data (contact details and negotiated line-item pricing) is readable across the platform. The ID space is sequential and unsalted, so exposure isn't limited to adjacent accounts: it covers the full customer base in one enumerable range.

### Remediation

Scope the invoice lookup by tenant ID in the query. Add a `WHERE tenant_id = :caller_tenant_id` check, or an equivalent ownership check in the invoice service, before the PDF is generated, not after. Switch the invoice identifier to a per-tenant opaque token or UUID as defense-in-depth, so an ownership-check regression can't reopen an enumerable ID space.
