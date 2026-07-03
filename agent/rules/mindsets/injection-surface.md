# Injection Surface — Mindset

This is a generative lens for the injection family (SQLi, XXE, SSTI, command injection, NoSQLi,
LDAP, and their kin) — it shapes *where you look and how you decide a value is a candidate*, not
*how you send the payload*. Detection technique order (error-based → time-based → OOB →
boolean-based) is `vulnerability-analyst.md`'s Injection Detection Cascade; payload/bypass detail
lives in the vuln-class skill (`sqli-testing`, `ssti-testing`, `nosql-injection`, etc.). This file
is upstream of both: it generates the candidate list they then work.

## 1. Every parsed value is a candidate

Any input a downstream interpreter parses — SQL engine, XML/YAML parser, template engine, shell,
NoSQL query builder, LDAP filter, regex engine, serializer — is an injection candidate, regardless
of field name or apparent type. A `quantity` field that gets string-concatenated into a query is as
live a candidate as a `search` box. Enumerate every value that crosses into an interpreter, not
just the ones that read like queries.

## 2. Trust the boundary, not the field name

Ask "what interpreter consumes this value, and where?" — not "what does the label suggest?" A
UUID, a filename, an integer-looking string, a header, a cookie: each is only as safe as the
interpreter it eventually reaches. The field name is the developer's intent; the trust boundary is
the actual attack surface, and they routinely disagree.

## 3. Second-order — test where the value is *consumed*, not *submitted*

Injected content often lands inert at submission and detonates later, in a different context: a
profile field rendered by an admin dashboard, a filename read by a batch processor, a support
ticket parsed by an internal tool, a stored search query re-executed by a scheduled job. Trace the
value forward to every place it is read, rendered, or re-parsed — not just the endpoint that
accepted it.

## 4. Structured-format smuggling

When one parser hands a value to another (JSON body → XML deserializer, YAML → template engine,
CSV cell → spreadsheet formula, multipart field → LDAP filter), the outer format treats the
smuggled payload as an opaque string and never inspects it. Look for format-within-format
boundaries — that seam is where a payload rides through a filter that only understands the outer
shape.

## 5. Encoding mismatch

The layer that filters (WAF, block-list, regex) and the layer that decodes/normalizes (app,
interpreter) are often different code paths at different times. Double URL-encoding, Unicode
normalization after the check, mixed-case keywords, alternate charset representations — these
survive a filter tuned to the canonical payload because the interpreter's decode step runs later
than the filter's inspection.

## 6. Blind-until-disproven

Absence of reflected output or an error is not a verdict — it is the default state you must
actively disprove. Assume every candidate is blind until you either observe visible signal or
prove the value never reaches an interpreter (parameterized query, escaped output, dead code path,
literal storage). OOB and timing probes are how you disprove blind, not a fallback you reach only
after visible checks fail.

---

This is a lens, not a checklist; the sibling, variant, and adjacent class is still yours to find.
