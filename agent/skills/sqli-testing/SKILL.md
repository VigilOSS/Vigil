---
name: sqli-testing
description: Detect and exploit SQL injection vulnerabilities in web application parameters
origin: Vigil
vuln_class: sqli
---

# SQL Injection Testing

## When to Activate

- A parameter reaches a query: search, login, filter/sort controls, ID lookups, API fields that
  drive WHERE/ORDER BY/LIKE, bulk operations with `IN(...)`, and any parameter that changes the
  response's shape (column count, ordering, presence).
- Errors leak the backend (`You have an error in your SQL syntax`, `PSQLException`, `ORA-`,
  `SQLITE_ERROR`, `Unclosed quotation mark`); a numeric parameter accepts arithmetic
  (`?id=2-1` behaves like `?id=1`); JSON/GraphQL values feed queries (ORMs often parameterize
  scalars but pass objects and arrays unsafely).

`--technique SQLI`. Manual probes via `vigil assess kali exec … -- curl …`; exploitation depth
via the typed `vigil assess kali sqlmap` verb (`--sql-technique` selects BEUSTQ; when sqlmap
misses or invents an injection: `agent/references/tools/exploitation/sqlmap.md` "When sqlmap
lies"; its tuning section has the rate-limit controls and the blind-extraction time estimate).
DBMS fingerprinting, OOB extraction, the SQLite time oracle, LDAP/XPath probes, and the per-database
privilege gates for file read/write and OS commands ("File and OS Access — Privilege Gates"; load it before
any file or OS step): `agent/references/payloads/sqli-payloads.md`. WAF-specific SQLi shapes:
`agent/references/web/waf-bypass-and-safe-testing.md` §E (load when a WAF blocks payloads).
Seed variants with `vigil assess classify-payload <value> --mutations`; rank a boolean sweep with
`vigil assess anomaly-score <file> --top N`.

## Where SQLi lives in ORM-backed apps

An ORM narrows the surface; it does not close it. Test the gaps it cannot parameterize, and run
the blind channels before calling a parameter clean:

- **Identifiers:** dynamic column/table names and **ORDER BY / GROUP BY** (the most common modern
  SaaS SQLi; identifiers cannot be bound). `?sort=created_at,(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)`
  vs `1=2`. Usually blind: pivot to conditional-error or time extraction. GraphQL enum arguments
  for sort/filter are often mapped straight to column names.
- **Escape hatches:** Rails `connection.execute`, Django `raw()`, Sequelize `sequelize.query()`,
  Prisma `$queryRaw`/`$executeRaw`.
- **JSON/JSONB path keys:** `where("data->>'#{key}' = ?", value)` binds the value, not the key.
- **Bulk `IN(...)` built by string join:** `{"ids": [1, "2 OR 1=1"]}`.
- **Stored procedures** that build dynamic SQL internally.
- **Second-order:** a value stored safely (registration `company_name`) is concatenated later by
  a different team's admin report, export or audit query. Store a quote or a time-based payload,
  then trigger every admin-facing consumer.
- **JSON endpoints** often use a different code path (a query builder) from the form endpoint;
  test nested objects too.
- **LIKE wildcards:** `%`/`_` in a search can return every record (data exposure, total counts)
  even when the string is bound.

## Blind channels

- **Time:** measure the baseline first. The delay must exceed 3× the jitter's standard deviation
  (SLEEP(5) minimum); above ~2 s jitter, time-based is unusable on this target. Confirm with the
  conditional pair (`IF(1=1,SLEEP(N),0)` delays, `IF(1=2,…)` does not), three runs each, never one
  delayed response.
- **OOB** (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure
  (mint→poll→correlate)"): put the version in the left label so the hit carries data, and
  reproduce with a second payload shape. Prerequisites: MySQL `LOAD_FILE` UNC paths work only on
  Windows hosts and need FILE privilege with `secure_file_priv` unset; MSSQL `xp_dirtree` works on
  most default installs; PostgreSQL `COPY … TO PROGRAM` needs superuser or
  `pg_execute_server_program`.
- **Managed databases** (RDS, Aurora, Azure SQL, Cloud SQL) block file read/write and OS
  commands: the realistic critical path is data extraction → credentials in application tables →
  lateral movement.
- **Cross-database reach** sizes the impact: after a confirmed differential, list co-hosted
  schemas (`information_schema.schemata`, `master..sysdatabases`). A shared multi-tenant database
  reached from one tenant's injection is a tenant-isolation breach (Critical); PII or credentials
  are High; non-sensitive data is Medium.

## Recording a partial extraction

A reproduced boolean, time or OOB differential is a real finding even when extraction is
unfinished (rate-limited, slow, partial). Record it yourself with
`vigil assess finding record <your-role> <file> --pending-runtime-proof "<what is proven, what is
left>" --next-test-file <next-test.json>` naming the byte-by-byte extraction as the next test,
rather than closing the parameter as clean; blind injection is the class most often lost to
premature abandonment (`agent/skills/finding-verification/SKILL.md`). Format:
`agent/references/runtime-guides/web-finding-recording.md`; severity:
`agent/references/finding-fp-and-severity-gate.md`.

## Kill and escalate

- Identical responses to error probes with no timing delta make parameterization likely, not
  proven: a negative needs the measured time pass, a boolean-differential pass and OOB when
  available (`agent/rules/hunting.md` §12, §13).
- A WAF blocks every payload and no other context (JSON body, headers, ORDER BY) exists → report
  it to the operator as a blocked surface; do not drop it.
- Escalate when: an invalid payload returns the same body as a valid one (errors swallowed; blind
  channels still live); timing drifts beyond the measured jitter; different encodings of one
  character behave differently (parser disagreement); an OOB hit arrives (reproduce with a second
  shape, then file read or `xp_cmdshell` where the DBMS allows, with approval); a generic 500 leaks
  a driver, version or table name.
