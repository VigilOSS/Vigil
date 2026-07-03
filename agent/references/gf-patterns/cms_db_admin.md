---
name: gf-patterns:cms_db_admin
description: CMS and database admin-panel path patterns (Joomla, Umbraco, Sitecore, TYPO3, Ghost, phpMyAdmin, Adminer, Tomcat Manager) the /admin boundary matcher misses
origin: local overlay (no upstream gf equivalent)
bucket: cms_db_admin
weight: 35
---

# gf: cms_db_admin

## What this bucket classifies

CMS back-office consoles and database administration panels exposed on web paths:
Joomla (`/administrator`), Umbraco, Sitecore, TYPO3, Ghost, phpMyAdmin
(`/phpmyadmin`, `/pma`), Adminer (`/adminer`, `/adminer.php`), generic DB admin
(`/dbadmin`), the Apache Tomcat Manager (`/manager/html`), and the
`/admin-console` / `/wp-admin` consoles. These are management surfaces where an
attacker can exploit default/weak credentials, auth bypass, forced browsing, or
post-auth deploy-to-RCE. This bucket closes Issue 3: the `/admin` boundary matcher
only fires on a literal `/admin` segment, so hyphenated and product-specific
consoles (`/wp-admin` carries `-admin`, not `/admin`; `/administrator`,
`/admin-console`) slip through and score 0.

## Load this reference when

- The corpus contains CMS or DB-admin routes (`/administrator`, `/phpmyadmin`,
  `/adminer.php`, `/manager/html`, `/umbraco`, `/sitecore`, `/typo3`, `/ghost`,
  `/pma`, `/dbadmin`, `/admin-console`)
- Operator is checking for default-credential or auth-bypass entry into a CMS
  back office or a database administration tool
- A management/admin panel is suspected behind a non-default port or nonprod host
  and the path shape matches one of these products

## Parameter keys that match

(none — `cms_db_admin` is a path-only bucket)

Admin panels are identified by their route, not by a query parameter, so the key
set is empty (`frozenset()` in `classify_buckets.py`). A bare `admin` parameter
toggle is deliberately kept out of `debug_logic` and routed to
`privileged_action` instead, so it does not belong here either.

## Path patterns that match

CMS back-office consoles:
`/administrator` (Joomla), `/umbraco`, `/sitecore`, `/typo3`, `/ghost`,
`/admin-console`, `/wp-admin` (WordPress)

Database admin panels:
`/phpmyadmin`, `/pma` (phpMyAdmin), `/adminer`, `/adminer.php` (Adminer),
`/dbadmin` (generic DB admin)

Application-server manager:
`/manager/html` (Apache Tomcat Manager)

All fragments use boundary-anchored `fragment_in_path` semantics: the fragment
must terminate at a segment boundary, so `/administrator` matches
`/administrator/index.php` but NOT the content slug `/administration-guide`.

## Weight and priority interpretation

- Baseline priority score: 35
- Maps to canonical vuln class `auth-bypass` in
  `vuln_taxonomy.GF_BUCKET_TO_CLASS` (same class as `auth` and `idp_admin`), so
  the drift gate stays green and auth-bypass skills route automatically
- Declared AFTER `wordpress` (also weight 35): on the shared `/wp-admin`
  fragment, the first-at-max-weight tie-break gives the `gf:wordpress` cluster
  key, with `cms_db_admin` additively recorded in the reason chain
- Below specific vulnerability buckets (auth=40, graphql=45) — those dominate the
  cluster key when they co-fire; above `redirect` (25) and `debug_logic` (30)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

CMS back office:

- `https://target.example/administrator/index.php` — Joomla admin login
- `https://target.example/umbraco/` — Umbraco backoffice
- `https://target.example/typo3/index.php` — TYPO3 backend
- `https://target.example/admin-console/login` — generic admin console

Database admin panels:

- `https://target.example/phpmyadmin/` — phpMyAdmin DB console
- `https://target.example/adminer.php` — Adminer single-file DB client
- `https://target.example/pma/index.php` — phpMyAdmin alias
- `https://target.example/dbadmin/login` — generic DB admin panel

Application-server manager:

- `https://target.example/manager/html` — Apache Tomcat Manager (WAR deploy)

## What it does NOT classify

- `/wp-admin` — the fragment IS carried here, but the row CLUSTERS as
  `gf:wordpress` (declared first, first-at-max-weight tie-break); `cms_db_admin`
  appears only in the reason chain, never as the cluster key
- bare `/admin`, `/console`, `/dashboard`, `/manage` — owned by `debug_logic`
  (weight 30, `/admin` segment). This bucket only carries the hyphenated /
  product-specific consoles the `/admin` boundary matcher cannot reach
- `/administration-guide`, `/administrator-faq` (content slugs) — excluded by the
  boundary-anchored matcher: the fragment must end at a segment boundary, so
  `/administrator-guide` does NOT match `/administrator`
- bare `admin`/`grant`/`access` query-param toggles — routed to
  `privileged_action` / `debug_logic`, not here (this bucket is path-only)

## Attack classes

- **Default / weak admin credentials:** Joomla `/administrator`, Tomcat
  `/manager/html` (`tomcat:tomcat`, `admin:admin`), and CMS back offices ship
  with well-known defaults that survive into production
- **Unauthenticated DB console / SQL execution:** phpMyAdmin and Adminer panels
  exposed without auth grant direct database access; Adminer is also abusable for
  SSRF and credential theft via the server-connect form
- **Post-auth deploy-to-RCE:** Tomcat Manager `manager-gui`/`manager-script`
  roles allow WAR upload, turning admin access into remote code execution
- **CMS auth bypass / privilege escalation:** Umbraco, Sitecore, and TYPO3
  back-office auth-bypass and broken-access-control chains reach administrative
  configuration and template/code execution
- **Forced browsing / console enumeration:** discovering an `/admin-console` or
  product back office that was assumed hidden but is reachable unauthenticated

## Corpus grounding

Forward-looking coverage. Per the plan's Part 3 §A.3, the reference engagement
work buffer has approximately 0 hits for these CMS/DB-admin fragments today; the
bucket exists for cross-engagement recurrence — CMS and database admin panels are
ubiquitous enterprise surface, not artifacts of any one target. The bucket also
closes Issue 3: under the prior `/admin` boundary matcher, hyphenated and
product-specific consoles (`/wp-admin`, `/administrator`, `/admin-console`,
`/management`, `/manage-users`) missed the matcher and 63 of 67 such rows were
zero-priority. See `docs/plans/classify-context-and-surface-buckets-2026-06.md`
(Part 1 Issue 3, Part 3 §A.3).

## Sources

The plan cites no bucket-specific CVE for `cms_db_admin`; the authoritative
vendor and security references for the panels in scope are:

- [Joomla — Administrator security checklist](https://docs.joomla.org/Security_Checklist/Joomla!_Setup)
- [phpMyAdmin — Security documentation](https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation)
- [Adminer — Security](https://www.adminer.org/en/security/)
- [Apache Tomcat — Manager App HOW-TO (roles and credentials)](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html)
- [OWASP WSTG — Test for default and weak credentials / admin interfaces](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks — Pentesting CMS and admin panels](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web)

## Related

- `agent/references/gf-patterns/wordpress.md` — shares the `/wp-admin` fragment;
  `/wp-admin` clusters as `gf:wordpress` by the tie-break, this bucket co-fires
- `agent/references/gf-patterns/idp_admin.md` — sibling `auth-bypass` admin-surface
  bucket for IdP realm/admin consoles (Keycloak, PingFederate, ADFS)
- `agent/references/gf-patterns/auth.md` — auth-entry / credential-bearing surfaces
  (also canonical class `auth-bypass`)
- `agent/references/gf-patterns/debug_logic.md` — bare `/admin`, `/console`,
  `/manage` management segments (weight 30) that this bucket complements
