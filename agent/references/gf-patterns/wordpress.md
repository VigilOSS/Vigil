---
name: gf-patterns:wordpress
description: WordPress surface patterns (REST user/media enumeration, XML-RPC pingback, login/admin, debug log)
origin: local overlay (no upstream gf equivalent; added in the classify-context-and-surface 2026-06 expansion)
bucket: wordpress
weight: 35
---

# gf: wordpress

## What this bucket classifies

WordPress surfaces that the generic `/admin` boundary matcher and the URL typer miss today
(Issue 3): the REST API user/media enumeration endpoints (`/wp-json`, `/wp-json/wp/v2/users`),
the XML-RPC entry point used for pingback SSRF and `system.multicall` brute-force amplification
(`/xmlrpc.php`), the WP-Cron trigger (`/wp-cron.php`), the writable debug log
(`/wp-content/debug.log`), and the login / admin consoles (`/wp-login.php`, `/wp-admin`).
The canonical vuln class is `user-enumeration` — the headline WordPress weakness is that the
unauthenticated REST users endpoint and the `?author=<n>` redirect both leak the site's account
roster, which seeds credential-stuffing and targeted brute-force against `/wp-login.php`.

## Load this reference when

- The corpus contains `/wp-json`, `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`, `/wp-cron.php`,
  or `/wp-content/debug.log` paths
- Param keys `author` (especially with a numeric value) or `rest_route` appear in query strings
- Operator is checking a WordPress install for unauthenticated user enumeration, XML-RPC
  pingback SSRF / brute amplification, or an exposed admin/login surface

## Parameter keys that match

`author, rest_route`

`author` is the classic user-enumeration vector — `?author=1` redirects to `/author/<username>/`,
disclosing the login slug. `rest_route` is the non-pretty-permalink form of a REST route
(`?rest_route=/wp/v2/users`), so it reaches the same enumeration surface as the path form.

## Path patterns that match

`/wp-json`, `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`, `/wp-cron.php`,
`/wp-content/debug.log`, `/wp-json/wp/v2/users`

All fragments are boundary-anchored by `fragment_in_path()` (literal match via `re.escape()`).
Note `/wp-admin` carries the `-admin` token, NOT a clean `/admin` segment, so the `debug_logic`
bucket's `/admin` boundary matcher never fires on it — this bucket is the only one that catches
`/wp-admin`. Likewise `/wp-login.php` has `-login`, not a `/login` segment, so the `auth` bucket's
`/login` fragment does not match it (the URL typer's lexical auth rescue, typer Fix #15b, is what
routes the extensioned `wp-login.php` page to `auth_entry`).

## Weight and priority interpretation

- Baseline priority score: 35
- Below the specific vulnerability buckets (secret_vault=45, graphql=45, ssrf=40, auth=40,
  deserialization=40, dotnet_handler=40) — when one of those co-fires (e.g. a WordPress endpoint
  that also carries a `?url=` SSRF param), the higher-weight bucket owns `cluster_key` /
  `priority_score` and `wordpress` is recorded additively in the `+`-joined reason chain
- Declared in `_BUCKETS` immediately BEFORE `cms_db_admin` (both weight 35): on a row that
  matches the shared `/wp-admin` fragment, the first-at-max-weight tie-break keeps the cluster as
  `gf:wordpress`, with `cms_db_admin` recorded in the reason chain
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

REST API enumeration:

- `https://target.example/wp-json/wp/v2/users` — unauthenticated user roster (login slugs + IDs)
- `https://target.example/?rest_route=/wp/v2/users` — same surface via the non-pretty REST route
- `https://target.example/wp-json/wp/v2/media` — media object enumeration under `/wp-json`

Author / login / admin:

- `https://target.example/?author=1` — author-ID redirect that discloses the username slug
- `https://target.example/wp-login.php` — login console (credential brute target)
- `https://target.example/wp-admin/` — admin dashboard surface

XML-RPC, cron, and debug:

- `https://target.example/xmlrpc.php` — pingback SSRF + `system.multicall` brute amplification
- `https://target.example/wp-cron.php` — unauthenticated cron trigger (DoS / task abuse)
- `https://target.example/wp-content/debug.log` — exposed `WP_DEBUG_LOG` (paths, queries, secrets)

## What it does NOT classify

- A generic `?author=<freetext>` byline on a non-WordPress CMS — the bucket is keyed on the
  WordPress-specific path/param shapes; an `author` param without a WordPress route is weak signal
- DB / CMS admin panels of OTHER products (`/administrator`, `/phpmyadmin`, `/umbraco`,
  `/manager/html`, etc.) — those belong to `cms_db_admin`
- The OAuth/OIDC or SAML flow endpoints a WordPress SSO plugin may expose — those are owned by
  `oauth-oidc` / `sso`, which model the flow rather than the WordPress surface

## Attack classes

- **REST user enumeration:** `GET /wp-json/wp/v2/users` (or `?rest_route=/wp/v2/users`) returns the
  account roster — usernames, display names, and IDs — to an unauthenticated client, seeding
  targeted credential stuffing and brute-force
- **Author-ID enumeration:** `?author=<n>` redirects to `/author/<slug>/`, disclosing the login
  slug even when the REST endpoint is locked down
- **XML-RPC pingback SSRF:** `pingback.ping` against `/xmlrpc.php` coerces the server into fetching
  an attacker-supplied URL (internal-network / metadata SSRF), and `system.multicall` collapses
  thousands of `wp.getUsersBlogs` login attempts into one request for brute-force amplification
- **Login / admin brute force:** `/wp-login.php` and `/wp-admin` are the password-spray and
  session-hijack targets the enumerated roster feeds into
- **Debug-log disclosure:** a world-readable `/wp-content/debug.log` (left enabled via
  `WP_DEBUG_LOG`) leaks absolute paths, SQL, and occasionally credentials/tokens

## Corpus grounding

(mostly incidental — unscored before this bucket landed), and `/wp-login.php` = 0 (it typed `page`
and scored 0 because it carries `-login`, not a `/login` segment). The remaining fragments
(`/xmlrpc.php`, `/wp-cron.php`, `/wp-content/debug.log`, `/wp-json/wp/v2/users`, `/wp-admin`) are
forward-looking coverage: WordPress is a ubiquitous CMS, so these are sized for recurrence across
future engagements rather than the immediate corpus. See ADR 0008, `DRIFT.md`, and the `wordpress`
`_BUCKETS` comment in `agent/scripts/assess/lib/classify_buckets.py`.

## Sources

- [WordPress REST API Handbook — Users endpoint](https://developer.wordpress.org/rest-api/reference/users/)
- [CVE-2017-5487 — WordPress < 4.7.1 REST API user enumeration via `/wp-json/wp/v2/users`](https://nvd.nist.gov/vuln/detail/CVE-2017-5487)
- [WordPress — XML-RPC and pingback abuse (SSRF / `system.multicall` brute amplification)](https://developer.wordpress.org/apis/xml-rpc/)
- [OWASP WSTG — Testing for Account Enumeration and Guessable User Account](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)

## Related

- `agent/references/gf-patterns/cms_db_admin.md` — sibling CMS/DB admin-panel bucket (same weight; `/wp-admin` co-fires)
- `agent/references/gf-patterns/auth.md` — login/credential surface the enumerated roster feeds into
- `agent/references/gf-patterns/ssrf.md` — XML-RPC pingback SSRF reaches the SSRF specialist
- `agent/references/gf-patterns/debug_logic.md` — `/wp-content/debug.log` and admin-surface debug exposure
- `agent/references/gf-patterns/idor.md` — object-reference enumeration that overlaps user/media enumeration
