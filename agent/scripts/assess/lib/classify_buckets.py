"""Shared gf-style bucket classification used by both ingestion and re-runs.

This module is the single source of truth for the priority/cluster assignments
that the ingest producers compute inline (into the work_item block the backend
derives) and that `vigil assess work-buffer reclassify` re-applies idempotently. Keeping the logic in one
place ensures the two paths cannot drift — operators forgetting to run
`work-buffer reclassify` after an ingest used to leave the work buffer unscored, which
broke priority-mode dispatch silently.

Design notes:
- Bucket weights only control triage ordering, not skip/include. Adding a
  marginal bucket at low weight (~10-15) is therefore strictly better than
  letting the URL drown in a `path:<seg1>/<seg2>` cluster — the URL still
  surfaces in `gf:*` clusters and gets specialist attention proportional to
  its weight.
- The Python `_BUCKETS` is authoritative. `agent/references/gf-patterns/DRIFT.md`
  records accepted and rejected GF category decisions so future reviewers can
  see why a bucket exists here or intentionally belongs to another pipeline.
- Adversarial-mindset alignment (per `agent/rules/adversarial-mindset.md`):
  trust-delegation surfaces (uploads, webhooks, password-reset, OAuth callback,
  exports, imports) score high enough on their own to guarantee specialist
  attention, even when no obviously vulnerable parameter is present.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from . import vuln_taxonomy
from .dependency_manifests import url_path_fragments


# gf-style bucket weights. Higher = more likely to yield exploitable signal.
# Each tuple is (name, weight, parameter-key set, path-fragment tuple). A
# parameter-key hit OR a path-fragment hit puts the row in the bucket. When
# multiple buckets fire, the highest-weight normally wins for `cluster_key` /
# `priority_score`; every match is recorded in `priority_reason` as a `+`
# joined chain so operators can see the full classification trail.
#
# Regex buckets (override #1): `fragment_in_path()` matches a literal fragment
# via `re.escape()`, so a regex pattern can NEVER be a literal `path_fragments`
# entry. Override #1 authorizes either a 5th tuple field OR a separate rule list.
# We use the separate `_REGEX_BUCKET_RULES` list (keyed by bucket name) so the
# `_BUCKETS` tuples stay a 4-element shape — a 5th field would break the
# 4-tuple unpacks in `_IDOR_WEIGHT` / `_INTERESTINGEXT_WEIGHT` and in the
# `test_vuln_taxonomy.py` drift check (`for name, _w, _k, _p in _BUCKETS`).
# `bucket_matches` keeps a SINGLE declaration-ordered iteration over `_BUCKETS`
# and consults `_REGEX_BUCKET_RULES.get(name)` on the same pass, so tie-break
# order (first bucket at max weight) and reason-chain order (declaration order)
# remain defined by the one `_BUCKETS` list. A regex bucket still gets a real
# `_BUCKETS` entry (empty key set + empty literal fragments) so it is visible to
# `GF_BUCKET_TO_CLASS` and the bucket iteration; its only match signal is the
# regex rule.
_BUCKETS: tuple[tuple[str, int, frozenset[str], tuple[str, ...]], ...] = (
    (
        "rce",
        # Param set widened (classify-context-and-surface 2026-06, Part 6): add the
        # upstream command-exec params our 6-key set lacked — `ping`,`exe`,`func`,
        # `function`,`cli`,`daemon`. DELIBERATELY NOT `code`: rce(50) outranks
        # oauth-oidc(35), so a bare `?code=` OAuth callback would mis-cluster as
        # `gf:rce`. `query`/`load`/`read`/`download`/`upload`/`dir` are also skipped
        # (owned by other buckets).
        50,
        frozenset({
            "cmd", "exec", "command", "shell", "run", "execute",
            "ping", "exe", "func", "function", "cli", "daemon",
            # Curated command-exec compound families (Fix 4 precision layer; both
            # snake_case and concatenated forms). A bare `?cmd_exec=` would
            # otherwise only reach rce via the capped weak inner-token tier — these
            # promote the common compound names to the full rce weight.
            "cmd_exec", "cmdexec", "exec_cmd", "execcmd",
            "run_cmd", "runcmd", "run_command", "runcommand",
            "shell_cmd", "shellcmd", "shell_exec", "shellexec",
            "system_cmd", "systemcmd", "system_command", "systemcommand",
            "exec_command", "execcommand", "cmd_line", "cmdline",
            "command_line", "commandline",
        }),
        ("/exec/", "/cmd/", "/shell/"),
    ),
    (
        "graphql",
        # NEW (classify-surface 2026-06, §6.1): GraphQL endpoints and the
        # canonical GraphQL request keys. `/query` is deliberately NOT a path
        # fragment (it would mis-bucket REST search routes at weight 45); the
        # `query` PARAM key already carries that signal.
        45,
        frozenset({"query", "mutation", "subscription", "operationname", "variables"}),
        (
            "/graphql", "/graphiql", "/graphql/v1", "/graphql/v2",
            "/api/graphql", "/gql",
        ),
    ),
    (
        "secret_vault",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.6) → class
        # `secrets-exposure`. Credential-store / vault APIs: HashiCorp Vault
        # (`/v1/secret`,`/v1/secrets`,`/v1/auth/token`,`/vault/`), AWS Secrets
        # Manager (`/secretsmanager`), Azure Key Vault (`/keyvault`), and generic
        # credential-proxy endpoints (`/credential-stores`,`/credentials/retrieve`,
        # `/values/retrieve`,`/api/secrets`). Highest NON-RCE weight (45, tied
        # with graphql and declared AFTER it) because an exposed credential store
        # is a P1-class finding. Path-only — these surfaces have no single
        # canonical parameter name. Fragments are boundary-anchored by
        # `fragment_in_path` (`/vault/` -> core `/vault` + boundary), so
        # `/v1/secret` matches `/v1/secret`,`/v1/secret/data` but NOT
        # `/v1/secretstore`; `/v1/secrets` is therefore listed separately.
        45,
        frozenset(),
        (
            "/v1/secret", "/v1/secrets", "/credential-stores",
            "/credentials/retrieve", "/values/retrieve", "/vault/",
            "/keyvault", "/secretsmanager", "/api/secrets", "/v1/auth/token",
        ),
    ),
    (
        "ssrf",
        # Reduced from 45 -> 40 during the upstream review-and-merge: the prior
        # generic key set (`data`, `path`, `view`, `src`) produced too many
        # false positives on benign APIs that take a `view` query param. The
        # path fragments still anchor true SSRF surfaces (proxies, fetchers).
        # Key set NARROWED (§7, override #7): redirect/callback/continue/next/
        # link/dest moved OUT to `redirect`. ssrf still fires on those via its
        # `/proxy/`,`/fetch/` PATH fragments, not the param keys.
        #
        # Curated server-fetch compound families (Fix 4 precision layer, mirrors
        # `redirect`): these name a URL the SERVER fetches (SSRF), as opposed to
        # the `redirect` family which names a URL the BROWSER follows. Both
        # `snake_case` and `concatenated` (camelCase-lowercased) forms are listed.
        # Deepened (vuln-taxonomy-audit 2026-07): image/avatar-fetch compound
        # family. "SSRF via avatar/profile-picture URL" (the server
        # downloads a user-supplied image URL server-side to resize/host it) is
        # one of the most frequently reported bug-bounty SSRF variants and was
        # entirely absent from the curated `_url` families below — the bare
        # `image`/`photo`/`avatar` keys exist only in `img_traversal` (local
        # path traversal) and `upload_fields` (multipart upload), neither of
        # which carries the server-fetch-a-remote-URL semantics. Both
        # `snake_case` and concatenated forms, mirroring the existing
        # `webhook_url`/`webhookurl` idiom; none collide with any other
        # bucket's key set (`avatar`/`image`/`photo` bare are used elsewhere,
        # but the `_url` compound forms here are novel).
        40,
        frozenset({
            "url", "uri", "host", "port", "feed", "window",
            "fetch_url", "fetchurl", "proxy_url", "proxyurl",
            "remote_url", "remoteurl", "webhook_url", "webhookurl",
            "feed_url", "feedurl", "dest_uri", "desturi",
            "target_uri", "targeturi", "request_uri", "requesturi",
            "image_url", "imageurl", "avatar_url", "avatarurl",
            "photo_url", "photourl", "picture_url", "pictureurl",
            "logo_url", "logourl", "thumbnail_url", "thumbnailurl",
            "icon_url", "iconurl",
        }),
        ("/proxy/", "/fetch/"),
    ),
    (
        "cloud_metadata",
        # NEW (classify-context-and-surface 2026-06, Part 3 §B.10) → class `ssrf`.
        # REGEX bucket (override #1): like `api-versioning`, its only match signal
        # is the `_REGEX_BUCKET_RULES["cloud_metadata"]` alternation — it has NO
        # key set and NO literal fragments. The patterns catch SSRF-to-IMDS
        # payloads (Capital-One-class): the AWS link-local IMDS address
        # `169.254.169.254`, GCP `metadata.google.internal`, the IMDS PATHS
        # (`/latest/meta-data`, `/computeMetadata`, `/metadata/instance`), and the
        # obfuscated decimal/hex forms of the link-local address
        # (`2852039166`, `0xA9FEA9FE`). Because the address most often sits in a
        # QUERY-PARAM VALUE or HOST of a proof URL (not the url_path), `classify_row`
        # also runs these rules against the FULL `url` in the supplementary
        # `_FULL_URL_REGEX_BUCKETS` pass (the regex still also runs against url_path
        # in `bucket_matches`, catching the path-form IMDS literals). Weight 40
        # (tied with `ssrf`); declared AFTER `ssrf` so a co-fire on a shared
        # weight-40 SSRF surface keeps the existing cluster by the
        # first-at-max-weight tie-break, with `cloud_metadata` additively recorded.
        40,
        frozenset(),
        (),
    ),
    (
        "sqli",
        # Param set widened (classify-context-and-surface 2026-06, Part 6): add the
        # SQL-keyword-flavored params upstream carries — `where`,`select`,`table`,
        # `column`,`field`,`from`,`row`,`sleep`,`fetch`. `where`/`select` also
        # overlap the `nosqli` bucket via `$`-operators; both firing is fine (the
        # reason chain is multi-bucket).
        # Deepened (vuln-taxonomy-audit 2026-07): ORM sort/group compound
        # family. "SQLi via sort/orderBy parameter" (an ORM building
        # `ORDER BY <param>` or `GROUP BY <param>` directly from a request
        # value, unparameterizable because column names cannot be bound) is a
        # recurring bug-bounty pattern and a direct extension of the same
        # rationale already used for the bare `where`/`select`/`sleep`/`fetch`
        # additions above ("a param literally named after a SQL clause/function
        # is a genuine injection signal" — see `sqli.md`). `order`/`sort` bare
        # keys already exist; the compound `_by` forms and `having` do not, and
        # none collide with any other bucket.
        40,
        frozenset({
            "id", "uid", "pid", "sid", "tid", "order", "sort", "filter",
            "q", "search", "query", "category",
            "where", "select", "table", "column", "field", "from", "row",
            "sleep", "fetch",
            "order_by", "orderby", "sort_by", "sortby",
            "group_by", "groupby", "having",
        }),
        (),
    ),
    (
        "lfi",
        # Param set widened (classify-context-and-surface 2026-06, Part 6): add the
        # directory/traversal params upstream carries that we lacked — `folder`,
        # `root`, `dir`, `inc` (include shorthand), `conf` (config inclusion).
        40,
        frozenset({
            "file", "path", "doc", "document", "page", "pg", "template",
            "load", "include", "read",
            "folder", "root", "dir", "inc", "conf",
            # Curated file-inclusion / traversal compound families (Fix 4 precision
            # layer; both snake_case and concatenated forms). A bare `?file_path=`
            # would otherwise only reach lfi via the capped weak inner-token tier;
            # these promote the common compound names to the full lfi weight.
            "file_path", "filepath", "download_path", "downloadpath",
            "include_path", "includepath", "config_path", "configpath",
            "config_file", "configfile", "log_path", "logpath",
            "log_file", "logfile", "doc_path", "docpath",
            "local_path", "localpath", "root_path", "rootpath",
            "base_path", "basepath", "template_path", "templatepath",
            "read_file", "readfile", "load_file", "loadfile",
            "include_file", "includefile",
        }),
        (),
    ),
    (
        "auth",
        # NEW (classify-surface 2026-06, §6.2, override #8): authentication-entry
        # surfaces. COMPOUND path fragments only — bare `/verify` is EXCLUDED
        # (captcha/verify FP); only the compound `/auth/verify` and
        # `/email/verify` are allowed. `email`/`token` are NOT auth keys (too
        # generic / owned by jwt+interestingparams).
        40,
        frozenset({"username", "password", "mfa_code", "otp", "totp"}),
        (
            "/login", "/signin", "/sign-in", "/signon", "/sign-on",
            "/logout", "/sign-out", "/mfa", "/2fa", "/totp", "/otp",
            "/authenticate", "/auth/login", "/auth/signin", "/auth/verify",
            "/email/verify", "/saml/acs", "/saml/sso",
        ),
    ),
    (
        "deserialization",
        # NEW (classify-surface 2026-06, §6.7): unsafe deserialization surfaces.
        # `/sfsites/` is the Siteforce loader-state PATH PREFIX — it fires even
        # when the URL ends `.js`. Ordinary `.js` (no /sfsites/, no deserial
        # param) stays low (roster requirement).
        40,
        frozenset({
            "data", "payload", "blob", "object", "serialized",
            "viewstate", "__viewstate",
        }),
        (
            "/deserialize", "/marshal", "/unmarshal", "/pickle",
            "/java-serial", "/sfsites/",
        ),
    ),
    (
        "dotnet_handler",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.1) → class
        # `deserialization`. ASP.NET / WCF handler surfaces that the typer would
        # otherwise drop to `unknown` (Issue A, 835 rows). Catches:
        # WebResource/ScriptResource padding oracle (CVE-2010-3332),
        # ViewState/Telerik deserialization RCE (CVE-2019-18935), WCF/ASMX SOAP
        # services, ELMAH log disclosure (`/elmah.axd`), SharePoint `_vti_bin`.
        # Declared AFTER `deserialization` (both weight 40) so the shared
        # `__viewstate` param resolves to `gf:deserialization` by the
        # first-at-max-weight tie-break — the pinned `__VIEWSTATE`→gf:deserialization
        # cluster (test_classify_buckets_storage_deser_debug) is preserved;
        # dotnet_handler is recorded in the reason chain alongside it. The
        # leading-dot extension fragments (`.axd`,`.ashx`,`.asmx`,`.svc`) are
        # boundary-anchored by `fragment_in_path` exactly like interestingext's
        # `.env`/`.bak`, so `/trace.axd` matches but `/report.axdx` does NOT.
        40,
        frozenset({"__viewstate", "__eventvalidation"}),
        (
            ".axd", ".ashx", ".asmx", ".svc", "/_vti_bin/", "/trace.axd",
            "/elmah.axd",
        ),
    ),
    (
        "xxe",
        # NEW (vuln-taxonomy-audit 2026-07) → class `xxe` (already canonical;
        # `xxe-testing` skill already exists — this bucket was the classifier's
        # one confirmed gap: the class had a skill but no gf-style signal).
        # XML/SOAP surfaces that accept attacker-controlled XML are the classic
        # XXE entry point (external entity / DTD abuse, blind OOB exfil, SSRF via
        # entity expansion). Weight 40 (tied with ssrf/sqli/lfi/auth/deserialization/
        # dotnet_handler) reflects real severity; declared AFTER `dotnet_handler`
        # so a future shared fragment would keep that bucket's existing tie-break
        # win. Every key/fragment below is DELIBERATELY NOVEL (verified against
        # no other bucket) so this addition cannot recluster any existing row:
        # `.svc`/`.asmx` (also classic SOAP endpoints) already belong to
        # `dotnet_handler` and `/xmlrpc.php` already belongs to `wordpress` — both
        # are real adjacent XXE surfaces, cross-referenced in
        # `agent/references/gf-patterns/xxe.md` rather than re-declared here, so
        # this bucket cannot change either bucket's pinned `cluster_key`.
        40,
        frozenset({"xml", "soap", "wsdl", "rss"}),
        ("/soap", ".wsdl"),
    ),
    (
        "img_traversal",
        # NEW (review-and-merge): image-serving endpoints that take a path
        # fragment are a classic LFI variant — `/img?src=../../etc/passwd`
        # style. Separate bucket from `lfi` because the param key set is
        # different (image-flavored) and the path fragments are distinctive.
        35,
        frozenset({"img", "image", "photo", "thumb", "thumbnail"}),
        ("/img/", "/image/", "/images/", "/thumb/", "/thumbnail/", "/photo/"),
    ),
    (
        "oauth-oidc",
        # NEW (classify-surface 2026-06, §6.5): OAuth2/OIDC flow endpoints and
        # the canonical OAuth request keys. Declared BEFORE `trust_surface`
        # (both weight 35) so a co-fire on shared fragments (`/connect/token`,
        # `/oauth2/authorize`'s `/authorize`) resolves to `gf:oauth-oidc` by the
        # first-at-max-weight tie-break (matrix O2/O3). `/oauth2/`,`/oidc/` are
        # distinct from trust_surface's `/oauth` fragment — `/oauth/callback`
        # does NOT contain `/oauth2/` (the `2` is required), so trust_surface
        # keeps owning the bare callback (regression pin §10.5).
        #
        # Extended (classify-context-and-surface 2026-06, §C.11) with the Dynamic
        # Client Registration endpoint `/connect/register` (DCR abuse — DEEPSEEK
        # VA-707 surface). It is declared here, ahead of trust_surface's `/connect`
        # fragment, so a DCR route clusters `gf:oauth-oidc`, not the generic
        # callback bucket. `/oidc/register` is already subsumed by `/oidc/`. The
        # PingFederate `/as/*.oauth2` fragments live in the `idp_admin` bucket
        # (which models the IdP admin/realm surface) rather than being duplicated
        # here.
        35,
        frozenset({
            "client_id", "redirect_uri", "response_type", "scope", "state",
            "nonce", "code_challenge", "grant_type",
        }),
        (
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth2/", "/oidc/",
            "/connect/authorize", "/connect/token", "/connect/userinfo",
            "/connect/register",
            "/jwks.json", "/.well-known/jwks.json",
        ),
    ),
    (
        "sso",
        # NEW (classify-surface 2026-06, §6.11): SAML/SSO surfaces. `/saml` is
        # boundary-anchored so it covers `/saml`,`/saml/acs` but NOT `/saml2`
        # (next char `2` is not a boundary) — `/saml2` is listed separately.
        # Declared before `trust_surface` (weight 35) for the same tie-break
        # reason as `oauth-oidc`.
        #
        # Fragment set widened (classify-context-and-surface 2026-06, Part 3 §C.12):
        # add the ADFS federation-metadata endpoint `/federationmetadata` (SAML
        # metadata disclosure / SP enumeration). It is a metadata-only surface with
        # no auth-fragment sibling, so it cleanly raises previously-unmatched
        # federationmetadata URLs from 0 to `gf:sso`. The other §C.12 entries are
        # DELIBERATELY NOT added (see Part 3 §C.12 deviation note): `/saml/metadata`
        # and `/adfs/ls` are already covered by the existing `/saml` and `/adfs/`
        # fragments (no-ops), and `/simplesaml`/`/shibboleth.sso` are NOT added
        # because the canonical product endpoints under them (`/Shibboleth.sso/Login`,
        # `/Shibboleth.sso/Logout`, `/simplesaml/logout.php`) carry an auth fragment
        # that `_suppress_auth_on_sso_route` would then suppress — DEMOTING those
        # rows from `gf:auth` (40) to `gf:sso` (35), which is a non-additive score
        # decrease, so they are left out.
        35,
        frozenset({"samlresponse", "samlrequest", "relaystate", "wctx", "wresult"}),
        (
            "/sso/", "/sso", "/saml", "/saml2", "/cas/", "/adfs/", "/fed/",
            "/sts/", "/federationmetadata",
        ),
    ),
    (
        "trust_surface",
        # NEW (review-and-merge): adversarial-mindset rule 2 — uploads,
        # webhooks, password-reset, OAuth callbacks, exports, imports, file
        # download/preview/render are all places where the server trusts
        # client-supplied content type, filename, or token. Path-only
        # detection because these surfaces almost never have a single
        # canonical parameter name.
        35,
        frozenset(),
        (
            "/upload", "/import", "/export", "/webhook", "/callback",
            "/reset", "/recover", "/invite", "/share",
            "/oauth", "/authorize", "/token", "/connect",
            "/download", "/preview", "/render", "/convert",
        ),
    ),
    (
        "idor",
        # Object-reference parameter keys. Expanded beyond the original upstream
        # gf slice (`id,user,account,number,doc,email,group,profile,order,report`)
        # to cover the *_id family, tenant/org/workspace scoping keys (cross-tenant
        # BOLA), and the modern chat/agent object refs (conversation/thread/message)
        # that 2024-2026 IDOR research flags as primary surfaces. Path-embedded
        # object references (`/users/1024/profile`) are handled separately by the
        # `_PATH_OBJECT_REF_SEGMENT` rule in `classify_row`, not by path fragments
        # here, because they need id-shape detection (numeric/UUID/hex) rather than
        # a fixed substring.
        35,
        frozenset({
            # original upstream slice
            "id", "user", "account", "number", "doc", "email", "group",
            "profile", "order", "report",
            # user / identity references
            "uid", "userid", "user_id", "owner", "owner_id", "member",
            "member_id", "customer", "customer_id", "account_id", "accountid",
            # tenant / org scoping (cross-tenant BOLA)
            "org", "org_id", "organization", "organization_id", "tenant",
            "tenant_id", "workspace", "workspace_id",
            # generic object handles
            "object", "object_id", "objectid", "oid", "record", "record_id",
            "ref", "reference", "uuid", "guid", "gid", "node", "pid",
            # domain objects
            "order_id", "orderid", "invoice", "invoice_id", "document_id",
            "doc_id", "file_id", "fileid", "transaction", "transaction_id",
            "payment", "payment_id", "ticket", "ticket_id", "case_id",
            # modern chat / agent object refs
            "conversation", "conversation_id", "thread", "thread_id",
            "message_id", "msg_id",
        }),
        (),
    ),
    (
        "idp_admin",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.5) → class
        # `auth-bypass`. Identity-provider ADMIN / realm-config surfaces:
        # Keycloak (`/auth/realms`,`/realms/` — v17+ dropped the `/auth` prefix,
        # `/auth/admin`,`/admin/master/console`), PingFederate
        # (`/as/authorization.oauth2`,`/as/token.oauth2`,`/as/clients.oauth2`),
        # generic IdP (`/idp/`,`/nidp/`), and ADFS (`/adfs/ls`). Complements
        # `oauth-oidc` (which models the FLOW) by modelling the admin/realm
        # surface. Weight 35; declared AFTER `sso`/`trust_surface` (also 35) so a
        # co-fire on a shared fragment keeps the EXISTING cluster by the
        # first-at-max-weight tie-break — `/adfs/ls` stays `gf:sso` (sso's
        # `/adfs/` fragment) and `/as/token.oauth2` stays `gf:trust_surface`
        # (trust_surface's `/token` fragment), with `idp_admin` additively
        # recorded in the reason chain. Path-only (no canonical param key).
        35,
        frozenset(),
        (
            "/auth/realms", "/realms/", "/auth/admin", "/admin/master/console",
            "/as/authorization.oauth2", "/as/token.oauth2", "/as/clients.oauth2",
            "/idp/", "/nidp/", "/adfs/ls",
        ),
    ),
    (
        "wordpress",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.2) → class
        # `user-enumeration`. WordPress surfaces the boundary matcher misses today
        # (Issue 3): REST user/media enum (`/wp-json`,`/wp-json/wp/v2/users`),
        # XML-RPC pingback SSRF/brute (`/xmlrpc.php`), WP-Cron (`/wp-cron.php`),
        # the debug log (`/wp-content/debug.log`), and login/admin
        # (`/wp-login.php`,`/wp-admin` — note `/wp-admin` carries `-admin`, NOT the
        # `/admin` segment debug_logic looks for, so only this bucket catches it).
        # Param keys: `author` (numeric -> user enum) and `rest_route`. Weight 35;
        # declared BEFORE `cms_db_admin` (also 35) so the shared `/wp-admin`
        # fragment clusters as `gf:wordpress` by the first-at-max-weight tie-break.
        35,
        frozenset({"author", "rest_route"}),
        (
            "/wp-json", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
            "/wp-cron.php", "/wp-content/debug.log", "/wp-json/wp/v2/users",
        ),
    ),
    (
        "cms_db_admin",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.3) → class
        # `auth-bypass`. CMS + DB admin panels that the `/admin` boundary matcher
        # misses (Issue 3): Joomla (`/administrator`), Umbraco, Sitecore, TYPO3,
        # Ghost, phpMyAdmin (`/phpmyadmin`,`/pma`), Adminer
        # (`/adminer`,`/adminer.php`), generic DB admin (`/dbadmin`), Tomcat
        # (`/manager/html`), and the `/admin-console`/`/wp-admin` consoles
        # (hyphenated, so debug_logic's `/admin` segment never matches them).
        # Weight 35; declared AFTER `wordpress` so `/wp-admin` clusters as
        # `gf:wordpress`. Path-only.
        35,
        frozenset(),
        (
            "/administrator", "/umbraco", "/sitecore", "/typo3", "/ghost",
            "/phpmyadmin", "/adminer", "/adminer.php", "/pma", "/dbadmin",
            "/manager/html", "/admin-console", "/wp-admin",
        ),
    ),
    (
        "nosqli",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.8) → class `nosqli`.
        # Mongo/Elasticsearch operator-injection surfaces (gf had no NoSQL concept).
        # The param keys are the Mongo/ES query operators (`$ne`,`$gt`,`$gte`,`$lt`,
        # `$regex`,`$where`,`$in`,`$or`,`$exists`); a compound key such as
        # `username[$ne]` is decomposed by `expand_compound_key` (which splits on
        # `[`/`]`) into the `$ne` token, so the operator survives into the matcher.
        # Path fragments are the ES/Mongo search/aggregation routes (`/_search`,
        # `/aggregate`, `/_msearch`). `$where`/`$gt` also overlap the `sqli`
        # SQL-keyword params (`where`,...) — both firing is fine (multi-bucket
        # reason chain). Weight 35; declared AFTER `cms_db_admin` (also 35).
        35,
        frozenset({
            "$ne", "$gt", "$gte", "$lt", "$regex", "$where", "$in", "$or",
            "$exists",
        }),
        ("/_search", "/aggregate", "/_msearch"),
    ),
    (
        "prototype-pollution",
        # NEW (vuln-taxonomy-audit 2026-07) → class `prototype-pollution`
        # (already canonical; the `prototype-pollution` skill already exists).
        # PortSwigger's server-side prototype-pollution research (Gareth Heyes,
        # portswigger.net/research/server-side-prototype-pollution) shows the
        # gadget is triggered by literal `__proto__`/`constructor`/`prototype`
        # keys reaching an object-merge sink; a captured request whose JSON body
        # already carries one of these keys (often as a compound bracket path
        # like `constructor[prototype][x]`, decomposed by `expand_compound_key`)
        # is a strong, low-FP signal — these are not normal application
        # parameter names. Param-only (no path fragment carries the signal),
        # mirroring `ssti`/`cors`/`sqli`. Weight 35 (nosqli/idor tier): real
        # severity (server-side PP can reach RCE via gadget chains) but keyed on
        # rare literal names rather than a proven interpreter sink. All three
        # keys are DELIBERATELY NOVEL (verified against every other bucket) so
        # this addition cannot recluster any existing row.
        35,
        frozenset({"__proto__", "constructor", "prototype"}),
        (),
    ),
    (
        "upload_fields",
        # NEW (review-and-merge): parameter-level signal for upload surfaces
        # that may not match the `trust_surface` path heuristic (e.g.,
        # /api/v2/users/avatar uses `file` as the multipart key but the path
        # has no /upload fragment). Lower weight than `trust_surface` because
        # a parameter named `file` alone is weaker signal than the path
        # fragment, but still high enough to dispatch.
        #
        # classify-surface 2026-06 (§6.12.1): the roster's "rename to
        # file-upload, raise to 35" is OVERRIDDEN by soundness override #9 (no
        # regression). The bucket KEEPS its name `upload_fields` (so the
        # `gf:upload_fields` cluster key and the pinned reason string
        # `gf:lfi+gf:upload_fields` survive) and KEEPS weight 30 (so the pinned
        # `priority_score == 40` arithmetic in
        # `test_upload_rows_prefer_upload_fields_over_generic_lfi` survives).
        # The real recall win is delivered via the new REST path fragments and
        # the three new content-type keys (`content_type`,`mime_type`,
        # `multipart`), NOT a weight bump. `GF_BUCKET_TO_CLASS["upload_fields"]`
        # already maps to the `file-upload` class.
        30,
        frozenset({
            "file", "filename", "upload", "attachment", "avatar",
            "image", "photo", "document", "media",
            "content_type", "mime_type", "multipart",
        }),
        (
            "/attachments", "/upload-file", "/file-upload", "/attach",
            "/media-upload",
        ),
    ),
    (
        "debug_logic",
        # Extended (classify-surface 2026-06, §6.13, override #3): keep ALL
        # existing fragments and ADD only compound/specific fragments. Bare
        # `/health`,`/info`,`/status`,`/version`,`/metrics`,`/env` are
        # deliberately NOT added (they flood content corpora).
        #
        # Param set added (classify-context-and-surface 2026-06, Part 6): this
        # bucket was path-only; `?debug=1`/`?dbg=1`/`?test=1` toggles are a real
        # debug-mode signal it missed. `admin`/`grant`/`access` are kept OUT of the
        # debug params (those route to `privileged_action`).
        30,
        frozenset({"debug", "dbg", "test"}),
        (
            "/admin", "/debug", "/dbg", "/dev", "/staging", "/stage",
            "/test", "/internal", "/mgmt", "/manage", "/console",
            "/dashboard", "/_profiler", "/phpinfo", "/actuator",
            "/.git", "/.env", "/config", "/backup",
            # ADDED (override #3): compound/specific only. `/package.json` was
            # listed here originally and is now supplied by the shared
            # dependency-manifest roster below.
            "/healthz", "/readyz", "/server-status", "/server-info",
            "/actuator/health", "/actuator/env",
            "/actuator/mappings", "/actuator/metrics", "/actuator/beans",
            "/prometheus",
            # Java deployment descriptor — source/dependency disclosure in the
            # same family as the manifests below, but it declares no
            # dependencies, so it stays a literal here. Leading-slash form for
            # boundary precision (so `/myweb.xml` does NOT match). The VCS/IDE
            # dotfiles (`.svn`,`.hg`,...) are in `interestingext`.
            "/web-inf/web.xml",
            # Dependency manifests and lockfiles. The roster is owned by
            # `dependency_manifests.RECOGNIZED_MANIFESTS` — the same table the
            # code-side readers walk — so an ecosystem is added in one place and
            # the web and code tracks cannot drift apart. The hand-typed list
            # this replaced knew only npm and Composer, so an exposed
            # `/pom.xml`, `/go.sum` or `/requirements.txt` scored nothing.
            *url_path_fragments(),
        ),
    ),
    (
        "websocket",
        # NEW (classify-surface 2026-06, §6.8): WebSocket / real-time transport
        # endpoints. `/ws` is boundary-anchored → `/ws`,`/ws/feed` match but
        # `/wsdl`,`/wsus` do NOT.
        30,
        frozenset({"channel", "room", "topic"}),
        (
            "/ws", "/wss", "/websocket", "/socket.io", "/sockjs", "/stomp",
            "/mqtt",
        ),
    ),
    (
        "webhook",
        # NEW (classify-surface 2026-06, §6.9): inbound/outbound webhook
        # surfaces. `url` is NOT a webhook key (ssrf at 40 already wins on
        # `?url=`); `/callback` is OMITTED (owned by trust_surface).
        #
        # The spec roster listed `/event`,`/events` as path fragments, but the
        # authoritative matrix proves they are content-navigation-prone
        # (`/events/2024/conf` is a conference listing, not a webhook): a bare
        # `/events` path must NOT fire webhook, yet `/events/...?endpoint=` MUST.
        # So `/event`,`/events` are dropped from the PATH set — the real
        # webhook-with-target case is captured by the `endpoint`/`target` keys,
        # while the unambiguous `/webhook(s)`,`/hook(s)`,`/notify` routes still
        # fire path-only.
        30,
        frozenset({"endpoint", "target"}),
        ("/webhook", "/webhooks", "/hook", "/hooks", "/notify"),
    ),
    (
        "jwt",
        # NEW (classify-surface 2026-06, §6.10, override #8): JWT/bearer-token
        # surfaces. Low-incremental secondary reason — bare `token` key and
        # bare `/token` path are OMITTED (owned by trust_surface /
        # interestingparams) to avoid double-firing on every `?token=`.
        30,
        frozenset({"access_token", "refresh_token", "id_token", "jwt", "bearer"}),
        ("/jwt", "/bearer", "/refresh-token"),
    ),
    (
        "servicenow",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.4) → class `idor`.
        # ServiceNow guest Service Portal / GlideRecord / Struts `.do` surfaces
        # (Issue B): REST table API (`/api/now`), UI actions (`/nav_to.do`,
        # `auth_redirect.do`), `sys_*`/`x_*` scoped tables (`/sys_`,`/x_`), the
        # GlideRecord `/$` and Service Portal `/sp?` entry points. Param keys are
        # the ServiceNow `sysparm_*` family + `glide_sso_id`. Generic — ServiceNow
        # is a ubiquitous enterprise SaaS, not a target-specific artifact. Weight 30. The
        # `auth_redirect.do?sysparm_url=` open-redirect/SSO surface clusters here
        # via the `sysparm_url` WHOLE key (servicenow wins as the strong match);
        # Fix 4's tiered inner-token mechanism (now landed) additionally exposes the
        # inner `url` token, so the row ALSO carries `ssrf`/`redirect` as
        # `secondary_buckets` (cross-routing), without disturbing the servicenow
        # cluster.
        30,
        frozenset({
            "sysparm_url", "sysparm_query", "sysparm_table", "glide_sso_id",
        }),
        (
            "/api/now", "/nav_to.do", "auth_redirect.do", "/sys_", "/$",
            "/sp?", "/x_",
        ),
    ),
    (
        "privileged_action",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.9) → class `bfla`.
        # Two complementary match signals:
        #   1. The `path_has_privileged_action` predicate appended in `classify_row`
        #      (mirroring the `path_has_object_ref`->idor append), which requires a
        #      state-change verb SEGMENT (`/grant`,`/revoke`,`/approve`,... — see
        #      `_PRIVILEGED_ACTION_VERBS`) GUARDED by an API/version sibling segment
        #      or an embedded object reference. That precision override stops a
        #      content slug like `/transfer-your-number` (rejected by the segment
        #      split) or a bare `/transfer` page from firing.
        #   2. The param-key form of those state verbs (added Part 6): `grant`,
        #      `delete`, `create`, `disable`, `enable`, `toggle`, `reset`, `rename`,
        #      `modify`, `alter`, `clone` — `?delete=`/`?grant=` reinforce the
        #      path-based signal. (Upstream's catch-all `ssrf.json` is really a
        #      "dangerous params" list; these are its state-change param NAMES.)
        # The `path_has_privileged_action` append in `classify_row` is deduped
        # against a param-key match so the reason chain never lists the bucket
        # twice. Path fragments stay empty (the path signal is the predicate, not a
        # literal fragment). Weight 30; declared after `servicenow` (30).
        30,
        frozenset({
            "grant", "delete", "create", "disable", "enable", "toggle",
            "reset", "rename", "modify", "alter", "clone",
        }),
        (),
    ),
    (
        "mass-assignment",
        # NEW (vuln-taxonomy-audit 2026-07) → class `mass-assignment` (already
        # canonical; `bff-parameter-override`/`mass-assignment` skills already
        # exist). OWASP API Security Top 10:2023 folds mass assignment into
        # API3:2023 "Broken Object Property Level Authorization" — a top-3 API
        # risk. Autobinding frameworks (Rails/Spring MVC/ASP.NET MVC/Node ORMs)
        # bind body keys straight onto a model, so a captured request whose body
        # already carries a privilege-shaped key (`isAdmin`, `role`, `verified`,
        # `access_level`, ...) is real over-posting signal — the canonical
        # example is the 2012 GitHub mass-assignment breach via a public-key
        # upload endpoint. Param-only (body-shape issue, no distinctive path).
        # Weight 30 (privileged_action/servicenow tier — bfla-adjacent
        # authorization risk); declared AFTER `privileged_action` so a shared
        # weight never disturbs its existing wins. Every key below is
        # DELIBERATELY NOVEL (verified against every other bucket, including
        # oauth-oidc's `scope` and privileged_action's own verb set) so this
        # addition cannot recluster any existing row.
        30,
        frozenset({
            "role", "roles", "admin", "isadmin", "is_admin",
            "permissions", "permission",
            "verified", "is_verified", "isverified",
            "approved", "is_approved", "isapproved",
            "access_level", "accesslevel", "privilege", "privileges",
            "account_type", "accounttype", "user_type", "usertype",
            "user_role", "userrole", "is_active", "isactive",
        }),
        (),
    ),
    (
        "devops_console",
        # NEW (classify-context-and-surface 2026-06, Part 3 §A.7) → class
        # `debug-exposure`. Ops dashboards / metrics & registry planes that are
        # routinely deployed unauthenticated: Grafana (`/grafana`,
        # `/api/datasources` — CVE-2026-27876 family), Jenkins (`/jenkins`),
        # Jolokia (`/jolokia` — JMX RCE), Hystrix (`/hystrix`), the ELK stack
        # (`/kibana`, `/_cat/`, `/solr/`, `/druid`), Go pprof (`/debug/pprof`),
        # the Docker registry catalog (`/v2/_catalog`), and the GitLab projects
        # API (`/api/v4/projects`). Path-only (no canonical param key). Weight 30;
        # declared AFTER `debug_logic` (also 30) so `/debug/pprof` — which also
        # matches debug_logic's `/debug` fragment — keeps cluster `gf:debug_logic`
        # by the first-at-max-weight tie-break, with `devops_console` additively
        # recorded in the reason chain.
        30,
        frozenset(),
        (
            "/grafana", "/api/datasources", "/jenkins", "/jolokia", "/hystrix",
            "/kibana", "/_cat/", "/solr/", "/druid", "/debug/pprof",
            "/v2/_catalog", "/api/v4/projects",
        ),
    ),
    (
        "ssi",
        # NEW (vuln-taxonomy-audit 2026-07) → NEW class `ssi-injection` (OWASP
        # WSTG 4.7.8 "Testing for SSI Injection"; www-community "Server-Side
        # Includes (SSI) Injection"). SSI directives (`<!--#exec cmd="..."-->`)
        # can reach OS command execution when a server parses these extensions
        # and echoes unsanitized input. Extension-only detection mirrors
        # `dotnet_handler`'s `.axd`/`.asmx` idiom: a hit on one of these rare,
        # largely-legacy extensions is a low-FP signal even without a param key.
        # No skill exists yet for this rare/legacy class — allowlisted
        # skill-less in `test_vuln_taxonomy.KNOWN_SKILLLESS_CLASSES`, mirroring
        # `ldap-injection`/`path-authz`. Weight 30 (below `dotnet_handler`'s 40 —
        # SSI is rarer/lower-triage-priority in 2026 stacks than ASP.NET
        # handlers, but still real when present). All three extensions are
        # DELIBERATELY NOVEL (verified against `interestingext`'s extension list
        # and every other bucket) so this addition cannot recluster any
        # existing row.
        30,
        frozenset(),
        (".shtml", ".shtm", ".stm"),
    ),
    (
        "redirect",
        # Param set widened (classify-context-and-surface 2026-06, Part 6): add the
        # single-token open-redirect params `goto`,`rt`,`to`,`domain`,`site`.
        # `to`/`domain`/`site` are mildly generic but only affect ordering.
        #
        # The compound `*_url`/`*_uri`/`*_to` open-redirect family is handled on TWO
        # layers (Fix 4, LANDED — see DRIFT.md "Fix 4"): the curated whole-key
        # members below match the common names STRONGLY and PRECISELY here, so a
        # bare `?return_url=` clusters `gf:redirect` (NOT `gf:ssrf` — the inner
        # `url` token alone would mis-route to ssrf@40 in the generic rescue); and
        # `classify_row`'s tiered inner-token (`_weak_token_matches`) backstop
        # catches novel compound names. This mirrors the `idor` bucket's enumerated
        # `*_id` whole-key idiom (the codebase's established way to handle compound
        # keys without naively tokenizing high-weight generics like `id`/`url`).
        25,
        frozenset({
            "redirect", "return", "returnto", "return_to", "next", "redir",
            "forward", "continue", "url", "rurl", "u", "target", "dest",
            "destination", "redirect_uri", "go",
            "goto", "rt", "to", "domain", "site",
            # Curated compound open-redirect families. Both `snake_case` and
            # `concatenated` lowercased forms are listed because the typer
            # lowercases keys before matching, so camelCase (`returnUrl`) arrives
            # as the concatenated form (`returnurl`).
            "return_url", "returnurl", "return_uri", "returnuri",
            "redirect_url", "redirecturl", "redirect_to", "redirectto",
            "callback_url", "callbackurl", "callback_uri", "callbackuri",
            "next_url", "nexturl", "continue_url", "continueurl",
            "goto_url", "gotourl", "success_url", "successurl",
            "failure_url", "failureurl", "back_url", "backurl",
            "forward_url", "forwardurl", "dest_url", "desturl",
            "origin_url", "originurl", "return_path", "returnpath",
        }),
        (),
    ),
    (
        "ssti",
        # Curated template-injection compound families (Fix 4 precision layer; both
        # snake_case and concatenated forms). The render-flavored compounds live
        # here; the path/file-flavored `template_path`/`template_file` go to `lfi`
        # (file inclusion), which outranks ssti(25) anyway.
        25,
        frozenset({
            "template", "tpl", "theme", "layout", "view",
            "template_name", "templatename", "template_string", "templatestring",
            "template_content", "templatecontent", "render_template", "rendertemplate",
            "page_template", "pagetemplate", "email_template", "emailtemplate",
            "custom_template", "customtemplate", "template_engine", "templateengine",
            "template_code", "templatecode",
        }),
        (),
    ),
    (
        "cors",
        # NEW (review-and-merge): upstream `cors` patterns target headers
        # rather than query params, but request bodies/path traversal
        # endpoints that echo the Origin header are a recognizable surface.
        # Param-key match catches the small set of endpoints that take an
        # explicit origin/access-control parameter.
        25,
        frozenset({"origin", "access_control", "allow_origin"}),
        (),
    ),
    (
        "api-versioning",
        # NEW (classify-surface 2026-06, §6.4, override #1): REGEX bucket. Its
        # only match signal is the `_REGEX_BUCKET_RULES["api-versioning"]`
        # pattern `/v[0-9]+(?=[/?#]|$)` — it has NO key set and NO literal
        # fragments. The empty `_BUCKETS` entry keeps it in the single
        # declaration-ordered iteration (for tie-break + reason-chain order)
        # and visible to `GF_BUCKET_TO_CLASS`.
        25,
        frozenset(),
        (),
    ),
    (
        "object-storage",
        # NEW (classify-surface 2026-06, §6.6, override #2): NEVER a bare
        # `/files/` or `/storage/` fragment (document-heavy sites have thousands of
        # `/files/*.pdf`). Use Domino-specific discriminators (`$file`,`.nsf`,
        # `files.nsf`,`docscat`,`didc`) PLUS cloud (`/s3/`,`/gcs/`,`/blob/`,
        # `/bucket/`). `key`/`object` dropped from the key set (too generic).
        #
        # Param set widened (classify-context-and-surface 2026-06, Part 3 §C.14):
        # add the S3/GCS/Azure bucket-LISTING params (`list-type`, `marker`,
        # `delimiter`, `continuation-token`; `prefix` was already present) so an
        # open-bucket object-enumeration URL fires this bucket. The cloud HOST
        # markers from §C.14 (`.s3.amazonaws.com`, `blob.core.windows.net`,
        # `storage.googleapis.com`) live in the URL AUTHORITY, not the url_path, so
        # they are matched via `_REGEX_BUCKET_RULES["object-storage"]` in the
        # supplementary `_FULL_URL_REGEX_BUCKETS` full-`url` pass in `classify_row`.
        25,
        frozenset({
            "bucket", "blob", "prefix",
            "list-type", "marker", "delimiter", "continuation-token",
        }),
        (
            "$file", ".nsf", "files.nsf", "docscat", "didc",
            "/s3/", "/gcs/", "/blob/", "/bucket/",
        ),
    ),
    (
        "api",
        # NEW (classify-surface 2026-06, §6.3, override #9): path-only, NARROWED.
        # Bare `/api/` and `/api/v` are DELIBERATELY OMITTED — a bare `/api/`
        # fragment would append `gf:api` to `/api/users/avatar` and break the
        # pinned exact reason chain `gf:lfi+gf:upload_fields`. The generic
        # params-less `/api/...` rescue is delivered by the `api_route` TYPE
        # FLOOR (§2); `/api/v<n>/` is covered by the `api-versioning` regex.
        20,
        frozenset(),
        ("/rest/", "/rest/v", "/services/apexrest/", "/apexrest/"),
    ),
    (
        "xss",
        20,
        frozenset({
            "q", "query", "search", "keyword", "name", "message", "comment",
            "text", "content", "input", "data",
        }),
        (),
    ),
    (
        "interestingparams",
        15,
        frozenset({
            "api_key", "apikey", "token", "auth", "session", "secret",
            "password", "passwd", "pwd",
        }),
        (),
    ),
    (
        "interestingext",
        # NEW (review-and-merge): backup files, source maps, env files,
        # dumped config — extension-based detection keyed off the URL path's
        # trailing fragment. Weight is intentionally low because the URL
        # itself is the finding (a 200 on /backup.sql is the vuln); we
        # mainly want it in a `gf:interestingext` cluster instead of
        # buried in a `path:` bucket.
        #
        # Fragments widened (classify-context-and-surface 2026-06, Part 6): add the
        # backup/cred/cert/db extensions from `1ndianl33t/interestingEXT.json` we
        # lacked. DELIBERATELY EXCLUDE `.xml`/`.json`/`.csv`/`.yml`/`.pdf`/`.doc`/
        # `.txt` — they are legitimate data files already typed `data` and would
        # flood the bucket. Extension fragments are boundary-anchored by
        # `fragment_in_path` exactly like `.bak`, so `/db.backup` matches `.backup`
        # but `/notes.backupx` does NOT.
        #
        # Fragments widened (classify-context-and-surface 2026-06, Part 3 §C.13):
        # add the VCS / IaC / IDE dotfile artifacts (`.svn`, `.hg`, `.gitlab-ci.yml`,
        # `.ds_store`, `.terraform`, `.tfstate`) — source/config disclosure surfaces
        # (`.git`/`.env` are already covered by debug_logic). The build-manifest
        # FILENAMES from §C.13 (`composer.json`, `composer.lock`, `yarn.lock`,
        # `package-lock.json`, `web-inf/web.xml`) are added to `debug_logic` instead,
        # mirroring its existing `/package.json` entry. The specific name
        # `.gitlab-ci.yml` does NOT reintroduce the generic `.yml` flood that Part 6
        # deliberately excluded — boundary-anchoring requires the full distinctive
        # token, so `/config.yml` still does NOT match.
        10,
        frozenset(),
        (
            ".bak", ".old", ".sql", ".swp", ".swo",
            ".config", ".env", ".conf", ".ini",
            ".pem", ".key", ".log",
            ".backup", ".bkp", ".cfg", ".cnf", ".crt", ".csr",
            ".passwd", ".pwd", ".mdb", ".rdp", ".dat", ".pac",
            ".svn", ".hg", ".gitlab-ci.yml", ".ds_store", ".terraform",
            ".tfstate",
        ),
    ),
)

# Weight of the `idor` bucket, resolved from the table above so the
# path-object-reference rule in `classify_row` cannot drift from the declared
# bucket weight if it is ever retuned.
_IDOR_WEIGHT: int = next(weight for name, weight, _, _ in _BUCKETS if name == "idor")

# Weight of the `privileged_action` bucket. Like `_IDOR_WEIGHT`, resolved from
# the table so the `path_has_privileged_action` predicate (which appends the
# match in `classify_row`, not via `bucket_matches`) cannot drift from the
# declared bucket weight if it is ever retuned.
_PRIVILEGED_ACTION_WEIGHT: int = next(
    weight for name, weight, _, _ in _BUCKETS if name == "privileged_action"
)


# Regex-fragment rules (override #1), keyed by the bucket name they belong to.
# `bucket_matches` consults `_REGEX_BUCKET_RULES.get(name)` on the SAME
# declaration-ordered pass over `_BUCKETS`, so a regex hit appends the bucket
# exactly as a literal/key hit would — preserving tie-break order (first bucket
# at the max weight) and reason-chain order (declaration order). Each entry is a
# tuple of raw regex strings; unlike literal fragments they are NOT
# boundary-wrapped by the helper — the pattern author supplies its own anchoring.
#
# `api-versioning` (§3.4): matches a path segment that is `v` + one-or-more
# digits, bounded by `/`, `?`, `#`, or end-of-string. Matches `/v1/`, `/v2/`,
# `/v3`, `/dhrp/rns/v3/actions`, `/api/v1/`; rejects `/version/1.0` (segment
# `version`), `/v/1` (segment `v`, no digits), `/vue/app` (segment `vue`),
# `/v1beta/x` (the lookahead rejects `beta` after the digits).
#
# `cloud_metadata` (§B.10) and `object-storage` (§C.14, host markers) are
# FULL-URL regex buckets: their signal lives in the URL authority / query string,
# not just the url_path. `bucket_matches` runs these rules against `url_path` like
# any regex bucket (catching the path-form IMDS literals), and `classify_row`
# additionally runs them against the FULL `url` for the buckets listed in
# `_FULL_URL_REGEX_BUCKETS` so a `169.254.169.254` proof param or an
# `*.s3.amazonaws.com` host also fires. The cloud_metadata path literals are
# authored LOWERCASE and boundary-anchored: `regex_fragment_in_path` compiles
# WITHOUT `re.IGNORECASE` and both match sites lowercase the haystack first, so a
# literal-uppercase pattern could never match and an un-anchored substring would
# false-positive (`/metadata/instance` on `/api/metadata/instances`). Hence
# `/computemetadata` matches `/computeMetadata/...` after lowercasing, and the
# `(?=[/?#]|$)` boundary keeps `/latest/meta-data` off `/.../meta-database` and
# `/metadata/instance` off `/api/metadata/instances`. The obfuscated hex form
# keeps its `[aA]`/`[fF]` classes as belt-and-suspenders.
_REGEX_BUCKET_RULES: dict[str, tuple[str, ...]] = {
    "api-versioning": (r"/v[0-9]+(?=[/?#]|$)",),
    "cloud_metadata": (
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"/latest/meta-data(?=[/?#]|$)",
        r"/computemetadata(?=[/?#]|$)",
        r"/metadata/instance(?=[/?#]|$)",
        r"0x[aA]9[fF][eE][aA]9[fF][eE]",
        r"\b2852039166\b",
    ),
    "object-storage": (
        r"\.s3\.amazonaws\.com",
        r"blob\.core\.windows\.net",
        r"storage\.googleapis\.com",
    ),
}

# Regex buckets whose `_REGEX_BUCKET_RULES` patterns must ALSO be tested against
# the FULL `url` (authority + query), not only the url_path. `classify_row` runs
# this supplementary pass after `bucket_matches`, appending a matched bucket
# (deduped) exactly like the idor / privileged_action path-predicate appends.
# Boost-only: a missing `url` (the default-kwarg test convention) skips the pass
# entirely, so every pinned arithmetic / reason-chain test stays byte-identical.
_FULL_URL_REGEX_BUCKETS: tuple[str, ...] = ("cloud_metadata", "object-storage")

_regex_fragment_cache: dict[str, "re.Pattern[str]"] = {}


def regex_fragment_in_path(pattern: str, url_path_lower: str) -> bool:
    """True when the raw regex `pattern` (its own anchoring) matches the path."""
    rx = _regex_fragment_cache.get(pattern)
    if rx is None:
        rx = re.compile(pattern)
        _regex_fragment_cache[pattern] = rx
    return rx.search(url_path_lower) is not None


# Producer `type` → (floor_bucket, floor_weight) table (§2.1, override #4). The
# producer `type` is otherwise discarded for non-inert rows; the floor makes it
# a first-class input. When a row matches NO bucket, a floor (if its type is
# present) sets cluster_key = `gf:<floor_bucket>` (NOT the path:* fallback) so
# specialist routing still fires. When a bucket DID match, the floor only raises
# the score (never the routing) via `max(match, floor)`. `api_spec` is a
# label-only floor bucket (no `_BUCKETS` entry) — like `interestingext` is used
# as the sourcemap cluster label.
#
# PRODUCER-VOCABULARY ALIGNMENT (do not let this silently drift). The keys here
# MUST match the types the producer actually emits, NOT plan-invented names.
# There are TWO producer typing paths and they emit DIFFERENT spellings of the
# same semantic type:
#
#   * `assess.lib.classify.classify_type()` — the dominant categorizer that every
#     ingest path (ingest-endpoints / ingest-spec / ingest-candidates / dispatch)
#     runs. It emits the canonical, content-derived types: `api` (the dominant
#     API type — 1,002 rows in the nested route fixtures, 92 in the consumer-service
#     corpus), `api-spec` (HYPHEN — the
#     OpenAPI/Swagger/api-docs type), `graphql`, `sourcemap`, `host_root`, etc.
#   * `assess.lib.candidate_records.candidate_type()` — a SECONDARY signal-driven
#     path that RELABELS `api` → `api_route` (underscore) and adds the
#     surface-flavored types `auth_entry`, `portal_session`, `debug_config`,
#     `event_feed`, `workflow`. These are the minority types (e.g. 41 `api_route`
#     in the nested route fixtures) layered on top of the `classify_type` output.
#
# Therefore:
#   * `api` and `api_route` are the SAME semantic type (api_route is just
#     candidate_type's relabel of api) → both floor to `gf:api` at weight 20.
#   * `api-spec` (hyphen, real) and `api_spec` (underscore) are pure
#     hyphen/underscore SPELLING DRIFT of one type → both floor to the label-only
#     `gf:api_spec` at weight 40. The underscore form `api_spec` is also the
#     taxonomy key in `vuln_taxonomy.GF_BUCKET_TO_CLASS`, so the FLOOR BUCKET
#     LABEL stays underscore even though the producer emits a hyphen.
#
# Robustness: the lookup normalizes the row's `type` (lowercase + hyphen→
# underscore) via `_normalize_floor_type()` BEFORE indexing this table, so a new
# hyphen/underscore/case variant of an existing type can never silently lose its
# floor again. The table itself is keyed on the NORMALIZED (underscore) form.
# Keep every key below in normalized form (no hyphens, lowercase).
_TYPE_FLOOR: dict[str, tuple[str, int]] = {
    "graphql": ("graphql", 45),
    # api family: `api` (classify_type, dominant) + `api_route`
    # (candidate_type's relabel) are one type → gf:api / 20.
    "api": ("api", 20),
    "api_route": ("api", 20),
    # api-spec family: `api-spec` (classify_type, hyphen) normalizes to
    # `api_spec`; the floor bucket LABEL is the underscore taxonomy key.
    "api_spec": ("api_spec", 40),
    "auth_entry": ("auth", 40),
    "form": ("auth", 30),
    "portal_session": ("auth", 35),
    "debug_config": ("debug_logic", 35),
    "workflow": ("idor", 30),
    "event_feed": ("ssrf", 25),
    # privileged_write (classify-context-and-surface 2026-06, Part 3 §D.16): the
    # `privileged_write` surface_type already exists in SURFACE_TYPE_TO_CLASSES;
    # floor a row a producer typed `privileged_write` to the `privileged_action`
    # bucket (the bfla surface added in Phase 2a) at weight 30 so it routes to the
    # bfla specialist even when no state-verb path predicate / param key fired.
    "privileged_write": ("privileged_action", 30),
}


def _normalize_floor_type(case_type: str) -> str:
    """Normalize a producer `type` for the `_TYPE_FLOOR` lookup ONLY.

    Lowercases and unifies hyphen/underscore so producer spelling drift (the
    real `api-spec` hyphen vs the `api_spec` underscore floor key, or any future
    case/separator variant) cannot silently drop a row's floor. This is applied
    EXCLUSIVELY at the floor-lookup site — the inert/sourcemap/host_root
    early-returns above compare against their own (already-lowercased) literals
    and are deliberately NOT routed through this, so the floor stage's normalize
    cannot perturb that precedence. `case_type` is expected pre-lowercased by the
    caller; the `.lower()` here is a belt-and-suspenders guard for direct callers.
    """
    return case_type.lower().replace("-", "_")


# Canonical UUID and long-hex (Mongo ObjectId / SHA prefix) segment shapes,
# reused by both the raw path-object-ref predicate (§4) and the cluster-key
# normalizer (§5). Compiled here so neither call site re-compiles per row.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{24,}$")
_YEAR_RE = re.compile(r"^(?:19|20)[0-9]{2}$")
_NUMERIC_RE = re.compile(r"^[0-9]+$")
# Opaque app token: starts with a lowercase letter, contains at least one digit
# (e.g. `M0004`, `G0058` after lowercasing). The len >= 5 guard lives at the
# call site in `_normalize_cluster_segment`. Used only by the cluster normalizer (§5).
_OPAQUE_TOKEN_RE = re.compile(r"^[a-z][0-9a-z]*[0-9][0-9a-z]*$")
# Literal pre-normalized template placeholders (override #5): `{id}`,`{uuid}`,
# `{n}` (case-insensitive on the word; braces literal).
_PLACEHOLDER_TOKENS = frozenset({"{id}", "{uuid}", "{n}"})


def _is_object_ref_segment(seg: str) -> bool:
    """True if a RAW lowercased path segment is an object-ref candidate (§4.1).

    UUID, long-hex, a placeholder token, or a numeric that survives the
    precision predicates (§4.2: year-excluded, not a bare 1-digit small-int).
    """
    if seg in _PLACEHOLDER_TOKENS:
        return True
    if _UUID_RE.match(seg) or _LONG_HEX_RE.match(seg):
        return True
    if _NUMERIC_RE.match(seg):
        if _YEAR_RE.match(seg):
            return False  # 4-digit year 1900..2099 is not an object ref
        if len(seg) == 1:
            return False  # bare 1-digit small-int (pagination/ordinal noise)
        return True
    return False


def _is_context_segment(seg: str) -> bool:
    """True if a RAW lowercased path segment can serve as collection context
    (§4.2): a >=2-char word that is NOT itself an object-ref candidate. Short
    prefixes like `efi`,`v2`,`wps` DO count (override #5)."""
    if len(seg) < 2:
        return False
    return not _is_object_ref_segment(seg)


def path_has_object_ref(url_path_lower: str) -> bool:
    """True if the RAW lowercased path embeds an object reference (§4).

    Fires iff there EXISTS an object-ref segment preceded somewhere earlier in
    the SAME path by at least one collection-context segment. This rejects a
    LONE id with no context (`/2024/`, `/{n}/`, `/12345`) while accepting real
    short-prefixed IDOR (`/efi/{id}`, `/v2/{id}`, `/api/users/1024/profile`).
    Runs on the RAW url only — normalization (§5) is NEVER consulted here
    (override #6).
    """
    segments = [s for s in url_path_lower.split("/") if s]
    seen_context = False
    for seg in segments:
        if _is_object_ref_segment(seg):
            if seen_context:
                return True
            # An object-ref segment is never itself counted as context for a
            # later id; fall through without flipping seen_context.
            continue
        if _is_context_segment(seg):
            seen_context = True
    return False


# Privileged-action verb SEGMENTS (classify-context-and-surface 2026-06, Part 3
# §A.9). State-change verbs that, as a standalone path segment, signal a
# function-level-authz / business-logic surface. Stored as the segment form (no
# leading slash) since `path_has_privileged_action` matches against
# `url_path.split("/")` segments — so `/assume-role/...` matches the
# `"assume-role"` segment exactly, while the boundary-anchored `fragment_in_path`
# semantics (which the predicate does NOT use) are unnecessary here.
_PRIVILEGED_ACTION_VERBS: frozenset[str] = frozenset({
    "grant", "revoke", "approve", "reject", "impersonate", "transfer",
    "sendotp", "promote", "setrole", "disable", "deactivate", "sudo",
    "assume-role",
})
# A bare version path segment (`v1`,`v2`,...). Together with a literal `api`
# segment this is the API-route precision sibling that distinguishes a real
# privileged endpoint from a content slug. (Distinct from the `api-versioning`
# regex bucket rule, which matches the version segment WITHIN a path string; this
# one is anchored to a SINGLE already-split segment.)
_API_VERSION_SEG_RE = re.compile(r"^v[0-9]+$")


def path_has_privileged_action(url_path_lower: str) -> bool:
    """True if the RAW lowercased path embeds a state-change verb SEGMENT that is
    GUARDED by an API/version sibling segment or an embedded object reference (§A.9).

    Precision override (documented in the `privileged_action` `_BUCKETS` comment):
    a state-change verb alone is NOT enough — a bare content page such as
    `/transfer` (no API/version sibling, no object-ref) or the hyphenated content
    slug `/transfer-your-number` (whose single segment is not the bare verb) does
    NOT fire. A verb co-occurring with an `api`/`v<n>` sibling (`/api/users/grant`,
    `/v2/accounts/transfer`) or with a path object-ref (`/users/1024/revoke`) DOES.
    Runs on the RAW url only — normalization (§5) is never consulted here.
    """
    segments = [s for s in url_path_lower.split("/") if s]
    if not any(seg in _PRIVILEGED_ACTION_VERBS for seg in segments):
        return False
    has_api_sibling = any(
        seg == "api" or _API_VERSION_SEG_RE.match(seg) for seg in segments
    )
    if has_api_sibling:
        return True
    return path_has_object_ref(url_path_lower)


BUCKET_SKILLS: dict[str, tuple[str, ...]] = vuln_taxonomy.derive_bucket_skills()


# Types that carry no exploitable surface on their own.
#
# This frozenset is the SINGLE SOURCE OF TRUTH for "inert" work-item types
# across the codebase. Every consumer that needs the same set imports
# `INERT_TYPES` from this module:
#
# - the ingest producers (`ingest_endpoints`/`ingest_candidates`/`ingest_spec`,
#   the proxy addon) read it to set `status='skipped'` in the work_item block
#   they POST, so inert rows never enter the dispatch queue.
# - `agent/scripts/assess/lib/classify_buckets.py:classify_row()` (this file)
#   reads it to stamp `terminal_reason='inert_type'` so `fetch-by-priority`
#   excludes them with one predicate.
# - `agent/scripts/assess/commands/dispatch/work_items.py` reads it to scope the
#   `--reclassify-all` WHERE clause to the same set the inline classifier
#   skips on insert.
# Adding a new inert type means editing this one place — every consumer
# picks it up automatically. Hand-maintained copies in any of those files
# are a drift hazard.
INERT_TYPES: frozenset[str] = frozenset(
    {"image", "video", "font", "archive", "manifest"}
)

# Backwards-compatible alias for the previous private name; new code should
# import the public `INERT_TYPES` symbol above.
_INERT_TYPES = INERT_TYPES


# ---------------------------------------------------------------------------- #
# Classifier version stamp (reclassification staleness).
#
# `CLASSIFIER_VERSION` is a short, cross-process-DETERMINISTIC digest of EVERY
# module-level table/constant that `classify_row` (and the helpers it calls)
# reads to produce a row's `priority_score` / `cluster_key` / `priority_reason`
# / `terminal_reason` / `matched_buckets`. That is NOT just the four headline
# tables (`_BUCKETS`, `_REGEX_BUCKET_RULES`, `_TYPE_FLOOR`, `INERT_TYPES`): it
# also covers the path-predicate signals (`_PRIVILEGED_ACTION_VERBS`,
# `_FULL_URL_REGEX_BUCKETS`, the object-ref / api-version / cluster regexes and
# `_PLACEHOLDER_TOKENS` / `_CLUSTER_PLACEHOLDERS`), the boost-only context tables
# (`_NONPROD_HOST_LABEL_RE`, `_NONDEFAULT_PORTS`, `_LIVE_STATUS_TOKENS`), the
# weak-token cap / fragment boundary / camelCase splitter, the SAML-auth
# fragments, the upload-shadow set, AND a hand-maintained `_CLASSIFIER_LOGIC_REVISION`
# integer that maintainers MUST bump for any `classify_row` LOGIC change not
# captured by one of those data tables (e.g. an edit to the +15/+5 context
# weights or a branch reordering). Constants DERIVED from `_BUCKETS` via `next(...)`
# (`_IDOR_WEIGHT`, `_PRIVILEGED_ACTION_WEIGHT`, `_INTERESTINGEXT_WEIGHT`,
# `_AUTH_KEY_SET`, `_SSO_PATH_FRAGMENTS`) are covered transitively — they cannot
# change without `_BUCKETS` itself changing — so they are not re-listed.
# the ingest producers stamp it inline at ingest and
# `work-buffer reclassify` re-stamps it on every re-classification, so a later
# `work-buffer reclassify --reclassify-stale` can tell rows scored under an OLD taxonomy
# from rows already at the current one — restamping only the stale
# ones instead of the all-or-nothing `--reclassify-all`. A taxonomy edit to ANY
# of the above tables bumps the digest so `--reclassify-stale` picks up the rows
# it changes; keeping this input set complete is what makes that guarantee hold.
#
# DETERMINISM IS LOAD-BEARING (do not "simplify" this). The digest MUST be
# identical across separate Python processes (the ingest process and the
# `--reclassify-stale` process compute it independently); if it were not, every
# row would always look stale and every run would reclassify the whole corpus.
# That rules out `repr(frozenset(...))`, `str(set(...))`, and the builtin
# `hash()` — all three are PYTHONHASHSEED-randomized, so their output varies run
# to run. The same trap is documented at
# `src/vigil_cli/bench/factory/axes.py:116` (blake2s chosen over `hash()` for
# exactly this reason).
#
# We instead CANONICALIZE the input: recursively turn every set/frozenset into a
# SORTED list (order-independent), leave tuples/lists in declaration order
# (order IS meaningful for `_BUCKETS` tie-breaks), sort dict keys, then hash the
# `sort_keys=True` JSON. A comment/refactor edit that does not change the tables
# leaves the digest byte-identical; a real taxonomy edit (new bucket, changed
# weight, new inert type, new regex rule) bumps it.
def _canonicalize(obj: Any) -> Any:
    """Return a JSON-serializable, order-canonical mirror of ``obj``.

    Sets/frozensets → sorted lists (membership, not iteration order, is what
    matters). Dicts → key-sorted dicts with canonicalized values. Tuples/lists
    → lists with canonicalized elements, order PRESERVED (declaration order is
    semantically significant for `_BUCKETS`). Compiled ``re.Pattern`` objects →
    their source `.pattern` string (a bare Pattern is NOT JSON-serializable and
    would crash `json.dumps`; the digest inputs pass `.pattern` explicitly, but
    this keeps a stray Pattern from silently breaking the stamp). Scalars pass
    through unchanged.
    """
    if isinstance(obj, re.Pattern):
        return obj.pattern
    if isinstance(obj, (set, frozenset)):
        return sorted(_canonicalize(item) for item in obj)
    if isinstance(obj, dict):
        return {key: _canonicalize(value) for key, value in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(item) for item in obj]
    return obj


# `_CLASSIFIER_VERSION_INPUTS` and `CLASSIFIER_VERSION` are assembled at the END
# of this module (see "Classifier version stamp — digest assembly" below): the
# input set intentionally spans tables/regexes/scalars declared throughout the
# file (context tables, weak-token cap, cluster placeholders, ...), so
# the dict cannot be built here without forward-referencing names that do not
# exist yet. `_canonicalize` (above) is the only piece needed at this point.

# Sentinel `classifier_version` value for rows an operator has hand-tuned. It is
# NOT a real digest, so it never equals `CLASSIFIER_VERSION` and is protected
# from `--reclassify-stale` (which excludes it explicitly). `work-buffer
# mark-manual <id>` stamps it; `--reclassify-all` is the only path that
# overwrites it. Single source of truth so `dispatch/work_items.py` and the
# `mark-manual` verb reference the same string.
MANUAL_CLASSIFIER_VERSION: str = "manual"


# Structured reason tags for deferred/skipped work items. SINGLE SOURCE OF TRUTH
# for the skip vocabulary so `defer-cluster`/`defer-items`, `work-buffer stats
# --by reason`, and any future gate read the same set. The stored value is
# ``skipped:<tag> | <free text>`` (or just ``skipped:<tag>``), which de-overloads
# the `skipped` terminal state: a query can now distinguish a correct exclusion
# (out-of-scope/blackholed/dead/low-signal/duplicate/egress) from a bare,
# un-reasoned drop. ``out-of-scope`` is stamped at ingest by `ingest-endpoints`
# on a URL whose host is not admitted by scope.json — a reachable-but-
# unauthorized host (gau/wayback historical URLs routinely surface these) is
# recorded skipped instead of admitted to the work buffer.
SKIP_REASON_TAGS: frozenset[str] = frozenset(
    {
        "already-covered",
        "out-of-scope",
        "blackholed",
        "dead-host",
        "low-signal-cluster",
        "duplicate",
        "egress-blocked",
    }
)


def tagged_terminal_reason(tag: str, detail: str = "") -> str:
    """Build a structured ``terminal_reason`` from a reason tag + free-text detail."""
    tag = (tag or "").strip()
    detail = (detail or "").strip()
    prefix = f"skipped:{tag}" if tag else ""
    if prefix and detail:
        return f"{prefix} | {detail}"
    return prefix or detail


def reason_tag_of(terminal_reason: str | None) -> str:
    """Return the structured reason tag from a terminal_reason value.

    - ``inert_type`` → ``inert_type`` (auto-skipped at ingest).
    - ``skipped:<tag> | ...`` → ``<tag>``.
    - empty → ``""`` (no terminal reason).
    - any other free text → ``"untagged"`` (a legacy/un-reasoned defer — the
      exact state worth surfacing as "dropped without a machine-readable reason").
    """
    tr = (terminal_reason or "").strip()
    if not tr:
        return ""
    if tr == "inert_type":
        return "inert_type"
    if tr.startswith("skipped:"):
        head = tr.split("|", 1)[0].strip()
        return head[len("skipped:"):].strip() or "untagged"
    return "untagged"

_UPLOAD_GENERIC_SHADOWS = frozenset({"lfi", "idor"})

_INTERESTINGEXT_WEIGHT: int = next(
    weight for name, weight, _, _ in _BUCKETS if name == "interestingext"
)


# Context-scoring layer (classify-context-and-surface 2026-06, Part 4 "Fix 1";
# Issues 1/E/F/G). The classifier historically discarded the row's URL
# authority, ingest `source`, and `live_status` before scoring, so a `host_root`
# landing URL on a `dev.`/`admin.`/`internal.` host scored a hard 0 (677 such
# rows) and a non-default management port (`:9443` Keycloak, 8,034 distinct
# non-default authorities) played no role. `_context_bonus` reintroduces those
# signals as a STRICTLY BOOST-ONLY layer: it returns a non-negative integer that
# is applied as `priority_score = max(base, base + bonus)` on the relevant return
# branches, so an absent/zero context can NEVER lower a score and a default
# (no-kwargs) call stays byte-identical to the pre-context output. The bonus
# touches ONLY `priority_score` — never `cluster_key`, `priority_reason`,
# `terminal_reason`, or `matched_buckets`. It is GENERIC: only nonprod/admin host
# *labels*, well-known non-default ports, and source/liveness signals — no
# product/host/path literal.
#
# Host-label regex (boundary-anchored on the authority's host labels): a label
# token like `dev`/`qa`/`stage`/`admin` must sit at a `.`/`-` boundary so
# `dev.example.com`, `api-qa.example.com`, and `admin.corp.example.com` match
# while `development.example.com` (no boundary after `dev`) does NOT.
_NONPROD_HOST_LABEL_RE = re.compile(
    r"(^|[.-])(dev|qa|test|stage|staging|uat|sit|preprod|nonprod|internal|"
    r"intranet|admin|sandbox|dr|corp)([.-]|$)"
)
# Well-known non-default management / dev-server ports.
_NONDEFAULT_PORTS: frozenset[str] = frozenset(
    {"8080", "8443", "9443", "8000", "8888", "7001", "9000", "5000"}
)
# Live-status tokens that indicate a reachable surface (vs a dead/archive URL).
_LIVE_STATUS_TOKENS: frozenset[str] = frozenset({"live", "200"})

def _context_bonus(
    url: str | None = None,
    source: str | None = None,
    live_status: str | None = None,
) -> int:
    """Return a STRICTLY non-negative context score bonus (Fix 1, boost-only).

    Sums, independently (each signal stacks):
      * +15 when the URL authority's host matches the nonprod/admin/internal
        host-label regex;
      * +5  when the URL authority carries a well-known non-default port;
      * +5  when `source` is `source-analysis` or a `*-js-extract` producer;
      * +5  when `live_status` is `live`/`200`.

    The host/port signals are read from the FULL `url` authority (not the
    url_path); when `url` is None/blank both are 0. The return value is always
    `>= 0`, so callers can apply `max(base, base + bonus)` without ever lowering
    a bucket-driven score.
    """
    bonus = 0
    if url:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            host, port = "", None
        if host and _NONPROD_HOST_LABEL_RE.search(host):
            bonus += 15
        if port is not None and str(port) in _NONDEFAULT_PORTS:
            bonus += 5
    if source:
        s = source.strip().lower()
        if s == "source-analysis" or s.endswith("-js-extract"):
            bonus += 5
    if live_status:
        ls = str(live_status).strip().lower()
        if ls in _LIVE_STATUS_TOKENS:
            bonus += 5
    return bonus


def classify_row(
    row: sqlite3.Row,
    *,
    url: str | None = None,
    source: str | None = None,
    live_status: str | None = None,
) -> dict[str, Any]:
    """Return the per-row assignment dict (always present, never None).

    Inert types (image/video/font/archive/manifest) are stamped with
    `terminal_reason='inert_type'` so `fetch-by-priority` can skip them with a
    single predicate. For every other row the highest-weight matching bucket
    wins; the path fallback gives operators a coarse grouping when no bucket
    fires.

    Context is boost-only. Bucket-less rows use the ordinary ``path:*`` fallback;
    source/liveness context never demotes or terminally skips them.
    """
    case_type = (row["type"] or "").lower()
    if case_type in _INERT_TYPES:
        return {
            "priority_score": 0,
            "priority_reason": None,
            "cluster_key": f"type:{case_type}",
            "terminal_reason": "inert_type",
            "matched_buckets": [],
            "secondary_buckets": [],
        }

    if case_type == "sourcemap":
        return {
            "priority_score": _INTERESTINGEXT_WEIGHT,
            "priority_reason": "gf:interestingext",
            "cluster_key": "gf:interestingext",
            "terminal_reason": None,
            "matched_buckets": ["interestingext"],
            "secondary_buckets": [],
        }

    # Boost-only context layer (Fix 1). Computed AFTER the inert/sourcemap
    # early-returns (those stay fixed — they never receive the bonus) and BEFORE
    # host_root so the nonprod/admin/internal host_root rows can be rescued from
    # a hard 0. `bonus >= 0` always, so every `max(base, base + bonus)` below is
    # boost-only and a default (no-context) call stays byte-identical.
    bonus = _context_bonus(url, source, live_status)

    if case_type == "host_root":
        # A bare scheme://host[/] landing URL: no exploitable surface on its own,
        # but a Phase-2 crawl seed. Stamp a stable, greppable cluster so the
        # operator can see "N hosts await crawling" instead of it hiding among
        # unrouted `unknown` / `path:/` rows. NOT inert — it must stay `pending`,
        # not be skipped, so it is never silently dropped. The context bonus
        # rescues nonprod/admin/internal host_root rows (e.g. a `dev.` host →
        # 15) from priority 0 WITHOUT changing the stable `type:host_root`
        # cluster.
        return {
            "priority_score": max(0, 0 + bonus),
            "priority_reason": None,
            "cluster_key": "type:host_root",
            "terminal_reason": None,
            "matched_buckets": [],
            "secondary_buckets": [],
        }

    url_path = row["url_path"] or ""
    url_path_lower = url_path.lower()
    keys = collect_keys(row["query_params"], row["body_params"], row["path_params"])
    matches = bucket_matches(url_path_lower, keys)

    # SSO-route disambiguation (matrix W8 vs W10/X3/A7). On an SSO ROUTE
    # (`/sso/...`) the generic auth `/login`/`/signin` suffix is part of the SSO
    # entry, not a standalone auth surface — so `gf:auth` must not fire there
    # (W8 pins cluster `gf:sso` AND score 35, i.e. auth fully absent). But auth
    # still wins when it fired via a real SAML-auth compound (`/saml/acs`,
    # `/saml/sso` — X3, A7) or via an auth PARAM key (W10's SAMLResponse lands on
    # a `/login` page → auth wins). So: drop auth IFF an sso PATH fragment fired,
    # the path has no `/saml/acs`|`/saml/sso`, and no auth param key fired.
    matches = _suppress_auth_on_sso_route(matches, url_path_lower, keys)

    # Path-embedded object references (`/users/1024/profile`, `/files/<uuid>`,
    # `/efi/{id}`) carry an IDOR surface even when no query/body parameter names
    # an id — the identifier lives in a path segment the param-key buckets cannot
    # see. `path_has_object_ref` runs on the RAW url only (§4 / override #6) with
    # precision predicates (year/small-int exclusion, collection-noun gate). If
    # it fires, route the row to the idor specialist too, deduped against an
    # existing key-based idor match so the reason chain never lists `gf:idor`
    # twice.
    if path_has_object_ref(url_path_lower) and not any(
        name == "idor" for name, _ in matches
    ):
        matches.append(("idor", _IDOR_WEIGHT))

    # Privileged-action surfaces (`/api/users/grant`, `/users/1024/revoke`): a
    # state-change verb segment guarded by an API/version sibling or an embedded
    # object reference (§A.9). Appended via the dedicated `path_has_privileged_action`
    # predicate — exactly like the idor path-object-ref append above — rather than
    # a naive path fragment, so a content slug (`/transfer-your-number`, a bare
    # `/transfer` page) cannot fire it. Deduped against any existing
    # `privileged_action` match: `bucket_matches` now CAN produce one (the bucket
    # gained a state-verb param-key set in Part 6 — `?delete=`/`?grant=`), so this
    # guard keeps the reason chain single-entry when both the path predicate and a
    # param key fire on the same row.
    if path_has_privileged_action(url_path_lower) and not any(
        name == "privileged_action" for name, _ in matches
    ):
        matches.append(("privileged_action", _PRIVILEGED_ACTION_WEIGHT))

    # Full-URL regex buckets (§B.10 cloud_metadata / §C.14 object-storage host
    # markers). Their match signal lives in the URL authority or query string,
    # which `bucket_matches` (url_path only) cannot see, so re-test their
    # `_REGEX_BUCKET_RULES` against the FULL `url` here and append (deduped against
    # a url_path-side hit). Declaration-ordered over `_BUCKETS` so the appended
    # entries keep a stable reason-chain order. Boost-only: skipped entirely when
    # `url` is absent (the default-kwarg test convention), so a no-context call is
    # byte-identical. An appended bucket can only RAISE the score / add a chain
    # entry; like every weight-driven match it never reorders the existing chain.
    if url:
        url_lower = url.lower()
        for name, weight, _key_set, _path_fragments in _BUCKETS:
            if name not in _FULL_URL_REGEX_BUCKETS:
                continue
            if any(existing == name for existing, _ in matches):
                continue
            rules = _REGEX_BUCKET_RULES.get(name)
            if rules and any(
                regex_fragment_in_path(rule, url_lower) for rule in rules
            ):
                matches.append((name, weight))

    # Producer-`type` floor (§2.2, override #4). Applied AFTER the
    # inert/sourcemap/host_root early-returns (those still win above). The floor
    # NEVER lowers a bucket-driven score (`score = max(match, floor)`); when a
    # bucket matched it only raises the number, not the routing. The lookup key
    # is normalized (lowercase + hyphen→underscore) so the producer's real
    # `api-spec` (hyphen) and the `api`/`api_route` spellings all resolve to
    # their intended floor — see `_TYPE_FLOOR`'s producer-vocabulary note.
    floor = _TYPE_FLOOR.get(_normalize_floor_type(case_type))
    floor_weight = floor[1] if floor else 0

    # Compound-key inner-token ("weak") matches (Fix 4, landed as a TIERED signal).
    # A param named `return_url` / `targetServer` / `cmd_exec` carries bucket
    # signal in its inner tokens, but an inner token is WEAKER evidence than a
    # whole key (see `WEAK_TOKEN_CAP` / `_weak_token_matches`). Computed once here
    # and used two ways below, NEVER overriding a strong match:
    #   * on a strong/floor row -> `secondary_buckets` (extra coverage routing so a
    #     `?id=` + `?return_url=` row reaches BOTH the sqli and redirect specialists)
    #     WITHOUT touching cluster_key / priority_reason / priority_score /
    #     matched_buckets, so every pinned strong/floor row is byte-identical;
    #   * when NO strong bucket and NO floor fired -> the weak match RESCUES the row
    #     from the score-0 `path:*` fallback (deep coverage: a real `?return_url=`
    #     surface is never left invisible). Precise routing for the COMMON compound
    #     families is delivered by the curated whole-key members on `redirect`/`ssrf`
    #     (strong path), so those never reach the weak rescue.
    weak_matches = _weak_token_matches(
        collect_weak_tokens(
            row["query_params"], row["body_params"], row["path_params"]
        )
    )
    weak_names: list[str] = []
    for name, _ in weak_matches:
        if name not in weak_names:
            weak_names.append(name)

    if matches:
        best_weight = max(weight for _, weight in matches)
        top_buckets = [name for name, weight in matches if weight == best_weight]
        best_name = select_cluster_bucket(case_type, matches, top_buckets[0])
        reason = "+".join(f"gf:{name}" for name, _ in matches)
        matched_buckets: list[str] = []
        for name, _ in matches:
            if name not in matched_buckets:
                matched_buckets.append(name)
        base_score = max(best_weight, floor_weight)
        return {
            "priority_score": max(base_score, base_score + bonus),
            "priority_reason": reason,
            "cluster_key": f"gf:{best_name}",
            "terminal_reason": None,
            "matched_buckets": matched_buckets,
            "secondary_buckets": [n for n in weak_names if n not in matched_buckets],
        }

    if floor:
        # NO bucket matched but a floor fires: cluster as `gf:<floor_bucket>`
        # (NOT path:* — override #4) so specialist routing / the 2b coverage
        # bridge / fetch-by-priority still route the row.
        floor_bucket = floor[0]
        return {
            "priority_score": max(floor_weight, floor_weight + bonus),
            "priority_reason": f"gf:{floor_bucket}",
            "cluster_key": f"gf:{floor_bucket}",
            "terminal_reason": None,
            "matched_buckets": [floor_bucket],
            "secondary_buckets": [n for n in weak_names if n != floor_bucket],
        }

    if weak_matches:
        # Inner-token RESCUE: no strong bucket and no floor fired, but a compound
        # key's inner token matched. Promote the row out of the score-0 `path:*`
        # fallback so the surface is triaged instead of dropped. Weights are capped
        # (`WEAK_TOKEN_CAP`) so these guessed matches rank below confirmed strong
        # matches across the buffer. Declaration-ordered tie-break (first weak
        # bucket at the max capped weight) mirrors the strong path.
        best_weak = max(weight for _, weight in weak_matches)
        top_weak = next(name for name, weight in weak_matches if weight == best_weak)
        reason = "+".join(f"gf:{name}" for name, _ in weak_matches)
        return {
            "priority_score": max(best_weak, best_weak + bonus),
            "priority_reason": reason,
            "cluster_key": f"gf:{top_weak}",
            "terminal_reason": None,
            "matched_buckets": weak_names,
            "secondary_buckets": [],
        }

    # Bucket-less, floor-less, weak-less fallback. Context remains boost-only:
    # no source or liveness value can lower the score or stamp a terminal skip.
    return {
        "priority_score": max(0, 0 + bonus),
        "priority_reason": None,
        "cluster_key": f"path:{normalize_path_for_cluster(url_path)}",
        "terminal_reason": None,
        "matched_buckets": [],
        "secondary_buckets": [],
    }


def select_cluster_bucket(
    case_type: str,
    matches: list[tuple[str, int]],
    default_name: str,
) -> str:
    """Choose the cluster bucket, with a narrow upload-specific override.

    Multipart rows commonly use generic field names such as `file` or
    `document`, which also appear in LFI/IDOR patterns. Keep those generic
    buckets for ordinary requests, but cluster true upload rows as
    `upload_fields` when the only winner is one of those generic overlaps.
    Higher-risk buckets such as RCE/SSRF/SQLi still win normally.
    """
    if (
        case_type == "upload"
        and default_name in _UPLOAD_GENERIC_SHADOWS
        and any(name == "upload_fields" for name, _ in matches)
    ):
        return "upload_fields"
    return default_name


def collect_keys(*columns: str | None) -> set[str]:
    """Collect lowercased parameter keys across JSON-encoded columns."""
    keys: set[str] = set()
    for raw in columns:
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(decoded, dict):
            continue
        for k in decoded.keys():
            keys.update(expand_compound_key(str(k).lower()))
    return keys


def expand_compound_key(key: str) -> set[str]:
    """Expand a single parameter key into its STRONG matchable tokens.

    Forms (e.g., search frameworks) commonly send compound keys like
    `filter[user][id]` or `data.user.id`. We split on `.` / `[` / `]` so the
    inner tokens (`filter`, `user`, `id`, `data`) all participate in bucket
    matching alongside the original.

    Splits ONLY on `.` / `[` / `]` by design — these are structural framework
    delimiters where the inner token IS the parameter, so the inner token is
    full-strength evidence (e.g. `username[$ne]` -> `$ne` for nosqli). The
    weaker `_` / `-` / camelCase compounds (`return_url`, `returnUrl`) are
    handled separately by `collect_weak_tokens` / `_weak_token_matches` at a
    capped weight (`WEAK_TOKEN_CAP`), because the inner token there is a weaker
    indicator of intent than the whole name (the `url` suffix of `return_url`
    is weaker SSRF signal than a literal `url` param). Keeping this function
    `.[]`-only is what makes the existing pinned reason chains byte-identical.
    """
    tokens = {key}
    for sep in (".", "[", "]"):
        key = key.replace(sep, " ")
    for part in key.split():
        part = part.strip()
        if part:
            tokens.add(part)
    return tokens


# Weight cap for inner-token ("weak") compound-key matches. A param literally
# named `url` is a strong SSRF signal; the `url` SUFFIX of `return_url` is a
# weaker one (the `return` prefix is the real intent). So inner tokens derived
# from `_` / `-` / camelCase splitting are matched separately and capped here —
# below every HIGH-VALUE strong bucket (35-50), so a guessed inner-token hit never
# outranks a confirmed injection/auth/ssrf surface (precision), yet well above 0 so
# a recognizable compound surface is never dropped to score 0 (deep coverage). It
# can sit at or just above the lowest-confidence strong signals (`interestingext`
# =10, `interestingparams`=15, `xss`/`api`=20), which is acceptable — those are
# themselves low-confidence, and weight only orders triage, never gates.
WEAK_TOKEN_CAP = 20

# camelCase boundary: a lower-alnum char immediately followed by an upper char.
# Applied to the ORIGINAL-case key BEFORE lowercasing so `returnUrl` splits into
# `return` / `Url`; `_` and `-` are split afterwards.
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def weak_tokens_for_key(raw_key: str) -> set[str]:
    """Inner tokens of a compound key via `_` / `-` / camelCase split (lowercased).

    `returnUrl` -> {return, url}; `sysparm_url` -> {sysparm, url};
    `glide-sso-id` -> {glide, sso, id}. These are WEAKER evidence than a whole
    key — see `WEAK_TOKEN_CAP` and `_weak_token_matches`.
    """
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", raw_key).replace("_", " ").replace("-", " ")
    return {tok.lower() for tok in spaced.split() if tok}


def collect_weak_tokens(*columns: str | None) -> set[str]:
    """Collect inner ("weak") compound-key tokens across JSON-encoded columns."""
    tokens: set[str] = set()
    for raw in columns:
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(decoded, dict):
            continue
        for k in decoded.keys():
            tokens.update(weak_tokens_for_key(str(k)))
    return tokens


def _weak_token_matches(weak_keys: set[str]) -> list[tuple[str, int]]:
    """Param-key buckets matched by compound inner tokens, at capped weak weight.

    Declaration-ordered over `_BUCKETS` (preserving tie-break / reason-chain
    order). Param-key buckets ONLY — path-only and regex buckets do not take part
    in inner-token rescue. Each weight is capped at `WEAK_TOKEN_CAP`.
    """
    if not weak_keys:
        return []
    out: list[tuple[str, int]] = []
    for name, weight, key_set, _path_fragments in _BUCKETS:
        if key_set and (weak_keys & key_set):
            out.append((name, min(weight, WEAK_TOKEN_CAP)))
    return out


# A literal path fragment must be followed by a segment boundary. `.` is in the
# boundary set so an auth route like `/Login.aspx` (lowercased `/login.aspx`)
# still matches the `/login` fragment (matrix W10), and `.env.local` matches
# `.env`, while `/administration-guide` still does NOT match `/admin` (next char
# `i`) and `/notes.nsfx` does NOT match `.nsf` (next char `x`).
_FRAGMENT_BOUNDARY = r"(?=[/?#=&.]|$)"
_fragment_pattern_cache: dict[str, "re.Pattern[str]"] = {}


def _fragment_pattern(fragment: str) -> "re.Pattern[str]":
    """Return a cached, boundary-anchored regex for a risk path fragment.

    The fragment is matched literally but must be followed by a segment
    boundary, so `/admin` matches `/admin` and `/admin/users` but NOT
    `/administration-guide`, and `.env` matches `/.env` / `/app/.env?x` but NOT
    `.environment`. A trailing slash on the fragment is the boundary itself, so
    it is dropped before anchoring (`/proxy/` → `/proxy` + boundary).
    """
    cached = _fragment_pattern_cache.get(fragment)
    if cached is not None:
        return cached
    core = fragment[:-1] if fragment.endswith("/") and len(fragment) > 1 else fragment
    pattern = re.compile(re.escape(core) + _FRAGMENT_BOUNDARY)
    _fragment_pattern_cache[fragment] = pattern
    return pattern


def fragment_in_path(fragment: str, url_path_lower: str) -> bool:
    """True when `fragment` occurs in `url_path_lower` at a segment boundary."""
    return _fragment_pattern(fragment).search(url_path_lower) is not None


def bucket_matches(url_path_lower: str, keys: set[str]) -> list[tuple[str, int]]:
    """Return matching buckets in declaration order.

    Both a parameter-key hit and a path-fragment hit count as a match. We
    return the full list (rather than just the winner) so callers can record
    the entire classification trail in `priority_reason`.
    """
    matches: list[tuple[str, int]] = []
    for name, weight, key_set, path_fragments in _BUCKETS:
        key_hit = bool(keys & key_set) if key_set else False
        path_hit = any(
            fragment_in_path(fragment, url_path_lower) for fragment in path_fragments
        )
        regex_rules = _REGEX_BUCKET_RULES.get(name)
        rx_hit = bool(regex_rules) and any(
            regex_fragment_in_path(rule, url_path_lower) for rule in regex_rules
        )
        if key_hit or path_hit or rx_hit:
            matches.append((name, weight))
    return matches


# Auth param keys and the SAML-auth compound fragments that keep `auth` winning
# even on an SSO route (see `_suppress_auth_on_sso_route`). Resolved from
# `_BUCKETS` so they cannot drift from the bucket definition.
_AUTH_KEY_SET: frozenset[str] = next(
    key_set for name, _w, key_set, _p in _BUCKETS if name == "auth"
)
_SSO_PATH_FRAGMENTS: tuple[str, ...] = next(
    path_fragments for name, _w, _k, path_fragments in _BUCKETS if name == "sso"
)
_AUTH_SAML_FRAGMENTS: tuple[str, ...] = ("/saml/acs", "/saml/sso")


def _suppress_auth_on_sso_route(
    matches: list[tuple[str, int]],
    url_path_lower: str,
    keys: set[str],
) -> list[tuple[str, int]]:
    """Drop a generic-only `auth` match on an SSO route (matrix W8).

    Returns `matches` unchanged unless ALL hold: `auth` and `sso` both fired, an
    sso PATH fragment fired, the path contains no `/saml/acs`|`/saml/sso`
    SAML-auth compound, and no auth PARAM key fired. In that one case the `auth`
    entry is removed so the row clusters as `gf:sso` (W8) — while X3/A7 (auth via
    `/saml/acs`) and W10 (auth via a SAMLResponse-bearing `/login` page) keep
    `auth`.
    """
    has_auth = any(name == "auth" for name, _ in matches)
    has_sso = any(name == "sso" for name, _ in matches)
    if not (has_auth and has_sso):
        return matches
    sso_path_fired = any(
        fragment_in_path(f, url_path_lower) for f in _SSO_PATH_FRAGMENTS
    )
    if not sso_path_fired:
        return matches  # sso fired only via a param key (W10) → keep auth
    auth_via_saml = any(
        fragment_in_path(f, url_path_lower) for f in _AUTH_SAML_FRAGMENTS
    )
    auth_via_key = bool(keys & _AUTH_KEY_SET)
    if auth_via_saml or auth_via_key:
        return matches  # real auth surface (X3, A7) → keep auth
    return [(name, weight) for name, weight in matches if name != "auth"]


_CLUSTER_PLACEHOLDERS = frozenset({"{id}", "{n}", "{uuid}", "{token}", "{year}"})


def _normalize_cluster_segment(seg: str) -> str:
    """Collapse one path segment to a stable placeholder for cluster keys (§5.1).

    Precedence (first match wins): UUID → `{uuid}`, long-hex → `{id}`, year →
    `{year}`, numeric → `{n}`, opaque app token (len>=5, letter+digit) →
    `{token}`; otherwise lowercased as-is. Operates on a lowercased segment.
    Note: a literal pre-normalized placeholder (`{id}`,`{n}`,`{uuid}`) does not
    match any of these shapes (the braces are not hex/numeric/token chars), so
    it is preserved verbatim — `/{n}/` clusters as `path:/{n}`.
    """
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _LONG_HEX_RE.match(seg):
        return "{id}"
    if _YEAR_RE.match(seg):
        return "{year}"
    if _NUMERIC_RE.match(seg):
        return "{n}"
    if len(seg) >= 5 and _OPAQUE_TOKEN_RE.match(seg):
        return "{token}"
    return seg


def normalize_path_for_cluster(url_path: str) -> str:
    """Build the `path:*` fallback cluster key with id-shaped segments collapsed.

    Used ONLY for the `path:*` fallback (override #6) — NEVER for bucket matching
    or the raw path-object-ref predicate. Collapses numeric / uuid / hex /
    opaque-token / year segments to placeholders so distinct ids and years share
    one cluster (e.g. `/explore-mvps/2024/M0004` and `/explore-mvps/2023/G0058`
    both cluster as `path:/explore-mvps/{year}`). After substitution, runs of
    identical adjacent placeholders are collapsed, then the first two segments
    are joined.
    """
    if not url_path:
        return "/"
    stripped = url_path.strip("/")
    if not stripped:
        return "/"
    normalized: list[str] = []
    prev: str | None = None
    for raw_seg in stripped.split("/"):
        seg = _normalize_cluster_segment(raw_seg.lower())
        if seg in _CLUSTER_PLACEHOLDERS and seg == prev:
            continue  # collapse adjacent identical placeholders
        normalized.append(seg)
        prev = seg
    return "/" + "/".join(normalized[:2])


def normalize_route_template(url_path: str) -> str:
    """Full route template: id-shaped segments collapsed, NO segment truncation.

    Same per-segment id/uuid/hex/year/token collapsing as
    `normalize_path_for_cluster`, but keeps EVERY structural segment instead of
    truncating to the first two. Used for Arjun target dedup, where two distinct
    routes that merely share a 2-segment prefix (e.g. `/api/users/search` and
    `/api/users/export`) must stay SEPARATE targets so hidden-parameter discovery
    runs on both — while id-varied siblings (`/api/users/123/profile`,
    `/api/users/456/profile` -> `/api/users/{n}/profile`) still collapse to one.
    """
    if not url_path:
        return "/"
    stripped = url_path.strip("/")
    if not stripped:
        return "/"
    normalized: list[str] = []
    prev: str | None = None
    for raw_seg in stripped.split("/"):
        seg = _normalize_cluster_segment(raw_seg.lower())
        if seg in _CLUSTER_PLACEHOLDERS and seg == prev:
            continue  # collapse adjacent identical placeholders
        normalized.append(seg)
        prev = seg
    return "/" + "/".join(normalized)


def classify_from_fields(
    *,
    case_type: str,
    url_path: str,
    query_params: str = "{}",
    body_params: str = "{}",
    path_params: str = "{}",
    url: str | None = None,
    source: str | None = None,
    live_status: str | None = None,
) -> dict[str, Any]:
    """Adapter for ingest paths that classify from raw fields (no row yet).

    The ingest producers call this while building the work_item block they POST
    so the backend-derived row carries `priority_score` / `priority_reason` /
    `cluster_key` / `terminal_reason`. Returns the same shape as `classify_row()`.

    `url`/`source`/`live_status` are the optional boost-only context inputs
    (Fix 1). They default to None so the legacy 5-keyword call convention (and
    every pinned arithmetic test) stays byte-identical: with no context the
    `_context_bonus` is 0 and `max(base, base + 0) == base`.

    """
    fake_row: dict[str, Any] = {
        "type": case_type,
        "url_path": url_path,
        "query_params": query_params,
        "body_params": body_params,
        "path_params": path_params,
    }
    return classify_row(
        fake_row,
        url=url,
        source=source,
        live_status=live_status,
    )


# ---------------------------------------------------------------------------- #
# Classifier version stamp — digest assembly.
#
# Assembled here, at the module's end, because a complete `classify_row` digest
# must reference constants declared throughout the file (the context tables,
# `WEAK_TOKEN_CAP`, `_CLUSTER_PLACEHOLDERS`, `_AUTH_SAML_FRAGMENTS`, ...).
# See the "Classifier version stamp" comment near `_canonicalize` for the intent
# and the determinism contract. Every entry below is a classification-affecting
# module-level constant; compiled `re.Pattern` values are digested via their
# `.pattern` source string (a bare Pattern is not JSON-serializable). Constants
# derived from `_BUCKETS` (`_IDOR_WEIGHT`, `_PRIVILEGED_ACTION_WEIGHT`,
# `_INTERESTINGEXT_WEIGHT`, `_AUTH_KEY_SET`, `_SSO_PATH_FRAGMENTS`) are covered
# transitively by `buckets` and deliberately not re-listed.

# Hand-maintained logic-revision counter. BUMP THIS whenever you change
# `classify_row` / `_context_bonus` / a classification helper in a way NOT
# captured by one of the data tables digested below — e.g. editing the +15/+5
# context-bonus weights, reordering the return branches, or adding a new scalar
# literal to the scoring logic. It is the escape hatch that keeps the stamp from
# silently falling out of sync with a pure-logic edit; a data-table edit already
# bumps the digest on its own, so this only needs a bump for logic-only changes.
_CLASSIFIER_LOGIC_REVISION: int = 1

_CLASSIFIER_VERSION_INPUTS: dict[str, Any] = {
    # Headline bucket / floor / inert tables.
    "buckets": _BUCKETS,
    "regex_bucket_rules": _REGEX_BUCKET_RULES,
    "type_floor": _TYPE_FLOOR,
    "inert_types": INERT_TYPES,
    # Path-predicate signals (`classify_row` appends these directly).
    "privileged_action_verbs": _PRIVILEGED_ACTION_VERBS,
    "full_url_regex_buckets": _FULL_URL_REGEX_BUCKETS,
    "auth_saml_fragments": _AUTH_SAML_FRAGMENTS,
    "upload_generic_shadows": _UPLOAD_GENERIC_SHADOWS,
    # Object-ref / cluster-normalization tables + regexes.
    "placeholder_tokens": _PLACEHOLDER_TOKENS,
    "cluster_placeholders": _CLUSTER_PLACEHOLDERS,
    "uuid_re": _UUID_RE.pattern,
    "long_hex_re": _LONG_HEX_RE.pattern,
    "year_re": _YEAR_RE.pattern,
    "numeric_re": _NUMERIC_RE.pattern,
    "opaque_token_re": _OPAQUE_TOKEN_RE.pattern,
    "api_version_seg_re": _API_VERSION_SEG_RE.pattern,
    # Weak-token rescue: cap + camelCase splitter + fragment boundary.
    "weak_token_cap": WEAK_TOKEN_CAP,
    "camel_boundary_re": _CAMEL_BOUNDARY_RE.pattern,
    "fragment_boundary": _FRAGMENT_BOUNDARY,
    # Boost-only context layer (`_context_bonus`).
    "nonprod_host_label_re": _NONPROD_HOST_LABEL_RE.pattern,
    "nondefault_ports": _NONDEFAULT_PORTS,
    "live_status_tokens": _LIVE_STATUS_TOKENS,
    # Logic-revision escape hatch (see above).
    "logic_revision": _CLASSIFIER_LOGIC_REVISION,
}
CLASSIFIER_VERSION: str = hashlib.sha256(
    json.dumps(_canonicalize(_CLASSIFIER_VERSION_INPUTS), sort_keys=True).encode("utf-8")
).hexdigest()[:12]
