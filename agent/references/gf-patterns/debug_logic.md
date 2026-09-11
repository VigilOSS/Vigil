---
name: gf-patterns:debug_logic
description: Privileged, admin, and debug path patterns that signal exposed management surface
origin: 1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc (+ local overlay)
bucket: debug_logic
skill: info-disclosure-testing
weight: 30
---

# gf: debug_logic

## What this bucket classifies

URL path fragments that historically expose admin consoles, debug handlers, ops endpoints,
and accidentally-shipped config files. These surfaces often yield information disclosure,
auth bypass, or direct RCE without any parameter fuzzing required.

## Load this reference when

- The corpus contains any `/admin`, `/debug`, `/actuator`, `/phpinfo`, `/.git`, or `/.env` path
- Staging/dev routes leaked into the production crawl (e.g. `/dev/`, `/stage/`, `/_profiler`)
- Operator is sweeping for config exposure before sending nuclei/info-disclosure templates

## Parameter keys that match

`debug`, `dbg`, `test`.

This bucket was path-only until the 2026-06 Part 6 expansion. The `?debug=1` /
`?dbg=1` / `?test=1` toggles are a real debug-mode signal it previously missed,
so those three param keys now also fire the bucket.

`admin`, `grant`, and `access` are deliberately kept **out** of the debug param
set — those route to the `privileged_action` bucket (class `bfla`) instead, so
that function-level-authz state changes are not diluted into debug-mode signal.

## Path patterns that match

Base set:
`/admin`, `/debug`, `/dbg`, `/dev`, `/staging`, `/stage`, `/test`, `/internal`, `/mgmt`,
`/manage`, `/console`, `/dashboard`, `/_profiler`, `/phpinfo`, `/actuator`, `/.git`, `/.env`,
`/config`, `/backup`

Compound/specific ops & health fragments (the bare `/health`, `/info`, `/status`,
`/version`, `/metrics`, `/env` forms are deliberately NOT added — they flood content
corpora):
`/healthz`, `/readyz`, `/server-status`, `/server-info`, `/package.json`,
`/actuator/health`, `/actuator/env`, `/actuator/mappings`, `/actuator/metrics`,
`/actuator/beans`, `/prometheus`

**Plan #13 — build / dependency manifests + Java deployment descriptor**
(source & dependency disclosure, mirroring the existing `/package.json` entry):
`/composer.json`, `/composer.lock`, `/yarn.lock`, `/package-lock.json`,
`/web-inf/web.xml`. These are the build-artifact half of Plan #13; the VCS / IDE
dotfile half (`.svn`, `.hg`, `.gitlab-ci.yml`, `.ds_store`, `.terraform`,
`.tfstate`) lives in the `interestingext` bucket. The leading-slash form
(`/composer.json`, not bare `composer.json`) preserves boundary precision, so
`/mycomposer.json` does not match.

## Weight and priority interpretation

- Baseline priority score: 30
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/admin/users` — admin console
- `https://target.example/actuator/env` — Spring Boot env leak
- `https://target.example/_profiler/latest` — Symfony profiler
- `https://target.example/.git/HEAD` — exposed git repo
- `https://target.example/phpinfo.php?debug=1` — phpinfo disclosure
- `https://target.example/api/internal/metrics` — internal ops endpoint
- `https://target.example/backup/db.sql.bak` — backup file exposure

## What it does NOT classify

- `/admin` behind a working auth wall that returns 401 without payload — record as surface but deprioritize
- Documentation pages that happen to mention `/debug` without the endpoint being live — verify live status first
- CDN-served `/dev` paths that resolve to static HTML — these fire but the secret-scan pass usually clears them

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings Info Disclosure](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Insecure%20Source%20Code%20Management)

## Related

- `agent/references/payloads/info-disclosure-probes.md` — standard endpoints checklist
- `agent/references/gf-patterns/interestingEXT.md` — complementary bucket (.bak, .swp, .old extensions)
- `agent/references/gf-patterns/interestingparams.md` — adjacent bucket (debug often combines with `debug=1` or `token=`)
