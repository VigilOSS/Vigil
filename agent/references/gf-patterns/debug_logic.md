---
name: gf-patterns:debug_logic
description: Privileged, admin, and debug path patterns that signal exposed management surface
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
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

None — debug_logic matches on path fragments only.

## Path patterns that match

`/admin`, `/debug`, `/dbg`, `/dev`, `/staging`, `/stage`, `/test`, `/internal`, `/mgmt`,
`/manage`, `/console`, `/dashboard`, `/_profiler`, `/phpinfo`, `/actuator`, `/.git`, `/.env`,
`/config`, `/backup`

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
- [PayloadsAllTheThings Info Disclosure](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Source%20Code%20Management)

## Related

- `agent/references/payloads/info-disclosure-probes.md` — standard endpoints checklist
- `agent/references/gf-patterns/interestingEXT.md` — complementary bucket (.bak, .swp, .old extensions)
- `agent/references/gf-patterns/interestingparams.md` — adjacent bucket (debug often combines with `debug=1` or `token=`)
