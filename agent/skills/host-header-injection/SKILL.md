---
name: host-header-injection
description: Test for Host header injection — password reset poisoning, cache poisoning, routing-based SSRF, Host-gated access control, virtual host discovery, and connection-state attacks
origin: Vigil
vuln_class: host-header-injection
---

# Host Header Injection

## When to Activate

- The Host (or an override header) is reflected in bodies, links, redirects or emails; reset or
  recovery links are built from it; a proxy, load balancer or CDN may route on it differently from
  the origin; hostname-gated admin or internal endpoints exist.

`--technique HOST-HEADER` (`SSRF` when the header re-routes the server to an attacker-chosen
back-end). Single probes via `vigil assess kali exec … -- curl -sv -H "Host: …"`; lists via
`vigil assess kali sweep --values-file <file> … -- curl -s -i -H "Host: {}" https://target.example/`
(one audited run per value, clustered by response signature).

## Vectors

- **Reflection:** `Host`, then the override headers `X-Forwarded-Host`, `X-Host`,
  `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=`, and a duplicated `Host` (which
  one the proxy routes on vs which the app uses). `X-Original-URL`/`X-Rewrite-URL` rewrite the path
  past front-end restrictions.
- **Password-reset poisoning:** trigger a reset only for an identity you own (a lab or second test
  account) after the side-effect preflight (`agent/shared-constraints.md` §2d), with the poisoned
  header, and check the link in your own mailbox. Mail scanners fetch links automatically, so a
  callback from the link is not a victim click; the poisoned host in the received email is the
  proof.
- **Cache poisoning via Host:** a reflected, unkeyed Host on a busted key; full method in
  `agent/skills/cache-poisoning/SKILL.md`.
- **Routing SSRF:** sweep `Host: localhost:<port>`, internal IPs and service names and rank the
  clusters (a port whose response breaks from the closed baseline is reachable). A resolved
  `Host: $OOB_HOST` can come from a CDN, WAF or logging resolver, so a callback needs a real HTTP
  interaction from the origin's egress and internal reach to count
  (`agent/skills/ssrf-testing/SKILL.md`).
- **Host-gated access control:** `Host: localhost`, `127.0.0.1` or an internal name on `/admin`;
  the broader gate sweep is in `agent/skills/auth-bypass/SKILL.md`.
- **Virtual host discovery:** sweep candidate names in `Host`; the cluster that differs from the
  default vhost is a hidden vhost (wildcard parents from subdomain enumeration are good sources).
- **Connection state:** some front-ends validate Host only on the first request of a keep-alive
  connection; send a legitimate request then an internal-Host request on one connection with a
  raw-socket script through `vigil assess kali exec` (curl opens new connections).

## What to Record

The vector, the exact request, where the injected value lands (body, `Location`, email link,
cached response) and the outcome (`agent/rules/hunting.md` §2: a reset link to an attacker host
received by a test account, a poisoned cache entry served to a clean client, internal service
access, an admin bypass). Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`. Redirect impact:
`agent/skills/open-redirect-testing/SKILL.md`.
