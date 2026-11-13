---
name: ssrf-testing
description: Detect and exploit server-side request forgery to reach internal services, cloud metadata, and internal networks
origin: Vigil
vuln_class: ssrf
---

# Server-Side Request Forgery (SSRF) Testing

## When to Activate

- A feature fetches a URL server-side: webhooks, URL previews/OEmbed, avatar or image import,
  PDF/HTML render, RSS/feed import, file import from URL, SSO metadata/JWKS/discovery URLs,
  integration "test connection" buttons, or a parameter carrying a URL, hostname, IP or path.
  Parameter-name lists: `agent/references/gf-patterns/ssrf.md`, `webhook.md`, `cloud_metadata.md`.

`--technique SSRF`; every target-facing call is `vigil assess kali exec --technique SSRF --intent
"<purpose>" --probe-kind <kind> --phase <phase> --timeout 60 -- curl …` (the request lines below
show only the request). Payload families — URL schemes, URL-parser tricks,
hostname-string bypasses, DNS rebinding and when the HTTP stack defeats it, internal service
names, cloud metadata (AWS/ECS task credentials/GCP/Azure/Kubernetes service-account files and
others), user-data endpoints, post-SSRF services including gopher to MySQL/PostgreSQL/SMTP:
`agent/references/payloads/ssrf-payloads.md`. API checklist:
`agent/references/api-security/API07-ssrf.md`. Seed variants with
`vigil assess classify-payload <url> --mutations` (`boundary` gives loopback and scheme-confusion
probes, `format` parser-differential variants); swap the minted `$OOB_HOST` into each variant
before firing.

## SaaS integration connectors

Admin/settings "outbound integration" screens fetch by design: SIEM forwarders (Splunk HEC
`instanceUrl`, QRadar/LogRhythm `host`, syslog), IdP integrations (SAML `idpMetadataUrl`, OIDC
discovery, ADFS `providerUrl`, JWKS URIs), MFA (Duo `apiHost`, Okta tenant URL), webhooks,
feed/import sources, autodiscover, CI git-clone URLs, S3-compatible endpoints.

1. POST a minimal body per provider; the 400 usually leaks the required-field schema. Providers
   with a hard-coded ingestion endpoint (Azure Sentinel always uses `*.ods.opinsights.azure.com`)
   are not vulnerable.
2. A generic 400/403 on IP literals, distinct from "connection failed", means a denylist: that
   is the surface to bypass, not a stop.
3. Validator and fetcher are often split (shape check, then resolve at connect time): DNS
   rebinding lands there.
4. For a persistent channel, make the connection test pass (a listener returning the expected
   shape, e.g. Splunk HEC `{"text":"Success","code":0}`; operator-provisioned per
   `agent/shared-constraints.md` §12), confirm the config persisted, and watch for follow-on
   requests. Score persistence separately.
5. Sibling providers in one controller share the code path: record them as variants of one root
   finding.

## Differential error oracle

A partial SSRF that leaks only content length, status or headers is still an oracle: a
length or status difference per guessed byte can extract a metadata value bit by bit. Distinct
error strings per failure mode are a port-mapping primitive even with no body returned:
internal closed port → `Timeout`; external closed → `ConnectionRefusal`; open port, wrong protocol
→ `InvalidCertificate`/bad shape (fingerprint it); open and right protocol → `WrongCredentials`/
401. Score the oracle separately from the SSRF; timing differences between internal and external
targets survive identical bodies.

## Blind SSRF and OOB

Follow `agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure
(mint→poll→correlate)": one minted host per injection point, fired verbatim. A matched HTTP
interaction from a public address shows the server fetches on your behalf; a DNS-only hit carries
the recursive resolver's address and validators resolve hostnames without fetching, so it shows
less. Either way the callback proves the primitive, not impact (`agent/rules/hunting.md` §2): a
blind SSRF with no internal data and no privileged follow-on belongs on the chain-only list.
Without OOB, fall back to the error oracle and timing.

**OOB self-resolution.** A hit whose `from=` address is RFC-1918, a container-bridge range or the
Kali runtime's own IP is the Kali side resolving your host, not the target. Put the callback host
in the request body or the parameter under test rather than in curl header argv, where Kali-side
tooling resolves it first, and confirm a public egress source (or a real HTTP interaction from the
target's egress path) before recording.

## Classify the guard first

| Guard family | How it presents | Branch |
|---|---|---|
| IP-literal block | rejects `127.0.0.1`/`169.254.169.254`, accepts hostnames | IP encodings (decimal/hex/octal/IPv6/short) |
| Resolve-then-check | any hostname accepted; fails after resolving private | DNS rebinding (TOCTOU); encodings are useless |
| Hostname-string list | rejects the string `imds`/`metadata`/`localhost`, often case-sensitively | case variants (`IMDS`), trailing dot (`imds.`), percent-encoded host bytes |

If 10-15 variants of one family fail identically, the family is wrong: switch, do not deepen. An
allowlist keyed on an approved public domain falls to that domain resolving or 30x-redirecting
internally. A DNS-resolve-then-validate library (`ssrf-filter` and similar) or network-level
controls leave rebinding with a tight race as the remaining path; whether the stack allows it at
all (resolver caching, connection reuse, TTL) is in the payload reference "DNS Rebinding".

## Internal topology

In container, compose, Kubernetes and cloud deployments loopback reaches only the app itself (and
a self-SSRF can deadlock a single-worker server). Internal services answer to service names
(`store`, `objstore`, `s3`, `db`, `redis`, `api`), metadata names (`imds`, `metadata.internal`,
`metadata.google.internal`) and link-local IPs (`169.254.169.254`; ECS `169.254.170.2`).
Enumerate both names and IPs. IMDSv2 blocks GET-only or header-less SSRF, and
`HttpPutResponseHopLimit=1` blocks it across a container boundary. GCP (`Metadata-Flavor: Google`)
and Azure (`Metadata: true`) need a header: a GET-only SSRF reaches them only when CR/LF injection
in the URL or a forwarded header adds it (`agent/skills/crlf-injection/SKILL.md`). Client-side redirects and
JavaScript-only URL handling are not SSRF.

## Metadata → next hop → store

1. Pull the role/instance credential document (`--probe-kind exploit`).
2. Always read user-data/startup-script/customData and the attribute tree too (`--probe-kind
   fingerprint`): the credential document usually does not name the next hop, the provisioning
   payload does (object-store endpoint, bucket, DB DSN). Skipping it is what stalls a chain with
   credentials in hand and nowhere to spend them.
3. Pivot with the stolen credential forwarded: list first (discovery), then read the named
   object (the outcome). A store returning 403 without the credential and serving with it
   confirms both validity and trust.
4. Signed cloud calls with stolen keys run on the host: `vigil assess host-exec --tool aws … --
   env AWS_ACCESS_KEY_ID=… aws sts get-caller-identity` (the Kali container has no credential
   path); `agent/skills/aws-iam-privesc/SKILL.md` owns escalation once you hold role credentials.

Credentials are where the chain starts, not where it stops: show what they grant. Post-SSRF
services (Redis, Elasticsearch, Docker, Kubelet, Consul, CouchDB, Memcached, Kubernetes API): read
first; any write needs operator approval (payload reference "Post-SSRF Services").

## Kill and escalate

- A negative needs §13's bracket (`agent/rules/hunting.md`): guard family identified, each
  matching branch tried, run ids, a positive control.
- Escalate when: a callback arrives for any payload, even an allowlisted domain (enumerate schemes,
  ports and internal hosts, a fresh mint per host); an error, redirect `Location`, stack trace or
  length delta leaks an internal host or port state; a non-http scheme (gopher, dict, file, ftp,
  ldap) is accepted without a parser error; DNS resolves before the block check.

## What to Record

Parameter and endpoint; SSRF type (full response, status-only, partial, blind, timing-only); the
matched probe↔callback pair (`vigil oob poll --client <name> --json`) for blind cases; the bypass
used; the internal service or metadata reached and the attacker outcome it enables (e.g. what the
credentials grant on which data store); full request/response. Format:
`agent/references/runtime-guides/web-finding-recording.md`; severity:
`agent/references/finding-fp-and-severity-gate.md`.
