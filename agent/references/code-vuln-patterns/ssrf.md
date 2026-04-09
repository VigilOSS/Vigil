# SSRF — URL Parser Confusion, Internal Reachability, and Cross-Protocol Fetches

> Target: Server-side outbound fetch paths where attacker-controlled destinations can reach
> internal services, cloud metadata, loopback-only APIs, or privileged network zones.

---

## Baseline Patterns

- User-provided URL fetched directly with no allowlist
- Webhook/test-connection endpoints that return arbitrary response bodies
- XML/HTML/PDF renderers that fetch remote resources from attacker-controlled URLs

---

## What You're Hunting

### 1. Parser Differential Bugs

Validation and fetch use different URL parsers or different normalization rules.

- Host validation on raw string, fetch after redirect or reparse
- Allowlist checks on `hostname`, fetch path built from full authority
- Userinfo, fragments, or mixed encodings masking the real destination

### 2. DNS Rebinding and Resolution Drift

The code validates the hostname once, but the actual connection target changes later.

- Validation before DNS resolution
- Resolution done twice with different libraries
- Redirect handling that re-resolves without re-checking trust policy

### 3. Cross-Protocol and Secondary Fetch Paths

The “HTTP fetch” code can reach more than HTTP.

- `file://`, `gopher://`, `ftp://`, `dict://`
- Proxy support that tunnels to internal hosts
- Image/PDF/HTML parsers that fetch nested subresources

### 4. Internal Surface Discovery

The impact is not just the first response body.

- Metadata endpoints
- Loopback admin APIs
- Service mesh / discovery endpoints
- Debug, health, or metrics ports assumed private

---

## Audit Questions

- What exact parser decides whether a URL is allowed, and what parser performs the request?
- Are redirects revalidated on every hop?
- Is DNS/connection target pinned after validation?
- Can a “harmless” fetch primitive reach internal-only protocols or subresources?
