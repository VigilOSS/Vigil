---
description: Per-host TLS SAN extraction (openssl s_client + x509 -ext subjectAltName), cross-host SAN collision detection (shared multi-tenant cert flag), vhost / cert mismatch detection, multi-time DNS resolution (split-VIP detection), dnsx live-host confirmation of SAN-discovered names — paired with `agent/skills/tls-vhost-correlation/SKILL.md`
skill: tls-vhost-correlation
---

# openssl s_client — Per-Host SAN Extraction and Cross-Host Collision Detection

> Purpose: Extract Subject Alternative Name (SAN) hosts from per-host TLS certs, detect cross-host SAN collisions (shared multi-tenant certs), check vhost / cert mismatch, and feed the discovered names back into subdomain enumeration via dnsx.

This recipe is the cross-host complement to nmap's TLS-grab pass and httpx's `-tls-grab`. nmap and httpx record SANs per host; this recipe is what turns the per-host SAN sets into a *global* picture — collisions that flag shared frontends, mismatches that flag misconfigured vhosts, and a unified SAN-discovered subdomain list that feeds back into Phase 1a / Phase 3 of subdomain enumeration.

## When to run

- After nmap and httpx have produced per-host SAN data, before Phase 2 collection. The cross-host view is what the per-host tools cannot produce.
- After a wildcard-apex enumeration round identifies a candidate SAN-shared cluster (e.g., a load-balanced frontend serving multiple tenant SANs).
- When httpx fingerprint shows a cert whose CN does not match the requested hostname — the vhost-cert mismatch is a frontend-misconfiguration signal that can leak adjacent tenant identities.

## 1. Per-host SAN extraction recipe

```bash
vigil assess kali exec --technique RECON \
  --intent "openssl per-host SAN extraction" \
  --probe-kind fingerprint --phase recon --timeout 30 -- \
  bash -c '
    HOST="TARGET_HOST"
    PORT="${PORT:-443}"
    echo | timeout 10 openssl s_client \
      -connect "$HOST:$PORT" \
      -servername "$HOST" \
      2>/dev/null \
      | openssl x509 -noout -ext subjectAltName \
      | grep -oE "DNS:[^,]+" \
      | sed "s/DNS://" \
      | sort -u
  '
```

Save per-host SAN sets to disk for the cross-host comparison in step 2:

```bash
vigil assess kali exec --technique RECON \
  --intent "per-host SAN extraction loop, write to scans/" \
  --probe-kind fingerprint --phase recon --timeout 600 -- \
  bash -c '
    while read HOST; do
      OUT="/engagements/$ENGAGEMENT_KEY/scans/sans_${HOST}.txt"
      echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | grep -oE "DNS:[^,]+" \
        | sed "s/DNS://" \
        | sort -u > "$OUT"
      echo "wrote $OUT ($(wc -l < "$OUT") SANs)"
    done < /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt
  '
```

## 2. Cross-host SAN collision detection

The collision script counts how many input hosts share each SAN entry — a SAN that appears in multiple hosts' SAN sets indicates a shared multi-tenant cert (one cert serving multiple tenant SANs), which is a tenant-identity disclosure surface and a vhost-routing hint:

```bash
vigil assess kali exec --technique RECON \
  --intent "cross-host SAN collision detection — flags shared multi-tenant certs" \
  --probe-kind fingerprint --phase recon --timeout 600 -- \
  bash -c '
    HOSTS_FILE="/engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt"
    OUT="/engagements/$ENGAGEMENT_KEY/scans/san_collisions.txt"
    : > "$OUT"
    for h in $(cat "$HOSTS_FILE"); do
      echo | timeout 10 openssl s_client -connect "$h:443" -servername "$h" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | grep -oE "DNS:[^,]+" \
        | sort -u
    done | sort | uniq -c | sort -rn > "$OUT"
    head -100 "$OUT"
  '
```

Interpretation:

- `count == 1` — SAN appears in exactly one host's cert. Normal per-host cert.
- `count >= 2` — SAN appears in multiple hosts' certs. Either (a) a shared multi-tenant cert is fronting both hosts, or (b) the SAN is a wildcard that matches both hosts' apex.
- `count >= 5` — strong shared-frontend signal. Cluster the hosts by their full SAN set to identify the shared edge.

Record the high-count entries as intel-notes and feed them as inputs to Phase 1a subdomain expansion (every distinct SAN is a candidate subdomain).

## 3. vhost-cert mismatch detection

When the cert's CN (or first SAN) does not match the requested hostname, the host is sitting on a shared frontend that is not vhost-aware for this name. Mismatches commonly indicate:

- A staging hostname pointed at a production frontend whose cert excludes the staging name.
- A misconfigured vhost where the default backend cert is served instead of the per-vhost cert.
- A canonical-name CDN edge that does not have a SAN for the requested hostname (the CDN serves the request anyway, but the cert proves the host is not a first-class tenant on that edge).

```bash
vigil assess kali exec --technique RECON \
  --intent "vhost-cert CN/SAN mismatch detection" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  bash -c '
    while read HOST; do
      CERT_INFO=$(echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
        | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null)
      CN=$(echo "$CERT_INFO" | grep -oE "CN ?= ?[^,]+" | sed "s/CN ?= ?//;s/^ *//;s/ *$//" | head -1)
      MATCH="no"
      if echo "$CERT_INFO" | grep -oE "DNS:[^,]+" | sed "s/DNS://" | grep -qFx "$HOST"; then
        MATCH="yes"
      elif [ "$CN" = "$HOST" ]; then
        MATCH="yes"
      else
        # check wildcard matches
        APEX=$(echo "$HOST" | sed -E "s/^[^.]+\\.//")
        if echo "$CERT_INFO" | grep -oE "DNS:\\*\\.[^,]+" | sed "s/DNS:\\*\\.//" | grep -qFx "$APEX"; then
          MATCH="wildcard"
        fi
      fi
      echo "$HOST cn=$CN match=$MATCH"
    done < /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt \
      > /engagements/$ENGAGEMENT_KEY/scans/vhost_cert_match.txt
    grep -E "match=no" /engagements/$ENGAGEMENT_KEY/scans/vhost_cert_match.txt
  '
```

`match=no` means the cert does not cover the hostname — record as intel-note and pivot to the cert's CN / SAN list (those names are adjacent attack surface).

## 4. Multi-time DNS resolution (split-VIP detection)

Single-resolution DNS misses split-VIP load-balanced clusters. When a name resolves to a different IP across multiple resolutions, the cluster is rotating answers (DNS round-robin, GSLB, anycast with split routing) — each unique IP can be probed independently and may serve different content / different cert / different rate-limit policy:

```bash
vigil assess kali exec --technique RECON \
  --intent "multi-time DNS resolution — detect split-VIP load-balanced clusters" \
  --probe-kind fingerprint --phase recon --timeout 120 -- \
  bash -c '
    HOST="$1"
    OUT="/engagements/$ENGAGEMENT_KEY/scans/dns_multi_${HOST}.txt"
    : > "$OUT"
    for i in 1 2 3 4 5; do
      dig +short "$HOST" A >> "$OUT"
      sleep 10
    done
    sort -u "$OUT"
  ' -- TARGET_HOST
```

Interpretation:

- 1 unique IP across 5 samples → single backend, no split-VIP.
- 2-3 unique IPs → small load-balanced cluster (typical).
- 4+ unique IPs across 5 samples → wide cluster; each IP is independently probeable. Capture each IP's cert via step 1 (`-connect <ip>:443 -servername <hostname>`) — different IPs in the cluster sometimes carry different certs.

Five samples × 10s spacing (50s total) catches the common GSLB / round-robin
rotation cadence without blocking the dispatch on a five-minute sleep loop.
Most DNS-rotation TTLs land in the 30-300s band; if the first pass shows a
single IP and the operator suspects a longer rotation, re-run with `sleep 60`
inside a follow-up dispatch.

## 5. dnsx live-host confirmation of SAN-discovered names

The SAN extraction in step 1 surfaces candidate subdomains that did not appear in passive sources. Feed them through `dnsx -resp` to confirm which ones are live before adding them to the work buffer.

This is a TWO-call sequence: vigil is a host-side CLI and is not on the runtime container's `$PATH`, so a nested `vigil assess kali dnsx` inside a `kali exec` heredoc cannot run. Build the candidate list inside the runtime via `kali exec`, then issue a separate `kali dnsx` call from the host so its audit row stamps the dnsx invocation cleanly.

```bash
# Step 5a — build the candidate list inside the runtime (host-readable path).
vigil assess kali exec --technique RECON \
  --intent "build SAN candidate list from per-host SAN sets" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c '
    cat /engagements/$ENGAGEMENT_KEY/scans/sans_*.txt \
      | sort -u > /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt
    wc -l /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt
  '

# Step 5b — confirm live SAN-discovered names with a separate dnsx call so the
# audit row records dnsx by name (a single nested wrapper would lose the
# dnsx-specific audit metadata).
vigil assess kali dnsx \
  -l /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt \
  -a -resp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/san_live.txt \
  --technique RECON --intent "dnsx -resp confirmation of SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Tradeoff for one-call collapse: `dnsx` is on the runtime container's `$PATH`, so a single `kali exec ... -- bash -c '... dnsx ...'` heredoc would also run, but the audit row would be stamped against `bash` rather than `dnsx`, and downstream coverage queries (`list-command-runs --tool-bin dnsx`) would miss the run. Use the two-call form unless audit fidelity is explicitly out of scope.

`san_live.txt` is the input to `vigil assess ingest-endpoints "$ENGAGEMENT_DIR/cases.db" subdomain-enum` — every confirmed live SAN-discovered name becomes a Phase 2 collection target.

## What to record

- Per-host SAN sets (write to `scans/sans_<host>.txt`).
- Cross-host SAN collision counts (write to `scans/san_collisions.txt`); record an intel-note for each shared multi-tenant cert (count >= 2).
- vhost-cert match results (`scans/vhost_cert_match.txt`); record an intel-note for each `match=no` row.
- Multi-time DNS resolution sets (`scans/dns_multi_<host>.txt`); record an intel-note when the unique-IP count is >= 2 (split-VIP detected).
- dnsx-confirmed SAN-discovered names; ingest each as a subdomain-enum endpoint.

## Cross-references

- `agent/skills/web-recon/SKILL.md` "TLS / SAN / vhost cross-host" — the methodology section that calls into this recipe.
- `agent/skills/subdomain-enumeration/SKILL.md` "TLS SAN extraction as primary source" — the Phase 0/3 subdomain step that consumes SAN-discovered names.
- `agent/skills/port-scanning/SKILL.md` "Multi-time DNS resolution" — the cross-link from the port-scanning side.
- `agent/references/tools/recon/dnsx.md` — the `-resp` invocation pattern for live-host confirmation.
- `agent/references/tools/recon/cero.md` — the Phase 3 TLS-SAN scrape that complements per-host openssl extraction (cero is faster on a known CIDR; openssl is more flexible on a specific hostname).
