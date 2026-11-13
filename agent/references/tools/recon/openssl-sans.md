---
description: Per-host TLS SAN extraction (openssl s_client + x509 -ext subjectAltName), cross-host SAN collision thresholds (shared multi-tenant cert flag), vhost / cert mismatch check, multi-time DNS split-VIP thresholds, two-call dnsx confirmation of SAN-discovered names — paired with `agent/skills/tls-vhost-correlation/SKILL.md`
skill: tls-vhost-correlation
---

# openssl s_client — Per-Host SAN Extraction and Cross-Host Collision Detection

Mechanics for `agent/skills/tls-vhost-correlation/SKILL.md`, which owns when to run, the
collision counter and the multi-time DNS loop. Per-host tools (nmap, httpx `-tls-grab`) record SANs
host by host; these steps produce the cross-host picture and feed the discovered names back into
subdomain enumeration. Every step runs under `vigil assess kali exec` (container paths
`/engagements/$ENGAGEMENT_KEY/...`).

## 1. Per-host SAN extraction

Write one SAN set per host; step 5 merges them.

```bash
vigil assess kali exec --technique RECON \
  --intent "per-host SAN extraction loop, write to scans/" \
  --probe-kind fingerprint --phase recon --timeout 600 -- \
  bash -c '
    while read -r HOST; do
      echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | grep -oE "DNS:[^,]+" | sed "s/DNS://" | sort -u \
        > "/engagements/$ENGAGEMENT_KEY/scans/sans_${HOST}.txt"
    done < /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt
  '
```

For one IP of a split-VIP cluster, keep `-servername <hostname>` and change only
`-connect <ip>:443`.

## 2. Cross-host SAN collision detection

The counter is the skill's "Cross-host SAN collision detection" block (write its output to
`scans/san_collisions.txt`). Reading the counts:

- `1` — a normal per-host cert.
- `>= 2` — a shared multi-tenant cert fronts those hosts, or a wildcard SAN covers both apexes.
- `>= 5` — a strong shared-frontend signal; cluster the hosts by full SAN set to find the edge.

Every distinct SAN is a candidate subdomain for Phase 1a.

## 3. vhost-cert mismatch detection

A cert whose SANs and CN do not cover the requested name means a shared frontend that is not
vhost-aware for it: a staging name on a production frontend, a default backend cert, or a CDN edge
serving a name it holds no SAN for. The cert's own CN/SANs are adjacent surface.

```bash
vigil assess kali exec --technique RECON \
  --intent "vhost-cert CN/SAN mismatch detection" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  bash -c '
    while read -r HOST; do
      CERT=$(echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
        | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null)
      SANS=$(printf "%s\n" "$CERT" | grep -oE "DNS:[^,]+" | sed "s/DNS://")
      CN=$(printf "%s\n" "$CERT" | grep -oE "CN ?= ?[^,/]+" | head -1 | sed -E "s/CN ?= ?//")
      APEX=${HOST#*.}
      if printf "%s\n%s\n" "$SANS" "$CN" | grep -qFx -e "$HOST" -e "*.$APEX"; then MATCH=yes; else MATCH=no; fi
      echo "$HOST cn=$CN match=$MATCH"
    done < /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt \
      > /engagements/$ENGAGEMENT_KEY/scans/vhost_cert_match.txt
    grep "match=no" /engagements/$ENGAGEMENT_KEY/scans/vhost_cert_match.txt
  '
```

`match=no` is an intel note; pivot to that cert's CN and SAN list.

## 4. Multi-time DNS resolution (split-VIP detection)

The sampling loop is the skill's "Multi-time DNS resolution (split-VIP detection)". Across five
samples: 1 unique IP is a single backend; 2-3 is a small load-balanced cluster; 4 or more is a wide
cluster where each IP is independently probeable and may carry its own cert (step 1 per IP).

The skill spaces its five samples 60 s apart (about five minutes), which spans most DNS-rotation
TTLs (30-300 s). A first pass at `sleep 10` (five samples, 50 s total) catches the common GSLB /
round-robin rotation cadence without blocking the dispatch on the five-minute loop; when it shows a
single IP and a longer rotation is suspected, run the 60 s loop. This varies time from one
vantage; geo-varying answers need `dnsx.md` "GeoDNS multi-region resolver pass".

## 5. dnsx live-host confirmation of SAN-discovered names

Two calls, because the container has no `vigil` executable: build the list inside the runtime,
then confirm from the host with the typed verb so the run gets the dnsx rate profile and guard. A
raw `dnsx` inside the same `bash -c` would run, and its audit row would still name `dnsx`, but at
whatever `-rl`/`-t` the script passes.

```bash
vigil assess kali exec --technique RECON \
  --intent "build SAN candidate list from per-host SAN sets" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'cat /engagements/$ENGAGEMENT_KEY/scans/sans_*.txt | sort -u > /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt'

vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt \
  -a -resp -silent -o /engagements/$ENGAGEMENT_KEY/scans/san_live.txt \
  --technique RECON --intent "dnsx -resp confirmation of SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 600
```

In-scope names from `san_live.txt` feed `vigil assess ingest endpoints subdomain-enum`; the rest
stay intel (the skill's "Required Behavior").

## What to record

Per-host SAN sets (`scans/sans_<host>.txt`), collision counts with one intel note per shared cert
(count >= 2), `vhost_cert_match.txt` with a note per `match=no`, a note per split-VIP cluster
(>= 2 unique IPs), and the dnsx-confirmed names.
