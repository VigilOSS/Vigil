---
description: nmap through the nmap-scan verb — Docker -sT vs -sS and raw-packet limits, one -iL process, SAN and rDNS extraction from scan output, the XML-closure trap and the per-host port-data presence gate
skill: port-scanning
---

# nmap

Run as `vigil assess kali nmap-scan` (`vigil assess contract kali nmap-scan` for defaults and an
example; `agent/skills/port-scanning/SKILL.md` for the canonical runs). Timing comes from the row
of `agent/references/recon/rate-calibration.md` the wafw00f result picks; only the Lab / CTF row
runs `-T4`.

**Docker runtime.** The verb defaults to `-sT` (connect). Raw SYN probes do not pass Docker's
userland NAT (Docker Desktop/macOS especially), so `-sS` silently returns 0-open on live hosts;
`--scan-type sS` belongs only on a bridged-network Linux runtime. Everything else that needs raw
packets has the same limit: `-O`, `-f`, `--source-port`, decoys (`-D`, which also spoofs
third-party sources and sits outside most ROEs).

**One process.** Scan a host list with one `-iL` process rather than N per-host calls; nmap
parallelises internally, and extra processes add CPU and audit rows without speed (the skill's
"Process consolidation"; per-tier cap in `rate-calibration.md`).

## SAN and rDNS extraction

TLS SANs in the `-sV` output surface staging and internal names; rDNS identifies CDN/SaaS edge
ownership. Newly found names are intel until admitted to scope (the skill's "Adjacent hosts and ownership").

```bash
grep -ohE 'DNS:[^ ,]+' "$DIR"/scans/nmap_initial.nmap | sed 's/DNS://' | sort -u > "$DIR/scans/nmap_san_hosts.txt"
grep -oE 'Host: [0-9.]+ \([^)]+\)' "$DIR/scans/nmap_initial.gnmap" \
  | sed -E 's/Host: ([0-9.]+) \(([^)]+)\)/\1\t\2/' | sort -u > "$DIR/scans/nmap_rdns.tsv"
```

## XML-closure trap and the correct port-data presence gate

`</nmaprun>` closure and a "Nmap scan report for" line both appear when a host hit
`--host-timeout` with no port data captured: closure means the binary exited, not that every host
finished. A `-iL` batch can mix finished hosts and timed-out ones, so check presence per host. Run
both layers host-side against `$DIR/scans` before declaring a batch complete:

```bash
# Layer 1: nmap's own per-host timeout line in the normal output.
grep -H "due to host timeout" "$DIR"/scans/*.nmap

# Layer 2: per host in the XML, timed out or up with no <ports> element.
for f in "$DIR"/scans/*.xml; do
  xmllint --xpath '//host[@timedout="true" or (status/@state="up" and not(ports))]/address[@addrtype!="mac"]/@addr' "$f" 2>/dev/null \
    | grep -oE '"[^"]+"' | tr -d '"' | sed "s|^|GAP $f: |"
done
```

Each flagged host is either a local rate/WAF intercept (re-queue alone at the slow profile) or,
when that retry also returns no port data, upstream-filtering kill-evidence that gets its own
intel note. The retry profile and the note are the skill's
"Per-host port-data presence assertion".
