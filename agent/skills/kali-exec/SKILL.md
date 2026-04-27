---
name: kali-exec
description: Foundational discovery skill for the `aith assess kali` CLI surface — verb menu, audit flags, sync-vs-async decision, and per-verb invocation profiles
origin: AI Threat Hunting
---

# Kali Execution via `aith assess kali`

> **Use when:** Always — every target-facing call uses `aith assess kali ...`. This skill is foundational and is paired with `agent/shared-constraints.md`. Load it before any other skill that runs probes against scoped targets, because the verb menu and audit-flag mapping below are how the runtime stays auditable and the orchestrator backend stays in sync.

`aith assess kali` is the host-side CLI that runs Kali tools inside the runtime container with audit recording. It writes a queued audit row to the orchestrator backend before exec, streams stdout/stderr to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}` from line one, and finalizes the row on exit. The CLI is the only sanctioned path for target-facing work — host Bash, `docker run`, `docker exec`, and ad-hoc curl/nmap from the host bypass the audit pipeline and the runtime's network isolation.

## Discovery layers

The CLI surface is intentionally large. Three discovery layers keep per-turn context cost bounded while still letting you find the right invocation fast:

1. **This skill (methodology layer)** — verb menu, sync-vs-async decision, audit-flag mapping, half-phase tags, and example flag profiles per verb. Load when you need to pick a verb or remind yourself of the audit-flag set.
2. **`aith assess kali --help` and `aith assess kali <verb> --help`** — live argparse output. Use when you are composing an invocation and need the exact flag spelling or default for a verb you have already chosen.
3. **`aith assess contract kali <verb>`** — canonical schema introspection: preferred invocations, helper-supplied defaults, common mistakes, and a JSON example payload. Use when you are authoring a complex invocation and want the canonical field list — same purpose `contract record-intel <type>` serves for intel writes. The schema is derived from `agent/scripts/assess/lib/contracts.py`, so it stays current with the implementation.

Skills should point you at `aith assess contract kali <verb>` for field tables instead of duplicating them, because the contract is generated from the same source as the CLI's argparse. When this skill omits a flag detail, that is intentional — go to layer 2 or 3.

## Verb menu

19 verbs total: 17 typed and 2 fallback. Each typed verb wraps a tool with argparse-validated flags and the audit recording path; the fallback verbs cover unmodeled tools and async lifecycles.

| Verb | Use | Paired reference |
|------|-----|------------------|
| `kali nmap-scan` | Port + service scan with optional NSE scripts. TLS SAN extraction and rDNS via `-sV`. | `references/tools/recon/nmap.md` |
| `kali nuclei` | Template-based vulnerability scanner. Curated template set is the mandatory web-vuln pass — `nuclei` is the primary, `nikto` is the conditional fallback. | `references/tools/recon/nuclei.md` |
| `kali httpx` | Fast HTTP probing: status, title, tech-detect, TLS-grab. Drives WAF-tier and CDN decisions. | `references/tools/recon/httpx.md` |
| `kali wafw00f` | WAF identification. Run FIRST, before nmap/nikto/dir-fuzz, because WAF tier dictates rate limits for every later tool. | `references/tools/recon/wafw00f.md` |
| `kali ffuf` | Directory and parameter fuzzing with fast filtering. | `references/tools/fuzzing/ffuf.md` |
| `kali sqlmap` | SQL injection detection and exploitation. Native sqlmap `--technique` flag (BEUSTQ) is distinct from the audit `--technique` enum. | `references/tools/exploitation/sqlmap.md` |
| `kali subfinder` | Passive subdomain enumeration (Tier A). | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali bbot` | Deep passive recon (Tier A+). `bbot -p subdomain-enum -rf passive -t <target>`. `--allow-deadly` requires `--destructive`. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali cero` | TLS-handshake SAN scraper (Tier B). CIDR-fed; complements CT logs. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali alterx` | Subdomain permutation generator (Tier C). Feed into `puredns resolve`. Run `-enrich -estimate` first to bound output before `-limit N`. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali asnmap` | ASN → CIDR mapper. Resolves a domain or org name to its announced IP ranges; the cero feed for the Phase 3 TLS SAN sweep. | `references/tools/recon/asnmap.md` |
| `kali puredns` | Active DNS brute-force with massdns + wildcard filter (Tier C). | `references/tools/recon/puredns.md` |
| `kali dnsx` | Bulk DNS resolution and record enrichment (Tier D). | `references/tools/recon/dnsx.md` |
| `kali nikto` (CONDITIONAL — see triggers in `references/tools/recon/nikto.md`) | Web vuln scanner; legacy/odd-stack only. CLI flag is `--host <h>` (not `-h`, which argparse reserves for help) — the underlying nikto invocation builds `nikto -h <host>` correctly. | `references/tools/recon/nikto.md` |
| `kali katana` | Authenticated crawler with JS-aware extraction (`-jc`, `-jsl`). | `references/tools/recon/nuclei.md` (no katana.md yet) |
| `kali gau` | Historical URL collection (Wayback / OTX / Common Crawl / URLScan). | `references/tools/recon/gau.md` |
| `kali whatweb` | Deep web technology fingerprinting. | `references/tools/recon/whatweb.md` |
| `kali exec <cmd>` | Raw passthrough for tools not yet typed. Same audit metadata flags. | `references/runtime-guides/kali-cli.md` |
| `kali job <start\|status\|tail\|stop\|list>` | Async-job lifecycle for long scans (nmap+scripts, sqlmap, nuclei sweep, dirb, gobuster, ffuf large wordlists). | `references/runtime-guides/kali-cli.md` |

`kali exec` is the escape hatch — use it for tools the typed surface does not yet model (dirb, gobuster, hydra, john, hashcat, custom scripts, etc.) and pass the same audit-metadata flags as a typed verb. `kali job` is the supervisor — see the sync-vs-async decision below.

## Long-tail flags via `--extra-args`

Every typed verb accepts an optional `--extra-args "<shell-quoted string>"` to bridge the typed-flag gap without dropping to `kali exec`. The string is shlex-split and appended to the underlying tool argv after the typed-flag-derived arguments — verb identity is preserved in the audit trail (`list-command-runs --tool-bin httpx` still finds these calls), so reach for raw `kali exec` only when no typed verb fits at all. Audit truth is preserved because the audit row records the full final argv, including the splatted extra args.

Critical: `--destructive` still applies. If the extra args include a write/delete (`--os-shell` for sqlmap, `--script vuln` for nmap, etc.), you must also pass `--destructive` so the audit row reflects the actual blast radius.

```bash
aith assess kali httpx -u https://x -tech-detect \
  --extra-args "-H 'X-Forwarded-For: 127.0.0.1' -mc 200,302" \
  --technique DISCOVERY --intent "tech detect with custom headers" \
  --probe-kind fingerprint --phase recon --timeout 60
```

## Synchronous vs. async decision

| Mode | When | Mechanism |
|------|------|-----------|
| Synchronous (default) | Probes that fit inside `--timeout 1800` (~30 minutes). Most recon, fingerprinting, and small fuzz passes. | The CLI runs as a single process, blocks the calling shell, and finalizes the audit row on exit. |
| Async (`kali job start ...`) | nmap+scripts on >10 hosts, nuclei sweeps with the full template tree, sqlmap with `--level 5 --risk 3`, dirb/gobuster on raft-large wordlists, ffuf on `directory-list-2.3-big.txt`. Also any case where the calling shell may exit (multi-hour sweeps, parallel batches). | `aith assess kali job start ...` returns a job-id immediately; the worker runs under `dtach` inside the container and survives calling-shell exit. Poll with `aith assess kali job status <id>` and read with `aith assess kali job tail <id>`. The job table is SQLite-backed (proven `plainjob`/`solid_queue` pattern). |

Long-running synchronous calls are killed cleanly on `--timeout` expiry — the CLI sends SIGTERM to the process group, then SIGKILL after 5 seconds. The audit row reflects `timed_out=true` so the row never disappears. Choose async when you need the work to outlive the calling agent, not just to extend the wall-clock budget.

## Audit-flag mapping (REQUIRED on every typed verb and `kali exec`)

The CLI fails closed when these are missing. Pass them explicitly — there is no env-var fallback for the agent-supplied fields, because a stale env-var would silently mislabel the audit row.

| Flag | Purpose | Notes |
|------|---------|-------|
| `--technique <enum>` | Vulnerability class this command tests, OR the operator-side category for non-attack runs. | Allowed values: `SSRF`, `XSS`, `XXE`, `SQLI`, `NOSQLI`, `SSTI`, `RCE`, `CMDI`, `IDOR`, `LFI`, `RFI`, `OPEN-REDIRECT`, `AUTH`, `JWT`, `CSRF`, `CORS`, `REQUEST-SMUGGLING`, `RATE-LIMIT`, `INFO-DISCLOSURE`, `RECON`, `DISCOVERY`, `FUZZ`, `OSINT`, `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `META`, `HEALTH`, `LOG-READ`, `OTHER`. Pick the enum the skill maps to (`sqli-testing` → `SQLI`); use `META` for operator-side dispatch metadata, registry writes, and scope decisions; `HEALTH` for runtime health checks (smoke test, version probes, container-status); `LOG-READ` for reading existing artifacts/log files (no new probes); `OTHER` only when no specific class fits. |
| `--intent "<text>"` | ≤200-char one-liner of purpose. | Replaces the old `echo "=== label ==="` pattern. The intent is what makes `list-command-runs --q <keyword>` searchable across an engagement. |
| `--probe-kind <kind>` | What the command represents. | One of `fingerprint` (learning the target, no payload) / `baseline` (vanilla control request, for diff) / `payload` (crafted attack payload testing a hypothesis) / `exploit` (attacker-outcome proof) / `replay` (captured primitive on a new surface) / `cleanup` (undoing target-side changes). |
| `--phase <enum>` | The phase the dispatch was authorized for. | REQUIRED. See "Phase tags" below — pass the dispatch phase, not `scope.json.current_phase`. |
| `--timeout <seconds>` | Wall-clock budget. | Required. Default suggestion: 1800 for synchronous probes; longer budgets must use `kali job start`. |
| `--destructive` | Flag for writes/deletes. | Off by default. Set when the command does POST/PUT/PATCH/DELETE, file upload, account creation, config change, or any state-modifying shell exec on the target. |
| `--force` | Bypass dedup-window check. | The CLI hashes `(command, argv_json)` and warns/blocks duplicates within `KALI_CLI_DEDUP_WINDOW_SECONDS` (default 30s). Use `--force` only when re-running a near-duplicate is intentional. |
| `--strace` | Wrap in `strace -e trace=network,write,unlink`. | Optional. Use for `--probe-kind exploit` or `--destructive` so the audit row records network egress and disk writes. The strace artifact spills to the same `scans/kali/` directory as stdout/stderr. |

`--engagement-key` and `--agent-name` are auto-derived from `${ENGAGEMENT_DIR}/engagement.json` and the dispatching role context — do not pass them manually unless correcting an inferred value.

## Phase tags (including half-phase tags)

`--phase` accepts the canonical phases plus two half-phase tags. Pass the phase the dispatch was authorized for — `scope.json.current_phase` is operator state and updates only on phase transitions, but engagements regularly operate **between phases**.

| Tag | When |
|-----|------|
| `recon` | Phase 1 reconnaissance work. |
| `collect` | Phase 2 surface collection. |
| `consume-test` | Phase 3 work-buffer consumption and targeted testing. |
| `verify` | Phase 4 finding verification. |
| `exploit` | Phase 5 exploitation. |
| `report` | Phase 7 reporting. |
| `code-ingest` / `code-classify` / `code-hunt` / `code-verify` | Code-analysis mode phases. |
| `recon-pivot` | Mid-engagement recon on a newly-surfaced host (e.g. Phase-3 vulnerability-analyst found a new vendor SaaS host and needs to fingerprint it before deciding scope). The audit row reflects "this was recon, even though the engagement was in Phase 3." |
| `exploit-recon` | Phase-5 exploit-developer running additional fingerprinting (e.g. version triangulation via npm registry, or per-CVE pre-exploit checks). |

The half-phase tags exist because the audit row must reflect what the dispatch was for, not what `scope.json` happened to say at the time. Source-analyzer mid-engagement looking up version intel uses `recon-pivot`. An exploit-developer fingerprinting a binary before exploitation uses `exploit-recon`. The CLI rejects calls without `--phase` so agents cannot silently rely on a stale env-var default.

## Cross-reference: rate-limit calibration

Per-target rate guidance (Cloud-fronted, Origin, WAF-protected, vendor-SaaS, high-friction) lives in `agent/shared-constraints.md` "Per-Target Rate Calibration Table". Tier-pick prose stays in `agent/operator-core.md` "Recon Dispatch Resource Policy".

## Examples per verb

Examples show the audit-flag set explicit so you can copy-paste and edit. All paths use `/engagements/$ENGAGEMENT_KEY/...` because that is what the runtime sees through the bind mount.

### `kali nmap-scan`

```bash
# Cautious-tier profile (CDN-fronted / WAF-protected / regulated) — top-1000 + service detection.
aith assess kali nmap-scan \
  --target www.example.gov \
  --ports top-1000 --service-detection \
  --max-rate 200 --max-retries 2 --host-timeout 300s \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_example_gov \
  --technique RECON --intent "top-1000 + -sV vs example.gov" \
  --probe-kind fingerprint --phase recon --timeout 1800

# TLS SAN extraction (ssl-cert + ssl-enum-ciphers on 443 only).
aith assess kali nmap-scan \
  --target api.example.com --ports 443 \
  --scripts ssl-cert,ssl-enum-ciphers \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_san_api \
  --technique RECON --intent "TLS SAN + cipher enum on api.example.com:443" \
  --probe-kind fingerprint --phase recon --timeout 600

# Multi-host batch from -iL list (recon-pivot when discovered mid-Phase-3).
aith assess kali nmap-scan \
  --target placeholder \
  -iL /engagements/$ENGAGEMENT_KEY/scans/new_hosts.txt \
  --ports top-100 --service-detection \
  --technique RECON --intent "fingerprint newly-discovered vendor SaaS hosts" \
  --probe-kind fingerprint --phase recon-pivot --timeout 1800
```

### `kali nuclei`

```bash
# Reactive sweep against a delta file (Phase 1-2 in-phase pattern).
aith assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.txt \
  -t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/ \
  -severity medium,high,critical \
  -as -stream -jsonl \
  -rate-limit 150 -c 25 -bs 25 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.jsonl \
  --technique CVE-VALIDATION --intent "reactive sweep on Phase-1 URL delta" \
  --probe-kind fingerprint --phase recon --timeout 1800

# CDN-fronted target — cap rate and concurrency lower so the edge doesn't 429.
aith assess kali nuclei \
  -u https://www.example.com \
  -tags cve -severity critical,high -as -jsonl \
  -rate-limit 50 -c 10 -bs 10 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_cdn.jsonl \
  --technique CVE-VALIDATION --intent "CVE templates against CDN-fronted host" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### `kali httpx`

```bash
# Live-host confirmation + tech-detect + TLS-grab over a candidate list.
aith assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/candidate_hosts.txt \
  -status-code -title -tech-detect -tls-grab -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.jsonl \
  --technique DISCOVERY --intent "live-host + tech + TLS over candidate hosts" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

### `kali wafw00f`

```bash
# Run FIRST so the WAF tier is known before nmap/nuclei/ffuf calibrate.
aith assess kali wafw00f https://www.example.com \
  -o /engagements/$ENGAGEMENT_KEY/scans/wafw00f_www.csv \
  --technique DISCOVERY --intent "WAF identification on www.example.com" \
  --probe-kind fingerprint --phase recon --timeout 300
```

### `kali ffuf`

```bash
# Standard L1 directory fuzz with a tech-aware extension list.
aith assess kali ffuf \
  -u https://www.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403 \
  -rate 50 \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_www.json -of json \
  --technique FUZZ --intent "L1 dir fuzz on www root" \
  --probe-kind payload --phase consume-test --timeout 1800
```

### `kali sqlmap`

```bash
# Targeted SQLi pass — sqlmap's --technique flag is the SQLi technique set
# (BEUSTQ); the audit --technique enum is SQLI.
aith assess kali sqlmap \
  -u "https://www.example.com/search?q=test" \
  --technique=BEUS --level 3 --risk 2 --batch \
  --threads 4 \
  --technique SQLI --intent "boolean+error+union+stacked SQLi on /search?q" \
  --probe-kind payload --phase consume-test --timeout 1800

# Long sqlmap dump — switch to async because dump can run for hours.
aith assess kali job start --container-name security-research -- \
  sqlmap -u "https://www.example.com/api/users?id=1" \
  --technique=BEUSTQ --level 5 --risk 3 --batch --dump \
  --technique SQLI --intent "deep sqlmap dump on /api/users?id" \
  --probe-kind exploit --phase exploit --timeout 28800 --destructive
```

### `kali subfinder` / `kali puredns` / `kali dnsx`

```bash
# Passive subdomain enum (subfinder) → active resolution (puredns/dnsx).
aith assess kali subfinder -d example.com -all -recursive -t 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "passive subdomain enum for example.com" \
  --probe-kind fingerprint --phase recon --timeout 1800

aith assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  --rate-limit 800 \
  -w /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  --technique RECON --intent "active wildcard-aware resolution @ polite-CDN-fronted-target rate" \
  --probe-kind fingerprint --phase recon --timeout 1800

aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  -a -cname -resp -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx.jsonl \
  --technique RECON --intent "A+CNAME enrichment for resolved subs" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

## Subdomain enumeration: Phase A→D workflow

Subdomain enumeration is layered because no single technique covers the surface. Run the phases in order; each phase compounds on the previous one. Stop at any phase when its exit signal fires (see "Skip-bruteforce signal" below). The full prioritization rationale and tool-tier table live in `references/tools/recon/subdomain-enumeration-tools.md` — load it before composing custom invocations.

### Phase A — Passive enumeration (always-on)

`kali subfinder` runs against every wildcard scope entry. It is fail-open without API keys (~60-70% of full-key coverage); set the worth-it free keys in `agent/.env.example` to lift coverage (`SUBFINDER_SECURITYTRAILS_API_KEY`, `SUBFINDER_CENSYS_API_ID`/`API_SECRET`, `SUBFINDER_VIRUSTOTAL_API_KEY`, `SUBFINDER_SHODAN_API_KEY` — ranked by signal-per-key). The runtime exposes provider config via the standard subfinder lookup chain (`~/.config/subfinder/provider-config.yaml`), so populating `${SUBFINDER_*_API_KEY}` env vars is enough.

```bash
aith assess kali subfinder -d example.com -all -recursive -t 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "passive enum" \
  --probe-kind fingerprint --phase recon --timeout 600
```

### Phase A+ — Deep passive (optional)

`kali bbot -p subdomain-enum -rf passive` chains 50+ passive sources (CT, DNS aggregators, security feeds) and is materially deeper than subfinder alone. Run when Phase A returned a thin set or the engagement budget allows the longer wall-clock. `-rf passive` excludes active modules; deadly modules require `--allow-deadly --destructive` and a hard-failed CLI gate keeps that contract.

```bash
aith assess kali bbot -t example.com -p subdomain-enum -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs \
  --technique OSINT --intent "deep passive enum" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### Phase B — TLS SAN scraping (CIDR-fed)

`kali cero` reads CIDR ranges (or domains) and harvests TLS-handshake Subject Alternative Names. It is complementary to CT logs because targets that issue private/internal certs do not appear in CT — only by handshaking the IP do those names surface. Pair with asnmap CIDR mapping upstream so cero gets a real CIDR block to sweep.

```bash
aith assess kali cero --target 198.51.100.0/24 -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "TLS SAN scraping for non-CT subs" \
  --probe-kind fingerprint --phase recon --timeout 600
```

### Phase C — Gated bruteforce (opt-in)

Permutations expand 10-100x, so feed them through wildcard-aware resolution (`puredns resolve`) instead of a raw resolver. `kali alterx` generates the candidate stream; `kali puredns resolve -` reads from stdin so the two compose without an intermediate file. Bruteforce is the highest-CPU step in the workflow — gate behind the skip signal below.

```bash
aith assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -limit 200000 \
  -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  --technique RECON --intent "permutation candidate generation" \
  --probe-kind fingerprint --phase recon --timeout 600

aith assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  --rate-limit 2500 \
  -w /engagements/$ENGAGEMENT_KEY/scans/perms_resolved.txt \
  --technique RECON --intent "permutation bruteforce resolve @ polite-residential rate" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### Phase D — Active probe (always-on after C)

`kali dnsx -all -resp` resolves the merged sub list and emits A/AAAA/CNAME/MX/NS/TXT records. This is the final pass — its output drives live-host confirmation (`httpx`) and the reactive nuclei sweep.

```bash
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -all -resp \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_full.jsonl \
  --technique RECON --intent "DNS resolution + record sweep" \
  --probe-kind baseline --phase recon --timeout 600
```

### Skip-bruteforce signal

Skip Phase C entirely when either of these is true — the marginal yield does not justify the CPU spend:

- **Phase A returned >5000 unique subs.** The passive set already covers the namespace; permutation candidates rarely add new live hosts at that volume.
- **Target is a top-tier organization** (federal agency, F500, large bug-bounty program). Passive sources and CT logs cover the namespace far better than alterx permutations against a brand-name target, and the live-host hit rate per permutation drops sharply.

When skipping C, jump straight from Phase B to Phase D. Record the skip rationale via `aith assess log operator "Phase C bruteforce skipped" "<reason>" --actor-kind operator` so the audit trail explains the missing run.

### `kali nikto` (CONDITIONAL)

```bash
# Only run when httpx fingerprint matches a trigger (legacy stack, intranet,
# basic-auth realm, WebDAV indicator) — see references/tools/recon/nikto.md.
# Note: --host (not -h) because argparse reserves -h for help; the underlying
# nikto invocation builds `nikto -h <host>` correctly inside the helper.
aith assess kali nikto \
  --host www.example.gov --ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www_gov.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

### `kali katana`

```bash
# JS-aware authenticated crawl with rate cap.
aith assess kali katana \
  -u https://app.example.com -jc -jsl -d 4 -c 10 -rl 20 \
  -jsonl -o /engagements/$ENGAGEMENT_KEY/scans/katana_app.jsonl \
  --technique DISCOVERY --intent "JS-aware crawl of app.example.com" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

### `kali gau`

```bash
# Historical URLs from passive archives — no traffic to the target.
aith assess kali gau example.com --subs --threads 5 \
  --providers wayback,otx,commoncrawl,urlscan \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  --technique DISCOVERY --intent "historical URL harvest for example.com (passive)" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

### `kali whatweb`

```bash
# Deep tech fingerprint — aggression 3 balances depth vs request volume.
aith assess kali whatweb https://www.example.com -a 3 \
  --log-json /engagements/$ENGAGEMENT_KEY/scans/whatweb_www.json \
  --technique DISCOVERY --intent "deep tech fingerprint on www.example.com" \
  --probe-kind fingerprint --phase recon --timeout 600
```

### `kali exec`

```bash
# Escape hatch — same audit-metadata flags as a typed verb.
aith assess kali exec -- \
  hydra -L /engagements/$ENGAGEMENT_KEY/wordlists/users.txt \
        -P /engagements/$ENGAGEMENT_KEY/wordlists/passes-small.txt \
        -t 4 -f -o /engagements/$ENGAGEMENT_KEY/scans/hydra_ssh.txt \
        ssh://target.example.com \
  --technique AUTH --intent "hydra ssh brute, small wordlist, throttled" \
  --probe-kind payload --phase exploit --timeout 3600 --destructive --strace
```

### `kali job`

```bash
# Start a long async run.
aith assess kali job start --container-name security-research -- \
  nuclei -l /engagements/$ENGAGEMENT_KEY/scans/all_live.txt \
         -t http/ -severity medium,high,critical \
         -rate-limit 100 -c 25 -bs 25 -jsonl \
         -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_full.jsonl \
  --technique CVE-VALIDATION --intent "full http/ nuclei sweep across engagement" \
  --probe-kind fingerprint --phase recon --timeout 21600

# Poll status and tail output.
aith assess kali job status 42
aith assess kali job tail 42
aith assess kali job tail 42 --follow

# Stop a runaway job.
aith assess kali job stop 42 --container-name security-research

# List recent jobs (filter by status).
aith assess kali job list --status running
```

## Quick "which verb?" recipes

When you know what you want to learn, this lookup gets you to the right verb without re-reading the menu:

- "Scan a host's TLS for SAN expansion?" → `kali nmap-scan --target <host> --ports 443 --scripts ssl-cert,ssl-enum-ciphers`.
- "Identify the WAF before scanning?" → `kali wafw00f <url>`.
- "Confirm hosts are live and grab tech?" → `kali httpx -l <list> -status-code -title -tech-detect -tls-grab`.
- "Find directories on a target?" → `kali ffuf -u <url>/FUZZ -w <wordlist>`.
- "Sweep for CVEs/misconfigs/exposures?" → `kali nuclei -l <list> -t http/cves/,http/misconfiguration/,http/exposures/`.
- "Probe a SQLi candidate?" → `kali sqlmap -u <url> --technique=<BEUSTQ subset> --batch`.
- "Crawl a JS-heavy SPA?" → `kali katana -u <url> -jc -jsl`.
- "Harvest historical URLs without touching the target?" → `kali gau <domain> --subs`.
- "Enumerate subdomains?" → `kali subfinder -d <domain> -all` then `kali puredns resolve` then `kali dnsx`.
- "Run a tool not in the typed surface?" → `kali exec -- <command...>` with the same audit flags.
- "Run something that needs to outlive my shell?" → `kali job start --container-name security-research -- <command...>`.

## Coverage check before probing

Every typed verb and `kali exec` writes an audit row with `command`, `argv`, `tool`, `agent`, `phase`, `technique`, `intent`, `probe_kind`, `destructive`, exit code, timings, and an output preview. Treat that history as a coverage map — search for prior work on this surface before dispatching, with `aith assess list-command-runs --q <keyword>`. The full coverage-vs-duplicate decision table lives in `agent/references/runtime-guides/command-history-auditing.md`. The shared `agent/shared-constraints.md §2b` has the agent-side rule.

## Process cleanup discipline

> Never `pkill <toolname>` (e.g. `pkill -f nmap`, `pkill -f ffuf`) — broad pkill stomps on sibling specialist processes in the shared runtime. For async jobs, use `aith assess kali job stop <id>` (signals only the job-owned in-container PID); for synchronous calls, the CLI already handles the SIGTERM/SIGKILL escalation on `--timeout` expiry.

## Troubleshooting and runtime errors

When `aith assess kali --help` errors or a verb fails unexpectedly, see `agent/references/runtime-guides/kali-cli.md` for diagnosis steps (runtime status, dtach reachability, dedup-window, common error messages).
