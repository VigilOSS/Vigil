---
description: Bulk TLS certificate harvester — SAN/CN/subject-org/issuer fields + JARM/JA3 fingerprints off live TLS handshakes; expands the subdomain set (private-CA certs CT logs miss) and drives cert pivoting
skill: subdomain-enumeration
---

# tlsx

**Purpose:** Open TLS handshakes against hosts/IPs and harvest the served certificate — Subject Alternative Names (SAN), Common Name (CN), subject organization, issuer, plus JARM/JA3 TLS fingerprints. The SAN/CN harvest **expands the subdomain set** with names that never appear in CT logs (private-CA certs that are still TLS-handshakable on internet-exposed IPs); the org/issuer + fingerprints drive **cert pivoting** (find sibling hosts that share a certificate or TLS stack).

Run target-facing tlsx via `vigil assess kali tlsx` (typed verb, audit-flag-aware, runs inside the isolated runtime). Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. Use `--technique RECON` for the SAN/CN harvest, `--technique OSINT` for issuer/fingerprint pivoting.

**Where it lives:** `/usr/local/bin/tlsx` in `runtime-full` (`go install github.com/projectdiscovery/tlsx/cmd/tlsx` — see `agent/docker/runtime-full/Dockerfile`).

## Default profile (read first)

A bare `vigil assess kali tlsx -l hosts.txt …` runs the **SAN+CN subdomain-harvest** profile — `tlsx -l hosts.txt -san -cn -resp-only -silent` — which emits a clean list of harvested names ready to feed back into the resolver/subdomain merge. Name any field flag (`-so`, `-cert`, `-jarm`, `-ja3`) and the default profile is replaced by exactly what you asked for. Pass `-json` for the structured per-field form (no `-resp-only`).

## Capability

- **Input:** `<host>` / `-u <host>` (single) or `-l <file>` (hosts / IPs / CIDRs). `-p <ports>` (default 443; add `8443,9443` for alt-TLS endpoints).
- **Fields:** `-san`, `-cn`, `-so` (subject org), `-cert` (full certificate incl. issuer/validity). Use SAN/CN for subdomain expansion; issuer/org for ownership pivots.
- **Fingerprints:** `-jarm`, `-ja3` — pivot to sibling hosts that present the same TLS-server fingerprint (shared infra / same appliance).
- **Output:** `-resp-only` (values only — the expansion feed), `-json` (structured), `-o <file>`, `-c <concurrency>`, `-silent`.
- Anything unmodeled rides `--extra-args`.

## Safety posture

tlsx speaks **raw TLS, not HTTP**, so it carries no attribution header and is in the required-header **SKIP** set (`kali_output._REQUIRED_HEADER_SKIP`) — same posture as `nmap`/`naabu`/`masscan`. Read-only handshakes: leave `--destructive` off.

**Docker per-destination-IP hazard:** the danger knob is *distinct destination IPs*, not concurrency. Feeding a whole CIDR (or an asnmap-derived CIDR file) fans out to thousands of distinct dest IPs and wedges the macOS Docker Desktop userspace proxy (I-001). **Default to the resolved A-record IPs of origin/staging hosts** (a small distinct-IP set); whole-CIDR sweeps are a gated escalation — see `agent/references/tools/recon/cero.md` and `agent/references/runtime-guides/docker-desktop-network-hazards.md`.

## vs. alternatives

- **vs. `cero`:** both scrape SANs; tlsx adds structured per-field JSON output and the JARM/JA3 fingerprints. Run both — they produce overlapping-but-not-identical name sets, and tlsx's fingerprints are unique to it.
- **vs. CT-log scraping (subfinder crt.sh/Censys):** tlsx catches private-CA certs that never publish to CT. Complementary — both feed the merged subdomain list.
- **vs. httpx `-tls-grab`:** httpx grabs TLS off already-live HTTP hosts; tlsx brute-handshakes a host/IP list independent of HTTP liveness.

## Workflow — harvest → expand → pivot

1. **Harvest** SAN/CN off live hosts or resolved origin IPs (`-san -cn -resp-only`).
2. **Expand:** merge the harvested names into the candidate subdomain set, then re-resolve (`vigil assess kali dnsx`) and re-probe liveness — the new names enter recon like any other candidate.
3. **Pivot:** on a high-value origin, pull `-cert -jarm` and look for other in-scope hosts sharing the issuer/fingerprint (shared appliance / shared origin behind a CDN).

Canonical annotated invocations: `vigil assess contract kali tlsx`.
