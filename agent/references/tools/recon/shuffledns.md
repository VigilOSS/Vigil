---
description: Lighter alternative to puredns; we generally prefer puredns for better wildcard handling
skill: subdomain-enumeration
---

# shuffledns

**Purpose:** Lighter alternative to puredns for active DNS brute-force. Wraps massdns directly with a simpler resolver-pool/wildcard-filter pipeline. Useful as a fallback when puredns errors at startup, or for very small wordlists where puredns's wildcard-batch pre-pass is overkill.

For live engagement targets, run shuffledns via `vigil assess kali exec --technique RECON --intent "<rate profile and purpose>" --probe-kind fingerprint --phase recon --timeout <seconds> -- shuffledns ...` (no typed verb — the canonical Phase 1 brute is puredns, and shuffledns is the rare-case fallback). Because the typed-verb gate is bypassed, the rate-limit ceiling from `agent/operator-core.md` "Recon Dispatch Resource Policy" DNS-brute column MUST be set in the `--intent` audit string explicitly (e.g. `--intent "shuffledns @ polite-CDN-fronted-target rate-limit 800 (vendor-controlled DNS)"`); the audit row records the intent verbatim so downstream coverage audits can verify the rate-limit choice without re-parsing the argv.

**Where it lives:** `/usr/local/bin/shuffledns` in `runtime-full` (`go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` — see `agent/docker/runtime-full/Dockerfile`). Like puredns, it requires `/usr/bin/massdns` on `$PATH`.

## Why we generally prefer puredns

puredns has materially better wildcard handling — its multi-pass wildcard test catches CDN-issued wildcards that shuffledns misclassifies as live hosts. The trade-off is RAM (puredns's wildcard-filter dedup map dominates memory at scale); shuffledns is leaner.

Default to puredns. Reach for shuffledns when:

- puredns fails at startup with an unrecoverable error (rare; check `vigil assess kali exec --technique HEALTH --intent "puredns startup preflight" --probe-kind fingerprint --phase recon --timeout 30 -- puredns -h` first).
- Wordlist is small (<5k entries) and you want to skip puredns's wildcard-batch pre-pass.
- Tight-RAM container (`VIGIL_RUNTIME_MEMORY_GB=2`) and the puredns dedup map is the limiting factor — shuffledns is materially leaner here.

## Resource-safe invocation

```bash
vigil assess kali exec --technique RECON \
  --intent "shuffledns fallback brute (small wordlist, lean profile)" \
  --probe-kind fingerprint --phase recon --timeout 1800 -- \
  shuffledns -d target.example \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  -massdns /usr/bin/massdns \
  -o /engagements/$ENGAGEMENT_KEY/scans/shuffledns_brute.txt
```

`-massdns /usr/bin/massdns` is required — shuffledns does not auto-discover the massdns path the way puredns does.

## When to use vs. alternatives

- **vs. puredns (canonical Phase 1 brute):** puredns wins on wildcard accuracy. Default to puredns.
- **vs. dnsx in brute mode:** dnsx is a resolver, not a brute-forcer; combine dnsx for resolution and shuffledns/puredns for brute generation.

## Cross-reference

- Comparison matrix: `agent/references/tools/recon/subdomain-enumeration-tools.md`.
- Phase 1 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
