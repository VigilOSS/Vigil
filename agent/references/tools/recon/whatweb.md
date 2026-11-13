---
description: whatweb technology fingerprinting through the typed verb — typed flags (-i, -a, --header, --user-agent, --proxy, --log-json), aggression choice, and its role cross-validating httpx for the nikto triggers
skill: web-recon
---

# whatweb

Run as `vigil assess kali whatweb` after httpx confirms live hosts (`--help` for the typed flags).
The typed verb takes a positional target or `-i <file>`, `-a <level>`, repeatable `--header`,
`--user-agent`, `--proxy` and `--log-json <file>`; other whatweb flags (`--log-brief`,
`--plugins`, `--wait`, `--max-threads`) go through `--extra-args`. Program attribution headers are
injected through whatweb's `--header`.

Use `-a 1` (one request per target) for the first fingerprint and `-a 3` for the deeper pass
web-recon Step 3 runs: its plugins catch legacy ColdFusion, classic ASP and niche WebSphere banners
and version numbers that httpx `-tech-detect` misses, and the union feeds the nikto triggers.

```bash
vigil assess kali whatweb -i /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -a 3 \
  --log-json /engagements/$ENGAGEMENT_KEY/scans/whatweb_results.json \
  --technique DISCOVERY --intent "whatweb -a 3 cross-validation of httpx fingerprints" \
  --probe-kind fingerprint --phase recon --timeout 600
```
