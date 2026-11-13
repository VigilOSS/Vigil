---
description: nuclei through the typed verb — wrapper-injected WAF-resilience and politeness defaults (pointer to the contract), OOB Callbacks via --oob-mode, template management in a fresh runtime
skill: nuclei-scanning
---

# nuclei

Run as `vigil assess kali nuclei`. The wrapper injects `-mhe 50` and the politeness
`-exclude-tags` set, disables blind callbacks by default, and documents why explicit `-t` paths lead
over `-as`: `vigil assess contract kali nuclei` (the result's `resolved_argv` shows what ran). Rate,
`-bs` and `-c` come from the matching row of `agent/references/recon/rate-calibration.md`; sweep
procedure is `agent/skills/nuclei-scanning/SKILL.md`.

**WAF resilience.** nuclei abandons a host after its own max-host-error count, which a WAF 403
storm reaches in seconds and which silently drops template coverage on the hardest hosts. Raise
`-mhe` above the injected 50 on heavily WAF'd targets (check `-mhe 0` semantics with
`vigil assess kali tool-help nuclei` before relying on it), and add `-random-agent` plus
browser-like `-H` headers when the edge blocks scanner user agents.

## OOB Callbacks

Callbacks use the persisted Vigil tenant route. The operator first confirms `health=ok` in
`vigil oob status --json` (it folds in `server`, `frpc`, `route_matches` and tenant-domain
resolution), then runs the verb with `--oob-mode vigil`; the wrapper supplies the tenant domain and
rejects raw `-interactsh-url` / `-interactsh-server` so ambient configuration cannot redirect
callbacks. nuclei's own JSONL finding is the correlation source for nuclei-managed callback IDs; a
separate `vigil oob client` + `mint` + `poll` is the path for manual callback probes and does not
replace nuclei's internal tracking. `--oob-mode none` is the default; `public` is an explicit
public-Interactsh data-egress decision.

## Template management

The runtime image ships the binary without templates, so the first run in a fresh runtime pays the
download. Run the update as its own call so the sweep fits the `--timeout` ceiling:

```bash
vigil assess kali exec --technique HEALTH --intent "nuclei template update" \
  --probe-kind fingerprint --phase recon --timeout 120 -- nuclei -ut
```

`nuclei -tl` under the same form lists installed templates. Template paths carry the protocol
prefix (`http/cves/`, `dns/`, `network/`).
