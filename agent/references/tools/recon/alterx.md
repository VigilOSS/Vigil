---
description: alterx permutation generator (Phase 2) quirks — estimate first, v0.1.0 stdin hang on raw runs, injected -disable-update-check; chains into puredns resolve
skill: subdomain-enumeration
---

# alterx

Phase 2 permutation generator, run as `vigil assess kali alterx`. The estimate-first commands, the
500k abort rule and the alterx → puredns chain are in
`agent/references/recon/subdomain-enum-manual-stages.md` "Phase 2". Output is 10-100x the input,
depending on input size and pattern set, so always run `-en -estimate` first: a 5,000-sub seed
with the default patterns can exceed 500k candidates.

- **stdin hang on raw runs.** alterx v0.1.0 given `-l <file>` still waits for stdin EOF: the
  process sits alive at ~0% CPU (`STAT=S`) with no output. The typed verb and `kali job` both close
  stdin, so it only bites a raw run; add `< /dev/null` there.
- The wrapper appends `-disable-update-check` (pure latency in an egress-restricted container)
  unless `--extra-args` already carries it.
- Custom patterns (`-p '{{sub}}-{{word}}.{{suffix}}'`, `-pf <file>`) earn their place only on a
  naming-convention signal, such as an internal pattern leaked in JS or breach data.
- alterx seeds from known subs, so it finds `staging-api.target.example` from
  `api.target.example` where a wordlist brute would need `staging-api` in the list. dnsgen is not
  in the runtime image.
