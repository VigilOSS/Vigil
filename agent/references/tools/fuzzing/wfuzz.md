---
description: wfuzz through kali exec, for payload encoder chains other fuzzers lack
skill: directory-fuzzing
---

# wfuzz

wfuzz has no typed verb; run it through `vigil assess kali exec --technique FUZZ --intent "<why>"
--probe-kind payload --phase <phase> --timeout <seconds> -- wfuzz ...` with the standard audit-flag
set. Live help: `vigil assess kali tool-help wfuzz`; `wfuzz -e encoders` lists the encoders.
Directory and parameter fuzzing belong to `vigil assess kali ffuf`
(`agent/skills/directory-fuzzing/SKILL.md`).

wfuzz earns a run for its encoder chains, which transform each payload before it is sent:
`-z file,<list>,base64@urlencode` chains encoders (`@`), while `-z file,<list>,urlencode-base64`
sends one request per listed encoder (`-`). That matters once wafw00f has named the WAF and a specific
encoding layer is the bypass under test (`agent/references/web/waf-bypass-and-safe-testing.md`).
The second payload's keyword is `FUZ2Z`, the third `FUZ3Z`. wfuzz has no requests-per-second cap;
pace it with `-t` and `-s` inside the dir-fuzz rate of the `agent/references/recon/rate-calibration.md`
row.
