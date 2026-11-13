---
description: dirb through kali exec, its bundled runtime wordlists, and its recursive default
skill: directory-fuzzing
---

# dirb

dirb has no typed verb; run it through `vigil assess kali exec --technique RECON --intent "<why>"
--probe-kind fingerprint --phase <phase> --timeout <seconds> -- dirb ...` with the standard
audit-flag set. Prefer `vigil assess kali ffuf` or feroxbuster
(`agent/skills/directory-fuzzing/SKILL.md`), which take the calibrated rate from
`agent/references/recon/rate-calibration.md`; dirb has no rate cap, only a per-request delay (`-z`
milliseconds).

- dirb recurses into every directory it finds by default; `-r` turns recursion off.
- dirb accepts self-signed certificates without a flag.
- Bundled wordlists in the runtime image live under `/usr/share/dirb/wordlists/`: `common.txt`
  (the default), `small.txt`, `big.txt`, `extensions_common.txt`, `mutations_common.txt`, and
  product-specific lists under `vulns/` (Apache, IIS, Tomcat, JBoss, WebLogic, WebSphere, SAP,
  SharePoint, ColdFusion, Domino and others). They work as `kali ffuf -w` lists too, which is the
  better way to run them against a fingerprinted product.
