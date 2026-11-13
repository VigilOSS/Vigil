---
description: Offline hash cracking with hashcat in the runtime (CPU OpenCL only), wordlist and rule paths, engagement-scoped potfiles
---

# hashcat

Run hashcat via `vigil assess kali exec --technique AUTH --intent "<why>" --probe-kind payload
--phase <phase> --timeout <seconds> -- hashcat ...` with the standard audit-flag set (`--technique
JWT` for an HS256 secret). It sends no target traffic, but the run is still audited. Live help and
mode list: `vigil assess kali tool-help hashcat`, `hashcat --example-hashes`.

Runtime facts:

- The runtime has no GPU. hashcat runs on the PoCL CPU OpenCL device and needs no `--force`;
  budget for CPU speed, so prefer wordlist plus rules over large masks and move slow modes (bcrypt
  `-m 3200`, sha512crypt `-m 1800`) to an operator-owned `vigil assess kali job`.
- rockyou ships compressed:
  `/usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz`. Extract it into
  the engagement directory; the `rockyou-NN.txt` slices next to it are ready to use.
- JWT HMAC secrets (`-m 16500`): `/usr/share/wordlists/SecLists/Passwords/scraped-JWT-secrets.txt`
  first. The JWT procedure is in `agent/skills/jwt-testing/SKILL.md`.
- Rules live in `/usr/share/hashcat/rules/` (`best64.rule` and the rest).
- Keep the potfile and session with the engagement
  (`--potfile-path /engagements/$ENGAGEMENT_KEY/scans/hashcat.pot --session <key>`), so one
  engagement's cracks never surface in another's `--show`.
