---
description: gobuster through kali exec; its DNS, S3 and vhost modes and the vhost domain quirk
skill: directory-fuzzing
---

# gobuster

gobuster has no typed verb; run it through `vigil assess kali exec --technique RECON --intent
"<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- gobuster ...` with the
standard audit-flag set. Live help: `vigil assess kali tool-help gobuster`. Directory work belongs
to `vigil assess kali ffuf` and feroxbuster (`agent/skills/directory-fuzzing/SKILL.md`); gobuster
earns a run only for its `s3` bucket mode or a quick `vhost` pass. Subdomain brute force goes
through the typed DNS verbs in `agent/skills/subdomain-enumeration/SKILL.md`, which carry the
resolver-load profiles.

- `gobuster vhost` sends each word as the whole `Host` header unless `--append-domain` is set, so a
  list of bare labels without it tests nothing useful.
- gobuster has no requests-per-second cap; pace it with `-t` and `--delay` inside the dir-fuzz rate
  of the `agent/references/recon/rate-calibration.md` row.
