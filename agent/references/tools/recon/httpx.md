---
description: httpx through the typed verb — alt-port liveness, typed vs --extra-args flags and confirming untyped spelling with tool-help, response-body capture, rate source, bulk-liveness hazards, one audit row per pipeline step
skill: web-recon
---

# httpx

Run as `vigil assess kali httpx`. Alt-port liveness (`-ports`; httpx probes only 80/443 by default,
so an alt-port-only host reads as dead), the typed flag names and the common `--extra-args`
passthroughs are in `vigil assess contract kali httpx`; `vigil assess kali httpx --help` lists every
typed flag.

**Untyped flags.** Confirm the spelling with `vigil assess kali tool-help httpx` before writing it
into `--extra-args`: the installed release is the source of truth, and names such as the JSON
field-selection flags (`-irr` / `-include-response`) have shifted between releases. A single-token
value that starts with a dash needs the `=` form (`--extra-args=-silent`). Example:
`--extra-args '-mr "(?i)internal"'`.

**Body capture.** `-store-response -store-response-dir /engagements/$ENGAGEMENT_KEY/scans/<dir>`
(both typed) saves bodies under the bind mount; `vigil assess gau secrets` already composes this
with trufflehog.

**Rate and load.** A multi-path probe takes `-rate-limit` from the dir-fuzz column of the
`agent/references/recon/rate-calibration.md` row. For bulk liveness, keep in-container
`-threads` near 25 (higher re-triggered the Docker Desktop per-destination-IP spike;
`agent/references/runtime-guides/docker-desktop-network-hazards.md`), leave `-tech-detect` off the
bulk pass and run it on the confirmed-live subset (it amplifies memory and drew RC137 kills on
large lists), and never run two bulk httpx passes or a DNS brute alongside one.

**One step, one audit row.** Write each tool's output to a file and pass it to the next typed verb
(`kali subfinder ... -o <file>`, then `kali httpx -l <file>`). Piping tools together inside one
`kali exec` leaves a single audit row and an untruthful coverage map.
