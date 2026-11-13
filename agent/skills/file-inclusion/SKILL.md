---
name: file-inclusion
description: Detect local and remote file inclusion vulnerabilities and escalate to code execution
origin: Vigil
vuln_class: lfi, rfi, path-traversal, img-traversal
---

# File Inclusion Testing

## When to Activate

- A parameter names a file, template, language or path (`page=`, `file=`, `template=`,
  `include=`, `path=`, `doc=`, `lang=`, image or download paths), content loads by name, or errors
  reveal filesystem paths.

`--technique LFI` for local inclusion and traversal; `RFI` when the server fetches a remote URL.
Manual probes via `vigil assess kali exec … -- curl …`; depth and encoding sweeps via the typed
`vigil assess kali ffuf` verb (`--probe-kind payload --phase consume-test --timeout 600`).
Traversal sequences and encodings (double, overlong UTF-8, null byte, truncation, recursive
stripping, NGINX+Tomcat `..;/`, ASP.NET cookieless), interesting files per OS:
`agent/references/payloads/directory-traversal-payloads.md`. PHP wrappers (`php://filter`,
`php://input`, `data://`, `expect://`, `zip://`, `phar://`), log/environ/session poisoning, RFI
and LFI-to-RCE chains including the no-write filter chain:
`agent/references/payloads/file-inclusion-payloads.md`.

## Method

1. **Seed:** `vigil assess classify-payload "<current value>" --mutations` (`escalation` gives
   traversal candidates, `format` the backslash and `%2F` parser-confusion forms, `boundary`
   absolute paths; `--max-per-intent 7` shows more).
2. **Depth sweep and triage:** capture one JSONL record per depth and rank with
   `vigil assess anomaly-score depth_sweep.jsonl --top 5`; the depth that read the file diverges on
   length/words/lines from the default-page population. Confirm the content (`root:x:0:0:`), not
   just a different size. A flat ranking means deepen, switch encoding, or this is not a
   filesystem include.
3. **Read what matters:** after `/etc/passwd` proves the read, go for application config,
   `.env`, credentials and source via `php://filter/convert.base64-encode` — the finding is what
   the read discloses.
4. **Escalate to code execution** with the least invasive path: the filter chain (no write) or
   `php://input`/`data://` where wrappers are allowed. Log and mail spool poisoning write to
   shared target state and need operator approval (`agent/shared-constraints.md` §1); poisoning
   your own session file changes only your own test data and needs none.
5. **RFI:** point the parameter at a minted host
   (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)").
   A matched fetch shows the server dereferences URLs, not that it includes them:
   `file_get_contents` with `allow_url_fopen` fetches without executing. Inclusion is shown by
   executed content, which needs a served payload from an operator-provisioned listener
   (`agent/shared-constraints.md` §12). On Windows, UNC paths (`\\$OOB_HOST\share\x`) are fetched
   even with `allow_url_include` Off. An empty `matched` can be egress filtering, not a disabled
   setting.

## What to Record

Parameter and endpoint, traversal depth, the encoding or bypass needed, the files read and what
they disclose (`agent/rules/hunting.md` §2), and the RCE method with `id` output if reached.
Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.
