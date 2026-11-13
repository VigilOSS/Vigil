---
name: write-probe-script
description: Author a single-file Python probe at runtime when a target needs bespoke tooling no existing skill or typed kali verb covers — draft, run via `kali exec`, validate, then `artifact register` for reuse
origin: Vigil
---

# Write a Probe Script

> **Use when:** a hypothesis needs request/response *logic* that no skill, typed
> `vigil assess kali` verb (with `--extra-args`) or off-the-shelf tool expresses: a multi-step
> differential, a parser-confusion crafter, a stateful auth sequence, blind-callback timing, or a
> chained primitive. Pair it with `agent/skills/kali-exec/SKILL.md`, because the probe runs through
> `vigil assess kali exec`.

A probe is a self-contained Python file in the engagement's `scripts/` directory. It runs inside the
runtime container through `kali exec`, so every run gets an audit row, and once it is validated it
is registered as an artifact linked to the finding it proves. Don't write one when a typed verb
fits, when a single curl answers the question (the `kali-exec` "Capture stdout/stderr to
engagement-scoped paths" pattern), or when the tool merely isn't typed yet (dirb, gobuster,
hydra), which is raw `kali exec -- <tool>`. The test is whether it encodes reasoning the tools
can't.

## Probe shapes and audit labels

| Shape | What it does | `--probe-kind` | `--destructive` |
|-------|--------------|----------------|-----------------|
| Passive / fingerprint | reads only, with response-shape differentials and no state change | `fingerprint` / `baseline` | no |
| Active / payload | one crafted input per hypothesis | `payload` | only if it changes target state |
| Blind / callback | fires an input expected to cause an out-of-band hit | `payload` | usually no |
| Exploit / proof | demonstrates the attacker outcome end to end (`agent/rules/hunting.md` §2) | `exploit` | per the writes actually performed |

If a probe grows a write, change `--probe-kind` and add `--destructive` on the `kali exec` call. A
"fingerprint" that POSTs under-audits its blast radius.

## Runtime facts

- The script runs under the container's Python 3. The stdlib is always present and `requests` is
  installed. Prefer the stdlib so the probe replays on any runtime tier.
- It has the container's network position, the same as any typed verb.
- Author it on the host at `$ENGAGEMENT_DIR/scripts/<name>.py`; it runs as
  `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py` (`agent/shared-constraints.md` §11a).
- Read wordlists from `/engagements/$ENGAGEMENT_KEY/wordlists/` and write evidence under
  `/engagements/$ENGAGEMENT_KEY/scans/`. Container `/tmp` and `/data` are invisible from the host,
  and registration refuses paths outside the engagement.
- There is no `vigil` executable in the container. A `subprocess` call to `vigil assess …` works on
  the host and exits 127 in the runtime, so parse scope and manifest files off the bind mount and
  make the recording calls from the host after the run.
- The audit flags belong to the outer `kali exec` call. The script just does the work and prints.

## Scope guard

`vigil assess kali` never refuses an outbound request on scope (`agent/shared-constraints.md` §1),
so the script's own allow list is the only guard. Treat a `--target` / `--tenant` / `--<vendor>-host`
argument as untrusted input:

1. Normalize it to a bare lowercase hostname (`urlsplit().hostname`, trailing dot stripped, port
   dropped).
2. Match it against `scope.json` `hosts` + `discovered_hosts`, read directly with the stdlib.
3. Build the allow list from that result, never from argv.

`vigil assess scaffold-probe` emits a `scoped_host()` helper that does this, so keep it. When a
probe is re-pointed at another tenant, replace the allow list rather than adding to it; a union
leaves every earlier tenant authorized without anyone re-approving it.

## The loop

1. **Scaffold.** `vigil assess scaffold-probe <name> [--finding <slug>] [--purpose <text>]` writes a
   runnable skeleton to `scripts/<name>.py` and pre-registers it.
2. **Draft.** Fill in the logic and parametrize anything you will vary (`--target`, `--payload`,
   `--marker`). Read bounded slices for marker detection, and stream large bodies to a file.
3. **Run:**
   ```bash
   vigil assess kali exec \
     --technique <ENUM> --intent "<why, ≤200 chars>" \
     --probe-kind <fingerprint|baseline|payload|exploit> --phase <phase> \
     --timeout <seconds ≤600> [--destructive] -- \
     python3 /engagements/$ENGAGEMENT_KEY/scripts/<name>.py \
       --target <url> --out /engagements/$ENGAGEMENT_KEY/scans/<name>.json
   ```
   Output streams to `scans/kali/<run-id>.{out,err}`. The result JSON names `stdout_path`.
4. **Read and tighten.** Adjust payloads, encodings or branching and re-run, with `--force` on an
   intentional retry to silence the dedup warning.
5. **Validate against a control.** A known-negative input must produce `finding: false`. A probe
   that fires on everything is a false-positive engine.
6. **Register.** `vigil assess artifact register scripts/<name>.py --kind probe-script --finding
   <slug>`. Re-register after substantive edits so the stored hash matches the bytes on disk. It
   is then findable with `vigil assess artifact search --q <term>`.

Validated examples to copy and parametrize are in `agent/references/probe-scripts/`
(`http_differential.py`, `blind_callback_timing.py`).

## The finding-return convention

The skeleton prints one JSON object as its last stdout line, which makes the run decidable from the
audit preview:

```json
{"finding": true, "summary": "traversal returns /etc/passwd (200, 'root:x:0:0')", "evidence": {"status": 200, "marker": "root:x:0:0"}}
```

`finding` is the verdict. `summary` is the line a human reads first. `evidence` holds the facts
that justify the verdict: status codes, markers, timing deltas, the callback nonce. When `finding`
is true, this JSON seeds `finding record`: the summary feeds the title or notes, and the evidence
file plus the registered script become the `evidence_ref`.

## Blind callbacks: `vigil oob mint`

Mint a nonce-tagged callback host on the host before the probe runs, and pass it in as an
argument. `mint` binds the nonce under a running client's interactsh id, and that binding is what
lets `poll` correlate the hit. Use its output verbatim; a hand-built or hard-coded host can't be
correlated. Mint one nonce per payload. The full protocol is in
`agent/references/offensive-tactics/frp-tunneling.md`.

```bash
vigil oob status --json                      # health=ok; degraded exits non-zero
vigil oob mint --client <your-client-name> --technique ssrf \
  --target-url https://target.example/fetch --param url   # prints <nonce>.<client-id>.oob... = $OOB_HOST
vigil assess kali exec --technique SSRF --intent "blind SSRF via url param, oob callback" \
  --probe-kind payload --phase consume-test --timeout 120 -- \
  python3 /engagements/$ENGAGEMENT_KEY/scripts/ssrf_callback.py \
    --target https://target.example/fetch --param url --callback http://$OOB_HOST/ssrf-probe
vigil oob poll --client <your-client-name>   # same client; correlates nonce to probe
```

Other `mint` flags worth setting: `--probe-kind`, `--request-hash`, `--notes`, `--json`.
