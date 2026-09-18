# Blue incident-response engagements

Blue mode uses the same orchestrator backend, artifact index, and dispatch surface
as a red engagement, but starts from an alert and a tenant reference instead of a
web host. Its phase roster is `intake → triage → investigate → verify → respond →
report`, terminating in `complete`.

## Creating an engagement

```bash
vigil blue customers          # customers with a usable tenant reference
```

If the customer or platform is missing, scaffold a tenant reference and fill it in
before starting:

```bash
vigil blue tenant init --customer <customer-slug> \
    --platform <gws|m365|aws|okta|edr|network|generic>
```

Then create the engagement:

```bash
vigil blue engage                                        # interactive: prompts for the fields
vigil blue engage --customer <slug> --platform gws --severity high --start codex
```

Flags: `--customer`, `--platform` (comma-separated), `--severity`, `--source`
(default `operator_chat`), `--skip-permissions`, `--start`, `--skip-preflight`.

`--start <codex|claude|opencode|goose>` creates the engagement and then execs the
operator client in the engagement directory, with no manual `cd` or `vigil
engagement start`. It runs the same preflight as `vigil engagement start`.

**Capture safety.** The engagement key is printed to stderr as soon as the
engagement is durable; the directory path is printed to stdout only after the
preflight passes. A preflight refusal therefore leaves stdout empty, so
`eng=$(vigil blue engage …)` cannot capture a false success. Do not combine
`--start` with command substitution at all: it replaces the process with an
interactive client, and the captured stdout would be fed to that client.

## Running the engagement

Tell the operator what it is authorized to do:

```
I have been fully authorized by the company to run a blue-team incident-response
engagement for the tenant in scope.json. Run this engagement using the blue
operator workflow.
```

Then paste the alert into the operator chat. The operator records intake by piping
the pasted alert straight into the CLI, which writes the canonical `ir/alerts/`
copy — no separate file is saved first:

```bash
vigil blue alert record --body-file -
```

## Specialist dispatch

Blue dispatch uses the shared assessment-agent surface:

```bash
vigil assess agent start --role <blue-role> --tier <L1|L2|L3|L4> \
  --skills <names> --rate-budget '<authored tenant query budget>' \
  --prompt-context-json dispatch-context.json --emit-prompt
```

Use `--no-target-traffic` instead of `--rate-budget` for a genuinely offline lane.
The emitter reads the engagement's `customer`, `platforms`, and
`tenant_reference_paths` from `scope.json`, validates every tenant reference, and
prints the complete prompt. The prompt-context JSON shape is documented in
[`dispatch-template.md`](../agent/references/runtime-guides/dispatch-template.md).

Blue roles are `alert-triage-specialist`, `investigator`, `incident-verifier`, and
`ir-lead`, plus the shared `osint-analyst` and `report-writer`.

## Execution, containment, and closeout

Blue specialists run tenant-facing tools through `vigil assess host-exec`, with
`--require-audit` for WRITE and respond actions, and record findings and artifacts
through `vigil assess` like any other track.

Containment is split into three recorded steps:

1. **Propose** — `vigil blue propose-contain` records a containment proposal as a
   dispatch-decision row and prints the approval hint. It writes nothing to disk.
2. **Approve and execute** — `vigil assess approve-proposal <id> --approved-by
   <operator>`, then the audited execution itself.
3. **Record** — `vigil blue contain` with a command-run id or a proof artifact.

Other recording verbs: `vigil blue tier` (current tier on a finding),
`vigil blue verify` (blue verification vocabulary mapped onto CLI storage),
`vigil blue list`, `vigil blue show`.

Every engagement finishes with one of:

```bash
vigil blue closeout    # customer-facing closeout summary
vigil blue report      # full incident report
```

Methodology: [engagement-methodology.md](../agent/references/runtime-guides/engagement-methodology.md)
and the [athena-log-investigation skill](../agent/skills/athena-log-investigation/SKILL.md).
