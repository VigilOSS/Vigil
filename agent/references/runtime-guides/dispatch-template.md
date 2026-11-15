---
description: Canonical dispatch capture, short native launch envelope, and paired assignment examples for discovery and verification/reporting.
---

# Dispatch capture and launch

`vigil assess agent start` captures the canonical assignment with the dispatch row. Its returned
`launch_message` is the native child prompt: a short envelope that selects the role and points to
one immutable packet path and SHA-256. It doesn't repeat the assignment. Don't write a second
packet, paste both versions, or take a finished loop as proof that capture succeeded.

```bash
vigil assess agent start --agent-id acme-auth-a --role vulnerability-analyst \
  --task "Investigate the authorization boundary on the assigned surface" \
  --model <selected-model> --reasoning high --rate-budget "<authored budget>" \
  --prompt-context-json dispatch-context.json
```

The first output line is a JSON receipt with `dispatch_id`, `launch_required`, packet identity,
size and `launch_message`. Capture has succeeded only when both the backend registration and the
immutable local packet are published. `--dry-run` validates without registering, publishing or
authorizing a launch. The command spawns nothing. Choose the registered role in the client,
launch a fresh child with the envelope, then record the child's real handle with
`agent bind-client-handle` unless the task result's `Vigil dispatch binding:` line (OpenCode)
reports `bound` or `already_bound`. The backend dispatch ID and the native client handle are separate
namespaces.

An exact registration retry returns the same dispatch and packet with `launch_required=false`.
That is for recovery and inspection, not a licence to launch a duplicate worker. Changed inputs
under the same ID conflict. After an uncertain failure, inspect the existing dispatch and native
execution before launching anything.

## Assignment context

`--task` is the objective. `--prompt-context-json` (or `prompt_context` in `--from-json`) carries
only context the specialist cannot cheaply recover from canonical state. Omitted fields stay
unknown; nothing guesses traffic rights, credentials, approvals or source identity. The field
vocabulary and validation are in `vigil assess contract agent start`. Leave unused fields out
rather than filling them with ceremony.

```json
{
  "authorized_phase": "consume-test",
  "target": "https://app.example.com/orders",
  "auth_context": "member_a and member_b",
  "credential_id": "credential-store IDs only",
  "prior_state": "surface 17; command runs 31 and 34; agent handoff acme-recon-a",
  "coverage": "anonymous boundary covered; cross-member access is open",
  "cleanup": "remove test records created in the owned accounts"
}
```

- **`--packet-file assignment.md`**: a longer authored assignment, captured from a bounded UTF-8
  file inside the engagement with its path, exact text and digest. It is a scoped supplement and
  can't override the canonical identity, role, source, scope, approval or proof gates, so don't
  hand-write those headers.
- **`prior_state`**: stored losslessly as data, with a 16,384-character limit. Prefer IDs and
  artifact pointers to retold history. `prior_agent_id` loads a bounded saved handoff inside the
  same untrusted prior-state boundary.
- **`--standing-brief-file engagement-brief.md`** (or `prompt_context.standing_brief_file`):
  context shared across lanes. The exact bytes are captured once under
  `tools/dispatch-briefs/<sha256>.md`, and packets carry the path and digest instead of the body.
  Keep standing engagement facts there, and leave `--task` / `--packet-file` for the lane's own
  files, open question and constraints. For a blind review, choose briefing that preserves the
  reviewer's independence. Editing the brief gives new dispatches a new digest; a continuation
  keeps its original brief.
- **Code assignments**: `queue_item_ids`, or a `lane_file` naming a queue-fetch JSON or newline
  path list. The helper resolves the current file, status and source identity before
  registration, renders bounded manifest previews, and renders shared required families once with
  per-file additions. Their union is each item's closeout floor. Never regenerate source digests
  or paths by hand.
- **Blue assignments**: validated tenant-reference loads come from the engagement configuration.

Size and discovery-prescription diagnostics are advisory, never a brevity gate. Model and
reasoning requests are dispatch provenance, not specialist instructions.

## Paired examples

Each example is an assignment input. The envelope and packet come from the receipt. A packet
opens with `## Runtime Identity` (`agent_id`, `agent_role`, `assessment_mode`,
`authorized_phase`), followed by `## Code Source Identity` for code roles. A proof-work packet puts
the backend's `proof_route:` line and `## Proof assignment` first, then `## Runtime Identity`.

**Code discovery.** The hunter chooses its own hypotheses and techniques, and file ownership,
source identity and role methods come from the backend and the role:

```bash
vigil assess agent start --agent-id acme-parser-a --role code-vuln-hunter \
  --code-repo-id 7 --task "Investigate trust-boundary failures in the parser batch" \
  --no-target-traffic --prompt-context-json parser-context.json
```

```json
{"authorized_phase":"hunt","queue_item_ids":[41,42],"prior_state":"module acme-parser; no completed security review","hunt_scope":"deep"}
```

**Web discovery.** Name the target, owned identities, rate budget and measured coverage, not a
guessed exploit:

```bash
vigil assess agent start --agent-id acme-orders-a --role vulnerability-analyst \
  --task "Investigate the order-management trust boundary" \
  --rate-budget "maximum 1 request/second" --prompt-context-json orders-context.json
```

```json
{"authorized_phase":"consume-test","target":"https://app.example.com/orders","auth_context":"two owned member accounts","prior_state":"surface 17; recon handoff acme-recon-a","coverage":"creation observed; ownership enforcement untested"}
```

**Verification.** Verification is an execution assignment, so explicit reproduction steps and
controls belong in it. When proof work owns execution, claim it rather than starting a competing
dispatch:

```bash
vigil assess proof-work claim 9 --agent-id acme-proof-a --agent-role vulnerability-analyst \
  --rate-budget "maximum 1 request/second" --prompt-context-json proof-context.json
```

The claim returns `launch.launch_message`. The backend-selected proof route and approval stay
authoritative, and the packet points to the finding's recorded next test, required controls,
receipts and source boundary. Launch only when `launch_required=true`; a retry just shows the
current owner.

**Reporting.** Content comes from the canonical finding and the captured submission workspace,
and reporting mechanics come from the role:

```bash
vigil assess agent start --agent-id acme-report-a --role report-writer \
  --task "Author the recipient-specific submission for VA-001 and build its triage packet" \
  --finding-slugs VA-001 --no-target-traffic --prompt-context-json report-context.json
```

```json
{"authorized_phase":"report","prior_state":"finding VA-001; recipient guidance artifact 72; submission workspace","role_specific_additions":"Submission authoring mode; preserve material preconditions; record no review decision"}
```

The independent QC is a second `report-writer` dispatch with its own agent ID (for example
`acme-report-qc-a`, task "Submission QC for VA-001 packet <packet_id>"), which reviews the packet
and records `submission_qc_verdict`.

## Continuation

Once the predecessor has actually ended and been closed, `agent continue <prior-id> --agent-id
<new-id> --task "<current unresolved objective>"` captures a fresh packet. It carries one
effective Runtime Identity, the current task, the retained traffic, source and authorization
boundaries, and pointers to the predecessor and current state. Earlier packets stay immutable and
are not appended. A changed source or a missing authority boundary needs a newly scoped dispatch.
Proof owners use proof-work reconciliation, release and a fresh claim instead.

## Swarm dispatch

A swarm fans a corpus workload (an exposed bucket's files, a long URL list, a large code corpus)
out to parallel workers. `vigil assess agent start-swarm` writes one dispatch row per worker, puts
each worker's batch range in its `task`, and prints a `## Swarm Dispatch Table` (`worker`,
`agent_id`, `items`, `status`). It spawns nothing: launch each captured row yourself through the
client's native spawn (operator core "Runtime Dispatch Syntax") with that row's envelope. Each
worker reads its range with `vigil assess agent get <agent_id>`. A partial swarm exits non-zero
with per-row receipts, so launch only the rows that were captured.

```bash
vigil assess agent start-swarm --role code-vuln-hunter \
    --workers 10 --batch-size 50 \
    --items-file /engagements/$ENGAGEMENT_KEY/scans/exposed-bucket/files.txt \
    --skills code-vulnerability-analysis --model <selected-model> --reasoning low \
    --no-target-traffic \
    --task "scan batch for hardcoded credentials, API keys, exploitable patterns"
```

Every worker is a concurrent subagent, so size `--workers` inside the concurrency budget
(operator core "Dispatch Discipline") with room for lanes already running. `start-swarm` warns
when a wave would exceed it. Match the reasoning level to the work:

- an exposed-bucket secret scan is pattern matching, so use low reasoning (500 files → 10 × 50)
- a URL-shape classification sweep that one `surface-collector` couldn't finish before its
  iteration cap needs medium reasoning (2000 URLs → 8 × 250)
- a corpus-scale CWE pattern hunt needs medium reasoning (300 files → 6 × 50)

Phase-4 depth lanes are never a swarm. They are a few deep lanes keyed on surface group and
mindset lens (`agent/phases/phase-4-consume-test.md`). When the swarm finishes, list its rows with
`vigil assess agent list --filter-role <role> --task-q "[swarm"` and run one consolidating dispatch
(usually `vulnerability-analyst` or `exploit-developer`) over the union of recorded findings.
