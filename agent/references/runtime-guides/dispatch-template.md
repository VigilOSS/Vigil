---
description: Canonical dispatch capture, short native launch envelope, and paired assignment examples for discovery and verification/reporting.
---

# Dispatch capture and launch

`vigil assess agent start` captures the canonical assignment with the dispatch row. Use its returned
`launch_message` as the native child prompt. That short envelope selects the role and points to one
immutable packet path and SHA-256. It does not repeat the assignment. Never independently write a
second packet, paste both versions, or infer success from a loop finishing.

```bash
vigil assess agent start --agent-id acme-auth-a --role vulnerability-analyst \
  --task "Investigate the authorization boundary on the assigned surface" \
  --model <selected-model> --reasoning high --rate-budget "<authored budget>" \
  --prompt-context-json dispatch-context.json
```

The first output line is a JSON receipt containing `dispatch_id`, `launch_required`, packet identity,
size, and `launch_message`. Capture succeeded only after both backend registration and immutable local
packet publication succeed. `--dry-run` validates without registering, publishing, or authorizing launch.
The command does not spawn a native specialist. Choose the registered role in the client, launch a
fresh child with the returned envelope, then bind its actual handle using `agent bind-client-handle`.
The backend dispatch ID and the native client handle are different namespaces.

An exact registration retry returns the same dispatch and saved packet with `launch_required=false`.
It is recovery/inspection, not permission to duplicate a worker. Changed inputs under the same ID
conflict. After an uncertain failure, inspect the existing dispatch and native execution before any
launch. A partial swarm has per-row receipts and exits nonzero; launch only successfully captured rows.

## Assignment context

`--task` is the objective. Optional `--prompt-context-json` (or `prompt_context` in `--from-json`)
carries only context the specialist cannot cheaply recover from its canonical state:

```json
{
  "authorized_phase": "hunt",
  "target": "https://app.example.com/orders",
  "auth_context": "member_a and member_b",
  "credential_id": "credential-store IDs only",
  "prior_state": "surface 17; command runs 31 and 34; agent handoff acme-recon-a",
  "coverage": "anonymous boundary covered; cross-member access is open",
  "cleanup": "remove test records created in the owned accounts"
}
```

Omitted fields remain unknown, without guessed traffic rights, credentials, approvals, or source
identity. Exactly one traffic declaration is still required: `--rate-budget` or `--no-target-traffic`.
Mixed roles need `--assessment-mode code|web`. The executable field vocabulary and validation live in
`vigil assess contract agent start`; do not fill unused fields with paragraphs of ceremony.

For a longer authored assignment, `--packet-file assignment.md` captures a bounded UTF-8 file inside
the engagement as a scoped supplement. Its path, exact text, and digest are saved. It cannot override
the canonical identity, role, source, scope, approval, or proof gates. Do not hand-write those headers.
Prior-state text is losslessly contained as data, with a 16,384-character safety limit; prefer IDs and
working-artifact pointers to repeated history. Size and discovery-prescription diagnostics are advisory,
never a hard brevity gate. Preserve required environment facts and proof controls.

Code assignments can add `queue_item_ids`, or `lane_file` naming a queue-fetch JSON/newline path list.
The helper resolves current backend file/status/source identity before registration, renders bounded
manifest previews, and preserves pointers to the full selection. `prior_agent_id` loads a bounded saved
handoff inside the untrusted prior-state boundary. Never regenerate source digests or paths by hand.
Blue assignments receive validated tenant-reference loads from the owned engagement configuration.

## Paired example 1: code discovery

Assignment input:

```bash
vigil assess agent start --agent-id acme-parser-a --role code-vuln-hunter \
  --code-repo-id 7 --task "Investigate trust-boundary failures in the parser batch" \
  --no-target-traffic --prompt-context-json parser-context.json
```

```json
{"authorized_phase":"hunt","queue_item_ids":[41,42],"prior_state":"module acme-parser; no completed security review","hunt_scope":"deep"}
```

Illustrative envelope and generated-packet excerpt (the actual paths/digest come from the receipt;
do not author these packet headers yourself):

```text
Read the captured dispatch packet <packet_path>; verify SHA-256 <packet_sha256>.
Use registered role code-vuln-hunter; if it is not already loaded, read agent/agents/code-vuln-hunter.md, then load its required references before work.
Follow the packet's single Runtime Identity and inherited scope/approval boundaries; do not replace it with a second prompt.
```

```text
## Runtime Identity
agent_id: acme-parser-a
agent_role: code-vuln-hunter
assessment_mode: code
authorized_phase: hunt
## Code Source Identity
repo_id: 7
repo_generation: <backend generation>
source_manifest_digest: <backend digest>
```

The envelope points to the captured source-bound packet;
the hunter chooses hypotheses and techniques. Backend file ownership, source identity, and installed
role methods do not need to be restated in an operator-authored test recipe.

## Paired example 2: web discovery

Assignment input:

```bash
vigil assess agent start --agent-id acme-orders-a --role vulnerability-analyst \
  --task "Investigate the order-management trust boundary" \
  --rate-budget "maximum 1 request/second" --prompt-context-json orders-context.json
```

```json
{"authorized_phase":"hunt","target":"https://app.example.com/orders","auth_context":"two owned member accounts","prior_state":"surface 17; recon handoff acme-recon-a","coverage":"creation observed; ownership enforcement untested"}
```

Paired launch excerpt: `Read the captured dispatch packet <packet_path>; verify SHA-256
<packet_sha256>. Use registered role vulnerability-analyst; load the role and required references
before work if not already loaded. Follow its single identity and inherited authority boundaries.`

Generated packet excerpt:

```text
## Runtime Identity
agent_id: acme-orders-a
agent_role: vulnerability-analyst
assessment_mode: not applicable
authorized_phase: hunt
```

The packet also names the orders target, two owned identities, authored rate budget, and measured coverage;
it does not prescribe a guessed exploit. Credentials and current backend evidence remain canonical.

## Paired example 3: verification and reporting

Verification is an execution assignment, so explicit reproduction steps and controls are appropriate.
When proof work owns execution, use `proof-work claim`, not an ordinary competing dispatch:

```bash
vigil assess proof-work claim 9 --agent-id acme-proof-a --agent-role vulnerability-analyst \
  --rate-budget "maximum 1 request/second" --prompt-context-json proof-context.json
```

Paired launch excerpt: `Read the captured dispatch packet <launch.packet_path>; verify SHA-256
<launch.packet_sha256>. Use registered role vulnerability-analyst and its required references before
work. Follow its single identity and backend proof-work authority.`

Generated proof packet excerpt:

```text
proof_route: web
## Proof assignment
proof_work_id: 9
## Runtime Identity
agent_id: acme-proof-a
agent_role: vulnerability-analyst
assessment_mode: web
authorized_phase: exploit
```

These are excerpts; the helper includes the intervening approval and proof-assignment instructions.
The claim returns `launch.launch_message`, pointing to the same materialized packet workflow. The
backend-selected proof route and approval remain authoritative. Launch only on `launch_required=true`;
a retry merely exposes its current owner. The packet points to the finding's recorded next test,
required controls, receipts, and source boundary rather than inventing fresh authorization.

For an authoring/QA task:

```bash
vigil assess agent start --agent-id acme-report-a --role report-writer \
  --task "Prepare recipient-specific content and Pass 1 QA for VA-001" \
  --finding-slugs VA-001 --no-target-traffic --prompt-context-json report-context.json
```

```json
{"authorized_phase":"report","prior_state":"finding VA-001; recipient guidance artifact 72; submission workspace","role_specific_additions":"Review-and-fix mode; preserve material preconditions and current review gates"}
```

For reporting, the same short envelope selects `report-writer` and points to a captured packet whose
Runtime Identity names `acme-report-a`, authorized phase `report`, and the supplied finding/workspace
pointers. Content belongs to the canonical finding and captured submission
workspace. Reporting mechanics and proof limits come from the role, not another pasted checklist.

## Continuation

After the predecessor has actually ended and is closed, `agent continue <prior-id> --agent-id <new-id>
--task "<current unresolved objective>"` captures a fresh packet with one effective Runtime Identity,
current task, retained traffic/source/authorization boundaries, and predecessor/current-state pointers.
The original packets remain immutable history; their text and prior continuation deltas are not
recursively appended. A changed source or missing authority boundary requires a newly scoped dispatch.
Proof owners follow proof-work reconciliation, release, and fresh claim instead of ordinary continuation.
