# Root-Cause Review Mode (Phase 5 → 6 exit)

This is a **separate mode** from the Phase 5 verification work above. Phase 5 verification validates individual findings (unreviewed → verified / disputed / downgraded / killed). The root-cause review runs AFTER verification, walks the confirmed-finding set as a group, and surfaces three things the per-finding verification cannot:

1. Root-cause links that should be drawn between confirmed findings (so blast radius is visible to the report-writer)
2. Findings whose PoC is missing the prerequisites exploit-developer will need (captured tokens, replayed credentials, intermediate state)
3. Orphan `chain_required=true` flags — findings the operator marked as chain-dependent but never had a follow-up scheduled

When dispatched with `mode=root_cause_review`, do not run new probes. Inspect the confirmed-finding set and emit a structured handoff naming the gaps.

Inputs to consult:

- `vigil assess list-findings --status active --verification-state verified --json` — confirmed-finding set
- `vigil assess list-finding-group --json` — current root-cause groupings
- For each finding: read `details_json` for `poc_request` / `poc_response` / `chain_required` / `evidence_type`

Review checklist (emit one line per gap, naming the finding slug + the missing element):

- [ ] Each confirmed finding evaluated for `link-finding` against at least one other confirmed finding when a shared code path / shared auth boundary / shared input vector is plausible. Group obvious siblings as roots even if no one has run `link-finding` yet.
- [ ] Findings that should be grouped under one root cause but currently sit independent are surfaced — propose the `link-finding` command in the handoff `next_step`.
- [ ] Each finding's PoC carries chain-relevant prerequisites: captured token id (in `credentials` table via `details.credential_id`), replayed credential confirmation, intermediate state needed to reach the vulnerable step. If a prerequisite is missing, recommend the operator re-dispatch VA in standard mode to capture it.
- [ ] Each finding's stated attacker outcome (per the Dispatch Completion Gate in `agent/operator-core.md`) is concrete enough that exploit-developer can build on it without re-deriving the exploitation step.
- [ ] Every `details.chain_required=true` flag has an actual exploit-developer dispatch recorded against the slug — no orphan chain-required flags reaching the exploit phase.

Output: backend handoff via `vigil assess agent handoff --from-json <path>` with per-finding gaps. Each `next_step` names the specific dispatch to fire (role, finding slug, capture target). Do NOT run `link-finding` or re-dispatch from inside review mode — those are operator decisions. Review mode is read-only assessment so the operator can sequence the missing dispatches deliberately before Phase 6.
