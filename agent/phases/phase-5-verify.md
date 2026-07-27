# Phase 5 — Verify Findings

**Read-on-phase-entry.** When you ENTER Phase 5, Read this doc; re-read it on a method re-anchor. It carries the adversarial review-mode dispatch, the triage-scope rule, the disposition set (confirmed / upgraded / downgraded / killed), the dedup + chain-primitive passes, the exit gate, and the `transition-phase exploit` checkpoint. The Mandatory Phase-Exit variant/sibling pass (Verify → Exploit) and the Phase-Exit Review Dispatches table stay in `AGENTS.md`. Cross-phase machinery stays in `AGENTS.md`.

5. **VERIFY FINDINGS** → adversarial review of Phase 4 findings before investing in exploitation. This catches false positives, severity inflation, and weak evidence early — fixing a finding after exploitation wastes far more tokens than catching it here.
   a. Fetch all active findings: `vigil assess fetch findings`
   b. Triage the review scope:
      - **Must review**: all HIGH and CRITICAL findings — these drive exploitation and dominate the report
      - **Review by escalation potential, not a fixed quota**: review the MEDIUM findings that have *escalation potential* — chain potential (pairs with another finding into a high: info-disclosure + open-redirect, SSRF + token leak, IDOR + impersonation), auth / privilege-escalation relevance, or that sit on a high-value app unit (auth boundary, object-reference-heavy API, privileged-write surface). A medium on a throwaway static surface with no chain or auth angle can wait; a medium that could become the pivot of a high cannot. Cover the distinct vuln classes present rather than clustering the review on one.
      - **Skip**: LOW and INFO findings — review cost exceeds downstream impact
   c. Dispatch `vulnerability-analyst` in review mode. The dispatch context must include:
      - The finding slugs, titles, and full payloads being reviewed
      - Target access (the reviewer re-tests via `vigil assess kali ...`, not just reads the evidence text)
      - **Trust-boundary / threat-model summary**: which entry points are unauthenticated vs privileged, which inputs are operator-trusted (config, internal callers), and the blast-radius tiers. Build it from what already exists — the host's auth tier in `scope.json`, the surface's `auth_context`, and recon/fingerprint intel about internal or trusted callers — sliced to the finding's host/module rather than dumped whole on large scope. The triager is overconfident without this grounding — reachability and auth-path severity calls depend on it.
      - Explicit instruction: "You are reviewing findings produced by other agents. Your job is adversarial — challenge the evidence, reproduce the PoC, and verify the claimed severity. Confirm, upgrade, downgrade, or kill each finding with specific counter-evidence."
      - Run the FP & severity-downgrade gate (`agent/references/finding-fp-and-severity-gate.md`, C1–C7) on each finding, then author the report-ready story into `details` — this is `agent/agents/vulnerability-analyst.md`'s Four Validation Gates (Gate 3), which owns the full catch-list and field checklist; this dispatch just needs to invoke that gate, not re-derive it.
      - `finding-verification` (the adversarial Phase-4 verify procedure) plus the matching vuln-class skill (selected via `vigil assess list-skills`) for the findings under review
   d. For each reviewed finding, the reviewer decides a disposition per its own Decision Framework
      (`agent/agents/vulnerability-analyst.md` — `PASS`/`UPGRADE`/`DOWNGRADE`/`KILL`), then the
      operator maps it to the backend disposition set and runs the matching command:
      - **Confirmed** (`PASS`) → `vigil assess finding verify <slug> --disposition confirmed --reason "..."`
      - **Upgraded** (`UPGRADE`) → `vigil assess finding update <slug> --severity <higher> --reason "severity upgrade: ..."` then `vigil assess finding verify <slug> --disposition confirmed --reason "..."`
      - **Downgraded** (`DOWNGRADE`) → `vigil assess finding verify <slug> --disposition downgraded --reason "..." --new-severity <lower>`
      - **Killed** (`KILL`) → `vigil assess finding verify <slug> --disposition false_positive --reason "..." --kill-reason "..." --kill-check <1-5>`
   e. **Dedup pass**: check for findings with overlapping `canonical_location` and similar `defect_family` across different agent prefixes. Merge the weaker into the stronger:
      `vigil assess finding merge <source-slug> <target-slug> "<reason>"`
   f. **Chain-only primitives stay in the normal finding table**: when a finding is real only as part of a proved or expected escalation path, update it with `vigil assess finding update <slug> ...` so `details.chain_required`, `details.chain_rationale`, and `details.required_followup` are populated. Do not invent a chain-specific workflow status.
   g. **Exit gate**: all HIGH/CRITICAL findings have a verification disposition. When kills substantially outnumber confirms, ask why before moving on — are Phase-4 dispatches producing findings from theory rather than evidence (`agent/rules/hunting.md` §2), or did the dispatch context under-specify scope? Tighten the dispatch context for future engagements rather than treating the kill count itself as a verdict.
   Transition phase: `vigil assess transition-phase exploit` (checks unverified high/critical findings).
