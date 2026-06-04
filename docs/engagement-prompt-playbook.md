# Engagement Prompt Playbook

> A field guide to driving Vigil (formerly `security-research`) Operator engagements — distilled from real
> sessions across **git, libcurl, fluent-bit, BIA.gov, CMS.gov, LastPass, the `.mil`/DoD VDP, the acme
> Google Workspace blue-team, and an iPhone hardware job.**
>
> Every quoted block below is a **real prompt** pulled from session history. They are kept in the original voice
> on purpose — these are the phrasings that actually moved engagements forward. Use them as templates: copy,
> swap the target, and go.

---

## Table of Contents

1. [The Operating Model](#1-the-operating-model)
2. [Phase 0 — Kicking off an engagement](#2-phase-0--kicking-off-an-engagement)
3. [Phase 1 — Recon, scope & coverage](#3-phase-1--recon-scope--coverage)
4. [Phase 2 — Hunting: digging deeper, finding more](#4-phase-2--hunting-digging-deeper-finding-more)
5. [Phase 3 — Escalation, chaining & severity](#5-phase-3--escalation-chaining--severity)
6. [Phase 4 — Adversarial verification (the BugCrowd-reviewer mindset)](#6-phase-4--adversarial-verification-the-bugcrowd-reviewer-mindset)
7. [Phase 5 — Reporting & submission](#7-phase-5--reporting--submission)
8. [Phase 6 — Triage defense (after you submit)](#8-phase-6--triage-defense-after-you-submit)
9. [Cross-cutting: resume, status, recovery](#9-cross-cutting-resume-status--recovery)
10. [Specialized tracks: source-code audits, blue team, hardware](#10-specialized-tracks)
11. [The one-liner arsenal (the "push" phrases)](#11-the-one-liner-arsenal)
12. [What made these prompts work](#12-what-made-these-prompts-work)
13. [Copy-paste templates](#13-copy-paste-templates)

---

## 1. The Operating Model

Almost every engagement follows the same spine, and your prompts reflect it:

```
Read AGENTS.md → assume Operator role (operator-core.md / operator-core-code.md)
   → Recon (find every surface)  → Hunt (find every bug)  → Escalate/chain
   → Adversarially verify (FP + downgrade checks)  → Report-writer → QA → normalize
   → Submit → defend in triage
```

The **Operator stays the brain; specialists do the work.** Your single most repeated structural instruction:

> "You should always delegate work to sub-agents, and you as the Operator stay as the brain. Do also vary what
> you send to sub-agents sometimes too much guardrils can choke them, and just giving findings/idea is good too."
> — *cms.gov*

> "So a single agent, dispatched 12 of its own agents, that is what this multi agent thing is? What about having
> 3 of those, which dispatch their own agents, running say 20-30 agents at a time." — *libcurl*

---

## 2. Phase 0 — Kicking off an engagement

The opener almost always: **(a) loads the role, (b) states authorization + scope, (c) sets the tempo.**

### Web app / bug-bounty kickoff

> "Read AGENTS.md and assume Operator role. Authorized bug-bounty engagement: `https://bugcrowd.com/engagements/cms-bbpublic`
> Full authorization confirmed. Run the operator workflow. Take full advantage of specialist agents to delegate all
> target-facing work — dispatch in parallel where phases permit. Prefer claude-opus-4-7 / gpt-5.5 xhigh reasoning for
> operator-level and substantial specialist work; use sonnet / medium only for clearly bounded sidecar tasks.
> Exploitation policy is pause — explicit human approval required before any exploit-developer dispatch.
> For the rules of engagement, read RULES.md it is very important to follow the rules otherwise we could get bannd
> from future engagements. Targets, update scope.json: …" — *cms.gov*

> "Authorized bug bounty engagement against lastpass: `https://bugcrowd.com/engagements/lastpass`. Specifically
> lastpass.com, blog.lastpass.com … explicitly out of scope: … Do not rush, make heavy use of sub-agents, do not
> leave any stone un-turned. Read AGENTS.md, assume Operator role, and start the engagement." — *lastpass.com*

> "Authorized engagement `https://www.acme.example/vulnerability-disclosure-program/`. In-scope domains:
> `*.acme.example`, `*.content.acme.example`, `*.library.acme.example`, `*.content-api.acme.example`" — *acme.example*

> "Authorized engagement against www.agency.example, we have ran throughal recon BUT since running it the way we bucket
> IDORs has changed. I want you to review what we have, and all the surfaces we have, and determine if you want to
> rerun katana/gau, or somehow reingest ungrouped surfaces. Read AGENTS.md → operator-core.md. The primary goal of
> this engagement is solely finding IDORs … Exploitation is allowed, though its CMS and must be careful as its
> production." — *cms.gov IDOR pass*

### Research-the-program-first kickoff

> "Before starting as Operator, research `https://hackerone.com/deptofdefense` DOD/Mil and tell me about their VDP,
> what is in scope, dont just take HackerOne's word which is below, but look across other sites: …" — *.mil*

> "Great, encapsulate what the scope is, in a concise, short manner to RULES.md. Then dispatch batch of recon
> specalists to start on .mil domain, finding ALL subdomains, this first phase will be the entire goal of this
> session. The goal is to find ANYTHING mil / DOD related, all domains. It is important to dispatch OSINT specalists,
> and get this all ingested as surfaces. Read AGENTS.md before starting." — *.mil*

### Resume / take-over-an-existing-engagement kickoff

> "Pull engagement information, tell me about the engagement what has been found, what should be tested, P2s and
> above that BugCrowd wouldn't fight and can be explained clearly. Read AGENTS.md, assume Operator role." — *lastpass-macos*

> "This engagement has already been ran, but not as thoroughly as it should've been especially for `https://www.agency.example/`.
> Read AGENTS.md, and operator-core.md, then resume engagement specifically and only for www.agency.example." — *cms.gov*

**Pattern:** the opener names the role file, pastes the *authorization + scope verbatim*, then sets one of two
tempos — "do not rush / no stone unturned" or "this session's entire goal is Phase 1."

---

## 3. Phase 1 — Recon, scope & coverage

Phase 1 is treated as a goal in itself, not a warm-up. The recurring theme: **depth over speed, and QA the recon.**

> "Its not that you should run things FASTER, but COVERAGE should be DEEP. I don't want to crash things, and
> specifically UDP/DNS discovery causes that if done at too high of a rate. Continue, but realize running commands,
> and sleeping / scheduling to checkup in 30m is OK." — *.mil*

> "Phase 1 is the sole priority, there is no urgency to go to the next phase, phase 1 has a lot, and we need to be
> thorough. What are next steps in short, and what needs to be done to finish with phase 1 coverage." — *.mil*

> "Dispatch an agent to review phase 1, verify the commands that should've ran did run, and that we have sufficient
> coverage. Missing a domain, or not working through gau results can cause massive misses." — *.mil*

> "There is still what 20k some domains, were they all checked to be alive? If not then specialist should be
> dispatched to run the liveness checks … Was katana ran? How about the gau results … leave no stone unturned." — *.mil*

> "Re-evaluate coverage of this engagement, was katana ran, were all the results bucketed, and properly triaged,
> what gaps exist. Then next steps, what specialists to dispatch." — *cms.gov*

> "Anything we cannot access or are blackholed from, we simply exclude as a target. Nuclei, and other tools need to
> be ran. Dispatch batches of recon specalists to work through coverage … You will end up dispatching upwards to 50
> agents, that each are going deep, and targeting different batches of surfaces." — *.mil*

**Recon QA checklist embedded in these prompts:** *did katana run? did gau run? were results bucketed/triaged?
are all hosts liveness-checked? which domains are blackholed (drop them)? what is the % coverage per host?*

---

## 4. Phase 2 — Hunting: digging deeper, finding more

This is the heart of the playbook. The phrasing that consistently produced more findings:

### Dispatch wide, in batches, and don't over-constrain

> "Proceed with recommended next moves, dispatch sub-agents, do read AGENTS.md before starting. But also don't
> constrain yourself when you think you have a higher chance of finding something worth more value in-terms of
> severity. Do bear in mind another agent is working … Do not drain the queue quickly, we want to leave no stone
> unturned." — *fluent-bit*

> "Continue to dispatch batches of sub-agents to fill the gaps, continue to work through all the surfaces, continue
> to dispatch unique sub-agents to try non-trivial creative ways to find vulnerabilities, continue to look for
> chains, and finally dispatch sub-agents for exploit-developer now to try and A) verify vulnerabilities
> B) raise severity." — *cms.gov*

> "Continue with multi agent dispatch on the tier 1 & 2 … continue with your creative, non-trivial ideas." — *libcurl*

### The "non-trivial / creative / out-of-the-box" lever (your highest-signal phrase)

> "Continue dispatching sub-agents to continue to dig into different ideas i.e. non-trivial creative out of the box
> ideas to think of new methods of exploitation. Dispatch more sub-agents to keep looking into other
> vulnerabilities. Make sure this is all being logged to findings, and into the assess log so its clear what has
> been tested and not tested." — *bia.gov*

> "What things should be dug into further that have potential for vulnerability escalation? Dispatch sub-agents to
> escalate. Dispatch sub-agents to verify unverified findings. Dispatch sub-agent to try non-trivial creative
> exploitation ideas for standalone findings and another agent for chains." — *bia.gov*

> "Stop editing the other vulnerabilities, the focus is new, non-trivial creative findings and potential chains.
> Looking at new areas of the codebase, katana results, parameters, functionality using adversial-mindset.md." — *cms.gov*

### Encapsulate what worked into a reusable lever

> "What derived the dispatch for 'VA-044 blank-password auth bypass test' — I want to encapsulate that prompt/logic
> so we can find more vulnerabilities. Think of many different ways of using va-044, through chains … non-trivial
> creative ways of using it. Dispatch in parallel." — *cms.gov*

> "How was the SSRF found, what lead to the finding and how can we find more like it in the future in other
> engagements." — *lastpass.com*

### Anchor on a known critical and hunt for siblings/variants

> "Dispatch sub-agents if there are any findings that have this primitive that look for similar exploits like the
> Log4j Critical finding, in that its through log ingestion. Don't let this deviate everything, but do look into
> this entrypoint and see if there are similar potentials/variants, or even non-trivial creative new ways which is
> important to check for." — *fluent-bit*

> "Pickout 10 files, any in particular you want to dig harder into to find something more like the Log4j finding?
> What about the High findings we have, any that could potentially be escalated to a Critical through more digging
> or potential chains?" — *fluent-bit*

### Don't let the agent stop early

> "Stop telling me of stopping points. and why you would stop, I want you to continue, continue till a cURL and real
> world high is found, continuing to dispatch non-trivial, creative exploitation ideas." — *libcurl*

> "Even after the findings you are looking into now dont find anything, try again, and try harder. Be careful of
> causing actual damage…" — *cms.gov*

> "Continue with specialist agent dispatches, nothing quick, continue to be thorough leaving no stone un-turned." — *fluent-bit*

### Calibrate agent depth (don't waste cheap dispatches)

> "The dispatches you are doing, each agent should be running (I think) for multiple minutes, at least the main
> agent you dispatch that dispatches it's agents should run for multiple minutes 10-15m want to be careful to waste
> time dispatching agents whom only run for 20-30s. Token usage is great, and should be used. With this in mind, do
> dispatch more agents UNLESS the ones you have are actually deep, and are expected to run awhile." — *libcurl*

> "Even if you think you've failed, try again, try a different way, think about it differently." — *bia.gov*

> "Before starting, take a deep breath, review what we have, and the fact we have the source code and several good
> findings already. Then tell me, what other files do you want investigated … OR what exploit-developer sub-agents
> do you want to dispatch." — *bia.gov*

---

## 5. Phase 3 — Escalation, chaining & severity

Once a bug exists, the prompts pivot to **"what is the real-world impact, and can it go higher."**

> "Lets go through the critical, whats the real world entrypoint, how does the vulnerability work, whats the impact.
> How similar is it to the Critical Log4j CVE that gave RCE with defaults." — *fluent-bit*

> "Once you've redetermined the severity if the severity drops then determine how it could be raised again, review
> more code … Most importantly dispatch specialist verifier agent to re-verify these findings and confirm no other
> guards are in-place … Finally create full end to end POCs with proof/evidence as none of this can be theory." — *git*

> "Dispatch a specialist to look for chains across the existing findings, siblings so forth, look for any potential
> criticals. Dispatch another sub-agent to review existing standalone findings … look for escalation of severity,
> non-trivial creative ways are desired as well in addition to normal ways." — *fluent-bit*

> "Remember as a BugCrowd reviewer root cause and any siblings from that root cause is the same finding. Now the
> siblings can increase the overall severity especially what can be done with the siblings (say credentials)." — *bia.gov*

> "This means that VA-044 would be the root cause, and consolidated all into a single submission." — *cms.gov*

> "No this is not good enough, lets keep digging to escalate. … what other files do you want investigated in the
> source code? OR if that is not needed, then what exploit-developer sub-agents do you want to dispatch." — *bia.gov*

> "'Cookie Forgery (P3)' spend more time thinking on this, what else does this open us up to? Why are we blocked?
> I dont understand how this is still a P3 … With the source code what would help? Knowing of more paths? finding a
> SSRF? Help me understand." — *bia.gov*

**Stop-when-you've-proven-it discipline** (don't over-exploit, especially on `.gov`/`.mil`/prod):

> "Dispatch exploit developers to exploit the findings, stay true to the HackerOne recommendation of show
> proof/evidence/poc but dont go further then needed, you stop at the point that shows the attacker severity/real
> world impact, but dont need to exploit past that unless it could raise severity furthermore." — *.mil*

> "I setup researcher.example to point to 169.254.169.254. So you can continue testing, remember once you confirm,
> stop at confirmation no need to review anything further in their aws account." — *lastpass.com*

---

## 6. Phase 4 — Adversarial verification (the BugCrowd-reviewer mindset)

**This is the single most valuable recurring move in the whole corpus.** Before anything ships, a fresh,
low-context skeptic re-reviews it as a triager. The question that anchors everything: *"What can an attacker do
right now?"*

> "Dispatch a fresh specialist with little information to be a BugCrowd /libcurl reviewer to review the High,
> determine if A) There isn't anything missed in the code that guards it, that the local testing didn't cheat, and
> what the real world attack potential really is, what is the impact, who is affected, and is SSRF protection really
> on the application." — *libcurl*

> "Do an aggressive review again as a bugcrowd reviewer look for inconsistencies, and lack of impact.. 'What can an
> attacker do right now' is very important to answer the question of is this a P1, p2, p3, p4." — *cms.gov*

> "Act as a BugCrowd reviewer with knowledge on cms.gov, and review findings_payloads/…/ex-003.md for downgrades or
> lack of attacker impact today. I am concerned about severity downgrade." — *cms.gov*

> "Be careful where docs are WRONG but code is RIGHT this happens often and makes people look stupid when
> submitting." — *libcurl*

> "Make sure all the criticals would pass a bugcrowd reviewer, have full evidence, no theory, works against source
> code without the LLM actually changing source code, or work against the Docker image … Remember defense in depth,
> and if a vulnerability requires being on the server already unless its an escalating, its a lower severity. Think
> of things that would cause a downgrade." — *fluent-bit*

> "You sure this is not expected? Since its internal either way? Sanity check wise, are any of the 4 criticals that
> you ordered to be submitted have any obvious 'Uh yeah that is expected'." — *fluent-bit*

> "Are you sure '[finding]' is actually a finding, is it not a personal instance, or some weird clause 'you are an
> admin' this is expected. Just want to confirm." — *lastpass.com*

> "CV-017 seems a little too simple to be true, it very well appears to be true. Think of potential other reasons it
> could be wrong." — *fluent-bit*

> "I had to push and prod and push to get you to give me the real impact, without over hyping, over stating the
> criticality. How can this be improved, is there not a vulnerability reviewer or something that can help with
> downgrades?" — *cms.gov* *(→ this is why a dedicated FP/severity-downgrade reviewer step exists)*

**Codify the checks into a living document:**

> "Create a SEVERITY-IMPACT-CHECK.md document that encapsulates the checks, questions, tests that are being
> done/asked to find the real world exploitability." — *libcurl*

> "What .md exists for trying to help with handling severity downgrades in the future, i.e. real world attacker
> potential, not just fits a CVSS score … if not create one." — *cms.gov*

> "Write these guardrails/logic to a .md file that would hold other caveats to help in properly rating findings with
> correct severity." — *git*

---

## 7. Phase 5 — Reporting & submission

The report pipeline is consistent: **report-writer (draft) → report-writer (QA/structure) → operator normalize
across reports.** The rules are strict and repeated.

> "Then proceed with report creation report-writer and then dispatch another round of report writer to verify the
> report structure and quality, then a final agent to review consistency across the reports." — *git*

> "Dispatch report-writers, then a report normalizer across the submissions, and a report-writer QA to verify
> structure, consistency, get reports created for the Criticals and Highs." — *.mil*

> "Dispatch QA to verify reports are correct and follow the expected submission structure and rules for report
> writing to prevent AI slop." — *lastpass.com*

**The hard reporting rules (stated again and again):**

- **Standalone submissions** — no cross-references, no internal IDs, no tool names:
  > "Each submission needs to work standalone, i.e. should not mention other findings, consolidate where same root
  > cause." — *bia.gov*
  > "Lets not have submission v2s, and remember report-writer … we do not reference internal material, and finding
  > IDs. If files needed to be attached to the BugBounty submission that can be done, just reference the filename,
  > and make the filename more suitable for the submission." — *cms.gov*

- **No theory — evidence + working PoC only:**
  > "Make sure nothing speculative exists, and evidence/poc is firm. BugCrowd pushes back quickly when full evidence
  > and poc is not given." — *bia.gov*
  > "Remove almost all the theory but if app goes live, X can happen. Then that is all." — *bia.gov*

- **Write for the triager, not an IT person; kill AI slop:**
  > "Fix the wording in that this is being read by a BugCrowd triager not any IT person. So notes like 'HTTP allows
  > cleartext xyz' and 'Credentials masked' dont need to be said." — *bia.gov*
  > "As if you were a BugCrowd reviewer, what in the submission is just weird, non human like, doesn't really make
  > sense, and is said too obviously … Compare to professional high quality submissions. Then bullet list what you
  > see is off." — *cms.gov*
  > "It needs more, but be mindful of ai slop / wall of text it scares humans." — *fluent-bit*

- **Deduplicate; inline the PoC where you can:**
  > "I hate duplication. Why cant we have a disclosure email, and then attach only what is needed, and inline what we
  > can." — *fluent-bit*
  > "Don't force yourself to have one POC file at the top, prefer whatever is most needed … Inline — curl commands or
  > short HTTP in Steps to Reproduce; Single file — any extension; Multi-file — main entry point + supporting files." — *cms.gov*

- **Validate the VRT category actually exists** (a repeated triage-killer):
  > "Double check VRT categories as 'Broken Access Control > Insufficient Authorization > Sensitive Data' does not
  > exist. Check the others." — *cms.gov*
  > "You yourself pull BB VRT categories — the one you gave does not exist." — *cms.gov*

---

## 8. Phase 6 — Triage defense (after you submit)

Triage isn't the end — it's a phase with its own prompts. The move: **re-read as a reviewer, decide whether to
push back, and craft a tight, concise reply.**

> "So put a BB reviewer hat on, why would this close as no repro? is there lacking impact? Should I reply?" — *keeper/lastpass-macos*

> "I got my previous submission rejected due to them claiming it was brute forcing / resource exhaustion. Is
> [ex-003.md] at risk of that?" — *cms.gov*

> "They already closed the submission as saying its brute forcing, but totally skipped over the APIGW bypass which I
> could resubmit as a new finding. What do you think?" — *cms.gov*

> "[Finding] closed as INFO saying the info is already public, should I give any pushback." — *.mil*

> "Can you retest the default credentials and default cookie encryption key for bia.gov. They said they fixed the
> issue, and asked me in the submission to re-test." — *bia.gov*

> "Pull down fluent/fluent-bit master, and re-test … Reviewer said its been fixed in master." — *fluent-bit*

> "Then small oneliner argument I can paste at the top to argue for p3. Send it here do not edit submission." — *cms.gov*

> "Proceed with evidence/poc/no theory, and give me a solid reply to get a P4 if and only if you think the BB
> Reviewer wont push back anymore after this reply." — *cms.gov*

> "Look for cleanup opportunities in both submissions, especially look for where it seems like its talking in weird
> third person instead of to a triager. Then try and encapsulate this into a rule/prompt write to issues.md." — *cms.gov*

**Honesty guardrail you enforce repeatedly:** maintain the real severity, don't overreach.

> "I am not trying to actually raise severity … the goal right now is trying to MAINTAIN 9.1 … we may be overreaching
> some since the real world impact excluding what the CVSS actually says is looking less like a high." — *cms.gov*

> "I want to get what we have submitted. I am only interested in vulnerabilities that have real world impact, so if
> one of the criticals dont then lets not submit it right now." — *fluent-bit*

---

## 9. Cross-cutting: resume, status & recovery

Long engagements span days, models, crashes, and lost internet. A consistent vocabulary handles it.

**Resume:**
> "Read AGENTS.md, read operator-core.md, then resume the engagement." — *(every engagement)*
> "Continue from where you left off." / "Continue, lost internet. Resume exactly where you left off at, and
> resume/restart commands if needed." — *cms.gov*
> "Read OPERATOR_HANDOFF.md, AGENTS.md, Operator-core.md, and RULES.md, then resume the engagement. Do take
> OPERATOR_HANDOFF.md with a grain of salt, in that it may of missed things." — *.mil*

**Status / health checks:**
> "Check running specalists, make sure commands are still working, and files they are writing to are still being
> written to, and that nothing is stuck." — *(recurring)*
> "What happened? Looks like you stalled. Look at what failed, needs rerunning, or was running and mid execution
> failed." — *fluent-bit*
> "Check status, look for anything stuck, my laptop turned off (to sleep) for a bit." — *fluent-bit*
> "Stuck or still working?" — *lastpass.com*

**Recover & re-dispatch:**
> "Looks like the sub-agents failed, check why, determine what to do, redispatch." — *lastpass.com*
> "Agents died, re-dispatch the same ones, and continue where you left off at. (I switched from Sonnet 1m to Opus
> 4.7 1m so beware)." — *(recurring)*
> "Continue, previous model denied due to security, but this is an authorized engagement, and I am already Cyber
> verified." — *(recurring)*

**Keep the backend authoritative** (so the next session/agent isn't blind):
> "Make sure to continue keeping the backend findings updated, evidence, details, linking so forth." — *fluent-bit*
> "Give me a few sentences on what has been tried that isn't saved to the backend, so a new agent can resume." — *fluent-bit*
> "Distill the attacks / effort / Katana/gau coverage per target so I can start a new session, and go even deeper
> with IDOR, do not include any bias." — *cms.gov*

**Hands-free runs via Stop-hook goals** (let it run without babysitting):
> "A session-scoped Stop hook is now active with condition: 'Read operator-core.md every few batches, dispatch 3-7
> agents at a time for Vulnerability Analyst to work through all surfaces, stop once all surfaces / targets have
> been worked through, if a particular target did not receive a nuclei, katana, or nmap scan then run one…'" — *.mil*

---

## 10. Specialized tracks

### Source-code audit (git, libcurl, fluent-bit)

> "Continue the efforts, read operator-core-code.md, assume Operator role, and get these existing findings fully
> proofed and severity escalated where possible: [list of CV-/CH- findings, killed/stale, still-live clusters]." — *git*

> "From a BugCrowd vulnerability reviewer A) review these vulnerabilities and determine the real severity, and how
> the exploits are delivered then re-determine the severity B) if the severity drops then determine how it could be
> raised again, review more code C) dispatch specialist verifier agent to re-verify … confirm no other guards are in
> place D) create full end to end POCs with proof/evidence as none of this can be theory." — *git*

> "list-skills, checkout the fuzzing skills and C related BOFs, dispatch specialist sub-agents to do some targeted
> fuzzing to find other potential OOBs/BOFs … also think of non-trivial, creative ideas." — *fluent-bit*

> "Continue working till you can get RCE on a live binary without assist. Keep taking [notes], and working through
> different ideas. If you think the agents are getting consistently stuck do a deep research to think up other ideas
> or find similar RCEs/BOFs." — *fluent-bit*

> "The ASLR assist, a BugCrowd reviewer would call it out still. Continue the work to show a full end to end
> real-world POC." — *fluent-bit*

> "I want you to ignore what is actually said in the submission/finding, but actually look at the code itself, and
> also do research for other similar CVEs or similar discussion, I want to really make sure this is a real and
> unique finding nothing that has been discussed." — *libcurl*

> "Clone down cURL and verify not already resolved since I found it. … dispatch an agent to check what
> repositories/codebases/software would be affected by this finding." — *libcurl*

### Blue team / Google Workspace (acme)

> "Load the google workspaces skill, and the blue team related resources, read AGENTS.md this is not a red team
> engagement, its a blue team engagement. Then load agent/references/tenants/acme-workspace.md and start
> investigating. The alert details include: User / IP / Activity Date …" — *acme*

> "Did you load the blue team skill to understand how to use gam and other CLI tools.. Make sure you are using the
> correct GCP project as well." — *acme*

> "Distill the generic information you know about the Acme Workspace setup for another agent to continue
> doing threat hunts for when GWorkspace alerts come in. Provide things that would help the agent not have to hunt
> for information." — *acme*

> "False positive register is so important for future blue team engagements, anything else you would want include if
> the backend was adding blue team centric features?" — *acme*

### Hardware / device (iPhone)

> "Read AGENTS.md, Assume Operator role, load in information on red team engagements against iPhones. I have an
> iphone plugged in, pull whatever info you can on it." — *iphone*

> "As part of an authorized engagement see AGENTS.md and operator-core-code.md I need to bypass the login. … Either
> using the existing API access we have now, or using an existing CVE, or creating a new bypass." — *iphone*

> "Signed customer consent form on file. Document the hardware attack surface, threat model, and then plan out but
> dont execute DFU mode backup, happy to do a complete reset." — *iphone*

---

## 11. The one-liner arsenal

Short prompts that punch above their weight, grouped by intent. Keep these in muscle memory.

**Push forward**
- `Continue` · `Go` · `Status?`
- "Continue with dispatches" / "Continue with multi agent dispatch on the tier 1 & 2"
- "Dispatch sub-agents to test these new things"
- "Use the attack value, try and find more vulnerabilities dispatch 2-3 more sub-agents"
- "Any other areas, please dispatch 2 more agents that'll handle 20 agents of their own."

**Dig deeper**
- "Try and escalate, authenticate with a session."
- "Continue with exploit developer for findings that need to be proved, escalated, chained."
- "Dispatch a fresh agent with little context for [finding] to further think of severity downgrades, verify sinks."
- "Think of potential other reasons it could be wrong."
- "Merge if same root cause."

**Verify / sanity-check**
- "Did you actually test [function]? If not proceed and verify."
- "How is [finding] actually high … what real world attack can be launched right now?"
- "The criticals we have so far, none have the same root cause yes?"
- "So what happened? What did you downgrade, what was verified, what was FP'd? Are you highly certain?"
- "Confirm and not just read the .md, but is the data that is exposed actually not public."

**Report / submit**
- "Provide links to submissions if they are done, I will submit them."
- "For each submission, provide me the Attack Vector, Attack Complexity, etc — the long names of each, HackerOne
  requires it when submitting."
- "Provide me the report filepath for each in order, and entrypoint — I mean from an attacker standpoint."

---

## 12. What made these prompts work

Patterns that show up again and again in the prompts that produced real, accepted findings:

1. **Lead with the role + scope + rules, every time.** `Read AGENTS.md → operator-core(-code).md → assume Operator`
   and paste authorization/scope verbatim. It re-grounds the model after compaction, model switches, and resumes.

2. **Make the Operator the brain and fan out aggressively.** "Dispatch batches (3-7, sometimes 50) of specialists";
   "you as the Operator stay as the brain." Parallelism is the throughput.

3. **"Non-trivial, creative, out-of-the-box" is your highest-yield phrase.** It explicitly licenses the agent to
   leave the obvious path — and it's what surfaced the chains and variants.

4. **Depth over speed, always — "leave no stone unturned."** You repeatedly reject time as a metric:
   *"Stop using time as a way to measure if something should be tested. It all should be thoroughly tested."*

5. **Anchor hunts on a known high-value pattern** (Log4j-style log-ingestion RCE, the SSRF that worked, the
   blank-password bypass) and hunt for siblings/variants/chains off its root cause.

6. **Adversarial fresh-eyes verification before anything ships.** A low-context "BugCrowd reviewer" skeptic that
   asks *"what can an attacker do RIGHT NOW?"*, hunts downgrades, and flags "that's expected" — this is what kept
   submissions from getting closed.

7. **Real-world impact > CVSS math.** You consistently de-hype: maintain the honest severity, drop theory,
   only submit things with genuine attacker impact.

8. **Strict report hygiene:** standalone, no internal IDs/tool names, no theory, working PoC (inline where
   possible), validated VRT category, zero AI slop, written for the triager.

9. **Encapsulate wins into docs/skills.** When a prompt or check worked, you ask to write it into a `.md`
   (severity guardrails, FP checks, IDOR tactics, IMPROVEMENTS.md) so the next engagement starts smarter.

10. **Keep the backend authoritative and treat triage as a phase** with its own re-tests, pushbacks, and concise
    reviewer replies.

---

## 13. Copy-paste templates

### A. Engagement kickoff (web / bug bounty)
```
Read AGENTS.md and assume Operator role (operator-core.md).
Authorized bug-bounty engagement: <program URL>. Full authorization confirmed.
Read RULES.md — following the rules is critical, we don't want to get banned from future engagements.
In-scope: <domains>.  Out-of-scope: <domains>.  Update scope.json.
Exploitation policy: <pause / allowed>.
Make heavy use of sub-agents, dispatch in parallel where phases permit. Do not rush — leave no stone unturned.
Start the engagement.
```

### B. Phase 1 recon push
```
Phase 1 (recon) is the sole priority — no urgency to advance. Dispatch batches of recon/OSINT specialists to find
ALL subdomains and surfaces, ingest everything. Depth over speed; throttle UDP/DNS so we don't crash anything.
Then dispatch a QA specialist to verify the commands that should've run did run — was katana run? gau? were results
bucketed and triaged? are all hosts liveness-checked? Fill any gaps. Tell me coverage % per host and what's next.
```

### C. Hunt deeper
```
Continue dispatching batches of specialists (3-7 at a time) across all surfaces. Don't over-constrain them — give
findings/ideas and let them run deep (10-15m each, not 20-30s). Specifically try NON-TRIVIAL, CREATIVE,
out-of-the-box exploitation ideas, and look for chains + siblings off existing root causes. Load adversial-mindset.md.
Log everything to the backend + assess log so we don't re-run work. Don't stop until <condition>; if stuck, try a
different way or do a deep-research pass for similar CVEs/techniques.
```

### D. Escalate / chain
```
For <finding>: what is the real-world entrypoint, how does it work, what is the impact, and can it go higher?
Dispatch a specialist to find chains across existing findings (siblings share a root cause). Dispatch exploit-developer
to (A) verify and (B) raise severity. Stop at the point that proves attacker impact — don't over-exploit on prod.
```

### E. Adversarial verification (do this before every submission)
```
Dispatch a fresh specialist with little context to act as a BugCrowd/<vendor> reviewer on <finding>:
- What can an attacker do RIGHT NOW? Is this real-world impact or just CVSS-fits-the-criteria?
- Did local testing cheat / are there guards in code that kill it? (docs may be wrong but code right — check code.)
- Is any of it "that's expected" (internal-only, requires existing access, personal instance, public-by-design)?
- Look for downgrades and missing evidence. Bullet-list what's off.
Then tell me if a downgrade is warranted and whether a BugCrowd reviewer would push back.
```

### F. Report pipeline
```
Dispatch report-writer (draft) for <findings>, following report-writer.md / reporting.md rules:
standalone submissions, no internal IDs or tool names, no theory, working PoC (inline where possible), validated VRT
category that actually exists, zero AI slop, written for the triager. Then dispatch a fresh report-writer in QA mode
to fix structure, then normalize across all reports. Give me the file path + attacker entrypoint for each so I can submit.
```

### G. Triage reply
```
They closed/pushed back on <submission> saying <reason>. Put a BugCrowd-reviewer hat on: is the pushback fair?
If we should push back, give me a concise, professional reply (paste it here, don't edit the submission) that proves
real-world impact with evidence — only if you genuinely think they'll stop pushing back after it. If they're right,
say so and tell me whether to resubmit under a different VRT or drop it.
```

### H. Resume
```
Read AGENTS.md → operator-core(-code).md → assume Operator role → resume the engagement exactly where it left off.
Check running specialists are alive and writing files; re-dispatch any that died. Take OPERATOR_HANDOFF.md with a
grain of salt. Keep the backend findings authoritative as you go.
```

---

*Generated from session-history review of all `~/security-research` and `~/vigil` engagements. All quotes are real
operator prompts, lightly cleaned for typos only where it aided readability.*
