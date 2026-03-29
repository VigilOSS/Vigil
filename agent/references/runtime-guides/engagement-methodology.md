# Engagement Methodology

Primary engagement style and investigation mindset for `security-research`.

## Engagement Style

- Work like an experienced operator, not a point scanner.
- Treat web, services, credentials, pivots, and post-access as one connected assessment.
- Use the durable orchestrator state for tracking, but keep the investigative mindset evidence-first and chain-oriented.
- Prefer proving impact over listing weak signals.
- If a finding suggests a deeper chain, spend effort trying to raise severity before moving on.
- Read between the lines: infer backend frameworks, proxies, auth boundaries, and internal architecture from subtle indicators.
- Prefer realistic attack paths that transfer to real environments rather than challenge-style hidden-step assumptions.

## Methodology Pillars

### External Assessment + Threat Hunting

Combine:
- external attack-surface mapping
- vulnerability assessment
- exploitation and chain analysis
- behavioral validation where logs or telemetry exist

### PEAK Thinking

Use PEAK as the hunt mindset:
- preserve evidence as you go
- expand from indicators into behaviors and techniques
- assess attacker goals, pivots, and follow-on opportunities
- keep knowledge in a form that supports later reporting and incident review

### Hypothesis-Driven Recon

Recon is not only inventory.

Use observations to form hypotheses about:
- framework and middleware behavior
- hidden trust boundaries
- internal routing or proxy layers
- likely privileged workflows
- post-auth or internal-only reachability

### Pyramid of Pain

Bias toward findings that move beyond easy indicators:
- exposed paths, headers, and versions matter, but they are starting points
- auth boundaries, object references, unsafe workflows, and trust violations matter more
- attacker behaviors, access patterns, and repeatable chains matter most

### MITRE ATT&CK Mapping

When a finding or chain is material, note:
- the ATT&CK technique or sub-technique
- what stage of the chain it supports
- what telemetry would have shown it

Do not force ATT&CK language onto every low-signal issue. Use it where it clarifies attacker behavior.

## Coverage Expectations

### Do Not Pin-Hole Into Web Only

Web is often the largest surface, but not the only one.

Track and test:
- network exposure and ports
- service banners and protocol behavior
- auth and credential use
- tunnels, pivots, and post-access opportunities
- web request variants, auth states, and payload families

### Auth States Matter

Unauthenticated and authenticated coverage are separate.

If credentials are found or provided:
- re-run collection where auth changes reachability
- retest previously blocked or partial findings
- record which findings were only blocked by missing auth

### Auth-Blocked Findings Are Still Real

Do not dismiss a finding because it needs a session first.

Document:
- what access is needed
- what would be tested next
- what impact follows with valid auth

## Depth and Escalation

### Never Stop at the First Finding

For each real issue, ask:
- can this be chained with another issue
- can this reach a more privileged workflow
- can this move from read to write, or from partial to decisive proof
- can this reach internal services or cross trust boundaries

### Proof Standard

Every important finding should answer:
- what was tested
- what happened
- why it matters
- how it could be repeated

Prefer:
- exact request/response evidence
- replayable commands
- direct impact statements

When a decisive exploit is not immediate, prove it in stages:
- timing/sleep or behavior change
- DNS or OOB callbacks
- environment or config leakage
- version or file-read disclosure
- then code execution or post-access when justified

### Completeness Audit

At each phase boundary, check:
- which services were discovered but not tested
- which request variants were discovered but not covered
- which findings remain partial or blocked
- which attack families were not exercised yet
- which discovered surfaces remain unresolved

## Reporting Expectations

- Merge overlapping findings into authoritative final findings.
- Preserve decisive proof in the body, not only in raw artifacts.
- Distinguish live-confirmed, code-confirmed, and auth-blocked results.
- Call out gaps honestly where logs, credentials, or telemetry were unavailable.

## Optional Final Athena Phase

If Athena or log access is available, add an optional final validation phase after exploit testing and before final report closure:
- query WAF, ALB, CloudTrail, or application logs for signs of prior exploitation
- search for the exact paths, parameters, IPs, headers, and payload families surfaced during testing
- record whether the evidence shows exploitation, likely exploitation, or no evidence in the available retention window

Use the dedicated Athena skill for that work:
- `agent/skills/athena-log-investigation/SKILL.md`
