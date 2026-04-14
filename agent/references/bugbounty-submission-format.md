# Bug Bounty Submission Format

Use this format when the operator requests a bug bounty submission (Bugcrowd, HackerOne, or similar platform). Each finding is a standalone submission.

## Structure

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Platform taxonomy category path]

**Severity:** [P1-P4 or Critical/High/Medium/Low]

**POC:** `[file path]`
**Run:** `[exact command]`
**Pass if:** [one-line expected output that proves the finding]

---

### Description
[2-4 sentences. First sentence = attacker outcome. Then the code fault. Then what the POC proves.]

### Steps to Reproduce
[Numbered steps. One action per step. No narrative between steps. Include the POC command.]

### Evidence
[Key POC output proving the finding. Annotated with <-- proof markers on critical lines.
Truncated to only the lines that matter. No full tool dumps.]

### Attack Scenario
[2-3 sentences. Concrete attacker persona + action + outcome. No theory.]

### Impact
[1-2 sentences. Proven impact only.]

### Remediation
[1-2 sentences. Name the technology, the control, the fix.]
```

## Rules

- Each finding is one submission. Do not bundle.
- The POC must exercise the vendor's code, not reimplemented logic. Import and call their functions. Run their binary. Show their output.
- If end-to-end testing requires infrastructure (LDAP server, SSH host, proxy), document what the human sets up and what the script does. Use `# HUMAN:` comments in scripts for manual steps.
- Evidence must come from running the POC, not from reading the source. Code analysis supports the description but does not replace proof.
- Credentials and secrets go in environment variables, never in submission text or script source.
- No theory. No "could potentially." No "may allow." State what happens, not what might.
- No class definitions. The triager knows what LDAP injection is.
- Active voice. Subject-verb-object.
- Every sentence must be load-bearing. If removing it does not reduce understanding, remove it.

## Example

See `agent/references/examples/bugbounty-submission-ldap-injection.md` for a complete example of this format applied to an LDAP injection finding with a working POC.
