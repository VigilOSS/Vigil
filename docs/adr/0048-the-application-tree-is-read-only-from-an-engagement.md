# ADR 0048 — The application tree is read-only from an engagement

- Status: Accepted — rule in `agent/operator-core.md`, `agent/operator-core-blue.md` and
  `agent/shared-specialist-core.md`; hook `agent/scripts/hooks/application-read-only.sh`
- Date: 2026-11-14
- Amends: [ADR 0019](0019-vigil-does-not-defend-against-its-own-operator.md), section
  "PreToolUse command-filtering hooks are not reintroduced"

## Context

An engagement operator diagnosed a real crawler-scope defect, then edited the harness to fix it:
three `Edit` calls and a scripted rewrite of `web_discovery.py`, two more on `lib/scope.py`, and a
decision row saying "FIX APPLIED". Told to stop, it reverted both files with
`git checkout -- web_discovery.py lib/scope.py`. The application tree was an editable install: the
maintainer's working copy, with other uncommitted work in it. The revert happened to touch only the
operator's own hunks; a `git checkout` on that tree would equally have wiped concurrent edits.

Nothing told it not to. The operator and specialist cores had no rule about the application tree,
the engagement pointer handed it the absolute path of a writable git checkout, and the engagement's
own issues file, which encourages diagnosing harness defects down to the line, made the step from
diagnosis to `Edit` short. Bypass-permissions mode refused nothing.

The harness is what gives the engagement's records their meaning: the gates that decide a phase is
done, the scope fence, receipt and proof checks, the contracts every write is validated against. An
engagement session that edits it changes those rules for itself and for every other engagement on
the same install, without review, and the change shows nowhere in the engagement's evidence.

## Decision

The Vigil application tree is read-only from an engagement session. The operator cores and the
shared specialist core state it: do not edit, format, revert or check out files there, even to fix
a defect already pinned to a file and line. A harness defect is recorded with its failing command,
the error and the per-run workaround (operator: the engagement's `ISSUES-AND-ENHANCEMENTS.md`;
specialist: the handoff's `runtime_issues`), surfaced to the user, and worked around.

A `PreToolUse` hook backs the rule in every client with a hook surface (Claude, Codex, Goose,
OpenCode). It refuses a call that would modify the directory holding the hook's agent root, or
`$VIGIL_APPLICATION_DIR`, and names that directory and where the defect goes instead. The
engagement directory is exempt. It reads structure, not prose:

- file tools by their own target-path field, resolved through symlinks, so a write through an
  engagement symlink into the application (`.claude/agents/`) is caught;
- shell commands by the paths their grammar says they write: redirection targets, operands of
  file-changing programs, `cp`/`install`/`ln`/`rsync` destinations, `sed`/`perl -i`, `dd of=`,
  `patch`, `find -delete`/`-exec`, and git or jj subcommands outside a read-only set when their work
  tree or pathspec lies under the application. `bash -c` and `eval` bodies are read one level deep,
  as are commands inside compound commands (`if`/`then`, `for`/`while` `do`, `{ ...; }`, `case`
  arms, `!`) and after wrappers that run another program (`sudo -u USER`, `env`, `nice -n`,
  `timeout`, `xargs`). Relative paths resolve against the working directory the command reaches
  through `cd`, `cd -`, `pushd` and `popd`; a directory change inside a subshell (`( )`, `$( )`,
  backticks, a `bash -c` body) ends with it.

### Why this is not the hook ADR 0019 removed

ADR 0019 removed `scope-check.sh` because it string-matched four destructive command shapes,
protected the operator's own machine from the operator, and failed silently on every other spelling
of the same command. It asked that a future agent-error guardrail first get its own review of the
trust boundary. This is that review.

The boundary here is the harness's integrity, the same reason proof and evidence integrity stay in
ADR 0019's list of real controls: an edited harness changes what recorded evidence means. The rule is
the control; it lives in the prompts every engagement agent loads, and it holds whether or not the
hook sees a given write. The hook makes the ordinary violations loud at the moment they happen and
teaches the alternative in its refusal. It is a tripwire, not a sandbox: a script file, an
interpreter's inline code (`python3 -c`, a here-doc fed to `python3 -`), or a variable it cannot
expand can still write to the tree. Nothing relies on it as a boundary, so its misses cost what the
prompt rule alone would have cost, and documentation says plainly what it does not see.

It also does not filter what the operator does to targets, to the engagement, or to the rest of the
machine, and it never masks or rewrites data.

## Consequences

- Engagement sessions report harness defects instead of patching them; the maintainer fixes them in
  a reviewed change.
- A command that names the application tree and writes elsewhere, or reads it, runs as before; a
  `git -C <application> status` or `log` runs, a `checkout`, `restore`, `reset` or `stash` does not.
- The hook needs `jq`; without it, or outside an engagement session, it allows every call.
- ZCode, kimi and pi have no hook binding and rely on the rule alone.
- OpenCode runs the hook from its plugin's `tool.execute.before`, which does not fire for a
  subagent's (`task`) tool calls or for MCP tools (opencode#5894). A specialist dispatched in
  OpenCode relies on the rule alone; the operator's own calls are checked.
- An existing Codex engagement gains the hook on its next refresh: the generated
  `.codex/config.toml` keeps the operator's tables and appends each Vigil hook table it lacks,
  the same merge the Claude settings get.
