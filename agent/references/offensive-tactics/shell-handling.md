---
description: pwncat-vl listener commands, tmux session and log conventions, `.listener_url` callback addresses for reverse shells — paired with `agent/skills/exploit-playbook-authoring/SKILL.md` for playbook bash structure and `# MANUAL:` annotation conventions
skill: exploit-playbook-authoring
---

# Shell Handling & Post-Exploitation Listeners

## Who runs what

Listeners (pwncat-vl), frp tunnels and `chisel server` are operator-controlled shared
infrastructure (`agent/shared-constraints.md` §2a): the Kali runtime is shared across
engagements, so a listener an agent starts on 4444 can collide with another engagement's.

- The agent writes the exact listener command as a `# MANUAL:` playbook step, supplies the
  reverse-shell payload, and waits for the operator's confirmation before continuing past it.
- The operator runs it, exposes it through frp, and records the address in `$DIR/.listener_url`.
- The agent reads `LISTENER_HOST:LISTENER_PORT` from `$DIR/.listener_url` (or dispatch context)
  and never hardcodes a tunnel address. Without the file, record a blocked technique (`agent/shared-constraints.md` §12).
- Agents leave existing listener and tunnel sessions running; stopping one breaks whoever else
  is using it.

Tunnel exposure and OOB callbacks (interactsh) are in
`agent/references/offensive-tactics/frp-tunneling.md`. The `oob-rev` proxy that `vigil oob start`
renders in `/data/oob/frpc.toml` exposes the listener; once `vigil oob status` is healthy the
operator records it, e.g. `echo "<frp-host>:8443" > "$DIR/.listener_url"`.

## pwncat-vl listener commands

pwncat-vl is the maintained fork of pwncat-cs (Python 3.13+). Run each session in a named tmux
session with output teed to `/data/`, which is the shared runtime data mount, so the log survives
tmux restarts and agents can read it:

```bash
vigil runtime shell-exec "tmux new-session -d -s shell-4444 'pwncat -l -p 4444 2>&1 | tee /data/shell-4444.log'"
```

The same shape covers `--ssl` listeners, bind shells (`pwncat -c TARGET_IP -p 4444`), and SSH
sessions with recovered keys (`pwncat -c TARGET_IP -p 22 --ssh --identity /data/<key>`).

Naming: shell sessions are `shell-<port>` or `shell-<tag>`; tunnel sessions are `frp-<name>`.

## Observing a session

Agents read shell output through `vigil runtime shell-exec` because listeners are shared runtime
infrastructure, not target-facing probes:

```bash
vigil runtime shell-exec "tmux list-sessions"
vigil runtime shell-exec "tail -80 /data/shell-4444.log"
vigil runtime shell-exec "tmux send-keys -t shell-4444 'whoami' Enter"   # for the operator to run
```

Record what the log shows (shell connected, command output) in the finding, probe-run or handoff;
the backend is the durable record, the log is not. Interactive `tmux attach` is for manual operator
debugging only.
