---
name: container-escape-detection
description: Detect and test container escape vectors — privileged containers, Docker socket exposure, cgroup abuse, kernel exploits
origin: Vigil
---

# Container Escape Detection

## When to Activate

- You hold an execution channel inside a **target** container or pod (an approved RCE, shell or
  exec primitive recorded under exploit approval), or are assessing a containerised deployment's
  runtime controls. Blue use: validating Falco/seccomp/AppArmor coverage after a suspected
  breakout (detection rules belong to the alert-triage skills).

**Where the commands run.** `vigil assess kali exec` executes inside Vigil's own runtime
container: enumeration or an escape run there tests the operator's machine, not the target. Run
in-container checks through the target's execution channel, with `kali exec` carrying only the
network leg (the request that delivers the command). `--technique RECON` for enumeration,
`EXPLOIT-CHAIN` for a breakout attempt; a breakout, host write, module load or anything that
can crash the host needs `--destructive` and explicit exploit approval.

## Methodology

Self-identification and enumeration are standard (`/.dockerenv`, `/proc/1/cgroup`, `capsh
--print`/CapEff, seccomp and AppArmor status, mounts, sockets; amicontained, deepce or CDK when
present on the target). Then check each escape family:

- **Privileged container** (all capabilities, host devices): host filesystem mount + chroot.
- **Runtime sockets:** `docker.sock`, `containerd.sock`, `crio.sock` mounted anywhere, not only
  `/var/run/` — creating a container with the host root bind-mounted is host root.
- **Sensitive mounts:** host `/`, `/proc/1/root`, `/var/lib/docker`, `/etc/kubernetes`;
  writable `/proc/sys/kernel/core_pattern` or `/sys/kernel/uevent_helper` (helper execution on
  crash/device events); `/proc/sysrq-trigger` (can reboot or crash the host — never fire it).
- **Capabilities beyond the default set**, each with a known gadget: `CAP_SYS_ADMIN` (cgroup v1
  `release_agent`, CVE-2022-0492), `CAP_SYS_MODULE` (module load), `CAP_SYS_PTRACE` (inject into
  host processes with host PID), `CAP_DAC_READ_SEARCH` (Shocker-style file-handle reads),
  `CAP_NET_ADMIN`/`CAP_NET_RAW` (network-namespace abuse).
- **Host PID namespace:** `nsenter --target 1 …`.
- **Kernel:** an unpatched host kernel is exploitable regardless of capabilities (Dirty Pipe
  CVE-2022-0847, OverlayFS bugs, CVE-2024-1086); confirm kernel exposure before calling the
  container hardened.
- **Kubernetes:** the service-account token's RBAC (`kubectl auth can-i --list`); `pods`,
  `pods/exec`, `secrets`, `configmaps`, `nodes` or `clusterrolebindings` permissions, or pod
  creation with `hostPID`/`hostNetwork`/`hostIPC`, enable movement even when the host is sealed.

## Escape Binaries (Detection)
Alert on these binaries executing inside containers:
`nsenter`, `unshare`, `mount`, `chroot`, `modprobe`, `insmod`

Falco rule example:
```yaml
- rule: Container Escape via nsenter
  desc: nsenter executed inside container — potential breakout
  condition: container.id != host and proc.name = nsenter
  output: "Container escape attempt (user=%user.name container=%container.name proc=%proc.cmdline)"
  priority: CRITICAL
```

## Proof

Show the vector and a benign host-level marker (e.g. host `hostname`/`id` via the escaped
context, or writing and removing a marker file under approval), not host credential files or
cluster secret dumps (`agent/rules/hunting.md` §2, §10). Severity:
`agent/references/finding-fp-and-severity-gate.md`. Format:
`agent/references/runtime-guides/web-finding-recording.md`. Record runtime and version,
capabilities vs default, seccomp/AppArmor state, mounts and sockets, the vector, and the
service-account RBAC.

## Kill and escalate

- No extra capabilities, no runtime socket or sensitive mount, seccomp and AppArmor enforcing,
  patched kernel → hardened; an SA token without pod-create/exec rights → no Kubernetes path.
- A privileged container or a mounted runtime socket is the whole finding once proven; still
  note the other vectors present, since remediation needs all of them.
