"""Host-side DNS resolution + ``--resolve`` IP-pinning for the kali HTTP path (CR-36).

On macOS Docker Desktop the container's resolver is unreliable (engagement I-013:
the in-VM ``com.docker.backend`` userspace DNS proxy intermittently returns
``http=000`` / SERVFAIL for a name that resolves fine on the host). A container
HTTP probe that hits that flap looks identical to a real ``connection-refused`` /
patched / 404 from the target — a SILENT FALSE NEGATIVE an agent could record as a
clean target verdict.

The durable fix has two halves, both implemented here and wired from
``kali.kali_exec``:

1. **Pre-flight ``--resolve`` pin** (:func:`apply_resolve_pin`): before the run, on
   Docker Desktop, resolve the target host on the HOST (``socket.getaddrinfo``) and
   inject ``--resolve <host>:<port>:<ip>`` into the tool argv so the in-container
   HTTP request bypasses the broken container resolver entirely. curl, httpx,
   nuclei and katana all accept ``--resolve`` with identical ``host:port:ip``
   syntax. ffuf is deliberately NOT pinned (I-10): its flag parser has no
   ``--resolve`` and would abort the run; see ``RESOLVE_PIN_TOOLS``.

2. **Post-run host-resolved retry input** (:func:`resolve_host_ips`): when the
   false-negative guard in ``kali_exec`` detects the ``http=000`` /
   connection-failed / DNS-resolution-failure signature, it re-resolves on the host
   and retries ONCE with the pin before the result is allowed to stand.

Platform posture (locked): host resolution + pinning ACTIVATE only on macOS Docker
Desktop (via :func:`runtime_route.detect_runtime`) and are a transparent NO-OP on
native Linux / remote Docker, where the container resolver is the real, correct
resolver and a clean connection-refused is a legitimate verdict. The behavior ships
ON with an operator escape hatch: set ``VIGIL_NO_RESOLVE_PIN=1`` (or pass an
explicit ``--resolve`` for the host yourself — pinning is idempotent and never
double-adds).

Multi-A-record hosts: a host with several A records is pinned to the FIRST address
``getaddrinfo`` returns, by default (:func:`resolve_host_ips` returns the full,
order-preserving, de-duplicated list; the pin uses ``ips[0]``). This is a
deliberate, documented choice — pinning one edge keeps the probe deterministic and
matches what a single in-container request would have hit. The trade-off is that a
per-edge difference (one CDN PoP behaving differently) is not exercised by the pin;
an operator who needs to fan across edges should pin each explicitly. The resolved
IP is surfaced on stderr so it is auditable.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys

from . import runtime_route
from .kali_audit import _extract_target_anchor

# Tools whose HTTP request honors a ``--resolve host:port:ip`` pin with curl's
# syntax. curl/httpx/nuclei/katana all accept the identical ``host:port:ip``
# form. sqlmap and ffuf are EXCLUDED — they have no equivalent host-pin flag, so
# injecting ``--resolve`` makes them reject the argument and abort the run.
#
# ffuf in particular (I-10): the image's ffuf (v2.x) has no ``--resolve`` flag —
# its Go flag parser errors with "flag provided but not defined: -resolve" and
# exits 2 WITHOUT firing the probe, so a pin would turn a recoverable
# Docker-Desktop resolver flap into a hard, silent total failure of every pinned
# ffuf run. ffuf also supports the ``FUZZ`` keyword in the host position (vhost
# fuzzing), where there is no single fixed host to pin, so a URL-rewrite +
# ``Host:``/``-sni`` translation would silently corrupt those runs. ffuf stays
# an http-prober (``is_http_prober``), so the post-run http=000 false-negative
# guard still arms for it and records a TRANSPORT ERROR (not a target verdict),
# directing the operator to re-run via the host path — the safety property holds
# without the broken pin.
RESOLVE_PIN_TOOLS: frozenset[str] = frozenset({"curl", "httpx", "nuclei", "katana"})

# Operator escape hatch. Truthy disables host-resolve + --resolve pinning even on
# Docker Desktop (mirrors the --no-resolve-pin flag; threaded via env because the
# kali CLI scaffolding is owned by a sibling module). Default OFF → pinning ON.
_NO_PIN_ENV = "VIGIL_NO_RESOLVE_PIN"

# Default ports by URL scheme when the target URL carries no explicit port.
_DEFAULT_PORT_HTTPS = 443
_DEFAULT_PORT_HTTP = 80


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def pinning_disabled() -> bool:
    """True when the operator opted out of host-resolve pinning (``VIGIL_NO_RESOLVE_PIN``)."""
    return _truthy(os.environ.get(_NO_PIN_ENV))


def is_pin_eligible_runtime(runtime: runtime_route.RuntimeInfo | None = None) -> bool:
    """True only on macOS Docker Desktop (where the container resolver flap occurs).

    Transparent no-op everywhere else: native Linux / remote Docker uses the real
    container resolver, so pinning would be both unnecessary and a behavior change
    on a platform where a clean connection-refused is a legitimate verdict.
    """
    rt = runtime if runtime is not None else runtime_route.detect_runtime()
    return bool(rt.is_docker_desktop)


def _exe_name(cmd: list[str]) -> str:
    return os.path.basename(str(cmd[0])).lower() if cmd else ""


def _is_ip_literal(host: str) -> bool:
    """True when ``host`` is already an IP literal (nothing to resolve / pin)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _default_port_for(cmd: list[str], host: str) -> int:
    """Pick the port to pin when the target URL carried no explicit port.

    Defaults to 443 unless an ``http://<host>`` (non-TLS) URL for this host is
    present in the argv, in which case 80. Mirrors curl/httpx scheme defaults.
    """
    host_l = (host or "").lower()
    for token in cmd[1:]:
        text = str(token)
        if host_l and host_l in text.lower() and text.lower().startswith("http://"):
            return _DEFAULT_PORT_HTTP
    return _DEFAULT_PORT_HTTPS


def _resolve_target(tool_name: str, cmd: list[str]) -> tuple[str, int]:
    """Return ``(host, port)`` of the probe's target, or ``("", 0)`` if none/IP.

    Uses the shared :func:`_extract_target_anchor` so the host/port parse stays
    single-sourced with the audit + depth-ledger anchor logic. An IP-literal host
    is returned as ``("", 0)`` — there is nothing to resolve, and pinning an IP to
    itself is a no-op that would only risk a malformed flag.
    """
    host, _path, port = _extract_target_anchor(tool_name, cmd)
    if not host or _is_ip_literal(host):
        return "", 0
    if not port:
        port = _default_port_for(cmd, host)
    return host, int(port)


def resolve_host_ips(host: str) -> list[str]:
    """Resolve ``host`` to its IPv4/IPv6 addresses ON THE HOST, IPv4 before IPv6.

    Order-preserving de-dup of ``socket.getaddrinfo`` results, but with ALL IPv4
    (A) addresses returned BEFORE any IPv6 (AAAA), preserving the original
    relative order within each family (I-11). ``--resolve`` pins ``ips[0]``, and
    ``getaddrinfo`` may legitimately return the AAAA first (RFC 6724 / a
    v6-preferring resolver); pinning an AAAA on an IPv4-only container runtime
    makes the in-container HTTP request fail with http=000, which the
    false-negative guard then surfaces as a SUPPRESSED real surface. Putting the
    IPv4 first keeps the pin probe-able in the common (v4-reachable) case.

    Returns ``[]`` on any resolution failure — the caller treats an empty result
    as "could not pin" and proceeds without the pin (never hard-fails on the
    pre-flight path; the post-run guard surfaces a transport error instead).
    """
    if not host or _is_ip_literal(host):
        return []
    ipv4: list[str] = []
    ipv6: list[str] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    for info in infos:
        family = info[0]
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if not ip or ip in seen:
            continue
        seen.add(ip)
        # Classify by the returned address itself (robust to AI_V4MAPPED forms),
        # falling back to the addrinfo family if the literal won't parse.
        try:
            is_v4 = ipaddress.ip_address(ip).version == 4
        except ValueError:
            is_v4 = family == socket.AF_INET
        (ipv4 if is_v4 else ipv6).append(ip)
    return ipv4 + ipv6


def _already_pinned(cmd: list[str], host: str, port: int) -> bool:
    """True when the argv already carries a ``--resolve`` for this host:port.

    Idempotency guard: if the operator (or a prior pin pass) supplied
    ``--resolve <host>:<port>:...`` we must NOT double-add. Matches host+port
    case-insensitively on the host; a ``--resolve`` for a *different* host:port is
    left untouched (curl allows several).
    """
    host_l = (host or "").lower()
    prefix = f"{host_l}:{port}:"
    for idx, token in enumerate(cmd):
        if token == "--resolve" and idx + 1 < len(cmd):
            val = str(cmd[idx + 1]).strip().lower()
            if val.startswith(prefix) or val.startswith(f"{host_l}:*:"):
                return True
    return False


def apply_resolve_pin(
    cmd: list[str],
    tool_name: str,
    *,
    runtime: runtime_route.RuntimeInfo | None = None,
    ips: list[str] | None = None,
) -> str | None:
    """Inject ``--resolve <host>:<port>:<ip>`` into ``cmd`` so the container HTTP
    request bypasses the broken Docker-Desktop container resolver.

    Mutates ``cmd`` in place (parallel to ``_apply_identity_material``). Returns the
    pinned IP string when a pin was added, else ``None``. NO-OP (returns ``None``)
    when any of: the operator opted out (``VIGIL_NO_RESOLVE_PIN``); the runtime is
    not Docker Desktop; the tool does not honor ``--resolve``; the target is an
    IP-literal / un-parseable / list-mode; host resolution failed; or a
    ``--resolve`` for this host:port is already present (idempotent).

    Multi-A: pins the FIRST resolved address (see module docstring). ``ips`` may be
    passed to reuse an already-resolved list (the post-run retry path does this).
    """
    if pinning_disabled():
        return None
    if not is_pin_eligible_runtime(runtime):
        return None
    if _exe_name(cmd) not in RESOLVE_PIN_TOOLS:
        return None
    host, port = _resolve_target(tool_name, cmd)
    if not host or not port:
        return None
    if _already_pinned(cmd, host, port):
        return None
    resolved = ips if ips is not None else resolve_host_ips(host)
    if not resolved:
        return None
    pin_ip = resolved[0]
    cmd.extend(["--resolve", f"{host}:{port}:{pin_ip}"])
    return pin_ip


def target_host_port(tool_name: str, cmd: list[str]) -> tuple[str, int]:
    """Public accessor for the parsed ``(host, port)`` (``("", 0)`` if none/IP).

    Used by the post-run false-negative guard to re-resolve the same target for
    the single pinned-IP retry.
    """
    return _resolve_target(tool_name, cmd)


def warn_resolved_pin(host: str, port: int, pin_ip: str, *, all_ips: list[str]) -> None:
    """Emit ONE concise stderr line recording the pinned IP (auditable choice)."""
    extra = ""
    if len(all_ips) > 1:
        extra = f" (host has {len(all_ips)} A records {', '.join(all_ips)}; pinned the first)"
    print(
        f"note: host-resolved {host}:{port} -> {pin_ip}; injected --resolve to "
        f"bypass the Docker Desktop container resolver{extra}.",
        file=sys.stderr,
    )
