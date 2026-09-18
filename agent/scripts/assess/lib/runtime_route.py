"""Platform-aware runtime routing for DNS-heavy / bulk recon tools (CR-3, CR-4, CR-12, CR-18).

The macOS / Windows Docker Desktop runtime proxies every container packet through
a host-side userspace proxy (``com.docker.backend``) that tracks NAT/socket state
PER DISTINCT DESTINATION IP. A DNS brute against a large resolver list (e.g. the
trickest ~15k-IP list, engagement I-001) saturates that per-destination NAT table
and wedges the whole VM — regardless of qps. The danger knob is the COUNT of
distinct resolver destination IPs, not the query rate.

This module is the shared seam the consumer agents hook into:

* :func:`detect_runtime` — cached, side-effect-free platform probe. It distinguishes
  *macOS Docker Desktop* (where the guards/host-routing must activate) from
  native-Linux / remote Docker (where they are a transparent no-op and the
  container path is unchanged).
* :func:`resolve_runtime` — turns an ``auto|host|container`` request into a concrete
  ``host`` | ``container`` decision for a given tool. On ``auto`` it routes DNS-heavy
  / bulk tools to the host *only* on Docker Desktop; everywhere else it stays in the
  container. An explicit ``host`` request with a missing host binary falls back to
  ``container`` with a WARN (never a hard-fail).
* :func:`warn_excessive_resolver_ips` — the CR-3 guard. WARN-only (never raises) when
  a container-routed DNS op on Docker Desktop points at more distinct resolver IPs
  than the cap.
* resolver-list path resolution (CR-12 / CR-18): :func:`resolver_data_dir`,
  :func:`resolver_list_path`, :func:`premium_anycast_path`, :func:`trusted_anycast_path`,
  and :func:`count_distinct_resolver_ips` (used by the CR-3 guard).

Stdlib only; importable with NO side effects (detection is lazy + cached).

Container-path note: the assess CLI runs HOST-SIDE and dispatches into the runtime
container via ``docker exec``. Only ``<engagements_dir>:/engagements`` and
``<data_dir>:/data`` are bind-mounted into the container — the ``agent/`` tree
(where these resolver lists ship) is NOT. So :func:`resolver_list_path` returns the
HOST path; a caller that needs the file visible IN-container must stage it under the
engagement dir (``<engagement_dir>/wordlists/`` → ``/engagements/<key>/wordlists/``).
:func:`container_staged_path` computes that destination container path.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- #
# Tool classification (CR-4 host-eligible allowlist)
# --------------------------------------------------------------------------- #

# DNS-heavy / bulk-resolution tools that benefit from the host path on Docker
# Desktop (no userspace proxy → no per-destination-IP NAT wedge, ~30x faster).
# Bulk httpx liveness (CR-5) is included; auth'd/exploit HTTP is NOT (callers
# route those tools through the container regardless).
DNS_HEAVY_TOOLS: frozenset[str] = frozenset(
    {"massdns", "puredns", "dnsx", "subfinder", "shuffledns", "alterx", "httpx"}
)

# Default cap on distinct resolver destination IPs for the in-container path on
# Docker Desktop (CR-3). Overridable via VIGIL_RESOLVER_IP_CAP.
DEFAULT_RESOLVER_IP_CAP = 50

_RESOLVER_IP_CAP_ENV = "VIGIL_RESOLVER_IP_CAP"

# The runtime guide the CR-3 WARN points operators at.
_DOCKER_HAZARD_GUIDE = "agent/references/runtime-guides/docker-desktop-network-hazards.md"

# The cero tool guide the CR-22 WARN points operators at (alongside the hazard guide).
_CERO_GUIDE = "agent/references/tools/recon/cero.md"

# CR-22 CIDR-expansion cap: counting every host in a large CIDR is pointless work
# (a /8 is 16M IPs) and the guard only cares whether we're WAY over the small cap.
# Any CIDR with a prefix SHORTER than these (i.e. wider than a /24 v4 or /120 v6)
# is treated as "instantly over cap" without enumerating it.
_CIDR_HOST_ENUM_MIN_PREFIX_V4 = 24
_CIDR_HOST_ENUM_MIN_PREFIX_V6 = 120


@dataclass(frozen=True)
class RuntimeInfo:
    """Result of :func:`detect_runtime` (cached per-process).

    Attributes:
        platform: ``platform.system()`` lowercased — ``'darwin'`` | ``'linux'`` | ...
        is_docker_desktop: True only when the active Docker runtime is Docker
            Desktop (the macOS/Windows userspace-proxy VM). The CR-3 guards and
            CR-4 host-routing activate ONLY when this is True; elsewhere they are
            a transparent no-op.
        recommended: the default route for a DNS-heavy/bulk tool on this runtime —
            ``'host'`` on Docker Desktop, ``'container'`` otherwise.
    """

    platform: str
    is_docker_desktop: bool
    recommended: str  # 'host' | 'container'


# Per-process cache (the probe shells out to `docker`, so we do it at most once).
_RUNTIME_CACHE: RuntimeInfo | None = None


def _docker_info_text(runner=None) -> str:
    """Return combined ``docker context inspect`` + ``docker info`` text, lowercased.

    Best-effort and fully defensive: any failure (docker absent, timeout,
    permission) yields ``""`` so detection falls back to the OS heuristic. The
    ``runner`` hook (callable taking argv → object with ``.returncode`` and
    ``.stdout``) exists for tests; production uses ``subprocess`` directly.
    """
    if runner is None:
        import subprocess

        def runner(argv):  # type: ignore[misc]
            try:
                return subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
            except (OSError, ValueError, subprocess.SubprocessError):
                return None

    chunks: list[str] = []
    for argv in (
        ["docker", "context", "inspect"],
        ["docker", "info", "--format", "{{json .}}"],
    ):
        try:
            result = runner(argv)
        except Exception:
            result = None
        if result is None:
            continue
        rc = getattr(result, "returncode", 1)
        out = getattr(result, "stdout", "") or ""
        if rc == 0 and out.strip():
            chunks.append(out)
    return "\n".join(chunks).lower()


def _looks_like_docker_desktop(info_text: str) -> bool:
    """Heuristic: does the docker-info/context text name Docker Desktop?

    Docker Desktop's ``docker info`` reports an ``OperatingSystem`` of
    ``Docker Desktop`` and a default context ``desktop-linux``; ``docker context
    inspect`` surfaces the ``desktop-linux`` endpoint. We treat any of these
    signals as Docker Desktop.
    """
    if not info_text:
        return False
    needles = ("docker desktop", "desktop-linux")
    return any(n in info_text for n in needles)


def detect_runtime(*, runner=None, force: bool = False) -> RuntimeInfo:
    """Detect the active recon runtime; cached per-process.

    macOS Docker Desktop detection is robust: ``platform.system() == 'Darwin'``
    AND a Docker-Desktop signal from ``docker context inspect`` / ``docker info``
    (``desktop-linux`` / ``Docker Desktop``). When ``docker`` is unavailable on a
    Mac we still default ``is_docker_desktop`` True — a Darwin host running Docker
    is ~always Docker Desktop, and erring toward the guard/host-path is the safe
    bias (the guards are WARN-only; the host path is faster and avoids the wedge).

    On non-Darwin platforms ``is_docker_desktop`` is True only when the runtime
    text explicitly names Docker Desktop (rare: Docker Desktop on Windows/Linux),
    so native Linux / remote Docker is a transparent no-op.

    Args:
        runner: test hook forwarded to :func:`_docker_info_text`.
        force: bypass the per-process cache (tests).
    """
    global _RUNTIME_CACHE
    if _RUNTIME_CACHE is not None and not force:
        return _RUNTIME_CACHE

    plat = platform.system().lower()  # 'darwin' | 'linux' | 'windows'
    info_text = _docker_info_text(runner=runner)
    named_desktop = _looks_like_docker_desktop(info_text)

    if plat == "darwin":
        # Darwin Docker is ~always Docker Desktop, so both arms are true: a named
        # probe confirms it, and absence of the probe must NOT disable the guard.
        is_desktop = True if not info_text else (named_desktop or True)
    else:
        # Native Linux / remote Docker: only Docker Desktop when explicitly named.
        is_desktop = named_desktop

    recommended = "host" if is_desktop else "container"
    _RUNTIME_CACHE = RuntimeInfo(
        platform=plat,
        is_docker_desktop=is_desktop,
        recommended=recommended,
    )
    return _RUNTIME_CACHE


def reset_runtime_cache() -> None:
    """Clear the per-process detection cache (tests only)."""
    global _RUNTIME_CACHE
    _RUNTIME_CACHE = None


# --------------------------------------------------------------------------- #
# Route resolution (CR-4)
# --------------------------------------------------------------------------- #


class HostRoutingRequired(RuntimeError):
    """Raised by :func:`resolve_runtime` when ``enforce=True`` and a stage that
    MUST run host-side (a DNS-heavy/bulk tool on Docker Desktop) cannot, because
    the host binary is missing. Kept a stdlib ``RuntimeError`` subclass so this
    module stays import-light; callers translate it to their own error type
    (e.g. the recon orchestrator re-raises it as ``AssessError``)."""


def _host_binary_available(tool: str) -> bool:
    """True when ``tool`` is on the host PATH (so a host route is runnable)."""
    return shutil.which(tool) is not None


def resolve_runtime(
    requested: str,
    *,
    tool: str,
    host_eligible: set[str] | frozenset[str] = DNS_HEAVY_TOOLS,
    runtime: RuntimeInfo | None = None,
    check_host_binary: bool = True,
    enforce: bool = False,
) -> str:
    """Resolve ``auto|host|container`` → concrete ``'host'`` | ``'container'``.

    Policy:
      * ``'container'`` → always container (caller forced isolation).
      * ``'host'`` → host, UNLESS ``check_host_binary`` and the host binary is
        missing on PATH → fall back to ``'container'`` with a one-line WARN
        (never a hard-fail).
      * ``'auto'`` → ``'host'`` for a host-eligible DNS-heavy/bulk tool when the
        runtime is Docker Desktop AND the host binary is present; otherwise
        ``'container'``. On native Linux / remote Docker, ``'auto'`` always
        stays ``'container'`` (transparent no-op).

    Args:
        requested: one of ``'auto'``, ``'host'``, ``'container'`` (case-insensitive;
            empty/None treated as ``'auto'``).
        tool: tool name (e.g. ``'puredns'``); matched against ``host_eligible``.
        host_eligible: the set of tools eligible for host routing on ``auto``.
        runtime: override the detected runtime (tests); defaults to
            :func:`detect_runtime`.
        check_host_binary: when True, verify the host binary exists before routing
            host (set False in unit tests that don't have the tool installed).
        enforce: when True, a DNS-heavy/bulk tool that WOULD route host on this
            platform but cannot (host binary missing) raises
            :class:`HostRoutingRequired` instead of silently degrading to the
            I-001-prone container path. An explicit ``'container'`` request is
            always honoured (caller forced isolation) and never enforced. On
            native Linux / remote Docker the container path is safe, so enforce
            is a no-op there. The recon job sets ``enforce=True`` for its
            DNS-heavy stages.
    """
    req = (requested or "auto").strip().lower()
    if req not in ("auto", "host", "container"):
        req = "auto"
    rt = runtime if runtime is not None else detect_runtime()

    if req == "container":
        return "container"

    if req == "host":
        if check_host_binary and not _host_binary_available(tool):
            if enforce:
                raise HostRoutingRequired(
                    f"host routing is REQUIRED for {tool} (DNS-heavy/bulk stage) but "
                    f"'{tool}' is not on the host PATH. On macOS Docker Desktop the "
                    "container path wedges the userspace proxy (I-001), so the recon "
                    "job refuses to silently degrade. Install the host binary (see "
                    "agent setup / CR-11) or run on native Linux / remote Docker."
                )
            _warn(
                f"--runtime host requested for {tool} but '{tool}' is not on the "
                "host PATH — falling back to the container path. Install the host "
                "binary (see agent setup / CR-11) to use the faster host route."
            )
            return "container"
        return "host"

    # auto
    if not rt.is_docker_desktop:
        return "container"
    if tool not in host_eligible:
        return "container"
    if check_host_binary and not _host_binary_available(tool):
        if enforce:
            raise HostRoutingRequired(
                f"host routing is REQUIRED for {tool} (DNS-heavy/bulk stage) on macOS "
                f"Docker Desktop but '{tool}' is not on the host PATH — the container "
                "path would wedge the userspace proxy (I-001). Install the host binary "
                "(see agent setup / CR-11) or run on native Linux / remote Docker."
            )
        # No nag on auto: host binary absent simply means we can't take the fast
        # path — stay in the container silently (the CR-3 guard still warns if the
        # resolver set is too large for the container path).
        return "container"
    return "host"


# --------------------------------------------------------------------------- #
# CR-3 distinct-destination-IP guard (WARN only)
# --------------------------------------------------------------------------- #


def resolver_ip_cap() -> int:
    """The active distinct-resolver-IP cap (CR-3); env-overridable, clamped >=1."""
    raw = os.environ.get(_RESOLVER_IP_CAP_ENV, "").strip()
    if raw:
        try:
            val = int(raw)
            if val >= 1:
                return val
        except ValueError:
            pass
    return DEFAULT_RESOLVER_IP_CAP


def warn_excessive_resolver_ips(
    n_distinct: int,
    *,
    threshold: int | None = None,
    route: str,
    runtime: RuntimeInfo | None = None,
) -> bool:
    """CR-3 guard: WARN (never raise) on too many distinct resolver IPs in-container.

    Fires exactly when ALL hold: the runtime is Docker Desktop, the op is routed
    ``'container'``, and ``n_distinct`` exceeds the cap. On native Linux / remote
    Docker, or for a host-routed op, this is a transparent no-op. Threshold defaults
    to :func:`resolver_ip_cap` (env ``VIGIL_RESOLVER_IP_CAP``).

    Returns True when a warning was emitted (handy for callers/tests); never raises.
    """
    cap = resolver_ip_cap() if threshold is None else threshold
    rt = runtime if runtime is not None else detect_runtime()
    if not rt.is_docker_desktop:
        return False
    if route != "container":
        return False
    if n_distinct <= cap:
        return False
    _warn(
        f"{n_distinct} distinct resolver IPs exceeds the in-container cap "
        f"(~{cap}) on macOS Docker Desktop: every distinct destination IP is "
        "NAT-tracked by the host userspace proxy (com.docker.backend), so a large "
        "resolver set can wedge the VM regardless of qps (engagement I-001). "
        f"Route this DNS op to the host (--runtime host) or trim to a small "
        f"validated resolver tier (premium-anycast ~40 IPs). See {_DOCKER_HAZARD_GUIDE}."
    )
    return True


# --------------------------------------------------------------------------- #
# Resolver-list path resolution (CR-12 / CR-18)
# --------------------------------------------------------------------------- #

# These ship under agent/scripts/assess/data/resolvers/ — i.e. one dir up from
# this lib/ dir, then data/resolvers/.
_PREMIUM_ANYCAST_FILE = "premium-anycast.txt"
_TRUSTED_ANYCAST_FILE = "trusted-anycast.txt"


def resolver_data_dir() -> Path:
    """Host path of the shipped resolver-list directory.

    Resolved relative to this file: ``<install_root>/agent/scripts/assess/data/
    resolvers/``. This is a HOST path — the agent/ tree is NOT bind-mounted into
    the runtime container (only /engagements and /data are), so a caller that needs
    the list visible in-container must stage it under the engagement dir; see
    :func:`container_staged_path`.
    """
    # runtime_route.py lives at .../assess/lib/runtime_route.py
    return Path(__file__).resolve().parent.parent / "data" / "resolvers"


def resolver_list_path(name: str) -> Path:
    """Host path of a shipped resolver list by file name (e.g. ``premium-anycast.txt``)."""
    return resolver_data_dir() / name


def premium_anycast_path() -> Path:
    """Host path of the BRUTE-tier premium-anycast resolver list (CR-18, puredns ``-r``)."""
    return resolver_list_path(_PREMIUM_ANYCAST_FILE)


def trusted_anycast_path() -> Path:
    """Host path of the VALIDATION-tier trusted-anycast list (CR-12, ``--resolvers-trusted``)."""
    return resolver_list_path(_TRUSTED_ANYCAST_FILE)


def container_staged_path(engagement_key: str, name: str) -> str:
    """Container path a resolver list occupies once staged under the engagement dir.

    Callers that copy ``resolver_list_path(name)`` into
    ``<engagement_dir>/wordlists/<name>`` can pass this string to an in-container
    tool: ``/engagements/<engagement_key>/wordlists/<name>``.
    """
    return f"/engagements/{engagement_key}/wordlists/{name}"


def iter_resolver_ips(path: str | os.PathLike[str]):
    """Yield the distinct resolver IPs/hosts from a resolver file.

    One entry per line; blanks and ``#`` comments skipped. A ``host:port`` or
    ``proto:ip`` (e.g. ``tcp:1.1.1.1``) entry is reduced to its address token so
    the count reflects distinct DESTINATIONS. Order-preserving de-dup.
    """
    seen: set[str] = set()
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for raw in text.splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        # Strip a leading transport prefix like 'tcp:' / 'udp:' (dnsx style).
        if ":" in entry and entry.split(":", 1)[0] in ("tcp", "udp"):
            entry = entry.split(":", 1)[1].strip()
        # Reduce host:port to host (IPv6 with >1 colon is left intact).
        if entry.count(":") == 1:
            entry = entry.split(":", 1)[0].strip()
        if not entry or entry in seen:
            continue
        seen.add(entry)
        yield entry


def count_distinct_resolver_ips(path: str | os.PathLike[str]) -> int:
    """Count distinct resolver destinations in a resolver file (CR-3 guard input)."""
    return sum(1 for _ in iter_resolver_ips(path))


# --------------------------------------------------------------------------- #
# CR-22 distinct-TARGET-IP guard (cero / whole-CIDR scans, WARN only)
# --------------------------------------------------------------------------- #

# Sentinel returned once a target set is so large that the exact count no longer
# matters — the guard only asks "are we WAY over the small cap?". Bounded (we never
# enumerate a wide CIDR) yet far above any sane VIGIL_RESOLVER_IP_CAP override.
_TARGET_IP_OVER_CAP_SENTINEL = 1_000_000


def count_distinct_target_ips(targets: Iterable[str]) -> int:
    """Estimate the distinct destination IPs a target list fans out to (CR-22 input).

    Per entry (blanks and ``#`` comments skipped):

    * a bare IP counts 1;
    * a CIDR is expanded via :func:`ipaddress.ip_network` (``strict=False``), BUT a
      CIDR wider than a /24 (IPv4) or /120 (IPv6) is treated as "instantly over cap"
      — enumerating a /8 (16M hosts) is pointless when the cap is ~50, so such an
      entry short-circuits the whole estimate to :data:`_TARGET_IP_OVER_CAP_SENTINEL`;
    * a hostname counts 1 (it is unresolved at plan time; it may in fact resolve to
      several A-records, which the WARN text flags).

    The return is a best-effort UPPER-ish estimate of distinct destination IPs, not a
    deduped exact count — good enough to drive the WARN-only CR-22 guard.
    """
    total = 0
    for raw in targets:
        entry = (raw or "").strip()
        if not entry or entry.startswith("#"):
            continue
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                # Not a CIDR (e.g. a URL/path) — treat as a single host destination.
                total += 1
                continue
            min_prefix = (
                _CIDR_HOST_ENUM_MIN_PREFIX_V6
                if net.version == 6
                else _CIDR_HOST_ENUM_MIN_PREFIX_V4
            )
            if net.prefixlen < min_prefix:
                # Wider than the enum threshold → instantly over cap; stop counting.
                return _TARGET_IP_OVER_CAP_SENTINEL
            total += net.num_addresses
            if total >= _TARGET_IP_OVER_CAP_SENTINEL:
                return _TARGET_IP_OVER_CAP_SENTINEL
            continue
        # Bare IP or hostname → one destination at plan time.
        total += 1
    return total


def warn_excessive_target_ips(
    n_distinct: int,
    *,
    route: str,
    runtime: RuntimeInfo | None = None,
    tool: str = "cero",
) -> bool:
    """CR-22 guard: WARN (never raise) on too many distinct TARGET IPs in-container.

    The CR-3 guard (:func:`warn_excessive_resolver_ips`) counts RESOLVER destinations
    and is wired only into the DNS/web-discovery path; it does NOT cover cero, whose
    danger knob is the count of distinct SCAN-TARGET IPs (a whole-CIDR cero in the
    container NAT-saturates the Docker Desktop userspace proxy exactly like a large
    resolver list — engagement I-001).

    Fires exactly when ALL hold: the runtime is Docker Desktop, the op is routed
    ``'container'``, and ``n_distinct`` exceeds :func:`resolver_ip_cap` (the SAME
    ``VIGIL_RESOLVER_IP_CAP`` knob — no new env). On native Linux / remote Docker, or
    for a host-routed op, this is a transparent no-op.

    Returns True when a warning was emitted (handy for callers/tests); never raises.
    """
    cap = resolver_ip_cap()
    rt = runtime if runtime is not None else detect_runtime()
    if not rt.is_docker_desktop:
        return False
    if route != "container":
        return False
    if n_distinct <= cap:
        return False
    _warn(
        f"{tool}: ~{n_distinct} distinct target IPs exceeds the in-container cap "
        f"(~{cap}) on macOS Docker Desktop: every distinct destination IP is "
        "NAT-tracked by the host userspace proxy (com.docker.backend), so a "
        f"whole-CIDR {tool} run can wedge the VM regardless of concurrency "
        "(engagement I-001). Trim to a small validated target set, or split the "
        "scan into smaller batches. Note: hostnames may each resolve to several "
        f"A-records, so the live fan-out can exceed this estimate. See "
        f"{_DOCKER_HAZARD_GUIDE} and {_CERO_GUIDE}."
    )
    return True


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #


def _warn(message: str) -> None:
    """Emit ONE concise stderr WARN line (the locked WARN-not-fail posture)."""
    print(f"WARN: {message}", file=sys.stderr)
