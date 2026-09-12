"""Audit POST/PATCH plumbing and input validation for kali runs.

Owns the orchestrator-backend interactions tied to the audit pipeline:
the pre-exec ``command-runs`` POST that registers a ``running`` row before
docker-exec starts, the finalize PATCH that writes the terminal status,
and the ``failed-audit`` marker file written when the POST itself fails.
Also hosts the input-validation helpers (``--phase`` enum, agent-name
resolution, engagement-dir resolution) because they gate whether a row
makes it onto the wire at all.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import scope as scope_lib
from .audit_enums import (
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
    normalize_probe_kind,
    normalize_technique,
)
from .client import (
    AssessError,
    AssessmentClient,
    require_command_run_finalize_response,
)
from .phases import AUDIT_PHASE_TAGS
from .scope import execution_policy_notes
from .config import Config
from .kali_output import (
    _CURL_NON_ARM_URL_FLAGS,
    _utcnow_iso,
    _wrapped_shell_script_index,
)


# The fail-closed `--phase` enum. Sourced from the canonical roster in
# `lib/phases.py` rather than re-spelled here, so the audit vocabulary and the
# engagement phase tracks cannot drift apart. The backend stores `phase` as
# plain TEXT for forward compatibility with older rows, so this host-side check
# is the one that gives the operator a clear error before a malformed row is
# written.
ALLOWED_PHASES: tuple[str, ...] = AUDIT_PHASE_TAGS


_INTENT_MAX_LEN = 400


def _enum_reject_message(
    flag: str, bad_value: str, allowed: tuple[str, ...], *, hint: str = ""
) -> str:
    """One-line, scoped enum-rejection text: closest matches first, then the full list.

    Leads with up to 3 edit-distance suggestions + the offending flag, so the
    caller does not have to scan a 46-value table to find the value they meant.
    The full allowed list is ALWAYS appended after the suggestion — the
    suggestion is additive, never a replacement — so validation behavior is
    unchanged and only the error TEXT becomes scoped.

    Matching is case-insensitive: both the offending value and the allowed
    values are upper-cased before ``difflib.get_close_matches`` so a lowercase
    ``--probe-kind`` typo or an upper-cased ``--technique`` both surface a
    suggestion, while the echoed suggestion and allowed list keep each enum's
    own canonical casing.
    """
    from .schema_validation import suggest_close_match

    bad_upper = (bad_value or "").upper()
    canonical_by_upper = {value.upper(): value for value in allowed}
    raw_suggestion = suggest_close_match(bad_upper, list(canonical_by_upper.keys()))
    upper_matches: list[str]
    if raw_suggestion:
        upper_matches = [token.strip() for token in raw_suggestion.split(",")]
    else:
        # Difflib's 0.55 edit-distance cutoff misses the "spelled-out
        # abbreviation" shape — e.g. a user typing the full word ``SQLINJECTION``
        # for the abbreviated enum ``SQLI`` (ratio 0.50) — because the long
        # operator word dilutes the ratio. Fall back to a conservative
        # substring/prefix check: an allowed token of length >= 3 that is wholly
        # contained in the bad value (or vice-versa) is a strong "you wrote the
        # long form of what we abbreviate" signal. Still additive (the full list
        # is always appended) and tight enough that unrelated tokens do not hit.
        upper_matches = [
            key
            for key in canonical_by_upper
            if len(key) >= 3 and bad_upper and (key in bad_upper or bad_upper in key)
        ][:3]
    head = f"{flag} '{bad_value}' is not valid."
    if upper_matches:
        # Map the upper-cased matches back to each enum's canonical spelling.
        canonical_matches = ", ".join(
            canonical_by_upper.get(token, token) for token in upper_matches
        )
        head += f" Did you mean: {canonical_matches}?"
    if hint:
        head += f" {hint}"
    return head + f" (allowed: {', '.join(allowed)})"


# Phases where a kali run resolving to the "operator" default is almost
# certainly a misattributed specialist call. Operators legitimately run
# mechanical probes in `recon`/`consume-test` (tier-pick smoke, runtime
# health, credential validation), so those are deliberately EXCLUDED — the
# WARN must stay non-noisy. `exploit`/`verify` are specialist-owned phases
# operators essentially never run mechanical kali in, so a fall-through to
# "operator" there is the misattribution signal CR-35 targets.
_SPECIALIST_ONLY_PHASES: frozenset[str] = frozenset({"exploit", "verify"})


def _extract_target_host(tool_name: str, cmd: list[str]) -> str:
    """C30: extract a parsed target host from argv for high-traffic verbs.

    Operators query coverage with ``vigil assess command-run list
    --target-host <host>``; the backend stores this in the
    ``target_host`` column. Per-verb extraction keeps the logic simple
    and deterministic — each kali wrapper knows its argv shape, so the
    parser is a switch on tool_name rather than a generic URL/host
    regex over the whole command string.

    Unhandled tools return ''. The existing FTS ``--q`` search still
    matches those rows, so no row is hidden from coverage queries —
    only the exact-match filter is empty.
    """
    if not cmd:
        return ""
    tool = (tool_name or "").lower()

    def _host_from_url(value: str) -> str:
        # Strip scheme, port, path. Tolerate '@user:pass' shapes.
        # Returns the canonical bare host so `--target-host <host>` queries
        # match — for bracketed IPv6 URLs that means the address inside the
        # brackets (e.g. `https://[2001:db8::1]:8443` → `2001:db8::1`), not
        # the `[addr]:port` literal.
        v = value.strip()
        if not v:
            return ""
        if "://" in v:
            v = v.split("://", 1)[1]
        # Drop everything after the first '/'
        v = v.split("/", 1)[0]
        # Drop credentials
        if "@" in v:
            v = v.split("@", 1)[1]
        # Bracketed IPv6 with optional :port suffix — extract the address
        # inside the brackets. URLs MUST bracket IPv6 literals per RFC 3986,
        # so unbracketed-IPv6 input is out of scope.
        if v.startswith("["):
            end = v.find("]")
            if end > 0:
                return v[1:end].lower()
            # Malformed input — fall through and emit the lowercased literal.
        elif ":" in v:
            # plain host:port
            v = v.split(":", 1)[0]
        return v.lower()

    def _next_value(flag_names: tuple[str, ...]) -> str:
        for idx, token in enumerate(cmd):
            if token in flag_names and idx + 1 < len(cmd):
                return cmd[idx + 1]
        return ""

    if tool == "httpx":
        # httpx supports -u <url> (single) or -l <file> (list); for list mode
        # we cannot pin a single target, leave empty.
        return _host_from_url(_next_value(("-u", "--url", "-target")))
    if tool == "nuclei":
        # nuclei -u <target> or -l <list>; list mode leaves target_host empty.
        return _host_from_url(_next_value(("-u", "--target", "-target")))
    if tool == "ffuf":
        # ffuf -u <url-with-fuzz-marker>; strip the FUZZ marker before host parse.
        raw = _next_value(("-u", "--url"))
        return _host_from_url(raw.split("FUZZ", 1)[0] if raw else "")
    if tool == "sqlmap":
        # sqlmap -u <url>; the URL is the canonical target.
        return _host_from_url(_next_value(("-u", "--url")))
    return ""


# Where a probe's target anchor comes from, and what it is allowed to be.
#
# The anchor (host + path + port) feeds THREE consumers with different failure
# modes: the ``--resolve`` IP pin (which decides where the runtime connects),
# the identity host scope (which decides whose cookies ride the request), and
# the auto-emitted probe_run (which decides which app unit earns depth credit).
# Its predecessor was one loose scan — "the first whitespace-delimited word in
# argv that starts with http:// or contains a dot" — which meant a `-H 'Origin:
# https://attacker'` value outranked the real positional URL, a `bash -c` body
# was invisible because its URL carried a leading quote, and a JWT or a line of
# Python source parsed as a 300-char "hostname". The rosters and shape checks
# below are what make the anchor a parse rather than a guess.

# Flags whose VALUE is (or can embed) a URL but is never the transfer target:
# proxies, referers, request headers, cookies, request bodies, upload/output
# files. Seeded from ``kali_output._CURL_NON_ARM_URL_FLAGS`` — the same
# "URL-valued but not a transfer arm" idea — so the two rosters cannot drift.
# A hazard flag's value is DROPPED, never demoted to a fallback candidate:
# ``Origin`` is attacker-controlled request content on half the tests run here
# and must never steer runtime networking, not even as a last resort.
_NON_TARGET_VALUE_FLAGS: frozenset[str] = _CURL_NON_ARM_URL_FLAGS | frozenset(
    {
        "-H", "--header",
        "-b", "--cookie",
        "-c", "--cookie-jar",
        "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
        "--data-urlencode", "--url-query",
        "-F", "--form", "--form-string",
        "-A", "--user-agent",
        "-o", "--output",
        "-w", "--write-out",
        "-D", "--dump-header",
        "-T", "--upload-file",
        "--resolve", "--connect-to",
    }
)

# curl-family only. ``-u`` is credentials for curl but THE TARGET URL for httpx,
# nuclei, sqlmap, katana, ffuf and arjun, so this set must never be applied
# globally — doing so would un-anchor every arjun run.
_CURL_ONLY_NON_TARGET_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-u", "--user", "-K", "--config", "--trace", "--trace-ascii"}
)
_CURL_FAMILY_TOOLS: frozenset[str] = frozenset({"curl", "wget"})

# Tools that name their target with a flag rather than a positional argument.
# These branches are authoritative and never fall through to the generic scan.
_FLAG_DRIVEN_TARGET_TOOLS: dict[str, tuple[str, ...]] = {
    "httpx": ("-u", "--url", "--target", "-target"),
    "nuclei": ("-u", "--url", "--target", "-target"),
    "sqlmap": ("-u", "--url", "--target", "-target"),
    "katana": ("-u", "--url", "--target", "-target"),
    "ffuf": ("-u", "--url"),
}

# RFC 1035 label + total-length bounds, and the backend's ``target_path`` cap
# (``ProbeRunRecordRequest.target_path``, max_length=2048). The host bound is
# deliberately tighter than the backend's 256-char ``target_host`` column: a
# name longer than 253 octets is not resolvable, so submitting one only ever
# earns a 422 that discards the whole probe row.
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_HOSTNAME_LEN = 253
MAX_TARGET_PATH_LEN = 2048


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_plausible_host(host: str) -> bool:
    """True when ``host`` has the shape of something we could connect to.

    The last-line bound on every anchor, whichever branch produced it — an argv
    "word" is not a host just because a URL parser accepted it. A 332-char
    session cookie and a line of Python source both used to reach the wire as
    ``target_host``; the backend refused them on its length cap, and the client
    swallowed the 422, losing the probe row and silently skipping the depth
    harness for that run.

    Deliberately permissive about SHAPE — a single-label container/compose alias
    (``target``) and an IP literal are both real hosts here. It rejects only what
    cannot be a hostname at all.
    """
    if not host or len(host) > _MAX_HOSTNAME_LEN:
        return False
    if _is_ip_literal(host):
        return True
    return all(
        _HOST_LABEL_RE.match(label) for label in host.rstrip(".").split(".")
    )


def _looks_like_bare_target(word: str) -> bool:
    """True when a scheme-less argv word is plausibly ``host[:port][/path]``.

    The strict half of the parse, and the one that matters: a scheme-less word is
    a GUESS, so it has to look like a real address — an IP literal, a bracketed
    IPv6, a dotted name ending in a plausible TLD, or a single-label host made
    concrete by an explicit port (an internal or compose-alias target). The
    predecessor accepted any non-flag word with a dot before the first ``/``,
    which is true of a JWT, a base64 blob, and ``requests.get(...)`` alike.

    A scheme-BEARING URL is not a guess and never reaches this gate.
    """
    head = word.split("/", 1)[0]
    if "@" in head:
        head = head.split("@", 1)[1]
    if not head:
        return False
    if head.startswith("["):
        end = head.find("]")
        return end > 1 and _is_ip_literal(head[1:end])
    host, separator, port = head.rpartition(":")
    if not separator:
        host, port = head, ""
    if not host or (port and not port.isdigit()):
        return False
    if _is_ip_literal(host):
        return True
    if not _is_plausible_host(host):
        return False
    labels = host.rstrip(".").split(".")
    if len(labels) == 1:
        return bool(port)
    tld = labels[-1]
    return len(tld) >= 2 and (tld.isalpha() or tld.lower().startswith("xn--"))


def _flag_value(tokens: list[str], flags: tuple[str, ...]) -> str:
    """Value of the first occurrence of any flag in ``flags`` (separate or ``=``)."""
    for idx, token in enumerate(tokens):
        text = str(token)
        if text in flags and idx + 1 < len(tokens):
            return str(tokens[idx + 1])
        head, separator, attached = text.partition("=")
        if separator and head in flags:
            return attached
    return ""


def _target_url_from_tokens(tokens: list[str], *, hazard_flags: frozenset[str]) -> str:
    """The transfer-target URL in ONE simple command's arguments (program excluded).

    Two ordered passes over the POSITIONAL tokens only: an explicit
    ``http(s)://`` URL first, then a scheme-less ``host[:port][/path]``. Tokens
    are never split on whitespace — a single argv token that reads
    ``Origin: https://x`` is one header value, never a target.
    """
    candidates: list[str] = []
    skip_next = False
    for raw in tokens:
        token = str(raw)
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-") and token != "-":
            head, separator, attached = token.partition("=")
            if head in hazard_flags:
                # ``--header=X`` carries its value inline; ``--header X`` does not.
                skip_next = not separator
                continue
            if (
                not separator
                and not token.startswith("--")
                and token[:2] in hazard_flags
            ):
                continue  # curl's glued short form (``-eURL``, ``-d@file``)
            if separator and attached:
                candidates.append(attached)  # ``--url=https://x``
            continue
        candidates.append(token)
    url = next(
        (c for c in candidates if c.lower().startswith(("http://", "https://"))),
        "",
    )
    if url:
        return url
    return next((c for c in candidates if _looks_like_bare_target(c)), "")


def _extract_target_url(tool_name: str, cmd: list[str]) -> str:
    """The raw target-URL token of a kali argv, or ``""`` for list-mode shapes.

    Single source for "which token is the target", shared by
    :func:`_extract_target_anchor` and the ``--resolve`` pin's scheme-derived
    default port, so the two cannot disagree about what is being probed.

    A shell wrapper is LEXED into simple commands, not whitespace-split:
    ``bash -c "curl -s 'https://api.example.com/v1/x'"`` is ONE argv token whose
    URL carries a leading quote, so the naive scan found no host — which is why
    ``--identity`` refused to run on the documented ``bash -c`` escape hatch
    (the credential was fine; the request host was empty). A multi-command body
    anchors on the first sub-command that names a target.
    """
    if not cmd:
        return ""
    tool = (tool_name or "").lower()
    hazard = _NON_TARGET_VALUE_FLAGS
    if tool in _CURL_FAMILY_TOOLS:
        hazard = hazard | _CURL_ONLY_NON_TARGET_VALUE_FLAGS

    script_idx = _wrapped_shell_script_index(cmd)
    if script_idx is not None and script_idx < len(cmd):
        segments, ambiguous = scope_lib._shell_command_segments(str(cmd[script_idx]))
        if ambiguous:
            # An unbalanced quote means we cannot reason about token boundaries;
            # an unanchored probe is honest, a mis-anchored one is not.
            return ""
    else:
        segments = [[str(token) for token in cmd]]

    target_flags = _FLAG_DRIVEN_TARGET_TOOLS.get(tool)
    for segment in segments:
        args = segment[1:]
        if target_flags is not None:
            url = _flag_value(args, target_flags)
        else:
            url = _target_url_from_tokens(args, hazard_flags=hazard)
        if url:
            return url
    return ""


def _extract_target_anchor(tool_name: str, cmd: list[str]) -> tuple[str, str, int | None]:
    """Extract ``(host, path, port)`` of a probe's target URL from a kali argv.

    The depth ledger maps a null-FK probe_run to an app unit by host + PATH
    containment, so a probe against ``/api/...`` MUST carry its path or it can
    never cover that unit and the terminal backstop keeps blocking despite real
    tests. Unlike ``_extract_target_host`` (host only), this returns the path and
    port too, and also handles the raw ``kali exec curl <url>`` fallback (a
    positional URL token), which the host-only switch missed.

    Returns ``("", "", None)`` for list-mode / unrecognized argv shapes, and for
    anything whose parsed host is not a plausible hostname — an honest UNKNOWN
    anchor beats one derived from a header value or a blob of program source.
    """
    url = _extract_target_url(tool_name, cmd)
    if not url:
        return "", "", None
    url = url.split("FUZZ", 1)[0]
    parse = url if "://" in url else "http://" + url
    try:
        split = urlsplit(parse)
        host = (split.hostname or "").lower()
        path = split.path or ""
        port = split.port
    except ValueError:
        return "", "", None
    if not _is_plausible_host(host):
        return "", "", None
    return host, path[:MAX_TARGET_PATH_LEN], port


def _validate_inputs(
    *,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    timeout: int,
    agent_name: str,
) -> None:
    if not technique:
        raise AssessError("--technique is required")
    canonical_technique = normalize_technique(technique)
    if TECHNIQUE_ENUM and canonical_technique not in TECHNIQUE_ENUM:
        raise AssessError(_enum_reject_message(
            "--technique", technique, TECHNIQUE_ENUM,
            hint="--technique is the vuln-class tag for the AUDIT row, not the probe step; "
                 "the per-step kind is --probe-kind. For initial mapping use RECON.",
        ))
    if not intent:
        raise AssessError("--intent is required")
    if len(intent) > _INTENT_MAX_LEN:
        raise AssessError(f"--intent exceeds {_INTENT_MAX_LEN} characters")
    if not probe_kind:
        raise AssessError("--probe-kind is required")
    canonical_probe_kind = normalize_probe_kind(probe_kind)
    if PROBE_KIND_ENUM and canonical_probe_kind not in PROBE_KIND_ENUM:
        raise AssessError(_enum_reject_message(
            "--probe-kind", probe_kind, PROBE_KIND_ENUM,
            hint="--probe-kind is the step type (recon vs. crafted payload vs. proof); "
                 "the vuln-class tag is --technique.",
        ))
    if not phase:
        raise AssessError("--phase is required (no env-var fallback)")
    if phase not in ALLOWED_PHASES:
        raise AssessError(_enum_reject_message("--phase", phase, ALLOWED_PHASES))
    if timeout is None or timeout <= 0:
        raise AssessError("--timeout (seconds) is required and must be > 0")
    if not agent_name:
        # `_resolve_agent_name` always returns a non-empty string thanks to the
        # default-to-"operator" fallback, so reaching this branch means an
        # internal regression (e.g. someone bypassed the resolver). Defense in
        # depth — keep the guard with a different message so the failure mode
        # is clear if it ever fires.
        raise AssessError("internal error: agent_name unexpectedly empty")


def _resolve_agent_name(
    explicit: str | None,
    *,
    agent_id: str | None = None,
    phase: str | None = None,
    warn: bool = False,
) -> str:
    """Resolve the kali audit attribution with a deterministic carrier.

    Precedence (CR-35):
        explicit ``--agent-name`` > ``--agent-id`` > $AGENT_NAME >
        $VIGIL_AGENT_NAME > "operator".

    The ``--agent-id`` companion is a deterministic carrier for the common
    case where a specialist knows its dispatch id (from its Runtime Identity
    block) but not its role string: the dispatch id (e.g. ``va-7f3``) is
    itself a non-"operator" attribution that ties the row to a specific
    dispatch, so it is used verbatim WITHOUT a backend lookup (no hot-path
    GET, no auto-inference of the in-progress dispatch — parallel lanes make
    that ambiguous). Env is an unreliable carrier because subagent shells do
    not inherit AGENT_NAME and Bash env does not persist across calls, so the
    explicit flags are the real fix.

    The "operator" default lets the operator run mechanical pipeline checks
    (tier-pick smoke, runtime health, credential validation) without
    remembering to set an attribution.

    WARN (only when ``warn=True``): a single concise stderr line nudging
    ``--agent-name <role>`` fires ONLY when the run falls through to the
    "operator" default while ``phase`` is a specialist-only phase
    (``exploit``/``verify``). It deliberately does NOT fire in
    ``recon``/``consume-test`` where operators legitimately run mechanical
    probes, so routine operator calls stay silent.
    """
    if explicit:
        return explicit
    if agent_id:
        return agent_id
    env_value = os.environ.get("AGENT_NAME") or os.environ.get("VIGIL_AGENT_NAME") or ""
    if env_value:
        return env_value
    if warn and (phase or "").strip().lower() in _SPECIALIST_ONLY_PHASES:
        print(
            f"warning: kali run in --phase '{phase}' resolved to agent_name='operator' "
            "(no --agent-name/--agent-id and no AGENT_NAME env). If you are a specialist, "
            "pass --agent-name <role> so coverage is attributed to you, not the operator.",
            file=sys.stderr,
        )
    return "operator"


def _resolve_engagement_dir(explicit: Path | None, cfg: Config) -> Path:
    configured = Path(cfg.engagement_dir).resolve()
    configured_key = str(cfg.engagement_key or "").strip()
    if configured_key != configured.name:
        raise AssessError(
            f"config engagement key {configured_key!r} conflicts with configured "
            f"directory basename {configured.name!r}"
        )
    if explicit is not None:
        selected = Path(explicit).resolve()
        if selected != configured:
            raise AssessError(
                f"explicit engagement directory {selected} conflicts with resolved "
                f"config {configured}"
            )
        return selected
    return configured


def _post_pre_exec_row(
    client: AssessmentClient,
    *,
    cmd: list[str],
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool,
    agent_name: str,
    engagement_dir: Path,
    container_name: str,
    timeout: int,
    force: bool,
    started_at_iso: str,
    stdout_path: str,
    stderr_path: str,
    working_dir: str,
    scope_version: str,
    auth_context: str,
    tool_name: str,
    run_uuid: str,
    execution_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command": " ".join(cmd),
        "argv": list(cmd),
        "tool_name": tool_name,
        "route": f"vigil assess kali/{tool_name}",
        "agent_name": agent_name,
        "phase": phase,
        "target_host": _extract_target_host(tool_name, cmd),
        "started_at": started_at_iso,
        # Empty until the post-exec PATCH-finalize writes the real terminal
        # timestamp. Previously we wrote started_at here to satisfy the
        # backend NOT NULL constraint, which made orphan rows look "completed
        # at the same instant they started." Backend now accepts empty for
        # status="running" rows and rejects empty on terminal status.
        "completed_at": "",
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "audit_source": "header",
        "technique": technique,
        "intent": intent,
        "probe_kind": probe_kind,
        "destructive": destructive,
        "status": "running",
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "working_dir": working_dir,
        "scope_version": scope_version,
        "auth_context": auth_context,
        "timeout_seconds_requested": int(timeout),
        "force": bool(force),
        # Pin the backend's `run_uuid` column to the engagement-wide id the
        # CLI generated for the wrapper pid file and stdout path. Without
        # this, the backend would generate its OWN uuid and the column would
        # not match the pid file key — orphan-sweep would have no DB-side way
        # to recover the in-container PID and would fall back to regex-parsing
        # stdout_path, which breaks the moment the artifact dir is reconfigured.
        "run_uuid": run_uuid,
    }
    if execution_policy is not None:
        payload["notes"] = execution_policy_notes(execution_policy)
    return client.post("command-runs", payload)


_OUTPUT_HASH_CHUNK_BYTES = 1 << 20


def _stream_output_truth(path: str | Path | None) -> tuple[int, str] | None:
    """Return ``(bytes_written, sha256)`` for one wrapper-owned output file.

    The run streams its FULL stdout/stderr to a file this CLI opened, while the
    finalize payload carries only a head+tail-truncated preview — so this file
    is the only honest source for the byte count and digest the audit row
    records. Hashed in chunks because a scan's output is routinely far larger
    than memory-comfortable. Returns None when the path is missing or unreadable
    so the row simply records no byte truth, never a wrong one.
    """
    if not path:
        return None
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_OUTPUT_HASH_CHUNK_BYTES), b""):
                size += len(chunk)
                digest.update(chunk)
    except OSError:
        return None
    # Empty streams carry no digest, matching the backend's own retention rule.
    return size, digest.hexdigest() if size else ""


def _patch_finalize(
    client: AssessmentClient,
    *,
    run_id: int,
    run_uuid: str,
    status: str,
    return_code: int | None,
    ended_at_iso: str,
    duration_ms: int,
    stdout_preview: str,
    stderr_preview: str,
    timed_out: bool,
    partial_results: bool,
    peak_rss_bytes: int | None,
    cpu_user_seconds: float | None,
    cpu_system_seconds: float | None,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "return_code": return_code,
        "ended_at": ended_at_iso,
        "duration_ms": int(duration_ms),
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "timed_out": bool(timed_out),
        "partial_results": bool(partial_results),
    }
    # Retention/byte columns are only recomputed backend-side for the host_exec
    # lane; on every other route (`vigil assess kali/<tool>`) they keep the
    # pre-exec placeholders unless this PATCH carries the measured truth. Pass
    # the paths this row was OPENED with, so the recorded bytes and digest
    # belong to the file the row names.
    for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        truth = _stream_output_truth(path)
        if truth is None:
            continue
        payload[f"{stream}_bytes"], payload[f"{stream}_sha256"] = truth
    if peak_rss_bytes is not None:
        payload["peak_rss_bytes"] = int(peak_rss_bytes)
    if cpu_user_seconds is not None:
        payload["cpu_user_seconds"] = float(cpu_user_seconds)
    if cpu_system_seconds is not None:
        payload["cpu_system_seconds"] = float(cpu_system_seconds)
    # 409 from the finalize endpoint means a concurrent finalize already
    # wrote the canonical row — accept it and return that row, do not raise.
    response = client.patch(
        f"command-runs/{int(run_id)}", payload, accept_409=True
    )
    return require_command_run_finalize_response(
        response,
        run_id=run_id,
        run_uuid=run_uuid,
        requested_status=status,
    )


def _write_failed_audit_marker(engagement_dir: Path, *, run_uuid: str, error: str) -> None:
    marker_dir = engagement_dir / "scans" / "kali"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{run_uuid}.failed-audit"
    try:
        marker.write_text(f"{_utcnow_iso()} {error}\n", encoding="utf-8")
    except OSError:
        pass
