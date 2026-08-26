"""Output preview, RSS rollup, scope/auth context helpers for kali runs.

Pure-ish I/O: read stdout/stderr files into a head+tail preview capped at
32KB, parse ``/proc/<pid>/status`` for the actual peak RSS (more accurate
than ``getrusage`` for a single child), and derive the scope-version /
auth-context audit fields from engagement files. Also owns the
``KaliResult`` dataclass that the orchestrator returns to callers.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Optional

from . import scope as scope_lib
from .kali_tool_naming import _SHELL_BINARIES


@dataclasses.dataclass
class KaliResult:
    run_id: int | None
    status: str
    return_code: int | None
    stdout_path: str
    stderr_path: str
    duration_ms: int
    peak_rss_bytes: int | None
    stdout_preview: str
    stderr_preview: str
    timed_out: bool
    partial_results: bool
    # CR-36 false-negative guard. True when the run ended in the
    # http=000 / connection-failed / DNS-resolution-failure transport signature
    # — i.e. NO real HTTP answer came back — so an agent must NOT read the
    # terminal status as a target verdict (404/patched/gated). Stays False on a
    # legitimate, body-bearing answer (incl. 4xx/5xx walls) and for non-HTTP
    # tools. ``transport_error_detail`` carries a one-line human reason.
    transport_error: bool = False
    transport_error_detail: str = ""
    # W1 WAF/bot-challenge guard. True when the run came back with a real HTTP
    # exchange whose BODY is a vendor interstitial / bot-challenge (Cloudflare
    # "Just a moment", Akamai "Access Denied", Imperva "Pardon Our Interruption")
    # or a renamed-marker page whose SHAPE is a JS-only challenge shell behind a
    # CDN/edge. That body is the WAF's, NOT the origin app's, so the run MUST NOT
    # be recorded as a target verdict (404/patched/gated). Surfaced exactly like
    # ``transport_error`` (out-of-band on the KaliResult, loud stderr, agent-
    # facing status='waf_challenge') so the agent re-renders the URL with
    # ``vigil assess kali browser`` to obtain the real origin response. Stays
    # False for a genuine app body and for non-HTTP-prober tools (incl. the
    # browser verb itself, so the recovery path never self-flags into a loop).
    waf_challenge: bool = False
    waf_challenge_detail: str = ""
    # The fully-resolved argv that actually ran inside the container, AFTER
    # kali_exec's transparent mutations (program attribution ``-H`` headers, the
    # ``--resolve`` IP-pin, injected identity material, nuclei's default
    # ``-exclude-tags``). Surfaced on the result so the operator/LLM sees what
    # RAN, not just what it typed — the command written and the command executed
    # can diverge, and that gap is the most common source of "why did this probe
    # behave unexpectedly". Empty list only when a caller never populates it.
    resolved_argv: list[str] = dataclasses.field(default_factory=list)


# --------------------------------------------------------------------------- #
# Terminal status -> process exit code
# --------------------------------------------------------------------------- #
#
# Every `vigil assess kali <verb>` used to exit 0 no matter what happened, so a
# timed-out run that produced zero artifacts was indistinguishable from a clean
# negative unless the caller parsed `.status` out of the JSON. These codes put
# the run's own verdict in `$?`.
#
# 0 means "a usable result came back": `completed`, and `waf_challenge` — a WAF
# challenge IS a complete HTTP exchange (the process exited 0), the body is
# merely the WAF's rather than the origin's, which is already loud on stderr and
# in `.status`/`.waf_challenge`, and its documented remedy is to re-render with
# `kali browser`, not to abort a `&&` chain. Non-zero is reserved for "no
# complete output exists to interpret".
#
# 1 and 2 are deliberately unused here: `cli.main` exits 1 on an AssessError
# (Vigil refused) and argparse exits 2 on a parse error, so a target-run verdict
# stays distinguishable from a Vigil-side failure.
KALI_EXIT_CODES: dict[str, int] = {
    "failed": 3,
    "timed_out": 4,
    "killed": 5,
    "transport_error": 6,
}


def kali_exit_code(status: str) -> int:
    """Process exit code for a ``KaliResult.status`` (0 = a usable result)."""
    return KALI_EXIT_CODES.get(str(status or "").strip().lower(), 0)


# --------------------------------------------------------------------------- #
# CR-36 false-negative (http=000 / connection-failed / DNS-failure) detection
# --------------------------------------------------------------------------- #

# HTTP prober tools whose run can be classified by the transport-error guard.
# A non-HTTP tool (nmap, subfinder, puredns, ...) never trips the guard — its
# non-zero exit is a legitimate signal, not a masked target verdict.
_HTTP_PROBER_TOOLS = frozenset({"curl", "httpx", "nuclei", "ffuf", "katana", "wafw00f", "nikto"})

# curl/libcurl exit codes that mean the transport never completed an HTTP
# exchange (no answer came back): 6 DNS-resolve-failure, 7 couldn't-connect,
# 28 timeout, 35 TLS-handshake error. These are NOT a target verdict.
_CURL_TRANSPORT_FAIL_EXITS = frozenset({6, 7, 28, 35})

# Telltale stderr fragments emitted by curl / httpx / the underlying resolver
# on the http=000 transport-failure path. Matched case-insensitively. Kept tight
# so a body that merely mentions these words does not trip the guard (we only
# inspect stderr, never stdout/the response body).
_TRANSPORT_FAIL_STDERR_NEEDLES = (
    "could not resolve host",
    "couldn't resolve host",
    "name or service not known",
    "temporary failure in name resolution",
    "no address associated with hostname",
    "failed to connect",
    "connection refused",
    "connection timed out",
    "could not connect to server",
    "no route to host",
    "network is unreachable",
    "operation timed out",
    "empty reply from server",
    "ssl_connect",
    "no such host",
    "i/o timeout",
    "lookup ",  # Go/httpx 'lookup host: no such host'
)


def is_http_prober(tool_name: str) -> bool:
    """True when ``tool_name`` is an HTTP prober the http=000 guard applies to."""
    return (tool_name or "").strip().lower() in _HTTP_PROBER_TOOLS


def detect_transport_error(
    *,
    tool_name: str,
    return_code: int | None,
    stdout_preview: str,
    stderr_preview: str,
    timed_out: bool,
) -> tuple[bool, str]:
    """Detect the http=000 / connection-failed / DNS-failure signature (CR-36).

    Returns ``(is_transport_error, detail)``. This is the SINGLE in-process
    detector the kali path uses to decide a run produced NO real HTTP answer and
    so MUST NOT be read as a target verdict (404/patched/gated). It composes the
    exit-code + empty-body + telltale-stderr signature and delegates the verdict
    semantics to :func:`reachability.classify_probe` (the project-wide single
    source of truth for "a bare http=000 is not a blocked signal").

    The signature requires ALL of:
      * the tool is an HTTP prober (non-HTTP tools never trip the guard);
      * the run did NOT time out (a timeout is its own terminal status, kept
        distinct — it is partial-but-real, handled by the existing cascade);
      * a transport-level failure exit code OR a telltale resolver/connect stderr
        fragment is present; AND
      * the stdout body is empty (a real HTTP answer — even a 4xx/5xx wall — that
        produced ANY body is LIVE and must stand as a verdict).

    A non-HTTP tool, a clean ``return_code == 0``, or any body-bearing answer
    yields ``(False, "")``.
    """
    from . import reachability

    if not is_http_prober(tool_name):
        return False, ""
    if timed_out:
        return False, ""
    # A successful exit with no transport-failure stderr is a real answer.
    if return_code == 0:
        return False, ""

    stderr_l = (stderr_preview or "").lower()
    exit_is_transport_fail = isinstance(return_code, int) and return_code in _CURL_TRANSPORT_FAIL_EXITS
    stderr_needle = next((n for n in _TRANSPORT_FAIL_STDERR_NEEDLES if n in stderr_l), "")

    if not exit_is_transport_fail and not stderr_needle:
        return False, ""

    # A non-empty stdout body does NOT by itself prove an HTTP answer came back:
    # the project's canonical liveness probe
    # ``curl -o /dev/null -w "%{http_code} %{time_connect} %{remote_ip}"`` writes a
    # write-out line (e.g. ``000 0.000000 ``) to stdout EVEN on a transport
    # failure, so a naive "non-empty stdout = LIVE" shortcut would let the most
    # common failed-curl shape through as a clean verdict — the exact false
    # negative CR-36 exists to prevent. Parse the body as a curl ``-w`` write-out
    # and feed the REAL parsed values into the classifier:
    #   * a real (>0) HTTP status, or a body that is not a write-out line at all
    #     (actual HTML/JSON response content) → a genuine verdict (bail);
    #   * a ``000``/empty write-out → no answer; fall through to flag it.
    # Using the parsed time_connect/remote_ip (not a hard-coded http_code="000")
    # also lets the classifier distinguish "connected but no HTTP" (LIVE — a real,
    # if degraded, reach) from "never connected" (the resolver-flap false negative).
    body = (stdout_preview or "").strip()
    parsed = (
        reachability.parse_curl_w(body.splitlines()[0])
        if body
        else {"http_code": "", "time_connect": 0.0, "remote_ip": ""}
    )
    if body:
        try:
            body_is_real_answer = int(str(parsed["http_code"]).strip()) > 0
        except (TypeError, ValueError):
            # First token is not a numeric status → the body is actual response
            # content, not a write-out line → keep it as a real verdict.
            body_is_real_answer = True
        if body_is_real_answer:
            return False, ""

    # Confirm via the project-wide classifier. With no real answer in the body the
    # parsed http_code is 000/empty; classify_probe returns BLACKHOLED (clean
    # connect failure) or UNKNOWN (DNS-resolve failure / TLS) — both mean "no real
    # HTTP verdict came back", which the false-negative guard must flag. Only an
    # explicit LIVE (e.g. TCP connected, write-out carried a remote_ip) keeps the
    # run as a verdict.
    verdict = reachability.classify_probe(
        http_code=parsed["http_code"] or "000",
        time_connect=parsed["time_connect"],
        remote_ip=parsed["remote_ip"],
        curl_exit=return_code if exit_is_transport_fail else None,
        stderr=stderr_preview or "",
    )
    if verdict == reachability.LIVE:
        return False, ""

    reason = stderr_needle or (
        f"exit {return_code}" if exit_is_transport_fail else "http=000"
    )
    detail = (
        f"http=000/connection-failed signature (tool={tool_name}, "
        f"return_code={return_code}, reachability={verdict}, signal='{reason}')"
    )
    return True, detail


# --------------------------------------------------------------------------- #
# W1 — WAF / bot-challenge interstitial detection
# --------------------------------------------------------------------------- #
#
# A real HTTP exchange can come back 200/403 with a body that is the WAF's
# challenge page, NOT the origin app's response. Reading that body (or its
# status) as a target verdict (404/patched/gated) is a false negative as
# dangerous as the http=000 one. Two complementary detectors run:
#
#   1. NAMED VENDOR SIGNATURES — high-confidence per-vendor markers in the body,
#      headers, or stderr. Cheap and precise.
#   2. GENERIC challenge-SHAPE — a small, JS-only body with no real app content
#      sitting behind a CDN/edge fingerprint at a challenge-ish status. This is
#      the safety net so a RENAMED vendor marker does not silently revert to
#      "challenge read as a verdict".
#
# FAIL-SAFE direction: a MISSED detection just trusts the tool as before (no new
# harm); a false "this is real" is the dangerous direction. So on ambiguity we
# lean to flagging — an over-flag routes the surface to the headless-browser
# recovery (``vigil assess kali browser``), it does not strand it.

# (needle_lowercased, vendor) — substring match against the body+headers+stderr
# haystack. Each is on its own a strong WAF/bot-challenge signal: an
# interstitial-page string, a challenge-form field name, or a challenge-only
# resource path. Deliberately EXCLUDED here are the always-present session /
# edge fingerprints (Akamai ``_abck``/``ak_bmsc``/``bm_sz``/``AkamaiGHost``,
# Imperva ``incap_ses``/``visid_incap``/``reese84``/``x-iinfo``): a bot manager
# sets those on ~every response it fronts, so their mere presence means "this
# vendor is in front", NOT "this is a challenge". They are demoted to the
# edge-marker tier (``_CDN_EDGE_MARKERS``) and flag ONLY alongside a real
# challenge SHAPE. The Akamai challenge STATE that a header-only block DOES carry
# lives in the ``_abck`` cookie VALUE and is recovered by
# :func:`_abck_challenge_sentinel`, not by matching the cookie name.
_WAF_NAMED_SIGNATURES: tuple[tuple[str, str], ...] = (
    # Imperva / Incapsula — challenge-specific needles only.
    ("_incapsula_resource", "imperva"),
    ("pardon our interruption", "imperva"),
    # Akamai — the Access-Denied reference-error body string only (the session
    # cookies + AkamaiGHost banner are edge markers, see _CDN_EDGE_MARKERS).
    ("reference&#32;&#35;", "akamai"),
    # Cloudflare
    ("cf-chl", "cloudflare"),
    ("__cf_chl", "cloudflare"),
    ("cf_chl_opt", "cloudflare"),
    ("jschl_vc", "cloudflare"),
    ("just a moment", "cloudflare"),
    ("checking your browser", "cloudflare"),
    ("cf-mitigated", "cloudflare"),
    ("attention required! | cloudflare", "cloudflare"),
    ("challenge-platform", "cloudflare"),
    # Other common bot-defense vendors — challenge/BLOCK-specific needles only.
    # The always-present fingerprints for these vendors (the DataDome ``datadome``
    # cookie + ``js.datadome.co`` sensor tag, the PerimeterX ``_px`` cookies +
    # ``client.perimeterx.net`` sensor, the Sucuri ``x-sucuri-id`` proxy header)
    # ride ~every response the vendor fronts — challenge or not — so, exactly like
    # the Akamai/Imperva session cookies above, they are DEMOTED to the edge-marker
    # tier and flag only alongside a real challenge SHAPE. What survives here is
    # block-only: DataDome's captcha host (referenced only when it serves a
    # challenge) and Sucuri's block-page title.
    ("captcha-delivery.com", "datadome"),  # DataDome captcha/challenge host — block-only.
    ("sucuri website firewall", "sucuri"),  # Sucuri block-page title — block-only.
)

# Generic block phrases that ALSO appear on legitimate origin 401/403 pages, so
# they flag ONLY when corroborated by a vendor marker in the SAME response.
# "Access Denied" is the Akamai Ghost body title, but it is equally the default
# IIS / nginx / app-level 403 page — so the bare phrase must never flag on its own
# (a real Akamai block still trips _abck/AkamaiGHost, or the 403 generic-shape
# pass). Each entry: (phrase, vendor, corroborating markers — any one suffices).
_WAF_CORROBORATION_PHRASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "access denied",
        "akamai",
        ("_abck", "ak_bmsc", "bm_sz", "akamaighost", "x-akamai", "reference&#32;&#35;"),
    ),
)

# CDN / edge / bot-defense fingerprints used by the generic-shape pass. Presence
# of one of these (in a header dump or the body) is necessary — but NOT
# sufficient — to call a JS-only shell a challenge. This tier ALSO owns the
# always-present vendor session/edge fingerprints (Akamai ``_abck``/``ak_bmsc``/
# ``bm_sz``, Imperva ``incap_ses``/``visid_incap``/``reese84``, DataDome
# ``datadome``, PerimeterX ``_px``/``x-px``, Sucuri ``x-sucuri``) that were
# previously (and inconsistently) treated as sufficient signatures: front ~every
# response, they corroborate a challenge only when a real challenge SHAPE is
# present, never on the name alone.
_CDN_EDGE_MARKERS: tuple[str, ...] = (
    "cf-ray",
    "cloudflare",
    "akamaighost",
    "x-akamai",
    "akamai",
    "_abck",
    "ak_bmsc",
    "bm_sz",
    "x-iinfo",
    "incapsula",
    "imperva",
    "incap_ses",
    "visid_incap",
    "reese84",
    "x-cdn",
    "x-sucuri",
    "sucuri",
    "x-amz-cf-id",
    "x-amzn-waf",
    "awselb",
    "barracuda",
    "x-datadome",
    "datadome",
    "perimeterx",
    "_px",
    "x-px",
)

# Statuses a challenge/interstitial is served with. A determinable status outside
# this set (e.g. a 301 redirect, a 500 origin error) means it is NOT a challenge
# shell. An UNDETERMINABLE status does not veto the shape match (lean to flag).
_CHALLENGE_STATUSES: frozenset[int] = frozenset({200, 403, 429, 503})

# The subset of challenge statuses that, ON THEIR OWN, signal a block/throttle
# strongly enough to corroborate a JS-only shell as a challenge WITHOUT any
# CDN/edge header present — the fail-safe path for a header-less curl ``-sS``
# probe. 200 is deliberately EXCLUDED: a 200 + tiny JS-only body is the single
# most common shape of a legitimate SPA bootstrap, so a 200 needs an actual
# edge/vendor signal (header or named body marker), never shape alone.
_HARD_CHALLENGE_STATUSES: frozenset[int] = frozenset({403, 429, 503})

# A challenge shell is SMALL. A large body with an inlined app bundle is far more
# likely a real (if JS-heavy) app page; keep the generic-shape pass off it so a
# heavy SPA shell is not perpetually flagged. The unambiguous large vendor pages
# (Cloudflare's ~15KB "Just a moment") are already caught by the named pass.
_CHALLENGE_BODY_MAX = 15_000

# A challenge shell carries almost no human-visible text — a one-liner like
# "Checking your browser" or nothing at all. A real app page carries far more.
_CHALLENGE_VISIBLE_TEXT_MAX = 240


def _visible_text(body: str) -> str:
    """Strip script/style/noscript blocks and all tags; collapse whitespace.

    The remaining text approximates what a human would SEE on the page. A
    challenge shell de-tags to a one-liner (or empty); a real app page de-tags to
    substantial copy.
    """
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", body)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _strip_leading_header_block(text: str) -> str:
    """Return the response BODY when ``text`` begins with an HTTP header block.

    A curl probe run with ``-i``/``-D -`` prepends ``HTTP/x.y NNN`` + ``Name:
    Value`` lines + a blank line to stdout. Those header lines are NOT inside any
    tag, so the visible-text / JS-only-shell heuristics would wrongly count them
    as page content. Strip everything up to the first blank line so the shape
    pass measures the real body. Returns ``text`` unchanged when there is no
    leading header block (curl ``-sS``, httpx JSON, a raw body).
    """
    stripped = text.lstrip()
    if not re.match(r"^HTTP/\d", stripped):
        return text
    match = re.search(r"\r?\n[ \t]*\r?\n", stripped)
    return stripped[match.end():] if match else text


def _extract_http_status(body: str, headers: Optional[dict]) -> int | None:
    """Best-effort HTTP status for the generic-shape pass.

    Reads an explicit status off a ``headers`` mapping (``status`` /
    ``http_status`` / ``:status`` / ``status_code``) first, then falls back to a
    leading ``HTTP/x.y NNN`` status line in a header dump (curl ``-i`` / ``-D``).
    Returns ``None`` when no status is recoverable — the caller treats that as
    "do not veto" rather than "definitely not a challenge".
    """
    if isinstance(headers, dict):
        for key in ("status", "http_status", ":status", "status_code"):
            value = headers.get(key)
            if value is None:
                continue
            try:
                return int(str(value).strip().split()[0])
            except (ValueError, IndexError):
                continue
    match = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", body or "", re.MULTILINE)
    if match:
        return int(match.group(1))
    return None


def _has_challenge_redirect(low: str) -> bool:
    """True when the body BOUNCES the client — a meta-refresh or a scripted
    navigation/reload. A challenge interstitial reloads/redirects to clear the
    JS check; a plain ``<script src=bundle>`` SPA shell does NOT. This is what
    separates a challenge SHAPE from a normal single-page-app bootstrap, so a
    body that merely mentions a CDN in a comment is not mistaken for one.
    """
    if re.search(r"http-equiv\s*=\s*['\"]?refresh", low):
        return True
    return bool(
        re.search(r"(?:window|document|top|self)\.location", low)
        or re.search(r"location\.(?:href|replace|reload|assign)", low)
    )


def _looks_like_generic_challenge(
    body: str, header_text: str, status: int | None
) -> tuple[bool, str]:
    """Generic challenge-SHAPE heuristic (renamed-marker safety net).

    ``body`` is the response body (header block already stripped); ``header_text``
    is the lowercased REAL response headers the caller threaded in; ``status`` is
    the best-effort HTTP status (or ``None``).

    A small, JS-only body with no real app content is treated as a challenge
    when corroborated by ONE of (in descending confidence):

      * the HTTP status is a hard block/throttle (403/429/503) — even with no
        edge signal at all, a blocked JS-only shell with no app content leans to
        a challenge (the header-less ``curl -sS`` fail-safe direction); or
      * a CDN/edge fingerprint is present (a REAL threaded header, OR named in the
        body) AND the shell actually BOUNCES the client (meta-refresh / scripted
        navigation) — i.e. it behaves like an interstitial, not a static app shell.

    Two deliberate NON-triggers keep the false-positive rate down:
      * a bare CDN substring in the body alone (e.g. ``cloudflare`` in a comment
        on a normal SPA that ships a bundle ``<script>``) — that was the false
        positive when the body was the only haystack; and
      * a CDN/edge HEADER + a JS-only shell at a NON-block status (e.g. 200) with
        no client redirect — that is the single most common shape of a legitimate
        client-rendered SPA served behind Cloudflare/Akamai, so an edge header on
        its own is NOT taken as a challenge.

    A determinable HTTP status outside ``_CHALLENGE_STATUSES`` (a 301 redirect, a
    500 origin error) vetoes the match; an UNDETERMINABLE status does not.
    """
    if not body:
        return False, ""
    if len(body) > _CHALLENGE_BODY_MAX:
        return False, ""

    low = body.lower()
    has_script = "<script" in low or "window.location" in low or "document.location" in low
    has_redirect = _has_challenge_redirect(low)
    if not (has_script or has_redirect):
        return False, ""
    if len(_visible_text(body)) >= _CHALLENGE_VISIBLE_TEXT_MAX:
        return False, ""

    if status is not None and status not in _CHALLENGE_STATUSES:
        return False, ""

    # A hard block/throttle status on a JS-only no-content shell is the strongest,
    # edge-agnostic signal (and the only one available to a header-less curl -sS
    # probe that nonetheless surfaced a status).
    if status is not None and status in _HARD_CHALLENGE_STATUSES:
        return (
            True,
            f"status={status} block, js-only shell with no app content",
        )

    # Otherwise a CDN/edge fingerprint is necessary but NOT sufficient: it must
    # be paired with interstitial behaviour (the shell redirects/refreshes the
    # client). A header edge is higher confidence than a body mention, but both
    # demand the redirect so a static SPA behind a CDN at 200 is never flagged.
    header_edge = next((m for m in _CDN_EDGE_MARKERS if m in header_text), "")
    body_edge = next((m for m in _CDN_EDGE_MARKERS if m in low), "")
    edge = header_edge or body_edge
    if edge and has_redirect:
        source = "header" if header_edge else "body"
        detail = f"edge='{edge}' ({source}) + client redirect, no app content"
        if status is not None:
            detail += f", status={status}"
        return True, detail

    return False, ""


# Akamai Bot Manager sets ``_abck`` on ~every response it fronts, so the mere
# cookie NAME is an edge fingerprint (see ``_CDN_EDGE_MARKERS``), NOT a challenge.
# The challenge STATE lives in the cookie VALUE: the sensor-validation field (the
# second ``~``-delimited field) is held at ``-1`` until the client solves the
# sensor check, so an ``_abck`` whose validation field is ``-1`` is a genuine
# header-only BLOCK. A passed/normal Bot Manager ``_abck`` carries a non-``-1``
# validation field (later ``-1`` fields are normal), so this recovers a true
# block without flagging ordinary Bot Manager traffic. The value char class stops
# at the cookie/attribute separators and at JSON/quote delimiters so a Set-Cookie
# embedded in an httpx ``-json`` line is captured cleanly.
_ABCK_SENTINEL_RE = re.compile(r"_abck=([^;,\s\"']+)")


def _abck_challenge_sentinel(haystack: str) -> str:
    """Return the offending ``_abck`` value when it carries Akamai's
    sensor-unvalidated (``-1``) challenge sentinel, else ``""``.

    ``haystack`` is the lowercased body+headers+stderr blob. This inspects the
    cookie VALUE (not merely its name) and tests the SECOND ``~``-delimited field
    — the sensor-validation slot Akamai pins at ``-1`` on a not-yet-passed
    challenge/block. A normal (passed) Bot Manager cookie carries a non-``-1``
    value there, so ordinary Bot Manager traffic is never flagged.
    """
    for match in _ABCK_SENTINEL_RE.finditer(haystack):
        fields = match.group(1).split("~")
        if len(fields) >= 2 and fields[1] == "-1":
            return match.group(1)
    return ""


def detect_waf_challenge(
    stdout_preview: str,
    stderr_preview: str = "",
    headers: Optional[dict] = None,
) -> tuple[bool, str]:
    """Detect a WAF / bot-challenge interstitial in a finished HTTP run.

    Returns ``(is_waf_challenge, reason)``. When True, the run produced a real
    HTTP exchange whose BODY is the WAF's challenge page (not the origin app's
    response), so its terminal status MUST NOT be read as a target verdict.

    Composes the named-vendor-signature pass with the generic challenge-SHAPE
    heuristic. ``headers`` (when a caller has parsed them) is folded into the
    match haystack alongside the body and stderr; when ``None`` the body alone
    must carry the signal (e.g. curl with no ``-i`` only emits the body), which
    is the fail-safe degraded mode — a missed detection just trusts the tool.
    """
    raw = stdout_preview or ""
    header_text = ""
    if isinstance(headers, dict):
        try:
            header_text = "\n".join(f"{name}: {value}" for name, value in headers.items())
        except (AttributeError, TypeError):
            header_text = ""
    # The named pass scans the FULL stdout (so a curl ``-i`` dump's inline header
    # markers still substring-match even if the caller did not thread a dict) plus
    # the threaded header text and stderr.
    haystack = f"{raw}\n{header_text}\n{stderr_preview or ''}".lower()

    for needle, vendor in _WAF_NAMED_SIGNATURES:
        if needle in haystack:
            return True, f"{vendor} WAF/bot-challenge signature: '{needle}'"

    # Akamai header-only BLOCK: the _abck cookie VALUE carries the
    # sensor-unvalidated (-1) sentinel. The cookie NAME alone is an always-present
    # edge fingerprint (demoted to _CDN_EDGE_MARKERS); only the unvalidated VALUE
    # is a genuine challenge, so normal Bot Manager traffic is not flagged.
    abck = _abck_challenge_sentinel(haystack)
    if abck:
        return True, (
            f"akamai WAF/bot-challenge signature: _abck sensor-unvalidated "
            f"sentinel ('{abck}')"
        )

    # Generic block phrases (e.g. "Access Denied") flag ONLY when a vendor marker
    # is also present, so a legitimate origin 401/403 carrying the phrase is
    # recorded as the app's response rather than suppressed as a challenge.
    for phrase, vendor, markers in _WAF_CORROBORATION_PHRASES:
        if phrase in haystack:
            hit = next((m for m in markers if m in haystack), "")
            if hit:
                return True, (
                    f"{vendor} WAF/bot-challenge signature: '{phrase}' "
                    f"(corroborated by '{hit}')"
                )

    # The shape pass measures the real BODY (curl ``-i`` header block stripped) and
    # uses the best-effort status from the threaded headers or a leading HTTP line.
    body = _strip_leading_header_block(raw)
    status = _extract_http_status(raw, headers)
    is_shape, shape_detail = _looks_like_generic_challenge(
        body, header_text.lower(), status
    )
    if is_shape:
        return True, f"generic challenge-shape ({shape_detail})"

    return False, ""


def _flatten_header_value(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _headers_from_httpx_json(stdout_preview: str) -> Optional[dict]:
    """Response headers recovered from an httpx ``-json`` stdout stream.

    httpx emits one JSON object per probed target. The default lean liveness
    flags (``-web-server -status-code``, optionally ``-cdn``) already carry the
    ``webserver``/``status_code``/``cdn_name`` fields, and ``-irh`` /
    ``-include-response`` add the full ``header`` map / ``raw_header`` blob — none
    of which appear in a bare response BODY, so they are invisible to a
    body-only haystack. We flatten whatever is present into a header dict so the
    named-vendor pass (Akamai ``AkamaiGHost``/``_abck``, Imperva ``x-iinfo``) and
    the generic-shape status check can see it.
    """
    merged: dict[str, str] = {}
    for raw_line in (stdout_preview or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict) or obj.get("failed"):
            continue
        # Full response-header map (httpx -irh / -include-response-header) or the
        # raw header blob (httpx -irr / -include-response).
        for key in ("header", "response_header", "headers"):
            hmap = obj.get(key)
            if isinstance(hmap, dict):
                for hk, hv in hmap.items():
                    if isinstance(hk, str) and hk.strip():
                        merged.setdefault(hk.strip(), _flatten_header_value(hv))
        raw_header = obj.get("raw_header")
        if isinstance(raw_header, str) and raw_header.strip():
            merged.setdefault("raw_header", raw_header)
        # Synthesize from the lean default fields so a header-only Akamai/
        # Cloudflare edge is visible even without -irh.
        webserver = obj.get("webserver") or obj.get("web_server")
        if isinstance(webserver, str) and webserver.strip():
            merged.setdefault("Server", webserver.strip())
        cdn = obj.get("cdn_name") or obj.get("cdn")
        if isinstance(cdn, str) and cdn.strip():
            merged.setdefault("cdn", cdn.strip())
        status = obj.get("status_code")
        if isinstance(status, int):
            merged.setdefault("status_code", str(status))
    return merged or None


def _headers_from_curl_dump(stdout_preview: str) -> Optional[dict]:
    """Response headers parsed from a curl header dump prepended to stdout.

    A curl probe run with ``-i``/``--include`` or ``-D -``/``--dump-header -``
    writes the response header block (``HTTP/x.y NNN`` status line + ``Name:
    Value`` lines + blank line) ahead of the body. We parse the FIRST such block.
    Returns ``None`` when stdout carries no leading header block (the bare
    ``curl -sS`` liveness probe), so the caller falls back to body-only.
    """
    lines = (stdout_preview or "").splitlines()
    start = next(
        (i for i, ln in enumerate(lines[:64]) if re.match(r"^HTTP/\d", ln.strip())),
        None,
    )
    if start is None:
        return None
    headers: dict[str, str] = {}
    for ln in lines[start + 1:]:
        if not ln.strip():
            break
        if ":" not in ln:
            continue
        name, value = ln.split(":", 1)
        name = name.strip()
        if not name:
            continue
        value = value.strip()
        # Preserve repeated headers (e.g. multiple Set-Cookie) by joining.
        headers[name] = f"{headers[name]}\n{value}" if name in headers else value
    return headers or None


def extract_probe_response_headers(
    tool_name: str, cmd: list[str], stdout_preview: str
) -> Optional[dict]:
    """Best-effort response headers from a finished probe's stdout (W1 guard).

    The production ``kali_exec`` curl liveness probe runs ``-sS`` (no ``-i``/
    ``-D``), so its stdout is the BODY only — header-only WAF markers (Akamai
    ``_abck``, Imperva ``x-iinfo``) are simply not in those bytes and cannot be
    recovered. They ARE recoverable when the probe itself surfaced headers, and
    those are the cases this threads into :func:`detect_waf_challenge`:

      * ``httpx`` with ``-json``/``-j``: the per-target JSON carries response
        metadata (``header`` map / ``raw_header`` / ``webserver`` / ``cdn_name``
        / ``status_code``); parse and flatten it.
      * ``curl`` with ``-i``/``-D -``: the header block is prepended to stdout;
        parse it (this also covers combined short flags like ``-sSi`` since we
        key off the leading ``HTTP/`` status line, not the argv).

    Returns ``None`` when no headers are recoverable — the documented fail-safe
    degraded mode where the body-only / status-shape heuristic stands alone.
    """
    if not stdout_preview:
        return None
    name = (tool_name or "").strip().lower()
    if name == "httpx" and any(t in ("-json", "-j", "--json") for t in (cmd or [])):
        return _headers_from_httpx_json(stdout_preview)
    if name == "curl":
        return _headers_from_curl_dump(stdout_preview)
    return None


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope_version(engagement_dir: Path) -> str:
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return ""
    try:
        digest = hashlib.sha256(scope.read_bytes()).hexdigest()
    except OSError:
        return ""
    return digest[:16]


def _engagement_type(engagement_dir: Path) -> str:
    """Read ``engagement_type`` from ``scope.json`` (web/code/blue/both).

    Used by the probe-run emission WEB-ONLY guard so the depth
    harness never fires on code/blue engagements. Mirrors the default used by
    ``transition_phase`` (absent/unreadable scope ⇒ ``"web"``), so a legacy
    web engagement without the field still emits probes; only an explicit
    ``code``/``blue`` engagement is skipped.
    """
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return "web"
    try:
        data = json.loads(scope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "web"
    if not isinstance(data, dict):
        return "web"
    return str(data.get("engagement_type", "web")) or "web"


def _required_headers(engagement_dir: Path) -> dict[str, str]:
    """Read ``required_headers`` from ``scope.json``.

    These are program-mandated attribution headers (e.g. BugCrowd's
    ``X-Bug-Bounty: <handle>``) that every in-scope HTTP probe must carry. An
    absent/empty/unreadable scope returns ``{}`` so the no-header path is the
    unchanged default. Only string→string pairs survive; anything else is
    dropped so a malformed scope can never inject a non-header value into argv.
    """
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return {}
    try:
        data = json.loads(scope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    raw = data.get("required_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if isinstance(name, str) and name.strip() and isinstance(value, str):
            headers[name.strip()] = value
    return headers


# Program-mandated attribution headers (e.g. BugCrowd's ``X-Bug-Bounty: <handle>``)
# must ride every in-scope HTTP probe. Four-way classifier:
#   * INJECTABLE — HTTP-to-target tools that accept ``-H "Name: Val"``; inject.
#   * FLAG-MAP   — HTTP-to-target tools whose header flag is NOT ``-H`` (whatweb
#                  ``--header``, nikto ``-Add-header``, arjun ``--headers``);
#                  inject via the tool's own flag (Layer 1, I-3).
#   * SKIP       — passive / third-party-archive / DNS / L3-L4 tools that never
#                  send HTTP to the in-scope target. Injecting here would LEAK
#                  the researcher handle to web.archive.org/CommonCrawl/DNS APIs
#                  or is meaningless, so silently skip (never warn).
#   * else       — HTTP-to-target tools whose header flag can't carry an inline
#                  value (wafw00f's ``-H``/``--headers`` reads a FILE, not a
#                  string) or an unknown tool: WARN (never block).
#
# This classifier + injector lives here (rather than in kali.py) so BOTH the
# container path (kali.kali_exec) AND the audited host path (the recon
# host-dispatch wrappers in commands/web_discovery.py / dns_discovery.py) apply
# the SAME injectable/skip rules. kali.py re-exports these names for back-compat.
_REQUIRED_HEADER_INJECTABLE = frozenset(
    # dalfox sends active XSS payloads to the in-scope target and takes the
    # curl-style ``-H "Name: Value"`` (repeatable), so it injects via the same
    # ``-H`` path as curl/httpx — never leave a dalfox probe un-attributed on a
    # required-headers program.
    {"curl", "httpx", "nuclei", "ffuf", "sqlmap", "katana", "dalfox"}
)

# Layer-1 extension (I-3) — HTTP-to-target tools whose attribution-header flag is
# NOT the curl-style ``-H "Name: Value"``. Each entry maps a tool to
# ``(inject_flag, single_newline_block)``:
#   * whatweb ``--header "K: V"`` — repeatable, one header per flag occurrence;
#   * nikto   ``-Add-header "K: V"`` — repeatable (nikto's ``-H`` is ``-Help``;
#                  the real header flag is ``-Add-header``, verified in-container);
#   * arjun   ``--headers "K: V"`` — a SINGLE flag whose value is newline-joined
#                  for multiple headers (a second ``--headers`` would clobber the
#                  first under argparse store), so ``single_newline_block=True``.
# wafw00f is deliberately absent: its ``-H``/``--headers`` reads a file path, not
# an inline string, so it cannot carry an inline marker.
_REQUIRED_HEADER_FLAG_SPECS: dict[str, tuple[str, bool]] = {
    "whatweb": ("--header", False),
    "nikto": ("-Add-header", False),
    "arjun": ("--headers", True),
}
# Tools that apply the program-required attribution headers THEMSELVES, outside
# the argv. The `browser` verb hands them to the Playwright driver as extra HTTP
# headers, so there is nothing to append to a command line — and warning that
# injection "failed" on every browser run against a required-headers program
# taught operators that a real deconfliction rule was being violated when it was
# not. Deliberately NOT folded into ``_REQUIRED_HEADER_SKIP``: a skip asserts
# "this tool never speaks HTTP to the target", which is false here and would
# hide a genuine regression if the driver ever stopped applying them.
_REQUIRED_HEADER_SELF_ATTRIBUTING = frozenset({"browser"})

_REQUIRED_HEADER_SKIP = frozenset(
    {
        "gau",
        "waybackurls",
        "subfinder",
        "amass",
        "dnsx",
        "nmap",
        "naabu",
        "masscan",
        "puredns",
        # tlsx opens a raw TLS handshake to harvest cert SAN/CN/issuer fields;
        # like nmap it is an L4-L6 connect that carries NO HTTP request, so an
        # HTTP attribution header cannot ride it. Skip without warning — same
        # posture as nmap/naabu/masscan, which also reach the target without
        # speaking HTTP.
        "tlsx",
    }
)


def _existing_header_names(cmd: list[str]) -> set[str]:
    """Lower-cased header names already present as ``-H`` values in ``cmd``.

    Splits each ``-H`` argument on the first colon and tolerates a space before
    it (``Name:`` and ``Name :``) so the idempotency check matches regardless of
    spacing.
    """
    names: set[str] = set()
    for idx, token in enumerate(cmd):
        if token == "-H" and idx + 1 < len(cmd):
            value = cmd[idx + 1]
            head = value.split(":", 1)[0].strip()
            if head:
                names.add(head.lower())
    return names


def _flag_header_names(cmd: list[str], flags: tuple[str, ...]) -> set[str]:
    """Lower-cased header names already carried by any flag in ``flags``.

    A single value may pack several newline-separated headers (arjun's
    ``--headers`` block), so each line of every matching value is examined.
    """
    names: set[str] = set()
    for idx, token in enumerate(cmd):
        if token in flags and idx + 1 < len(cmd):
            for line in cmd[idx + 1].splitlines():
                head = line.split(":", 1)[0].strip()
                if head:
                    names.add(head.lower())
    return names


def _inject_tool_flag_headers(
    cmd: list[str], tool: str, headers: dict[str, str]
) -> str:
    """Inject required header(s) into ``cmd`` via a non-``-H`` tool's own flag.

    Returns ``"injected"`` when a missing header was added, ``"noop"`` when every
    required header is already present. Idempotent on the header NAME.
    """
    inject_flag, single_block = _REQUIRED_HEADER_FLAG_SPECS[tool]
    if single_block:
        # arjun-style: one flag, newline-joined value; argparse keeps the LAST,
        # so merge into the last existing block rather than append a second flag
        # that would clobber an operator-supplied auth-headers block.
        last_idx: Optional[int] = None
        for idx in range(len(cmd) - 1):
            if cmd[idx] == inject_flag:
                last_idx = idx
        existing: set[str] = set()
        if last_idx is not None:
            for line in cmd[last_idx + 1].splitlines():
                head = line.split(":", 1)[0].strip()
                if head:
                    existing.add(head.lower())
        missing = [(n, v) for n, v in headers.items() if n.lower() not in existing]
        if not missing:
            return "noop"
        addition = "\n".join(f"{n}: {v}" for n, v in missing)
        if last_idx is not None:
            cmd[last_idx + 1] = f"{cmd[last_idx + 1]}\n{addition}"
        else:
            cmd.extend([inject_flag, addition])
        return "injected"

    # Repeatable flag (whatweb ``--header``, nikto ``-Add-header``). whatweb also
    # accepts ``-H`` as an alias, so an operator ``-H`` counts as already-present.
    recognized = (inject_flag, "-H") if tool == "whatweb" else (inject_flag,)
    existing = _flag_header_names(cmd, recognized)
    injected = False
    for name, value in headers.items():
        if name.lower() in existing:
            continue
        cmd.extend([inject_flag, f"{name}: {value}"])
        existing.add(name.lower())
        injected = True
    return "injected" if injected else "noop"


# --------------------------------------------------------------------------- #
# W5 — BEST-EFFORT required-header injection into `sh -c` / `bash -c` scripts
# --------------------------------------------------------------------------- #
#
# A required_headers engagement may run a shell wrapper whose ``-c`` script
# carries curl/wget (or other -H-capable) sub-commands. A plain ``-H`` append on
# the argv would land on the SHELL as a positional parameter ($1/$2) and never
# reach the inner tool, so we parse the script TEXT and inject ``-H 'Name: Val'``
# (``--header`` for wget) right after each recognized sub-command head that lacks
# it.
#
# BEST-EFFORT, NEVER fail-closed: a missing attribution header is a REDUCED
# REWARD, not a ban-risk, and a hard block would stall a legitimate multi-curl
# probe mid-hunt and hurt performance. When the script can't be safely lexed, or
# carries no -H-capable sub-command, we leave it untouched and let the caller
# WARN (or silently skip a purely-passive wrapper). We never raise, never block.

# curl/wget plus the other -H-capable injectable tools that may appear as a
# sub-command head inside a shell script. wget's header flag is ``--header``;
# every other entry uses ``-H``. (curl is already in _REQUIRED_HEADER_INJECTABLE.)
_SHELL_SUBCMD_INJECTABLE = frozenset({"wget"} | set(_REQUIRED_HEADER_INJECTABLE))

# A sub-command head = one of the injectable tool names at the START of a
# sub-command: at script start, right after a shell separator/opener
# (newline ; & | backtick ( ) { } or the ``&&``/``||`` operators) or a
# ``do``/``then``/``else``/``if``/``elif``/``while``/``until`` keyword (so a
# command head inside a control-flow wrapper is still found). The trailing
# lookahead pins it to a whole
# word so ``mycurl`` / ``curls`` / ``echo curl`` are never taken as heads.
_SHELL_SUBCMD_HEAD_RE = re.compile(
    r"(?P<pre>(?:\A|[\n;&|`(){}]|&&|\|\||\b(?:do|then|else|if|elif|while|until)\b)\s*)"
    r"(?P<cmd>"
    + "|".join(
        sorted((re.escape(t) for t in _SHELL_SUBCMD_INJECTABLE), key=len, reverse=True)
    )
    + r")(?=\s|\Z|[;&|)<>])",
    re.IGNORECASE,
)

# A shell command-string flag: a bare ``-c`` OR a combined short-option bundle
# ending in ``c`` (``bash -lc`` / ``sh -ec`` / ``-xc``). ``c`` must be LAST so the
# script is still the next argument; ``-cl`` etc. are not command-string forms.
_SHELL_C_FLAG_RE = re.compile(r"-[A-Za-z]*c")


def _shell_script_index(cmd: list[str]) -> Optional[int]:
    """Index of the ``-c`` script argument when ``cmd`` is a sh/bash command-string
    wrapper, else ``None``. Recognizes a bare ``-c`` and combined short-option
    bundles ending in ``c`` (``bash -lc 'curl ...'``, ``sh -ec '...'``), and matches
    both the bare (``sh``) and absolute (``/bin/bash``) head forms via the shared
    ``_SHELL_BINARIES`` set."""
    if not cmd:
        return None
    head = cmd[0]
    if head not in _SHELL_BINARIES and os.path.basename(head) not in _SHELL_BINARIES:
        return None
    for idx in range(1, len(cmd) - 1):
        if _SHELL_C_FLAG_RE.fullmatch(cmd[idx]):
            return idx + 1
    return None


def _wrapped_shell_script_index(cmd: list[str]) -> Optional[int]:
    """Locate a shell command string behind supported transparent launchers."""
    offset = 0
    current = [str(token) for token in cmd]
    for _ in range(16):
        local = _shell_script_index(current)
        if local is not None:
            return offset + local
        if not current:
            return None
        head = Path(current[0]).name.lower()
        if head not in scope_lib._LAUNCHERS:
            return None
        inner_index, ambiguous = scope_lib._launcher_inner_index(current, head)
        if ambiguous or inner_index is None:
            return None
        offset += inner_index
        current = current[inner_index:]
    return None


def _shell_segment_end(script: str, start: int) -> int:
    """First index at/after ``start`` that ends the current sub-command — the
    next unquoted top-level separator (``;`` ``|`` ``&`` newline ``)``) or
    end-of-string. Tracks single/double quotes and backslash escapes so a
    separator inside a quoted argument is not mistaken for a real boundary."""
    i, n = start, len(script)
    in_single = in_double = False
    while i < n:
        c = script[i]
        if in_single:
            if c == "'":
                in_single = False
        elif in_double:
            if c == "\\" and i + 1 < n:
                i += 1
            elif c == '"':
                in_double = False
        else:
            if c == "'":
                in_single = True
            elif c == '"':
                in_double = True
            elif c == "\\" and i + 1 < n:
                i += 1
            elif c in ";\n|&)":
                break
        i += 1
    return i


def _segment_has_header(segment: str, name: str) -> bool:
    """True when ``segment`` (one sub-command's text) already carries a ``-H`` /
    ``--header`` naming ``name`` (case-insensitive). Tolerates ``-H Name: v``,
    ``-HName: v``, ``--header Name: v`` and ``--header=Name: v``. An unparseable
    segment is treated as already-present so we never risk a double-inject."""
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return True
    name_l = name.strip().lower()
    for i, tok in enumerate(tokens):
        candidate = ""
        if tok in ("-H", "--header") and i + 1 < len(tokens):
            candidate = tokens[i + 1]
        elif tok.startswith("-H") and len(tok) > 2:
            candidate = tok[2:]
        elif tok.startswith("--header="):
            candidate = tok[len("--header="):]
        if candidate and candidate.split(":", 1)[0].strip().lower() == name_l:
            return True
    return False


def _inject_headers_into_script(
    script: str, headers: dict[str, str]
) -> tuple[str, str]:
    """Best-effort inject required header(s) into a shell ``-c`` script's
    curl/wget/-H-capable sub-commands.

    Returns ``(status, new_script)`` where status is:
      * ``"injected"`` — at least one header was inserted into a sub-command;
      * ``"noop"``     — injectable sub-command(s) found, every required header
                         already present (idempotent);
      * ``"none"``     — no -H-capable sub-command found, OR the script could not
                         be safely lexed (unbalanced quote). The caller decides
                         warn-vs-skip; we never edit the script in this case.
    """
    # Whole-script sanity lex: an unbalanced quote means we cannot reason about
    # token boundaries safely, so we decline to edit (best-effort, never block).
    try:
        shlex.split(script)
    except ValueError:
        return "none", script

    matches = list(_SHELL_SUBCMD_HEAD_RE.finditer(script))
    if not matches:
        return "none", script

    insertions: list[tuple[int, str]] = []
    for m in matches:
        cmd_word = m.group("cmd").lower()
        seg_end = _shell_segment_end(script, m.end("cmd"))
        segment = script[m.start("cmd") : seg_end]
        flag = "--header" if cmd_word == "wget" else "-H"
        addition = ""
        for name, value in headers.items():
            if _segment_has_header(segment, name):
                continue
            addition += f" {flag} {shlex.quote(f'{name}: {value}')}"
        if addition:
            insertions.append((m.end("cmd"), addition))

    if not insertions:
        return "noop", script

    new_script = script
    for pos, text in sorted(insertions, key=lambda pair: pair[0], reverse=True):
        new_script = new_script[:pos] + text + new_script[pos:]
    return "injected", new_script


def _apply_required_headers(
    cmd: list[str], tool_name: str, headers: dict[str, str]
) -> str:
    """Inject program-mandated attribution header(s) into an HTTP command argv.

    Returns one of ``"injected"``, ``"self_attributed"``, ``"skipped"``,
    ``"warned"``, ``"noop"``:
      * ``"noop"``    — no required headers to apply, or every header was
                        already present (idempotent — an identity may have
                        injected the same header on an injectable tool).
      * ``"self_attributed"`` — the tool applies the headers itself, off the
                        argv (``browser``, via the Playwright driver). Nothing
                        to inject here and nothing to warn about.
      * ``"skipped"`` — passive/archive/DNS/L3-L4 tool that does not send HTTP
                        to the in-scope target; nothing applied, no warning.
      * ``"injected"``— at least one header was appended, either as ``-H "Name:
                        Val"`` (curl-shaped tools) or via a non-``-H`` tool's own
                        flag (whatweb ``--header`` / nikto ``-Add-header`` / arjun
                        ``--headers``; see ``_REQUIRED_HEADER_FLAG_SPECS``).
      * ``"warned"``  — an HTTP-capable tool whose flag can't carry an inline
                        header (wafw00f) or an unknown tool; cmd is left untouched
                        and the caller warns without blocking execution.

    Idempotency: a header is skipped when an existing ``-H`` value already names
    it (case-insensitive on the header name, tolerating ``Name:`` and
    ``Name :``), so an identity-injected header is never duplicated.

    Shell-wrapper best-effort (W5): when ``cmd`` is a ``sh -c``/``bash -c``
    wrapper, the header is injected into the recognized curl/wget sub-commands
    inside the SCRIPT TEXT (a plain argv append would never reach the inner
    tool). If no -H-capable sub-command is present or the script can't be lexed,
    we fall back to classifying by ``tool_name`` (silent ``skipped`` for a
    passive wrapper, else ``warned``) and NEVER append ``-H`` to the shell argv.
    """
    if not headers:
        return "noop"

    script_idx = _wrapped_shell_script_index(cmd)
    if script_idx is not None:
        status, new_script = _inject_headers_into_script(cmd[script_idx], headers)
        if status == "injected":
            cmd[script_idx] = new_script
            return "injected"
        if status == "noop":
            return "noop"
        # No -H-capable sub-command was edited (none present, or unsafe to lex).
        # Classify by the derived tool name so a passive/archive wrapper stays
        # silent and any other wrapper WARNs — but never append -H to the shell
        # argv, where it would become a positional param and miss the tool.
        if tool_name.lower() in _REQUIRED_HEADER_SKIP:
            return "skipped"
        return "warned"

    name_lower = tool_name.lower()
    if name_lower in _REQUIRED_HEADER_SELF_ATTRIBUTING:
        return "self_attributed"
    if name_lower in _REQUIRED_HEADER_SKIP:
        return "skipped"
    if name_lower in _REQUIRED_HEADER_FLAG_SPECS:
        return _inject_tool_flag_headers(cmd, name_lower, headers)
    if name_lower not in _REQUIRED_HEADER_INJECTABLE:
        return "warned"

    existing = _existing_header_names(cmd)
    injected = False
    for name, value in headers.items():
        if name.lower() in existing:
            continue
        cmd.extend(["-H", f"{name}: {value}"])
        existing.add(name.lower())
        injected = True
    return "injected" if injected else "noop"


def _apply_identity_headers(
    cmd: list[str], tool_name: str, headers: dict[str, str]
) -> str:
    """Inject identity headers through the required-header transformer.

    Existing header names win. This preserves required-attribution precedence
    when credential material happens to carry the same header name.
    """
    if not headers:
        return "noop"
    script_idx = _wrapped_shell_script_index(cmd)
    if script_idx is not None:
        status, new_script = _inject_headers_into_script(cmd[script_idx], headers)
        if status in {"injected", "noop"}:
            cmd[script_idx] = new_script
            return status
        return "warned"
    tool = tool_name.lower()
    if tool in _REQUIRED_HEADER_FLAG_SPECS:
        return _inject_tool_flag_headers(cmd, tool, headers)
    if tool not in _REQUIRED_HEADER_INJECTABLE:
        return "warned"
    existing = _existing_header_names(cmd)
    injected = False
    for name, value in headers.items():
        if name.lower() in existing:
            continue
        cmd.extend(["-H", f"{name}: {value}"])
        existing.add(name.lower())
        injected = True
    return "injected" if injected else "noop"


# --------------------------------------------------------------------------- #
# Argv-shape diagnostics
# --------------------------------------------------------------------------- #
#
# Three read-only inspectors that let the caller say something TRUE about an
# argv instead of refusing it. They never mutate ``cmd``.


def shell_script_file_argv(cmd: list[str]) -> str:
    """The script path when ``cmd`` runs a shell SCRIPT FILE, else ``""``.

    ``bash /engagements/x/poc.sh`` is a shell invocation with no ``-c`` command
    string, so :func:`_wrapped_shell_script_index` finds nothing to inject into
    and the derived tool name is ``bash``, which accepts no header flag. That is
    an argv-SHAPE problem, not a credential problem, and the two need different
    remedies — appending ``-H`` here would land on the script as ``$1``/``$2``
    and never reach the requests inside it.
    """
    effective = scope_lib._unwrap_launcher_argv([str(token) for token in cmd])
    if not effective or _wrapped_shell_script_index(cmd) is not None:
        return ""
    head = effective[0]
    if head not in _SHELL_BINARIES and os.path.basename(head) not in _SHELL_BINARIES:
        return ""
    for token in effective[1:]:
        if not token.startswith("-"):
            return token
    return ""


def shell_script_body_gap(cmd: list[str]) -> str:
    """Why a ``sh -c`` / ``bash -c`` script BODY could take no injected header.

    ``""`` when ``cmd`` is not a ``-c`` invocation, or its body is injectable.
    Otherwise a reason-plus-remedy clause, because the two ways
    :func:`_inject_headers_into_script` declines need opposite fixes — and
    neither is the "re-shape it as ``bash -c``" advice
    :func:`shell_script_file_argv` earns, since the caller already IS a ``-c``
    invocation. Without this the refusal told an operator to do the thing they
    had just done, and pointed at ``--identity-target``, which is deliberately
    ignored for this shape: a dead end mid-engagement.
    """
    index = _wrapped_shell_script_index(cmd)
    if index is None:
        return ""
    script = cmd[index]
    try:
        shlex.split(script)
    except ValueError:
        return (
            "the `-c` script body could not be lexed (an unbalanced quote — most "
            "often an apostrophe inside a comment), so the injector cannot find "
            "its sub-command boundaries and refuses to edit a script it cannot "
            "parse. Balance or drop that quote and re-run"
        )
    if not list(_SHELL_SUBCMD_HEAD_RE.finditer(script)):
        return (
            "the `-c` script body contains no header-capable sub-command "
            "(curl/wget) for the injector to attach the header to. Express the "
            "authenticated requests as curl inside the `-c` body"
        )
    return ""


# Header names that carry target credentials. A run that writes one of these by
# hand is authenticating without telling the audit trail who it authenticated as.
_AUTH_HEADER_NAMES = ("Cookie", "Authorization")


def handwritten_auth_headers(cmd: list[str]) -> list[str]:
    """Credential-bearing header names ``cmd`` carries as literal operator text.

    Covers the argv (``-H 'Cookie: …'``, ``-HCookie:…``, ``--header=…``) and a
    ``sh -c`` / ``bash -c`` script body, by round-tripping through the same
    :func:`_segment_has_header` matcher the injector uses. Callers WARN on a hit
    with no ``--identity``: such a run is recorded as ``auth_context=anonymous``,
    which voids exactly the cross-identity evidence an IDOR/BOLA finding needs.
    """
    haystacks = [shlex.join(str(token) for token in cmd)]
    script_idx = _wrapped_shell_script_index(cmd)
    if script_idx is not None:
        script = cmd[script_idx]
        try:
            shlex.split(script)
        except ValueError:
            script = ""  # unlexable: do not guess, _segment_has_header says yes
        if script:
            haystacks.append(script)
    return [
        name
        for name in _AUTH_HEADER_NAMES
        if any(_segment_has_header(hay, name) for hay in haystacks)
    ]


# --------------------------------------------------------------------------- #
# Multi-arm curl last-wins detection
# --------------------------------------------------------------------------- #
#
# Verified against curl 8.7.1: in ONE invocation carrying several `-o file url`
# pairs, `-o` is per-URL and correct, but `-w` and `-D` are GLOBAL and last-wins
# — every arm's output is formatted with the LAST `-w`, all response headers land
# in the LAST `-D` file, and the earlier `-D` paths are never created. That is
# genuine curl semantics surfaced by verbatim passthrough, not a Vigil bug, so we
# WARN and never block: an agent reading a per-arm status off its own label gets
# a wrong answer today with no signal at all.

_URL_ARM_RE = re.compile(r"^https?://", re.IGNORECASE)

# curl flags whose VALUE is a URL but which do not open another transfer arm.
_CURL_NON_ARM_URL_FLAGS = frozenset(
    {"-x", "--proxy", "--preproxy", "--proxy1.0", "-e", "--referer"}
)

# The global, last-wins flags. `--next` / `-:` starts a fresh operation with its
# own copy of them, which is exactly the fix we point the caller at.
_CURL_LASTWINS_FLAGS: dict[str, str] = {
    "-w": "-w",
    "--write-out": "-w",
    "-D": "-D",
    "--dump-header": "-D",
}
_CURL_NEXT_FLAGS = frozenset({"--next", "-:"})


def _curl_invocations(cmd: list[str]) -> list[list[str]]:
    """Every curl argv reachable in ``cmd`` — bare, launcher-wrapped, or inside a
    ``sh -c`` script body."""
    script_idx = _wrapped_shell_script_index(cmd)
    if script_idx is not None:
        script = cmd[script_idx]
        found: list[list[str]] = []
        for match in _SHELL_SUBCMD_HEAD_RE.finditer(script):
            if match.group("cmd").lower() != "curl":
                continue
            segment = script[match.start("cmd") : _shell_segment_end(script, match.end("cmd"))]
            try:
                found.append(shlex.split(segment))
            except ValueError:
                continue
        return found
    effective = scope_lib._unwrap_launcher_argv([str(token) for token in cmd])
    if effective and os.path.basename(effective[0]).lower() == "curl":
        return [effective]
    return []


def _curl_lastwins_offenders(tokens: list[str]) -> tuple[int, list[str]]:
    """``(url_arm_count, offending_flags)`` for ONE curl argv.

    ``offending_flags`` is empty when the invocation is single-arm, uses no
    global last-wins flag, or already separates its arms with ``--next``/``-:``.
    """
    arms = 0
    offenders: list[str] = []
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token in _CURL_NEXT_FLAGS:
            return 0, []
        if token in _CURL_NON_ARM_URL_FLAGS:
            skip_next = True
            continue
        head = token.split("=", 1)[0]
        canonical = _CURL_LASTWINS_FLAGS.get(head)
        if canonical is None and len(token) > 2 and not token.startswith("--"):
            # curl accepts a short option with its value glued on (`-w%{...}`).
            canonical = _CURL_LASTWINS_FLAGS.get(token[:2])
        if canonical is not None:
            if canonical not in offenders:
                offenders.append(canonical)
            continue
        if _URL_ARM_RE.match(token):
            arms += 1
    return (arms, offenders if arms > 1 else [])


# What last-wins actually costs, per flag — so the warning states the concrete
# wrong outcome rather than a generic "this may be inaccurate".
_CURL_LASTWINS_EFFECT = {
    "-w": "every arm's output is formatted with the LAST -w",
    "-D": (
        "all response headers land in the LAST -D file and the earlier -D paths "
        "are never created"
    ),
}


def curl_multi_arm_warning(cmd: list[str]) -> str:
    """One WARN line when a single curl call fans out to several URLs while using
    a global last-wins flag, or ``""`` when nothing is wrong."""
    for tokens in _curl_invocations(cmd):
        arms, offenders = _curl_lastwins_offenders(tokens)
        if not offenders:
            continue
        return (
            f"warning: this curl call has {arms} URL arms, but "
            f"{' and '.join(offenders)} {'are' if len(offenders) > 1 else 'is'} "
            "GLOBAL and last-wins in curl — only -o is per-URL. So "
            + ", and ".join(_CURL_LASTWINS_EFFECT[flag] for flag in offenders)
            + ": a per-arm result read off its own label is WRONG. Separate the "
            "arms with `--next` (each arm then gets its own -w/-D), or fan out "
            "with `vigil assess kali sweep`."
        )
    return ""


def _auth_context(engagement_dir: Path) -> str:
    # Audit label for KaliResult — the active identity's mode from the
    # centralized credential store ("none" when no credentials / unreachable).
    from .creds_client import active_material

    material = active_material(str(engagement_dir))
    if not material:
        return "none"
    kind = material.get("mode") or "none"
    return str(kind) or "none"


def _peak_rss_kilobytes_to_bytes(peak_kb: int) -> int:
    # Linux exposes ru_maxrss in KB; macOS exposes it in bytes. Convert only
    # on Linux (the engagement runtime); on macOS the value is already bytes.
    if sys.platform == "linux":
        return peak_kb * 1024
    return peak_kb


def _read_proc_peak_rss(pid: int) -> Optional[int]:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("VmHWM:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _read_safely(path: Path, *, max_bytes: int = 32_768) -> str:
    """Return a preview of ``path`` capped at ``max_bytes``.

    For files smaller than ``max_bytes`` the full content is returned. For
    larger files we read ``head_budget`` bytes from the start and seek to the
    actual end-of-file for the tail — the previous implementation read
    ``max_bytes + 1`` bytes from the START and called the second half "tail",
    which silently lied about file content past the 32K mark (ISSUE-007).
    """
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size == 0:
        return ""
    head_budget = max_bytes // 2
    tail_budget = max_bytes - head_budget
    try:
        with path.open("rb") as fh:
            if size <= max_bytes:
                return fh.read().decode("utf-8", errors="replace")
            head = fh.read(head_budget)
            fh.seek(-tail_budget, os.SEEK_END)
            tail = fh.read(tail_budget)
    except OSError:
        return ""
    elided = size - len(head) - len(tail)
    return (
        f"{head.decode('utf-8', errors='replace')}\n"
        f"...\n[truncated {elided} bytes from middle of {size}-byte file]\n...\n"
        f"{tail.decode('utf-8', errors='replace')}"
    )
