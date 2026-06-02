"""Single source of truth for turning one host probe into a reachability verdict.

Both the egress self-test (`vigil assess egress-check`) and httpx ingestion
(`vigil assess ingest-httpx`) classify probes identically by importing
``classify_probe`` here, so the two cannot drift.

The verdict logic encodes the hard-won §9 engagement lesson: a bare
``connect=000`` / ``http_code=000`` is NOT a reliable "blocked" signal. It can be

  * a CONNECT-proxy field artifact (``http_connect`` is 0 for direct HTTPS) where
    the TCP/TLS path actually completed,
  * a TLS-1.3 appliance that resets the handshake (recoverable with
    ``--tls-max 1.2``), or
  * a genuine reputation/perimeter blackhole.

So a single probe never declares "blackholed" on an HTTP code alone — it requires
no TCP connect AND no resolved remote IP. The *cluster-level* "blackholed across
retries while a known-good control still connects" decision stays in the caller
(egress-check); this module only classifies one probe at a time.
"""
from __future__ import annotations

# Verdicts -------------------------------------------------------------------
LIVE = "live"                                   # TCP/TLS completed (any HTTP code, incl. 401/403/302 walls)
TLS13_RESET = "tls13_reset_recover_with_12"     # connect failed at TLS layer; retry with --tls-max 1.2
BLACKHOLED = "blackholed"                        # no TCP connect, no remote IP — candidate blackhole
UNKNOWN = "unknown"                              # not enough signal to decide

# curl -w format that yields the three fields classify_probe consumes. Both
# consumers build their probe with this so parsing stays in lock-step.
CURL_WRITE_FORMAT = "%{http_code} %{time_connect} %{remote_ip}\n"

# curl exit codes that mean the connection cleanly failed (no service reachable).
_CONN_FAIL_EXITS = frozenset({7, 28})           # 7 couldn't-connect, 28 timeout
# curl exit codes that mean a TLS-layer failure after TCP (often a TLS-1.3 reset).
_TLS_RESET_EXITS = frozenset({35})              # CURLE_SSL_CONNECT_ERROR
_SENTINEL_IPS = frozenset({"", "0.0.0.0", "::", "[::]", "0000:0000:0000:0000:0000:0000:0000:0000"})


def _to_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _has_ip(remote_ip) -> bool:
    return bool((remote_ip or "").strip()) and (remote_ip or "").strip() not in _SENTINEL_IPS


def _answered(http_code) -> bool:
    """True when http_code is a real, non-zero HTTP status."""
    if http_code in (None, ""):
        return False
    try:
        return int(str(http_code).strip()) > 0
    except (TypeError, ValueError):
        return False


def _is_explicit_zero_code(http_code) -> bool:
    """True only for an explicit zero status (curl's ``000`` / httpx ``0``).

    An absent code (``None``/``""``) is NOT a zero — it just means the field was
    not supplied, which must stay UNKNOWN rather than collapsing to a blackhole.
    """
    if http_code in (None, ""):
        return False
    try:
        return int(str(http_code).strip()) == 0
    except (TypeError, ValueError):
        return False


def _tls_reset_signature(curl_exit, stderr: str) -> bool:
    if curl_exit in _TLS_RESET_EXITS:
        return True
    s = (stderr or "").lower()
    if "ssl_connect" in s or "sslv3 alert" in s or "tlsv1 alert" in s:
        return True
    # "reset by peer" only counts as a TLS reset when it happened during the
    # TLS/SSL handshake — a bare connection reset with no TLS context is a
    # plain connection failure, not a downgrade-recoverable reset.
    return "reset by peer" in s and ("tls" in s or "ssl" in s)


def classify_probe(
    *,
    http_code=None,
    time_connect=None,
    remote_ip=None,
    curl_exit=None,
    stderr: str = "",
    failed=None,
) -> str:
    """Classify a single host probe.

    Accepts the union of fields available from a ``curl -w`` probe
    (``http_code``/``time_connect``/``remote_ip``/``curl_exit``/``stderr``) and
    from httpx ``-json`` output (``http_code``=status_code, ``remote_ip``=host_ip,
    ``failed``=bool). Pass whatever you have; missing signals are treated as absent.

    Returns one of :data:`LIVE`, :data:`TLS13_RESET`, :data:`BLACKHOLED`,
    :data:`UNKNOWN`.
    """
    tc = _to_float(time_connect)
    connected = tc > 0.0 or _has_ip(remote_ip)

    # Positive reachability — but an explicit ``failed=True`` always wins: httpx
    # resolves DNS *before* the connect attempt, so a failed record routinely
    # still carries a resolved IP. A present IP / non-zero connect time / HTTP
    # answer (even a 401/403/302 wall) means LIVE ONLY when the probe was not
    # explicitly marked failed. httpx ``failed=False`` is an explicit success.
    # (The §9 CONNECT-proxy-artifact case — IP present, no ``failed`` flag — is
    # still LIVE because ``failed`` is None there, not True.)
    if failed is False or (failed is not True and (connected or _answered(http_code))):
        return LIVE

    # The connection did not complete past here.
    if _tls_reset_signature(curl_exit, stderr):
        return TLS13_RESET

    if curl_exit is not None:
        # An explicit curl exit code decides it: only connect-refused/timeout is
        # an egress blackhole. Other errors (6 = DNS resolve failure, etc.) are
        # NOT blackholes and must not be counted toward a cluster verdict.
        return BLACKHOLED if curl_exit in _CONN_FAIL_EXITS else UNKNOWN

    # No curl exit available (e.g. the httpx-json path): a clean failure is an
    # explicit ``failed=true`` or an explicit zero status code.
    if failed is True or _is_explicit_zero_code(http_code):
        return BLACKHOLED

    return UNKNOWN


def parse_curl_w(line: str) -> dict:
    """Parse one line emitted by a probe using :data:`CURL_WRITE_FORMAT`.

    Returns ``{"http_code": str, "time_connect": float, "remote_ip": str}``.
    Tolerant of extra whitespace and a missing remote_ip field.
    """
    parts = (line or "").split()
    http_code = parts[0] if len(parts) >= 1 else ""
    time_connect = _to_float(parts[1]) if len(parts) >= 2 else 0.0
    remote_ip = parts[2] if len(parts) >= 3 else ""
    return {"http_code": http_code, "time_connect": time_connect, "remote_ip": remote_ip}
