"""Canonical deterministic classifier for credential liveness probes."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


def probe_scope_key(url: str | None, explicit_scope: str = "") -> str:
    """Return the explicit logical scope or a stable HTTP origin for ``url``.

    Liveness observations must never default to the legacy global scope merely
    because the caller omitted ``--scope``.  The origin is the narrowest safe
    automatic boundary: markers from one application host cannot globally kill
    an identity that is still valid on another host.
    """
    explicit = str(explicit_scope or "").strip()
    if explicit:
        return explicit
    parsed = urlparse(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    host = parsed.hostname.rstrip(".").lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    port_suffix = "" if port is None or default_port else f":{port}"
    return f"{parsed.scheme}://{host}{port_suffix}"


# A response that is ITSELF an authentication challenge is the only status-based
# proof that a session died. 401/407 say "you are not authenticated" verbatim;
# a 3xx whose Location points at a login surface is the classic session-expiry
# bounce. 403 is deliberately NOT here: it is an AUTHORIZATION verdict, and a
# 403 on another principal's object is the normal, healthy IDOR/BOLA signal —
# treating it as death would kill the identity doing the testing.
_AUTH_CHALLENGE_STATUSES = frozenset({401, 407})
# Deliberately no bare "auth": it also matches ``/authors``, ``/authority`` and
# similar ordinary redirects, and a false hit here is a killed live session.
# Every token below only appears on an actual authentication surface.
_LOGIN_LOCATION_TOKENS = (
    "login",
    "log-in",
    "signin",
    "sign-in",
    "sign_in",
    "logon",
    "oauth",
    "openid",
    "authorize",
    "authenticate",
    "sso",
    "saml",
    "adfs",
    "session/new",
    "my.policy",
)
_LOCATION_RE = re.compile(r"^location:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)


def _auth_challenge_reason(status: int, hay: str) -> str:
    """Return why ``status`` is itself an authentication challenge, else ``""``."""
    if status in _AUTH_CHALLENGE_STATUSES:
        return f"status {status} is an authentication challenge"
    if 300 <= status < 400:
        match = _LOCATION_RE.search(hay)
        location = match.group(1).strip() if match else ""
        lowered = location.lower()
        if location and any(token in lowered for token in _LOGIN_LOCATION_TOKENS):
            return f"status {status} redirects to a login location ({location!r})"
    return ""


def classify_liveness(
    status: int | None,
    haystack: str | None,
    liveness: dict[str, Any] | None,
) -> tuple[str, str]:
    """Classify one probe response as ``live`` / ``dead`` / ``unknown``.

    ``dead`` requires POSITIVE evidence of death — an operator-configured
    ``dead_marker`` in the response, or a response that is itself an
    authentication challenge. Everything else that merely fails to CONFIRM life
    (a missing ``authed_marker``, an unexplained status mismatch) is ``unknown``,
    because the far more common cause is that the probe URL is not an authed
    page for this identity's signature — and ``dead`` is a state that hides the
    identity from listings and refuses replay, costing a re-import to undo.

    ``liveness`` is ONE flat signature (``{expect_status, authed_marker,
    dead_marker}``) for the whole identity, and the rule is deliberately
    origin-agnostic: per-host modelling lives in the layers that already own it
    — :func:`probe_scope_key` scopes the recorded OBSERVATION, and an identity
    that genuinely differs per host is a separate identity selected by
    ``--identity-scope``. Any other shape carries none of the three keys and so
    resolves to "no signature configured" (``unknown``), never to a verdict
    produced by some other host's rule.
    """
    if status is None:
        return "unknown", "no response captured (transport error)"
    cfg = liveness if isinstance(liveness, dict) else {}
    raw_expect = cfg.get("expect_status")
    expect_status = raw_expect if isinstance(raw_expect, int) and not isinstance(raw_expect, bool) else None
    raw_authed = cfg.get("authed_marker")
    authed_marker = raw_authed if isinstance(raw_authed, str) and raw_authed else None
    raw_dead = cfg.get("dead_marker")
    dead_marker = raw_dead if isinstance(raw_dead, str) and raw_dead else None
    if expect_status is None and authed_marker is None and dead_marker is None:
        return (
            "unknown",
            "no liveness signature configured; set "
            "material.liveness = {expect_status, authed_marker, dead_marker}",
        )
    hay = haystack or ""
    if dead_marker is not None and dead_marker in hay:
        return "dead", f"dead_marker {dead_marker!r} present"
    # An authentication challenge is positive evidence of death on its own — it
    # does not need a configured ``expect_status`` to mean something. The guard
    # is the one exception: when the operator's own signature declares this
    # status as the expected authed response, they have said it is NOT a
    # challenge for this target, and their signature wins.
    if status != expect_status:
        challenge = _auth_challenge_reason(status, hay)
        if challenge:
            return "dead", challenge
    if expect_status is not None and status != expect_status:
        return (
            "unknown",
            f"status {status} != expect {expect_status} and the response is not an "
            "authentication challenge — the probe URL may not be an authed page "
            "for this identity's signature",
        )
    if authed_marker is not None and authed_marker not in hay:
        return (
            "unknown",
            f"authed_marker {authed_marker!r} absent with nothing contradicting the "
            "session — the probe URL may not be an authed page for this identity's "
            "signature",
        )
    confirmations: list[str] = []
    if authed_marker is not None:
        confirmations.append("authed_marker present")
    if dead_marker is not None:
        confirmations.append("dead_marker absent")
    if expect_status is not None:
        confirmations.append(f"status {status}")
    return "live", ", ".join(confirmations)
