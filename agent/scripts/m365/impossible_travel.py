#!/usr/bin/env python3
"""Impossible-travel detector for Microsoft Entra ID (Azure AD) sign-in logs.

Realizes step 3 ("Impossible-travel correlation") of the
``m365-signin-investigation`` skill. Given a set of Entra sign-in events, it
groups them by user, orders each user's events by ``createdDateTime``, and
flags every consecutive *geo-located* pair whose required great-circle
velocity exceeds a feasible-travel ceiling (default 800 km/h — the
commercial-flight band; subsonic civil aviation tops out near ~900 km/h).
A pair faster than a plane can fly means at least one of the two sign-ins
was not physically the claimed user.

Deterministic and stdlib-only (no third-party dependencies) so it runs
anywhere the operator wraps it with ``vigil assess host-exec --tool python3``.

Input — Microsoft Graph ``signIn`` JSON, in any of these shapes:
  * a bare JSON array of sign-in objects: ``[ {..}, {..} ]``
  * a Graph list response wrapper: ``{ "value": [ {..}, {..} ], ... }``
  * JSON Lines (one sign-in object per line)
  * a single sign-in object
Read from a file path argument or, if omitted, from stdin.

The field paths below are the real Graph v1.0 ``signIn`` schema
(https://learn.microsoft.com/en-us/graph/api/resources/signin):

  user   : ``userPrincipalName``  (always lowercase; falls back to ``userId``)
  time   : ``createdDateTime``     (ISO-8601, UTC, e.g. ``2023-12-01T16:03:35Z``)
  ip     : ``ipAddress``
  geo    : ``location.geoCoordinates.latitude`` / ``.longitude``  (Double)
  place  : ``location.city`` / ``location.countryOrRegion``  (2-letter code)

Edge cases handled:
  * missing / null ``geoCoordinates``  -> event dropped from the velocity
    chain (cannot place it), the surrounding geo-located events still pair
  * identical coordinates              -> 0 km, 0 km/h (never flagged)
  * zero / negative time delta         -> skipped (no division by zero; a
    same-instant or out-of-clock pair has no measurable velocity)
  * out-of-order timestamps            -> sorted per user before pairing

Output:
  * default            : a human-readable table of flagged pairs
  * ``--json``         : one JSON object per flagged pair (JSON Lines),
                         suitable for redirect into the skill's
                         ``impossible_travel_<slug>.jsonl`` evidence file

Each flagged pair carries: ``user``, ``from`` / ``to`` (both ISO times),
``from_ip`` / ``to_ip``, ``from_city`` / ``to_city``,
``from_country`` / ``to_country``, ``km`` (great-circle distance),
``hours`` (time delta), and ``kmh`` (required velocity).

Velocity is *necessary but not sufficient* for an adversarial verdict — the
skill requires an ASN / VPN-exit / CDN-PoP disambiguation pass (Common-FP
in step 3) before calling impossible-travel a compromise.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone

# Default feasible-travel ceiling, in km/h. 800 km/h sits in the
# commercial-flight band (subsonic civil aviation maxes out near ~900 km/h);
# anything faster is physical impossibility and the impossible-travel signal.
DEFAULT_THRESHOLD_KMH = 800.0

# Mean Earth radius (IUGG), in km, for the haversine great-circle formula.
_EARTH_RADIUS_KM = 6371.0088

# Clamp ISO-8601 fractional seconds to 6 digits: Graph emits up to 7
# (e.g. ``...:00.0000000Z``) but datetime only supports microsecond (6-digit)
# precision. Keep the first 6 fractional digits, drop the rest.
_FRACTIONAL_RE = re.compile(r"(\.\d{6})\d+")


# ---------------------------------------------------------------------------
# Geometry + time
# ---------------------------------------------------------------------------

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two WGS84 points, in kilometers."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    )
    # clamp against float error so asin's domain is never exceeded
    a = min(1.0, max(0.0, a))
    return 2.0 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def parse_iso(value) -> datetime:
    """Parse a Graph ``createdDateTime`` into a timezone-aware datetime (UTC).

    Handles the trailing ``Z``, explicit offsets, Graph's 7-digit fractional
    seconds, and naive timestamps (assumed UTC per the skill's UTC discipline).
    """
    s = str(value).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _FRACTIONAL_RE.sub(r"\1", s)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Field extraction (real Graph signIn paths)
# ---------------------------------------------------------------------------

def _user_key(event: dict) -> str:
    """User identifier: userPrincipalName, else userId, else '<unknown>'."""
    upn = event.get("userPrincipalName")
    if isinstance(upn, str) and upn.strip():
        return upn
    uid = event.get("userId")
    if isinstance(uid, str) and uid.strip():
        return uid
    return "<unknown>"


def _location(event: dict) -> dict:
    loc = event.get("location")
    return loc if isinstance(loc, dict) else {}


def extract_geo(event: dict):
    """Return ``(latitude, longitude)`` floats, or ``None`` if unavailable.

    Tolerates a missing ``location``, a null ``geoCoordinates``, and
    null / non-numeric latitude or longitude.
    """
    gc = _location(event).get("geoCoordinates")
    if not isinstance(gc, dict):
        return None
    lat = gc.get("latitude")
    lon = gc.get("longitude")
    if lat is None or lon is None:
        return None
    try:
        return float(lat), float(lon)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Input loading (shape variants)
# ---------------------------------------------------------------------------

def _coerce_to_events(data) -> list[dict]:
    """Normalize a parsed JSON document into a list of sign-in dicts."""
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        # Graph list response wrapper: {"@odata.context": ..., "value": [...]}
        value = data.get("value")
        if isinstance(value, list):
            return [e for e in value if isinstance(e, dict)]
        return [data]  # a single sign-in object
    return []


def load_events(text: str) -> list[dict]:
    """Parse Entra sign-in JSON (array / Graph wrapper / JSONL / single).

    Raises ``ValueError`` if the input opens with ``[`` (committing to a JSON
    array) but is not valid JSON — surfacing a truncated / malformed export
    rather than silently degrading to a partial JSON Lines parse that would
    drop sign-in events and skew the velocity chain.
    """
    text = (text or "").strip()
    if not text:
        return []

    # A leading '[' means the caller handed us one JSON array document; parse
    # it as such and raise on failure (do not fall back to JSONL).
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"input opens with '[' but is not a valid JSON array: {exc}"
            ) from exc
        return _coerce_to_events(data)

    # Otherwise try the whole document (Graph "{value: [...]}" wrapper or a
    # single sign-in object), then fall back to JSON Lines.
    try:
        return _coerce_to_events(json.loads(text))
    except json.JSONDecodeError:
        pass
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.extend(_coerce_to_events(json.loads(line)))
        except json.JSONDecodeError:
            continue  # skip an unparseable line rather than abort the pull
    return events


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _pair_record(user, prev, cur, d_km, dt_h, kmh) -> dict:
    p_loc, c_loc = _location(prev), _location(cur)
    return {
        "user": user,
        "from": prev.get("createdDateTime"),
        "to": cur.get("createdDateTime"),
        "from_ip": prev.get("ipAddress"),
        "to_ip": cur.get("ipAddress"),
        "from_city": p_loc.get("city"),
        "to_city": c_loc.get("city"),
        "from_country": p_loc.get("countryOrRegion"),
        "to_country": c_loc.get("countryOrRegion"),
        "km": round(d_km, 1),
        "hours": round(dt_h, 3),
        "kmh": round(kmh, 0),
    }


def detect_impossible_travel(
    events, threshold_kmh: float = DEFAULT_THRESHOLD_KMH
) -> list[dict]:
    """Flag consecutive geo-located sign-in pairs faster than ``threshold_kmh``.

    Events are grouped by user, restricted to those with both a parseable
    ``createdDateTime`` and resolvable geo-coordinates, sorted chronologically,
    and walked pairwise. A pair is flagged when ``distance_km / hours`` exceeds
    the threshold. Pairs with a non-positive time delta are skipped (guards
    against division by zero and unmeasurable same-instant pairs).
    """
    by_user: dict[str, list] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        geo = extract_geo(event)
        if geo is None:
            continue  # cannot place this sign-in — drop from the velocity chain
        ts = event.get("createdDateTime")
        if not ts:
            continue
        try:
            when = parse_iso(ts)
        except (ValueError, TypeError):
            continue  # unparseable timestamp — cannot order it
        by_user.setdefault(_user_key(event), []).append((when, geo, event))

    flagged: list[dict] = []
    for user, records in by_user.items():
        records.sort(key=lambda r: r[0])  # chronological; fixes out-of-order input
        for (p_when, p_geo, p_ev), (c_when, c_geo, c_ev) in zip(records, records[1:]):
            dt_h = (c_when - p_when).total_seconds() / 3600.0
            if dt_h <= 0:
                continue  # zero / negative delta — no measurable velocity
            d_km = haversine_km(p_geo[0], p_geo[1], c_geo[0], c_geo[1])
            kmh = d_km / dt_h
            if kmh > threshold_kmh:
                flagged.append(_pair_record(user, p_ev, c_ev, d_km, dt_h, kmh))
    return flagged


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _fmt_place(city, country) -> str:
    city = city or "?"
    country = country or "?"
    return f"{city}, {country}"


def _render_table(flagged: list[dict], threshold_kmh: float) -> str:
    users = len({f["user"] for f in flagged})
    lines = [
        f"impossible-travel: {len(flagged)} flagged pair(s) across {users} "
        f"user(s) (threshold {threshold_kmh:g} km/h)",
        "",
    ]
    for i, f in enumerate(flagged, 1):
        route = f"{_fmt_place(f['from_city'], f['from_country'])} -> " \
                f"{_fmt_place(f['to_city'], f['to_country'])}"
        lines.append(f"  #{i}  {f['user']}")
        lines.append(
            f"      {f['from']} -> {f['to']}  "
            f"({f['km']} km in {f['hours']} h = {f['kmh']:g} km/h)"
        )
        lines.append(f"      {route}")
        lines.append(f"      from_ip={f['from_ip']}  to_ip={f['to_ip']}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_input(path) -> str:
    if path:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return sys.stdin.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="impossible_travel.py",
        description=(
            "Flag impossible-travel sign-in pairs in Microsoft Entra ID / "
            "Azure AD sign-in logs (stdlib-only, deterministic, no network)."
        ),
    )
    parser.add_argument(
        "signins_file",
        nargs="?",
        default=None,
        help=(
            "Path to Entra sign-in JSON (array, Graph {\"value\": [...]} "
            "wrapper, or JSONL). Reads from stdin if omitted."
        ),
    )
    parser.add_argument(
        "--threshold-kmh",
        type=float,
        default=DEFAULT_THRESHOLD_KMH,
        help=(
            "Feasible-travel ceiling in km/h; pairs faster than this are "
            f"flagged (default: {DEFAULT_THRESHOLD_KMH:g})."
        ),
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        default=False,
        help="Emit one JSON object per flagged pair (JSON Lines).",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.threshold_kmh <= 0:
        print("impossible_travel: --threshold-kmh must be > 0", file=sys.stderr)
        return 2

    try:
        raw = _read_input(args.signins_file)
    except OSError as exc:
        print(f"impossible_travel: cannot read input: {exc}", file=sys.stderr)
        return 1

    try:
        events = load_events(raw)
    except ValueError as exc:
        print(f"impossible_travel: {exc}", file=sys.stderr)
        return 1

    # A non-empty payload that begins like a JSON object but yields zero events
    # is a parse failure (e.g. a truncated wrapper), not an empty result set.
    if raw.strip().startswith("{") and not events:
        print(
            "impossible_travel: input looked like a JSON object but no sign-in "
            "events could be parsed (malformed or truncated document)",
            file=sys.stderr,
        )
        return 1

    flagged = detect_impossible_travel(events, threshold_kmh=args.threshold_kmh)

    if args.as_json:
        for pair in flagged:
            sys.stdout.write(json.dumps(pair, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return 0

    if not flagged:
        print(
            f"impossible-travel: 0 flagged pair(s) "
            f"(threshold {args.threshold_kmh:g} km/h, "
            f"{len(events)} sign-in event(s) examined).",
            file=sys.stderr,
        )
        return 0

    sys.stdout.write(_render_table(flagged, args.threshold_kmh))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
