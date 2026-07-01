"""Deterministic unit tests for agent/scripts/m365/impossible_travel.py.

The script realizes step 3 ("Impossible-travel correlation") of the
``m365-signin-investigation`` skill: it reads Microsoft Entra ID / Azure AD
sign-in log JSON (Microsoft Graph ``signIn`` shape), groups events by user,
sorts by ``createdDateTime``, and flags consecutive geo-located pairs whose
required great-circle velocity exceeds a feasible-travel ceiling.

All tests are pure-function / deterministic — no network, no LLM, no DB. The
sign-in fixtures mirror the real Graph schema confirmed at
https://learn.microsoft.com/en-us/graph/api/resources/signin (v1.0):
``userPrincipalName``, ``userId``, ``createdDateTime``, ``ipAddress``, and
``location.geoCoordinates.{latitude,longitude}`` / ``location.city`` /
``location.countryOrRegion``.

Coverage:
  (a) haversine geometry (known long-haul distance; identical points = 0)
  (b) ISO-8601 timestamp parsing (Z suffix, 7-digit fractional, offset, naive)
  (c) event loading shape variants (bare list / Graph {"value": [...]} / JSONL)
  (d) clearly-impossible pair (New York -> Tokyo within 1h)  -> flagged
  (e) feasible pair (same metro, hours apart)                -> not flagged
  (f) missing-geo events                                     -> skipped, no crash
  (g) --threshold-kmh changes the verdict
  (h) zero-time-delta guard (no ZeroDivisionError, not flagged)
  (i) out-of-order timestamps are sorted before pairing
  (j) grouping by user (no cross-user pairing)
  (k) CLI: file/stdin input, table + --json (JSONL) output, exit codes
"""
from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path



# ---------------------------------------------------------------------------
# Module loader (same sys.path.insert + importlib pattern as
# test_anomaly_score.py / test_classify_payload.py)
# ---------------------------------------------------------------------------

def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_mod():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "m365_impossible_travel_ut",
        _scripts_root() / "m365" / "impossible_travel.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Geo fixtures (real coordinates; cities for human-readable output assertions)
# ---------------------------------------------------------------------------

NEW_YORK = (40.7128, -74.0060, "New York", "US")
TOKYO = (35.6762, 139.6503, "Tokyo", "JP")
CHICAGO = (41.8781, -87.6298, "Chicago", "US")
NYC_NEARBY = (40.7300, -73.9950, "New York", "US")  # ~2 km from NEW_YORK


def _signin(upn, when, place, *, ip="1.2.3.4", **extra) -> dict:
    """Build a Microsoft Graph signIn event in the real export shape."""
    lat, lon, city, country = place
    ev = {
        "id": f"signin-{upn}-{when}",
        "userPrincipalName": upn,
        "userId": f"uid-{upn}",
        "createdDateTime": when,
        "ipAddress": ip,
        "location": {
            "city": city,
            "state": "",
            "countryOrRegion": country,
            "geoCoordinates": {
                "altitude": None,
                "latitude": lat,
                "longitude": lon,
            },
        },
    }
    ev.update(extra)
    return ev


# ===========================================================================
# (a) Haversine geometry
# ===========================================================================

class TestHaversine:
    def setup_method(self):
        self.mod = _load_mod()

    def test_new_york_to_tokyo_known_distance(self):
        # Great-circle NY -> Tokyo is ~10,800-10,900 km.
        d = self.mod.haversine_km(NEW_YORK[0], NEW_YORK[1], TOKYO[0], TOKYO[1])
        assert 10_000 < d < 11_500, f"NY->Tokyo distance off: {d}"

    def test_identical_points_is_zero(self):
        d = self.mod.haversine_km(40.0, -74.0, 40.0, -74.0)
        assert d == 0.0

    def test_symmetric(self):
        a = self.mod.haversine_km(NEW_YORK[0], NEW_YORK[1], CHICAGO[0], CHICAGO[1])
        b = self.mod.haversine_km(CHICAGO[0], CHICAGO[1], NEW_YORK[0], NEW_YORK[1])
        assert abs(a - b) < 1e-6


# ===========================================================================
# (b) ISO-8601 timestamp parsing
# ===========================================================================

class TestParseIso:
    def setup_method(self):
        self.mod = _load_mod()

    def test_z_suffix(self):
        dt = self.mod.parse_iso("2023-12-01T16:03:35Z")
        assert dt.utcoffset().total_seconds() == 0

    def test_seven_digit_fractional_seconds(self):
        # Graph emits up to 7 fractional digits; stdlib fromisoformat only
        # accepts <=6 — the parser must clamp without raising.
        dt = self.mod.parse_iso("2025-12-03T00:23:00.0000000Z")
        assert dt.year == 2025 and dt.month == 12 and dt.day == 3

    def test_explicit_offset(self):
        dt = self.mod.parse_iso("2023-12-01T16:03:35+02:00")
        assert dt.utcoffset().total_seconds() == 7200

    def test_naive_assumed_utc(self):
        dt = self.mod.parse_iso("2023-12-01T16:03:35")
        assert dt.utcoffset().total_seconds() == 0

    def test_ordering_preserved(self):
        a = self.mod.parse_iso("2023-12-01T16:00:00Z")
        b = self.mod.parse_iso("2023-12-01T17:00:00Z")
        assert a < b


# ===========================================================================
# (c) Event loading — shape variants the export takes
# ===========================================================================

class TestLoadEvents:
    def setup_method(self):
        self.mod = _load_mod()

    def test_bare_list(self):
        evs = [_signin("a@x.com", "2023-12-01T16:00:00Z", NEW_YORK)]
        out = self.mod.load_events(json.dumps(evs))
        assert len(out) == 1 and out[0]["userPrincipalName"] == "a@x.com"

    def test_graph_value_wrapper(self):
        payload = {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x",
            "value": [
                _signin("a@x.com", "2023-12-01T16:00:00Z", NEW_YORK),
                _signin("a@x.com", "2023-12-01T17:00:00Z", TOKYO),
            ],
        }
        out = self.mod.load_events(json.dumps(payload))
        assert len(out) == 2

    def test_jsonl(self):
        evs = [
            _signin("a@x.com", "2023-12-01T16:00:00Z", NEW_YORK),
            _signin("a@x.com", "2023-12-01T17:00:00Z", TOKYO),
        ]
        text = "\n".join(json.dumps(e) for e in evs)
        out = self.mod.load_events(text)
        assert len(out) == 2

    def test_single_object(self):
        ev = _signin("a@x.com", "2023-12-01T16:00:00Z", NEW_YORK)
        out = self.mod.load_events(json.dumps(ev))
        assert len(out) == 1

    def test_empty_returns_empty(self):
        assert self.mod.load_events("") == []
        assert self.mod.load_events("   \n  ") == []


# ===========================================================================
# (d)/(e) Core detection — impossible vs feasible
# ===========================================================================

class TestDetectImpossibleTravel:
    def setup_method(self):
        self.mod = _load_mod()

    def test_new_york_to_tokyo_within_one_hour_is_flagged(self):
        events = [
            _signin("victim@acme.example", "2023-12-01T16:00:00Z", NEW_YORK, ip="1.1.1.1"),
            _signin("victim@acme.example", "2023-12-01T17:00:00Z", TOKYO, ip="2.2.2.2"),
        ]
        flags = self.mod.detect_impossible_travel(events)
        assert len(flags) == 1
        f = flags[0]
        assert f["user"] == "victim@acme.example"
        assert f["from"] == "2023-12-01T16:00:00Z"
        assert f["to"] == "2023-12-01T17:00:00Z"
        assert f["from_ip"] == "1.1.1.1" and f["to_ip"] == "2.2.2.2"
        assert f["from_city"] == "New York" and f["to_city"] == "Tokyo"
        assert f["from_country"] == "US" and f["to_country"] == "JP"
        assert f["hours"] == 1.0
        assert f["km"] > 9_000
        assert f["kmh"] > 800  # ~10,800 km/h

    def test_same_metro_hours_apart_not_flagged(self):
        events = [
            _signin("user@acme.example", "2023-12-01T09:00:00Z", NEW_YORK),
            _signin("user@acme.example", "2023-12-01T12:00:00Z", NYC_NEARBY),
        ]
        assert self.mod.detect_impossible_travel(events) == []

    def test_identical_location_not_flagged(self):
        events = [
            _signin("user@acme.example", "2023-12-01T09:00:00Z", NEW_YORK),
            _signin("user@acme.example", "2023-12-01T09:30:00Z", NEW_YORK),
        ]
        assert self.mod.detect_impossible_travel(events) == []


# ===========================================================================
# (f) Missing geo-coordinates are skipped, never crash
# ===========================================================================

class TestMissingGeo:
    def setup_method(self):
        self.mod = _load_mod()

    def _no_geo(self, upn, when, **extra):
        ev = {
            "userPrincipalName": upn,
            "createdDateTime": when,
            "ipAddress": "9.9.9.9",
            "location": {"city": "Unknown", "countryOrRegion": "", "geoCoordinates": None},
        }
        ev.update(extra)
        return ev

    def test_middle_no_geo_event_is_skipped_pair_still_flagged(self):
        # NY (geo) -> no-geo -> Tokyo (geo) within 1h: the no-geo event drops
        # out and NY->Tokyo remains the consecutive geo-located pair.
        events = [
            _signin("v@acme.example", "2023-12-01T16:00:00Z", NEW_YORK),
            self._no_geo("v@acme.example", "2023-12-01T16:30:00Z"),
            _signin("v@acme.example", "2023-12-01T17:00:00Z", TOKYO),
        ]
        flags = self.mod.detect_impossible_travel(events)
        assert len(flags) == 1
        assert flags[0]["from_city"] == "New York" and flags[0]["to_city"] == "Tokyo"

    def test_absent_location_key_does_not_crash(self):
        events = [
            {"userPrincipalName": "v@acme.example", "createdDateTime": "2023-12-01T16:00:00Z"},
            _signin("v@acme.example", "2023-12-01T17:00:00Z", TOKYO),
        ]
        assert self.mod.detect_impossible_travel(events) == []

    def test_only_one_geo_event_no_pair(self):
        events = [
            _signin("v@acme.example", "2023-12-01T16:00:00Z", NEW_YORK),
            self._no_geo("v@acme.example", "2023-12-01T16:30:00Z"),
        ]
        assert self.mod.detect_impossible_travel(events) == []


# ===========================================================================
# (g) --threshold-kmh changes the verdict
# ===========================================================================

class TestThreshold:
    def setup_method(self):
        self.mod = _load_mod()

    def _ny_chicago_2h(self):
        # NY -> Chicago (~1145 km) over 2h => ~572 km/h: above 500, below 800.
        return [
            _signin("user@acme.example", "2023-12-01T08:00:00Z", NEW_YORK),
            _signin("user@acme.example", "2023-12-01T10:00:00Z", CHICAGO),
        ]

    def test_velocity_is_between_500_and_800(self):
        flags = self.mod.detect_impossible_travel(self._ny_chicago_2h(), threshold_kmh=1.0)
        assert len(flags) == 1
        assert 500 < flags[0]["kmh"] < 800

    def test_default_threshold_does_not_flag(self):
        # Default ceiling is 800 km/h (commercial-flight band).
        assert self.mod.detect_impossible_travel(self._ny_chicago_2h()) == []
        assert self.mod.DEFAULT_THRESHOLD_KMH == 800.0

    def test_lower_threshold_flags(self):
        flags = self.mod.detect_impossible_travel(self._ny_chicago_2h(), threshold_kmh=500.0)
        assert len(flags) == 1


# ===========================================================================
# (h) Zero-time-delta guard
# ===========================================================================

class TestZeroTimeDelta:
    def setup_method(self):
        self.mod = _load_mod()

    def test_same_timestamp_distinct_geo_does_not_crash_or_flag(self):
        events = [
            _signin("v@acme.example", "2023-12-01T16:00:00Z", NEW_YORK),
            _signin("v@acme.example", "2023-12-01T16:00:00Z", TOKYO),
        ]
        # Must not raise ZeroDivisionError; the zero delta is unmeasurable.
        flags = self.mod.detect_impossible_travel(events)
        assert flags == []


# ===========================================================================
# (i) Out-of-order timestamps are sorted before pairing
# ===========================================================================

class TestOutOfOrder:
    def setup_method(self):
        self.mod = _load_mod()

    def test_reverse_chronological_input_still_flags_with_correct_direction(self):
        events = [
            _signin("v@acme.example", "2023-12-01T17:00:00Z", TOKYO, ip="2.2.2.2"),
            _signin("v@acme.example", "2023-12-01T16:00:00Z", NEW_YORK, ip="1.1.1.1"),
        ]
        flags = self.mod.detect_impossible_travel(events)
        assert len(flags) == 1
        # "from" must be the chronologically earlier event after sorting.
        assert flags[0]["from"] == "2023-12-01T16:00:00Z"
        assert flags[0]["from_city"] == "New York"
        assert flags[0]["to_city"] == "Tokyo"


# ===========================================================================
# (j) Grouping by user — no cross-user pairing
# ===========================================================================

class TestUserGrouping:
    def setup_method(self):
        self.mod = _load_mod()

    def test_two_users_one_event_each_not_paired(self):
        events = [
            _signin("alice@acme.example", "2023-12-01T16:00:00Z", NEW_YORK),
            _signin("bob@acme.example", "2023-12-01T16:30:00Z", TOKYO),
        ]
        assert self.mod.detect_impossible_travel(events) == []

    def test_interleaved_users_only_offending_user_flagged(self):
        events = [
            _signin("alice@acme.example", "2023-12-01T16:00:00Z", NEW_YORK),
            _signin("bob@acme.example", "2023-12-01T16:15:00Z", CHICAGO),
            _signin("alice@acme.example", "2023-12-01T17:00:00Z", TOKYO),
            _signin("bob@acme.example", "2023-12-01T19:15:00Z", NYC_NEARBY),
        ]
        flags = self.mod.detect_impossible_travel(events)
        assert len(flags) == 1
        assert flags[0]["user"] == "alice@acme.example"

    def test_user_falls_back_to_userId_when_no_upn(self):
        events = [
            {"userId": "guid-1", "createdDateTime": "2023-12-01T16:00:00Z",
             "ipAddress": "1.1.1.1", "location": {"city": "New York", "countryOrRegion": "US",
                "geoCoordinates": {"latitude": NEW_YORK[0], "longitude": NEW_YORK[1]}}},
            {"userId": "guid-1", "createdDateTime": "2023-12-01T17:00:00Z",
             "ipAddress": "2.2.2.2", "location": {"city": "Tokyo", "countryOrRegion": "JP",
                "geoCoordinates": {"latitude": TOKYO[0], "longitude": TOKYO[1]}}},
        ]
        flags = self.mod.detect_impossible_travel(events)
        assert len(flags) == 1
        assert flags[0]["user"] == "guid-1"


# ===========================================================================
# (k) CLI smoke — argparse main(), file/stdin input, table + JSON output
# ===========================================================================

class TestCLI:
    def setup_method(self):
        self.mod = _load_mod()

    def _impossible_events(self):
        return [
            _signin("victim@acme.example", "2023-12-01T16:00:00Z", NEW_YORK, ip="1.1.1.1"),
            _signin("victim@acme.example", "2023-12-01T17:00:00Z", TOKYO, ip="2.2.2.2"),
        ]

    def test_file_input_table(self, tmp_path, capsys):
        infile = tmp_path / "signins.json"
        infile.write_text(json.dumps(self._impossible_events()), encoding="utf-8")
        rc = self.mod.main([str(infile)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "victim@acme.example" in out
        assert "New York" in out and "Tokyo" in out

    def test_file_input_value_wrapper(self, tmp_path, capsys):
        infile = tmp_path / "signins.json"
        infile.write_text(json.dumps({"value": self._impossible_events()}), encoding="utf-8")
        rc = self.mod.main([str(infile)])
        out = capsys.readouterr().out
        assert rc == 0 and "victim@acme.example" in out

    def test_empty_graph_value_page_is_not_malformed(self, tmp_path, capsys):
        # F1: a well-formed {"value": []} (a user with zero sign-ins in the window)
        # is a legitimate empty result, not a malformed/truncated document.
        infile = tmp_path / "empty.json"
        infile.write_text(json.dumps({"value": []}), encoding="utf-8")
        rc = self.mod.main([str(infile)])
        captured = capsys.readouterr()
        assert rc == 0
        assert "malformed" not in captured.err.lower()

    def test_truncated_json_object_still_errors(self, tmp_path, capsys):
        # The fix must not weaken malformed detection: a truncated / invalid JSON
        # object is still a hard error.
        infile = tmp_path / "bad.json"
        infile.write_text('{"value"', encoding="utf-8")
        rc = self.mod.main([str(infile)])
        assert rc == 1

    def test_json_output_is_jsonl(self, tmp_path, capsys):
        infile = tmp_path / "signins.json"
        infile.write_text(json.dumps(self._impossible_events()), encoding="utf-8")
        rc = self.mod.main([str(infile), "--json"])
        raw = capsys.readouterr().out
        assert rc == 0
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        assert len(lines) == 1
        rec = json.loads(lines[0])  # each line is a standalone JSON object
        assert rec["user"] == "victim@acme.example"
        for key in ("from", "to", "from_ip", "to_ip", "from_city",
                    "to_city", "from_country", "to_country", "km", "hours", "kmh"):
            assert key in rec

    def test_stdin_input(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "sys.stdin", StringIO(json.dumps(self._impossible_events()))
        )
        rc = self.mod.main([])
        out = capsys.readouterr().out
        assert rc == 0 and "victim@acme.example" in out

    def test_threshold_flag_changes_verdict(self, tmp_path, capsys):
        # NY -> Chicago over 2h (~572 km/h): not flagged at default 800.
        events = [
            _signin("u@acme.example", "2023-12-01T08:00:00Z", NEW_YORK),
            _signin("u@acme.example", "2023-12-01T10:00:00Z", CHICAGO),
        ]
        infile = tmp_path / "s.json"
        infile.write_text(json.dumps(events), encoding="utf-8")

        rc_default = self.mod.main([str(infile), "--json"])
        default_out = capsys.readouterr().out.strip()
        assert rc_default == 0 and default_out == ""  # nothing flagged

        rc_low = self.mod.main([str(infile), "--json", "--threshold-kmh", "500"])
        low_out = capsys.readouterr().out.strip()
        assert rc_low == 0
        assert len([ln for ln in low_out.splitlines() if ln.strip()]) == 1

    def test_no_flags_table_prints_clean_message(self, tmp_path, capsys):
        events = [
            _signin("u@acme.example", "2023-12-01T09:00:00Z", NEW_YORK),
            _signin("u@acme.example", "2023-12-01T12:00:00Z", NYC_NEARBY),
        ]
        infile = tmp_path / "s.json"
        infile.write_text(json.dumps(events), encoding="utf-8")
        rc = self.mod.main([str(infile)])
        captured = capsys.readouterr()
        assert rc == 0
        combined = captured.out + captured.err
        assert "0" in combined and "impossible" in combined.lower()

    def test_missing_file_exits_nonzero(self, capsys):
        rc = self.mod.main(["/nonexistent/path/does/not/exist.json"])
        err = capsys.readouterr().err
        assert rc != 0
        assert err.strip()

    def test_malformed_json_exits_nonzero(self, tmp_path, capsys):
        infile = tmp_path / "bad.json"
        infile.write_text('[\n{"a":1},\n{"b":2}\n', encoding="utf-8")  # unterminated array
        rc = self.mod.main([str(infile)])
        err = capsys.readouterr().err
        assert rc != 0
        assert err.strip()
