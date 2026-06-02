"""Unit tests for assess.lib.anomaly (score_population) and the
assess.commands.anomaly_score CLI command.

All tests are pure-function / deterministic — no network, no LLM, no DB.

Test plan:
  (a) Clear outlier: 9 near-identical 200/4KB/html responses + 1 500/0-length
      → the outlier must rank #1.
  (b) Uniform population: all scores are (near-)zero / equal.
  (c) Weight degradation: a per-record unique nonce header must NOT dominate
      the ranking when a clear binary split (status 200 vs 500) also exists.
  (d) Tolerant of records missing fields.
  (e) CLI smoke for both file-input and stdin input.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Module loaders (same pattern as test_classify_payload.py)
# ---------------------------------------------------------------------------

def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_lib():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "anomaly_ut",
        _scripts_root() / "assess" / "lib" / "anomaly.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_cmd():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "anomaly_score_cmd_ut",
        _scripts_root() / "assess" / "commands" / "anomaly_score.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Fixtures: shared populations
# ---------------------------------------------------------------------------

def _normal_record(idx: int) -> dict:
    """A typical 200/4 KB/text-html response."""
    return {
        "url": f"https://example.com/page{idx}",
        "status": "200",
        "content_length": 4096,
        "content_type": "text/html; charset=utf-8",
        "title": "Example Page",
        "words": 300,
        "lines": 80,
        "headers": {
            "server": "nginx",
            "content-type": "text/html; charset=utf-8",
            "x-frame-options": "DENY",
        },
    }


def _outlier_record() -> dict:
    """A 500/0-byte response — clearly anomalous vs. the normal cluster."""
    return {
        "url": "https://example.com/broken",
        "status": "500",
        "content_length": 0,
        "content_type": "text/plain",
        "title": "Internal Server Error",
        "words": 0,
        "lines": 0,
        "headers": {
            "content-type": "text/plain",
        },
    }


def _build_population(n_normal: int = 9) -> list[dict]:
    """n_normal near-identical records + 1 clear outlier."""
    records = [_normal_record(i) for i in range(n_normal)]
    records.append(_outlier_record())
    return records


# ---------------------------------------------------------------------------
# (a) Clear outlier ranks #1
# ---------------------------------------------------------------------------

class TestClearOutlier:
    def setup_method(self):
        self.mod = _load_lib()

    def test_outlier_is_first(self):
        population = _build_population(9)
        ranked = self.mod.score_population(population)
        assert ranked, "Expected non-empty ranking"
        top = ranked[0]
        assert top["url"] == "https://example.com/broken", (
            f"Expected outlier URL at #1, got {top['url']}"
        )

    def test_outlier_has_highest_score(self):
        population = _build_population(9)
        ranked = self.mod.score_population(population)
        top_score = ranked[0]["anomaly_score"]
        assert top_score > 0.0, "Outlier must have a positive anomaly score"
        # All normal records must score lower
        for rec in ranked[1:]:
            assert rec["anomaly_score"] <= top_score

    def test_outlier_has_anomalous_attributes(self):
        population = _build_population(9)
        ranked = self.mod.score_population(population)
        attrs = ranked[0].get("anomalous_attributes", [])
        assert len(attrs) >= 1, "Outlier should report at least one anomalous attribute"
        # Status attribute must surface (500 appears once, 200 appears 9 times)
        assert any("status" in a for a in attrs), (
            f"Expected 'status' in anomalous attributes, got: {attrs}"
        )

    def test_all_records_returned(self):
        population = _build_population(9)
        ranked = self.mod.score_population(population)
        assert len(ranked) == 10

    def test_output_is_sorted_descending(self):
        population = _build_population(9)
        ranked = self.mod.score_population(population)
        scores = [r["anomaly_score"] for r in ranked]
        assert scores == sorted(scores, reverse=True), "Ranking must be descending by score"


# ---------------------------------------------------------------------------
# (b) Uniform population — all scores near-zero
# ---------------------------------------------------------------------------

class TestUniformPopulation:
    def setup_method(self):
        self.mod = _load_lib()

    def test_uniform_scores_are_zero(self):
        """When all records are identical, every score should be 0."""
        population = [_normal_record(0) for _ in range(8)]
        ranked = self.mod.score_population(population)
        for rec in ranked:
            assert rec["anomaly_score"] == 0.0, (
                f"Uniform record got non-zero score: {rec['anomaly_score']}"
            )

    def test_uniform_no_anomalous_attributes(self):
        population = [_normal_record(0) for _ in range(5)]
        ranked = self.mod.score_population(population)
        for rec in ranked:
            assert rec.get("anomalous_attributes") == [], (
                "Uniform records must have no anomalous attributes"
            )


# ---------------------------------------------------------------------------
# (c) Weight degradation — unique nonce must NOT dominate
# ---------------------------------------------------------------------------

class TestWeightDegradation:
    def setup_method(self):
        self.mod = _load_lib()

    def _build_nonce_population(self):
        """8 normal records with unique X-Nonce headers + 1 outlier (status 500).

        The nonce is unique per record (distinct_count == population_size) so its
        weight must degrade to the floor and must not prevent the 500-status record
        from ranking #1.
        """
        records = []
        for i in range(8):
            rec = _normal_record(i)
            rec["headers"] = dict(rec["headers"])
            rec["headers"]["x-nonce"] = f"unique-nonce-{i:04d}"
            records.append(rec)
        outlier = _outlier_record()
        outlier["headers"] = dict(outlier.get("headers", {}))
        outlier["headers"]["x-nonce"] = "unique-nonce-9999"
        records.append(outlier)
        return records

    def test_status_outlier_still_ranks_first_despite_unique_nonce(self):
        population = self._build_nonce_population()
        ranked = self.mod.score_population(population)
        assert ranked[0]["url"] == "https://example.com/broken", (
            "The 500-status record should still rank #1 even when all records "
            "have a unique nonce header (weight degradation must apply)"
        )

    def test_attribute_weight_degrades_for_near_unique(self):
        """_attribute_weight must return a small value when distinct_count ≈ pop size."""
        weight_2_distinct = self.mod._attribute_weight(2, 100)
        weight_many_distinct = self.mod._attribute_weight(100, 100)
        assert weight_2_distinct > weight_many_distinct, (
            "A binary attribute must outweigh a near-unique attribute"
        )
        # log(2)/log(100) ≈ 0.1505 — well below the max (1.0) and above _MIN_WEIGHT
        assert weight_many_distinct <= 0.2, (
            "Near-unique attribute weight must be substantially degraded from max (1.0)"
        )

    def test_attribute_weight_zero_for_one_distinct(self):
        """A non-varying attribute contributes zero weight."""
        weight = self.mod._attribute_weight(1, 100)
        assert weight == 0.0

    def test_attribute_weight_max_for_two_distinct(self):
        """A binary attribute gets maximum weight."""
        weight = self.mod._attribute_weight(2, 50)
        assert weight == 1.0


# ---------------------------------------------------------------------------
# (d) Tolerant of records missing fields
# ---------------------------------------------------------------------------

class TestMissingFields:
    def setup_method(self):
        self.mod = _load_lib()

    def test_empty_records_do_not_crash(self):
        population = [{}, {}, {}]
        ranked = self.mod.score_population(population)
        assert len(ranked) == 3

    def test_partial_records_with_outlier(self):
        """Partial records that vary on status should still find the outlier."""
        records = [
            {"url": f"https://example.com/{i}", "status": "200"} for i in range(6)
        ]
        records.append({"url": "https://example.com/err", "status": "404"})
        ranked = self.mod.score_population(records)
        assert ranked[0]["url"] == "https://example.com/err"

    def test_records_without_url_field(self):
        """url field absence must not crash."""
        records = [{"status": "200", "content_length": 1024} for _ in range(5)]
        records.append({"status": "503", "content_length": 0})
        ranked = self.mod.score_population(records)
        assert ranked[0]["status"] == "503"

    def test_single_record_scores_zero(self):
        """A population of one cannot compare against itself."""
        ranked = self.mod.score_population([_normal_record(0)])
        assert ranked[0]["anomaly_score"] == 0.0

    def test_empty_population_returns_empty(self):
        ranked = self.mod.score_population([])
        assert ranked == []

    def test_non_dict_headers_ignored(self):
        """headers as a non-dict value must not crash the extractor."""
        records = [
            {"url": f"u{i}", "status": "200", "headers": "not-a-dict"}
            for i in range(5)
        ]
        records.append({"url": "uX", "status": "500", "headers": "not-a-dict"})
        ranked = self.mod.score_population(records)
        assert ranked[0]["status"] == "500"

    def test_numeric_status_tolerated(self):
        """status as an integer (not a string) must still be extracted."""
        records = [
            {"url": f"u{i}", "status": 200} for i in range(5)
        ]
        records.append({"url": "uX", "status": 500})
        ranked = self.mod.score_population(records)
        assert ranked[0]["url"] == "uX"

    def test_length_alias_body_len(self):
        """body_len must be treated as content_length."""
        records = [
            {"url": f"u{i}", "body_len": 4096} for i in range(5)
        ]
        records.append({"url": "uX", "body_len": 0})
        ranked = self.mod.score_population(records)
        assert ranked[0]["url"] == "uX"


# ---------------------------------------------------------------------------
# (d2) Sparse attribute — rarity denominator must be the PRESENT count, not the
#      full population. A value shared by all records that HAVE the attribute is
#      not rare just because most of the population omits the attribute.
# ---------------------------------------------------------------------------

class TestSparseAttributeDenominator:
    def setup_method(self):
        self.mod = _load_lib()

    def _build_sparse_population(self):
        """10 records identical on every attribute EXCEPT `title`, which is
        present on only 3 of them: 2 share "common-title", 1 has "rare-title".
        The other 7 records carry no title at all.

        With the (buggy) population-size denominator, the common-title value's
        rarity would be 1 - 2/10 = 0.8 — wrongly inflated because 7 records
        merely *lack* the attribute.  With the correct present-count denominator
        (3 records have a title) it is 1 - 2/3 ≈ 0.333.
        """
        records = []
        for i in range(10):
            rec = {
                "url": f"https://example.com/page{i}",
                "status": "200",
                "content_length": 4096,
                "content_type": "text/html",
                "words": 300,
                "lines": 80,
                "headers": {"server": "nginx"},
            }
            if i in (0, 1):
                rec["title"] = "common-title"
            elif i == 2:
                rec["title"] = "rare-title"
            # i in 3..9 → no title key at all
            records.append(rec)
        return records

    def test_common_among_present_scores_low_rarity(self):
        """A title shared by all-but-one of the records that HAVE a title must
        score low — well below what the buggy population denominator would give
        (0.8).  The fixed present-count denominator yields ~0.333.
        """
        population = self._build_sparse_population()
        ranked = self.mod.score_population(population)
        by_url = {r["url"]: r for r in ranked}

        common = by_url["https://example.com/page0"]
        # title is the only varying attribute (weight 1.0 for a 2-value split),
        # so the score is exactly the rarity. Under the present-count denominator
        # that is 1 - 2/3 ≈ 0.333; the buggy 1 - 2/10 = 0.8 would fail this bound.
        assert common["anomaly_score"] < 0.5, (
            "Common-among-present title scored too high — denominator is using "
            f"population size, not the present count. score={common['anomaly_score']}"
        )

    def test_rare_value_still_ranks_above_common(self):
        """Relative ranking must be preserved: the genuinely-rare title (count 1
        of 3 present) still outranks the common one (count 2 of 3 present).
        """
        population = self._build_sparse_population()
        ranked = self.mod.score_population(population)
        by_url = {r["url"]: r for r in ranked}
        rare = by_url["https://example.com/page2"]
        common = by_url["https://example.com/page0"]
        assert rare["anomaly_score"] > common["anomaly_score"], (
            "Rare value must score higher than the common-among-present value"
        )

    def test_records_lacking_attribute_unaffected_by_it(self):
        """Records that omit `title` get no title contribution (None → skip);
        with title as the only varying attribute they score 0.
        """
        population = self._build_sparse_population()
        ranked = self.mod.score_population(population)
        by_url = {r["url"]: r for r in ranked}
        no_title = by_url["https://example.com/page5"]
        assert no_title["anomaly_score"] == 0.0


# ---------------------------------------------------------------------------
# (e) CLI smoke tests — file input and stdin
# ---------------------------------------------------------------------------

class TestAnomalyScoreCLI:
    def setup_method(self):
        self.cmd = _load_cmd()
        root = str(_scripts_root())
        if root not in sys.path:
            sys.path.insert(0, root)

    # ------ register ------

    def test_register_adds_anomaly_score_subparser(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        self.cmd.register(sub)
        ns = parser.parse_args(["anomaly-score"])
        assert ns.top == 10
        assert ns.as_json is False

    def test_register_top_flag_parsed(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        self.cmd.register(sub)
        ns = parser.parse_args(["anomaly-score", "--top", "3"])
        assert ns.top == 3

    def test_register_json_flag_parsed(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        self.cmd.register(sub)
        ns = parser.parse_args(["anomaly-score", "--json"])
        assert ns.as_json is True

    # ------ file input ------

    def test_file_input_json_array(self, tmp_path, capsys):
        population = _build_population(9)
        infile = tmp_path / "pop.json"
        infile.write_text(json.dumps(population), encoding="utf-8")
        self.cmd.run(SimpleNamespace(records_file=str(infile), top=5, as_json=False))
        out = capsys.readouterr().out
        assert "anomaly-score" in out
        assert "https://example.com/broken" in out

    def test_file_input_jsonl(self, tmp_path, capsys):
        population = _build_population(5)
        infile = tmp_path / "pop.jsonl"
        infile.write_text(
            "\n".join(json.dumps(r) for r in population),
            encoding="utf-8",
        )
        self.cmd.run(SimpleNamespace(records_file=str(infile), top=10, as_json=False))
        out = capsys.readouterr().out
        assert "https://example.com/broken" in out

    def test_file_input_json_output(self, tmp_path, capsys):
        population = _build_population(9)
        infile = tmp_path / "pop.json"
        infile.write_text(json.dumps(population), encoding="utf-8")
        self.cmd.run(SimpleNamespace(records_file=str(infile), top=5, as_json=True))
        raw = capsys.readouterr().out
        data = json.loads(raw)
        assert isinstance(data, list)
        assert len(data) <= 5
        # Top entry should be the outlier
        assert data[0]["url"] == "https://example.com/broken"
        # Each record must have the annotation keys
        for rec in data:
            assert "anomaly_score" in rec
            assert "anomalous_attributes" in rec

    def test_file_input_top_n_limits_output(self, tmp_path, capsys):
        population = _build_population(9)
        infile = tmp_path / "pop.json"
        infile.write_text(json.dumps(population), encoding="utf-8")
        self.cmd.run(SimpleNamespace(records_file=str(infile), top=3, as_json=True))
        raw = capsys.readouterr().out
        data = json.loads(raw)
        assert len(data) == 3

    def test_file_input_top_zero_returns_all(self, tmp_path, capsys):
        population = _build_population(9)
        infile = tmp_path / "pop.json"
        infile.write_text(json.dumps(population), encoding="utf-8")
        self.cmd.run(SimpleNamespace(records_file=str(infile), top=0, as_json=True))
        raw = capsys.readouterr().out
        data = json.loads(raw)
        assert len(data) == 10

    # ------ stdin input ------

    def test_stdin_input_json_array(self, monkeypatch, capsys):
        population = _build_population(9)
        fake_stdin = StringIO(json.dumps(population))
        monkeypatch.setattr("sys.stdin", fake_stdin)
        self.cmd.run(SimpleNamespace(records_file=None, top=5, as_json=False))
        out = capsys.readouterr().out
        assert "https://example.com/broken" in out

    def test_stdin_input_jsonl(self, monkeypatch, capsys):
        population = _build_population(5)
        payload = "\n".join(json.dumps(r) for r in population)
        fake_stdin = StringIO(payload)
        monkeypatch.setattr("sys.stdin", fake_stdin)
        self.cmd.run(SimpleNamespace(records_file=None, top=10, as_json=False))
        out = capsys.readouterr().out
        assert "https://example.com/broken" in out

    def test_stdin_empty_emits_no_records_message(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(""))
        self.cmd.run(SimpleNamespace(records_file=None, top=10, as_json=False))
        err = capsys.readouterr().err
        assert "No records" in err

    def test_stdin_empty_json_mode_returns_empty_array(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", StringIO(""))
        self.cmd.run(SimpleNamespace(records_file=None, top=10, as_json=True))
        out = capsys.readouterr().out.strip()
        assert out == "[]"


# ---------------------------------------------------------------------------
# CLI import regression: anomaly_score is wired into assess.cli
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Bug-fix regression guards — malformed JSON array raises ValueError
# ---------------------------------------------------------------------------

class TestLoadRecordsParseGuard:
    """_load_records must raise ValueError on a '['-leading malformed array
    and must NOT silently degrade to a partial JSONL parse.
    """

    def setup_method(self):
        self.cmd = _load_cmd()

    def _load_records(self, text: str) -> list[dict]:
        return self.cmd._load_records(text)

    def test_malformed_multiline_array_raises(self):
        """A '['-leading string that is not valid JSON raises ValueError."""
        bad = '[\n{"a":1},\n{"b":2}\n'   # missing closing ']'
        with pytest.raises(ValueError):
            self._load_records(bad)

    def test_malformed_array_error_is_not_silent(self):
        """The ValueError message mentions the '[' detection."""
        bad = '[\n{"a":1},\n{"b":2}\n'
        with pytest.raises(ValueError, match=r"starts with '\['|not valid JSON"):
            self._load_records(bad)

    def test_valid_multiline_array_parses_fully(self):
        """A valid multi-line JSON array (closed ']') must parse all records."""
        records = [{"a": i} for i in range(5)]
        import json
        text = '[\n' + ',\n'.join(json.dumps(r) for r in records) + '\n]'
        result = self._load_records(text)
        assert len(result) == 5
        for i, rec in enumerate(result):
            assert rec["a"] == i

    def test_cli_exits_nonzero_on_malformed_array(self, monkeypatch, capsys):
        """run() must write to stderr and call sys.exit(1) for malformed input."""

        bad = '[\n{"a":1},\n{"b":2}\n'
        fake_stdin = __import__("io").StringIO(bad)
        monkeypatch.setattr("sys.stdin", fake_stdin)

        with pytest.raises(SystemExit) as excinfo:
            self.cmd.run(__import__("types").SimpleNamespace(
                records_file=None,
                top=10,
                as_json=False,
            ))

        assert excinfo.value.code == 1
        err = capsys.readouterr().err
        assert err.strip(), "stderr must be non-empty when input is malformed"


def test_assess_cli_imports_anomaly_score() -> None:
    """cli.py must import anomaly_score from assess.commands."""
    import ast

    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent" / "scripts" / "assess" / "cli.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "assess.commands":
            imported.update(alias.name for alias in node.names)
    assert "anomaly_score" in imported, (
        "anomaly_score not found in 'from assess.commands import ...' block in cli.py"
    )


def test_assess_cli_registers_anomaly_score() -> None:
    """The registration loop in cli.py must include the anomaly_score module."""

    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent" / "scripts" / "assess" / "cli.py"
    source = path.read_text(encoding="utf-8")
    # The name must appear in the for-mod-in loop body
    assert "anomaly_score," in source or "anomaly_score\n" in source, (
        "anomaly_score not found in the registration loop in cli.py"
    )
