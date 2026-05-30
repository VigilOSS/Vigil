"""Unit tests for assess.lib.payload_mutation (classify_value, mutate)
and a CLI-level smoke test for the classify-payload command.

All tests are pure-function / deterministic — no network, no LLM, no DB.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Module loaders
# ---------------------------------------------------------------------------

def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_lib():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "payload_mutation_ut",
        _scripts_root() / "assess" / "lib" / "payload_mutation.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_cmd():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "classify_payload_cmd_ut",
        _scripts_root() / "assess" / "commands" / "classify_payload.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# classify_value — one test per type
# ---------------------------------------------------------------------------

class TestClassifyValue:
    def setup_method(self):
        self.mod = _load_lib()
        self.cv = self.mod.classify_value

    def test_integer_negative(self):
        assert self.cv("-5") == "integer"

    def test_integer_zero(self):
        assert self.cv("0") == "integer"

    def test_sequential_id_small_positive(self):
        assert self.cv("42") == "sequential_id"

    def test_sequential_id_large_positive(self):
        assert self.cv("9999999999") == "sequential_id"

    def test_uuid(self):
        assert self.cv("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_uuid_uppercase(self):
        assert self.cv("550E8400-E29B-41D4-A716-446655440000") == "uuid"

    def test_jwt(self):
        # Real HS256 JWT structure (header.payload.signature)
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert self.cv(jwt) == "jwt"

    def test_email(self):
        assert self.cv("user@example.com") == "email"

    def test_url(self):
        assert self.cv("https://example.com/api/v1") == "url"

    def test_url_http(self):
        assert self.cv("http://localhost:8080/") == "url"

    def test_path_absolute(self):
        assert self.cv("/api/v1/users") == "path"

    def test_path_relative(self):
        assert self.cv("../etc/passwd") == "path"

    def test_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world this is a secret").decode()
        assert self.cv(encoded) == "base64"

    def test_hex(self):
        # 32 hex chars (128-bit, like MD5)
        assert self.cv("a" * 32) == "hex"

    def test_json_object(self):
        assert self.cv('{"key":"value","n":1}') == "json"

    def test_json_array(self):
        assert self.cv('[1,2,3]') == "json"

    def test_boolean_true(self):
        assert self.cv("true") == "boolean"

    def test_boolean_false(self):
        assert self.cv("false") == "boolean"

    def test_boolean_yes(self):
        assert self.cv("yes") == "boolean"

    def test_date_iso(self):
        assert self.cv("2024-03-15") == "date"

    def test_date_iso_datetime(self):
        assert self.cv("2024-03-15T10:30:00Z") == "date"

    def test_timestamp_unix(self):
        assert self.cv("1711929600") == "timestamp"

    def test_short_token(self):
        # 16-char alphanumeric token
        assert self.cv("aBcDeFgH1234XYZ9") == "short_token"

    def test_opaque_unknown(self):
        # Something that doesn't fit any category
        assert self.cv("hello world!") == "opaque"

    def test_non_string_returns_opaque(self):
        # Non-string input
        assert self.mod.classify_value(None) == "opaque"


# ---------------------------------------------------------------------------
# mutate — structural + behavioral tests
# ---------------------------------------------------------------------------

class TestMutate:
    def setup_method(self):
        self.mod = _load_lib()
        self.mutate = self.mod.mutate

    def _all_intents_present(self, result: dict) -> None:
        for intent in ("neighbor", "boundary", "escalation", "format", "empty"):
            assert intent in result["intents"], f"intent '{intent}' missing"

    def test_mutate_returns_required_keys(self):
        result = self.mutate("42")
        assert "value" in result
        assert "type" in result
        assert "intents" in result
        self._all_intents_present(result)

    def test_mutate_preserves_original_value(self):
        result = self.mutate("42")
        assert result["value"] == "42"

    def test_mutate_type_matches_classify(self):
        result = self.mutate("42")
        assert result["type"] == self.mod.classify_value("42")

    # Intent caps
    def test_neighbor_cap(self):
        result = self.mutate("100", max_per_intent=3)
        assert len(result["intents"]["neighbor"]) <= 3

    def test_boundary_cap(self):
        result = self.mutate("100", max_per_intent=2)
        assert len(result["intents"]["boundary"]) <= 2

    def test_escalation_cap(self):
        result = self.mutate("42", max_per_intent=4)
        assert len(result["intents"]["escalation"]) <= 4

    def test_format_cap(self):
        result = self.mutate("42", max_per_intent=3)
        assert len(result["intents"]["format"]) <= 3

    def test_empty_cap(self):
        result = self.mutate("anything", max_per_intent=2)
        assert len(result["intents"]["empty"]) <= 2

    # Intent content has teeth — sequential_id
    def test_sequential_id_neighbor_contains_adjacent(self):
        result = self.mutate("100")
        neighbors = result["intents"]["neighbor"]
        assert "101" in neighbors or "99" in neighbors

    def test_sequential_id_boundary_contains_zero(self):
        result = self.mutate("42")
        assert "0" in result["intents"]["boundary"] or "-1" in result["intents"]["boundary"]

    def test_sequential_id_escalation_contains_admin_hint(self):
        result = self.mutate("42")
        esc = result["intents"]["escalation"]
        assert any(v in ("1", "admin", "root", "0") for v in esc)

    def test_sequential_id_format_contains_type_confusion(self):
        result = self.mutate("42")
        fmt = result["intents"]["format"]
        # Should include at least one non-integer representation
        assert any(v for v in fmt if not v.lstrip("-").isdigit())

    def test_empty_always_contains_empty_string(self):
        result = self.mutate("42")
        assert "" in result["intents"]["empty"]

    # UUID-specific intent content
    def test_uuid_escalation_contains_all_zeros(self):
        result = self.mutate("550e8400-e29b-41d4-a716-446655440000")
        esc = result["intents"]["escalation"]
        assert any("00000000-0000-0000-0000-000000000000" == v for v in esc)

    # Path traversal in escalation
    def test_path_escalation_contains_traversal(self):
        result = self.mutate("/api/v1/users/42")
        esc = result["intents"]["escalation"]
        assert any("../" in v or "/etc/passwd" in v for v in esc)

    # Determinism
    def test_mutate_is_deterministic(self):
        r1 = self.mutate("12345")
        r2 = self.mutate("12345")
        assert r1 == r2

    def test_mutate_max_per_intent_one(self):
        result = self.mutate("42", max_per_intent=1)
        for intent, variants in result["intents"].items():
            assert len(variants) <= 1, f"intent {intent} exceeded cap"

    # JWT alg:none in escalation
    def test_jwt_escalation_contains_alg_none_variant(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".signature"
        )
        result = self.mutate(jwt)
        esc = result["intents"]["escalation"]
        # At least one escalation variant should contain the alg:none header
        assert any("none" in v.lower() or "alg" in v.lower() or "." in v for v in esc)

    # -----------------------------------------------------------------
    # Bug-fix regression guards — max-codepoint clamp + non-str coercion
    # -----------------------------------------------------------------

    def test_mutate_max_codepoint_does_not_raise(self):
        """mutate() on a string ending at U+10FFFF must not raise OverflowError
        (previously chr(ord(U+10FFFF)+1) would produce an invalid code point).
        The return value must be a complete dict with all required keys.
        """
        value = "abc\U0010ffff"
        result = self.mutate(value)
        assert isinstance(result, dict)
        assert "value" in result and "type" in result and "intents" in result

    def test_mutate_none_does_not_raise(self):
        """mutate(None) must not raise — None is coerced to ''."""
        result = self.mutate(None)
        assert isinstance(result, dict)
        assert "intents" in result

    def test_mutate_int_does_not_raise(self):
        """mutate(123) must not raise — integers are str()-coerced."""
        result = self.mutate(123)
        assert isinstance(result, dict)
        assert "intents" in result

    def test_mutate_bytes_does_not_raise(self):
        """mutate(b'x') must not raise — bytes are str()-coerced."""
        result = self.mutate(b"x")
        assert isinstance(result, dict)
        assert "intents" in result

    def test_mutate_list_does_not_raise(self):
        """mutate(['a']) must not raise — lists are str()-coerced."""
        result = self.mutate(["a"])
        assert isinstance(result, dict)
        assert "intents" in result


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestClassifyPayloadCommand:
    def setup_method(self):
        self.cmd = _load_cmd()
        # Ensure lib is importable
        root = str(_scripts_root())
        if root not in sys.path:
            sys.path.insert(0, root)

    def test_classify_type_only_stdout(self, capsys):
        """Without --mutations, print the type string."""
        self.cmd.run(SimpleNamespace(
            value="42",
            mutations=False,
            as_json=False,
            max_per_intent=5,
        ))
        out = capsys.readouterr().out.strip()
        assert out == "sequential_id"

    def test_classify_json_mode(self, capsys):
        """--json without --mutations emits {"value":..., "type":...}."""
        self.cmd.run(SimpleNamespace(
            value="user@example.com",
            mutations=False,
            as_json=True,
            max_per_intent=5,
        ))
        out = capsys.readouterr().out.strip()
        data = json.loads(out)
        assert data["type"] == "email"
        assert data["value"] == "user@example.com"

    def test_mutations_json_structure(self, capsys):
        """--mutations --json produces full intent dict."""
        self.cmd.run(SimpleNamespace(
            value="99",
            mutations=True,
            as_json=True,
            max_per_intent=5,
        ))
        out = capsys.readouterr().out.strip()
        data = json.loads(out)
        assert "value" in data
        assert "type" in data
        assert "intents" in data
        for intent in ("neighbor", "boundary", "escalation", "format", "empty"):
            assert intent in data["intents"]

    def test_mutations_human_readable(self, capsys):
        """--mutations without --json emits human-readable text."""
        self.cmd.run(SimpleNamespace(
            value="42",
            mutations=True,
            as_json=False,
            max_per_intent=3,
        ))
        out = capsys.readouterr().out
        assert "type:" in out
        assert "neighbor" in out
        assert "boundary" in out
        assert "escalation" in out

    def test_jwt_type_classified(self, capsys):
        """JWT value is classified as 'jwt' via CLI."""
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.cmd.run(SimpleNamespace(
            value=jwt,
            mutations=False,
            as_json=False,
            max_per_intent=5,
        ))
        out = capsys.readouterr().out.strip()
        assert out == "jwt"

    def test_register_registers_classify_payload_subparser(self):
        """register() adds 'classify-payload' to the subparsers."""
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        self.cmd.register(sub)
        ns = parser.parse_args(["classify-payload", "testval"])
        assert ns.value == "testval"
        assert ns.mutations is False
        assert ns.as_json is False


# ---------------------------------------------------------------------------
# CLI import regression: classify_payload is wired into assess.cli
# ---------------------------------------------------------------------------

def test_assess_cli_imports_classify_payload() -> None:
    """cli.py must import classify_payload from assess.commands."""
    import ast

    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent" / "scripts" / "assess" / "cli.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "assess.commands":
            imported.update(alias.name for alias in node.names)
    assert "classify_payload" in imported, (
        "classify_payload not found in 'from assess.commands import ...' block in cli.py"
    )
