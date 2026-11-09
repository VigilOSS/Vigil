"""Behaviour pins captured before the S19 simplification packet.

Each case asserts an output this packet's refactors must reproduce byte for
byte. They are ordinary regressions: they describe what the code emits today,
not that anything was removed.
"""
from __future__ import annotations

import pytest

from assess.lib import (
    anomaly,
    coverage_checks,
    kali_output,
    payload_mutation,
    remediation_vcs,
    schema_validation,
    scope,
)


# ---------------------------------------------------------------------------
# payload_mutation — every (intent, value-type) arm, uncapped and capped
# ---------------------------------------------------------------------------

_MUTATION_GOLDEN = [
    (('neighbor', 'sequential_id', '42'), ['43', '41', '44', '40', '84']),
    (('neighbor#cap2', 'sequential_id', '42'), ['43', '41']),
    (('neighbor', 'integer', '-7'), ['-6', '-8', '-5', '-9', '-14']),
    (('neighbor#cap2', 'integer', '-7'), ['-6', '-8']),
    (('neighbor', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['3f2504e0-4f89-11d3-9a0c-0305e82c3302', '3f2504e0-4f89-11d3-9a0c-0305e82c3300', 'f32504e0-4f89-11d3-9a0c-0305e82c3301']),
    (('neighbor#cap2', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['3f2504e0-4f89-11d3-9a0c-0305e82c3302', '3f2504e0-4f89-11d3-9a0c-0305e82c3300']),
    (('neighbor', 'boolean', 'true'), []),
    (('neighbor#cap2', 'boolean', 'true'), []),
    (('neighbor', 'date', '2024-05-17'), []),
    (('neighbor#cap2', 'date', '2024-05-17'), []),
    (('neighbor', 'timestamp', '1715900000'), []),
    (('neighbor#cap2', 'timestamp', '1715900000'), []),
    (('neighbor', 'short_token', 'abc123def456'), ['abc123def4561', 'abc123def4562', 'abc123def457']),
    (('neighbor#cap2', 'short_token', 'abc123def456'), ['abc123def4561', 'abc123def4562']),
    (('neighbor', 'opaque', 'zz'), ['zz1', 'zz2', 'z{']),
    (('neighbor#cap2', 'opaque', 'zz'), ['zz1', 'zz2']),
    (('neighbor', 'base64', 'aGVsbG8gd29ybGQh'), []),
    (('neighbor#cap2', 'base64', 'aGVsbG8gd29ybGQh'), []),
    (('neighbor', 'hex', 'deadbeefcafe1234'), ['deadbeefcafe1235', 'deadbeefcafe1233']),
    (('neighbor#cap2', 'hex', 'deadbeefcafe1234'), ['deadbeefcafe1235', 'deadbeefcafe1233']),
    (('neighbor', 'jwt', 'aaa.bbb.ccc'), []),
    (('neighbor#cap2', 'jwt', 'aaa.bbb.ccc'), []),
    (('neighbor', 'url', 'https://acme.example/a/b?x=1'), []),
    (('neighbor#cap2', 'url', 'https://acme.example/a/b?x=1'), []),
    (('neighbor', 'path', '/var/www/html/index.php'), []),
    (('neighbor#cap2', 'path', '/var/www/html/index.php'), []),
    (('neighbor', 'email', 'user@acme.example'), []),
    (('neighbor#cap2', 'email', 'user@acme.example'), []),
    (('neighbor', 'json', '{"a": 1}'), []),
    (('neighbor#cap2', 'json', '{"a": 1}'), []),
    (('neighbor', 'unclassified', 'something-else'), []),
    (('neighbor#cap2', 'unclassified', 'something-else'), []),
    (('boundary', 'sequential_id', '42'), ['0', '-1', '1', '99999999', '2147483647', '-2147483648', '9999999999999']),
    (('boundary#cap2', 'sequential_id', '42'), ['0', '-1']),
    (('boundary', 'integer', '-7'), ['0', '-1', '1', '99999999', '2147483647', '-2147483648', '9999999999999']),
    (('boundary#cap2', 'integer', '-7'), ['0', '-1']),
    (('boundary', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff']),
    (('boundary#cap2', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff']),
    (('boundary', 'boolean', 'true'), ['false', '1', '0', '']),
    (('boundary#cap2', 'boolean', 'true'), ['false', '1']),
    (('boundary', 'date', '2024-05-17'), ['1970-01-01', '2038-01-19', '9999-12-31', '0', '1', '-1']),
    (('boundary#cap2', 'date', '2024-05-17'), ['1970-01-01', '2038-01-19']),
    (('boundary', 'timestamp', '1715900000'), ['1970-01-01', '2038-01-19', '9999-12-31', '0', '1', '-1']),
    (('boundary#cap2', 'timestamp', '1715900000'), ['1970-01-01', '2038-01-19']),
    (('boundary', 'short_token', 'abc123def456'), ['', 'a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']),
    (('boundary#cap2', 'short_token', 'abc123def456'), ['', 'a']),
    (('boundary', 'opaque', 'zz'), ['', 'a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']),
    (('boundary#cap2', 'opaque', 'zz'), ['', 'a']),
    (('boundary', 'base64', 'aGVsbG8gd29ybGQh'), ['', 'a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']),
    (('boundary#cap2', 'base64', 'aGVsbG8gd29ybGQh'), ['', 'a']),
    (('boundary', 'hex', 'deadbeefcafe1234'), ['', 'a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']),
    (('boundary#cap2', 'hex', 'deadbeefcafe1234'), ['', 'a']),
    (('boundary', 'jwt', 'aaa.bbb.ccc'), ['', 'a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']),
    (('boundary#cap2', 'jwt', 'aaa.bbb.ccc'), ['', 'a']),
    (('boundary', 'url', 'https://acme.example/a/b?x=1'), ['http://localhost/', 'http://127.0.0.1/', 'file:///etc/passwd', 'javascript:alert(1)']),
    (('boundary#cap2', 'url', 'https://acme.example/a/b?x=1'), ['http://localhost/', 'http://127.0.0.1/']),
    (('boundary', 'path', '/var/www/html/index.php'), ['/', '.', '', '/etc/passwd', '/proc/self/environ']),
    (('boundary#cap2', 'path', '/var/www/html/index.php'), ['/', '.']),
    (('boundary', 'email', 'user@acme.example'), ['', '0', '-1', 'null']),
    (('boundary#cap2', 'email', 'user@acme.example'), ['', '0']),
    (('boundary', 'json', '{"a": 1}'), ['', '0', '-1', 'null']),
    (('boundary#cap2', 'json', '{"a": 1}'), ['', '0']),
    (('boundary', 'unclassified', 'something-else'), ['', '0', '-1', 'null']),
    (('boundary#cap2', 'unclassified', 'something-else'), ['', '0']),
    (('escalation', 'sequential_id', '42'), ['1', '0', '2', 'admin', 'root', '-1', '99999999']),
    (('escalation#cap2', 'sequential_id', '42'), ['1', '0']),
    (('escalation', 'integer', '-7'), ['1', '0', '2', 'admin', 'root', '-1', '99999999']),
    (('escalation#cap2', 'integer', '-7'), ['1', '0']),
    (('escalation', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000001', '3F2504E0-4F89-11D3-9A0C-0305E82C3301']),
    (('escalation#cap2', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000001']),
    (('escalation', 'boolean', 'true'), ['1', 'yes', 'on', 'True']),
    (('escalation#cap2', 'boolean', 'true'), ['1', 'yes']),
    (('escalation', 'date', '2024-05-17'), ['admin', '1', 'root', '0']),
    (('escalation#cap2', 'date', '2024-05-17'), ['admin', '1']),
    (('escalation', 'timestamp', '1715900000'), ['admin', '1', 'root', '0']),
    (('escalation#cap2', 'timestamp', '1715900000'), ['admin', '1']),
    (('escalation', 'short_token', 'abc123def456'), ['admin', 'root', 'ADMIN', '0', '1', 'true']),
    (('escalation#cap2', 'short_token', 'abc123def456'), ['admin', 'root']),
    (('escalation', 'opaque', 'zz'), ['admin', 'root', 'ADMIN', '0', '1', 'true']),
    (('escalation#cap2', 'opaque', 'zz'), ['admin', 'root']),
    (('escalation', 'base64', 'aGVsbG8gd29ybGQh'), ['admin', 'root', 'ADMIN', '0', '1', 'true']),
    (('escalation#cap2', 'base64', 'aGVsbG8gd29ybGQh'), ['admin', 'root']),
    (('escalation', 'hex', 'deadbeefcafe1234'), ['admin', '1', 'root', '0']),
    (('escalation#cap2', 'hex', 'deadbeefcafe1234'), ['admin', '1']),
    (('escalation', 'jwt', 'aaa.bbb.ccc'), ['eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0.', 'aaa.bbb.AAAA']),
    (('escalation#cap2', 'jwt', 'aaa.bbb.ccc'), ['eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0.', 'aaa.bbb.AAAA']),
    (('escalation', 'url', 'https://acme.example/a/b?x=1'), ['http://169.254.169.254/latest/meta-data/', 'http://localhost/admin', 'http://[::1]/']),
    (('escalation#cap2', 'url', 'https://acme.example/a/b?x=1'), ['http://169.254.169.254/latest/meta-data/', 'http://localhost/admin']),
    (('escalation', 'path', '/var/www/html/index.php'), ['../../etc/passwd', '../../../etc/shadow', '/etc/passwd', '/admin', '/internal', '%2Fvar%2Fwww%2Fhtml%2Findex.php', '/var/www/html/index.php/..']),
    (('escalation#cap2', 'path', '/var/www/html/index.php'), ['../../etc/passwd', '../../../etc/shadow']),
    (('escalation', 'email', 'user@acme.example'), ['admin@example.com', 'root@localhost', 'administrator@example.com']),
    (('escalation#cap2', 'email', 'user@acme.example'), ['admin@example.com', 'root@localhost']),
    (('escalation', 'json', '{"a": 1}'), ['admin', '1', 'root', '0']),
    (('escalation#cap2', 'json', '{"a": 1}'), ['admin', '1']),
    (('escalation', 'unclassified', 'something-else'), ['admin', '1', 'root', '0']),
    (('escalation#cap2', 'unclassified', 'something-else'), ['admin', '1']),
    (('format', 'sequential_id', '42'), ['"42"', '[42]', '{"id": 42}', 'null', '[]', '{}', '42.0']),
    (('format#cap2', 'sequential_id', '42'), ['"42"', '[42]']),
    (('format', 'integer', '-7'), ['"-7"', '[-7]', '{"id": -7}', 'null', '[]', '{}', '-7.0']),
    (('format#cap2', 'integer', '-7'), ['"-7"', '[-7]']),
    (('format', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['3f2504e04f8911d39a0c0305e82c3301', '3F2504E0-4F89-11D3-9A0C-0305E82C3301', '"3f2504e0-4f89-11d3-9a0c-0305e82c3301"']),
    (('format#cap2', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['3f2504e04f8911d39a0c0305e82c3301', '3F2504E0-4F89-11D3-9A0C-0305E82C3301']),
    (('format', 'boolean', 'true'), ['"true"', '1', '["true"]', 'null']),
    (('format#cap2', 'boolean', 'true'), ['"true"', '1']),
    (('format', 'date', '2024-05-17'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'date', '2024-05-17'), ['null', '""']),
    (('format', 'timestamp', '1715900000'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'timestamp', '1715900000'), ['null', '""']),
    (('format', 'short_token', 'abc123def456'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'short_token', 'abc123def456'), ['null', '""']),
    (('format', 'opaque', 'zz'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'opaque', 'zz'), ['null', '""']),
    (('format', 'base64', 'aGVsbG8gd29ybGQh'), ['"aGVsbG8gd29ybGQh"', 'null', 'aGVsbG8gd29ybGQh==', 'aGVsbG8gd29ybG']),
    (('format#cap2', 'base64', 'aGVsbG8gd29ybGQh'), ['"aGVsbG8gd29ybGQh"', 'null']),
    (('format', 'hex', 'deadbeefcafe1234'), ['"deadbeefcafe1234"', 'null', 'deadbeefcafe1234==', 'deadbeefcafe12']),
    (('format#cap2', 'hex', 'deadbeefcafe1234'), ['"deadbeefcafe1234"', 'null']),
    (('format', 'jwt', 'aaa.bbb.ccc'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'jwt', 'aaa.bbb.ccc'), ['null', '""']),
    (('format', 'url', 'https://acme.example/a/b?x=1'), ['"https://acme.example/a/b?x=1"', 'http://acme.example/a/b?x=1', 'https:acme.example/a/b?x=1']),
    (('format#cap2', 'url', 'https://acme.example/a/b?x=1'), ['"https://acme.example/a/b?x=1"', 'http://acme.example/a/b?x=1']),
    (('format', 'path', '/var/www/html/index.php'), ['"/var/www/html/index.php"', '\\var\\www\\html\\index.php', '%2Fvar%2Fwww%2Fhtml%2Findex.php']),
    (('format#cap2', 'path', '/var/www/html/index.php'), ['"/var/www/html/index.php"', '\\var\\www\\html\\index.php']),
    (('format', 'email', 'user@acme.example'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'email', 'user@acme.example'), ['null', '""']),
    (('format', 'json', '{"a": 1}'), ['{"a": 1', '{"a": 1}}', '"a": 1}', 'null', '[]', '""']),
    (('format#cap2', 'json', '{"a": 1}'), ['{"a": 1', '{"a": 1}}']),
    (('format', 'unclassified', 'something-else'), ['null', '""', '0', '[]', '{}']),
    (('format#cap2', 'unclassified', 'something-else'), ['null', '""']),
    (('empty', 'sequential_id', '42'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'sequential_id', '42'), ['', 'null']),
    (('empty', 'integer', '-7'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'integer', '-7'), ['', 'null']),
    (('empty', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'uuid', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['', 'null']),
    (('empty', 'boolean', 'true'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'boolean', 'true'), ['', 'null']),
    (('empty', 'date', '2024-05-17'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'date', '2024-05-17'), ['', 'null']),
    (('empty', 'timestamp', '1715900000'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'timestamp', '1715900000'), ['', 'null']),
    (('empty', 'short_token', 'abc123def456'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'short_token', 'abc123def456'), ['', 'null']),
    (('empty', 'opaque', 'zz'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'opaque', 'zz'), ['', 'null']),
    (('empty', 'base64', 'aGVsbG8gd29ybGQh'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'base64', 'aGVsbG8gd29ybGQh'), ['', 'null']),
    (('empty', 'hex', 'deadbeefcafe1234'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'hex', 'deadbeefcafe1234'), ['', 'null']),
    (('empty', 'jwt', 'aaa.bbb.ccc'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'jwt', 'aaa.bbb.ccc'), ['', 'null']),
    (('empty', 'url', 'https://acme.example/a/b?x=1'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'url', 'https://acme.example/a/b?x=1'), ['', 'null']),
    (('empty', 'path', '/var/www/html/index.php'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'path', '/var/www/html/index.php'), ['', 'null']),
    (('empty', 'email', 'user@acme.example'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'email', 'user@acme.example'), ['', 'null']),
    (('empty', 'json', '{"a": 1}'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'json', '{"a": 1}'), ['', 'null']),
    (('empty', 'unclassified', 'something-else'), ['', 'null', 'undefined', ' ', '\x00', 'nil', 'none', 'None', 'NULL']),
    (('empty#cap2', 'unclassified', 'something-else'), ['', 'null']),
]


@pytest.mark.parametrize(("key", "expected"), _MUTATION_GOLDEN)
def test_mutation_arm_output_is_unchanged(key, expected) -> None:
    intent, vtype, value = key
    max_n = 2 if intent.endswith("#cap2") else 50
    generator = payload_mutation._INTENT_GENERATORS[intent.removesuffix("#cap2")]
    assert generator(value, vtype, max_n) == expected


# ---------------------------------------------------------------------------
# kali_output — the branches where identity injection diverges from required
# ---------------------------------------------------------------------------


def test_required_headers_classify_passive_tools() -> None:
    cmd = ["browser", "https://acme.example"]
    assert kali_output._apply_required_headers(
        cmd, "browser", {"X-Researcher": "acme"}
    ) == "self_attributed"
    assert cmd == ["browser", "https://acme.example"]
    cmd = ["gau", "acme.example"]
    assert kali_output._apply_required_headers(
        cmd, "gau", {"X-Researcher": "acme"}
    ) == "skipped"
    assert cmd == ["gau", "acme.example"]


def test_identity_headers_do_not_classify_passive_tools() -> None:
    cmd = ["browser", "https://acme.example"]
    assert kali_output._apply_identity_headers(
        cmd, "browser", {"Cookie": "sid=abc"}
    ) == "warned"
    assert cmd == ["browser", "https://acme.example"]
    cmd = ["gau", "acme.example"]
    assert kali_output._apply_identity_headers(
        cmd, "gau", {"Cookie": "sid=abc"}
    ) == "warned"
    assert cmd == ["gau", "acme.example"]


def test_no_headers_is_noop_on_both_doors() -> None:
    cmd = ["curl", "https://acme.example"]
    assert kali_output._apply_required_headers(cmd, "curl", {}) == "noop"
    assert kali_output._apply_identity_headers(cmd, "curl", {}) == "noop"
    assert cmd == ["curl", "https://acme.example"]


def test_wrapped_shell_script_without_injectable_subcommand() -> None:
    required = ["bash", "-lc", "gau acme.example"]
    assert kali_output._apply_required_headers(
        required, "gau", {"X-Researcher": "acme"}
    ) == "skipped"
    assert required == ["bash", "-lc", "gau acme.example"]
    identity = ["bash", "-lc", "gau acme.example"]
    assert kali_output._apply_identity_headers(
        identity, "gau", {"Cookie": "sid=abc"}
    ) == "warned"
    assert identity == ["bash", "-lc", "gau acme.example"]


def test_wrapped_shell_script_already_carrying_the_header() -> None:
    script = 'curl -H "Cookie: sid=abc" https://acme.example'
    required = ["bash", "-lc", script]
    assert kali_output._apply_required_headers(
        required, "curl", {"Cookie": "sid=abc"}
    ) == "noop"
    identity = ["bash", "-lc", script]
    assert kali_output._apply_identity_headers(
        identity, "curl", {"Cookie": "sid=abc"}
    ) == "noop"
    # Pinned exactly as they stand: the no-op rewrite is a byte-identical
    # script here, so neither door's write-back decision is observable.
    assert required[2] == script
    assert identity[2] == script


# ---------------------------------------------------------------------------
# scope.execution_script_argv — one case per interpreter argv-shape table arm
# ---------------------------------------------------------------------------

_SCRIPT_ARGV_GOLDEN = [
    (["bash", "/e/poc.sh"], "/e/poc.sh"),
    (["bash", "--verbose", "/e/poc.sh"], "/e/poc.sh"),
    (["bash", "--rcfile", "/e/rc", "/e/poc.sh"], "/e/poc.sh"),
    (["bash", "-c", "curl https://acme.example"], ""),
    (["bash", "-lc", "curl https://acme.example"], ""),
    (["bash", "--", "/e/poc.sh"], "/e/poc.sh"),
    (["sh", "/e/poc.sh"], "/e/poc.sh"),
    (["sh", "-o", "errexit", "/e/poc.sh"], "/e/poc.sh"),
    (["sh", "--verbose", "/e/poc.sh"], ""),
    (["dash", "/e/poc.sh"], "/e/poc.sh"),
    (["dash", "--verbose", "/e/poc.sh"], ""),
    (["zsh", "/e/poc.sh"], "/e/poc.sh"),
    (["zsh", "--version", "/e/poc.sh"], ""),
    (["node", "/e/probe.js"], "/e/probe.js"),
    (["node", "--require", "/e/hook.js", "/e/probe.js"], "/e/probe.js"),
    (["node", "-e", "fetch('x')"], ""),
    (["node", "--experimental-vm-modules", "/e/probe.js"], ""),
    (["nodejs", "/e/probe.js"], "/e/probe.js"),
    (["nodejs", "--require", "/e/hook.js", "/e/probe.js"], "/e/probe.js"),
    (["nodejs", "--experimental-vm-modules", "/e/probe.js"], ""),
    (["perl", "/e/probe.pl"], "/e/probe.pl"),
    (["perl", "-I", "/e/lib", "/e/probe.pl"], "/e/probe.pl"),
    (["perl", "-e", "print 1"], ""),
    (["perl", "-w", "/e/probe.pl"], ""),
    (["php", "-n", "/e/probe.php"], "/e/probe.php"),
    (["php", "-f", "/e/probe.php"], "/e/probe.php"),
    (["php", "--file=/e/probe.php"], "/e/probe.php"),
    (["php", "-r", "echo 1;"], ""),
    (["python3", "/e/probe.py"], "/e/probe.py"),
    (["python3", "-W", "ignore", "/e/probe.py"], "/e/probe.py"),
    (["python3", "-m", "http.server"], ""),
    (["python3", "-u", "/e/probe.py"], ""),
    (["python3"], ""),
    (["python3", "-"], ""),
    (["python", "/e/probe.py"], "/e/probe.py"),
    (["python", "-u", "/e/probe.py"], ""),
    (["ruby", "/e/probe.rb"], "/e/probe.rb"),
    (["ruby", "-I", "/e/lib", "/e/probe.rb"], "/e/probe.rb"),
    (["ruby", "-S", "gem"], ""),
    (["ruby", "-w", "/e/probe.rb"], ""),
    (["curl", "https://acme.example"], ""),
]


@pytest.mark.parametrize(("argv", "expected"), _SCRIPT_ARGV_GOLDEN)
def test_execution_script_argv_is_unchanged(argv, expected) -> None:
    assert scope.execution_script_argv(argv) == expected


# ---------------------------------------------------------------------------
# schema_validation — the exact message for every scalar type and bound keyword
# ---------------------------------------------------------------------------

_SCHEMA_MESSAGE_CASES = [
    ({"type": "object"}, [], ["payload must be an object"]),
    ({"type": "array"}, {}, ["payload must be an array"]),
    ({"type": "string"}, 1, ["payload must be a string"]),
    ({"type": "integer"}, "1", ["payload must be an integer"]),
    ({"type": "integer"}, True, ["payload must be an integer"]),
    ({"type": "integer"}, 1.5, ["payload must be an integer"]),
    ({"type": "number"}, "1", ["payload must be a number"]),
    ({"type": "number"}, True, ["payload must be a number"]),
    ({"type": "number"}, 1, []),
    ({"type": "number"}, 1.5, []),
    ({"type": "boolean"}, 1, ["payload must be a boolean"]),
    ({"type": "boolean"}, True, []),
    ({"type": "integer"}, 7, []),
    ({"type": ["integer", "string"]}, [], ["payload must be one of the allowed types: ['integer', 'string']"]),
    ({"type": ["integer", "string"]}, "x", []),
    ({"type": "null"}, None, []),
    ({"type": "integer", "minimum": 5}, 4, ["payload must be >= 5"]),
    ({"type": "integer", "maximum": 5}, 6, ["payload must be <= 5"]),
    ({"type": "integer", "exclusiveMinimum": 5}, 5, ["payload must be > 5"]),
    ({"type": "integer", "exclusiveMaximum": 5}, 5, ["payload must be < 5"]),
    ({"type": "integer", "minimum": 5, "maximum": 1}, 3, ["payload must be >= 5", "payload must be <= 1"]),
    ({"type": "array", "minItems": 2}, [1], ["payload must contain at least 2 items"]),
    ({"type": "array", "maxItems": 1}, [1, 2], ["payload must contain at most 1 items"]),
    ({"type": "string", "minLength": 3}, "ab", ["payload must be at least 3 characters"]),
    ({"type": "string", "maxLength": 1}, "ab", ["payload must be at most 1 characters"]),
    ({"type": "string", "pattern": "^a"}, "bc", ["payload must match pattern '^a'"]),
    ({"type": "string", "enum": ["a"]}, "b", ["payload must be one of ['a']"]),
    ({"const": 3}, 4, ["payload must equal 3"]),
    (
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}},
        {},
        ["payload.a is required"],
    ),
    (
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {"alpha": {"type": "integer"}},
        },
        {"alpha": "x", "alpba": 1},
        ["payload.alpba is not allowed. Did you mean: alpha?", "payload.alpha must be an integer"],
    ),
]


@pytest.mark.parametrize(("schema", "value", "expected"), _SCHEMA_MESSAGE_CASES)
def test_schema_validation_messages_are_unchanged(schema, value, expected) -> None:
    assert schema_validation.collect_validation_errors(value, schema) == expected


_PATCH_CASES = [
    ({"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}}, {}, []),
    (
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}},
        {"a": "x"},
        ["payload.a must be an integer"],
    ),
    (
        {
            "type": "object",
            "required": ["alpha"],
            "additionalProperties": False,
            "properties": {"alpha": {"type": "integer"}},
        },
        {"alpba": 1},
        ["payload.alpba is not allowed. Did you mean: alpha?"],
    ),
    ({"type": "object"}, [], ["payload must be an object"]),
    ("not-a-schema", {"a": 1}, []),
]


@pytest.mark.parametrize(("schema", "value", "expected"), _PATCH_CASES)
def test_patch_validation_messages_are_unchanged(schema, value, expected) -> None:
    assert schema_validation.collect_patch_validation_errors(value, schema) == expected


# ---------------------------------------------------------------------------
# anomaly — every boundary of the three count-bucket ladders
# ---------------------------------------------------------------------------

_HEADER_COUNT_BOUNDARIES = [
    (0, "hdrs_0"), (1, "hdrs_1_3"), (3, "hdrs_1_3"), (4, "hdrs_4_7"),
    (7, "hdrs_4_7"), (8, "hdrs_8_15"), (15, "hdrs_8_15"), (16, "hdrs_16+"),
    (17, "hdrs_16+"), (99, "hdrs_16+"),
]
_WORDS_BOUNDARIES = [
    (0, "words_0"), (1, "words_1_10"), (10, "words_1_10"), (11, "words_11_100"),
    (100, "words_11_100"), (101, "words_101_500"), (500, "words_101_500"),
    (501, "words_501_2000"), (2000, "words_501_2000"), (2001, "words_2001+"),
    (99999, "words_2001+"), (-1, "words_1_10"),
]
_LINES_BOUNDARIES = [
    (0, "lines_0"), (1, "lines_1_5"), (5, "lines_1_5"), (6, "lines_6_25"),
    (25, "lines_6_25"), (26, "lines_26_100"), (100, "lines_26_100"),
    (101, "lines_101+"), (99999, "lines_101+"), (-1, "lines_1_5"),
]


@pytest.mark.parametrize(("count", "expected"), _HEADER_COUNT_BOUNDARIES)
def test_header_count_bucket_boundaries(count, expected) -> None:
    headers = {f"h{index}": "v" for index in range(count)}
    assert anomaly._extract_header_count({"headers": headers}) == expected


@pytest.mark.parametrize(("value", "expected"), _WORDS_BOUNDARIES)
def test_words_bucket_boundaries(value, expected) -> None:
    assert anomaly._extract_words_bucket({"words": value}) == expected


@pytest.mark.parametrize(("value", "expected"), _LINES_BOUNDARIES)
def test_lines_bucket_boundaries(value, expected) -> None:
    assert anomaly._extract_lines_bucket({"lines": value}) == expected


def test_count_bucket_non_numeric_and_absent_inputs() -> None:
    assert anomaly._extract_header_count({"headers": "x"}) is None
    assert anomaly._extract_header_count({}) is None
    assert anomaly._extract_words_bucket({}) is None
    assert anomaly._extract_words_bucket({"words": "x"}) is None
    assert anomaly._extract_words_bucket({"words": "12"}) == "words_11_100"
    assert anomaly._extract_words_bucket({"words": 12.9}) == "words_11_100"
    assert anomaly._extract_lines_bucket({"lines": None}) is None
    assert anomaly._extract_lines_bucket({"lines": "12"}) == "lines_6_25"


# ---------------------------------------------------------------------------
# remediation_vcs — the exact jj argv each log read issues
# ---------------------------------------------------------------------------


def _record_jj_argv(monkeypatch, tmp_path):
    (tmp_path / ".jj").mkdir()
    issued: list[list[str]] = []

    def fake_run(args, **kwargs):
        issued.append(list(args))
        return __import__("subprocess").CompletedProcess(args, 0, "abc123\n", "")

    monkeypatch.setattr(remediation_vcs.subprocess, "run", fake_run)
    return issued


def test_resolve_revision_log_argv(monkeypatch, tmp_path) -> None:
    issued = _record_jj_argv(monkeypatch, tmp_path)
    assert remediation_vcs.resolve_revision(tmp_path, "main") == "abc123"
    assert issued == [
        [
            "jj", "--no-pager", "--color=never", "-R", str(tmp_path),
            "log", "-r", "main", "--no-graph", "-T", 'commit_id ++ "\\n"',
        ]
    ]


def test_resolve_revision_refuses_multiple_commits(monkeypatch, tmp_path) -> None:
    (tmp_path / ".jj").mkdir()

    def fake_run(args, **kwargs):
        return __import__("subprocess").CompletedProcess(args, 0, "a\nb\n", "")

    monkeypatch.setattr(remediation_vcs.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="exactly one commit"):
        remediation_vcs.resolve_revision(tmp_path, "main")


def test_branch_matches_log_argv(monkeypatch, tmp_path) -> None:
    issued = _record_jj_argv(monkeypatch, tmp_path)
    assert remediation_vcs.branch_matches(tmp_path, "main") is True
    assert issued == [
        [
            "jj", "--no-pager", "--color=never", "-R", str(tmp_path),
            "log", "-r", 'bookmarks(exact:"main")', "--no-graph",
            "-T", 'commit_id ++ "\\n"',
        ],
        [
            "jj", "--no-pager", "--color=never", "-R", str(tmp_path),
            "log", "-r", "abc123 & ancestors(@)", "--no-graph", "-T", "commit_id",
        ],
    ]


def test_ancestor_log_argv(monkeypatch, tmp_path) -> None:
    issued = _record_jj_argv(monkeypatch, tmp_path)
    # Both revisions resolve to the same commit id, so ancestry is False and no
    # third read is issued.
    assert remediation_vcs.ancestor(tmp_path, "old", "new") is False
    assert [args[7] for args in issued] == ["old", "new"]
    assert all(args[-1] == 'commit_id ++ "\\n"' for args in issued)


# ---------------------------------------------------------------------------
# coverage_checks — the surface-coverage blocker block and the vendor-SaaS walk
# ---------------------------------------------------------------------------


def test_surface_coverage_non_dict_payload() -> None:
    assert coverage_checks.render_surface_coverage(None) == (
        False, [], ["surface-coverage: unexpected response from backend"]
    )


def test_surface_coverage_ready() -> None:
    assert coverage_checks.render_surface_coverage({"ready": True}) == (
        True, ["surface coverage: ok"], []
    )


def test_surface_coverage_blocker_lines() -> None:
    ready, ok_lines, blockers = coverage_checks.render_surface_coverage(
        {
            "ready": False,
            "unresolved_surfaces": [
                {"surface_type": "http_api", "target_descriptor": "api.acme.example"}
            ],
            "partially_covered_surfaces": [
                {
                    "surface_type": "login",
                    "target_descriptor": "www.acme.example",
                    "followup_condition": "retest after MFA rollout",
                }
            ],
            "high_risk_deferred_surfaces": [
                {"surface_type": "admin", "target_descriptor": "admin.acme.example"}
            ],
        }
    )
    assert ready is False
    assert ok_lines == []
    assert blockers == [
        "Uncovered surfaces remain:",
        "  - http_api | api.acme.example",
        "Partially covered surfaces need follow-up:",
        "  - login | www.acme.example | retest after MFA rollout",
        "High-risk surfaces cannot remain deferred:",
        "  - admin | admin.acme.example",
        "Resolve them as covered or not_applicable before finishing Test/Report.",
    ]


def test_surface_coverage_empty_blocks_emit_no_header() -> None:
    _ready, _ok, blockers = coverage_checks.render_surface_coverage(
        {
            "ready": False,
            "unresolved_surfaces": [],
            "partially_covered_surfaces": [
                {
                    "surface_type": "login",
                    "target_descriptor": "www.acme.example",
                    "followup_condition": "retest",
                }
            ],
            "high_risk_deferred_surfaces": [],
        }
    )
    assert blockers == [
        "Partially covered surfaces need follow-up:",
        "  - login | www.acme.example | retest",
    ]


def test_vendor_saas_pending_decision_precedence_and_order() -> None:
    rows = coverage_checks._vendor_saas_hosts_pending_decision(
        services=[{"endpoint": "https://acme.zendesk.com/a"}],
        surfaces=[{"target_descriptor": "https://acme.statuspage.io"}],
        work_by_host={"support.acme.example": {"pending": 1}},
        decided_hosts={"acme.statuspage.io"},
    )
    assert rows == [("acme.zendesk.com", "zendesk")]
