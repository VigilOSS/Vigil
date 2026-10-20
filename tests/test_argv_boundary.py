"""The first delimiter separates parser options from byte-for-byte child argv."""
import pytest

from vigil_cli.argv import passthrough_boundary


@pytest.mark.parametrize(("argv", "expected"), [
    ([], 0),
    (["engagement", "mode"], 2),
    (["--"], 0),
    (["assess", "kali", "exec", "--", "acme-tool", "--help", "--", "--root"], 3),
    (["--root=/tmp/acme", "engagement", "start", "--", "--mode", "code"], 3),
])
def test_passthrough_boundary_preserves_input(argv, expected):
    original = list(argv)
    assert passthrough_boundary(argv) == expected
    assert argv == original
