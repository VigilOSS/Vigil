from __future__ import annotations

import codecs
import hashlib
import os
import sys
from pathlib import Path

import pytest

SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from assess.lib import code_snapshot as producer  # noqa: E402
from app import code_snapshot as attestor  # noqa: E402


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [
        ("utf-8", b""),
        ("utf-8", codecs.BOM_UTF8),
        ("utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-32-le", codecs.BOM_UTF32_LE),
        ("utf-32-be", codecs.BOM_UTF32_BE),
    ],
)
@pytest.mark.parametrize("chunk_size", [1, 3, 7])
@pytest.mark.parametrize(
    ("text", "expected_loc"),
    [("", 0), ("first\r\nੁ\r\nു😀\rfinal", 4), ("first\r\nlast\n", 2)],
    ids=["empty", "mixed-newlines-unterminated", "trailing-newline"],
)
def test_snapshot_text_metadata_agrees_without_changing_original_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    bom: bytes,
    chunk_size: int,
    text: str,
    expected_loc: int,
) -> None:
    data = bom + text.encode(encoding)
    source = tmp_path / "source.txt"
    source.write_bytes(data)
    monkeypatch.setattr(producer, "_READ_CHUNK_SIZE", chunk_size)
    monkeypatch.setattr(attestor, "_READ_CHUNK_SIZE", chunk_size)

    with producer.capture_regular_file(source) as captured:
        assert captured.loc == expected_loc
        assert captured.header == text
        assert captured.sha256 == hashlib.sha256(data).hexdigest()
        assert captured.size == len(data)
        assert captured.read_bounded(len(data)) == data

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _, observed, _ = attestor._read_regular_at(
            directory_fd, source.name, display_path=source, max_bytes=None
        )
    finally:
        os.close(directory_fd)

    assert observed["loc"] == expected_loc
    assert observed["header_snippet"] == text
    assert observed["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert observed["size"] == len(data)
    assert source.read_bytes() == data


@pytest.mark.parametrize(
    "data",
    [b"\xe2", codecs.BOM_UTF16_LE + b"x", codecs.BOM_UTF32_LE + b"x"],
    ids=["utf8-truncated-sequence", "utf16-truncated-unit", "utf32-truncated-unit"],
)
def test_snapshot_header_retains_replacement_for_malformed_trailing_text(
    tmp_path: Path, data: bytes
) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(data)

    with producer.capture_regular_file(source) as captured:
        assert captured.loc == 1
        assert captured.header == "\ufffd"

    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _, observed, _ = attestor._read_regular_at(
            directory_fd, source.name, display_path=source, max_bytes=None
        )
    finally:
        os.close(directory_fd)

    assert observed["loc"] == 1
    assert observed["header_snippet"] == "\ufffd"
