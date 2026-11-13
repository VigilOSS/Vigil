"""httpx-stored responses are decoded by Content-Encoding before anything mines them.

httpx ``-store-response`` writes each response as captured: the request block,
the response headers, the body exactly as it arrived (still brotli- or
gzip-encoded when the server compressed it, and re-framed as chunked when the
response was chunked), then ``\\n\\n\\n`` and the full URL. jsluice, trufflehog
and the regex extractor were reading those bytes directly, so every brotli
bundle contributed no endpoints and no secrets while the stage looked complete.
"""
from __future__ import annotations

import gzip
import io
import json
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import brotli

from assess.commands import gau_js_endpoints, gau_secrets, js_mining
from assess.lib import stored_responses

JS_SOURCE = (
    b'const api = "/api/v1/acme-orders";\n'
    b'fetch("https://api.example.com/v2/acme-users", {method: "POST"});\n'
    b'const key = "AKIAACMEEXAMPLE0000";\n'
)


def _stored(url: str, body: bytes, *, headers: list[str]) -> bytes:
    path = url.split("example.com", 1)[1] or "/"
    request = (
        f"GET {path} HTTP/1.1\r\nHost: app.example.com\r\n"
        "User-Agent: acme-test\r\nAccept-Encoding: gzip\r\n\r\n"
    ).encode()
    response = ("HTTP/1.1 200 OK\r\n" + "".join(f"{h}\r\n" for h in headers) + "\r\n").encode()
    return request + response + body + b"\n\n\n" + url.encode()


def _chunked(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n"


def test_brotli_body_is_decoded_and_framing_is_kept():
    raw = _stored(
        "https://app.example.com/assets/app.js",
        brotli.compress(JS_SOURCE),
        headers=["Content-Type: application/javascript", "Content-Encoding: br"],
    )
    decoded = stored_responses.decode_stored_response(raw)
    assert decoded.status == "decoded"
    assert decoded.encodings == ("br",)
    assert decoded.body == JS_SOURCE
    rebuilt = decoded.rebuilt()
    assert rebuilt.startswith(b"GET /assets/app.js HTTP/1.1\r\n")
    assert rebuilt.endswith(b"\n\n\nhttps://app.example.com/assets/app.js")
    assert JS_SOURCE in rebuilt


def test_chunked_gzip_body_is_dechunked_then_decoded():
    raw = _stored(
        "https://app.example.com/assets/vendor.js",
        _chunked(gzip.compress(JS_SOURCE)),
        headers=["Transfer-Encoding: chunked", "Content-Encoding: gzip"],
    )
    decoded = stored_responses.decode_stored_response(raw)
    assert decoded.status == "decoded"
    assert decoded.body == JS_SOURCE


def test_deflate_in_both_wrappings_is_decoded():
    for payload in (zlib.compress(JS_SOURCE), zlib.compress(JS_SOURCE)[2:-4]):
        raw = _stored(
            "https://app.example.com/a.js", payload, headers=["Content-Encoding: deflate"]
        )
        assert stored_responses.decode_stored_response(raw).body == JS_SOURCE


def test_identity_body_round_trips_byte_for_byte():
    raw = _stored("https://app.example.com/a.js", JS_SOURCE, headers=["Content-Length: 10"])
    decoded = stored_responses.decode_stored_response(raw)
    assert decoded.status == "identity"
    assert decoded.rebuilt() == raw


def test_truncated_brotli_body_yields_its_decoded_prefix_as_partial():
    big = b"".join(
        f'fetch("/api/v{i}/acme-{i * 7919 % 100003}");\n'.encode() for i in range(60000)
    )
    compressed = brotli.compress(big, quality=6)
    raw = _stored(
        "https://app.example.com/big.js",
        compressed[: len(compressed) // 2],
        headers=["Content-Encoding: br"],
    )
    decoded = stored_responses.decode_stored_response(raw)
    assert decoded.status == "partial"
    assert decoded.body and big.startswith(decoded.body)
    assert "truncated" in decoded.reason


def test_corrupt_and_unsupported_encodings_are_undecodable_and_keep_raw_bytes():
    corrupt = _stored("https://app.example.com/c.js", b"\xff\xfe not brotli", headers=["Content-Encoding: br"])
    unsupported = _stored("https://app.example.com/d.js", b"xx", headers=["Content-Encoding: compress"])
    for raw, reason in ((corrupt, "br"), (unsupported, "unsupported content-encoding 'compress'")):
        decoded = stored_responses.decode_stored_response(raw)
        assert decoded.status == "undecodable"
        assert reason in decoded.reason
        assert decoded.rebuilt() == raw


def test_a_file_without_a_response_block_is_passed_through():
    index = b"/engagements/eng/bodies/response/app.example.com/x.txt https://app.example.com/a.js (200 OK)\n"
    decoded = stored_responses.decode_stored_response(index)
    assert decoded.status == "unparsed"
    assert decoded.rebuilt() == index


# --------------------------------------------------------------------------- #
# js-mining mines the decoded corpus
# --------------------------------------------------------------------------- #


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _host_path(tmp_path: Path, container_path: str) -> Path:
    return tmp_path / container_path[len("/engagements/eng/"):]


def test_js_mining_runs_every_miner_over_decoded_bodies(monkeypatch, tmp_path, capsys):
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": ["*.example.com"]}), encoding="utf-8")
    src = tmp_path / "urls.txt"
    src.write_text(
        "https://app.example.com/assets/app.js\nhttps://app.example.com/assets/bad.js\n",
        encoding="utf-8",
    )
    seen: dict[str, Path] = {}

    def fake_kali(cmd, **kwargs):
        tool = kwargs.get("tool_name")
        if tool == "httpx":
            bodies = _host_path(tmp_path, cmd[cmd.index("-store-response-dir") + 1])
            host_dir = bodies / "response" / "app.example.com"
            host_dir.mkdir(parents=True, exist_ok=True)
            (host_dir / "aaa.txt").write_bytes(_stored(
                "https://app.example.com/assets/app.js",
                brotli.compress(JS_SOURCE),
                headers=["Content-Encoding: br"],
            ))
            (host_dir / "bbb.txt").write_bytes(_stored(
                "https://app.example.com/assets/bad.js",
                b"\xff\xfe not brotli",
                headers=["Content-Encoding: br"],
            ))
        elif tool in {"jsluice", "trufflehog"}:
            script = cmd[-1]
            seen[tool] = _host_path(tmp_path, script.split()[2 if tool == "trufflehog" else 1].strip("'"))
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(js_mining, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(js_mining, "kali_exec", fake_kali)
    monkeypatch.setattr(js_mining.ingest_endpoints, "run", lambda ns: None)

    out = io.StringIO()
    with redirect_stdout(out):
        returned = js_mining.run(SimpleNamespace(engagement_dir=str(tmp_path), urls_file=str(src)))
    summary = json.loads(out.getvalue())
    err = capsys.readouterr().err

    mine = tmp_path / "scans" / "web-discovery" / "js-mining"
    decoded_dir = mine / "bodies-decoded"
    assert seen["jsluice"] == decoded_dir
    assert seen["trufflehog"] == decoded_dir
    mirrored = (decoded_dir / "response" / "app.example.com" / "aaa.txt").read_bytes()
    assert JS_SOURCE in mirrored
    # The raw capture is kept as captured.
    assert JS_SOURCE not in (mine / "bodies" / "response" / "app.example.com" / "aaa.txt").read_bytes()

    endpoints = (mine / "js_endpoints.txt").read_text(encoding="utf-8")
    assert "https://app.example.com/api/v1/acme-orders" in endpoints

    assert summary["undecodable_bodies"] == 1
    assert summary["body_decoding"]["decoded"] == {"br": 1}
    assert summary["body_decoding"]["undecodable"][0]["file"].endswith("bbb.txt")
    assert returned == summary
    assert "1 stored body could not be decoded" in err
    assert "bbb.txt" in err


def test_js_mining_resolves_relative_jsluice_urls_against_their_source(monkeypatch, tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": ["*.example.com"]}), encoding="utf-8")
    src = tmp_path / "urls.txt"
    src.write_text("https://app.example.com/assets/app.js\n", encoding="utf-8")

    def fake_kali(cmd, **kwargs):
        tool = kwargs.get("tool_name")
        if tool == "httpx":
            bodies = _host_path(tmp_path, cmd[cmd.index("-store-response-dir") + 1])
            host_dir = bodies / "response" / "app.example.com"
            host_dir.mkdir(parents=True, exist_ok=True)
            (host_dir / "aaa.txt").write_bytes(_stored(
                "https://app.example.com/assets/app.js", b"// js", headers=[],
            ))
        elif tool == "jsluice":
            mine = tmp_path / "scans" / "web-discovery" / "js-mining"
            filename = "/engagements/eng/scans/web-discovery/js-mining/bodies-decoded/response/app.example.com/aaa.txt"
            rows = [
                {"url": "app.css", "filename": filename},
                {"url": "/api/v1/acme-orders", "filename": filename},
                {"url": "aura.js"},
                {"url": "https://app.example.com/absolute", "filename": filename},
            ]
            (mine / "jsluice.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(js_mining, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(js_mining, "kali_exec", fake_kali)
    monkeypatch.setattr(js_mining.ingest_endpoints, "run", lambda ns: None)
    with redirect_stdout(io.StringIO()):
        js_mining.run(SimpleNamespace(engagement_dir=str(tmp_path), urls_file=str(src), no_secrets=True))

    endpoints = (tmp_path / "scans" / "web-discovery" / "js-mining" / "js_endpoints.txt"
                 ).read_text(encoding="utf-8").split()
    assert "https://app.example.com/assets/app.css" in endpoints
    assert "https://app.example.com/api/v1/acme-orders" in endpoints
    assert "https://app.example.com/absolute" in endpoints
    # No source file to resolve against: kept as-is so ingest counts it relative.
    assert "aura.js" in endpoints
    assert not any(e.startswith("https://app.css") for e in endpoints)


def test_gau_js_endpoints_reads_the_decoded_body(tmp_path):
    body = tmp_path / "aaa.txt"
    body.write_bytes(_stored(
        "https://app.example.com/assets/app.js",
        brotli.compress(JS_SOURCE),
        headers=["Content-Encoding: br"],
    ))
    payload, status, _reason = gau_js_endpoints._read_js_payload(body)
    assert status == "decoded"
    assert "/api/v1/acme-orders" in payload


def test_gau_secrets_scans_the_decoded_mirror(monkeypatch, tmp_path, capsys):
    work = tmp_path / "scans" / "gau" / "acme.example" / "key"
    bodies = work / "bodies" / "response" / "app.example.com"
    bodies.mkdir(parents=True)
    (bodies / "aaa.txt").write_bytes(_stored(
        "https://app.example.com/assets/app.js",
        brotli.compress(JS_SOURCE),
        headers=["Content-Encoding: br"],
    ))
    paths = SimpleNamespace(
        bodies_dir=work / "bodies",
        work_dir=work,
        container_work_dir="/engagements/eng/scans/gau/acme.example/key",
    )
    commands: list[str] = []

    def fake_kali(cmd, **kwargs):
        commands.append(cmd[-1])
        return SimpleNamespace(return_code=0, stderr_path="")

    monkeypatch.setattr(gau_secrets, "kali_exec", fake_kali)
    decode_summary = gau_secrets._decode_bodies(paths)
    gau_secrets._run_trufflehog(
        paths, cfg=_cfg(tmp_path),
        args=SimpleNamespace(verify=False, target="acme.example", phase="recon", timeout=60),
    )

    assert decode_summary["undecodable_bodies"] == 0
    assert decode_summary["body_decoding"]["decoded"] == {"br": 1}
    mirrored = work / "bodies-decoded" / "response" / "app.example.com" / "aaa.txt"
    assert JS_SOURCE in mirrored.read_bytes()
    assert commands[0].startswith(
        "trufflehog filesystem /engagements/eng/scans/gau/acme.example/key/bodies-decoded "
    )
