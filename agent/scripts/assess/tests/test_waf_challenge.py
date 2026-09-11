"""W1 — WAF/bot-challenge detector + kali_exec wiring (the trustworthy-signal substrate).

Covers the WAF guard in three layers, with the kali_exec tests exercising the
REAL production header-availability (NOT a hand-fed ``headers=dict``, which never
happens in prod and gave the original tests false confidence):

1. ``kali_output.detect_waf_challenge`` — a real HTTP exchange that returned a
   vendor interstitial / bot-challenge (Cloudflare 'Just a moment', Akamai
   'Access Denied', Imperva 'Pardon Our Interruption') OR a renamed-marker page
   whose SHAPE is a JS-only challenge shell. The fail-safe direction is to lean
   to flagging, BUT a static SPA that merely mentions a CDN (in a comment or via
   an edge header at a non-block status) must NOT be flagged.

2. ``kali_output.extract_probe_response_headers`` — the production header source.
   The curl liveness probe runs ``-sS`` (body only, NO headers), so the original
   ``detect_waf_challenge(stdout, stderr, None)`` was blind to every header-only
   marker. This recovers headers where they ARE available: httpx ``-json`` stdout
   JSON, and a curl ``-i``/``-D -`` header dump prepended to stdout.

3. ``kali.kali_exec`` end-to-end (mocked subprocess + AssessmentClient) — a WAF
   body/headers surface ``KaliResult.status='waf_challenge'`` (so the run is never
   recorded as a 404/patched/gated verdict) while the backend PATCH status stays
   inside the enum ('completed'). A clean real response is never over-flagged.

NEW, distinctly-named test file under the assess test tree; it reuses the
suite-wide ``conftest.py`` sys.path insertion and forces the runtime so the
CR-36 resolver pin never interferes.
"""
from __future__ import annotations

import importlib
import json
from types import ModuleType, SimpleNamespace

import pytest

from assess.lib import kali_output as ko


# --------------------------------------------------------------------------- #
# Fixture challenge bodies
# --------------------------------------------------------------------------- #

# Cloudflare 'Just a moment...' interstitial (JS challenge). Named markers:
# 'Just a moment', cf-chl, jschl_vc, __cf_chl.
_CLOUDFLARE_BODY = """<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1"></script></head>
<body><div class="main-wrapper"><h1>Checking your browser before accessing</h1>
<form id="challenge-form" action="/?__cf_chl_f_tk=abc" method="POST">
<input type="hidden" name="jschl_vc" value="deadbeef"/>
<input type="hidden" name="cf_chl_opt" value="x"/></form>
<script>window._cf_chl_opt={cType:'managed'};</script></div></body></html>"""

# Akamai Access-Denied / Reference error page + _abck bot-manager cookie + Server.
_AKAMAI_BODY = """<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD>
<BODY><H1>Access Denied</H1>You don't have permission to access "http://x/" on this server.<P>
Reference&#32;&#35;18.abcd1234.1700000000.deadbeef</P></BODY></HTML>"""
_AKAMAI_HEADERS = {
    "Server": "AkamaiGHost",
    "Set-Cookie": "_abck=ABCD~-1~deadbeef~-1; Domain=.x.com; Path=/",
    "Mime-Version": "1.0",
}

# NEGATIVE: normal Akamai Bot Manager session cookies on a benign, non-challenge
# response. ak_bmsc/bm_sz/_abck (and the AkamaiGHost banner) ride ~every
# Akamai-fronted response, challenge or not, so their mere presence must NOT
# flag. The _abck validation field (2nd ~-field) here is 0 = PASSED sensor; the
# later -1 fields are normal and must not trip the sensor-unvalidated sentinel.
_AKAMAI_BENIGN_SESSION_HEADERS = {
    "Server": "AkamaiGHost",
    "Set-Cookie": (
        "ak_bmsc=7F3C9A21D4B8E6; bm_sz=8B2Eopaquevalue; "
        "_abck=7A4C8D~0~YWJjZGVm~-1~-1~1700000000~2; Path=/"
    ),
}

# Imperva/Incapsula 'Pardon Our Interruption' + reese84 / incap_ses / X-Iinfo.
_IMPERVA_BODY = """<html style="height:100%"><head><META NAME="ROBOTS" CONTENT="NOINDEX, NOFOLLOW">
<title>Pardon Our Interruption</title>
<script src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3"></script></head>
<body><iframe src="/_Incapsula_Resource?CWUDNSAI=24"></iframe>
<script>(function(){var z="reese84";})();</script></body></html>"""
_IMPERVA_HEADERS = {
    "Set-Cookie": "incap_ses_123_456=abc; visid_incap_456=def",
    "X-Iinfo": "1-23456789-0 0CNN RT(1700000000) q(0 0 0 -1) r(0 0)",
}

# Generic challenge SHAPE: a RENAMED vendor marker (none of the named needles),
# a JS-only shell with no real app content, a CDN/edge header, and a 403 status.
# This is the path that stops a renamed marker silently reverting to
# "challenge read as a verdict".
_GENERIC_SHAPE_BODY = """<!DOCTYPE html><html><head><meta charset="utf-8">
<script>setTimeout(function(){document.location.reload();},5000);</script></head>
<body><noscript>Please enable JavaScript to continue.</noscript></body></html>"""
_GENERIC_SHAPE_HEADERS = {
    "Server": "acme-edge",
    "X-CDN": "acme-shield-bot-defense",
    "status": "403",
}

# NEGATIVE: a real application body with substantial app content and NO WAF
# marker. Even served behind a CDN (cf-ray present) it must NOT be flagged.
_REAL_APP_BODY = """<!DOCTYPE html><html lang="en"><head><title>Acme Dashboard</title></head>
<body><header><nav><a href="/home">Home</a><a href="/billing">Billing</a>
<a href="/settings">Settings</a></nav></header>
<main><h1>Welcome back, Jordan</h1>
<section class="summary"><p>You have 3 unread messages and 2 pending invoices.</p>
<p>Your subscription renews on the 14th. Current plan: Team (12 seats).</p>
<table><tr><th>Invoice</th><th>Amount</th><th>Status</th></tr>
<tr><td>#1042</td><td>$420.00</td><td>Paid</td></tr>
<tr><td>#1043</td><td>$420.00</td><td>Due</td></tr></table>
</section></main><footer>(c) 2026 Acme Corp. All rights reserved.</footer>
<script src="/static/app.bundle.js"></script></body></html>"""
_REAL_APP_HEADERS = {"Server": "cloudflare", "cf-ray": "8abc1234-LHR", "status": "200"}

# NEGATIVE: a legit small client-rendered SPA shell. It SHIPS a bundle <script>,
# carries almost no visible text, AND its source has a build comment mentioning a
# CDN — exactly the false positive the old "body substring is enough" pass tripped
# on. There is no client redirect and no block status, so it must NOT be flagged.
_LEGIT_SPA_BODY = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Acme</title><!-- built and deployed on cloudflare pages -->
<script src="/static/app.bundle.js" defer></script></head>
<body><div id="root"></div><noscript>Please enable JavaScript to run this app.</noscript></body></html>"""

# A renamed-vendor 403 JS-only challenge as it arrives over curl ``-i``: a status
# line + header block (none of which name a known CDN/edge) prepended to a small
# JS-redirecting shell. The header-less ``curl -sS`` shape pass could only ever
# see the body; with the dumped status line it now leans to a challenge on the
# 403 alone (fail-safe direction).
_RENAMED_403_CURL_I = (
    "HTTP/2 403\r\n"
    "server: someedge\r\n"
    "content-type: text/html; charset=utf-8\r\n"
    "cache-control: no-store, max-age=0\r\n"
    "x-request-id: 7f3c9a21d4\r\n"
    "\r\n"
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<script>setTimeout(function(){window.location.reload();},2500);</script></head>"
    "<body><noscript>Please enable JavaScript.</noscript></body></html>"
)

# An httpx ``-json`` stdout line for a HEADER-ONLY Akamai bot-challenge: the body
# is not in the JSON, the markers ride the structured ``header`` map + ``webserver``
# field — exactly what the production liveness pass (-web-server -status-code -json)
# surfaces and the old ``headers=None`` call could not thread.
_HTTPX_AKAMAI_JSON = json.dumps(
    {
        "url": "https://api.example.com",
        "input": "api.example.com",
        "status_code": 403,
        "webserver": "AkamaiGHost",
        "header": {
            "Set-Cookie": "_abck=ABCD~-1~deadbeef~-1; bm_sz=opaque",
            "Server": "AkamaiGHost",
        },
        "title": "",
        "host": "203.0.113.7",
    }
)

# An httpx ``-json`` stdout line for a clean 200 origin app (no WAF marker).
_HTTPX_CLEAN_JSON = json.dumps(
    {
        "url": "https://app.example.com",
        "input": "app.example.com",
        "status_code": 200,
        "webserver": "nginx",
        "header": {"Server": "nginx", "Content-Type": "text/html"},
        "title": "Acme Dashboard",
        "host": "198.51.100.4",
    }
)


# --------------------------------------------------------------------------- #
# 1. detect_waf_challenge — named vendor signatures
# --------------------------------------------------------------------------- #


def test_detect_cloudflare_just_a_moment_is_flagged():
    is_waf, reason = ko.detect_waf_challenge(_CLOUDFLARE_BODY, "", None)
    assert is_waf is True
    assert "cloudflare" in reason.lower()


def test_cloudfront_s3_403_without_origin_request_id_is_an_edge_block() -> None:
    is_waf, reason = ko.detect_waf_challenge(
        "<Error><Code>AccessDenied</Code><Message>Request blocked.</Message></Error>",
        "",
        {
            "status_code": "403",
            "Server": "AmazonS3",
            "X-Cache": "Error from cloudfront",
            "X-Amz-Cf-Id": "opaque-edge-request",
        },
    )

    assert is_waf is True
    assert "CloudFront/S3 edge-block envelope" in reason


def test_cloudfront_s3_403_with_origin_request_id_is_not_universally_a_waf() -> None:
    is_waf, reason = ko.detect_waf_challenge(
        '{"message":"Forbidden"}',
        "",
        {
            "status_code": "403",
            "Server": "AmazonS3",
            "X-Cache": "Error from cloudfront",
            "X-Request-Id": "origin-observed-request",
        },
    )

    assert is_waf is False
    assert reason == ""


def test_detect_akamai_access_denied_is_flagged():
    is_waf, reason = ko.detect_waf_challenge(_AKAMAI_BODY, "", _AKAMAI_HEADERS)
    assert is_waf is True
    assert "akamai" in reason.lower()


def test_access_denied_without_akamai_marker_is_not_flagged():
    # "Access Denied" is also the default IIS/nginx/app 403 title. A real origin
    # 403 carrying the phrase with NO Akamai cookie/header (and a non-JS-shell
    # body) must be recorded as the app's response, not suppressed as a challenge.
    body = (
        "<html><head><title>Access Denied</title></head><body>"
        "<h1>Access Denied</h1><p>You do not have permission to access this "
        "resource on this server.</p></body></html>"
    )
    is_waf, _ = ko.detect_waf_challenge(body, "", {"Server": "nginx", "status_code": "403"})
    assert is_waf is False


def test_access_denied_corroborated_by_akamai_edge_header_is_flagged():
    # The same phrase WITH an Akamai edge marker present IS a challenge. Uses
    # x-akamai (an edge marker, not itself a standalone signature) so the
    # corroboration path — not the named pass — is what flags it.
    is_waf, reason = ko.detect_waf_challenge(
        "<html><body>Access Denied</body></html>",
        "",
        {"X-Akamai-Request-ID": "abc123", "status_code": "403"},
    )
    assert is_waf is True
    assert "access denied" in reason.lower()


def test_detect_akamai_session_cookie_only_is_not_flagged():
    # Akamai Bot Manager sets ak_bmsc/bm_sz/_abck (and the AkamaiGHost banner) on
    # ~every response it fronts. Their mere presence means "Akamai is in front",
    # NOT "this is a challenge". With a benign body and a normal (passed) _abck
    # validation field, the response must NOT be flagged — it is a genuine origin
    # answer, not a challenge interstitial. (This test previously encoded the bug
    # by asserting the bare cookie NAME flagged.)
    is_waf, reason = ko.detect_waf_challenge(
        "<html><body>ok</body></html>", "", _AKAMAI_BENIGN_SESSION_HEADERS
    )
    assert is_waf is False
    assert reason == ""


def test_api_gateway_403_json_with_akamai_session_cookie_is_not_flagged():
    # Reporter's exact false positive: a genuine API-Gateway 403 JSON verdict that
    # happens to sit behind Akamai (ak_bmsc session cookie set, benign Server). The
    # cookie NAME alone must not suppress a real origin 403 as a challenge — the
    # JSON body is a real verdict, not a JS-only challenge shell.
    body = '{"message":"Missing Authentication Token"}'
    headers = {
        "Server": "openresty",
        "Set-Cookie": "ak_bmsc=7F3C9A21D4B8E6G7H8; Domain=.api.example.com; Path=/",
        "status_code": "403",
    }
    is_waf, _ = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is False


def test_abck_sensor_unvalidated_sentinel_is_flagged():
    # Higher-fidelity Akamai signal (the header-only BLOCK recovery): the _abck
    # cookie VALUE carries the sensor-unvalidated sentinel (-1 in the 2nd ~-field)
    # Akamai holds until the client solves the sensor check. A benign body must
    # still be caught as a challenge via the cookie VALUE, not merely its name.
    headers = {
        "Server": "AkamaiGHost",
        "Set-Cookie": "_abck=8FD2A1B3~-1~xY9zAbC~-1~1700000000~2~0; Path=/",
    }
    is_waf, reason = ko.detect_waf_challenge("<html><body>ok</body></html>", "", headers)
    assert is_waf is True
    assert "akamai" in reason.lower()
    assert "_abck" in reason.lower()


# --------------------------------------------------------------------------- #
# DataDome / PerimeterX / Sucuri — same always-present-fingerprint demotion as
# Akamai/Imperva (consistency: presence != challenge). Their sensor tags/cookies/
# proxy headers ride ~every response, so the NAME alone must not flag; a real
# BLOCK still flags via a block-only needle or the generic challenge SHAPE.
# --------------------------------------------------------------------------- #

def test_datadome_session_cookie_only_is_not_flagged():
    # DataDome sets the `datadome` cookie + `js.datadome.co` sensor on ~every
    # protected response. On a benign page (real content, 200) that presence must
    # NOT flag — it means "DataDome is in front", not "this is a challenge".
    body = (
        "<html><head><script src='https://js.datadome.co/tags.js'></script></head>"
        "<body>" + ("Real application content. " * 30) + "</body></html>"
    )
    headers = {"Server": "nginx", "Set-Cookie": "datadome=AbC123opaque; Path=/"}
    is_waf, reason = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is False
    assert reason == ""


def test_datadome_403_json_verdict_is_not_flagged():
    # A genuine origin 403 JSON that happens to sit behind DataDome (cookie set,
    # benign Server) must not be suppressed as a challenge — no challenge shape,
    # no block-only needle.
    body = '{"message":"Forbidden"}'
    headers = {"Server": "openresty", "Set-Cookie": "datadome=Zz9opaque; Path=/", "status_code": "403"}
    is_waf, _ = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is False


def test_datadome_captcha_block_is_flagged():
    # A real DataDome BLOCK references its captcha host — a block-only needle that
    # is kept in the named table, so the block is still caught.
    body = '{"url":"https://geo.captcha-delivery.com/captcha/?initialCid=abc"}'
    headers = {"Server": "nginx", "Set-Cookie": "datadome=Zz9opaque; Path=/", "status_code": "403"}
    is_waf, reason = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is True
    assert "datadome" in reason.lower()


def test_perimeterx_cookie_only_is_not_flagged():
    # PerimeterX `_px*` cookies + `client.perimeterx.net` sensor ride ~every
    # protected response; the bare presence on a benign page must not flag.
    body = (
        "<html><head><script src='https://client.perimeterx.net/PXxxxx/main.min.js'></script></head>"
        "<body>" + ("Genuine content here. " * 30) + "</body></html>"
    )
    headers = {"Server": "cloudfront", "Set-Cookie": "_pxvid=abc; _pxhd=def; Path=/"}
    is_waf, reason = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is False
    assert reason == ""


def test_perimeterx_block_shape_is_flagged():
    # A real PerimeterX block is a small JS-only shell at a hard block status; the
    # generic-shape pass catches it (edge marker not even required at 403/429/503).
    body = (
        "<html><head><script>window.location.href='/px/captcha';</script></head>"
        "<body></body></html>"
    )
    headers = {"Server": "cloudfront", "Set-Cookie": "_px3=blockedopaque; Path=/", "status_code": "403"}
    is_waf, _ = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is True


def test_sucuri_proxy_header_only_is_not_flagged():
    # Sucuri's `x-sucuri-id` cache/proxy header is on ~every proxied response; a
    # benign page carrying it must not flag.
    body = "<html><body>" + ("Normal page body. " * 30) + "</body></html>"
    headers = {"Server": "Sucuri/Cloudproxy", "X-Sucuri-ID": "12007", "X-Sucuri-Cache": "HIT"}
    is_waf, reason = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is False
    assert reason == ""


def test_sucuri_website_firewall_block_page_is_flagged():
    # The Sucuri block page carries its firewall title — a block-only needle kept
    # in the named table.
    body = "<html><head><title>Sucuri WebSite Firewall - Access Denied</title></head><body>Access Denied</body></html>"
    headers = {"Server": "Sucuri/Cloudproxy", "X-Sucuri-ID": "12007", "status_code": "403"}
    is_waf, reason = ko.detect_waf_challenge(body, "", headers)
    assert is_waf is True
    assert "sucuri" in reason.lower()


def test_detect_imperva_pardon_our_interruption_is_flagged():
    is_waf, reason = ko.detect_waf_challenge(_IMPERVA_BODY, "", _IMPERVA_HEADERS)
    assert is_waf is True
    assert "imperva" in reason.lower()


# --------------------------------------------------------------------------- #
# 2. detect_waf_challenge — generic challenge-SHAPE heuristic
# --------------------------------------------------------------------------- #


def test_detect_generic_challenge_shape_is_flagged():
    """A renamed vendor marker must not silently revert to a verdict: a small,
    JS-only body with no app content behind a CDN/edge header at a 403 is a
    challenge by SHAPE even with no named marker present."""
    is_waf, reason = ko.detect_waf_challenge(_GENERIC_SHAPE_BODY, "", _GENERIC_SHAPE_HEADERS)
    assert is_waf is True
    assert "shape" in reason.lower()


def test_generic_shape_no_corroboration_is_not_flagged():
    # Same JS-only shell but NO edge fingerprint and an UNDETERMINABLE status →
    # not enough signal to call it a WAF challenge (could be a normal tiny SPA
    # bootstrap on origin). With no edge header, no body CDN mention, and no
    # block status, the shape alone must not flag.
    is_waf, _ = ko.detect_waf_challenge(_GENERIC_SHAPE_BODY, "", {"Server": "nginx"})
    assert is_waf is False


def test_generic_shape_hard_block_status_flags_without_edge():
    """Header-less fail-safe: a JS-only no-content shell served with a hard block
    status (403/429/503) leans to a challenge even with no CDN/edge marker at
    all — the direction the curl -sS path must lean when it has only a status."""
    is_waf, reason = ko.detect_waf_challenge(
        _GENERIC_SHAPE_BODY, "", {"status_code": "503", "Server": "nginx"}
    )
    assert is_waf is True
    assert "503" in reason


# --------------------------------------------------------------------------- #
# 2b. detect_waf_challenge — false-positive reductions (point 2 of the fix)
# --------------------------------------------------------------------------- #


def test_legit_spa_with_cdn_comment_is_not_flagged():
    """A body-substring CDN mention (``cloudflare`` in a build comment) on a
    normal SPA that ships a bundle <script>, with no client redirect and no block
    status, must NOT be flagged. This was the original body-only false positive."""
    is_waf, _ = ko.detect_waf_challenge(_LEGIT_SPA_BODY, "", None)
    assert is_waf is False


def test_spa_behind_cdn_header_at_200_no_redirect_is_not_flagged():
    """A JS-only SPA shell at status 200 behind a real CDN/edge HEADER but with
    NO client redirect is the most common legitimate client-rendered-app shape;
    an edge header on its own must not be taken as a challenge."""
    is_waf, _ = ko.detect_waf_challenge(
        _LEGIT_SPA_BODY, "", {"Server": "cloudflare", "cf-ray": "abc", "status_code": "200"}
    )
    assert is_waf is False


def test_edge_header_plus_redirect_is_flagged():
    """The edge path DOES fire when the shell actually bounces the client: a CDN
    header + a scripted redirect + no app content at an allowed status."""
    redirecting = (
        "<!DOCTYPE html><html><head><script>window.location.href='/check';</script>"
        "</head><body><noscript>enable js</noscript></body></html>"
    )
    is_waf, reason = ko.detect_waf_challenge(
        redirecting, "", {"Server": "cloudflare", "cf-ray": "z", "status_code": "200"}
    )
    assert is_waf is True
    assert "header" in reason.lower()


# --------------------------------------------------------------------------- #
# 3. detect_waf_challenge — NEGATIVE (real app body)
# --------------------------------------------------------------------------- #


def test_real_app_body_behind_cdn_is_not_flagged():
    is_waf, reason = ko.detect_waf_challenge(_REAL_APP_BODY, "", _REAL_APP_HEADERS)
    assert is_waf is False
    assert reason == ""


def test_empty_body_is_not_flagged():
    is_waf, _ = ko.detect_waf_challenge("", "", None)
    assert is_waf is False


def test_real_json_api_answer_is_not_flagged():
    # A genuine API verdict (404 JSON) must stand as a verdict.
    is_waf, _ = ko.detect_waf_challenge('{"error":"not found","code":404}', "", {"Server": "nginx"})
    assert is_waf is False


def test_curl_i_header_block_is_not_counted_as_visible_text():
    """A curl ``-i`` dump prepends a header block to the body. The shape pass must
    measure the BODY (header block stripped), so a real (text-heavy) app fetched
    with -i is NOT flagged just because the header block bytes exist."""
    dump = (
        "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n"
        + _REAL_APP_BODY
    )
    is_waf, _ = ko.detect_waf_challenge(dump, "", {"Server": "nginx"})
    assert is_waf is False


# --------------------------------------------------------------------------- #
# 4. extract_probe_response_headers — the production header source
# --------------------------------------------------------------------------- #


def test_extract_headers_from_httpx_json():
    headers = ko.extract_probe_response_headers(
        "httpx", ["httpx", "-u", "https://x", "-json", "-irh"], _HTTPX_AKAMAI_JSON
    )
    assert isinstance(headers, dict)
    assert headers.get("Server") == "AkamaiGHost"
    assert headers.get("status_code") == "403"
    assert "_abck" in headers.get("Set-Cookie", "")


def test_extract_headers_from_curl_dash_i_dump():
    headers = ko.extract_probe_response_headers(
        "curl", ["curl", "-i", "-sS", "https://x"], _RENAMED_403_CURL_I
    )
    assert isinstance(headers, dict)
    assert headers.get("server") == "someedge"
    assert headers.get("cache-control") == "no-store, max-age=0"


@pytest.mark.parametrize(
    ("cmd", "terminal_status", "terminal_reason"),
    [
        (["curl", "-L", "-i", "https://x"], 404, "Not Found"),
        (
            ["curl", "-L", "--dump-header", "-", "https://x"],
            500,
            "Internal Server Error",
        ),
    ],
)
def test_redirected_curl_headers_and_status_come_from_the_terminal_response(
    cmd, terminal_status, terminal_reason
):
    stdout = (
        "HTTP/1.1 302 Found\r\n"
        "Location: https://x/final\r\n"
        "Server: redirect-edge\r\n"
        "\r\n"
        f"HTTP/1.1 {terminal_status} {terminal_reason}\r\n"
        "Server: terminal-origin\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"error":"terminal response"}'
    )

    headers = ko.extract_probe_response_headers("curl", cmd, stdout)

    assert isinstance(headers, dict)
    normalized = {str(key).lower(): value for key, value in headers.items()}
    assert normalized["server"] == "terminal-origin"
    assert "location" not in normalized
    assert ko.extract_http_status(stdout, headers) == terminal_status


def test_extract_headers_curl_sS_body_only_returns_none():
    # The real production curl liveness probe: -sS, body only, NO header block.
    headers = ko.extract_probe_response_headers(
        "curl", ["curl", "-sS", "https://x"], _LEGIT_SPA_BODY
    )
    assert headers is None


def test_extract_headers_httpx_without_json_returns_none():
    headers = ko.extract_probe_response_headers(
        "httpx", ["httpx", "-u", "https://x", "-status-code"], "some text output"
    )
    assert headers is None


def test_extract_headers_non_http_tool_returns_none():
    headers = ko.extract_probe_response_headers("subfinder", ["subfinder", "-d", "x"], "a.x\nb.x")
    assert headers is None


# --------------------------------------------------------------------------- #
# 5. KaliResult carries the new flag (defaults False)
# --------------------------------------------------------------------------- #


def test_kali_result_waf_challenge_defaults_false():
    r = ko.KaliResult(
        run_id=1,
        status="completed",
        return_code=0,
        stdout_path="o",
        stderr_path="e",
        duration_ms=1,
        peak_rss_bytes=None,
        stdout_preview="",
        stderr_preview="",
        timed_out=False,
        partial_results=False,
    )
    assert r.waf_challenge is False
    assert r.waf_challenge_detail == ""


# --------------------------------------------------------------------------- #
# 6. kali_exec end-to-end (mocked subprocess + AssessmentClient)
#    Exercises the REAL production header-availability per tool/argv.
# --------------------------------------------------------------------------- #


def _import(name: str) -> ModuleType:
    return importlib.import_module(name)


def _runtime_linux():
    rr = _import("assess.lib.runtime_route")
    return rr, rr.RuntimeInfo(platform="linux", is_docker_desktop=False, recommended="container")


@pytest.fixture
def fake_engagement(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "2026-06-26-test"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(json.dumps({"hostname": "example.com"}))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(eng_dir))
    monkeypatch.setenv("AGENT_NAME", "vulnerability-analyst")
    monkeypatch.delenv("VIGIL_NO_RESOLVE_PIN", raising=False)
    return eng_dir


class _FakeClient:
    def __init__(self, base_url, engagement_key):
        self.posts: list = []
        self.patches: list = []
        self.decisions: list = []

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return {
            "id": 7,
            "run_uuid": payload.get("run_uuid"),
            "superseded_by_id": None,
        }

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        run_uuid = next(
            posted_payload["run_uuid"]
            for posted_endpoint, posted_payload in self.posts
            if posted_endpoint == "command-runs"
        )
        return {"id": 7, "run_uuid": run_uuid, "status": payload.get("status")}

    def record_decision(self, payload):
        self.decisions.append(payload)
        return {"id": 81}

    def close(self):
        return None


class _Proc:
    def __init__(self, returncode):
        self.pid = 4242
        self._rc = returncode

    def wait(self, timeout=None):
        return self._rc


def _setup(monkeypatch, eng_dir):
    """Wire kali_exec for a container-free run pinned to native Linux (no pin)."""
    kali = _import("assess.lib.kali")
    rr, linux = _runtime_linux()

    monkeypatch.setattr(
        kali,
        "load_config",
        lambda _flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        ),
    )
    client = _FakeClient("http://127.0.0.1:18000", eng_dir.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *a, **k: None)
    rr.reset_runtime_cache()
    monkeypatch.setattr(rr, "detect_runtime", lambda *a, **k: linux)
    return kali, client


def _run_with_stdout(monkeypatch, kali, body: str, *, cmd, tool_name, eng_dir):
    """Drive one kali_exec whose mocked child writes ``body`` to stdout."""
    def fake_popen(argv, **kwargs):
        kwargs["stdout"].write(body.encode("utf-8"))
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)
    return kali.kali_exec(
        cmd,
        technique="RECON",
        intent="liveness probe",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=eng_dir,
        tool_name=tool_name,
    )


def test_kali_exec_waf_challenge_blocks_verdict(monkeypatch, fake_engagement, capsys):
    """A curl probe that comes back with a Cloudflare 'Just a moment' challenge
    body (rc=0) must surface KaliResult.status='waf_challenge' so it is NOT read
    as a verdict, while the backend PATCH status stays inside the enum."""
    kali, client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _CLOUDFLARE_BODY,
        cmd=["curl", "-sS", "https://api.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert result.waf_challenge is True
    assert result.status == "waf_challenge"
    assert result.waf_challenge_detail
    # Backend PATCH status stayed inside the enum (completed — rc=0 real exchange).
    assert client.patches[-1][1]["status"] == "completed"
    assert len(client.decisions) == 1
    decision = client.decisions[0]
    assert decision["kind"] == "egress_decision"
    assert decision["surfaced_to_user"] is True
    assert decision["payload"]["subtype"] == "waf_challenge"
    assert decision["payload"]["verdict"] == "waf_challenge"
    assert decision["payload"]["reason"] == result.waf_challenge_detail
    assert decision["payload"]["artifact_ref"].startswith(
        f"/engagements/{fake_engagement.name}/scans/kali/"
    )
    assert decision["payload"]["provenance"] == {
        "source": "vigil assess kali",
        "detector": "detect_waf_challenge",
        "command_run_id": 7,
        "tool_name": "curl",
        "agent_name": "vulnerability-analyst",
    }
    # Loud stderr line surfaced.
    err = capsys.readouterr().err
    assert "WAF" in err or "challenge" in err.lower()
    assert "NOT a target verdict" in err


def test_kali_exec_header_only_akamai_via_httpx_json_is_flagged(monkeypatch, fake_engagement):
    """PRODUCTION PATH: a header-only Akamai BLOCK (a true challenge, carried by
    the _abck sensor-unvalidated ``~-1~`` value in the httpx -json structured
    header map, NOT by the bare AkamaiGHost/cookie NAME) is caught because
    kali_exec threads the real response headers parsed from stdout. Mere Akamai
    presence (Server: AkamaiGHost + a passed cookie) would NOT flag."""
    kali, client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _HTTPX_AKAMAI_JSON,
        cmd=["httpx", "-u", "https://api.example.com", "-json", "-irh", "-web-server"],
        tool_name="httpx", eng_dir=fake_engagement,
    )
    assert result.waf_challenge is True
    assert "akamai" in result.waf_challenge_detail.lower()
    assert result.status == "waf_challenge"
    assert client.patches[-1][1]["status"] == "completed"


def test_kali_exec_renamed_403_via_curl_i_is_flagged(monkeypatch, fake_engagement):
    """PRODUCTION PATH: a renamed-vendor 403 JS-only shell fetched with curl -i.
    The dumped status line + JS redirect SHAPE lean to a challenge (fail-safe)
    even though no named marker and no known CDN/edge fingerprint is present —
    the case the original edge-marker-required pass missed entirely."""
    kali, _client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _RENAMED_403_CURL_I,
        cmd=["curl", "-i", "-sS", "https://x.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert result.waf_challenge is True
    assert "403" in result.waf_challenge_detail
    assert result.status == "waf_challenge"


def test_kali_exec_legit_spa_curl_sS_not_flagged(monkeypatch, fake_engagement):
    """PRODUCTION PATH: the real curl -sS liveness probe (body only, headers=None)
    on a legit SPA whose source mentions a CDN in a comment must NOT be flagged —
    the original body-substring false positive."""
    kali, _client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _LEGIT_SPA_BODY,
        cmd=["curl", "-sS", "https://app.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert result.waf_challenge is False
    assert result.status == "completed"


def test_kali_exec_clean_httpx_json_not_flagged(monkeypatch, fake_engagement):
    """A clean httpx -json liveness row (200, nginx, real title) is a genuine
    verdict and must not be over-flagged by the threaded-header path."""
    kali, _client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _HTTPX_CLEAN_JSON,
        cmd=["httpx", "-u", "https://app.example.com", "-json", "-web-server"],
        tool_name="httpx", eng_dir=fake_engagement,
    )
    assert result.waf_challenge is False
    assert result.status == "completed"


def test_kali_exec_real_answer_not_waf_flagged(monkeypatch, fake_engagement):
    kali, client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _REAL_APP_BODY,
        cmd=["curl", "-sS", "https://api.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert result.waf_challenge is False
    assert result.status == "completed"
    assert client.decisions == []


def test_kali_exec_browser_tool_never_waf_flagged(monkeypatch, fake_engagement):
    """The recovery tool (browser) must never be WAF-flagged on its own output —
    that would strand the recovery path in a loop. It is not an http prober."""
    kali, _client = _setup(monkeypatch, fake_engagement)
    result = _run_with_stdout(
        monkeypatch, kali, _CLOUDFLARE_BODY,
        cmd=["python3", "-c", "print('x')", "https://api.example.com/"],
        tool_name="browser", eng_dir=fake_engagement,
    )
    assert result.waf_challenge is False
    assert result.status == "completed"


def test_kali_exec_curl_sS_header_only_marker_is_acknowledged_blind_spot(
    monkeypatch, fake_engagement
):
    """LIMITATION (documented): a HEADER-ONLY Akamai BLOCK whose BODY is benign is
    undetectable over a bare curl -sS probe — the marker bytes (the _abck
    sensor-unvalidated ``~-1~`` value) are simply not in stdout. The SAME block IS
    caught when the probe surfaces headers (curl -i), proving the gap is the
    invocation, not the detector. It is the ``~-1~`` challenge STATE, not the bare
    AkamaiGHost/_abck NAME, that flags it."""
    kali, _client = _setup(monkeypatch, fake_engagement)
    benign_body = "<html><body>ok</body></html>"

    # curl -sS: no headers in stdout -> the header-only marker cannot be seen.
    res_sS = _run_with_stdout(
        monkeypatch, kali, benign_body,
        cmd=["curl", "-sS", "https://api.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert res_sS.waf_challenge is False  # acknowledged blind spot

    # curl -i: the same block with the header block present IS caught — via the
    # _abck sensor-unvalidated ``~-1~`` value (2nd ~-field is -1), not the name.
    dump = (
        "HTTP/2 403\r\nServer: AkamaiGHost\r\n"
        "Set-Cookie: _abck=ABCD~-1~deadbeef~-1; Path=/\r\n\r\n" + benign_body
    )
    res_i = _run_with_stdout(
        monkeypatch, kali, dump,
        cmd=["curl", "-i", "-sS", "https://api.example.com/"], tool_name="curl",
        eng_dir=fake_engagement,
    )
    assert res_i.waf_challenge is True
    assert "akamai" in res_i.waf_challenge_detail.lower()
