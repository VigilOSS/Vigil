"""vigil assess kali browser — headless chromium render of one URL via selenium.

The trustworthy-signal recovery for a curl/httpx run that the WAF-challenge
detector flagged (``KaliResult.status='waf_challenge'``): drive a real headless
Chromium inside the runtime container, let it execute the page's JS (which clears
most JS bot-challenges), and return the ORIGIN HTTP status + the final rendered
DOM + a screenshot path. The run is audited like every other kali verb (pre-exec
command-runs POST + finalize PATCH) because it reaches the target.

Implementation: the command builds a ``python3 -c <driver> <url> <screenshot>
<dom> <page_timeout> <settle> <wait_selector> <required_headers_json> <eval_js>``
argv and hands it to ``kali_exec`` (so audit, output spilling, and the timeout
kill-cascade are all reused verbatim). The driver itself is a self-contained
selenium script
that runs inside the container. Reliability is LOAD-BEARING — an unreliable browser
plus the over-eager detector would strand real surfaces in reprobe limbo — so the
driver uses ``--no-sandbox``, explicit waits, a bounded page-load timeout, and
degrades to a best-effort JSON result (DOM/screenshot still captured) rather than
crashing when one capture step fails.

Program-mandated attribution headers (e.g. BugCrowd's ``X-Bug-Bounty: <handle>``)
must ride EVERY in-scope HTTP request, including this WAF-recovery navigation.
``kali_exec``'s central ``-H`` injector can't reach a Selenium-driven Chrome (a
``tool_name='browser'`` argv has no ``-H`` flag — the injector just WARNs and sets
nothing), so the verb resolves the engagement's ``required_headers`` itself and
threads them (JSON-encoded) into the driver, which sets them on the chromium
session via the Chrome DevTools Protocol (``Network.setExtraHTTPHeaders``) BEFORE
``driver.get()`` — so the rendered navigation carries the same attribution header
the curl/httpx probes inject.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from assess.lib.client import AssessError
from assess.lib.config import resolve_engagement_dir
from assess.lib.kali import (
    add_required_kali_flags,
    emit_result,
    kali_args_to_kwargs,
    kali_exec,
)
from assess.lib.kali_output import _required_headers


# Self-contained selenium driver run as ``python3 -c <this> <argv...>`` INSIDE
# the runtime container. Positional argv (after the ``-c`` body):
#   1 url  2 screenshot_path  3 dom_path  4 page_timeout  5 settle  6 wait_selector
#   7 required_headers_json (JSON object of attribution+operator headers; "{}" when none)
#   8 eval_js (optional operator JS evaluated in the page after settle; "" = skip)
# Paths are engagement-relative; the container working dir is the engagement
# root, so they land in the bind-mounted engagement tree on the host. The driver
# prints ONE JSON object to stdout (origin http_status, final_url, title,
# dom_length, screenshot/dom paths, a bounded ``console`` array of browser-console
# / JS-error entries, an optional ``eval_result``, plus any per-step *_warning)
# and exits 0 on a successful render, non-zero only when the browser could not be
# launched at all.
_BROWSER_DRIVER = r'''
import json, os, sys, time

def _emit(obj, code):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")
    sys.stdout.flush()
    sys.exit(code)

url = sys.argv[1] if len(sys.argv) > 1 else ""
screenshot_path = sys.argv[2] if len(sys.argv) > 2 else "scans/browser/render.png"
dom_path = sys.argv[3] if len(sys.argv) > 3 else "scans/browser/render.html"
page_timeout = float(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else 30.0
settle = float(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else 2.0
wait_selector = sys.argv[6] if len(sys.argv) > 6 else ""

# Program-mandated attribution headers (e.g. ``X-Bug-Bounty: <handle>``) passed
# JSON-encoded by the host CLI. They are set on the chromium session via CDP
# before navigation so this WAF-recovery render carries the same attribution
# header the curl/httpx probes inject. A missing/blank/malformed value degrades
# to no extra headers (never crashes the render).
extra_headers = {}
raw_headers = sys.argv[7] if len(sys.argv) > 7 else ""
if raw_headers:
    try:
        _parsed = json.loads(raw_headers)
        if isinstance(_parsed, dict):
            extra_headers = {
                str(k): str(v) for k, v in _parsed.items() if str(k).strip()
            }
    except Exception:
        extra_headers = {}

# Optional operator JS evaluated in the rendered page AFTER settle (argv[8]).
# LLM-friendly DOM/execution introspection e.g. "document.title" or a stored-XSS
# execution sentinel like "window.__xss_fired". Blank = skip.
eval_js = sys.argv[8] if len(sys.argv) > 8 else ""

if not url:
    _emit({"error": "no url supplied to browser driver"}, 2)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except Exception as exc:
    _emit({"error": "selenium import failed: %r" % (exc,)}, 3)

for d in (os.path.dirname(screenshot_path), os.path.dirname(dom_path)):
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass

opts = Options()
opts.add_argument("--headless=new")
opts.add_argument("--no-sandbox")
opts.add_argument("--disable-dev-shm-usage")
opts.add_argument("--disable-gpu")
opts.add_argument("--window-size=1366,900")
opts.add_argument("--ignore-certificate-errors")
opts.add_argument("--disable-blink-features=AutomationControlled")
opts.set_capability(
    "goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"}
)
for binloc in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"):
    if os.path.exists(binloc):
        opts.binary_location = binloc
        break

service = None
for drvpath in ("/usr/bin/chromedriver", "/usr/lib/chromium/chromedriver",
                "/usr/lib/chromium-browser/chromedriver", "/usr/local/bin/chromedriver"):
    if os.path.exists(drvpath):
        service = Service(executable_path=drvpath)
        break

try:
    driver = webdriver.Chrome(options=opts, service=service) if service \
        else webdriver.Chrome(options=opts)
except Exception as exc:
    _emit({"error": "chrome launch failed: %r" % (exc,)}, 4)

result = {"url": url, "screenshot": screenshot_path, "dom_path": dom_path}
try:
    try:
        driver.set_page_load_timeout(page_timeout)
    except Exception:
        pass
    # Set the program attribution header(s) on the chromium session over CDP
    # BEFORE navigating, so the main-document request (and every sub-request)
    # carries them — matching the -H the curl/httpx probes inject. Enable the
    # Network domain first (required for setExtraHTTPHeaders to take effect).
    if extra_headers:
        try:
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd(
                "Network.setExtraHTTPHeaders", {"headers": extra_headers}
            )
        except Exception as exc:
            result["header_warning"] = (
                "could not set required attribution header(s) %r: %r"
                % (sorted(extra_headers), exc)
            )
    try:
        driver.get(url)
    except Exception as exc:
        result["nav_warning"] = "%r" % (exc,)
    if wait_selector:
        try:
            WebDriverWait(driver, page_timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, wait_selector))
            )
        except Exception as exc:
            result["wait_warning"] = "selector %r not present: %r" % (wait_selector, exc)
    else:
        try:
            time.sleep(settle)
        except Exception:
            pass
    # Origin HTTP status of the main document from the CDP performance log.
    status = None
    try:
        for entry in driver.get_log("performance"):
            try:
                msg = json.loads(entry["message"])["message"]
            except Exception:
                continue
            if msg.get("method") != "Network.responseReceived":
                continue
            params = msg.get("params", {})
            if params.get("type") != "Document":
                continue
            resp = params.get("response", {})
            rstatus = resp.get("status")
            ru = resp.get("url", "")
            if status is None:
                status = rstatus
            if ru and (ru == url or ru.rstrip("/") == url.rstrip("/")):
                status = rstatus
                break
    except Exception as exc:
        result["status_warning"] = "%r" % (exc,)
    result["http_status"] = status
    try:
        result["final_url"] = driver.current_url
    except Exception:
        result["final_url"] = url
    try:
        result["title"] = driver.title
    except Exception:
        result["title"] = ""
    # Operator JS eval (optional) — run AFTER settle so page/app JS has executed.
    # Forgiving: try as a bare expression (auto-``return``) first, then as a full
    # statement body. Coerce a non-JSON-serializable return (e.g. a WebElement) to
    # its repr so it can never crash the final emit.
    if eval_js:
        try:
            try:
                _val = driver.execute_script("return (" + eval_js + ")")
            except Exception:
                _val = driver.execute_script(eval_js)
            try:
                json.dumps(_val)
                result["eval_result"] = _val
            except (TypeError, ValueError):
                result["eval_result"] = repr(_val)
        except Exception as exc:
            result["eval_warning"] = "%r" % (exc,)
    # Browser console + JS errors (uncaught exceptions, CSP violations, and any
    # console.* the page or a stored-XSS sentinel emitted). Captured after eval so
    # eval's own console output is included; bounded to the last 200 entries so a
    # noisy page cannot blow up the emitted JSON.
    try:
        _entries = driver.get_log("browser") or []
        result["console"] = [
            {"level": e.get("level"), "message": e.get("message"),
             "timestamp": e.get("timestamp")}
            for e in _entries[-200:]
        ]
    except Exception as exc:
        result["console_warning"] = "%r" % (exc,)
    dom = ""
    try:
        dom = driver.page_source or ""
    except Exception as exc:
        result["dom_warning"] = "%r" % (exc,)
    result["dom_length"] = len(dom)
    try:
        with open(dom_path, "w", encoding="utf-8") as fh:
            fh.write(dom)
    except Exception as exc:
        result["dom_write_warning"] = "%r" % (exc,)
    try:
        driver.save_screenshot(screenshot_path)
        result["screenshot_ok"] = True
    except Exception as exc:
        result["screenshot_ok"] = False
        result["screenshot_warning"] = "%r" % (exc,)
finally:
    try:
        driver.quit()
    except Exception:
        pass

_emit(result, 0)
'''


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "browser",
        help="Render a URL with headless chromium (selenium) in the runtime and "
        "return origin status + final DOM + screenshot. Recovery for WAF-flagged runs.",
    )
    add_required_kali_flags(p)
    p.add_argument("url", nargs="?", default="", help="Target URL to render (positional).")
    p.add_argument(
        "--screenshot",
        dest="screenshot",
        default="",
        help="Engagement-relative screenshot output path "
        "(default scans/browser/<host>-<id>.png).",
    )
    p.add_argument(
        "--dom-out",
        dest="dom_out",
        default="",
        help="Engagement-relative rendered-DOM output path "
        "(default scans/browser/<host>-<id>.html).",
    )
    p.add_argument(
        "--wait-selector",
        dest="wait_selector",
        default="",
        help="CSS selector to wait for (explicit wait) before capture. "
        "Omit to fall back to --settle.",
    )
    p.add_argument(
        "--page-timeout",
        dest="page_timeout",
        type=float,
        default=30.0,
        help="Per-page load + explicit-wait timeout in seconds (default 30).",
    )
    p.add_argument(
        "--settle",
        dest="settle",
        type=float,
        default=2.0,
        help="Extra settle wait after load when no --wait-selector is given "
        "(seconds, default 2).",
    )
    p.add_argument(
        "--eval",
        dest="eval_js",
        default="",
        help="Optional JS to evaluate in the rendered page AFTER settle and "
        "return in the result as ``eval_result`` (e.g. \"document.title\" or a "
        "stored-XSS execution sentinel like \"window.__xss_fired\"). A bare "
        "expression is auto-returned; a full statement body may use ``return``.",
    )
    p.add_argument(
        "--header",
        dest="extra_headers",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra request header to set on the render via CDP (repeatable, "
        "e.g. --header 'X-Debug: 1'). Program attribution headers are always "
        "applied and CANNOT be overridden or stripped by this flag.",
    )
    p.set_defaults(func=run)


def _safe_slug(url: str) -> str:
    """Filesystem-safe stem derived from the URL host (fallback 'target')."""
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        host = ""
    host = host or "target"
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def _parse_header_args(values: list[str]) -> dict[str, str]:
    """Parse repeatable ``--header NAME:VALUE`` flags into a name→value dict.

    Splits on the FIRST colon and trims surrounding whitespace (so both
    ``X-Debug: 1`` and ``X-Debug:1`` parse). A flag with no colon or an empty
    name is skipped rather than raising — a malformed flag degrades to "no extra
    header" instead of failing the render.
    """
    out: dict[str, str] = {}
    for raw in values or []:
        if not raw or ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name:
            continue
        out[name] = value.strip()
    return out


def _resolve_required_headers(args) -> dict[str, str]:
    """Program-mandated attribution headers (e.g. ``{"X-Bug-Bounty": "<handle>"}``)
    for this engagement, or ``{}`` when none are configured / the engagement dir
    cannot be resolved.

    ``kali_exec`` injects ``required_headers`` only into ``-H``-capable CLI tools;
    for the browser verb (``tool_name='browser'``) it just WARNs and sets nothing,
    so the Selenium-driven Chrome would otherwise omit the attribution header every
    curl/httpx probe carries — an in-scope request that violates program
    attribution rules and may observe a different response. We resolve the headers
    here and the driver sets them on the chromium session via CDP before
    navigation.

    Resolution honours the same precedence as every other verb (``--engagement-dir``
    > ``$ENGAGEMENT_DIR`` > cwd ``scope.json``); ``_required_headers`` then applies
    the SAME string→string filtering as the kali_exec / host-route injectors (only
    ``str`` name → ``str`` value pairs survive). An unresolvable engagement degrades
    quietly to ``{}`` rather than failing the render.
    """
    try:
        eng_dir = resolve_engagement_dir(getattr(args, "engagement_dir", None))
    except SystemExit:
        return {}
    return _required_headers(Path(eng_dir))


def run(args) -> None:
    url = (args.url or "").strip()
    if not url:
        print("browser: pass a <url> to render", file=sys.stderr)
        raise AssessError("missing <url>")

    token = uuid.uuid4().hex[:8]
    stem = f"scans/browser/{_safe_slug(url)}-{token}"
    screenshot = (args.screenshot or "").strip() or f"{stem}.png"
    dom_out = (getattr(args, "dom_out", "") or "").strip() or f"{stem}.html"
    wait_selector = getattr(args, "wait_selector", "") or ""
    page_timeout = float(getattr(args, "page_timeout", 30.0))
    settle = float(getattr(args, "settle", 2.0))

    print(
        f"browser: rendering {url} -> screenshot={screenshot} dom={dom_out}",
        file=sys.stderr,
    )

    # Program attribution headers (e.g. X-Bug-Bounty) — set on the chromium
    # session via CDP inside the driver, since kali_exec's -H injector can't
    # reach a Selenium navigation. Merged with any operator --header values;
    # required headers WIN the merge so attribution can never be stripped or
    # overridden. JSON-encoded so they thread safely through argv ("{}" when none).
    req_headers = _resolve_required_headers(args)
    operator_headers = _parse_header_args(getattr(args, "extra_headers", []) or [])
    merged_headers = {**operator_headers, **req_headers}
    headers_json = json.dumps(merged_headers, sort_keys=True)
    if req_headers:
        print(
            "browser: applying program attribution header(s) "
            f"{', '.join(sorted(req_headers))} to the chromium session via CDP.",
            file=sys.stderr,
        )
    if operator_headers:
        print(
            "browser: applying operator --header(s) "
            f"{', '.join(sorted(operator_headers))} via CDP.",
            file=sys.stderr,
        )

    eval_js = (getattr(args, "eval_js", "") or "").strip()

    cmd: list[str] = [
        "python3",
        "-c",
        _BROWSER_DRIVER,
        url,
        screenshot,
        dom_out,
        str(page_timeout),
        str(settle),
        wait_selector,
        headers_json,
        eval_js,
    ]

    result = kali_exec(cmd, tool_name="browser", **kali_args_to_kwargs(args))
    emit_result(result)
