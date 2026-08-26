"""Audited Playwright/Chromium browser workflow for target application evidence."""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from assess.lib import scope as scope_lib
from assess.lib.client import AssessError
from assess.lib.config import resolve_engagement_dir
from assess.lib.kali import (
    add_required_kali_flags,
    emit_result,
    kali_args_to_kwargs,
    kali_exec,
    prepare_browser_identity_material,
)

_MAX_STEPS = 50
_MAX_STEP_TIMEOUT_MS = 120_000
_ACTIONS = frozenset({"navigate", "click", "fill", "wait", "eval", "assert"})
_WAIT_STATES = ("attached", "visible", "hidden", "detached")
_NAV_WAIT_UNTIL = ("domcontentloaded", "load", "networkidle")
_STEP_KEYS = {
    "navigate": frozenset({"action", "url", "wait_until", "timeout_ms"}),
    "click": frozenset({"action", "selector", "timeout_ms"}),
    "fill": frozenset({"action", "selector", "value", "timeout_ms"}),
    "wait": frozenset({"action", "selector", "state", "timeout_ms"}),
    "eval": frozenset({"action", "script"}),
    "assert": frozenset({"action", "selector", "contains", "equals", "visible", "timeout_ms"}),
}


# Runs under the runtime image's system Python. The complete execution plan is one
# JSON argv value, avoiding shell interpolation and keeping every target URL
# visible in the audited argv before Chromium starts.
_BROWSER_DRIVER = r'''
import hashlib, ipaddress, json, os, re, sys
from urllib.parse import urlsplit

MAX_NETWORK_EVENTS = 500
MAX_CONSOLE_EVENTS = 200
MAX_ROUTE_CANDIDATES = 500

def emit(value, code=0):
    sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    raise SystemExit(code)

def origin(raw):
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    return "%s://%s%s" % (parsed.scheme.lower(), parsed.hostname.lower(), "" if not port or default else ":%d" % port)

raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    cfg = json.loads(raw)
except Exception as exc:
    emit({"error": "invalid browser execution plan: %r" % (exc,)}, 2)
if not isinstance(cfg, dict) or not cfg.get("url"):
    emit({"error": "browser execution plan requires url"}, 2)

try:
    from playwright.sync_api import sync_playwright
except Exception as exc:
    emit({"error": "playwright import failed: %r" % (exc,)}, 3)

for key in ("screenshot", "dom_path", "har_out", "body_dir"):
    value = str(cfg.get(key) or "")
    directory = value if key == "body_dir" else os.path.dirname(value)
    if directory:
        os.makedirs(directory, exist_ok=True)

result = {
    "url": cfg["url"], "screenshot": cfg.get("screenshot"),
    "dom_path": cfg.get("dom_path"), "network": [], "console": [],
    "route_candidates": [], "omitted_attribution_origins": [], "steps": [],
}
network = result["network"]
console = result["console"]
candidate_keys = set()
omitted = set()
required_headers = dict(cfg.get("required_headers") or {})
operator_headers = dict(cfg.get("operator_headers") or {})
identity_headers = dict(cfg.get("identity_headers") or {})
identity_hosts = set(cfg.get("identity_hosts") or [])
attribute_every_origin = cfg.get("attribution_scope") == "all"
allow_entries = list(cfg.get("attribution_allow") or [])
deny_entries = list(cfg.get("attribution_deny") or [])
page_timeout_ms = int(float(cfg.get("page_timeout") or 30) * 1000)

def entry_matches(entry, host):
    entry_host = entry.get("host") or ""
    kind = entry.get("entry_kind")
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry_host, strict=False)
        except ValueError:
            return False
    if kind == "wildcard":
        return host == entry_host or host.endswith("." + entry_host)
    return host == entry_host

def host_admitted(host):
    # Mirrors assess.lib.scope.host_admitted across the container boundary. The
    # host side ships pre-classified entries, so only the final comparison lives
    # here; the denylist still wins. Chromium hands over A-label hostnames, so
    # the shared matcher's IDNA step has nothing left to do. It decides ONE
    # thing: whether a request carries the program attribution header, never
    # whether the request is sent.
    if not host:
        return False
    if not any(entry_matches(entry, host) for entry in allow_entries):
        return False
    return not any(entry_matches(entry, host) for entry in deny_entries)

def add_candidate(request):
    if len(result["route_candidates"]) >= MAX_ROUTE_CANDIDATES:
        return
    parsed = urlsplit(request.url)
    key = (request.method, parsed.scheme, parsed.netloc, parsed.path)
    if key in candidate_keys:
        return
    candidate_keys.add(key)
    result["route_candidates"].append({
        "method": request.method, "origin": origin(request.url),
        "path": parsed.path or "/", "resource_type": request.resource_type,
    })

def on_request(request):
    if len(network) < MAX_NETWORK_EVENTS:
        network.append({
            "event": "request", "method": request.method, "url": request.url,
            "resource_type": request.resource_type,
            "header_names": sorted(str(k).lower() for k in request.headers),
        })
    add_candidate(request)

def on_response(response):
    if len(network) < MAX_NETWORK_EVENTS:
        network.append({
            "event": "response", "url": response.url, "status": response.status,
            "header_names": sorted(str(k).lower() for k in response.headers),
        })
    if not cfg.get("capture_bodies") or response.request.resource_type not in ("document", "xhr", "fetch"):
        return
    try:
        body = response.body()
        cap = int(cfg.get("max_body_bytes") or 262144)
        body = body[:cap]
        digest = hashlib.sha256((response.url + "\0").encode() + body).hexdigest()[:20]
        path = os.path.join(cfg["body_dir"], digest + ".body")
        with open(path, "wb") as fh:
            fh.write(body)
        result.setdefault("bodies", []).append({"url": response.url, "path": path, "bytes": len(body)})
    except Exception as exc:
        result.setdefault("body_warnings", []).append({"url": response.url, "error": repr(exc)})

def route_request(route, request):
    headers = dict(request.headers)
    headers.update(operator_headers)
    request_host = (urlsplit(request.url).hostname or "").lower().rstrip(".")
    # Bearer/custom identity headers are target credentials, not ambient browser
    # headers. They ride only to the hosts this run was explicitly told to visit
    # (the initial URL plus every declared navigate step); cookies use Chromium's
    # native domain/path scoping through context.add_cookies().
    if request_host in identity_hosts:
        headers.update(identity_headers)
    # Program attribution follows the SCOPE boundary, not the document origin. An
    # in-scope sibling host carrying the real testing traffic must be attributed
    # (deconfliction), and a third-party analytics/CDN origin must never see the
    # program handle. Everything is still sent either way.
    if required_headers:
        if attribute_every_origin or host_admitted(request_host):
            headers.update(required_headers)
        else:
            request_origin = origin(request.url)
            if request_origin:
                omitted.add(request_origin)
    route.continue_(headers=headers)

def capture_failure(page, label):
    stem = str(cfg.get("failure_stem") or "scans/browser/failure")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:40]
    png, html = stem + "-" + safe + ".png", stem + "-" + safe + ".html"
    try:
        page.screenshot(path=png, full_page=True)
    except Exception:
        png = ""
    try:
        with open(html, "w", encoding="utf-8") as fh:
            fh.write(page.content())
    except Exception:
        html = ""
    return {"screenshot": png, "dom_path": html}

with sync_playwright() as playwright:
    executable = next((p for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome") if os.path.exists(p)), None)
    try:
        browser = playwright.chromium.launch(
            executable_path=executable, headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
        )
    except Exception as exc:
        emit({"error": "chromium launch failed: %r" % (exc,)}, 4)
    context_options = {"ignore_https_errors": True, "viewport": {"width": 1366, "height": 900}}
    if cfg.get("har_out"):
        context_options.update({"record_har_path": cfg["har_out"], "record_har_mode": "minimal", "record_har_content": "omit"})
    if cfg.get("storage_state"):
        context_options["storage_state"] = cfg["storage_state"]
    context = browser.new_context(**context_options)
    cookies = cfg.get("cookies") or []
    if cookies:
        context.add_cookies(cookies)
    try:
        context.route("**/*", route_request)
    except Exception as exc:
        browser.close()
        emit({"error": "required attribution routing failed before navigation: %r" % (exc,)}, 5)
    page = context.new_page()
    page.on("request", on_request)
    page.on("response", on_response)
    page.on("console", lambda msg: console.append({"type": msg.type, "text": msg.text}) if len(console) < MAX_CONSOLE_EVENTS else None)
    page.on("pageerror", lambda exc: console.append({"type": "pageerror", "text": str(exc)}) if len(console) < MAX_CONSOLE_EVENTS else None)
    failed = False
    try:
        response = page.goto(cfg["url"], wait_until=cfg.get("wait_until") or "domcontentloaded", timeout=page_timeout_ms)
        result["http_status"] = response.status if response else None
        if cfg.get("wait_selector"):
            page.locator(cfg["wait_selector"]).wait_for(state=cfg.get("wait_state") or "attached", timeout=page_timeout_ms)
        # The settle composes with the selector wait instead of replacing it: an
        # XHR can land (selector attached) while the DOM it drives keeps mutating.
        if cfg.get("settle"):
            page.wait_for_timeout(int(float(cfg["settle"]) * 1000))
        if cfg.get("eval_js"):
            result["eval_result"] = page.evaluate(cfg["eval_js"])
        for index, step in enumerate(cfg.get("steps") or []):
            action = step["action"]
            timeout = int(step.get("timeout_ms") or min(page_timeout_ms, 120000))
            record = {"index": index, "action": action, "status": "completed"}
            try:
                if action == "navigate":
                    resp = page.goto(step["url"], wait_until=step.get("wait_until", "domcontentloaded"), timeout=timeout)
                    record["http_status"] = resp.status if resp else None
                elif action == "click":
                    page.locator(step["selector"]).click(timeout=timeout)
                elif action == "fill":
                    page.locator(step["selector"]).fill(step["value"], timeout=timeout)
                elif action == "wait":
                    if step.get("selector"):
                        page.locator(step["selector"]).wait_for(state=step.get("state") or "attached", timeout=timeout)
                    else:
                        page.wait_for_timeout(timeout)
                elif action == "eval":
                    record["result"] = page.evaluate(step["script"])
                elif action == "assert":
                    locator = page.locator(step["selector"])
                    locator.wait_for(state="hidden" if step.get("visible") is False else "visible", timeout=timeout)
                    if "contains" in step or "equals" in step:
                        text = locator.inner_text(timeout=timeout)
                        if "contains" in step and step["contains"] not in text:
                            raise AssertionError("expected selector text to contain %r" % step["contains"])
                        if "equals" in step and step["equals"] != text:
                            raise AssertionError("expected selector text %r, got %r" % (step["equals"], text))
                result["steps"].append(record)
            except Exception as exc:
                record.update({"status": "failed", "error": repr(exc), "artifacts": capture_failure(page, "step-%d-%s" % (index, action))})
                result["steps"].append(record)
                failed = True
                break
        result["final_url"] = page.url
        result["title"] = page.title()
        dom = page.content()
        result["dom_length"] = len(dom)
        with open(cfg["dom_path"], "w", encoding="utf-8") as fh:
            fh.write(dom)
        page.screenshot(path=cfg["screenshot"], full_page=True)
        result["screenshot_ok"] = True
    except Exception as exc:
        result["error"] = repr(exc)
        result["failure_artifacts"] = capture_failure(page, "navigation")
        failed = True
    finally:
        result["omitted_attribution_origins"] = sorted(omitted)
        context.close()
        browser.close()
    emit(result, 6 if failed else 0)
'''


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "browser",
        help="Run an audited, bounded Playwright/Chromium browser workflow.",
    )
    add_required_kali_flags(p)
    p.add_argument("url", nargs="?", default="", help="Initial HTTP(S) URL.")
    p.add_argument("--screenshot", default="", help="Engagement-relative screenshot path.")
    p.add_argument("--dom-out", dest="dom_out", default="", help="Engagement-relative DOM path.")
    p.add_argument(
        "--wait-selector", default="",
        help="CSS selector to await before capture; --settle then applies on top of it.",
    )
    p.add_argument(
        "--wait-state", choices=_WAIT_STATES, default="attached",
        help="Locator state --wait-selector waits for (default attached).",
    )
    p.add_argument(
        "--wait-until", choices=_NAV_WAIT_UNTIL, default="domcontentloaded",
        help="Completion event for the initial navigation (default domcontentloaded).",
    )
    p.add_argument("--page-timeout", type=float, default=30.0)
    p.add_argument(
        "--settle", type=float, default=2.0,
        help="Extra settle wait after the load and any --wait-selector; 0 disables.",
    )
    p.add_argument("--eval", dest="eval_js", default="", help="Evaluate JavaScript after initial load.")
    p.add_argument("--header", dest="extra_headers", action="append", default=[], metavar="NAME:VALUE")
    p.add_argument(
        "--attribution-scope", choices=("scope", "all"), default="scope",
        help=(
            "Which requests carry the program attribution headers: 'scope' (default) "
            "sends them to scope.json-admitted hosts only; 'all' sends them to every "
            "origin the page touches, leaking the program handle to third parties."
        ),
    )
    p.add_argument("--steps-file", default="", help="JSON array of typed browser steps (max 50).")
    p.add_argument(
        "--storage-state",
        default="",
        help="Explicit engagement-relative Playwright storage-state JSON artifact.",
    )
    p.add_argument("--har-out", default="", help="Optional engagement-relative metadata-only HAR path.")
    p.add_argument("--capture-bodies", action="store_true", help="Capture bounded document/XHR/fetch bodies.")
    p.add_argument("--body-dir", default="", help="Engagement-relative body artifact directory.")
    p.add_argument("--max-body-bytes", type=int, default=262_144, help="Maximum bytes stored per body.")
    p.set_defaults(func=run)


def _safe_slug(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        host = ""
    return re.sub(r"[^A-Za-z0-9._-]", "_", host or "target")


def _parse_header_args(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in values or []:
        if not raw or ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        if name.strip():
            out[name.strip()] = value.strip()
    return out


def _http_url(value: Any, *, field: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise AssessError(f"browser {field} is not a valid URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AssessError(f"browser {field} must be an absolute HTTP(S) URL")
    return text


def _artifact_path(value: str, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise AssessError(f"browser {field} must be engagement-relative without '..'")
    return path.as_posix()


def _load_steps(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssessError(f"browser cannot read steps file {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise AssessError("browser steps file must contain a JSON array")
    if len(payload) > _MAX_STEPS:
        raise AssessError(f"browser steps file exceeds the {_MAX_STEPS}-step cap")
    validated: list[dict[str, Any]] = []
    for index, raw in enumerate(payload):
        if not isinstance(raw, dict):
            raise AssessError(f"browser step {index} must be an object")
        action = str(raw.get("action") or "").strip().lower()
        if action not in _ACTIONS:
            raise AssessError(f"browser step {index} has unsupported action {action!r}")
        extras = set(raw) - _STEP_KEYS[action]
        if extras:
            raise AssessError(f"browser step {index} has unsupported fields: {', '.join(sorted(extras))}")
        step = dict(raw)
        step["action"] = action
        if action == "navigate":
            step["url"] = _http_url(step.get("url"), field=f"step {index} url")
            if step.get("wait_until", "domcontentloaded") not in {"commit", "domcontentloaded", "load", "networkidle"}:
                raise AssessError(f"browser step {index} has invalid wait_until")
        if action in {"click", "fill", "assert"} and not str(step.get("selector") or "").strip():
            raise AssessError(f"browser step {index} requires selector")
        if action == "fill" and "value" not in step:
            raise AssessError(f"browser step {index} requires value")
        if action == "wait" and step.get("state", "attached") not in _WAIT_STATES:
            raise AssessError(
                f"browser step {index} state must be one of {', '.join(_WAIT_STATES)}"
            )
        if action == "eval" and not str(step.get("script") or "").strip():
            raise AssessError(f"browser step {index} requires script")
        if action == "assert" and not any(key in step for key in ("contains", "equals", "visible")):
            raise AssessError(f"browser step {index} requires an assertion")
        timeout = step.get("timeout_ms")
        if timeout is not None and (not isinstance(timeout, int) or not 0 < timeout <= _MAX_STEP_TIMEOUT_MS):
            raise AssessError(f"browser step {index} timeout_ms must be 1..{_MAX_STEP_TIMEOUT_MS}")
        validated.append(step)
    return validated


def _load_storage_state(value: str, engagement_dir: Path | None) -> dict[str, Any] | None:
    relative = _artifact_path(value, field="storage-state")
    if not relative:
        return None
    if engagement_dir is None:
        raise AssessError("browser --storage-state requires a resolvable engagement directory")
    root = engagement_dir.resolve()
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise AssessError("browser storage-state artifact must remain inside the engagement")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssessError(f"browser cannot read storage-state artifact {relative}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssessError("browser storage-state artifact must contain a JSON object")
    if not isinstance(payload.get("cookies", []), list) or not isinstance(
        payload.get("origins", []), list
    ):
        raise AssessError("browser storage-state cookies and origins must be JSON arrays")
    return payload


def _engagement_dir(args) -> Path | None:
    try:
        return Path(resolve_engagement_dir(getattr(args, "engagement_dir", None)))
    except (SystemExit, OSError, ValueError):
        return None


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _attribution_entries(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Reduce classified scope entries to what the in-container driver matches on."""
    return [{"entry_kind": entry["entry_kind"], "host": entry["host"]} for entry in entries]


def _scope_attribution(
    engagement_dir: Path | None,
) -> tuple[dict[str, str], list[dict[str, str]], list[dict[str, str]]]:
    """Return ``(required_headers, allow_entries, deny_entries)`` for this run.

    One scope.json read feeds both halves of the attribution decision: which
    headers the program mandates, and which hosts are inside the boundary that
    must carry them. Entries are classified here with the shared scope
    primitives so the driver only performs the final host comparison. An
    unreadable scope yields nothing; a readable scope with an unusable ``hosts``
    list still yields its headers, so ``run`` can refuse rather than navigate a
    mandated-attribution engagement with no resolvable boundary.
    """
    if engagement_dir is None:
        return {}, [], []
    try:
        scope = scope_lib.load_scope(str(engagement_dir), persist_migration=False)
    except (SystemExit, OSError, ValueError):
        return {}, [], []
    headers = scope_lib.required_headers(scope)
    try:
        allow = scope_lib.scope_entries(scope)
        deny = scope_lib.out_of_scope_entries(scope)
    except SystemExit:
        return headers, [], []
    return headers, allow, deny


def _warn_timeout_budget(
    timeout: int, page_timeout: float, settle: float, wait_selector: str
) -> None:
    """WARN before launch when the wrapper ``--timeout`` cannot outlast the driver.

    The driver writes the DOM and screenshot only after the workflow completes and
    Playwright flushes the HAR at context close, so a wrapper kill mid-flight
    yields zero artifacts - a result structurally indistinguishable from a clean
    negative. That is worth saying out loud; it is NOT worth refusing over,
    because the driver budget is a CEILING and not a cost: a page that renders in
    3s finishes inside a 45s --page-timeout, so the tight pairing usually
    completes. Naming both numbers keeps the unfalsifiable outcome visible while
    leaving the run to the caller.
    """
    parts = [f"--page-timeout {page_timeout:g}s to load"]
    budget = page_timeout + settle
    if wait_selector:
        budget += page_timeout
        parts.append(f"{page_timeout:g}s more for --wait-selector")
    parts.append(f"--settle {settle:g}s")
    if timeout > budget:
        return
    print(
        f"browser: WARN --timeout {timeout}s does not outlast this run's worst-case "
        f"in-container budget of {budget:g}s ({' + '.join(parts)}). That budget is a "
        "CEILING, not the expected cost - most pages finish far inside it - but a run "
        "that DOES reach it is killed by the wrapper mid-flight, and the DOM, screenshot "
        "and HAR are all written at the end, so the kill leaves ZERO artifacts and reads "
        f"exactly like a clean negative. Raise --timeout above {budget:g}s to keep a slow "
        "page falsifiable.",
        file=sys.stderr,
    )


def _warn_unattributed_navigations(
    hosts: list[str],
    required_headers: dict[str, str],
    attribution_scope: str,
    allow_entries: list[dict[str, str]],
    deny_entries: list[dict[str, str]],
) -> None:
    """WARN when this run's OWN targets will not carry the mandated header.

    Scope routing sends the program handle only to ``scope.json``-admitted hosts.
    That is right for a third-party CDN and WRONG-looking for the host under
    test: Vigil does not gate execution on scope, so a run against a real target
    that ``hosts`` never declared (a recon-discovered sibling lives in
    ``discovered_hosts``) navigates it with NO attribution — the precise
    deconfliction failure the header exists to prevent, and silently, because
    ``kali_output`` reports ``browser`` as self-attributing so no injection
    warning fires either. Warn, never refuse: naming the host and both remedies
    keeps the operator in control of a call only they can make.
    """
    if attribution_scope == "all" or not required_headers or not hosts:
        return
    missing = [
        host
        for host in hosts
        if not scope_lib.host_admitted(host, allow_entries, deny_entries)
    ]
    if not missing:
        return
    print(
        f"browser: {', '.join(missing)} will be navigated WITHOUT the mandated "
        f"header(s) {', '.join(sorted(required_headers))} — scope.json `hosts` does "
        "not declare them (a discovered_hosts entry does not count). Declare the "
        "host in scope.json, or pass --attribution-scope all, before treating "
        "this run as deconflicted traffic.",
        file=sys.stderr,
    )


def run(args) -> None:
    url = _http_url(getattr(args, "url", ""), field="url")
    token = uuid.uuid4().hex[:8]
    stem = f"scans/browser/{_safe_slug(url)}-{token}"
    screenshot = _artifact_path(getattr(args, "screenshot", "") or f"{stem}.png", field="screenshot")
    dom_out = _artifact_path(getattr(args, "dom_out", "") or f"{stem}.html", field="dom-out")
    har_out = _artifact_path(getattr(args, "har_out", ""), field="har-out")
    body_dir = _artifact_path(getattr(args, "body_dir", "") or f"{stem}-bodies", field="body-dir")
    max_body_bytes = int(getattr(args, "max_body_bytes", 262_144))
    if not 1 <= max_body_bytes <= 10_485_760:
        raise AssessError("browser --max-body-bytes must be between 1 and 10485760")
    steps_path = str(getattr(args, "steps_file", "") or "").strip()
    steps = _load_steps(Path(steps_path).expanduser()) if steps_path else []
    page_timeout = float(getattr(args, "page_timeout", 30.0))
    settle = float(getattr(args, "settle", 2.0))
    wait_selector = str(getattr(args, "wait_selector", "") or "")
    _warn_timeout_budget(int(getattr(args, "timeout", 0) or 0), page_timeout, settle, wait_selector)

    eng_dir = _engagement_dir(args)
    required_headers, allow_entries, deny_entries = _scope_attribution(eng_dir)
    attribution_scope = str(getattr(args, "attribution_scope", "scope"))
    if required_headers:
        names = ", ".join(sorted(required_headers))
        if attribution_scope == "all":
            print(
                f"browser: --attribution-scope all sends the mandated header(s) {names} to EVERY "
                "origin this page loads - third-party analytics, CDN and vendor hosts included - "
                "so the program handle leaks off-target. Drop the flag to attribute only "
                "scope.json-admitted hosts.",
                file=sys.stderr,
            )
        elif not allow_entries:
            # The one fail-closed case: the program mandates attribution on every
            # in-scope request and the boundary cannot be resolved, so navigating
            # would send unattributed traffic to hosts that must be deconflicted.
            raise AssessError(
                f"browser cannot resolve the scope boundary that mandated header(s) {names} apply "
                "to: scope.json declares no usable `hosts` entry, so in-scope traffic would be "
                "sent unattributed. Declare the in-scope hosts, or pass --attribution-scope all "
                "to attribute every origin the page touches."
            )

    operator_headers = _parse_header_args(getattr(args, "extra_headers", []) or [])
    # Required program attribution always wins an explicit operator collision.
    required_header_names = {name.lower() for name in required_headers}
    operator_headers = {
        name: value
        for name, value in operator_headers.items()
        if name.lower() not in required_header_names
    }

    storage_state = _load_storage_state(
        str(getattr(args, "storage_state", "") or ""), eng_dir
    )
    identity_headers: dict[str, str] = {}
    cookies: list[dict[str, Any]] = []
    prepared_auth_context = "anonymous"
    identity = getattr(args, "identity", None)
    if storage_state is not None and not identity:
        raise AssessError("browser --storage-state requires --identity")
    if identity is not None and eng_dir is None:
        raise AssessError("browser --identity requires engagement context")
    if identity is not None:
        prepared_auth_context, prepared = prepare_browser_identity_material(
            eng_dir,
            identity,
            url,
            scope_key=str(getattr(args, "identity_scope", "") or ""),
            external_state_applied=storage_state is not None,
        )
        identity_headers = dict(prepared.get("headers") or {})
        cookies = list(prepared.get("cookies") or [])
        if prepared_auth_context == "anonymous":
            # Name the reason (state + age + recovery command) rather than
            # leaving the operator to guess — a bare refusal is what pushes
            # people onto hand-written Cookie headers, which record the run as
            # auth_context=anonymous and destroy cross-identity evidence.
            detail = str(prepared.get("refusal_detail") or "").strip()
            raise AssessError(
                f"browser requested identity '{identity}' could not be applied; "
                "refusing to run anonymously"
                + (f" because {detail}." if detail else ".")
            )

    # Identity credentials follow every host this run was explicitly told to
    # visit, so a multi-step workflow keeps its session across a declared
    # navigation. Hosts the page merely pulls resources from are not included.
    navigation_urls = [url, *(step["url"] for step in steps if step["action"] == "navigate")]
    identity_hosts = sorted({host for host in map(_host, navigation_urls) if host})
    _warn_unattributed_navigations(
        identity_hosts, required_headers, attribution_scope, allow_entries, deny_entries
    )

    config = {
        "url": url,
        "screenshot": screenshot,
        "dom_path": dom_out,
        "failure_stem": f"{stem}-failure",
        "page_timeout": page_timeout,
        "settle": settle,
        "wait_selector": wait_selector,
        "wait_state": str(getattr(args, "wait_state", "attached")),
        "wait_until": str(getattr(args, "wait_until", "domcontentloaded")),
        "eval_js": str(getattr(args, "eval_js", "") or "").strip(),
        "attribution_scope": attribution_scope,
        "attribution_allow": _attribution_entries(allow_entries),
        "attribution_deny": _attribution_entries(deny_entries),
        "required_headers": required_headers,
        "operator_headers": operator_headers,
        "identity_headers": identity_headers,
        "identity_hosts": identity_hosts,
        "cookies": cookies,
        "storage_state": storage_state,
        "steps": steps,
        "har_out": har_out,
        "capture_bodies": bool(getattr(args, "capture_bodies", False)),
        "body_dir": body_dir,
        "max_body_bytes": max_body_bytes,
    }
    print(f"browser: Playwright workflow {url} -> screenshot={screenshot} dom={dom_out}", file=sys.stderr)
    cmd = ["python3", "-c", _BROWSER_DRIVER, json.dumps(config, sort_keys=True, separators=(",", ":"))]
    kwargs = kali_args_to_kwargs(args)
    # The browser prepares identity inside its execution plan. Shared CLI-tool
    # injection cannot reach Chromium and would only duplicate/warn.
    kwargs["identity"] = None
    kwargs["prepared_auth_context"] = prepared_auth_context
    result = kali_exec(cmd, tool_name="browser", **kwargs)
    emit_result(result)
