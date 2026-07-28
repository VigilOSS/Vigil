"""Audited Playwright/Chromium browser workflow for target application evidence."""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from assess.lib.client import AssessError
from assess.lib.config import resolve_engagement_dir
from assess.lib.kali import (
    add_required_kali_flags,
    emit_result,
    kali_args_to_kwargs,
    kali_exec,
    prepare_browser_identity_material,
)
from assess.lib.kali_output import _required_headers

_MAX_STEPS = 50
_MAX_STEP_TIMEOUT_MS = 120_000
_ACTIONS = frozenset({"navigate", "click", "fill", "wait", "eval", "assert"})
_STEP_KEYS = {
    "navigate": frozenset({"action", "url", "wait_until", "timeout_ms"}),
    "click": frozenset({"action", "selector", "timeout_ms"}),
    "fill": frozenset({"action", "selector", "value", "timeout_ms"}),
    "wait": frozenset({"action", "selector", "timeout_ms"}),
    "eval": frozenset({"action", "script"}),
    "assert": frozenset({"action", "selector", "contains", "equals", "visible", "timeout_ms"}),
}


# Runs under the runtime image's system Python. The complete execution plan is one
# JSON argv value, avoiding shell interpolation and keeping every target URL
# visible in the audited argv before Chromium starts.
_BROWSER_DRIVER = r'''
import hashlib, json, os, re, sys, time
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
document_origins = set(cfg.get("document_origins") or [])
identity_hosts = set(cfg.get("identity_hosts") or [])

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
    request_origin = origin(request.url)
    request_host = (urlsplit(request.url).hostname or "").lower().rstrip(".")
    is_document_navigation = request.is_navigation_request()
    # Bearer/custom identity headers are target credentials, not ambient browser
    # headers. Keep them on the resolved identity target host; cookies use
    # Chromium's native domain/path scoping through context.add_cookies().
    if request_host in identity_hosts:
        headers.update(identity_headers)
    should_attribute = cfg.get("attribution_scope") == "all" or (
        cfg.get("attribution_scope") == "document-origin"
        and (request_origin in document_origins or is_document_navigation)
    )
    if should_attribute:
        headers.update(required_headers)
        if is_document_navigation and request_origin:
            document_origins.add(request_origin)
    elif required_headers and request_origin:
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
        response = page.goto(cfg["url"], wait_until="domcontentloaded", timeout=int(float(cfg.get("page_timeout") or 30) * 1000))
        result["http_status"] = response.status if response else None
        if cfg.get("wait_selector"):
            page.locator(cfg["wait_selector"]).wait_for(state="attached", timeout=int(float(cfg.get("page_timeout") or 30) * 1000))
        else:
            page.wait_for_timeout(int(float(cfg.get("settle") or 0) * 1000))
        if cfg.get("eval_js"):
            result["eval_result"] = page.evaluate(cfg["eval_js"])
        for index, step in enumerate(cfg.get("steps") or []):
            action = step["action"]
            timeout = int(step.get("timeout_ms") or min(int(float(cfg.get("page_timeout") or 30) * 1000), 120000))
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
                        page.locator(step["selector"]).wait_for(state="attached", timeout=timeout)
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
    p.add_argument("--wait-selector", default="", help="CSS selector to await before capture.")
    p.add_argument("--page-timeout", type=float, default=30.0)
    p.add_argument("--settle", type=float, default=2.0)
    p.add_argument("--eval", dest="eval_js", default="", help="Evaluate JavaScript after initial load.")
    p.add_argument("--header", dest="extra_headers", action="append", default=[], metavar="NAME:VALUE")
    p.add_argument(
        "--attribution-scope", choices=("all", "document-origin"), default="all",
        help="Apply required attribution to all requests or only document origins.",
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


def _resolve_required_headers(args) -> dict[str, str]:
    try:
        eng_dir = resolve_engagement_dir(getattr(args, "engagement_dir", None))
    except SystemExit:
        return {}
    return _required_headers(Path(eng_dir))


def _engagement_dir(args) -> Path | None:
    try:
        return Path(resolve_engagement_dir(getattr(args, "engagement_dir", None)))
    except (SystemExit, OSError, ValueError):
        return None


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    port = parsed.port
    default = (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{'' if not port or default else f':{port}'}"


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

    required_headers = _resolve_required_headers(args)
    operator_headers = _parse_header_args(getattr(args, "extra_headers", []) or [])
    # Required program attribution always wins an explicit operator collision.
    required_header_names = {name.lower() for name in required_headers}
    operator_headers = {
        name: value
        for name, value in operator_headers.items()
        if name.lower() not in required_header_names
    }

    eng_dir = _engagement_dir(args)
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

    config = {
        "url": url,
        "screenshot": screenshot,
        "dom_path": dom_out,
        "failure_stem": f"{stem}-failure",
        "page_timeout": float(getattr(args, "page_timeout", 30.0)),
        "settle": float(getattr(args, "settle", 2.0)),
        "wait_selector": str(getattr(args, "wait_selector", "") or ""),
        "eval_js": str(getattr(args, "eval_js", "") or "").strip(),
        "attribution_scope": str(getattr(args, "attribution_scope", "all")),
        "required_headers": required_headers,
        "operator_headers": operator_headers,
        "identity_headers": identity_headers,
        "identity_hosts": [(urlsplit(url).hostname or "").lower().rstrip(".")],
        "cookies": cookies,
        "storage_state": storage_state,
        "document_origins": [_origin(url)],
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
