"""vigil assess kali httpx — typed wrapper around httpx inside the runtime."""
from __future__ import annotations

import sys

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    count_list_targets,
    emit_result,
    safe_engagement_dir,
    extend_cmd_with_extra_args,
    incomplete_list_run_warning,
    kali_args_to_kwargs,
    kali_exec,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "httpx",
        help="Run httpx inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Single target URL.")
    p.add_argument("-l", dest="target_list", default="", help="File of newline-separated targets.")
    p.add_argument("-ports", "-p", dest="ports", default="",
                   help="-ports/-p comma-separated port list to probe in addition to each URL's own "
                        "scheme default (e.g. 80,443,8080,8443). Without this, httpx only probes "
                        "80/443, so alt-port-only hosts read as dead and are never seeded/crawled.")
    p.add_argument("-path", dest="path", default="", help="-path append a path to each probed URL (e.g. /api/v1).")
    p.add_argument("-status-code", dest="status_code", action="store_true", help="-status-code probe.")
    p.add_argument("-title", dest="title", action="store_true", help="-title extraction.")
    p.add_argument("-content-length", "-cl", dest="content_length", action="store_true",
                   help="-content-length/-cl include the response Content-Length in output.")
    p.add_argument("-tech-detect", dest="tech_detect", action="store_true", help="-tech-detect via wappalyzer.")
    p.add_argument("-tls-grab", dest="tls_grab", action="store_true", help="-tls-grab certificate metadata.")
    p.add_argument("-web-server", dest="web_server", action="store_true", help="-web-server (Server header).")
    p.add_argument("-ip", dest="show_ip", action="store_true", help="-ip resolved address.")
    p.add_argument("-cdn", dest="cdn", action="store_true", help="-cdn CDN/WAF identification.")
    p.add_argument("-favicon", dest="favicon", action="store_true", help="-favicon mmh3 favicon hash.")
    p.add_argument("-location", dest="location", action="store_true", help="-location redirect target.")
    p.add_argument("-follow-redirects", "-fr", dest="follow_redirects", action="store_true",
                   help="-follow-redirects follow 30x.")
    # Transport / politeness knobs (were only reachable via --extra-args).
    p.add_argument("-threads", "-t", dest="threads", default="", help="-threads concurrent workers.")
    p.add_argument("-rate-limit", "-rl", dest="rate_limit", default="", help="-rate-limit req/s (single global bucket).")
    p.add_argument("-timeout", dest="timeout_http", default="", help="-timeout per-request seconds.")
    p.add_argument("-retries", dest="retries", default="", help="-retries per host.")
    p.add_argument("-H", "-header", dest="headers", action="append", default=None,
                   help="Extra request header (repeatable). Program attribution headers are "
                        "injected automatically on top of these.")
    p.add_argument("-mc", dest="match_codes", default="", help="-mc match status codes (e.g. 200,302).")
    p.add_argument("-fc", dest="filter_codes", default="", help="-fc filter (drop) status codes.")
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-store-response", "-sr", dest="store_response", action="store_true",
                   help="-store-response/-sr save each response body to disk under -store-response-dir.")
    p.add_argument("-store-response-dir", "-srd", dest="store_response_dir", default="",
                   help="-store-response-dir/-srd directory to save response bodies into (engagement-relative "
                        "or in-container absolute); requires -store-response.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("httpx: pass -u <url> or -l <list>", file=sys.stderr)
        raise AssessError("missing -u or -l")
    cmd: list[str] = ["httpx"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.ports:
        cmd.extend(["-ports", args.ports])
    if args.path:
        cmd.extend(["-path", args.path])
    if args.status_code:
        cmd.append("-status-code")
    if args.title:
        cmd.append("-title")
    if args.content_length:
        cmd.append("-cl")
    if args.tech_detect:
        cmd.append("-tech-detect")
    if args.tls_grab:
        cmd.append("-tls-grab")
    if args.web_server:
        cmd.append("-web-server")
    if args.show_ip:
        cmd.append("-ip")
    if args.cdn:
        cmd.append("-cdn")
    if args.favicon:
        cmd.append("-favicon")
    if args.location:
        cmd.append("-location")
    if args.follow_redirects:
        cmd.append("-follow-redirects")
    if args.threads:
        cmd.extend(["-threads", str(args.threads)])
    if args.rate_limit:
        cmd.extend(["-rate-limit", str(args.rate_limit)])
    if args.timeout_http:
        cmd.extend(["-timeout", str(args.timeout_http)])
    if args.retries:
        cmd.extend(["-retries", str(args.retries)])
    for header in args.headers or []:
        cmd.extend(["-H", header])
    if args.match_codes:
        cmd.extend(["-mc", args.match_codes])
    if args.filter_codes:
        cmd.extend(["-fc", args.filter_codes])
    if args.output_json:
        cmd.append("-json")
    if args.store_response:
        cmd.append("-store-response")
    if args.store_response_dir:
        cmd.extend(["-store-response-dir", args.store_response_dir])
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="httpx", **kali_args_to_kwargs(args))

    # Incomplete-run guard: a timed-out httpx liveness pass over a host LIST
    # under-probes — hosts past the cut never answer and would be wrongly read as
    # dead (and then never tested). Flag the truncation so a partial pass is not a
    # liveness verdict for the unscanned remainder.
    total = count_list_targets(
        args.target_list, engagement_dir=safe_engagement_dir(args)
    ) if args.target_list else 0
    note = incomplete_list_run_warning(
        tool="httpx", total_targets=total,
        timed_out=getattr(result, "timed_out", False),
        return_code=getattr(result, "return_code", None),
        stdout_preview=getattr(result, "stdout_preview", "") or "",
        stderr_preview=getattr(result, "stderr_preview", "") or "",
    )
    if note:
        print(f"WARN {note}", file=sys.stderr)
    emit_result(result)
