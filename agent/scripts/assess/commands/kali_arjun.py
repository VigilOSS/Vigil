"""vigil assess kali arjun — typed wrapper around Arjun inside the runtime.

Arjun discovers *hidden* HTTP parameters an endpoint silently accepts but never
advertises. This verb exposes the FULL Arjun v2.2.7 CLI surface as first-class
typed flags (no capability narrowed): single-URL (`-u`) and list (`-i`) input,
all four methods (GET/POST/JSON/XML), the passive OSINT mode (`--passive`),
header-based auth (`--headers`), every rate/politeness/stability knob, the
casing styles, and all three output formats. A `--extra-args` passthrough is
kept as the safety net for any future Arjun flag.

Output policy: JSON (`-oJ`) is ALWAYS written into the engagement scan dir
(`scans/arjun/<target>/<hash>.json`, reachable in-container at
`/engagements/$ENGAGEMENT_KEY/...`) so every run is captured and auditable,
even when the operator also requests `-oT`/`-oB`. The JSON file is what
`vigil assess ingest-arjun` consumes to enrich the work buffer.

Like every other kali_* verb, Arjun runs INSIDE the isolated Kali runtime
(it sends HTTP to the target and, in passive mode, hits external OSINT
sources) under the same egress isolation. The host never makes the request.
"""
from __future__ import annotations

import hashlib
import re
import sys
from urllib.parse import urlparse

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)

# Arjun's own four methods, verbatim. JSON/XML matter for modern APIs.
_ARJUN_METHODS = ("GET", "POST", "XML", "JSON")
# Arjun's three param-casing styles.
_ARJUN_CASINGS = ("like_this", "likeThis", "likethis")

# Methods whose discovered params land in the request BODY rather than the
# query string. GET stays query; everything else is a body parameter. Mirrored
# host-side by ingest_arjun._slot_for_method so the two never drift.
_BODY_METHODS = frozenset({"POST", "XML", "JSON"})

# Sentinel for nargs="?" flags whose VALUE is optional (--headers, -oB). argparse
# stores this when the flag is ABSENT, the empty string ("") when it was passed
# bare (const=""), and the supplied string otherwise — so absent vs. bare-empty
# is unambiguous without inspecting raw argv.
_UNSET = "\x00__arjun_unset__"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "arjun",
        help="Run Arjun hidden-parameter discovery inside the runtime with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)

    # --- Input (one of -u / -i required) ---
    p.add_argument("-u", dest="target_url", default="", help="Single target URL.")
    p.add_argument(
        "-i",
        dest="import_file",
        default="",
        help="Import target URLs from a file (one per line, LIST input).",
    )

    # --- Method ---
    p.add_argument(
        "-m",
        dest="method",
        default="GET",
        type=lambda v: v.upper(),
        choices=list(_ARJUN_METHODS),
        help="HTTP method: GET | POST | XML | JSON (default GET). JSON/XML for modern APIs.",
    )

    # --- Output formats (all first-class; -oJ is also auto-defaulted) ---
    p.add_argument(
        "-oJ",
        dest="output_json",
        default="",
        help=(
            "JSON output file. ALWAYS defaulted to scans/arjun/<target>/<hash>.json "
            "when omitted so the run is captured for `ingest-arjun`."
        ),
    )
    p.add_argument("-oT", dest="output_text", default="", help="Text output file.")
    p.add_argument(
        "-oB",
        dest="output_burp",
        default=_UNSET,
        nargs="?",
        const="",
        help="Burp proxy output (optional proxy address; default Burp proxy when bare).",
    )

    # --- Discovery tuning ---
    p.add_argument(
        "-w",
        dest="wordlist",
        default="",
        help="Wordlist path. Default = Arjun's own db/large.txt (most thorough); override for a faster list.",
    )
    p.add_argument("-c", dest="chunks", default="", help="Chunk size (params sent per request).")
    p.add_argument("-t", dest="threads", default="", help="Concurrent threads (default 5).")
    p.add_argument("-d", dest="delay", default="", help="Delay between requests in seconds (default 0).")
    p.add_argument("-T", dest="timeout_http", default="", help="HTTP timeout in seconds (default 15).")
    p.add_argument(
        "--rate-limit",
        dest="rate_limit",
        default="",
        help="Max requests/second (default 9999). Load-bearing for politeness on content-heavy targets.",
    )
    p.add_argument(
        "--stable",
        dest="stable",
        action="store_true",
        help="Prefer stability over speed (recommended against rate-sensitive targets).",
    )

    # --- Auth-aware discovery ---
    p.add_argument(
        "--headers",
        dest="headers",
        default=_UNSET,
        nargs="?",
        const="",
        help=(
            "Add headers to every request (newline-separated, e.g. "
            "$'Authorization: Bearer X\\nCookie: s=Y'). THIS is auth-aware discovery."
        ),
    )

    # --- Passive OSINT mode ---
    p.add_argument(
        "--passive",
        dest="passive",
        default=None,
        nargs="?",
        const="",
        help=(
            "Collect param names PASSIVELY from wayback / commoncrawl / otx (no/low "
            "target traffic). Optional source list (e.g. --passive 'wayback,otx'); "
            "bare --passive uses all sources."
        ),
    )

    # --- Misc ---
    p.add_argument(
        "--include",
        dest="include",
        default="",
        help="Data to include in every request (e.g. 'token=123' or a JSON blob).",
    )
    p.add_argument(
        "--disable-redirects",
        dest="disable_redirects",
        action="store_true",
        help="Disable following redirects.",
    )
    p.add_argument(
        "--casing",
        dest="casing",
        default="",
        choices=list(_ARJUN_CASINGS),
        help="Param casing style: like_this | likeThis | likethis.",
    )
    p.add_argument("-q", dest="quiet", action="store_true", help="Quiet output.")

    p.set_defaults(func=run)


def _target_token(args) -> str:
    """A filesystem-safe token identifying the run's target for the scan path.

    Single-URL runs use the hostname; list runs use the import file's stem.
    Falls back to 'targets' so the path is always well-formed.
    """
    if args.target_url:
        host = urlparse(args.target_url).hostname or args.target_url
        token = host
    elif args.import_file:
        token = args.import_file.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    else:
        token = "targets"
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", token).strip("_")
    return token or "targets"


def _default_json_path(args) -> str:
    """Container-relative default JSON output path under the engagement scan dir.

    `scans/arjun/<target>/<hash>.json` — the kali container working dir is
    `/engagements/<engagement_key>`, so this relative path resolves there.
    The hash keys off the full invocation shape (target+method+wordlist+passive)
    so distinct runs against the same target do not clobber each other.
    """
    token = _target_token(args)
    shape = "|".join(
        str(v)
        for v in (
            args.target_url,
            args.import_file,
            args.method,
            args.wordlist,
            args.passive,
            args.headers,
        )
    )
    digest = hashlib.sha256(shape.encode("utf-8")).hexdigest()[:12]
    return f"scans/arjun/{token}/{digest}.json"


def run(args) -> None:
    if not args.target_url and not args.import_file:
        print("arjun: pass -u <url> or -i <file>", file=sys.stderr)
        raise AssessError("missing -u or -i")
    if args.target_url and args.import_file:
        print("arjun: pass only one of -u <url> / -i <file>", file=sys.stderr)
        raise AssessError("-u and -i are mutually exclusive")

    cmd: list[str] = ["arjun"]

    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.import_file:
        cmd.extend(["-i", args.import_file])

    # Method is always passed (defaults to GET) so the audit argv is explicit.
    cmd.extend(["-m", args.method])

    # JSON output is ALWAYS produced so the run is captured for ingest-arjun.
    json_path = args.output_json or _default_json_path(args)
    cmd.extend(["-oJ", json_path])
    if args.output_text:
        cmd.extend(["-oT", args.output_text])
    # -oB: _UNSET == flag absent; "" == bare -oB (default Burp proxy); else the
    # supplied proxy address.
    if args.output_burp != _UNSET:
        if args.output_burp:
            cmd.extend(["-oB", args.output_burp])
        else:
            cmd.append("-oB")

    if args.wordlist:
        cmd.extend(["-w", args.wordlist])
    if args.chunks:
        cmd.extend(["-c", str(args.chunks)])
    if args.threads:
        cmd.extend(["-t", str(args.threads)])
    if args.delay:
        cmd.extend(["-d", str(args.delay)])
    if args.timeout_http:
        cmd.extend(["-T", str(args.timeout_http)])
    if args.rate_limit:
        cmd.extend(["--rate-limit", str(args.rate_limit)])
    if args.stable:
        cmd.append("--stable")

    # --headers: _UNSET == absent; "" == bare --headers; else the header block.
    if args.headers != _UNSET:
        if args.headers:
            cmd.extend(["--headers", args.headers])
        else:
            cmd.append("--headers")

    if args.passive is not None:
        if args.passive:
            cmd.extend(["--passive", args.passive])
        else:
            cmd.append("--passive")

    if args.include:
        cmd.extend(["--include", args.include])
    if args.disable_redirects:
        cmd.append("--disable-redirects")
    if args.casing:
        cmd.extend(["--casing", args.casing])
    if args.quiet:
        cmd.append("-q")

    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="arjun", **kali_args_to_kwargs(args))
    emit_result(result)
