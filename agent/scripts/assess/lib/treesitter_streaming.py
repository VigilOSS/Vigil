"""Bounded streaming fallback owned by the tree-sitter index."""
from __future__ import annotations

import re
from typing import Any

from assess.lib.treesitter_catalogues import (
    _ENTRY_ANNOTATIONS,
    _ENTRY_LINE_PATTERNS,
    _PHP_CLI_INPUT_PATTERNS,
    _PHP_FILE_INCLUSION_VULN_CLASSES,
    _PHP_SERVER_ARGV,
    _PHP_STREAM_MASS_ASSIGNMENT,
    _PHP_STREAM_VARIABLE_VARIABLE,
    _SINK_DEFINITIONS,
)
from assess.lib.treesitter_common import _gate_literals, _literal_gate, _php_import_record
from assess.lib.treesitter_lightweight import (
    _LUA_DYNAMIC_REDIS_COMMAND_RE,
    _PS_SINK_PATTERNS,
    _TEMPLATE_BRACE_STEP_LINE,
)

UNSCANNED_SCOPE_DEGRADATION_REASON = "unscanned_function_scope"

STREAMING_SCAN_WINDOW_BYTES = 64 * 1024
STREAMING_SCAN_OVERLAP_BYTES = 512
STRUCTURAL_SIGNAL_LIMIT = 2_000
STREAMING_FALLBACK_BASELINE_UNAVAILABLE = frozenset({
    "call_sites",
    "classes",
    "dataflow",
    "exports",
    "functions",
})
# Every dimension a structural index publishes, and the subset whose records
# carry signal counts. `code_structural_metadata` validates against both.
STRUCTURAL_DIMENSIONS = {
    "call_sites",
    "classes",
    "dataflow",
    "entry_points",
    "exports",
    "functions",
    "imports",
    "security_sinks",
    "security_sources",
}
# An unsupported language reaches no reader, so every dimension is unavailable.
_UNSUPPORTED_UNAVAILABLE_DIMENSIONS = sorted(STRUCTURAL_DIMENSIONS)
SIGNAL_DIMENSIONS = (
    "entry_points",
    "imports",
    "security_sinks",
    "security_sources",
)
# The capped lists whose records carry a kind and a line; past the limit each
# keeps its records in turn across kinds, so no kind is lost behind another.
_KINDED_SIGNAL_LISTS = ("entry_points", "security_sinks", "security_sources")
_CAPPED_INDEX_LISTS = (
    "call_sites",
    "classes",
    "entry_points",
    "exports",
    "functions",
    "import_targets",
    "imports",
    "security_sinks",
    "security_sources",
)

# Where a value enters the file. A source is not a vulnerability -- the sink it
# reaches is -- so these records carry a `kind` and no vuln class. Every one
# of them used to name a class no taxonomy declares, which made the field a
# vehicle that could hold nothing true.
_STREAM_SOURCE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "python": [
        ("http_request_input", r"\brequest\.(?:args|form|json|values|files|headers|GET|POST|FILES|COOKIES|META|body)\b"),
        # Tornado's handler reads its request through `self`: the argument
        # accessors, and the request attributes the table above does not name.
        ("http_request_input",
         r"\bself\.get_(?:query_|body_)?arguments?\s*\(|\bself\.get_(?:secure_)?cookie\s*\("),
        ("http_request_input",
         r"\bself\.request\.(?:arguments|query_arguments|body_arguments|path|uri|query)\b"),
        ("process_input", r"\b(?:sys\.argv|os\.environ|getenv\s*\(|input\s*\()"),
    ],
    "javascript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies|url|originalUrl|path|rawHeaders)\b"),
        ("process_input", r"\bprocess\.(?:argv|env)\b"),
    ],
    "typescript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies|url|originalUrl|path|rawHeaders)\b"),
        ("process_input", r"\bprocess\.(?:argv|env)\b"),
    ],
    "java": [
        ("http_request_input", r"\bget(?:Parameter|Header|InputStream)\s*\("),
        ("http_request_input", r"@(?:PathVariable|MatrixVariable|RequestParam|RequestHeader|CookieValue|RequestBody|RequestPart|ModelAttribute|PathParam|QueryParam|FormParam|HeaderParam|CookieParam|MatrixParam)\b"),
        ("http_request_input", r"\brequest\.(?:pathVariable|queryParam|param|headers|body)\s*\("),
        ("process_input", r"\bSystem\.getenv\s*\("),
    ],
    "go": [
        ("http_request_input", r"\b(?:r|req|request)\.(?:URL\.Query|FormValue|PostFormValue|PathValue|Header\.Get|Cookie|FormFile)\s*\("),
        ("http_request_input", r"\b(?:r|req|request)\.(?:URL\.(?:Path|RawPath|RawQuery)|Body|Form|PostForm)\b"),
        ("process_input", r"\bos\.(?:Args|Getenv)\b"),
    ],
    "ruby": [
        ("http_request_input", r"\b(?:params\s*\[|request\.)"),
        ("process_input", r"\b(?:ENV\s*\[|ARGV\b)"),
    ],
    # Blade's two echo forms are where controller data -- and through it the
    # request -- enters the rendered document. This is the streaming fallback's
    # reading only, and it is the weaker one: `(?!--)` rejects a match starting
    # at a comment's `{{` but not the echo written inside that comment, and a
    # line-bounded scanner cannot see the `{{-- ... --}}` that encloses it.
    # `_blade_template_sources` is the authority wherever the whole file is in
    # hand, which is every path but this one; `_STREAM_EXTRA_SINK_PATTERNS`
    # reads Blade's sinks with the same limit, so the two stay symmetrical.
    "blade": [
        ("template_input",
         r"\{\{(?!--)" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}|\{!![^!\r\n]+!!\}"),
    ],
    "php": [
        # `$_SERVER['argv']` is read below, as process and request input both.
        # Variable names are case-sensitive, so `$_files` is a property.
        ("http_request_input",
         r"(?-i:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER(?!\s*\[\s*['\"]arg[vc]['\"]))\b"
         r"|\$HTTP_(?:(?:GET|POST|COOKIE|SERVER)_VARS|POST_FILES|RAW_POST_DATA)\b)"),
        ("http_request_input", _PHP_SERVER_ARGV),
        # Idiomatic Laravel/Symfony/CodeIgniter never touches a superglobal:
        # the request arrives as an injected object, `$this->request`, or the
        # `request()` helper. Anchored on the request object rather than on
        # accessor names, because a bare `->get(`/`->all(` also names a
        # repository, a config bag and an Eloquent query builder.
        ("http_request_input",
         r"(?:\$request|\$req|\$this->(?:request|input)|\brequest\s*\(\s*\))\s*->"),
        # The facade spellings the anchor above cannot see, narrowed to the
        # accessors that only ever read request data.
        ("http_request_input",
         r"\b(?:Input|Request)::(?:input|get|all|query|post|json|file|header|cookie)\s*\("),
        # The request readers of the frameworks that wrap them: Moodle's page
        # parameter functions, and the read accessors of the request a Magento,
        # Zend or MediaWiki controller reaches through `getRequest()`.
        ("http_request_input",
         r"(?<![\w$>:])(?<!function )(?:optional|required)_param(?:_array)?\s*\("
         r"|\bgetRequest\s*\(\s*\)\s*->\s*(?:get(?:Params?|Post(?:Value)?|Query(?:Value)?"
         r"|Cookie|Header|Content|Files|Val|RawVal|Text|Int|Bool|Array|Check)\s*\("
         r"|(?:query|request|cookies|files|headers)\b)"),
        # The raw request body, the filtered superglobal reads, and the header
        # helpers: request input that names no superglobal at all.
        ("http_request_input",
         r"php://input|\bfilter_input(?:_array)?\s*\(\s*INPUT_(?:GET|POST|COOKIE|SERVER|REQUEST)\b"
         r"|\b(?:getallheaders|apache_request_headers)\s*\("),
        ("process_input", r"\bgetenv\s*\(|(?-i:\$_ENV\b)"),
        ("process_input", "|".join(pattern for _evidence, pattern in _PHP_CLI_INPUT_PATTERNS)),
    ],
    "csharp": [
        # Classic ASP.NET reads request data off the `Request` object; the
        # `HttpContext.Request` spelling is the same surface reached the long
        # way. ASP.NET Core's model binding attaches it to action parameters
        # instead, which is what the `[From...]` binding attributes mark.
        ("http_request_input",
         r"\b(?:HttpContext\.)?Request\.(?:Form|QueryString|Query|Params|Headers|Cookies|Body)\b"),
        ("http_request_input", r"\[From(?:Body|Query|Route|Form|Header)\b"),
        ("process_input",
         r"\b(?:Environment\.GetEnvironmentVariable\s*\(|Console\.ReadLine\s*\()"),
    ],
    "c": [
        ("process_input", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()"),
    ],
    "cpp": [
        ("process_input", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()"),
        ("http_request_input", r"\b(?:req|request)\.(?:path|body|get_param_value\s*\(|get_header_value\s*\()"),
    ],
    "shell": [
        ("positional_parameter", r"\$(?:[1-9]\b|[@*]|\{(?:[1-9][0-9]*|[@*])\})"),
        ("environment_input", r"\$\{?[A-Z_][A-Z0-9_]*\}?"),
    ],
    "powershell": [
        ("script_parameter", r"\$(?:args|PSBoundParameters|MyInvocation)\b"),
        ("environment_input", r"\$env:[A-Za-z_]\w*"),
        ("interactive_input", r"\bRead-Host\b"),
    ],
    "dockerfile": [
        ("build_argument", r"^\s*(?:ARG|ENV)\s+[A-Za-z_][A-Za-z0-9_]*"),
    ],
    "lua": [
        ("script_argument", r"\b(?:ARGV|KEYS)\s*\["),
    ],
    "html": [
        ("template_input", r"\{\{" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}|<%[^%\r\n]+%>"),
    ],
    "css": [
        ("template_input", r"\{\{" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}|<%[^%\r\n]+%>"),
    ],
    "freemarker": [
        ("template_input", r"[$#]\{[^}\r\n]+\}"),
    ],
    "twig": [
        ("template_input", r"\{\{" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}"),
    ],
}

# PHP's inclusion constructs as a line can show them. A keyword written as a
# method (`$this->include(`), a static call, a variable (`$include`) or a
# quoted array key is not one. The parse tree tells the rest -- a comment, a
# string -- apart; a line cannot, so this reader only ever says `dynamic`
# (the argument interpolates a variable) or `unclassified`.
_PHP_STREAM_INCLUDE = (
    r"(?<![\w$>:'\"\\])(include_once|include|require_once|require)\b"
    r"(?!\s*(?:=>|::))[^\r\n;]*"
)
_PHP_STREAM_SINGLE_QUOTED = re.compile(rb"'(?:[^'\\]|\\.)*'")
_PHP_STREAM_INTERPOLATION = re.compile(rb"(?<!\\)\$(?:[A-Za-z_\x80-\xff]|\{)")

_STREAM_IMPORT_PATTERNS: dict[str, list[str]] = {
    "blade": [
        r"@(?:extends|include(?:First|Unless|When|If)?|component|each)\s*\([^\r\n)]*",
        r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+",
    ],
    "python": [r"\b(?:from\s+[\w.]+\s+import\b[^\r\n]*|import\s+[^\r\n]+)"],
    "javascript": [r"\bimport\b[^\r\n]*", r"\brequire\s*\([^\r\n]*"],
    "typescript": [r"\bimport\b[^\r\n]*", r"\brequire\s*\([^\r\n]*"],
    "java": [r"\bimport\s+[\w.*]+"],
    "go": [r"\bimport\s*(?:\([^\r\n]*|[\"`][^\"`]+[\"`])"],
    "ruby": [r"\b(?:require|require_relative|load)\s*\(?\s*['\"][^'\"]+"],
    # A namespace `use` is read as a statement by `StreamingSecurityScanner`,
    # so it publishes the same one-record-per-name shape the parser does. This
    # row is the inclusion construct; see `_PHP_STREAM_INCLUDE`.
    "php": [_PHP_STREAM_INCLUDE],
    "csharp": [r"\busing\s+(?:static\s+)?[^\r\n;=]+"],
    "c": [r"#\s*include\s*[<\"][^>\"]+[>\"]"],
    "cpp": [r"#\s*include\s*[<\"][^>\"]+[>\"]"],
    "lua": [r"\brequire\s*\(?\s*['\"][^'\"]+"],
    "dockerfile": [r"^\s*(?:FROM|ADD)\s+[^\r\n]+"],
    "shell": [r"^\s*(?:\.|source)\s+[^\r\n]+"],
    "powershell": [
        r"^\s*(?:Import-Module|using\s+(?:module|namespace))\s+[^\r\n]+",
        r"^\s*\.\s+[^\s\r\n]+\.psm?1",
    ],
    "html": [r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+"],
    "css": [r"@import\s+(?:url\()?\s*['\"]?[^'\"\s)]+"],
    "freemarker": [
        r"<#(?:include|import)\s[^\r\n>]*",
        r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+",
    ],
    "twig": [
        r"\{%[-~]?\s*(?:extends|include|embed|import|from)\b[^\r\n%]*",
        r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+",
    ],
}

_STREAM_EXTRA_SINK_PATTERNS: dict[str, list[tuple[str, str, list[str]]]] = {
    "blade": [
        ("unescaped_output", r"\{!![^!\r\n]+!!\}", ["xss"]),
        ("template_interpolation",
         r"\{\{(?!--)" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}", ["xss"]),
        ("inline_event_handler", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", ["xss"]),
    ],
    "php": [
        ("file_inclusion", _PHP_STREAM_INCLUDE, list(_PHP_FILE_INCLUSION_VULN_CLASSES)),
        ("mass_assignment", _PHP_STREAM_MASS_ASSIGNMENT, ["mass-assignment"]),
        ("mass_assignment", _PHP_STREAM_VARIABLE_VARIABLE, ["mass-assignment"]),
    ],
    "dockerfile": [
        ("remote_pipe_to_shell", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", ["supply-chain", "injection"]),
        ("permissive_chmod", r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", ["privilege-escalation"]),
    ],
    "shell": [
        ("shell_eval", r"\beval\b", ["injection"]),
        ("remote_pipe_to_shell", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", ["supply-chain", "injection"]),
    ],
    # One table, two readers: the structural extractor compiles these same
    # strings, so a `.ps1` reports the same sinks whichever path indexed it.
    "powershell": _PS_SINK_PATTERNS,
    "lua": [
        ("redis_dynamic_command", _LUA_DYNAMIC_REDIS_COMMAND_RE, ["injection"]),
        ("dynamic_code_load", r"\b(?:loadstring|load)\s*\(", ["injection"]),
        ("os_execute", r"\bos\.execute\s*\(", ["injection"]),
    ],
    "html": [
        ("inline_event_handler", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", ["xss"]),
        ("template_interpolation",
         r"\{\{" + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}", ["xss", "ssti"]),
    ],
    "css": [
        ("css_expression", r"\bexpression\s*\(", ["xss"]),
        ("css_behavior", r"\bbehavior\s*:", ["xss"]),
    ],
    "freemarker": [
        ("template_interpolation", r"[$#]\{[^}\r\n]+\}", ["xss"]),
        ("inline_event_handler", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", ["xss"]),
        (
            "freemarker_dynamic_evaluation",
            r"\?(?:eval|eval_json|evalJson|interpret|new)\b",
            ["ssti", "injection"],
        ),
    ],
    "twig": [
        ("unescaped_output",
         r"\{\{" + _TEMPLATE_BRACE_STEP_LINE + r"*\|\s*raw\b" + _TEMPLATE_BRACE_STEP_LINE
         + r"*\}\}|\{%[-~]?\s*autoescape\s+false\b", ["xss", "ssti"]),
        ("template_interpolation",
         r"\{\{(?!" + _TEMPLATE_BRACE_STEP_LINE + r"*\|\s*raw\b)"
         + _TEMPLATE_BRACE_STEP_LINE + r"+\}\}", ["xss", "ssti"]),
        ("inline_event_handler", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", ["xss"]),
        ("twig_dynamic_evaluation", r"\btemplate_from_string\s*\(", ["ssti", "injection"]),
    ],
}

# Line-level shapes of the structural entry rules that read a signature or a
# class header rather than a catalogue line: Go's handler signature, the Node
# server registration, and a Tornado handler class.
_STREAM_EXTRA_ENTRY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "blade": [("html_form", r"<form\b")],
    "go": [(
        "go_http_handler",
        r"\bfunc\s+(?:\([^)]*\)\s*)?\w+\s*\(\s*(?:\w+\s+)?\w+\.ResponseWriter\s*,"
        r"\s*(?:\w+\s+)?\*\w+\.Request\s*\)",
    )],
    # Only the server constructor: a line scanner cannot tell a server's
    # `.on('request', fn)` from a browser-automation page listener.
    "javascript": [("node_http_server", r"\bhttps?2?\.createServer\s*\(")],
    "typescript": [("node_http_server", r"\bhttps?2?\.createServer\s*\(")],
    "python": [("tornado_handler", r"^\s*class\s+\w+\s*\([^)]*\bRequestHandler\b")],
    "shell": [("shell_script", r"^#!")],
    "powershell": [("script_parameters", r"^\s*param\s*\(")],
    "dockerfile": [
        ("container_cmd", r"^\s*CMD\b"),
        ("container_entrypoint", r"^\s*ENTRYPOINT\b"),
    ],
    "html": [("html_form", r"<form\b")],
    "freemarker": [
        ("html_form", r"<form\b"),
        ("freemarker_macro", r"<#(?:macro|function)\s"),
    ],
    "twig": [("html_form", r"<form\b")],
}


def _kind_balanced(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """The *limit* records ordered by (rank within kind, line), in their original order."""
    ranks: dict[str, int] = {}
    keys: list[tuple[int, int, int]] = []
    for index in sorted(range(len(records)), key=lambda item: records[item]["line"]):
        kind = records[index]["kind"]
        ranks[kind] = ranks.get(kind, 0) + 1
        keys.append((ranks[kind], records[index]["line"], index))
    return [records[index] for index in sorted(key[2] for key in sorted(keys)[:limit])]


def _byte_pattern(pattern: str, case_blind: bool = True) -> re.Pattern[bytes]:
    return re.compile(pattern.encode("ascii"), re.IGNORECASE if case_blind else 0)


# PHP's namespace `use` statement, read statement by statement where no parse
# tree exists; a line can hold several. A trait `use` inside a class body is
# spelled identically, so a statement only counts until a class-like
# declaration opens and again after the next `namespace`: imports precede the
# declarations that use them.
_PHP_STATEMENT_LEAD = re.compile(rb"\s*(?:<\?php\b\s*)?", re.IGNORECASE)
_PHP_STATEMENT_BOUNDARY = re.compile(rb"[;{]")
_PHP_USE_STATEMENT = re.compile(rb"use\s+(?=[\\A-Za-z_\x80-\xff])", re.IGNORECASE)
_PHP_CLASS_DECLARATION = re.compile(
    rb"(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\b", re.IGNORECASE
)
_PHP_NAMESPACE_DECLARATION = re.compile(rb"namespace\b", re.IGNORECASE)
_PHP_USE_STATEMENT_LIMIT = STREAMING_SCAN_WINDOW_BYTES
_PHP_USE_COMMENT = re.compile(r"//[^\n]*|#[^\n]*|/\*.*?\*/", re.DOTALL)
_PHP_USE_KIND = re.compile(r"\s*(function|const)\s+", re.IGNORECASE)
_PHP_USE_CLAUSE = re.compile(
    r"\s*(?:(?P<kind>function|const)\s+)?"
    r"(?P<name>\\?[^\W\d]\w*(?:\s*\\\s*[^\W\d]\w*)*)"
    r"(?:\s+as\s+(?P<alias>[^\W\d]\w*))?\s*",
    re.IGNORECASE,
)


def _php_use_clauses(body: str) -> list[tuple[str, str, str, int]]:
    """`(kind, name, alias, offset)` for each name one `use` statement imports.

    *body* is the statement after its `use` keyword. A group spells its shared
    prefix once (`Acme\\Http\\{Request, function respond}`), and a
    `function`/`const` keyword belongs to the statement or to one member.
    """
    body = _PHP_USE_COMMENT.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), body)
    declared = _PHP_USE_KIND.match(body)
    start = declared.end() if declared else 0
    prefix = ""
    end = len(body)
    brace = body.find("{", start)
    if brace >= 0:
        prefix = "".join(body[start:brace].split()).rstrip("\\")
        close = body.find("}", brace)
        start, end = brace + 1, close if close >= 0 else len(body)
    clauses: list[tuple[str, str, str, int]] = []
    offset = start
    for segment in body[start:end].split(","):
        clause = _PHP_USE_CLAUSE.fullmatch(segment)
        if clause is not None:
            name = clause.group("name")
            clauses.append((
                (clause.group("kind") or (declared.group(1) if declared else "") or "class").lower(),
                f"{prefix}\\{name}" if prefix else name,
                clause.group("alias") or "",
                offset + clause.start("name"),
            ))
        offset += len(segment) + 1
    return clauses


# Languages whose line comments open with `#`. An allowlist, because a leading
# `#` is *code* in the rest of what this scanner serves: a C preprocessor
# directive, a FreeMarker `#{...}` numeric interpolation, a Lua length operator.
# Reading one as a comment drops the whole line from every detector below.
_HASH_COMMENT_LANGUAGES = frozenset(
    {"dockerfile", "php", "powershell", "python", "ruby", "shell"}
)
# ...and even there, `#` followed by one character is not: `#!` opens a shell
# script's interpreter line, which is that language's own entry-point signal,
# and `#[` opens a PHP 8 attribute, which carries the framework route table.
_HASH_CODE_PREFIXES: dict[str, bytes] = {"php": b"#[", "shell": b"#!"}
# Languages whose grammar ends a `//` or `#` comment where a template tag
# closes, which puts the rest of that line back in code: `// legacy ?><?php
# system($cmd);` runs the command.
_LINE_COMMENT_CLOSERS: dict[str, bytes] = {"php": b"?>"}
# Languages with a `/* ... */` comment, which the parse-tree reader labels as
# commentary however many lines it spans. A docblock continuation (` * ...`)
# only reads as commentary inside one; outside it a leading `*` is a
# dereference or a multiplication, and the call after it runs.
_BLOCK_COMMENT_LANGUAGES = frozenset(
    {"c", "cpp", "csharp", "css", "go", "java", "javascript", "php", "typescript"}
)
_BLOCK_COMMENT_OPEN = b"/*"
_BLOCK_COMMENT_CLOSE = b"*/"


class StreamingSecurityScanner:
    """Bounded line/window scanner used when exact structural parsing is unavailable."""

    def __init__(
        self,
        file_path: str,
        language: str,
        *,
        signal_limit: int = STRUCTURAL_SIGNAL_LIMIT,
        window_bytes: int = STREAMING_SCAN_WINDOW_BYTES,
        overlap_bytes: int = STREAMING_SCAN_OVERLAP_BYTES,
        sources_only: bool = False,
        text_from_line: int | None = None,
    ) -> None:
        if signal_limit < 1:
            raise ValueError("signal_limit must be positive")
        if overlap_bytes < 1 or window_bytes <= overlap_bytes:
            raise ValueError("streaming scan window must exceed its positive overlap")
        self.file_path = file_path
        self.language = language
        # Every structurally parsed file reads its taint sources through this
        # scanner and keeps nothing else, so that caller skips the other
        # readers. Sources depend only on line framing, comment detection and
        # their own patterns, none of which the skipped readers touch.
        self.sources_only = sources_only
        self.signal_limit = signal_limit
        self.window_bytes = window_bytes
        self.overlap_bytes = overlap_bytes
        self._stride = window_bytes - overlap_bytes
        self._line_buffer = bytearray()
        self._line_number = 1
        self._line_had_bytes = False
        self._line_comment: bool | None = None
        # Carried across the pieces of one line: a `//` or `#` comment runs to
        # the line's end, so no later piece of that line can hold code, and
        # the last byte of a piece is where the next one's `*/` may begin.
        self._line_to_end_comment = False
        self._piece_tail = b""
        # Carried across lines: a `/*` runs until its `*/`, however far away.
        self._block_comment = False
        self._block_comment_line = 0
        # The line a previous read of this same source opened a `/*` on and
        # never closed. A `/*` at or after it opens nothing: see `_scan_bytes`.
        self._text_from_line = text_from_line
        # Where this read left a `/*` open at the end of the source, which is
        # the one position at which it read bytes it never proved were comment.
        self.unclosed_block_line: int | None = None
        self._line_windows = 0
        self._php_use_open = True
        self._php_use_pending: list[tuple[int, bytearray]] | None = None
        self._php_use_pending_bytes = 0
        self._pending_cr = False
        self.bytes_scanned = 0
        self.total_lines = 0
        self.entry_points: list[dict[str, Any]] = []
        self.imports: list[str] = []
        self.import_targets: list[dict[str, Any]] = []
        self.security_sinks: list[dict[str, Any]] = []
        self.security_sources: list[dict[str, Any]] = []
        self.signal_counts = {dimension: 0 for dimension in SIGNAL_DIMENSIONS}
        self._kind_counts: dict[str, dict[str, int]] = {
            dimension: {} for dimension in _KINDED_SIGNAL_LISTS
        }
        self._truncated: set[str] = set()
        self._source_patterns = [
            (kind, _byte_pattern(pattern))
            for kind, pattern in _STREAM_SOURCE_PATTERNS.get(language, [])
        ]
        self._sink_patterns: list[tuple[str, re.Pattern[bytes], list[str]]] = []
        self._entry_patterns: list[tuple[str, re.Pattern[bytes]]] = []
        self._import_patterns: list[re.Pattern[bytes]] = []
        if not sources_only:
            self._sink_patterns = self._compile_sink_patterns()
            self._entry_patterns = [
                (item["kind"], _byte_pattern(item["pattern"]))
                for item in (
                    _ENTRY_ANNOTATIONS.get(language, []) + _ENTRY_LINE_PATTERNS.get(language, [])
                )
            ] + [
                (kind, _byte_pattern(pattern))
                for kind, pattern in _STREAM_EXTRA_ENTRY_PATTERNS.get(language, [])
            ]
            self._import_patterns = [
                _byte_pattern(pattern) for pattern in _STREAM_IMPORT_PATTERNS.get(language, [])
            ]
        # Most windows hold no literal any pattern requires. One search of the
        # lowered window rules those out; only the patterns the gate does not
        # cover still run there, in their catalogue order.
        self._literal_gate = _literal_gate((
            *(pattern for _kind, pattern, _classes in self._sink_patterns),
            *(pattern for _kind, pattern in self._source_patterns),
            *(pattern for _kind, pattern in self._entry_patterns),
            *self._import_patterns,
        ))
        self._ungated_patterns = (
            [entry for entry in self._sink_patterns if _gate_literals(entry[1]) is None],
            [entry for entry in self._source_patterns if _gate_literals(entry[1]) is None],
            [entry for entry in self._entry_patterns if _gate_literals(entry[1]) is None],
            [pattern for pattern in self._import_patterns if _gate_literals(pattern) is None],
        )

    def retains_nothing_from(self, source: bytes) -> bool:
        """Whether a sources-only scan of *source* could retain no record.

        Every window is a slice of one line of the source, so a lowered
        source holding no literal the gate looks for leaves every window to
        the ungated patterns, and a sources-only scanner whose patterns are
        all gated runs nothing else.
        """
        return (
            self.sources_only
            and self._literal_gate is not None
            and not any(self._ungated_patterns)
            and self._literal_gate.search(source.lower()) is None
        )

    def _compile_sink_patterns(
        self,
    ) -> list[tuple[str, re.Pattern[bytes], list[str]]]:
        patterns: list[tuple[str, re.Pattern[bytes], list[str]]] = []
        # Only PHP names its functions case-blind; JavaScript's `Function(`
        # is not every `function(`.
        for definition in _SINK_DEFINITIONS:
            for pattern in definition["patterns"].get(self.language, []):
                patterns.append(
                    (
                        str(definition["kind"]),
                        _byte_pattern(pattern, self.language == "php"),
                        list(definition["vuln_classes"]),
                    )
                )
        for kind, pattern, vuln_classes in _STREAM_EXTRA_SINK_PATTERNS.get(
            self.language, []
        ):
            patterns.append((kind, _byte_pattern(pattern), vuln_classes))
        return patterns

    def feed(self, chunk: bytes) -> None:
        """Consume a fixed source chunk without retaining an attacker-sized line."""
        if not chunk:
            return
        self.bytes_scanned += len(chunk)
        position = 0
        if self._pending_cr:
            if chunk.startswith(b"\n"):
                position = 1
            self._pending_cr = False
        # A separator found ahead of *position* is still the next one, so each
        # kind is searched for again only once the scan has passed it.
        carriage = newline = -2
        while position < len(chunk):
            if carriage != -1 and carriage < position:
                carriage = chunk.find(b"\r", position)
            if newline != -1 and newline < position:
                newline = chunk.find(b"\n", position)
            separators = [value for value in (carriage, newline) if value >= 0]
            if not separators:
                self._append_line_bytes(chunk[position:])
                return
            separator = min(separators)
            if self._line_buffer or separator - position >= self.window_bytes:
                self._append_line_bytes(chunk[position:separator])
                self._finish_line()
            else:
                self._finish_short_line(chunk[position:separator])
            byte = chunk[separator]
            position = separator + 1
            if byte == 0x0D:
                if position < len(chunk) and chunk[position] == 0x0A:
                    position += 1
                elif position == len(chunk):
                    self._pending_cr = True

    def _opens_a_comment(self, stripped: bytes) -> bool:
        """Whether *stripped* — bytes at a line position — opens a `//`/`#` comment."""
        if stripped.startswith(b"//"):
            return True
        if not stripped.startswith(b"#") or self.language not in _HASH_COMMENT_LANGUAGES:
            return False
        code_prefix = _HASH_CODE_PREFIXES.get(self.language)
        if code_prefix is None:
            return True
        # A `#` with nothing after it is either a comment holding nothing a
        # reader could want or the `#[`/`#!` a piece boundary cut in two, and
        # reading it as code costs the first nothing while it keeps the second
        # -- a route table, an interpreter line -- and the rest of its line.
        return len(stripped) >= len(code_prefix) and not stripped.startswith(code_prefix)

    def _line_is_commentary(self, line: bytes) -> bool:
        """Whether every byte of *line* is commentary, carrying block state.

        The parse-tree reader calls a line commentary only when the grammar
        puts all of its text in comments, and this asks the same question of
        bytes: a `//` or `#` comment runs to the end of its line unless the
        language closes one at a tag, and a `/*` runs to its `*/`, which may
        be lines away. Agreeing on this is what keeps a finding from appearing
        or vanishing with the reader that ran; a line holding code anywhere is
        read whole by both, comment text included.

        A block is entered only from a line that *opens* with one, so a `/*`
        written inside a string literal -- which no line reader can see -- can
        never blind the scan to the code that follows it. A block opened after
        code on its line therefore reads as code, which over-reports its
        continuation lines rather than dropping them.

        An opener the source never closes is not a comment region either, and
        reading one as if it were is the one error with no safe direction: it
        drops every signal below the opener while the artifact still reports a
        clean complete read. `_mask_delimited_comments` restores an unclosed
        markup opener verbatim for that reason, and *text_from_line* is how a
        re-read of the same source restores this one.
        """
        position = 0
        while position < len(line):
            if self._block_comment:
                close = line.find(_BLOCK_COMMENT_CLOSE, position)
                if close < 0:
                    return True
                self._block_comment = False
                position = close + len(_BLOCK_COMMENT_CLOSE)
                continue
            stripped = line[position:].lstrip(b" \t\v\f")
            if not stripped:
                return True
            position = len(line) - len(stripped)
            if self._opens_a_comment(stripped):
                closer = _LINE_COMMENT_CLOSERS.get(self.language)
                if closer is not None and line.find(closer, position) >= 0:
                    return False
                self._line_to_end_comment = True
                return True
            if (
                self.language in _BLOCK_COMMENT_LANGUAGES
                and stripped.startswith(_BLOCK_COMMENT_OPEN)
            ):
                if (
                    self._text_from_line is not None
                    and self._line_number >= self._text_from_line
                ):
                    return False
                self._block_comment = True
                self._block_comment_line = self._line_number
                position += len(_BLOCK_COMMENT_OPEN)
                continue
            return False
        # Read to the end: the last byte went into a delimiter or a blank run,
        # so the next piece of this line carries nothing. Every other exit
        # leaves that byte unread, which is what `_closes_in_piece` searches.
        self._piece_tail = b""
        return True

    def _closes_in_piece(self, carry: bytes, piece: bytes, closer: bytes) -> int:
        """Where *closer* ends inside *piece*, or -1 if it is not in it.

        The delimiter may straddle the boundary between two pieces of one
        line, so the search runs over *carry* -- the unread byte the piece
        before it ended on -- and a hit that starts there ends at the front
        of this piece.
        """
        found = (carry + piece).find(closer)
        if found < 0:
            return -1
        return max(found + len(closer) - len(carry), 0)

    def _piece_is_commentary(self, piece: bytes) -> bool:
        """`_line_is_commentary` for one more piece of the line already begun.

        A line the reader is not handed whole -- one longer than a window, or
        one a chunk boundary falls inside -- arrives in pieces, and a comment
        open in the first of them closes wherever the line puts its delimiter,
        which may be any piece. Reading past that delimiter costs signal in
        silence: a `/*` runs on to whatever `*/` comes next and the lines
        between read as comment text, and a `//` or `#` holds the rest of a
        line whose template tag already ended it.

        Nothing is *opened* from a later piece. A `/*` a boundary happens to
        land on sits mid-line, where `_line_is_commentary` opens no block
        either, and once the line holds code it is read whole however many
        pieces that takes.
        """
        carry, self._piece_tail = self._piece_tail, piece[-1:]
        if self._block_comment:
            position = self._closes_in_piece(carry, piece, _BLOCK_COMMENT_CLOSE)
            if position < 0:
                return True
            self._block_comment = False
            return self._line_is_commentary(piece[position:])
        if self._line_to_end_comment:
            closer = _LINE_COMMENT_CLOSERS.get(self.language)
            if closer is None:
                return True
            if self._closes_in_piece(carry, piece, closer) < 0:
                return True
            # The tag put the rest of the line back in code, which is what
            # `_line_is_commentary` answers for the same line read whole.
            self._line_to_end_comment = False
            return False
        if self._line_comment is False:
            return False
        return self._line_is_commentary(piece)

    def _append_line_bytes(self, data: bytes) -> None:
        if not data:
            return
        self._line_had_bytes = True
        if data.strip(b" \t\v\f") or self._block_comment:
            commentary = self._piece_is_commentary(data)
            # The first piece with text owns the verdict, and a later one that
            # reaches code past a closing delimiter overrides it: a line
            # holding code anywhere is read whole, so what is left of it after
            # that piece is scanned.
            if self._line_comment is None or not commentary:
                self._line_comment = commentary
        else:
            self._piece_tail = data[-1:]
        self._line_buffer.extend(data)
        while len(self._line_buffer) >= self.window_bytes:
            window = bytes(self._line_buffer[: self.window_bytes])
            self._scan_window(window, accept_before=self._stride)
            del self._line_buffer[: self._stride]

    def _finish_short_line(self, line: bytes) -> None:
        """`_append_line_bytes` then `_finish_line` for one whole line.

        Only for a line shorter than a window that opens on an empty buffer,
        which is every line's state until bytes are appended: it is scanned in
        place instead of being copied through the buffer.
        """
        if line:
            if line.strip(b" \t\v\f") or self._block_comment:
                self._line_comment = self._line_is_commentary(line)
            self._scan_window(line, accept_before=len(line))
        self._reset_line()

    def _finish_line(self) -> None:
        if self._line_buffer:
            self._scan_window(bytes(self._line_buffer), accept_before=len(self._line_buffer))
        self._line_buffer.clear()
        self._reset_line()

    def _reset_line(self) -> None:
        """Advance to the next line and clear the per-line scan state. Not
        `_line_buffer`: the short-line path never fills it, which is the whole
        difference between the two callers."""
        self.total_lines += 1
        self._line_number += 1
        self._line_had_bytes = False
        self._line_comment = None
        self._line_to_end_comment = False
        self._piece_tail = b""
        self._line_windows = 0

    @staticmethod
    def _snippet(window: bytes, start: int, end: int) -> str:
        left = max(0, start - 48)
        right = min(len(window), max(end + 72, start + 120))
        text = window[left:right].decode("utf-8", errors="replace").strip()
        return text if len(text) <= 120 else text[:117] + "..."

    def _retain_import(self, raw: str, target: dict[str, Any]) -> None:
        self.signal_counts["imports"] += 1
        if len(self.imports) < self.signal_limit:
            self.imports.append(raw)
            self.import_targets.append(target)
        else:
            self._truncated.add("imports")

    def _read_php_use(self, text: bytes) -> None:
        """Accumulate each PHP `use` statement across lines, then publish it."""
        position = 0
        while True:
            if self._php_use_pending is None:
                if self._line_windows:
                    return
                position = _PHP_STATEMENT_LEAD.match(text, position).end()
                namespace = _PHP_NAMESPACE_DECLARATION.match(text, position) is not None
                if namespace:
                    self._php_use_open = True
                elif _PHP_CLASS_DECLARATION.match(text, position):
                    self._php_use_open = False
                statement = (
                    _PHP_USE_STATEMENT.match(text, position) if self._php_use_open else None
                )
                if statement is None:
                    boundary = _PHP_STATEMENT_BOUNDARY.search(text, position)
                    # Only a namespace block holds imports; a `use` inside any
                    # other block on this line is a trait or closure capture.
                    if boundary is None or (boundary.group() == b"{" and not namespace):
                        return
                    position = boundary.end()
                    continue
                position = statement.end()
                self._php_use_pending = []
                self._php_use_pending_bytes = 0
            terminators = [
                (index, len(token))
                for token in (b";", b"?>")
                if (index := text.find(token, position)) >= 0
            ]
            terminator, width = min(terminators, default=(-1, 0))
            segment = text[position:] if terminator < 0 else text[position:terminator]
            if self._php_use_pending and self._php_use_pending[-1][0] == self._line_number:
                # The next window of one long line continues the same text.
                self._php_use_pending[-1][1].extend(segment)
            else:
                self._php_use_pending.append((self._line_number, bytearray(segment)))
            self._php_use_pending_bytes += len(segment)
            if terminator < 0 and self._php_use_pending_bytes < _PHP_USE_STATEMENT_LIMIT:
                return
            self._publish_php_use()
            if terminator < 0:
                return
            position = terminator + width

    def _publish_php_use(self) -> None:
        segments = [
            (line, text.decode("utf-8", errors="replace"))
            for line, text in self._php_use_pending or []
        ]
        self._php_use_pending = None
        body = "\n".join(text for _line, text in segments)
        starts: list[tuple[int, int]] = []
        offset = 0
        for line, text in segments:
            starts.append((offset, line))
            offset += len(text) + 1
        for kind, name, alias, position in _php_use_clauses(body):
            line = next(line for start, line in reversed(starts) if start <= position)
            record = _php_import_record(kind, name, alias, line)
            self._retain_import(
                record["raw"], {**record, "detection": "heuristic_streaming"}
            )

    def _retain(self, dimension: str, record: dict[str, Any]) -> None:
        self.signal_counts[dimension] += 1
        kinds = self._kind_counts[dimension]
        if kinds.get(record["kind"], 0) < self.signal_limit:
            kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
            getattr(self, dimension).append(record)

    def _scan_window(self, window: bytes, *, accept_before: int) -> None:
        if self._line_comment is True:
            return
        if self.language == "php" and not self.sources_only:
            self._read_php_use(window[:accept_before])
        self._line_windows += 1
        sink_patterns, source_patterns, entry_patterns, import_patterns = (
            (self._sink_patterns, self._source_patterns, self._entry_patterns, self._import_patterns)
            if self._literal_gate is None or self._literal_gate.search(window.lower())
            else self._ungated_patterns
        )
        for kind, pattern, vuln_classes in sink_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                self._retain(
                    "security_sinks",
                    {
                        "kind": kind,
                        "line": self._line_number,
                        "function": "<streaming>",
                        "snippet": self._snippet(window, match.start(), match.end()),
                        "vuln_classes": vuln_classes,
                        "detection": "heuristic_streaming",
                    },
                )
        for kind, pattern in source_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                self._retain(
                    "security_sources",
                    {
                        "kind": kind,
                        "line": self._line_number,
                        "snippet": self._snippet(window, match.start(), match.end()),
                        "detection": "heuristic_streaming",
                    },
                )
        for kind, pattern in entry_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                self._retain(
                    "entry_points",
                    {
                        "name": kind,
                        "line": self._line_number,
                        "kind": kind,
                        "annotation": "",
                        "detection": "heuristic_streaming",
                    },
                )
        for pattern in import_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                raw = self._snippet(window, match.start(), match.end())
                target: dict[str, Any] = {
                    "raw": raw,
                    "resolved": "",
                    "line": self._line_number,
                    "detection": "heuristic_streaming",
                }
                if self.language == "php":
                    argument = match.group()[len(match.group(1)):]
                    target.update({
                        "kind": "include",
                        "construct": match.group(1).decode("ascii").lower(),
                        "status": (
                            "dynamic"
                            if _PHP_STREAM_INTERPOLATION.search(
                                _PHP_STREAM_SINGLE_QUOTED.sub(b"''", argument)
                            )
                            else "unclassified"
                        ),
                    })
                self._retain_import(raw, target)

    def finish(self, *, degradation_reason: str) -> dict[str, Any]:
        if self._line_had_bytes:
            self._finish_line()
        if self._php_use_pending is not None:
            self._publish_php_use()
        if self._block_comment:
            # The source ended inside a `/*` it never closed, so the lines
            # from the opener were read as comment text without that ever
            # being true. A caller holding the bytes re-reads them from the
            # opener instead (`_scan_bytes`); a chunk-fed caller cannot, and
            # the debt is what it publishes: a dimension that retained
            # nothing is named unavailable below, and one that retained
            # records says here that it does not carry all of them.
            self.unclosed_block_line = self._block_comment_line
            self._truncated.update(
                dimension
                for dimension in SIGNAL_DIMENSIONS
                if self.signal_counts[dimension]
            )
        for dimension in _KINDED_SIGNAL_LISTS:
            records = getattr(self, dimension)
            if len(records) > self.signal_limit:
                setattr(self, dimension, _kind_balanced(records, self.signal_limit))
            if self.signal_counts[dimension] > len(getattr(self, dimension)):
                self._truncated.add(dimension)
        truncated = sorted(self._truncated)
        unavailable = set(STREAMING_FALLBACK_BASELINE_UNAVAILABLE)
        for dimension, patterns in (
            ("entry_points", self._entry_patterns),
            ("imports", self._import_patterns),
            ("security_sinks", self._sink_patterns),
            ("security_sources", self._source_patterns),
        ):
            # A dimension with no reader was never measured, and so was one
            # whose reader retained nothing: the line tables see neither what
            # the grammar sees -- a script's own statements as its entry point,
            # a sink name that is only quoted text -- nor past the window they
            # read, so silence here is not the negative that an empty
            # dimension on a complete artifact is. A dimension that did retain
            # records says so through the degraded mode and each record's
            # `heuristic_streaming` detection instead; it cannot be named here,
            # because `code_structural_metadata.validated_structural_metadata`
            # and the backend's `StructuralMetadataItem` both require an
            # unavailable dimension to hold nothing at all.
            #
            # The sources-only scan is the exception. Its caller hands it
            # source the grammar already blanked every comment out of and
            # keeps that reading as the file's own, so an empty answer there
            # is the measurement, not the absence of one.
            if not patterns or not (self.sources_only or self.signal_counts[dimension]):
                unavailable.add(dimension)
        return {
            "file_path": self.file_path,
            "language": self.language,
            "structural_index_available": False,
            "analysis_status": "degraded",
            "analysis_mode": "streaming_security_fallback",
            "degradation_reason": degradation_reason,
            "source_size": self.bytes_scanned,
            "bytes_scanned": self.bytes_scanned,
            "unavailable_dimensions": sorted(unavailable),
            "artifact_truncated": bool(truncated),
            "truncated_dimensions": truncated,
            "signal_counts": dict(self.signal_counts),
            "signal_limit_per_dimension": self.signal_limit,
            "scan_window_bytes": self.window_bytes,
            "scan_overlap_bytes": self.overlap_bytes,
            "total_functions": 0,
            "total_exports": 0,
            "total_lines": self.total_lines,
            "functions": [],
            "entry_points": self.entry_points,
            "security_sinks": self.security_sinks,
            "security_sources": self.security_sources,
            "call_sites": [],
            "imports": self.imports,
            "import_targets": self.import_targets,
            "exports": [],
            "classes": [],
        }


def streaming_security_fallback(
    file_path: str,
    language: str,
    chunks,
    *,
    degradation_reason: str,
) -> dict[str, Any]:
    scanner = StreamingSecurityScanner(file_path, language)
    for chunk in chunks:
        scanner.feed(chunk)
    return scanner.finish(degradation_reason=degradation_reason)


def _feed_bytes(
    scanner: StreamingSecurityScanner, source: bytes, *, degradation_reason: str
) -> dict[str, Any]:
    for offset in range(0, len(source), STREAMING_SCAN_WINDOW_BYTES):
        scanner.feed(source[offset : offset + STREAMING_SCAN_WINDOW_BYTES])
    return scanner.finish(degradation_reason=degradation_reason)


def _scan_bytes(
    scanner: StreamingSecurityScanner, source: bytes, *, degradation_reason: str
) -> dict[str, Any]:
    """`_feed_bytes`, re-read from an opener the source never closes.

    A scan that ends inside a `/*` read every line from its opener as comment
    text, which is the one reading nothing in the source supports: the opener
    is a construct the file got wrong, and `_mask_delimited_comments` restores
    such an opener verbatim rather than deleting the signals below it. Having
    the bytes, this does the same -- the second read treats a `/*` at or after
    that line as the text it is, and finds what the first read passed over.

    One re-read is always enough. The first read searched every line from the
    opener for a `*/` and found none, so the source holds none after it, and
    no opener at or after that line can close either.
    """
    observed = _feed_bytes(scanner, source, degradation_reason=degradation_reason)
    if scanner.unclosed_block_line is None:
        return observed
    return _feed_bytes(
        StreamingSecurityScanner(
            scanner.file_path,
            scanner.language,
            signal_limit=scanner.signal_limit,
            window_bytes=scanner.window_bytes,
            overlap_bytes=scanner.overlap_bytes,
            sources_only=scanner.sources_only,
            text_from_line=scanner.unclosed_block_line,
        ),
        source,
        degradation_reason=degradation_reason,
    )


def _fallback_from_bytes(
    file_path: str,
    language: str,
    source: bytes,
    *,
    degradation_reason: str,
) -> dict[str, Any]:
    return _scan_bytes(
        StreamingSecurityScanner(file_path, language),
        source,
        degradation_reason=degradation_reason,
    )


def _attach_bounded_security_sources(
    indexed: dict[str, Any],
    *,
    file_path: str,
    language: str,
    source: bytes,
) -> dict[str, Any]:
    """Read taint sources with the bounded line scanner, unless the caller read
    them exactly. An extractor that already resolved whole-file constructs
    (Blade) keeps its own answer; the per-line table stays the reading the
    streaming fallback uses, where it is the only one available."""
    if "security_sources" in indexed:
        counts = dict(indexed.get("signal_counts") or {})
        counts["security_sources"] = len(indexed["security_sources"])
        indexed["signal_counts"] = counts
        return indexed
    scanner = StreamingSecurityScanner(file_path, language, sources_only=True)
    observed = (
        scanner.finish(degradation_reason="bounded_security_source_scan")
        if scanner.retains_nothing_from(source)
        else _scan_bytes(scanner, source, degradation_reason="bounded_security_source_scan")
    )
    if "security_sources" in observed["unavailable_dimensions"]:
        raise RuntimeError(f"no bounded security-source detector for {language}")
    indexed["security_sources"] = observed["security_sources"]
    counts = dict(indexed.get("signal_counts") or {})
    counts["security_sources"] = int(observed["signal_counts"]["security_sources"])
    indexed["signal_counts"] = counts
    return indexed


def _complete_index_metadata(
    indexed: dict[str, Any],
    *,
    source_size: int,
    analysis_mode: str,
    unscanned_dimensions: set[str],
) -> dict[str, Any]:
    provided_counts = indexed.get("signal_counts")
    if not isinstance(provided_counts, dict):
        provided_counts = {}
    retained_signal_counts = {
        "entry_points": len(indexed.get("entry_points", [])),
        "imports": max(
            len(indexed.get("imports", [])), len(indexed.get("import_targets", []))
        ),
        "security_sinks": len(indexed.get("security_sinks", [])),
        "security_sources": len(indexed.get("security_sources", [])),
    }
    signal_counts: dict[str, int] = {}
    for dimension, retained in retained_signal_counts.items():
        observed = provided_counts.get(dimension, retained)
        if type(observed) is not int or observed < retained:
            raise ValueError(f"{dimension} total undercounts retained records")
        signal_counts[dimension] = observed

    functions = indexed.setdefault("functions", [])
    exports = indexed.setdefault("exports", [])
    total_functions = indexed.get("total_functions", len(functions))
    total_exports = indexed.get("total_exports", len(exports))
    if type(total_functions) is not int or total_functions < len(functions):
        raise ValueError("function total undercounts retained records")
    if type(total_exports) is not int or total_exports < len(exports):
        raise ValueError("export total undercounts retained records")
    indexed["total_functions"] = total_functions
    indexed["total_exports"] = total_exports

    truncated: set[str] = set()
    for dimension, retained in retained_signal_counts.items():
        if signal_counts[dimension] > retained:
            truncated.add(dimension)
    if total_functions > len(functions):
        truncated.add("functions")
    if total_exports > len(exports):
        truncated.add("exports")
    for dimension in _CAPPED_INDEX_LISTS:
        values = indexed.setdefault(dimension, [])
        if len(values) > STRUCTURAL_SIGNAL_LIMIT:
            indexed[dimension] = (
                _kind_balanced(values, STRUCTURAL_SIGNAL_LIMIT)
                if dimension in _KINDED_SIGNAL_LISTS
                else values[:STRUCTURAL_SIGNAL_LIMIT]
            )
            truncated.add("imports" if dimension == "import_targets" else dimension)
    # Truncation and an unscanned scope are different debts on one field. The
    # signal limit is the louder of the two -- it means retained records were
    # dropped -- so it owns the reason, and `unavailable_dimensions` still names
    # what was never read.
    unavailable = sorted(unscanned_dimensions)
    if truncated:
        degradation_reason: str | None = "artifact_signal_limit"
    elif unavailable:
        degradation_reason = UNSCANNED_SCOPE_DEGRADATION_REASON
    else:
        degradation_reason = None
    indexed.update(
        {
            "structural_index_available": True,
            "analysis_status": "complete" if degradation_reason is None else "degraded",
            "analysis_mode": analysis_mode,
            "degradation_reason": degradation_reason,
            "source_size": source_size,
            "bytes_scanned": source_size,
            "unavailable_dimensions": unavailable,
            "artifact_truncated": bool(truncated),
            "truncated_dimensions": sorted(truncated),
            "signal_counts": signal_counts,
            "signal_limit_per_dimension": STRUCTURAL_SIGNAL_LIMIT,
        }
    )
    return indexed


__all__ = ['STREAMING_SCAN_WINDOW_BYTES', 'STREAMING_SCAN_OVERLAP_BYTES', 'STRUCTURAL_SIGNAL_LIMIT', 'STREAMING_FALLBACK_BASELINE_UNAVAILABLE', 'STRUCTURAL_DIMENSIONS', '_UNSUPPORTED_UNAVAILABLE_DIMENSIONS', 'SIGNAL_DIMENSIONS', '_CAPPED_INDEX_LISTS', '_STREAM_SOURCE_PATTERNS', '_STREAM_IMPORT_PATTERNS', '_STREAM_EXTRA_SINK_PATTERNS', '_STREAM_EXTRA_ENTRY_PATTERNS', '_byte_pattern', '_HASH_COMMENT_LANGUAGES', '_HASH_CODE_PREFIXES', 'StreamingSecurityScanner', 'streaming_security_fallback', '_fallback_from_bytes', '_attach_bounded_security_sources', '_complete_index_metadata']
