"""Bounded streaming fallback owned by the tree-sitter index."""
from __future__ import annotations

import re
from typing import Any

from assess.lib.treesitter_catalogues import (
    _ENTRY_ANNOTATIONS,
    _ENTRY_LINE_PATTERNS,
    _SINK_DEFINITIONS,
)
from assess.lib.treesitter_lightweight import (
    _LUA_DYNAMIC_REDIS_COMMAND_RE,
    _PS_SINK_PATTERNS,
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
_UNSUPPORTED_UNAVAILABLE_DIMENSIONS = [
    "call_sites",
    "classes",
    "dataflow",
    "entry_points",
    "exports",
    "functions",
    "imports",
    "security_sinks",
    "security_sources",
]
_SIGNAL_DIMENSIONS = (
    "entry_points",
    "imports",
    "security_sinks",
    "security_sources",
)
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
        ("process_input", r"\b(?:sys\.argv|os\.environ|getenv\s*\(|input\s*\()"),
    ],
    "javascript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies)\b"),
        ("process_input", r"\bprocess\.(?:argv|env)\b"),
    ],
    "typescript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies)\b"),
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
        ("template_input", r"\{\{(?!--)[^}\r\n]+\}\}|\{!![^!\r\n]+!!\}"),
    ],
    "php": [
        ("http_request_input", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),
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
        ("process_input", r"\bgetenv\s*\("),
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
        ("template_input", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>"),
    ],
    "css": [
        ("template_input", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>"),
    ],
    "freemarker": [
        ("template_input", r"[$#]\{[^}\r\n]+\}"),
    ],
}

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
    "php": [r"\b(?:include|include_once|require|require_once|use)\b[^\r\n;]*"],
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
}

_STREAM_EXTRA_SINK_PATTERNS: dict[str, list[tuple[str, str, list[str]]]] = {
    "blade": [
        ("unescaped_output", r"\{!![^!\r\n]+!!\}", ["xss"]),
        ("template_interpolation", r"\{\{(?!--)[^}\r\n]+\}\}", ["xss"]),
        ("inline_event_handler", r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", ["xss"]),
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
        ("template_interpolation", r"\{\{[^}\r\n]+\}\}", ["xss", "ssti"]),
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
}

_STREAM_EXTRA_ENTRY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "blade": [("html_form", r"<form\b")],
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
}


def _byte_pattern(pattern: str) -> re.Pattern[bytes]:
    return re.compile(pattern.encode("ascii"), re.IGNORECASE)


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
    ) -> None:
        if signal_limit < 1:
            raise ValueError("signal_limit must be positive")
        if overlap_bytes < 1 or window_bytes <= overlap_bytes:
            raise ValueError("streaming scan window must exceed its positive overlap")
        self.file_path = file_path
        self.language = language
        self.signal_limit = signal_limit
        self.window_bytes = window_bytes
        self.overlap_bytes = overlap_bytes
        self._stride = window_bytes - overlap_bytes
        self._line_buffer = bytearray()
        self._line_number = 1
        self._line_had_bytes = False
        self._line_comment: bool | None = None
        self._pending_cr = False
        self.bytes_scanned = 0
        self.total_lines = 0
        self.entry_points: list[dict[str, Any]] = []
        self.imports: list[str] = []
        self.import_targets: list[dict[str, Any]] = []
        self.security_sinks: list[dict[str, Any]] = []
        self.security_sources: list[dict[str, Any]] = []
        self.signal_counts = {dimension: 0 for dimension in _SIGNAL_DIMENSIONS}
        self._truncated: set[str] = set()
        self._sink_patterns = self._compile_sink_patterns()
        self._source_patterns = [
            (kind, _byte_pattern(pattern))
            for kind, pattern in _STREAM_SOURCE_PATTERNS.get(language, [])
        ]
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

    def _compile_sink_patterns(
        self,
    ) -> list[tuple[str, re.Pattern[bytes], list[str]]]:
        patterns: list[tuple[str, re.Pattern[bytes], list[str]]] = []
        for definition in _SINK_DEFINITIONS:
            for pattern in definition["patterns"].get(self.language, []):
                patterns.append(
                    (
                        str(definition["kind"]),
                        _byte_pattern(pattern),
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
        while position < len(chunk):
            carriage = chunk.find(b"\r", position)
            newline = chunk.find(b"\n", position)
            separators = [value for value in (carriage, newline) if value >= 0]
            if not separators:
                self._append_line_bytes(chunk[position:])
                return
            separator = min(separators)
            self._append_line_bytes(chunk[position:separator])
            byte = chunk[separator]
            self._finish_line()
            position = separator + 1
            if byte == 0x0D:
                if position < len(chunk) and chunk[position] == 0x0A:
                    position += 1
                elif position == len(chunk):
                    self._pending_cr = True

    def _opens_a_comment(self, stripped: bytes) -> bool:
        """Whether *stripped* — a line's first non-blank bytes — starts a comment."""
        if stripped.startswith(b"//"):
            return True
        if not stripped.startswith(b"#") or self.language not in _HASH_COMMENT_LANGUAGES:
            return False
        code_prefix = _HASH_CODE_PREFIXES.get(self.language)
        return code_prefix is None or not stripped.startswith(code_prefix)

    def _append_line_bytes(self, data: bytes) -> None:
        if not data:
            return
        self._line_had_bytes = True
        if self._line_comment is None:
            stripped = data.lstrip(b" \t\v\f")
            if stripped:
                self._line_comment = self._opens_a_comment(stripped)
        self._line_buffer.extend(data)
        while len(self._line_buffer) >= self.window_bytes:
            window = bytes(self._line_buffer[: self.window_bytes])
            self._scan_window(window, accept_before=self._stride)
            del self._line_buffer[: self._stride]

    def _finish_line(self) -> None:
        if self._line_buffer:
            self._scan_window(bytes(self._line_buffer), accept_before=len(self._line_buffer))
        self.total_lines += 1
        self._line_number += 1
        self._line_buffer.clear()
        self._line_had_bytes = False
        self._line_comment = None

    @staticmethod
    def _snippet(window: bytes, start: int, end: int) -> str:
        left = max(0, start - 48)
        right = min(len(window), max(end + 72, start + 120))
        text = window[left:right].decode("utf-8", errors="replace").strip()
        return text if len(text) <= 120 else text[:117] + "..."

    def _retain(self, dimension: str, record: dict[str, Any] | str) -> None:
        self.signal_counts[dimension] += 1
        target = getattr(self, dimension)
        if len(target) < self.signal_limit:
            target.append(record)
        else:
            self._truncated.add(dimension)

    def _scan_window(self, window: bytes, *, accept_before: int) -> None:
        if self._line_comment is True:
            return
        for kind, pattern, vuln_classes in self._sink_patterns:
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
        for kind, pattern in self._source_patterns:
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
        for kind, pattern in self._entry_patterns:
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
        for pattern in self._import_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                raw = self._snippet(window, match.start(), match.end())
                self.signal_counts["imports"] += 1
                if len(self.imports) < self.signal_limit:
                    self.imports.append(raw)
                    self.import_targets.append(
                        {
                            "raw": raw,
                            "resolved": "",
                            "line": self._line_number,
                            "detection": "heuristic_streaming",
                        }
                    )
                else:
                    self._truncated.add("imports")

    def finish(self, *, degradation_reason: str) -> dict[str, Any]:
        if self._line_had_bytes:
            self._finish_line()
        truncated = sorted(self._truncated)
        unavailable = set(STREAMING_FALLBACK_BASELINE_UNAVAILABLE)
        for dimension, patterns in (
            ("entry_points", self._entry_patterns),
            ("imports", self._import_patterns),
            ("security_sinks", self._sink_patterns),
            ("security_sources", self._source_patterns),
        ):
            if not patterns:
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


def _fallback_from_bytes(
    file_path: str,
    language: str,
    source: bytes,
    *,
    degradation_reason: str,
) -> dict[str, Any]:
    return streaming_security_fallback(
        file_path,
        language,
        (source[offset : offset + STREAMING_SCAN_WINDOW_BYTES] for offset in range(0, len(source), STREAMING_SCAN_WINDOW_BYTES)),
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
    observed = _fallback_from_bytes(
        file_path,
        language,
        source,
        degradation_reason="bounded_security_source_scan",
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
            indexed[dimension] = values[:STRUCTURAL_SIGNAL_LIMIT]
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


__all__ = ['STREAMING_SCAN_WINDOW_BYTES', 'STREAMING_SCAN_OVERLAP_BYTES', 'STRUCTURAL_SIGNAL_LIMIT', 'STREAMING_FALLBACK_BASELINE_UNAVAILABLE', '_UNSUPPORTED_UNAVAILABLE_DIMENSIONS', '_SIGNAL_DIMENSIONS', '_CAPPED_INDEX_LISTS', '_STREAM_SOURCE_PATTERNS', '_STREAM_IMPORT_PATTERNS', '_STREAM_EXTRA_SINK_PATTERNS', '_STREAM_EXTRA_ENTRY_PATTERNS', '_byte_pattern', '_HASH_COMMENT_LANGUAGES', '_HASH_CODE_PREFIXES', 'StreamingSecurityScanner', 'streaming_security_fallback', '_fallback_from_bytes', '_attach_bounded_security_sources', '_complete_index_metadata']
