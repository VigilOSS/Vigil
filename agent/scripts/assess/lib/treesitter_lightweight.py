"""Lightweight structural extractors owned by the tree-sitter index."""
from __future__ import annotations

import bisect
import json
import re
import shlex
from pathlib import Path
from typing import Any

from assess.lib.treesitter_common import _empty_func, _snippet

_DOCKER_INSTR_RE = re.compile(r"^\s*([A-Z]+)\s+(.*)$")
_DOCKER_SECRET_NAMES = re.compile(r"\b(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH)\b", re.IGNORECASE)
_DOCKER_URL_RE = re.compile(r"https?://\S+")


def _extract_dockerfile(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []
    local_sources: list[str] = []
    has_user_directive = False

    # Logical blocks: collect contiguous lines that belong to the same instruction
    # (handle backslash continuations).
    i = 0
    n = len(source_lines)
    while i < n:
        raw = source_lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        m = _DOCKER_INSTR_RE.match(raw)
        if not m:
            i += 1
            continue
        instr = m.group(1).upper()
        block_start = i + 1
        block_text_parts = [m.group(2)]
        while raw.rstrip().endswith("\\") and i + 1 < n:
            i += 1
            raw = source_lines[i]
            block_text_parts.append(raw.rstrip("\\").strip())
        block_end = i + 1
        block_text = " ".join(block_text_parts)
        i += 1

        if instr in {"RUN", "COPY", "ADD", "CMD", "ENTRYPOINT", "USER", "EXPOSE", "HEALTHCHECK", "ENV", "FROM", "ARG", "WORKDIR", "VOLUME", "LABEL"}:
            funcs.append(_empty_func(instr, block_start, block_end))

        if instr == "USER":
            has_user_directive = True
            if re.match(r"\s*(0|root)\b", block_text):
                sinks.append({
                    "kind": "container_runs_as_root",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(stripped),
                    "vuln_classes": ["privilege-escalation"],
                })

        if instr in {"CMD", "ENTRYPOINT"}:
            entry_points.append({
                "name": instr,
                "line": block_start,
                "kind": "container_" + instr.lower(),
                "annotation": "",
            })
            exports.append({"name": instr, "kind": "container_entrypoint", "line": block_start})

        if instr == "EXPOSE":
            for port in re.findall(r"\b(\d+)(?:/\w+)?\b", block_text):
                sinks.append({
                    "kind": "exposed_port",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(f"EXPOSE {port}"),
                    "vuln_classes": ["network-exposure"],
                })

        if instr == "RUN":
            if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sh|bash|zsh)\b", block_text):
                sinks.append({
                    "kind": "remote_pipe_to_shell",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(block_text),
                    "vuln_classes": ["supply-chain", "injection"],
                })
            elif re.search(r"\b(curl|wget)\b", block_text):
                sinks.append({
                    "kind": "external_fetch",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(block_text),
                    "vuln_classes": ["supply-chain"],
                })
            if re.search(r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", block_text):
                sinks.append({
                    "kind": "permissive_chmod",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(block_text),
                    "vuln_classes": ["privilege-escalation"],
                })
            if re.search(r"\bsudo\b", block_text):
                sinks.append({
                    "kind": "sudo_in_build",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(block_text),
                    "vuln_classes": ["privilege-escalation"],
                })

        if instr == "ENV" and _DOCKER_SECRET_NAMES.search(block_text):
            sinks.append({
                "kind": "embedded_secret_env",
                "line": block_start,
                "function": instr,
                "snippet": _snippet(stripped),
                "vuln_classes": ["secrets-exposure"],
            })

        arg_name, has_default, arg_default = block_text.partition("=")
        if instr == "ARG" and has_default and arg_default.strip() and _DOCKER_SECRET_NAMES.search(arg_name):
            sinks.append({
                "kind": "embedded_secret_arg",
                "line": block_start,
                "function": instr,
                "snippet": _snippet(stripped),
                "vuln_classes": ["secrets-exposure"],
            })

        if instr == "ADD":
            url_match = _DOCKER_URL_RE.search(block_text)
            if url_match:
                sinks.append({
                    "kind": "add_external_url",
                    "line": block_start,
                    "function": instr,
                    "snippet": _snippet(block_text),
                    "vuln_classes": ["supply-chain"],
                })
                imports.append(url_match.group(0))

        if instr in {"COPY", "ADD"}:
            try:
                operands = (
                    json.loads(block_text)
                    if block_text.startswith("[") else shlex.split(block_text)
                )
            except (ValueError, TypeError):
                operands = []
            if isinstance(operands, list) and all(isinstance(part, str) for part in operands):
                from_stage = any(part.startswith("--from=") for part in operands)
                paths = [part for part in operands if not part.startswith("--")]
                if not from_stage and len(paths) >= 2:
                    local_sources.extend(
                        path for path in paths[:-1]
                        if not path.startswith(("/", "http://", "https://", "$"))
                    )

        if instr == "FROM":
            # FROM image[:tag][@digest] [AS name]
            img = block_text.split(" AS ")[0].split(" as ")[0].strip()
            if img:
                imports.append(img)

    if not has_user_directive and funcs:
        sinks.append({
            "kind": "missing_user_directive",
            "line": 1,
            "function": "FROM",
            "snippet": "Dockerfile does not set USER -- container runs as root by default",
            "vuln_classes": ["privilege-escalation"],
        })

    return funcs, entry_points, sinks, exports, imports, local_sources


# --- Shell ------------------------------------------------------------------

_SHELL_FUNC_PAREN_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{?")
_SHELL_FUNC_KW_RE = re.compile(r"^\s*function\s+([A-Za-z_][\w-]*)\s*(?:\(\s*\))?\s*\{?")
_SHELL_SOURCE_RE = re.compile(r"^\s*(?:\.|source)\s+(\S+)")


def _extract_shell(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    # First pass: find function starts and infer ends by brace matching (best-effort)
    func_starts: list[tuple[str, int]] = []
    for idx, line in enumerate(source_lines):
        # Skip comment-only lines (but not lines with trailing comments)
        if line.lstrip().startswith("#"):
            continue
        m = _SHELL_FUNC_KW_RE.match(line) or _SHELL_FUNC_PAREN_RE.match(line)
        if m:
            name = m.group(1)
            func_starts.append((name, idx + 1))

    # Compute approximate end lines by scanning braces from each start
    for fi, (name, start_line) in enumerate(func_starts):
        end_line = start_line
        depth = 0
        seen_brace = False
        for j in range(start_line - 1, len(source_lines)):
            for ch in source_lines[j]:
                if ch == "{":
                    depth += 1
                    seen_brace = True
                elif ch == "}":
                    depth -= 1
                    if seen_brace and depth <= 0:
                        end_line = j + 1
                        break
            if seen_brace and depth <= 0:
                break
            end_line = j + 1
        funcs.append(_empty_func(name, start_line, end_line))
        exports.append({"name": name, "kind": "shell_function", "line": start_line})

    for idx, line in enumerate(source_lines):
        stripped = line.lstrip()
        if stripped.startswith("#") and not stripped.startswith("#!"):
            continue
        line_no = idx + 1
        # shebang as entry point
        if idx == 0 and stripped.startswith("#!"):
            entry_points.append({
                "name": "script",
                "line": 1,
                "kind": "shell_script",
                "annotation": stripped,
            })
        # source / dot includes
        m = _SHELL_SOURCE_RE.match(line)
        if m:
            imports.append(m.group(1))
        # Security sinks
        if re.search(r"\beval\b", line):
            sinks.append({
                "kind": "shell_eval",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sh|bash|zsh)\b", line):
            sinks.append({
                "kind": "remote_pipe_to_shell",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["supply-chain", "injection"],
            })
        if re.search(r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", line):
            sinks.append({
                "kind": "permissive_chmod",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["privilege-escalation"],
            })
        if re.search(r"\bsudo\b", line):
            sinks.append({
                "kind": "sudo",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["privilege-escalation"],
            })
        # Command substitution with $1/$@/$* (user-tainted) inside backticks or $(...)
        if re.search(r"(?:`[^`]*\$[1-9@*][^`]*`|\$\([^)]*\$[1-9@*][^)]*\))", line):
            sinks.append({
                "kind": "tainted_command_substitution",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        # Hardcoded credentials: VAR=... where VAR name looks secret-y and value is a quoted literal
        cred_m = re.match(r"\s*(?:export\s+)?([A-Za-z_][\w]*)\s*=\s*['\"]([^'\"]+)['\"]", line)
        if cred_m and _DOCKER_SECRET_NAMES.search(cred_m.group(1)):
            sinks.append({
                "kind": "hardcoded_credential",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["secrets-exposure"],
            })

    return funcs, entry_points, sinks, exports, imports


def _find_enclosing_func(funcs: list[dict[str, Any]], line_no: int) -> str:
    """Name the script-language function a line falls in, or the file scope."""
    for f in funcs:
        if f["line_start"] <= line_no <= f["line_end"]:
            return f["name"]
    return "<script>"


# --- PowerShell -------------------------------------------------------------

_PS_FUNC_RE = re.compile(
    r"^\s*(?:function|filter|workflow)\s+([A-Za-z_][\w-]*(?::[A-Za-z_][\w-]*)?)",
    re.IGNORECASE,
)
_PS_PARAM_BLOCK_RE = re.compile(r"\bparam\s*\(", re.IGNORECASE)
_PS_FUNC_SIGNATURE_RE = re.compile(
    r"^\s*(?:function|filter|workflow)\s+[\w:-]+\s*\(", re.IGNORECASE
)
_PS_PARAM_NAME_RE = re.compile(r"\$([A-Za-z_]\w*)")
_PS_IMPORT_RE = re.compile(
    r"""^\s*(?:Import-Module|using\s+(?:module|namespace))\s+['"]?([^\s'";]+)""",
    re.IGNORECASE,
)
# Dot-sourcing runs another script's contents in the caller's scope, which is
# both an import edge and how most PowerShell codebases share helpers.
_PS_DOT_SOURCE_RE = re.compile(
    r"""^\s*\.\s+['"]?([^\s'";]+\.psm?1)""", re.IGNORECASE
)

# PowerShell's security-relevant cmdlets, one table serving both the structural
# extractor below and the bounded streaming scanner, so the two paths cannot
# report a `.ps1` differently. Each pattern is anchored on a cmdlet or type
# accelerator rather than a bare verb, because PowerShell's own aliases (`iex`,
# `iwr`) are the short forms an attacker-facing script actually uses.
_PS_SINK_PATTERNS: list[tuple[str, str, list[str]]] = [
    (
        "dynamic_code_evaluation",
        r"\b(?:Invoke-Expression|iex)\b|\[scriptblock\]::Create\s*\(|\bAdd-Type\b",
        ["injection"],
    ),
    (
        "process_exec",
        r"\b(?:Start-Process|Invoke-Item|Invoke-Command|Start-Job)\b",
        ["injection"],
    ),
    (
        "url_fetch",
        r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bNet\.WebClient\b",
        ["ssrf"],
    ),
    (
        "remote_download_to_execution",
        r"\b(?:DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
        r"[^|\r\n]*\|\s*(?:iex|Invoke-Expression)\b",
        ["injection"],
    ),
    (
        "deserialization",
        r"\bImport-Clixml\b"
        r"|\[System\.Management\.Automation\.PSSerializer\]::Deserialize",
        ["deserialization"],
    ),
    (
        "file_path",
        r"\b(?:Get-Content|Set-Content|Add-Content|Out-File|Remove-Item|Join-Path)\b",
        ["path-traversal"],
    ),
    (
        "plaintext_secret",
        r"\bConvertTo-SecureString\b[^\r\n]*-AsPlainText",
        ["secrets-exposure"],
    ),
    (
        "certificate_validation_disabled",
        r"\bServerCertificateValidationCallback\b|-SkipCertificateCheck\b",
        ["crypto-misuse"],
    ),
]
_PS_LITERAL_ASSIGNMENT_RE = re.compile(r"""\s*\$([A-Za-z_]\w*)\s*=\s*['"][^'"]+['"]""")
_PS_COMPILED_SINKS = tuple(
    (kind, re.compile(pattern, re.IGNORECASE), vuln_classes)
    for kind, pattern, vuln_classes in _PS_SINK_PATTERNS
)


def _ps_balanced_span(text: str, open_paren: int) -> str:
    """Return what sits between the `(` at *open_paren* and its matching `)`."""
    depth = 0
    for index in range(open_paren, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
    return text[open_paren + 1 :]


def _ps_declared_params(block: str) -> list[str]:
    """Return the parameter names a function declares, either way it can.

    PowerShell accepts both a C-style signature after the name and a `param()`
    block as the body's first statement; a script's own arguments arrive only
    through the latter.
    """
    signature = _PS_FUNC_SIGNATURE_RE.match(block)
    if signature is not None:
        declaration = _ps_balanced_span(block, signature.end() - 1)
    else:
        param_block = _PS_PARAM_BLOCK_RE.search(block)
        if param_block is None:
            return []
        declaration = _ps_balanced_span(block, param_block.end() - 1)
    return _PS_PARAM_NAME_RE.findall(declaration)


def _ps_block_end(source_lines: list[str], start_index: int) -> int:
    """Return the 1-based line on which the block opened at *start_index* closes."""
    depth = 0
    opened = False
    for index in range(start_index, len(source_lines)):
        for char in source_lines[index]:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
        if opened and depth <= 0:
            return index + 1
    return len(source_lines)


def _extract_powershell(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    in_block_comment = False
    for idx, line in enumerate(source_lines):
        stripped = line.strip()
        # `<# ... #>` is comment-based help, and its `.EXAMPLE` sections quote
        # the very cmdlets this extractor flags -- skipping the block is what
        # keeps a documented script from reading as a vulnerable one.
        if in_block_comment:
            in_block_comment = "#>" not in stripped
            continue
        if stripped.startswith("<#"):
            in_block_comment = "#>" not in stripped[2:]
            continue
        if stripped.startswith("#"):
            continue
        line_no = idx + 1

        declaration = _PS_FUNC_RE.match(line)
        if declaration is not None:
            name = declaration.group(1)
            end_line = _ps_block_end(source_lines, idx)
            func = _empty_func(name, line_no, end_line)
            func["params"] = _ps_declared_params("\n".join(source_lines[idx:end_line]))
            funcs.append(func)
            exports.append(
                {"name": name, "kind": "powershell_function", "line": line_no}
            )

        enclosing = _find_enclosing_func(funcs, line_no)
        # A `param()` block outside every function is the script's own argument
        # surface: whatever invokes the script reaches the body through it.
        if enclosing == "<script>" and _PS_PARAM_BLOCK_RE.match(stripped):
            entry_points.append({
                "name": "<script>",
                "line": line_no,
                "kind": "script_parameters",
                "annotation": _snippet(line),
            })

        imported = _PS_IMPORT_RE.match(line) or _PS_DOT_SOURCE_RE.match(line)
        if imported is not None:
            imports.append(imported.group(1))

        for kind, pattern, vuln_classes in _PS_COMPILED_SINKS:
            if pattern.search(line):
                sinks.append({
                    "kind": kind,
                    "line": line_no,
                    "function": enclosing,
                    "snippet": _snippet(line),
                    "vuln_classes": list(vuln_classes),
                })
        credential = _PS_LITERAL_ASSIGNMENT_RE.match(line)
        if credential and _DOCKER_SECRET_NAMES.search(credential.group(1)):
            sinks.append({
                "kind": "hardcoded_credential",
                "line": line_no,
                "function": enclosing,
                "snippet": _snippet(line),
                "vuln_classes": ["secrets-exposure"],
            })

    return funcs, entry_points, sinks, exports, imports


# --- Lua --------------------------------------------------------------------

_LUA_FUNC_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][\w.:]*)\s*\(([^)]*)\)"
)
_LUA_LOCAL_FUNC_ASSIGN_RE = re.compile(
    r"^\s*local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(([^)]*)\)"
)
_LUA_DYNAMIC_REDIS_COMMAND_RE = r"\bredis\.(?:call|pcall)\s*\(\s*(?!['\"])[^,\s)]+"


def _extract_lua(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    starts: list[tuple[str, list[str], int, int, bool]] = []
    for idx, line in enumerate(source_lines):
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        m = _LUA_FUNC_RE.match(line) or _LUA_LOCAL_FUNC_ASSIGN_RE.match(line)
        if m:
            name = m.group(1)
            params = [p.strip() for p in m.group(2).split(",") if p.strip()]
            starts.append((name, params, idx + 1, m.end(), stripped.startswith("local ")))

    # Approximate function end by counting nested block-openers against `end`.
    for k, (name, params, start_line, signature_end, is_local) in enumerate(starts):
        next_start = starts[k + 1][2] - 1 if k + 1 < len(starts) else len(source_lines)
        end_line = next_start
        depth = 1
        for j in range(start_line - 1, len(source_lines)):
            line = source_lines[j][signature_end:] if j == start_line - 1 else source_lines[j]
            code = re.sub(r"--.*$", "", line)
            # These keywords each open a block that requires a matching `end`.
            depth += len(re.findall(r"\b(?:function|if|for|while|do)\b", code))
            depth -= len(re.findall(r"\bend\b", code))
            if depth <= 0:
                end_line = j + 1
                break
            end_line = j + 1
        funcs.append({
            "name": name,
            "qualified_name": name,
            "line_start": start_line,
            "line_end": end_line,
            "params": params,
            "modifiers": [],
            "annotations": [],
            "is_entry_point": False,
        })
        if not is_local:
            exports.append({"name": name, "kind": "lua_function", "line": start_line})

    for idx, line in enumerate(source_lines):
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        line_no = idx + 1
        req_m = re.search(r"""require\s*\(?\s*['"]([^'"]+)['"]""", line)
        if req_m:
            imports.append(req_m.group(1))
        if re.search(_LUA_DYNAMIC_REDIS_COMMAND_RE, line):
            sinks.append({
                "kind": "redis_dynamic_command",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\b(loadstring|load)\s*\(", line):
            sinks.append({
                "kind": "dynamic_code_load",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\bos\.execute\s*\(", line):
            sinks.append({
                "kind": "os_execute",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\bio\.popen\s*\(", line):
            sinks.append({
                "kind": "io_popen",
                "line": line_no,
                "function": _find_enclosing_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })

    return funcs, entry_points, sinks, exports, imports


# --- HTML / templates -------------------------------------------------------

_HTML_TAG_RE = re.compile(
    r"<(?P<tag>form|script|link|iframe)\b(?P<attrs>(?:\"[^\"]*\"|'[^']*'|[^'\">])*)>",
    re.IGNORECASE,
)
_HTML_ATTR_RE = re.compile(
    r"(?P<name>[^\s=/>]+)(?:\s*=\s*(?:\"(?P<double>[^\"]*)\"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+)))?"
)
_HTML_INLINE_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE)
_HTML_JS_URL_RE = re.compile(r"""=\s*['"]\s*javascript:""", re.IGNORECASE)
_HTML_MUSTACHE_RE = re.compile(r"\{\{[^}]+\}\}")
_HTML_ASP_RE = re.compile(r"<%[^%]+%>")
def _mask_delimited_comments(
    source_lines: list[str], opening: str, closing: str
) -> list[str]:
    """Blank out comment regions, keeping every line and column in place.

    An HTML comment spans lines, so a per-line prefix test cannot see it. Masking
    with spaces rather than deleting keeps line numbers and match offsets true, so
    a real tag sharing a line with a closed comment is still found. Without this a
    commented-out `<form>` registers as an entry point and a commented-out remote
    `<script src>` as a supply-chain sink -- a reachability claim on dead markup.
    """
    masked: list[str] = []
    in_comment = False
    for line in source_lines:
        out: list[str] = []
        i = 0
        while i < len(line):
            if in_comment:
                close = line.find(closing, i)
                if close == -1:
                    out.append(" " * (len(line) - i))
                    i = len(line)
                else:
                    out.append(" " * (close + len(closing) - i))
                    i = close + len(closing)
                    in_comment = False
            else:
                start = line.find(opening, i)
                if start == -1:
                    out.append(line[i:])
                    i = len(line)
                else:
                    out.append(line[i:start])
                    i = start
                    in_comment = True
        masked.append("".join(out))
    return masked


def _extract_html(
    source_lines: list[str],
    *,
    template_comments: tuple[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    # Detect against a comment-masked copy; keep raw lines for evidence.
    masked_lines = _mask_delimited_comments(source_lines, "<!--", "-->")
    if template_comments is not None:
        masked_lines = _mask_delimited_comments(masked_lines, *template_comments)
    text = "\n".join(masked_lines)
    line_starts = [0]
    for line in masked_lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    for match in _HTML_TAG_RE.finditer(text):
        tag = match.group("tag").lower()
        attrs: dict[str, str] = {}
        for attr in _HTML_ATTR_RE.finditer(match.group("attrs")):
            value = next(
                (part for part in attr.group("double", "single", "bare") if part is not None),
                None,
            )
            if value is not None:
                attrs.setdefault(attr.group("name").lower(), value)
        line_no = bisect.bisect_right(line_starts, match.start())
        raw_line = source_lines[line_no - 1]
        if tag == "form":
            action = attrs.get("action", "")
            entry_points.append({
                "name": "form",
                "line": line_no,
                "kind": "html_form",
                "annotation": action,
            })
            funcs.append(_empty_func(f"form:{action}", line_no, line_no))
        elif tag == "script" and (src := attrs.get("src")):
            imports.append(src)
            if src.startswith(("http://", "//")):
                sinks.append({
                    "kind": "external_script_load",
                    "line": line_no,
                    "function": "<html>",
                    "snippet": _snippet(raw_line),
                    "vuln_classes": ["supply-chain", "xss"],
                })
            elif src.startswith("https://"):
                sinks.append({
                    "kind": "external_script_load",
                    "line": line_no,
                    "function": "<html>",
                    "snippet": _snippet(raw_line),
                    "vuln_classes": ["supply-chain"],
                })
        elif tag == "link" and (href := attrs.get("href")):
            imports.append(href)
        elif tag == "iframe" and (src := attrs.get("src")):
            imports.append(src)
            sinks.append({
                "kind": "iframe_embed",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(raw_line),
                "vuln_classes": ["clickjacking", "xss"],
            })

    for idx, (line, raw_line) in enumerate(zip(masked_lines, source_lines)):
        line_no = idx + 1
        if _HTML_INLINE_HANDLER_RE.search(line):
            sinks.append({
                "kind": "inline_event_handler",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(raw_line),
                "vuln_classes": ["xss"],
            })
        if _HTML_JS_URL_RE.search(line):
            sinks.append({
                "kind": "javascript_url",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(raw_line),
                "vuln_classes": ["xss"],
            })
        if _HTML_MUSTACHE_RE.search(line):
            sinks.append({
                "kind": "template_interpolation",
                "line": line_no,
                "function": "<template>",
                "snippet": _snippet(raw_line),
                "vuln_classes": ["xss", "ssti"],
            })
        if _HTML_ASP_RE.search(line):
            sinks.append({
                "kind": "asp_interpolation",
                "line": line_no,
                "function": "<template>",
                "snippet": _snippet(raw_line),
                "vuln_classes": ["xss", "ssti"],
            })

    return funcs, entry_points, sinks, exports, imports


# --- Blade (Laravel server templates) ---------------------------------------

# One alternation, scanned in order over the joined source: a Blade comment
# wins over the echo forms it can contain, and both echo forms cross line
# boundaries in real templates (`{!! trans('k', [\n ... \n]) !!}`), which a
# per-line pass cannot see. `@{{ ... }}` is Blade's own escape for a client-side
# framework's braces and renders literally, so it is not an echo at all.
_BLADE_CONSTRUCT_RE = re.compile(
    r"\{\{--(?P<comment>.*?)--\}\}"
    r"|\{!!(?P<raw>.*?)!!\}"
    r"|(?<!@)\{\{(?P<escaped>.*?)\}\}",
    re.DOTALL,
)
# The composition edges of the view graph: which template pulls in which.
# Longer directive names first so `includeIf` is not consumed by `include`.
_BLADE_IMPORT_RE = re.compile(
    r"@(?:extends|includeFirst|includeUnless|includeWhen|includeIf|include"
    r"|component|each)\s*\(\s*\[?\s*['\"]([^'\"]+)['\"]"
)
# The named slots a layout declares and a child fills -- the other half of the
# same graph, and the only thing a Blade template exports.
_BLADE_SLOT_RE = re.compile(
    r"@(?P<directive>section|yield)\s*\(\s*['\"](?P<name>[^'\"]+)['\"]"
)


def _blade_echoes(source_lines: list[str]) -> list[dict[str, Any]]:
    r"""Every Blade echo in one ordered `_BLADE_CONSTRUCT_RE` scan.

    The alternation is the only reading that can tell an echo from the
    `{{-- --}}` comment that may contain one: a per-line ``\{\{(?!--)`` rejects
    only a match *starting* at the comment's braces, and the engine then
    matches the echo inside it. `@{{ }}` is Blade's escape for a client-side
    framework's braces and renders literally, so it is not an echo either.
    Both the sink and the taint-source readings come from here, so the two
    cannot disagree about what a Blade echo is.
    """
    text = "\n".join(source_lines)
    line_starts = [0]
    for line in source_lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    echoes: list[dict[str, Any]] = []
    for match in _BLADE_CONSTRUCT_RE.finditer(text):
        if match.group("comment") is not None:
            continue
        raw = match.group("raw")
        line = bisect.bisect_right(line_starts, match.start())
        echoes.append({
            "line": line,
            "raw": raw is not None,
            "expression": raw if raw is not None else match.group("escaped"),
            "snippet": _snippet(source_lines[line - 1]),
        })
    return echoes


def _blade_template_sources(source_lines: list[str]) -> list[dict[str, Any]]:
    """Blade's taint sources: the echoes are where controller data -- and
    through it the request -- enters the rendered document."""
    return [
        {
            "kind": "template_input",
            "line": echo["line"],
            "snippet": echo["snippet"],
            "detection": "heuristic_template_regex",
        }
        for echo in _blade_echoes(source_lines)
    ]


def _extract_blade(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Index a Blade template.

    The HTML pass runs first so a `.blade.php` yields every signal a `.html`
    file would -- forms as entry points, external scripts, inline handlers. Its
    mustache rule is then dropped rather than kept: in Blade `{{ }}` is the
    *escaped* echo and `{{-- --}}` is a comment, so reporting both as one
    `ssti`-bearing `template_interpolation` is the wrong answer twice. Blade's
    own pass replaces it and distinguishes `{{ }}` from `{!! !!}`, which is the
    unescaped construct and the reason this language has its own extractor.

    Escaping is an observation, not clearance -- Blade's `e()` escapes for HTML
    text, so an escaped echo inside a `<script>` or a URL attribute is still
    XSS. See ``FREEMARKER_ESCAPE_OBSERVATIONS`` for the shared vocabulary.
    """
    funcs, entry_points, sinks, exports, imports = _extract_html(
        source_lines, template_comments=("{{--", "--}}")
    )
    sinks = [sink for sink in sinks if sink["kind"] != "template_interpolation"]

    text = "\n".join(_mask_delimited_comments(source_lines, "{{--", "--}}"))
    line_starts = [0]
    for line in source_lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    def line_of(offset: int) -> int:
        return bisect.bisect_right(line_starts, offset)

    for echo in _blade_echoes(source_lines):
        sinks.append({
            "kind": (
                "unescaped_output" if echo["raw"] else "template_interpolation"
            ),
            "line": echo["line"],
            "function": "<template>",
            "snippet": echo["snippet"],
            "vuln_classes": ["xss"],
            "detection": "heuristic_template_regex",
            "expression": _snippet(" ".join(echo["expression"].split())),
            "escape_observation": (
                "unverified_no_escape_observed"
                if echo["raw"]
                else "unverified_escape_observed"
            ),
        })

    for match in _BLADE_IMPORT_RE.finditer(text):
        imports.append(match.group(1))

    for match in _BLADE_SLOT_RE.finditer(text):
        exports.append({
            "name": match.group("name"),
            "kind": f"blade_{match.group('directive')}",
            "line": line_of(match.start()),
        })

    return funcs, entry_points, sinks, exports, imports


# --- CSS / SCSS -------------------------------------------------------------

_CSS_IMPORT_RE = re.compile(r"@import\s+(?:url\()?\s*['\"]?([^'\"\s)]+)", re.IGNORECASE)
_CSS_URL_RE = re.compile(r"\burl\(\s*['\"]?([^'\"\)]+)", re.IGNORECASE)
_CSS_EXPRESSION_RE = re.compile(r"\bexpression\s*\(", re.IGNORECASE)
_CSS_BEHAVIOR_RE = re.compile(r"\bbehavior\s*:", re.IGNORECASE)
_CSS_BINDING_RE = re.compile(r"-moz-binding\s*:", re.IGNORECASE)


def _extract_css(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    masked_lines = _mask_delimited_comments(source_lines, "/*", "*/")
    for idx, line in enumerate(masked_lines):
        if line.lstrip().startswith("//"):
            masked_lines[idx] = " " * len(line)
    text = "\n".join(masked_lines)
    line_starts = [0]
    for line in masked_lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    for match in _CSS_IMPORT_RE.finditer(text):
        url = match.group(1)
        imports.append(url)
        if url.startswith(("http://", "//")):
            line_no = bisect.bisect_right(line_starts, match.start())
            sinks.append({
                "kind": "external_css_import",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(source_lines[line_no - 1]),
                "vuln_classes": ["supply-chain"],
            })
    for match in _CSS_URL_RE.finditer(text):
        ref = match.group(1)
        if ref.startswith(("http://", "//", "https://", "data:")):
            imports.append(ref)

    for idx, line in enumerate(masked_lines):
        line_no = idx + 1
        if _CSS_EXPRESSION_RE.search(line):
            sinks.append({
                "kind": "css_expression",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(source_lines[idx]),
                "vuln_classes": ["xss"],
            })
        if _CSS_BEHAVIOR_RE.search(line):
            sinks.append({
                "kind": "css_behavior",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(source_lines[idx]),
                "vuln_classes": ["xss"],
            })
        if _CSS_BINDING_RE.search(line):
            sinks.append({
                "kind": "css_moz_binding",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(source_lines[idx]),
                "vuln_classes": ["xss"],
            })

    return funcs, entry_points, sinks, exports, imports


# --- FreeMarker -------------------------------------------------------------

# Escape and context evidence from a line scanner is advisory. FreeMarker's
# real escaping depends on the output format in force, the directive stack that
# encloses a site, and the runtime type of the value -- none of which a regex
# can settle. Every member of this vocabulary therefore names an *observation*,
# never a verdict: there is deliberately no value that reads as "safe", and an
# interpolation stays an XSS sink whatever was observed, because a false clean
# on a template is worse than no signal at all.
FREEMARKER_ESCAPE_OBSERVATIONS = (
    "unverified_escape_observed",
    "unverified_partial_escape_observed",
    "unverified_escape_suppressed",
    "unverified_no_escape_observed",
)

# Where an interpolation's bytes land in the rendered document. Which escaper
# would be correct depends on this, so a reviewer needs the context even though
# it too is regex-derived.
FREEMARKER_OUTPUT_CONTEXTS = (
    "html_text",
    "html_attribute",
    "url_attribute",
    "event_handler_attribute",
    "style_attribute",
    "html_tag",
    "html_comment",
    "script",
    "style",
)

_FREEMARKER_ESCAPER_BUILTINS = frozenset({
    "html", "xhtml", "xml", "rtf", "esc",
    "js_string", "jsString", "json_string", "jsonString",
    "url", "urlPath", "url_path",
})
_FREEMARKER_ESCAPE_SUPPRESSORS = frozenset({"no_esc", "noEsc"})
# Directives that change the escaping ambient to the interpolations they
# enclose. Tracked as a stack so an inner one overrides its parent.
_FREEMARKER_ESCAPE_SCOPES = frozenset({
    "escape", "noescape", "outputformat", "autoesc", "noautoesc",
})
# FreeMarker's markup output formats -- the ones whose auto-escaper escapes for
# a markup document. An allowlist, not a denylist of `plaintext`/`undefined`:
# `JavaScript`, `JSON` and `CSS` are built-in formats that escape for something
# other than HTML, and an application may register any name it likes, so a
# denylist reads every format nobody enumerated as escaping. That is a false
# clean on the exact template that needed the reviewer.
_FREEMARKER_ESCAPING_FORMATS = frozenset({"html", "xhtml", "xml", "rtf"})
# FreeMarker's "recognize output format by file extension" feature: ``.ftlh``
# means HTML and ``.ftlx`` means XML, both escaping output formats, so
# auto-escaping is on for the whole template before a single directive is read.
# A bare ``.ftl`` inherits the application's configured default, which is
# ``undefined`` out of the box and which this file cannot see either way -- so it
# stays False, and every interpolation in it is reported unescaped until an
# explicit directive says otherwise. An explicit ``<#ftl ...>`` header still wins
# over the extension in both directions, because that is FreeMarker's own order.
_FREEMARKER_ESCAPING_EXTENSIONS = frozenset({".ftlh", ".ftlx"})
_FREEMARKER_FORM_FIELD_TAGS = frozenset({"button", "input", "select", "textarea"})
_FREEMARKER_URL_ATTRIBUTES = frozenset({
    "action", "background", "cite", "codebase", "data", "formaction", "href",
    "longdesc", "manifest", "poster", "profile", "src", "srcset", "usemap",
    "xlink:href",
})
_FREEMARKER_URL_VULN_CLASSES = ("xss", "open-redirect")
_FREEMARKER_BUILTIN_RE = re.compile(r"\?([A-Za-z_]\w*)")
_FREEMARKER_DIRECTIVE_NAME_RE = re.compile(r"^</?[#@]([A-Za-z_][\w.]*)")
_FREEMARKER_CALLABLE_RE = re.compile(r"^<#(?:macro|function)\s+([A-Za-z_$][\w$]*)\s*")
# Matched with `re.match(text, offset)`, which anchors on its own; a `^` here
# would additionally demand the start of the whole source.
_FREEMARKER_TAG_NAME_RE = re.compile(r"</?([A-Za-z][-\w:]*)")
_FREEMARKER_ATTRIBUTE_NAME_RE = re.compile(r"[^\s=/>]+")
_FREEMARKER_STRING_LITERAL_RE = re.compile(r"""(['"])(.*?)\1""")
_FREEMARKER_OUTPUT_FORMAT_RE = re.compile(r"""output_format\s*=\s*(['"])([^'"]*)\1""")
_FREEMARKER_AUTO_ESC_RE = re.compile(r"auto_esc\s*=\s*(true|false)")
_FREEMARKER_EVENT_ATTRIBUTE_RE = re.compile(r"^on[a-z]+$")
_FREEMARKER_SCALAR_LITERAL_RE = re.compile(r"^(?:-?\d+(?:\.\d+)?|true|false)$")
# Constructs that evaluate template or Java code chosen at render time: the
# FreeMarker sandbox-escape primitives, distinct from ordinary interpolation.
_FREEMARKER_DYNAMIC_EVAL_RE = re.compile(
    r"\?(?:eval|eval_json|evalJson|interpret|new)\b"
    r"|\bfreemarker\.template\.utility\.(?:Execute|ObjectConstructor|JythonRuntime)\b"
)
# An unterminated `${` would otherwise make every later opener rescan the rest
# of the file, so the search for a closing brace is bounded. A run longer than
# this is reported as malformed, which keeps the site visible either way.
_FREEMARKER_MAX_EXPRESSION_CHARS = 4096


def _freemarker_split_top_level(expression: str, separators: str) -> list[str]:
    """Split *expression* on *separators* outside string literals and brackets."""
    pieces: list[str] = []
    quote = ""
    depth = 0
    start = 0
    index = 0
    while index < len(expression):
        char = expression[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and char in separators:
            pieces.append(expression[start:index])
            start = index + 1
        index += 1
    pieces.append(expression[start:])
    return [piece for piece in (item.strip() for item in pieces) if piece]


def _freemarker_interpolation_end(text: str, brace: int) -> int:
    """Return the offset just past the `}` closing the interpolation, or -1."""
    limit = min(len(text), brace + _FREEMARKER_MAX_EXPRESSION_CHARS)
    quote = ""
    depth = 0
    index = brace
    while index < limit:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return -1


def _freemarker_attribute_value_end(text: str, start: int, quote: str, length: int) -> int:
    """Return the offset of the `quote` closing an attribute value, or -1.

    Interpolation spans are stepped over, because a quote inside one belongs to
    the FreeMarker expression and not to the attribute: `href="${url!""}"` and
    `href="${msg("key")}"` are two of the commonest idioms in the themes this
    extractor targets, and stopping at the first matching quote truncates the
    value mid-`${`, downgrading a URL-context site to malformed noise.
    """
    index = start
    while index < length:
        char = text[index]
        if char == quote:
            return index
        if char in "$#" and index + 1 < length and text[index + 1] == "{":
            close = _freemarker_interpolation_end(text, index + 1)
            if close > 0:
                index = close
                continue
        index += 1
    return -1


def _freemarker_span_interpolations(text: str, start: int, end: int):
    """Yield ``(open, close, syntax)`` for each interpolation in ``text[start:end]``.

    ``close`` is -1 when the site is unterminated inside the span; the scan then
    resumes just past the opening marker so the rest of the file is still read.
    """
    index = start
    while index < end:
        if text[index] in "$#" and index + 1 < end and text[index + 1] == "{":
            syntax = "expression" if text[index] == "$" else "numeric"
            close = _freemarker_interpolation_end(text, index + 1)
            if close < 0 or close > end:
                yield index, -1, syntax
                index += 2
                continue
            yield index, close, syntax
            index = close
            continue
        index += 1


def _freemarker_builtins(expression: str) -> list[str]:
    """Return the `?builtin` tokens in *expression*, verbatim and in source order."""
    return [
        f"?{match.group(1)}"
        for match in _FREEMARKER_BUILTIN_RE.finditer(expression)
    ]


def _freemarker_observed_escapers(expression: str) -> list[str]:
    """Return the escaping-related builtins applied anywhere in *expression*."""
    return [
        token
        for token in _freemarker_builtins(expression)
        if token[1:] in _FREEMARKER_ESCAPER_BUILTINS
        or token[1:] in _FREEMARKER_ESCAPE_SUPPRESSORS
    ]


def _freemarker_value_operands(expression: str) -> list[str]:
    """Return the sub-expressions whose escaping decides the rendered bytes.

    Each top-level `+` operand contributes itself; a string literal contributes
    only the interpolations nested inside it, because FreeMarker evaluates
    `${...}` within string literals too; a scalar literal contributes nothing.
    """
    operands: list[str] = []
    for operand in _freemarker_split_top_level(expression, "+"):
        if len(operand) >= 2 and operand[0] in "\"'" and operand[-1] == operand[0]:
            operands.extend(
                operand[open_at + 2 : close_at - 1]
                for open_at, close_at, _syntax in _freemarker_span_interpolations(
                    operand, 0, len(operand)
                )
                if close_at > 0
            )
        elif not _FREEMARKER_SCALAR_LITERAL_RE.match(operand):
            operands.append(operand)
    return operands


def _freemarker_escape_observation(expression: str, *, ambient_escaping: bool) -> str:
    """Classify the escaping *observed* on one interpolation expression.

    The result is a member of ``FREEMARKER_ESCAPE_OBSERVATIONS``: evidence for a
    reviewer, never a clearance for the site.
    """
    if any(
        token[1:] in _FREEMARKER_ESCAPE_SUPPRESSORS
        for token in _freemarker_builtins(expression)
    ):
        return "unverified_escape_suppressed"
    if ambient_escaping:
        return "unverified_escape_observed"
    operands = _freemarker_value_operands(expression)
    escaped = [
        operand
        for operand in operands
        if any(
            token[1:] in _FREEMARKER_ESCAPER_BUILTINS
            for token in _freemarker_builtins(operand)
        )
    ]
    if operands and len(escaped) == len(operands):
        return "unverified_escape_observed"
    if escaped:
        return "unverified_partial_escape_observed"
    return "unverified_no_escape_observed"


def _freemarker_scope_escaping(name: str, directive: str) -> bool:
    """Whether an escape-scope directive turns escaping on for its body."""
    if name == "escape":
        # `<#escape x as x>` opens a scope that escapes nothing, so only a
        # recognized escaper in the replacement expression counts.
        return any(
            token[1:] in _FREEMARKER_ESCAPER_BUILTINS
            for token in _freemarker_builtins(directive)
        )
    if name == "outputformat":
        literal = _FREEMARKER_STRING_LITERAL_RE.search(directive)
        return (
            literal is not None
            and literal.group(2).strip().lower() in _FREEMARKER_ESCAPING_FORMATS
        )
    return name == "autoesc"


def _freemarker_attribute_context(attribute: str) -> str:
    """Return the output context an interpolation inside *attribute* lands in."""
    name = attribute.lower()
    if _FREEMARKER_EVENT_ATTRIBUTE_RE.match(name):
        return "event_handler_attribute"
    if name == "style":
        return "style_attribute"
    if name in _FREEMARKER_URL_ATTRIBUTES:
        return "url_attribute"
    return "html_attribute"


def _freemarker_callable_params(declaration: str) -> list[str]:
    """Return the parameter names declared after a macro/function name."""
    body = declaration.rstrip()
    if body.endswith("/>"):
        body = body[:-2]
    elif body.endswith(">"):
        body = body[:-1]
    params: list[str] = []
    for token in _freemarker_split_top_level(body, " \t\n"):
        name = token.split("=", 1)[0].strip().rstrip(".")
        if name:
            params.append(name)
    return params


def _freemarker_directive_end(text: str, start: int, length: int) -> int:
    """Return the offset just past the `>` closing the directive, or -1."""
    quote = ""
    index = start
    while index < length:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == ">":
            return index + 1
        index += 1
    return -1


def _freemarker_tag_regions(
    text: str, start: int, length: int
) -> tuple[int, str, bool, list[tuple[int, int, str, str]], list[tuple[str, str]]]:
    """Parse the HTML tag at *start* into interpolation regions.

    Returns the offset after the tag, the lowercased start-tag name (empty for an
    end tag), whether the tag is self-closing, the regions an interpolation can
    occur in as ``(start, end, attribute, quote)`` -- an empty attribute meaning
    the tag body itself, where an interpolation builds a tag or attribute name --
    and the tag's ``(lowercased name, verbatim value)`` attributes.
    """
    regions: list[tuple[int, int, str, str]] = []
    attributes: list[tuple[str, str]] = []
    is_end_tag = text[start + 1 : start + 2] == "/"
    name_match = _FREEMARKER_TAG_NAME_RE.match(text, start)
    tag_name = "" if is_end_tag or name_match is None else name_match.group(1).lower()
    index = name_match.end() if name_match is not None else start + (2 if is_end_tag else 1)
    bare_start = index
    self_closing = False
    while index < length:
        char = text[index]
        if char == ">":
            index += 1
            break
        if text.startswith("/>", index):
            self_closing = True
            index += 2
            break
        if char.isspace():
            index += 1
            continue
        attribute_match = _FREEMARKER_ATTRIBUTE_NAME_RE.match(text, index)
        if attribute_match is None:
            index += 1
            continue
        attribute = attribute_match.group(0)
        index = attribute_match.end()
        probe = index
        while probe < length and text[probe].isspace():
            probe += 1
        if probe >= length or text[probe] != "=":
            attributes.append((attribute.lower(), ""))
            continue
        probe += 1
        while probe < length and text[probe].isspace():
            probe += 1
        if probe >= length:
            index = length
            break
        quote = text[probe] if text[probe] in "\"'" else ""
        if quote:
            value_start = probe + 1
            value_end = _freemarker_attribute_value_end(text, value_start, quote, length)
            if value_end < 0:
                value_end = length
            index = min(value_end + 1, length)
        else:
            value_start = probe
            value_end = value_start
            while value_end < length and not text[value_end].isspace() and text[value_end] != ">":
                value_end += 1
            index = value_end
        regions.append((bare_start, value_start - len(quote), "", ""))
        regions.append((value_start, value_end, attribute, quote))
        attributes.append((attribute.lower(), text[value_start:value_end]))
        bare_start = index
    regions.append((bare_start, index, "", ""))
    return index, tag_name, self_closing, regions, attributes


def _extract_freemarker(
    source_lines: list[str],
    *,
    file_path: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Index a FreeMarker template.

    The HTML pass runs first so a `.ftl` yields every signal a `.html` file
    would; this pass adds the template layer on top -- interpolation sites with
    the output context they land in and the escaping observed on them, macros
    and functions, template includes, and form fields.  Context and escaping are
    regex-derived advisory signals only; see ``FREEMARKER_ESCAPE_OBSERVATIONS``.

    ``file_path`` is read for its extension alone: ``.ftlh`` and ``.ftlx`` carry
    an implied escaping output format, so the ambient starts on rather than off.
    See ``_FREEMARKER_ESCAPING_EXTENSIONS``.  An unknown or absent path is
    treated as a bare ``.ftl``, which is the reporting-heavy direction.
    """
    funcs, entry_points, sinks, exports, imports = _extract_html(
        source_lines, template_comments=("<#--", "-->")
    )

    # One linear scan over the joined source: interpolations, HTML tags and
    # FreeMarker directives all cross line boundaries, so a per-line pass cannot
    # resolve either the output context or the enclosing escape scope.
    text = "\n".join(source_lines)
    length = len(text)
    line_starts = [0]
    for line in source_lines:
        line_starts.append(line_starts[-1] + len(line) + 1)

    header_escaping = Path(file_path).suffix.lower() in _FREEMARKER_ESCAPING_EXTENSIONS
    escape_stack: list[dict[str, Any]] = []
    callable_stack: list[dict[str, Any]] = []
    state = "text"

    def line_of(offset: int) -> int:
        return bisect.bisect_right(line_starts, offset)

    def enclosing() -> str:
        return callable_stack[-1]["name"] if callable_stack else "<template>"

    def flag(kind: str, line: int, vuln_classes: list[str]) -> None:
        sinks.append({
            "kind": kind,
            "line": line,
            "function": enclosing(),
            "snippet": _snippet(source_lines[line - 1]),
            "vuln_classes": vuln_classes,
            "detection": "heuristic_template_regex",
        })

    def close_callable(frame: dict[str, Any], end_line: int) -> None:
        callable_kind = f"freemarker_{frame['kind']}"
        func = _empty_func(frame["name"], frame["line"], end_line)
        func["params"] = frame["params"]
        func["is_entry_point"] = True
        funcs.append(func)
        entry_points.append({
            "name": frame["name"],
            "line": frame["line"],
            "kind": callable_kind,
            "annotation": "",
        })
        exports.append({
            "name": frame["name"], "kind": callable_kind, "line": frame["line"]
        })

    def emit(span_start: int, span_end: int, context: str, attribute: str, quote: str) -> None:
        for open_at, close_at, syntax in _freemarker_span_interpolations(
            text, span_start, span_end
        ):
            line = line_of(open_at)
            if close_at < 0:
                flag("malformed_template_interpolation", line, ["xss"])
                continue
            expression = text[open_at + 2 : close_at - 1]
            sinks.append({
                "kind": "template_interpolation",
                "line": line,
                "function": enclosing(),
                "snippet": _snippet(source_lines[line - 1]),
                # An interpolation is an XSS sink whatever escaping was observed
                # on it: `escape_observation` below is evidence, not clearance.
                "vuln_classes": list(
                    _FREEMARKER_URL_VULN_CLASSES
                    if context == "url_attribute"
                    else ("xss",)
                ),
                "detection": "heuristic_template_regex",
                "interpolation_syntax": syntax,
                "expression": _snippet(expression),
                "output_context": context,
                "attribute": attribute,
                "attribute_quote": quote,
                "escape_observation": _freemarker_escape_observation(
                    expression,
                    ambient_escaping=(
                        bool(escape_stack[-1]["escaping"])
                        if escape_stack
                        else header_escaping
                    ),
                ),
                "observed_escapers": _freemarker_observed_escapers(expression),
                "ambient_escape_scopes": [
                    {"directive": scope["directive"], "line": scope["line"]}
                    for scope in escape_stack
                ],
            })
            if _FREEMARKER_DYNAMIC_EVAL_RE.search(expression):
                flag("freemarker_dynamic_evaluation", line, ["ssti", "injection"])

    def handle_directive(start: int) -> int:
        nonlocal header_escaping
        end = _freemarker_directive_end(text, start, length)
        line = line_of(start)
        if end < 0:
            flag("malformed_template_directive", line, ["xss"])
            return length
        directive = text[start:end]
        match = _FREEMARKER_DIRECTIVE_NAME_RE.match(directive)
        name = match.group(1).lower() if match is not None else ""
        closing = directive.startswith("</")
        self_closing = directive.rstrip().endswith("/>")
        if _FREEMARKER_DYNAMIC_EVAL_RE.search(directive):
            flag("freemarker_dynamic_evaluation", line, ["ssti", "injection"])
        if name in {"macro", "function"}:
            if closing:
                if callable_stack and callable_stack[-1]["kind"] == name:
                    close_callable(callable_stack.pop(), line)
                else:
                    flag("malformed_template_directive", line, ["xss"])
            else:
                declared = _FREEMARKER_CALLABLE_RE.match(directive)
                if declared is not None:
                    frame = {
                        "name": declared.group(1),
                        "kind": name,
                        "line": line,
                        "params": _freemarker_callable_params(directive[declared.end():]),
                    }
                    if self_closing:
                        close_callable(frame, line)
                    else:
                        callable_stack.append(frame)
        elif name in _FREEMARKER_ESCAPE_SCOPES:
            if closing:
                if escape_stack and escape_stack[-1]["name"] == name:
                    escape_stack.pop()
                else:
                    flag("malformed_template_directive", line, ["xss"])
            elif not self_closing:
                escape_stack.append({
                    "name": name,
                    "directive": _snippet(directive),
                    "line": line,
                    "escaping": _freemarker_scope_escaping(name, directive),
                })
        elif name == "ftl" and not closing:
            auto_esc = _FREEMARKER_AUTO_ESC_RE.search(directive)
            output_format = _FREEMARKER_OUTPUT_FORMAT_RE.search(directive)
            if auto_esc is not None:
                header_escaping = auto_esc.group(1) == "true"
            elif output_format is not None:
                header_escaping = (
                    output_format.group(2).strip().lower()
                    in _FREEMARKER_ESCAPING_FORMATS
                )
        elif name in {"include", "import"} and not closing:
            literal = _FREEMARKER_STRING_LITERAL_RE.search(directive)
            if literal is not None:
                imports.append(literal.group(2))
        return end

    def handle_tag(start: int) -> int:
        nonlocal state
        end, tag_name, self_closing, regions, attributes = _freemarker_tag_regions(
            text, start, length
        )
        for region_start, region_end, attribute, quote in regions:
            context = (
                _freemarker_attribute_context(attribute) if attribute else "html_tag"
            )
            emit(region_start, region_end, context, attribute, quote)
        if not self_closing:
            if tag_name == "script":
                state = "script"
            elif tag_name == "style":
                state = "style"
        if tag_name in _FREEMARKER_FORM_FIELD_TAGS:
            values = dict(attributes)
            field = values.get("name", "")
            if field:
                entry_points.append({
                    "name": field,
                    "line": line_of(start),
                    "kind": "html_form_field",
                    "annotation": values.get("type", ""),
                })
        return end

    index = 0
    while index < length:
        if text[index] != "<":
            stop = text.find("<", index)
            if stop < 0:
                stop = length
            emit(index, stop, "html_text" if state == "text" else state, "", "")
            index = stop
            continue
        if text.startswith("<#--", index):
            closed = text.find("-->", index + 4)
            index = length if closed < 0 else closed + 3
            continue
        if text.startswith(("<#", "</#", "<@", "</@"), index):
            index = handle_directive(index)
            continue
        if state in {"script", "style"}:
            closer = f"</{state}"
            if text[index : index + len(closer)].lower() == closer:
                state = "text"
                index += len(closer)
            else:
                index += 1
            continue
        if text.startswith("<!--", index):
            closed = text.find("-->", index + 4)
            emit(index + 4, length if closed < 0 else closed, "html_comment", "", "")
            index = length if closed < 0 else closed + 3
            continue
        following = text[index + 1 : index + 2]
        if following.isalpha() or following == "/" or text.startswith("<${", index):
            index = handle_tag(index)
            continue
        index += 1

    # Scopes still open at EOF are a template the scanner could not balance; the
    # sites they cover were still indexed, so report the imbalance rather than
    # dropping it.
    for scope in escape_stack:
        flag("malformed_template_directive", scope["line"], ["xss"])
    for frame in callable_stack:
        close_callable(frame, len(source_lines))
        flag("malformed_template_directive", frame["line"], ["xss"])

    return funcs, entry_points, sinks, exports, imports


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = ['_DOCKER_INSTR_RE', '_DOCKER_SECRET_NAMES', '_DOCKER_URL_RE', '_extract_dockerfile', '_SHELL_FUNC_PAREN_RE', '_SHELL_FUNC_KW_RE', '_SHELL_SOURCE_RE', '_extract_shell', '_find_enclosing_func', '_PS_FUNC_RE', '_PS_PARAM_BLOCK_RE', '_PS_FUNC_SIGNATURE_RE', '_PS_PARAM_NAME_RE', '_PS_IMPORT_RE', '_PS_DOT_SOURCE_RE', '_PS_SINK_PATTERNS', '_PS_LITERAL_ASSIGNMENT_RE', '_PS_COMPILED_SINKS', '_ps_balanced_span', '_ps_declared_params', '_ps_block_end', '_extract_powershell', '_LUA_FUNC_RE', '_LUA_LOCAL_FUNC_ASSIGN_RE', '_LUA_DYNAMIC_REDIS_COMMAND_RE', '_extract_lua', '_HTML_TAG_RE', '_HTML_ATTR_RE', '_HTML_INLINE_HANDLER_RE', '_HTML_JS_URL_RE', '_HTML_MUSTACHE_RE', '_HTML_ASP_RE', '_mask_delimited_comments', '_extract_html', '_BLADE_CONSTRUCT_RE', '_BLADE_IMPORT_RE', '_BLADE_SLOT_RE', '_blade_echoes', '_blade_template_sources', '_extract_blade', '_CSS_IMPORT_RE', '_CSS_URL_RE', '_CSS_EXPRESSION_RE', '_CSS_BEHAVIOR_RE', '_CSS_BINDING_RE', '_extract_css', 'FREEMARKER_ESCAPE_OBSERVATIONS', 'FREEMARKER_OUTPUT_CONTEXTS', '_FREEMARKER_ESCAPER_BUILTINS', '_FREEMARKER_ESCAPE_SUPPRESSORS', '_FREEMARKER_ESCAPE_SCOPES', '_FREEMARKER_ESCAPING_FORMATS', '_FREEMARKER_ESCAPING_EXTENSIONS', '_FREEMARKER_FORM_FIELD_TAGS', '_FREEMARKER_URL_ATTRIBUTES', '_FREEMARKER_URL_VULN_CLASSES', '_FREEMARKER_BUILTIN_RE', '_FREEMARKER_DIRECTIVE_NAME_RE', '_FREEMARKER_CALLABLE_RE', '_FREEMARKER_TAG_NAME_RE', '_FREEMARKER_ATTRIBUTE_NAME_RE', '_FREEMARKER_STRING_LITERAL_RE', '_FREEMARKER_OUTPUT_FORMAT_RE', '_FREEMARKER_AUTO_ESC_RE', '_FREEMARKER_EVENT_ATTRIBUTE_RE', '_FREEMARKER_SCALAR_LITERAL_RE', '_FREEMARKER_DYNAMIC_EVAL_RE', '_FREEMARKER_MAX_EXPRESSION_CHARS', '_freemarker_split_top_level', '_freemarker_interpolation_end', '_freemarker_attribute_value_end', '_freemarker_span_interpolations', '_freemarker_builtins', '_freemarker_observed_escapers', '_freemarker_value_operands', '_freemarker_escape_observation', '_freemarker_scope_escaping', '_freemarker_attribute_context', '_freemarker_callable_params', '_freemarker_directive_end', '_freemarker_tag_regions', '_extract_freemarker']
