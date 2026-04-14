"""Tree-sitter structural indexing for code analysis.

Parses source files using tree-sitter to extract function/method definitions,
class structures, import statements, entry points, security sinks, and call
sites.  All tree-sitter imports are guarded so the module remains importable
(returning empty/degraded results) when tree-sitter packages are absent.
"""
from __future__ import annotations

import re
import sys
import warnings
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Guarded tree-sitter imports
# ---------------------------------------------------------------------------

_TS_AVAILABLE = False

try:
    import tree_sitter  # type: ignore[import-untyped]
    _TS_AVAILABLE = True
except ImportError:
    tree_sitter = None  # type: ignore[assignment]

# Per-language grammar loaders (also guarded)
_GRAMMAR_MODULES: dict[str, Any] = {}

def _try_import_grammar(mod_name: str, key: str) -> None:
    try:
        import importlib
        _GRAMMAR_MODULES[key] = importlib.import_module(mod_name)
    except ImportError:
        pass

_try_import_grammar("tree_sitter_java", "java")
_try_import_grammar("tree_sitter_c", "c")
_try_import_grammar("tree_sitter_cpp", "cpp")
_try_import_grammar("tree_sitter_python", "python")
_try_import_grammar("tree_sitter_javascript", "javascript")
_try_import_grammar("tree_sitter_typescript", "typescript")
_try_import_grammar("tree_sitter_go", "go")
_try_import_grammar("tree_sitter_ruby", "ruby")
_try_import_grammar("tree_sitter_php", "php")


# ---------------------------------------------------------------------------
# tree-sitter API compat: 0.23 had Language.query() + Query.captures(node)
# returning {name: [nodes]}.  0.25 removed both — use Query() constructor +
# QueryCursor.matches() instead.  This helper provides a single call site.
# ---------------------------------------------------------------------------

def _ts_query_captures(lang_obj: Any, query_str: str, root_node: Any) -> dict[str, list[Any]]:
    """Run a tree-sitter query and return ``{capture_name: [nodes]}``."""
    if tree_sitter is None:
        return {}
    # 0.25+: Query() constructor + QueryCursor
    if hasattr(tree_sitter, "QueryCursor"):
        try:
            query = tree_sitter.Query(lang_obj, query_str)
        except Exception:
            return {}
        cursor = tree_sitter.QueryCursor(query)
        result: dict[str, list[Any]] = {}
        for _pattern_idx, match_dict in cursor.matches(root_node):
            for name, nodes in match_dict.items():
                result.setdefault(name, []).extend(nodes)
        return result
    # 0.23.x: Language.query() + Query.captures()
    try:
        query = lang_obj.query(query_str)
    except Exception:
        return {}
    return query.captures(root_node)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Extension → language mapping (for tree-sitter supported families only)
# ---------------------------------------------------------------------------

EXTENSION_LANG_MAP: dict[str, str] = {
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}

SUPPORTED_LANGUAGES = frozenset({
    "java", "c", "cpp", "python", "javascript", "typescript",
    "go", "ruby", "php",
})


# ---------------------------------------------------------------------------
# Lazy grammar / parser cache
# ---------------------------------------------------------------------------

_PARSERS: dict[str, Any] = {}  # lang -> tree_sitter.Parser


def _get_parser(language: str) -> Any | None:
    """Return a tree-sitter Parser for *language*, loading the grammar lazily."""
    if not _TS_AVAILABLE:
        return None

    if language in _PARSERS:
        return _PARSERS[language]

    # TypeScript needs special handling: the grammar module exposes
    # language_typescript() and language_tsx() as separate entry points.
    ts_lang = language
    if language == "typescript":
        gram = _GRAMMAR_MODULES.get("typescript")
        if gram is None:
            return None
        # Prefer language_typescript(); fall back to language()
        lang_fn = getattr(gram, "language_typescript", None) or getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    elif language == "tsx":
        gram = _GRAMMAR_MODULES.get("typescript")
        if gram is None:
            return None
        lang_fn = getattr(gram, "language_tsx", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    elif language == "php":
        gram = _GRAMMAR_MODULES.get("php")
        if gram is None:
            return None
        lang_fn = getattr(gram, "language_php", None) or getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    else:
        gram = _GRAMMAR_MODULES.get(language)
        if gram is None:
            return None
        lang_fn = getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())

    parser = tree_sitter.Parser(lang_obj)
    _PARSERS[language] = parser
    return parser


# ---------------------------------------------------------------------------
# Tree-sitter query strings per language (functions, classes, imports)
# ---------------------------------------------------------------------------

_FUNCTION_QUERIES: dict[str, str] = {
    "java": """
        (method_declaration) @func
        (constructor_declaration) @func
    """,
    "c": """
        (function_definition) @func
    """,
    "cpp": """
        (function_definition) @func
    """,
    "python": """
        (function_definition) @func
    """,
    "javascript": """
        (function_declaration) @func
        (method_definition) @func
    """,
    "typescript": """
        (function_declaration) @func
        (method_definition) @func
    """,
    "go": """
        (function_declaration) @func
        (method_declaration) @func
    """,
    "ruby": """
        (method) @func
        (singleton_method) @func
    """,
    "php": """
        (function_definition) @func
        (method_declaration) @func
    """,
}

_CLASS_QUERIES: dict[str, str] = {
    "java": """(class_declaration) @cls""",
    "cpp": """
        (class_specifier) @cls
        (struct_specifier) @cls
    """,
    "python": """(class_definition) @cls""",
    "javascript": """(class_declaration) @cls""",
    "typescript": """(class_declaration) @cls""",
    "go": """(type_spec) @cls""",
    "ruby": """
        (class) @cls
        (module) @cls
    """,
    "php": """
        (class_declaration) @cls
        (interface_declaration) @cls
        (trait_declaration) @cls
    """,
}

_IMPORT_QUERIES: dict[str, str] = {
    "java": """(import_declaration) @imp""",
    "c": """(preproc_include) @imp""",
    "cpp": """(preproc_include) @imp""",
    "python": """
        (import_statement) @imp
        (import_from_statement) @imp
    """,
    "javascript": """(import_statement) @imp""",
    "typescript": """(import_statement) @imp""",
    "go": """(import_spec) @imp""",
    "php": """(namespace_use_declaration) @imp""",
}


# ---------------------------------------------------------------------------
# Security sink patterns per vulnerability class
# ---------------------------------------------------------------------------

SinkPattern = dict[str, Any]  # {"kind", "patterns": {lang: [regex_str,...]}, "vuln_classes": [...]}

_SINK_DEFINITIONS: list[SinkPattern] = [
    {
        "kind": "file_path",
        "vuln_classes": ["path-traversal"],
        "patterns": {
            "java": [r"\bnew\s+File\s*\(", r"\bFileInputStream\s*\(", r"\bFileOutputStream\s*\(",
                     r"\bPaths\.get\s*\(", r"\bFileUtils\.copy"],
            "c": [r"\bfopen\s*\(", r"\bopen\s*\(", r"\baccess\s*\(", r"\bstat\s*\("],
            "cpp": [r"\bfopen\s*\(", r"\bopen\s*\(", r"\baccess\s*\(", r"\bstat\s*\("],
            "python": [r"\bopen\s*\(", r"\bos\.path\.join\s*\(", r"\bPath\s*\("],
            "javascript": [r"\bfs\.readFile\w*\s*\(", r"\bfs\.writeFile\w*\s*\(", r"\bpath\.join\s*\("],
            "typescript": [r"\bfs\.readFile\w*\s*\(", r"\bfs\.writeFile\w*\s*\(", r"\bpath\.join\s*\("],
            "go": [r"\bos\.Open\w*\s*\(", r"\bos\.Create\s*\(", r"\bfilepath\.Join\s*\(",
                   r"\bioutil\.ReadFile\s*\(", r"\bos\.ReadFile\s*\("],
            "ruby": [r"\bFile\.open\s*\(", r"\bFile\.read\s*\(", r"\bIO\.read\s*\(",
                     r"\bFileUtils\.\w+\s*\("],
            "php": [r"\bfopen\s*\(", r"\bfile_get_contents\s*\(", r"\bfile_put_contents\s*\(",
                    r"\binclude\b", r"\brequire\b", r"\binclude_once\b", r"\brequire_once\b"],
        },
    },
    {
        "kind": "sql_exec",
        "vuln_classes": ["sql-injection"],
        "patterns": {
            "java": [r"\bcreateStatement\s*\(", r"\.execute\s*\(", r"\.executeQuery\s*\(",
                     r"\.executeUpdate\s*\("],
            "c": [r"\bsqlite3_exec\s*\("],
            "cpp": [r"\bsqlite3_exec\s*\("],
            "python": [r"\bcursor\.execute\s*\(", r"\.execute\s*\("],
            "javascript": [r"\.query\s*\(", r"\.execute\s*\("],
            "typescript": [r"\.query\s*\(", r"\.execute\s*\("],
            "go": [r"\b\w+\.Query\s*\(", r"\b\w+\.QueryRow\s*\(", r"\b\w+\.Exec\s*\("],
            "ruby": [r"\b\w+\.execute\s*\(", r"\bActiveRecord.*\.find_by_sql\s*\(",
                     r"\b\w+\.where\s*\(.*\braw\b"],
            "php": [r"\bmysqli_query\s*\(", r"\$\w+->query\s*\(", r"\bPDO::query\s*\(",
                    r"\$\w+->prepare\s*\("],
        },
    },
    {
        "kind": "process_exec",
        "vuln_classes": ["injection"],
        "patterns": {
            "java": [r"\bRuntime\.\w*exec\s*\(", r"\bProcessBuilder\s*\("],
            "c": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve\s*\("],
            "cpp": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve\s*\("],
            "python": [r"\bos\.system\s*\(", r"\bsubprocess\.run\s*\(", r"\bsubprocess\.Popen\s*\(",
                       r"\bsubprocess\.call\s*\("],
            "javascript": [r"\bchild_process\.exec\s*\(", r"\bchild_process\.spawn\s*\("],
            "typescript": [r"\bchild_process\.exec\s*\(", r"\bchild_process\.spawn\s*\("],
            "go": [r"\bexec\.Command\s*\(", r"\bos\.StartProcess\s*\("],
            "ruby": [r"\bsystem\s*\(", r"\bexec\s*\(", r"\b`[^`]*`",
                     r"\bOpen3\.\w+\s*\(", r"\bIO\.popen\s*\("],
            "php": [r"\bexec\s*\(", r"\bsystem\s*\(", r"\bshell_exec\s*\(",
                    r"\bpassthru\s*\(", r"\bproc_open\s*\(", r"\bpopen\s*\("],
        },
    },
    {
        "kind": "url_fetch",
        "vuln_classes": ["ssrf"],
        "patterns": {
            "java": [r"\bnew\s+URL\s*\(", r"\bHttpURLConnection\b", r"\bHttpClient\.send\s*\("],
            "python": [r"\brequests\.get\s*\(", r"\burllib\.request\.urlopen\s*\("],
            "javascript": [r"\bfetch\s*\(", r"\bhttp\.request\s*\(", r"\baxios\."],
            "typescript": [r"\bfetch\s*\(", r"\bhttp\.request\s*\(", r"\baxios\."],
            "go": [r"\bhttp\.Get\s*\(", r"\bhttp\.Post\s*\(", r"\bhttp\.NewRequest\s*\(",
                   r"\bhttp\.DefaultClient\.Do\s*\("],
            "ruby": [r"\bNet::HTTP\.\w+\s*\(", r"\bHTTParty\.\w+\s*\(",
                     r"\bopen-uri\b", r"\bURI\.open\s*\("],
            "php": [r"\bcurl_exec\s*\(", r"\bfile_get_contents\s*\(.*http",
                    r"\bfopen\s*\(.*http"],
        },
    },
    {
        "kind": "deserialization",
        "vuln_classes": ["deserialization"],
        "patterns": {
            "java": [r"\bObjectInputStream\b", r"\breadObject\s*\(", r"\bXMLDecoder\b"],
            "python": [r"\bpickle\.loads?\s*\(", r"\byaml\.load\s*\(", r"\bmarshal\.loads?\s*\("],
            "go": [r"\bjson\.Unmarshal\s*\(", r"\bgob\.NewDecoder\s*\(",
                   r"\bxml\.Unmarshal\s*\("],
            "ruby": [r"\bMarshal\.load\s*\(", r"\bYAML\.load\s*\(",
                     r"\bJSON\.parse\s*\("],
            "php": [r"\bunserialize\s*\(", r"\bjson_decode\s*\("],
        },
    },
    {
        "kind": "eval_exec",
        "vuln_classes": ["injection"],
        "patterns": {
            "java": [r"\bScriptEngine\.eval\s*\("],
            "python": [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\("],
            "javascript": [r"\beval\s*\(", r"\bFunction\s*\(", r"\bsetTimeout\s*\("],
            "typescript": [r"\beval\s*\(", r"\bFunction\s*\(", r"\bsetTimeout\s*\("],
            "ruby": [r"\beval\s*\(", r"\bclass_eval\s*\(", r"\binstance_eval\s*\(",
                     r"\bsend\s*\(", r"\bpublic_send\s*\("],
            "php": [r"\beval\s*\(", r"\bassert\s*\(", r"\bpreg_replace\s*\(.*/e",
                    r"\bcreate_function\s*\("],
        },
    },
    {
        "kind": "crypto",
        "vuln_classes": ["crypto-misuse"],
        "patterns": {
            "java": [r"\bCipher\.getInstance\s*\(", r"\bSecretKeySpec\s*\(", r"\bMessageDigest\s*\("],
            "c": [r"\bEVP_Cipher\w*\s*\(", r"\bAES_encrypt\s*\("],
            "cpp": [r"\bEVP_Cipher\w*\s*\(", r"\bAES_encrypt\s*\("],
            "python": [r"\bhashlib\.", r"\bCrypto\.Cipher\."],
            "javascript": [r"\bcrypto\.createCipher\w*\s*\(", r"\bcrypto\.createHash\s*\("],
            "typescript": [r"\bcrypto\.createCipher\w*\s*\(", r"\bcrypto\.createHash\s*\("],
            "go": [r"\bcrypto/\w+\b", r"\baes\.NewCipher\s*\(", r"\bsha256\.New\s*\(",
                   r"\bhmac\.New\s*\("],
            "ruby": [r"\bOpenSSL::Cipher\b", r"\bDigest::\w+\b", r"\bOpenSSL::HMAC\b"],
            "php": [r"\bopenssl_encrypt\s*\(", r"\bmd5\s*\(", r"\bsha1\s*\(",
                    r"\bhash\s*\(", r"\bmcrypt_encrypt\s*\("],
        },
    },
    {
        "kind": "auth",
        "vuln_classes": ["auth-bypass", "web-app-auth"],
        "patterns": {
            "java": [r"\bgetSession\s*\(", r"\bsetAttribute\s*\(", r"\bisUserInRole\s*\(",
                     r"\bauthenticate\s*\("],
            "python": [r"\blogin\s*\(", r"\bsession\s*\[", r"@login_required\b"],
            "javascript": [r"\breq\.session\b", r"\bpassport\.authenticate\s*\("],
            "typescript": [r"\breq\.session\b", r"\bpassport\.authenticate\s*\("],
            "go": [r"\bjwt\.\w+\s*\(", r"\bsession\.Get\s*\(", r"\bbcrypt\.\w+\s*\("],
            "ruby": [r"\bauthenticate_user\b", r"\bdevise\b", r"\bcurrent_user\b",
                     r"\bsession\s*\["],
            "php": [r"\b\$_SESSION\b", r"\bAuth::\w+\s*\(", r"\bpassword_verify\s*\(",
                    r"\bsession_start\s*\("],
        },
    },
    {
        "kind": "xss_output",
        "vuln_classes": ["web-app-injection"],
        "patterns": {
            "java": [r"\bgetWriter\s*\(\s*\)\.write\s*\("],
            "javascript": [r"\.innerHTML\b", r"\.outerHTML\b", r"\bdocument\.write\s*\("],
            "typescript": [r"\.innerHTML\b", r"\.outerHTML\b", r"\bdocument\.write\s*\("],
            "go": [r"\btemplate\.HTML\s*\(", r"\bfmt\.Fprintf\s*\(\s*w\b"],
            "ruby": [r"\braw\s*\(", r"\.html_safe\b"],
            "php": [r"\becho\b", r"\bprint\b", r"\bprintf\s*\("],
        },
    },
    {
        "kind": "redirect",
        "vuln_classes": ["open-redirect"],
        "patterns": {
            "java": [r"\bsendRedirect\s*\(", r'\bsetHeader\s*\(\s*"Location"'],
            "python": [r"\bredirect\s*\(", r"\bHttpResponseRedirect\s*\("],
            "javascript": [r"\bres\.redirect\s*\("],
            "typescript": [r"\bres\.redirect\s*\("],
            "go": [r"\bhttp\.Redirect\s*\("],
            "ruby": [r"\bredirect_to\s*\("],
            "php": [r"\bheader\s*\(\s*['\"]Location", r"\bredirect\s*\("],
        },
    },
    {
        "kind": "xml_parse",
        "vuln_classes": ["xxe"],
        "patterns": {
            "java": [r"\bDocumentBuilderFactory\b", r"\bSAXParserFactory\b", r"\bXMLReader\b"],
            "c": [r"\bxmlParseFile\s*\("],
            "cpp": [r"\bxmlParseFile\s*\("],
            "python": [r"\bxml\.etree\.ElementTree\.parse\s*\(", r"\blxml\.etree\.parse\s*\("],
            "go": [r"\bxml\.NewDecoder\s*\(", r"\bxml\.Unmarshal\s*\("],
            "ruby": [r"\bNokogiri::XML\s*\(", r"\bREXML::Document\.new\s*\("],
            "php": [r"\bsimplexml_load_string\s*\(", r"\bDOMDocument\b",
                    r"\bxml_parse\s*\("],
        },
    },
    {
        "kind": "memory",
        "vuln_classes": ["buffer-overflow", "use-after-free"],
        "patterns": {
            "c": [r"\bmemcpy\s*\(", r"\bstrcpy\s*\(", r"\bsprintf\s*\(", r"\bmalloc\s*\(",
                  r"\bfree\s*\(", r"\brealloc\s*\("],
            "cpp": [r"\bmemcpy\s*\(", r"\bstrcpy\s*\(", r"\bsprintf\s*\(", r"\bmalloc\s*\(",
                    r"\bfree\s*\(", r"\brealloc\s*\("],
        },
    },
    {
        "kind": "format_string",
        "vuln_classes": ["format-string"],
        "patterns": {
            "c": [r"\bprintf\s*\(", r"\bfprintf\s*\(", r"\bsprintf\s*\(", r"\bsnprintf\s*\("],
            "cpp": [r"\bprintf\s*\(", r"\bfprintf\s*\(", r"\bsprintf\s*\(", r"\bsnprintf\s*\("],
        },
    },
]


# ---------------------------------------------------------------------------
# Entry-point detection patterns
# ---------------------------------------------------------------------------

# Annotation / decorator strings that mark entry points, keyed by language.
_ENTRY_ANNOTATIONS: dict[str, list[dict[str, str]]] = {
    "java": [
        {"pattern": r"@WebServlet\b", "kind": "servlet_annotation"},
        {"pattern": r"@RequestMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@GetMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@PostMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@PutMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@DeleteMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@PatchMapping\b", "kind": "spring_mapping"},
        {"pattern": r"@Path\b", "kind": "jaxrs_annotation"},
        {"pattern": r"@Scheduled\b", "kind": "scheduled_task"},
    ],
    "python": [
        {"pattern": r"@app\.route\b", "kind": "flask_route"},
        {"pattern": r"@app\.get\b", "kind": "fastapi_route"},
        {"pattern": r"@app\.post\b", "kind": "fastapi_route"},
        {"pattern": r"@blueprint\.route\b", "kind": "flask_blueprint"},
        {"pattern": r"@api_view\b", "kind": "drf_view"},
        {"pattern": r"@router\.\w+\b", "kind": "fastapi_router"},
        {"pattern": r"@celery\.task\b", "kind": "celery_task"},
    ],
    "php": [
        {"pattern": r"#\[Route\b", "kind": "symfony_route"},
    ],
}

# Method names that indicate entry points when in the right class context.
_ENTRY_METHOD_NAMES: dict[str, list[dict[str, str]]] = {
    "java": [
        {"name": "doGet", "kind": "servlet_override"},
        {"name": "doPost", "kind": "servlet_override"},
        {"name": "doFilter", "kind": "filter_override"},
        {"name": "doPut", "kind": "servlet_override"},
        {"name": "doDelete", "kind": "servlet_override"},
        {"name": "main", "kind": "main_method"},
    ],
    "go": [
        {"name": "main", "kind": "main_function"},
        {"name": "init", "kind": "init_function"},
    ],
    "ruby": [
        {"name": "call", "kind": "rack_call"},
    ],
    "php": [
        {"name": "__construct", "kind": "constructor"},
        {"name": "__destruct", "kind": "destructor"},
        {"name": "__wakeup", "kind": "deserialization_hook"},
    ],
}

# String patterns scanned against source lines to detect framework registrations.
_ENTRY_LINE_PATTERNS: dict[str, list[dict[str, str]]] = {
    "javascript": [
        {"pattern": r"\bapp\.get\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.post\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.put\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.delete\s*\(", "kind": "express_route"},
        {"pattern": r"\brouter\.get\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.post\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.put\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.delete\s*\(", "kind": "express_router"},
        {"pattern": r"\bexport\s+default\s+function\b", "kind": "default_export"},
        {"pattern": r"\bmodule\.exports\b", "kind": "module_exports"},
    ],
    "typescript": [
        {"pattern": r"\bapp\.get\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.post\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.put\s*\(", "kind": "express_route"},
        {"pattern": r"\bapp\.delete\s*\(", "kind": "express_route"},
        {"pattern": r"\brouter\.get\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.post\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.put\s*\(", "kind": "express_router"},
        {"pattern": r"\brouter\.delete\s*\(", "kind": "express_router"},
        {"pattern": r"\bexport\s+default\s+function\b", "kind": "default_export"},
        {"pattern": r"\bmodule\.exports\b", "kind": "module_exports"},
    ],
    "python": [
        {"pattern": r"if\s+__name__\s*==\s*['\"]__main__['\"]", "kind": "main_guard"},
    ],
    "c": [
        {"pattern": r"\b\w+_handler\s*\(", "kind": "handler_callback"},
        {"pattern": r"\b\w+_callback\s*\(", "kind": "handler_callback"},
    ],
    "cpp": [
        {"pattern": r"\b\w+_handler\s*\(", "kind": "handler_callback"},
        {"pattern": r"\b\w+_callback\s*\(", "kind": "handler_callback"},
    ],
    "go": [
        {"pattern": r"\bhttp\.HandleFunc\s*\(", "kind": "http_handler"},
        {"pattern": r"\bhttp\.Handle\s*\(", "kind": "http_handler"},
        {"pattern": r"\bmux\.HandleFunc\s*\(", "kind": "mux_handler"},
        {"pattern": r"\br\.HandleFunc\s*\(", "kind": "gorilla_router"},
        {"pattern": r"\b(?:e|g|app)\.\w+\s*\(", "kind": "framework_route"},
    ],
    "ruby": [
        {"pattern": r"\bget\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"\bpost\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"\bput\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"\bdelete\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"if\s+__FILE__\s*==\s*\$0", "kind": "main_guard"},
        {"pattern": r"if\s+\$PROGRAM_NAME\s*==\s*__FILE__", "kind": "main_guard"},
    ],
    "php": [
        {"pattern": r"\bRoute::\w+\s*\(", "kind": "laravel_route"},
        {"pattern": r"\$app->\w+\s*\(", "kind": "slim_route"},
        {"pattern": r"\$router->\w+\s*\(", "kind": "framework_route"},
    ],
}


# ---------------------------------------------------------------------------
# Call-site detection regex (simple heuristic)
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_text(node: Any, source: bytes) -> str:
    """Extract the source text of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_lines(node: Any) -> tuple[int, int]:
    """Return 1-based (start_line, end_line) for a tree-sitter node."""
    return (node.start_point[0] + 1, node.end_point[0] + 1)


def _extract_functions_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract function/method definitions using tree-sitter queries."""
    query_str = _FUNCTION_QUERIES.get(language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    functions: list[dict[str, Any]] = []
    seen_ranges: set[tuple[int, int]] = set()

    nodes = captures.get("func", [])

    for node in nodes:
        start_line, end_line = _node_lines(node)
        if (start_line, end_line) in seen_ranges:
            continue
        seen_ranges.add((start_line, end_line))

        func_info = _parse_function_node(node, language, source)
        if func_info:
            functions.append(func_info)

    return functions


def _parse_function_node(node: Any, language: str, source: bytes) -> dict[str, Any] | None:
    """Parse a single function/method tree-sitter node into a structured dict."""
    start_line, end_line = _node_lines(node)
    name = ""
    params: list[str] = []
    modifiers: list[str] = []
    annotations: list[str] = []

    if language == "java":
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, source)
            elif child.type == "formal_parameters":
                params = _extract_params(child, source)
            elif child.type == "modifiers":
                for mod in child.children:
                    txt = _node_text(mod, source)
                    if txt.startswith("@"):
                        annotations.append(txt.split("(")[0])
                    else:
                        modifiers.append(txt)
    elif language in ("c", "cpp"):
        decl = node.child_by_field_name("declarator")
        if decl:
            # function_declarator -> identifier + parameter_list
            for child in decl.children:
                if child.type == "identifier":
                    name = _node_text(child, source)
                elif child.type == "parameter_list":
                    params = _extract_params(child, source)
                elif child.type == "field_identifier":
                    name = _node_text(child, source)
                # Handle qualified identifiers (ns::func)
                elif child.type == "qualified_identifier":
                    name = _node_text(child, source)
    elif language == "python":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        # Check for decorators
        parent = node.parent
        if parent and parent.type == "decorated_definition":
            for child in parent.children:
                if child.type == "decorator":
                    annotations.append(_node_text(child, source).strip())
    elif language in ("javascript", "typescript"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
    elif language == "go":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        receiver = node.child_by_field_name("receiver")
        if receiver:
            recv_text = _node_text(receiver, source).strip("() ")
            if recv_text:
                annotations.append(f"receiver:{recv_text}")
    elif language == "ruby":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
    elif language == "php":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        for child in node.children:
            txt = _node_text(child, source)
            if child.type in ("visibility_modifier", "static_modifier", "abstract_modifier"):
                modifiers.append(txt)

    if not name:
        return None

    return {
        "name": name,
        "qualified_name": name,
        "line_start": start_line,
        "line_end": end_line,
        "params": params,
        "modifiers": modifiers,
        "annotations": annotations,
        "is_entry_point": False,
    }


def _extract_params(params_node: Any, source: bytes) -> list[str]:
    """Extract parameter text from a parameters node."""
    params: list[str] = []
    for child in params_node.children:
        if child.type in ("formal_parameter", "parameter", "spread_element",
                          "required_parameter", "optional_parameter",
                          "typed_parameter", "default_parameter",
                          "identifier", "typed_default_parameter",
                          "parameter_declaration", "simple_parameter",
                          "variadic_parameter", "optional_parameter",
                          "keyword_parameter", "block_parameter",
                          "splat_parameter", "hash_splat_parameter"):
            params.append(_node_text(child, source).strip())
    return params


def _extract_classes_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract class/struct definitions using tree-sitter queries."""
    query_str = _CLASS_QUERIES.get(language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    classes: list[dict[str, Any]] = []

    nodes = captures.get("cls", [])

    for node in nodes:
        start_line, end_line = _node_lines(node)
        cls_info = _parse_class_node(node, language, source)
        if cls_info:
            classes.append(cls_info)

    return classes


def _parse_class_node(node: Any, language: str, source: bytes) -> dict[str, Any] | None:
    """Parse a class/struct tree-sitter node."""
    start_line, end_line = _node_lines(node)
    name = ""
    extends: str = ""
    implements: list[str] = []

    if language == "java":
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, source)
            elif child.type == "superclass":
                for sc in child.children:
                    if sc.type == "type_identifier":
                        extends = _node_text(sc, source)
            elif child.type == "super_interfaces":
                for si in child.children:
                    if si.type == "type_list":
                        for ti in si.children:
                            if ti.type == "type_identifier":
                                implements.append(_node_text(ti, source))
    elif language in ("c", "cpp"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        # Base classes (C++)
        for child in node.children:
            if child.type == "base_class_clause":
                for base in child.children:
                    if base.type == "type_identifier":
                        extends = _node_text(base, source)
    elif language == "python":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        superclasses = node.child_by_field_name("superclasses")
        if superclasses:
            for child in superclasses.children:
                if child.type == "identifier" or child.type == "attribute":
                    txt = _node_text(child, source)
                    if not extends:
                        extends = txt
                    else:
                        implements.append(txt)
    elif language in ("javascript", "typescript"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        for child in node.children:
            if child.type == "class_heritage":
                for hc in child.children:
                    if hc.type == "identifier" or hc.type == "member_expression":
                        extends = _node_text(hc, source)
    elif language == "go":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
    elif language == "ruby":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        superclass_node = node.child_by_field_name("superclass")
        if superclass_node:
            for child in superclass_node.children:
                if child.type in ("constant", "scope_resolution"):
                    extends = _node_text(child, source)
                    break
    elif language == "php":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        for child in node.children:
            if child.type == "base_clause":
                for gc in child.children:
                    if gc.type in ("name", "qualified_name"):
                        extends = _node_text(gc, source)
                        break
            elif child.type == "class_interface_clause":
                for gc in child.children:
                    if gc.type in ("name", "qualified_name"):
                        implements.append(_node_text(gc, source))

    if not name:
        return None

    return {
        "name": name,
        "extends": extends,
        "implements": implements,
        "line_start": start_line,
        "line_end": end_line,
    }


_RUBY_REQUIRE_RE = re.compile(
    r"""(?:require|require_relative|load)\s*[\(]?\s*['"](.+?)['"]\s*[\)]?"""
)


def _extract_imports_ts(tree: Any, language: str, source: bytes) -> list[str]:
    """Extract import/include strings using tree-sitter queries."""
    if language == "ruby":
        return _extract_ruby_imports(source)

    query_str = _IMPORT_QUERIES.get(language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    imports: list[str] = []

    nodes = captures.get("imp", [])

    for node in nodes:
        text = _node_text(node, source).strip().rstrip(";")
        if language == "java":
            text = text.removeprefix("import").strip()
            text = text.removeprefix("static").strip()
        elif language in ("c", "cpp"):
            m = re.search(r'[<"](.+?)[>"]', text)
            if m:
                text = m.group(1)
        elif language == "go":
            text = text.strip().strip('"')
            if text.startswith("."):
                continue
        elif language == "php":
            text = text.removeprefix("use").strip().rstrip(";")
        elif language == "python":
            pass
        elif language in ("javascript", "typescript"):
            pass
        imports.append(text)

    return imports


def _extract_ruby_imports(source: bytes) -> list[str]:
    """Extract require/require_relative/load from Ruby source via regex."""
    imports: list[str] = []
    for line in source.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for m in _RUBY_REQUIRE_RE.finditer(line):
            imports.append(m.group(1))
    return imports


def _detect_entry_points(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Identify entry-point functions via annotations, names, and line patterns."""
    entry_points: list[dict[str, Any]] = []

    # Build class-membership lookup: line -> class name
    class_for_line: dict[int, dict[str, Any]] = {}
    for cls in classes:
        for line in range(cls["line_start"], cls["line_end"] + 1):
            class_for_line[line] = cls

    annotation_defs = _ENTRY_ANNOTATIONS.get(language, [])
    method_name_defs = _ENTRY_METHOD_NAMES.get(language, [])
    line_pattern_defs = _ENTRY_LINE_PATTERNS.get(language, [])

    for func in functions:
        matched = False

        # Check annotations / decorators
        for ann_def in annotation_defs:
            for ann in func.get("annotations", []):
                if re.search(ann_def["pattern"], ann):
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": ann_def["kind"],
                        "annotation": ann.split("(")[0],
                    })
                    func["is_entry_point"] = True
                    matched = True
                    break
            if matched:
                break

        if matched:
            continue

        # Check method name patterns (Java servlet overrides, main, etc.)
        for mdef in method_name_defs:
            if func["name"] == mdef["name"]:
                # For servlet methods, verify class extends HttpServlet/Filter
                if mdef["kind"] in ("servlet_override", "filter_override"):
                    cls = class_for_line.get(func["line_start"])
                    if cls and cls.get("extends") in ("HttpServlet", "Filter", "GenericServlet"):
                        entry_points.append({
                            "name": func["name"],
                            "line": func["line_start"],
                            "kind": mdef["kind"],
                            "annotation": "@Override",
                        })
                        func["is_entry_point"] = True
                        matched = True
                elif mdef["name"] == "main" and language == "java":
                    if "public" in func.get("modifiers", []) and "static" in func.get("modifiers", []):
                        entry_points.append({
                            "name": func["name"],
                            "line": func["line_start"],
                            "kind": "main_method",
                            "annotation": "",
                        })
                        func["is_entry_point"] = True
                        matched = True
                else:
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": mdef["kind"],
                        "annotation": "",
                    })
                    func["is_entry_point"] = True
                    matched = True
            if matched:
                break

        if matched:
            continue

        # Check source-line patterns within function body
        for lp in line_pattern_defs:
            start_idx = max(0, func["line_start"] - 1)
            end_idx = min(len(source_lines), func["line_end"])
            # Also check a few lines before for decorators
            check_start = max(0, start_idx - 3)
            for line_no in range(check_start, end_idx):
                if re.search(lp["pattern"], source_lines[line_no]):
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": lp["kind"],
                        "annotation": "",
                    })
                    func["is_entry_point"] = True
                    matched = True
                    break
            if matched:
                break

    if language in ("c", "cpp", "go"):
        for func in functions:
            if func["name"] == "main" and not func["is_entry_point"]:
                entry_points.append({
                    "name": "main",
                    "line": func["line_start"],
                    "kind": "main_function",
                    "annotation": "",
                })
                func["is_entry_point"] = True

    return entry_points


def _detect_sinks(
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect security-sensitive API calls within function bodies using regex."""
    sinks: list[dict[str, Any]] = []

    for func in functions:
        start_idx = max(0, func["line_start"] - 1)
        end_idx = min(len(source_lines), func["line_end"])

        for sink_def in _SINK_DEFINITIONS:
            lang_patterns = sink_def["patterns"].get(language, [])
            for pat in lang_patterns:
                compiled = re.compile(pat)
                for line_idx in range(start_idx, end_idx):
                    line_text = source_lines[line_idx]
                    # Skip comment-only lines
                    stripped = line_text.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                        continue
                    m = compiled.search(line_text)
                    if m:
                        snippet = line_text.strip()
                        if len(snippet) > 120:
                            snippet = snippet[:117] + "..."
                        sinks.append({
                            "kind": sink_def["kind"],
                            "line": line_idx + 1,
                            "function": func["name"],
                            "snippet": snippet,
                            "vuln_classes": list(sink_def["vuln_classes"]),
                        })
                        # One match per pattern per function is enough
                        break

    return sinks


def _detect_call_sites(
    functions: list[dict[str, Any]],
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect function calls within each function body using regex.

    Each call site includes a ``passes_caller_params`` boolean indicating
    whether the call forwards any of the caller's parameter names as
    arguments -- a lightweight signal for data-flow propagation.
    """
    known_names = {f["name"] for f in functions}

    # Common language keywords to exclude from call-site detection
    noise = frozenset({
        "if", "else", "for", "while", "switch", "case", "return", "throw",
        "new", "delete", "try", "catch", "finally", "import", "from",
        "class", "def", "function", "var", "let", "const", "static",
        "public", "private", "protected", "void", "int", "float",
        "double", "long", "short", "char", "boolean", "String",
        "True", "False", "None", "null", "undefined", "this", "self",
        "typeof", "instanceof", "sizeof", "assert", "print", "println",
        "func", "go", "defer", "select", "chan", "range", "type", "struct",
        "interface", "map", "make", "append", "len", "cap", "copy", "close",
        "string", "bool", "byte", "error", "nil", "fmt", "log",
        "puts", "raise", "rescue", "ensure", "yield", "begin", "end",
        "do", "then", "elsif", "unless", "until", "when", "module",
        "require", "include", "extend", "attr_accessor", "attr_reader",
        "echo", "isset", "empty", "unset", "array", "list",
        "foreach", "elseif", "endforeach", "endif", "endwhile",
    })

    calls: list[dict[str, Any]] = []
    for func in functions:
        start_idx = max(0, func["line_start"] - 1)
        end_idx = min(len(source_lines), func["line_end"])
        seen_callees: set[str] = set()

        param_names: set[str] = set()
        for p in func.get("params", []):
            tokens = re.split(r"[\s:=,*&]+", p.strip())
            for tok in tokens:
                tok = tok.strip().lstrip("$")
                if tok and tok not in noise and len(tok) > 1:
                    param_names.add(tok)

        for line_idx in range(start_idx, end_idx):
            line_text = source_lines[line_idx]
            stripped = line_text.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue
            for m in _CALL_RE.finditer(line_text):
                callee = m.group(1)
                simple_name = callee.rsplit(".", 1)[-1]
                if simple_name in noise:
                    continue
                if simple_name == func["name"]:
                    continue
                if simple_name in seen_callees:
                    continue
                seen_callees.add(simple_name)

                passes_params = False
                if param_names:
                    call_end = m.end()
                    rest_of_line = line_text[call_end:]
                    for pn in param_names:
                        if re.search(r'\b' + re.escape(pn) + r'\b', rest_of_line):
                            passes_params = True
                            break

                calls.append({
                    "caller": func["name"],
                    "callee": callee,
                    "line": line_idx + 1,
                    "passes_caller_params": passes_params,
                })

    return calls


def _detect_exports(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect exported symbols based on language conventions."""
    exports: list[dict[str, Any]] = []

    if language == "go":
        for func in functions:
            if func["name"] and func["name"][0].isupper():
                exports.append({"name": func["name"], "kind": "function", "line": func["line_start"]})
        for cls in classes:
            if cls["name"] and cls["name"][0].isupper():
                exports.append({"name": cls["name"], "kind": "type", "line": cls["line_start"]})
    elif language in ("javascript", "typescript"):
        export_re = re.compile(r"\bexport\s+(?:default\s+)?(?:abstract\s+)?(?:function|class|const|let|var|type|interface|enum)\s+(\w+)")
        named_export_re = re.compile(r"\bexport\s*\{([^}]+)\}")
        module_exports_re = re.compile(r"\bmodule\.exports\s*=")
        for idx, line in enumerate(source_lines):
            m = export_re.search(line)
            if m:
                exports.append({"name": m.group(1), "kind": "named_export", "line": idx + 1})
                continue
            m = named_export_re.search(line)
            if m:
                for name in m.group(1).split(","):
                    name = name.strip().split(" as ")[-1].strip()
                    if name:
                        exports.append({"name": name, "kind": "named_export", "line": idx + 1})
                continue
            if module_exports_re.search(line):
                exports.append({"name": "module.exports", "kind": "cjs_export", "line": idx + 1})
    elif language == "python":
        all_re = re.compile(r"__all__\s*=\s*\[([^\]]*)\]")
        has_all = False
        for idx, line in enumerate(source_lines):
            m = all_re.search(line)
            if m:
                has_all = True
                for name in re.findall(r"['\"](\w+)['\"]", m.group(1)):
                    exports.append({"name": name, "kind": "all_export", "line": idx + 1})
        if not has_all:
            for func in functions:
                if not func["name"].startswith("_"):
                    exports.append({"name": func["name"], "kind": "public_function", "line": func["line_start"]})
            for cls in classes:
                if not cls["name"].startswith("_"):
                    exports.append({"name": cls["name"], "kind": "public_class", "line": cls["line_start"]})
    elif language == "java":
        for func in functions:
            if "public" in func.get("modifiers", []):
                exports.append({"name": func["name"], "kind": "public_method", "line": func["line_start"]})
        for cls in classes:
            exports.append({"name": cls["name"], "kind": "public_class", "line": cls["line_start"]})
    elif language == "ruby":
        for func in functions:
            exports.append({"name": func["name"], "kind": "method", "line": func["line_start"]})
    elif language == "php":
        for func in functions:
            if "public" in func.get("modifiers", []) or not func.get("modifiers"):
                exports.append({"name": func["name"], "kind": "public_method", "line": func["line_start"]})

    return exports


def _resolve_import_targets(
    imports: list[str],
    language: str,
) -> list[dict[str, str]]:
    """Resolve import strings to likely file targets within the repo."""
    targets: list[dict[str, str]] = []

    for imp in imports:
        target: dict[str, str] = {"raw": imp, "resolved": ""}

        if language == "python":
            m = re.match(r"from\s+([\w.]+)\s+import", imp)
            if m:
                target["resolved"] = m.group(1).replace(".", "/") + ".py"
            elif imp.startswith("import "):
                mod = imp.removeprefix("import ").strip().split(",")[0].strip()
                target["resolved"] = mod.replace(".", "/") + ".py"
        elif language in ("javascript", "typescript"):
            m = re.search(r"""from\s+['"]([^'"]+)['"]""", imp)
            if m:
                path = m.group(1)
                if path.startswith("."):
                    target["resolved"] = path
        elif language == "go":
            target["resolved"] = imp
        elif language == "ruby":
            if "/" in imp or imp.startswith("."):
                target["resolved"] = imp + ".rb" if not imp.endswith(".rb") else imp
            else:
                target["resolved"] = imp
        elif language == "php":
            parts = imp.strip().rstrip(";")
            target["resolved"] = parts.replace("\\", "/")
        elif language in ("c", "cpp"):
            if not imp.startswith("<"):
                target["resolved"] = imp
        elif language == "java":
            target["resolved"] = imp.replace(".", "/") + ".java"

        targets.append(target)

    return targets


def _enrich_qualified_names(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
) -> None:
    """Set qualified_name to ClassName.method for methods inside classes."""
    for cls in classes:
        for func in functions:
            if cls["line_start"] <= func["line_start"] <= func["line_end"] <= cls["line_end"]:
                func["qualified_name"] = f"{cls['name']}.{func['name']}"


# ---------------------------------------------------------------------------
# Arrow function detection for JS/TS (assigned to variable)
# ---------------------------------------------------------------------------

_ARROW_RE = re.compile(
    r"(?:const|let|var)\s+([a-zA-Z_$]\w*)\s*=\s*(?:async\s+)?\(.*?\)\s*=>"
)


def _detect_arrow_functions(source_lines: list[str]) -> list[dict[str, Any]]:
    """Detect arrow functions assigned to named variables (JS/TS)."""
    arrows: list[dict[str, Any]] = []
    for idx, line in enumerate(source_lines):
        m = _ARROW_RE.search(line)
        if m:
            arrows.append({
                "name": m.group(1),
                "qualified_name": m.group(1),
                "line_start": idx + 1,
                "line_end": idx + 1,  # approximate; refined below if possible
                "params": [],
                "modifiers": [],
                "annotations": [],
                "is_entry_point": False,
            })
    return arrows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def language_for_file(file_path: str) -> str | None:
    """Return the tree-sitter language key for a file, or None if unsupported."""
    ext = Path(file_path).suffix.lower()
    return EXTENSION_LANG_MAP.get(ext)


def index_file(
    file_path: str,
    language: str,
    source: bytes | None = None,
) -> dict[str, Any]:
    """Parse a single file and return a structural index dict.

    If tree-sitter is not available, returns a minimal stub with only line
    counts and language metadata (no functions, sinks, etc.).
    """
    if source is None:
        try:
            with open(file_path, "rb") as fh:
                source = fh.read()
        except OSError as exc:
            warnings.warn(f"Cannot read {file_path}: {exc}")
            return _empty_index(file_path, language)

    source_lines = source.decode("utf-8", errors="replace").splitlines()
    total_lines = len(source_lines)

    if not _TS_AVAILABLE:
        warnings.warn(
            "tree-sitter is not installed; returning degraded index without "
            "structural analysis. Install tree-sitter and language grammars "
            "for full indexing.",
            stacklevel=2,
        )
        return _empty_index(file_path, language, total_lines=total_lines)

    if language not in SUPPORTED_LANGUAGES:
        return _empty_index(file_path, language, total_lines=total_lines)

    # For .tsx files, use the tsx parser variant
    parse_lang = language
    if file_path.endswith(".tsx"):
        parse_lang = "tsx"

    parser = _get_parser(parse_lang)
    if parser is None:
        warnings.warn(
            f"tree-sitter grammar for '{language}' not available; returning "
            "degraded index.",
            stacklevel=2,
        )
        return _empty_index(file_path, language, total_lines=total_lines)

    tree = parser.parse(source)

    # Extract structural elements
    functions = _extract_functions_ts(tree, parse_lang if parse_lang != "tsx" else "typescript", source)
    classes = _extract_classes_ts(tree, parse_lang if parse_lang != "tsx" else "typescript", source)
    imports = _extract_imports_ts(tree, parse_lang if parse_lang != "tsx" else "typescript", source)

    # For JS/TS, also find arrow functions assigned to variables
    effective_lang = "typescript" if parse_lang == "tsx" else language
    if effective_lang in ("javascript", "typescript"):
        arrows = _detect_arrow_functions(source_lines)
        # Merge arrows that are not already captured
        existing_names = {(f["name"], f["line_start"]) for f in functions}
        for arrow in arrows:
            if (arrow["name"], arrow["line_start"]) not in existing_names:
                functions.append(arrow)

    # Enrich qualified names with class context
    _enrich_qualified_names(functions, classes)

    # Detect entry points
    entry_points = _detect_entry_points(functions, classes, effective_lang, source_lines)

    # Detect security sinks
    sinks = _detect_sinks(functions, effective_lang, source_lines)

    # Detect call sites
    call_sites = _detect_call_sites(functions, source_lines)

    # Detect exports
    exports = _detect_exports(functions, classes, effective_lang, source_lines)

    # Resolve import targets
    import_targets = _resolve_import_targets(imports, effective_lang)

    return {
        "file_path": file_path,
        "language": language,
        "total_functions": len(functions),
        "total_lines": total_lines,
        "functions": functions,
        "entry_points": entry_points,
        "security_sinks": sinks,
        "call_sites": call_sites,
        "imports": imports,
        "import_targets": import_targets,
        "exports": exports,
        "classes": classes,
    }


def _empty_index(
    file_path: str,
    language: str,
    total_lines: int = 0,
) -> dict[str, Any]:
    """Return an empty structural index stub."""
    return {
        "file_path": file_path,
        "language": language,
        "total_functions": 0,
        "total_lines": total_lines,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
    }


def index_repo(
    repo_path: str,
    file_list: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Index all supported files in *file_list* and return (indices, manifest).

    Each entry in *file_list* must have at least ``file_path`` (relative to
    *repo_path*) and optionally ``language``.
    """
    indices: list[dict[str, Any]] = []
    lang_counts: dict[str, int] = {}
    total_functions = 0
    total_entry_points = 0
    total_sinks = 0
    total_exports = 0
    sinks_by_cat: dict[str, int] = {}
    skipped = 0

    for entry in file_list:
        rel_path = entry["file_path"]
        abs_path = str(Path(repo_path) / rel_path)
        lang = entry.get("language") or language_for_file(rel_path)
        if not lang or lang not in SUPPORTED_LANGUAGES:
            skipped += 1
            continue

        idx = index_file(abs_path, lang)
        idx["file_path"] = rel_path
        indices.append(idx)

        lang_counts[lang] = lang_counts.get(lang, 0) + 1
        total_functions += idx["total_functions"]
        total_entry_points += len(idx["entry_points"])
        total_sinks += len(idx["security_sinks"])
        total_exports += len(idx.get("exports", []))
        for sink in idx["security_sinks"]:
            kind = sink["kind"]
            sinks_by_cat[kind] = sinks_by_cat.get(kind, 0) + 1

    manifest = {
        "repo_path": repo_path,
        "total_files": len(file_list),
        "indexed_files": len(indices),
        "skipped_unsupported": skipped,
        "languages": lang_counts,
        "total_functions": total_functions,
        "total_entry_points": total_entry_points,
        "total_security_sinks": total_sinks,
        "total_exports": total_exports,
        "sinks_by_category": sinks_by_cat,
    }

    return indices, manifest
