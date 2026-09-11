"""Tree-sitter structural indexing for code analysis.

Parses source files using tree-sitter to extract function/method definitions,
class structures, import statements, entry points, security sinks, and call
sites.  All tree-sitter imports are guarded so the module remains importable
(returning empty/degraded results) when tree-sitter packages are absent.
"""
from __future__ import annotations

import re
import warnings
from typing import Any

from assess.lib.code_languages import (
    STRUCTURAL_SUPPORTED_LANGUAGES,
    structural_language_for_file,
)

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


# Tree-sitter backed languages (full structural parsing)
_TS_SUPPORTED_LANGUAGES = frozenset({
    "java", "c", "cpp", "python", "javascript", "typescript",
    "go", "ruby", "php",
})

# Lightweight regex/line-based extractors (pure-python, no tree-sitter grammar)
LIGHTWEIGHT_LANGUAGES = frozenset({
    "dockerfile", "shell", "lua", "html", "css",
})

# Combined set used by consumers (code_index.py / code_index_sync.py / assess
# backend) to gate which files are indexed. Anything not in this set is
# skipped silently with skipped_unsupported++.
SUPPORTED_LANGUAGES = STRUCTURAL_SUPPORTED_LANGUAGES


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

_CPP_DECLARATION_QUERY = """
    (declaration) @decl
    (field_declaration) @decl
"""

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
            "javascript": [
                r"\beval\s*\(",
                r"\bFunction\s*\(",
                r"""\bset(?:Timeout|Interval)\s*\(\s*["'`]""",
            ],
            "typescript": [
                r"\beval\s*\(",
                r"\bFunction\s*\(",
                r"""\bset(?:Timeout|Interval)\s*\(\s*["'`]""",
            ],
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
    ],
    "php": [
        {"pattern": r"\bRoute::\w+\s*\(", "kind": "laravel_route"},
        {"pattern": r"\$app->\w+\s*\(", "kind": "slim_route"},
        {"pattern": r"\$router->\w+\s*\(", "kind": "framework_route"},
    ],
}

_GLOBAL_ENTRY_LINE_PATTERNS: dict[str, list[dict[str, str]]] = {
    "python": [
        {"pattern": r"^\s*if\s+__name__\s*==\s*['\"]__main__['\"]", "kind": "main_guard"},
    ],
    "ruby": [
        {"pattern": r"^\s*if\s+__FILE__\s*==\s*\$0", "kind": "main_guard"},
        {"pattern": r"^\s*if\s+\$PROGRAM_NAME\s*==\s*__FILE__", "kind": "main_guard"},
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


def _query_language_family(language: str) -> str:
    """Map parser-specific keys to the query family used in *_QUERIES."""
    if language == "tsx":
        return "typescript"
    return language


_CPP_NAME_NODE_TYPES = frozenset({
    "conversion_operator",
    "destructor_name",
    "field_identifier",
    "identifier",
    "literal_operator_name",
    "operator_name",
    "qualified_identifier",
    "template_function",
})
_CPP_OBJECT_DECLARATOR_TYPES = frozenset({
    "abstract_array_declarator",
    "abstract_pointer_declarator",
    "abstract_reference_declarator",
    "array_declarator",
    "pointer_declarator",
    "reference_declarator",
})
_CPP_SIGNATURE_QUALIFIER_TYPES = frozenset({
    "noexcept",
    "ref_qualifier",
    "requires_clause",
    "type_qualifier",
})


def _field_children(node: Any, field_name: str) -> list[Any]:
    """Return direct children carrying *field_name* across tree-sitter APIs."""
    return [
        child
        for index, child in enumerate(node.children)
        if node.field_name_for_child(index) == field_name
    ]


def _cpp_declarator_child(node: Any) -> Any | None:
    child = node.child_by_field_name("declarator")
    if child is not None:
        return child
    if node.type in {
        "abstract_pointer_declarator",
        "abstract_reference_declarator",
        "parenthesized_declarator",
        "pointer_declarator",
        "reference_declarator",
    }:
        named_children = list(node.named_children)
        if len(named_children) == 1:
            return named_children[0]
    return None


def _cpp_declarator_path(declarator: Any) -> list[Any]:
    """Follow only the declared-name spine, excluding params and initializers."""
    path = [declarator]
    current = declarator
    while current.type not in _CPP_NAME_NODE_TYPES:
        current = _cpp_declarator_child(current)
        if current is None:
            return []
        path.append(current)
    return path


def _cpp_conversion_callable(
    declarator: Any,
    source: bytes,
) -> tuple[Any, str, str] | None:
    scope = ""
    conversion = declarator
    if declarator.type == "qualified_identifier":
        conversion = declarator.child_by_field_name("name")
        scope_node = declarator.child_by_field_name("scope")
        if scope_node is not None:
            scope = _node_text(scope_node, source)
    if conversion is None or conversion.type != "operator_cast":
        return None

    function_declarator = conversion.child_by_field_name("declarator")
    while function_declarator is not None and function_declarator.type not in {
        "abstract_function_declarator",
        "function_declarator",
    }:
        function_declarator = _cpp_declarator_child(function_declarator)
    operator_node = next(
        (child for child in conversion.children if child.type == "operator"),
        None,
    )
    if function_declarator is None or operator_node is None:
        return None
    target_type = source[operator_node.end_byte:function_declarator.start_byte].decode(
        "utf-8", errors="replace"
    ).strip()
    if not target_type:
        return None
    name = f"operator {target_type}"
    return function_declarator, name, scope


def _cpp_callable_declarator(
    declarator: Any,
    source: bytes,
) -> tuple[Any, str, str] | None:
    """Return the function declarator and name for an actual callable symbol.

    Walking from the declared name outward distinguishes a function returning
    a pointer from a pointer object whose pointee is a function: the nearest
    meaningful wrapper decides which one was declared.
    """
    conversion = _cpp_conversion_callable(declarator, source)
    if conversion is not None:
        return conversion

    path = _cpp_declarator_path(declarator)
    if not path:
        return None
    name_node = path[-1]
    for wrapper in reversed(path[:-1]):
        if wrapper.type == "function_declarator":
            scope = ""
            leaf_node = name_node
            if name_node.type == "qualified_identifier":
                scope_node = name_node.child_by_field_name("scope")
                qualified_leaf = name_node.child_by_field_name("name")
                if scope_node is not None:
                    scope = _node_text(scope_node, source)
                if qualified_leaf is not None:
                    leaf_node = qualified_leaf
            return wrapper, _node_text(leaf_node, source), scope
        if wrapper.type in _CPP_OBJECT_DECLARATOR_TYPES:
            return None
    return None


def _cpp_namespace_qualifier(node: Any, source: bytes) -> str:
    namespaces: list[str] = []
    current = node.parent
    while current is not None:
        if current.type == "namespace_definition":
            name_node = current.child_by_field_name("name")
            namespaces.append(
                _node_text(name_node, source) if name_node is not None else "<anonymous>"
            )
        current = current.parent
    return "::".join(reversed(namespaces))


def _cpp_has_ancestor(node: Any, node_type: str) -> bool:
    current = node.parent
    while current is not None:
        if current.type == node_type:
            return True
        current = current.parent
    return False


def _cpp_parameter_signature(params_node: Any, source: bytes) -> tuple[str, ...]:
    """Build a name-insensitive parameter signature for declaration dedup."""
    signatures: list[str] = []
    for parameter in params_node.named_children:
        if parameter.type == "comment":
            continue
        start = parameter.start_byte
        end = parameter.end_byte
        default_value = parameter.child_by_field_name("default_value")
        if default_value is not None:
            end = default_value.start_byte

        declarator = parameter.child_by_field_name("declarator")
        path = _cpp_declarator_path(declarator) if declarator is not None else []
        name_node = path[-1] if path else None
        if name_node is not None and name_node.start_byte < end:
            raw = source[start:name_node.start_byte] + source[name_node.end_byte:end]
        else:
            raw = source[start:end]
        canonical = re.sub(rb"\s+", b"", raw).rstrip(b"=").decode(
            "utf-8", errors="replace"
        )
        signatures.append(canonical)
    return tuple(signatures)


def _cpp_qualifier_signature(function_declarator: Any, source: bytes) -> tuple[str, ...]:
    return tuple(
        re.sub(r"\s+", "", _node_text(child, source))
        for child in function_declarator.named_children
        if child.type in _CPP_SIGNATURE_QUALIFIER_TYPES
    )


def _source_character_column(source: bytes, byte_offset: int) -> int:
    line_start = source.rfind(b"\n", 0, byte_offset) + 1
    return len(source[line_start:byte_offset].decode("utf-8", errors="replace"))


def _node_character_range(node: Any, source: bytes) -> tuple[int, int, int, int]:
    return (
        node.start_point[0] + 1,
        _source_character_column(source, node.start_byte),
        node.end_point[0] + 1,
        _source_character_column(source, node.end_byte),
    )


def _public_node_span(node: Any, source: bytes) -> dict[str, int]:
    start_line, start_column, end_line, end_column = _node_character_range(
        node, source
    )
    return {
        "start_byte": int(node.start_byte),
        "end_byte": int(node.end_byte),
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
    }


def _attach_callable_spans(
    parsed: dict[str, Any],
    *,
    callable_node: Any,
    source: bytes,
) -> None:
    parsed["source_span"] = _public_node_span(callable_node, source)
    body = callable_node.child_by_field_name("body")
    if body is None:
        return
    parsed["body_span"] = _public_node_span(body, source)
    (
        parsed["_body_start_line"],
        parsed["_body_start_column"],
        parsed["_body_end_line"],
        parsed["_body_end_column"],
    ) = _node_character_range(body, source)


def _parse_cpp_callable(
    *,
    container: Any,
    declarator: Any,
    source: bytes,
    is_declaration: bool,
) -> dict[str, Any] | None:
    callable_parts = _cpp_callable_declarator(declarator, source)
    if callable_parts is None:
        return None
    function_declarator, name, declared_scope = callable_parts
    params_node = function_declarator.child_by_field_name("parameters")
    start_line, end_line = _node_lines(container)
    parsed = {
        "name": name,
        "qualified_name": name,
        "line_start": start_line,
        "line_end": end_line,
        "params": _extract_params(params_node, source) if params_node else [],
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
        "is_declaration": is_declaration,
        "_start_byte": container.start_byte,
        "_end_byte": container.end_byte,
        "_cpp_is_friend": _cpp_has_ancestor(container, "friend_declaration"),
        "_cpp_declared_scope": declared_scope,
        "_cpp_namespace": _cpp_namespace_qualifier(container, source),
        "_cpp_parameter_signature": (
            _cpp_parameter_signature(params_node, source) if params_node else ()
        ),
        "_cpp_qualifier_signature": _cpp_qualifier_signature(
            function_declarator, source
        ),
    }
    body = container.child_by_field_name("body")
    if body is not None:
        parsed["source_span"] = _public_node_span(container, source)
        parsed["body_span"] = _public_node_span(body, source)
        (
            parsed["_body_start_line"],
            parsed["_body_start_column"],
            parsed["_body_end_line"],
            parsed["_body_end_column"],
        ) = _node_character_range(body, source)

    initializer_ranges: list[tuple[int, int, int, int]] = []
    for child in container.named_children:
        if child.type != "field_initializer_list":
            continue
        for initializer in child.named_children:
            if initializer.type != "field_initializer":
                continue
            initializer_children = list(initializer.named_children)
            if len(initializer_children) >= 2:
                initializer_ranges.append(
                    _node_character_range(initializer_children[-1], source)
                )
    if initializer_ranges:
        parsed["_initializer_ranges"] = initializer_ranges
    return parsed


_JAVASCRIPT_CALLABLE_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)


def _walk_named_nodes(node: Any):
    yield node
    for child in node.named_children:
        yield from _walk_named_nodes(child)


def _normalized_javascript_target(value: str) -> str:
    return value.replace(".prototype.", ".").removesuffix(".prototype")


def _javascript_define_property_name(node: Any, source: bytes) -> str | None:
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            callee = current.child_by_field_name("function")
            if callee is None or _node_text(callee, source) != "Object.defineProperty":
                return None
            arguments = current.child_by_field_name("arguments")
            values = list(arguments.named_children) if arguments is not None else []
            if len(values) < 3:
                return None
            target = _normalized_javascript_target(_node_text(values[0], source))
            property_node = values[1]
            property_name = _node_text(property_node, source).strip("'\"`")
            if not target or not property_name:
                return None
            return f"{target}.{property_name}"
        current = current.parent
    return None


def _javascript_callable_name(node: Any, source: bytes) -> str:
    explicit_name = node.child_by_field_name("name")
    if explicit_name is not None:
        return _node_text(explicit_name, source)

    define_property_name = _javascript_define_property_name(node, source)
    if define_property_name:
        return define_property_name

    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        if name is not None:
            return _node_text(name, source)
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _normalized_javascript_target(_node_text(left, source))
    if parent is not None and parent.type in {"pair", "public_field_definition"}:
        key = parent.child_by_field_name("key") or parent.child_by_field_name("name")
        if key is not None:
            return _node_text(key, source).strip("'\"`")

    line, column, _end_line, _end_column = _node_character_range(node, source)
    return f"<anonymous@{line}:{column}>"


def _parse_javascript_callable(node: Any, source: bytes) -> dict[str, Any]:
    name = _javascript_callable_name(node, source)
    parameters = node.child_by_field_name("parameters")
    single_parameter = node.child_by_field_name("parameter")
    parsed = {
        "name": name.rsplit(".", 1)[-1],
        "qualified_name": name,
        "line_start": node.start_point[0] + 1,
        "line_end": node.end_point[0] + 1,
        "params": (
            _extract_params(parameters, source)
            if parameters is not None
            else ([_node_text(single_parameter, source)] if single_parameter is not None else [])
        ),
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
        "_start_byte": node.start_byte,
        "_end_byte": node.end_byte,
    }
    _attach_callable_spans(parsed, callable_node=node, source=source)
    return parsed


def _extract_javascript_callables(
    tree: Any,
    source: bytes,
) -> list[dict[str, Any]]:
    return [
        _parse_javascript_callable(node, source)
        for node in _walk_named_nodes(tree.root_node)
        if node.type in _JAVASCRIPT_CALLABLE_TYPES
    ]


def _extract_cpp_declarations(
    tree: Any,
    language: str,
    source: bytes,
) -> list[dict[str, Any]]:
    parser = _get_parser(language)
    if parser is None:
        return []
    captures = _ts_query_captures(
        parser.language,
        _CPP_DECLARATION_QUERY,
        tree.root_node,
    )
    declarations: list[dict[str, Any]] = []
    seen_declarators: set[tuple[int, int]] = set()
    for node in captures.get("decl", []):
        for declarator in _field_children(node, "declarator"):
            callable_parts = _cpp_callable_declarator(declarator, source)
            if callable_parts is None:
                continue
            function_declarator, _name, _scope = callable_parts
            source_range = (function_declarator.start_byte, function_declarator.end_byte)
            if source_range in seen_declarators:
                continue
            seen_declarators.add(source_range)
            parsed = _parse_cpp_callable(
                container=node,
                declarator=declarator,
                source=source,
                is_declaration=True,
            )
            if parsed is not None:
                declarations.append(parsed)
    return declarations


def _extract_functions_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract function/method definitions and C++ declarations."""
    query_language = _query_language_family(language)
    query_str = _FUNCTION_QUERIES.get(query_language)
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
        source_range = (node.start_byte, node.end_byte)
        if source_range in seen_ranges:
            continue
        seen_ranges.add(source_range)

        func_info = _parse_function_node(node, language, source)
        if func_info:
            functions.append(func_info)

    if query_language == "cpp":
        functions.extend(_extract_cpp_declarations(tree, language, source))
    elif query_language in {"javascript", "typescript"}:
        functions = _extract_javascript_callables(tree, source)

    return functions


def _parse_function_node(node: Any, language: str, source: bytes) -> dict[str, Any] | None:
    """Parse a single function/method tree-sitter node into a structured dict."""
    start_line, end_line = _node_lines(node)
    language = _query_language_family(language)
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
    elif language == "cpp":
        decl = node.child_by_field_name("declarator")
        if decl is not None:
            return _parse_cpp_callable(
                container=node,
                declarator=decl,
                source=source,
                is_declaration=False,
            )
    elif language == "c":
        decl = node.child_by_field_name("declarator")
        if decl:
            for child in decl.children:
                if child.type == "identifier":
                    name = _node_text(child, source)
                elif child.type == "parameter_list":
                    params = _extract_params(child, source)
                elif child.type == "field_identifier":
                    name = _node_text(child, source)
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

    parsed = {
        "name": name,
        "qualified_name": name,
        "line_start": start_line,
        "line_end": end_line,
        "params": params,
        "modifiers": modifiers,
        "annotations": annotations,
        "is_entry_point": False,
    }
    parsed["_start_byte"] = node.start_byte
    parsed["_end_byte"] = node.end_byte
    _attach_callable_spans(parsed, callable_node=node, source=source)
    return parsed


def _extract_params(params_node: Any, source: bytes) -> list[str]:
    """Extract parameter text from a parameters node."""
    params: list[str] = []
    for child in params_node.children:
        if child.type in ("formal_parameter", "parameter", "spread_element",
                          "required_parameter", "optional_parameter",
                          "typed_parameter", "default_parameter",
                          "identifier", "typed_default_parameter",
                          "parameter_declaration", "optional_parameter_declaration",
                          "simple_parameter",
                          "variadic_parameter", "optional_parameter",
                          "keyword_parameter", "block_parameter",
                          "splat_parameter", "hash_splat_parameter"):
            params.append(_node_text(child, source).strip())
    return params


def _extract_classes_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract class/struct definitions using tree-sitter queries."""
    query_language = _query_language_family(language)
    query_str = _CLASS_QUERIES.get(query_language)
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
    language = _query_language_family(language)
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

    parsed_class = {
        "name": name,
        "extends": extends,
        "implements": implements,
        "line_start": start_line,
        "line_end": end_line,
        "_start_byte": node.start_byte,
        "_end_byte": node.end_byte,
    }
    if language == "cpp":
        parsed_class["_cpp_namespace"] = _cpp_namespace_qualifier(node, source)
    return parsed_class


_RUBY_REQUIRE_RE = re.compile(
    r"""(?:require|require_relative|load)\s*[\(]?\s*['"](.+?)['"]\s*[\)]?"""
)


def _extract_imports_ts(tree: Any, language: str, source: bytes) -> list[str]:
    """Extract import/include strings using tree-sitter queries."""
    query_language = _query_language_family(language)
    if query_language == "ruby":
        return _extract_ruby_imports(source)

    query_str = _IMPORT_QUERIES.get(query_language)
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
        if query_language == "java":
            text = text.removeprefix("import").strip()
            text = text.removeprefix("static").strip()
        elif query_language in ("c", "cpp"):
            m = re.search(r'[<"](.+?)[>"]', text)
            if m:
                text = m.group(1)
        elif query_language == "go":
            text = text.strip().strip('"')
            if text.startswith("."):
                continue
        elif query_language == "php":
            text = text.removeprefix("use").strip().rstrip(";")
        elif query_language == "python":
            pass
        elif query_language in ("javascript", "typescript"):
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


def _detect_top_level_entry_points(
    tree: Any,
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect guards whose conditional node is a direct program child."""
    entry_points: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    patterns = _GLOBAL_ENTRY_LINE_PATTERNS.get(language, [])
    if not patterns:
        return entry_points

    for node in getattr(tree.root_node, "named_children", ()):
        line_number = node.start_point[0] + 1
        if line_number > len(source_lines):
            continue
        line = source_lines[line_number - 1]
        for pattern in patterns:
            identity = (line_number, pattern["kind"])
            if identity in seen or not re.search(pattern["pattern"], line):
                continue
            entry_points.append({
                "name": "<top-level>",
                "line": line_number,
                "kind": pattern["kind"],
                "annotation": "",
            })
            seen.add(identity)
    return entry_points


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


def _function_scan_lines(
    function: dict[str, Any],
    source_lines: list[str],
) -> list[tuple[int, str]]:
    """Return source segments that execute as part of a function definition."""
    body_start_line = function.get("_body_start_line")
    if body_start_line is None:
        start = max(0, function["line_start"] - 1)
        end = min(len(source_lines), function["line_end"])
        return [(line_index, source_lines[line_index]) for line_index in range(start, end)]

    lines: list[tuple[int, str]] = []
    ranges = [
        *function.get("_initializer_ranges", []),
        (
            body_start_line,
            function["_body_start_column"],
            function["_body_end_line"],
            function["_body_end_column"],
        ),
    ]
    for start_line, start_column, end_line, end_column in ranges:
        for line_number in range(start_line, end_line + 1):
            line_index = line_number - 1
            if not 0 <= line_index < len(source_lines):
                continue
            line = source_lines[line_index]
            segment_start = start_column if line_number == start_line else 0
            segment_end = end_column if line_number == end_line else len(line)
            lines.append((line_index, line[segment_start:segment_end]))
    return lines


def _detect_sinks(
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect security-sensitive API calls within function bodies using regex."""
    sinks: list[dict[str, Any]] = []

    for func in functions:
        if func.get("is_declaration", False):
            continue
        scan_lines = _function_scan_lines(func, source_lines)

        for sink_def in _SINK_DEFINITIONS:
            lang_patterns = sink_def["patterns"].get(language, [])
            for pat in lang_patterns:
                compiled = re.compile(pat)
                for line_idx, line_text in scan_lines:
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
    # Common language keywords to exclude from call-site detection
    noise = frozenset({
        "if", "else", "for", "while", "switch", "case", "return", "throw",
        "new", "delete", "try", "catch", "finally", "import", "from",
        "class", "def", "function", "var", "let", "const", "static",
        "async",
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
        if func.get("is_declaration", False):
            continue
        seen_callees: set[str] = set()

        param_names: set[str] = set()
        for p in func.get("params", []):
            tokens = re.split(r"[\s:=,*&]+", p.strip())
            for tok in tokens:
                tok = tok.strip().lstrip("$")
                if tok and tok not in noise and len(tok) > 1:
                    param_names.add(tok)

        for line_idx, line_text in _function_scan_lines(func, source_lines):
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


def _cpp_qualified_name(
    namespace: str,
    declared_scope: str,
    name: str,
) -> str:
    if namespace and (
        declared_scope == namespace or declared_scope.startswith(f"{namespace}::")
    ):
        symbol_scope = declared_scope
    else:
        symbol_scope = "::".join(
            part for part in (namespace, declared_scope) if part
        )
    dotted_scope = symbol_scope.replace("::", ".")
    return f"{dotted_scope}.{name}" if dotted_scope else name


def _enrich_qualified_names(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
) -> None:
    """Set qualified_name to ClassName.method for methods inside classes."""
    if language == "cpp":
        for cls in classes:
            containers = [
                candidate
                for candidate in classes
                if candidate is not cls
                and candidate["_start_byte"] <= cls["_start_byte"]
                and cls["_end_byte"] <= candidate["_end_byte"]
            ]
            containers.sort(key=lambda candidate: candidate["_start_byte"])
            namespace = cls.get("_cpp_namespace", "").replace("::", ".")
            class_parts = [
                *(candidate["name"] for candidate in containers),
                cls["name"],
            ]
            cls["_qualified_name"] = ".".join(
                [*([namespace] if namespace else []), *class_parts]
            )

        for func in functions:
            containers = [
                cls
                for cls in classes
                if cls["_start_byte"] <= func["_start_byte"]
                and func["_end_byte"] <= cls["_end_byte"]
            ]
            if containers and not func.get("_cpp_is_friend", False):
                containers.sort(
                    key=lambda candidate: (
                        candidate["_end_byte"] - candidate["_start_byte"]
                    )
                )
                func["qualified_name"] = (
                    f"{containers[0]['_qualified_name']}.{func['name']}"
                )
            else:
                func["qualified_name"] = _cpp_qualified_name(
                    func.get("_cpp_namespace", ""),
                    func.get("_cpp_declared_scope", ""),
                    func["name"],
                )
        return

    for cls in classes:
        for func in functions:
            if cls["line_start"] <= func["line_start"] <= func["line_end"] <= cls["line_end"]:
                func["qualified_name"] = f"{cls['name']}.{func['name']}"


def _cpp_function_identity(function: dict[str, Any]) -> tuple[Any, ...]:
    qualified_name = re.sub(
        r"\s*([*&<>,()\[\]])\s*",
        r"\1",
        re.sub(
            r"\s+",
            " ",
            function["qualified_name"].replace("::", ".").strip(),
        ),
    )
    return (
        qualified_name,
        function["_cpp_parameter_signature"],
        function["_cpp_qualifier_signature"],
    )


def _deduplicate_cpp_functions(
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse repeated declarations, retaining every distinct definition."""
    by_identity: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for function in functions:
        identity = _cpp_function_identity(function)
        by_identity.setdefault(identity, []).append(function)

    retained: list[dict[str, Any]] = []
    for matching_functions in by_identity.values():
        definitions = [
            function
            for function in matching_functions
            if not function["is_declaration"]
        ]
        retained.extend(definitions or matching_functions[:1])
    return sorted(retained, key=lambda function: function["_start_byte"])


def _remove_internal_structural_fields(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
) -> None:
    for function in functions:
        for field_name in (
            "_body_end_column",
            "_body_end_line",
            "_body_start_column",
            "_body_start_line",
            "_initializer_ranges",
            "_cpp_parameter_signature",
            "_cpp_qualifier_signature",
            "_cpp_declared_scope",
            "_cpp_is_friend",
            "_cpp_namespace",
            "_end_byte",
            "_start_byte",
        ):
            function.pop(field_name, None)
    for cls in classes:
        for field_name in (
            "_cpp_namespace",
            "_end_byte",
            "_qualified_name",
            "_start_byte",
        ):
            cls.pop(field_name, None)


# ---------------------------------------------------------------------------
# Lightweight regex-based extractors
#
# These cover security-relevant file families that the tree-sitter pipeline
# ignores (Dockerfile, shell, Lua, HTML/templates, CSS). They return the same
# dict shape as the tree-sitter path so downstream consumers keep working.
# ---------------------------------------------------------------------------


def _snippet(line: str, limit: int = 120) -> str:
    s = line.strip()
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def _empty_func(name: str, line_start: int, line_end: int) -> dict[str, Any]:
    return {
        "name": name,
        "qualified_name": name,
        "line_start": line_start,
        "line_end": line_end,
        "params": [],
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
    }


def _index_lightweight(
    file_path: str,
    language: str,
    source_lines: list[str],
    total_lines: int,
) -> dict[str, Any]:
    """Dispatch helper for lightweight extractors."""
    dispatch = {
        "dockerfile": _extract_dockerfile,
        "shell": _extract_shell,
        "lua": _extract_lua,
        "html": _extract_html,
        "css": _extract_css,
    }
    fn = dispatch.get(language)
    if fn is None:
        return _empty_index(file_path, language, total_lines=total_lines)
    funcs, entry_points, sinks, exports, imports = fn(source_lines)
    return {
        "file_path": file_path,
        "language": language,
        "total_functions": len(funcs),
        "total_lines": total_lines,
        "functions": funcs,
        "entry_points": entry_points,
        "security_sinks": sinks,
        "call_sites": [],
        "imports": imports,
        "import_targets": [{"raw": i, "resolved": ""} for i in imports],
        "exports": exports,
        "classes": [],
    }


# --- Dockerfile -------------------------------------------------------------

_DOCKER_INSTR_RE = re.compile(r"^\s*([A-Z]+)\s+(.*)$")
_DOCKER_SECRET_NAMES = re.compile(r"\b(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH)\b", re.IGNORECASE)
_DOCKER_URL_RE = re.compile(r"https?://\S+")


def _extract_dockerfile(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []
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
        # Consume continuation lines
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
                "vuln_classes": ["secret-exposure"],
            })

        if instr == "ARG" and _DOCKER_SECRET_NAMES.search(block_text):
            sinks.append({
                "kind": "embedded_secret_arg",
                "line": block_start,
                "function": instr,
                "snippet": _snippet(stripped),
                "vuln_classes": ["secret-exposure"],
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

    return funcs, entry_points, sinks, exports, imports


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
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\b(curl|wget)\b[^|;]*\|\s*(sh|bash|zsh)\b", line):
            sinks.append({
                "kind": "remote_pipe_to_shell",
                "line": line_no,
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["supply-chain", "injection"],
            })
        if re.search(r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", line):
            sinks.append({
                "kind": "permissive_chmod",
                "line": line_no,
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["privilege-escalation"],
            })
        if re.search(r"\bsudo\b", line):
            sinks.append({
                "kind": "sudo",
                "line": line_no,
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["privilege-escalation"],
            })
        # Command substitution with $1/$@/$* (user-tainted) inside backticks or $(...)
        if re.search(r"(?:`[^`]*\$[1-9@*][^`]*`|\$\([^)]*\$[1-9@*][^)]*\))", line):
            sinks.append({
                "kind": "tainted_command_substitution",
                "line": line_no,
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        # Hardcoded credentials: VAR=... where VAR name looks secret-y and value is a quoted literal
        cred_m = re.match(r"\s*(?:export\s+)?([A-Za-z_][\w]*)\s*=\s*['\"]([^'\"]+)['\"]", line)
        if cred_m and _DOCKER_SECRET_NAMES.search(cred_m.group(1)):
            sinks.append({
                "kind": "hardcoded_credential",
                "line": line_no,
                "function": _find_enclosing_shell_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["secret-exposure"],
            })

    return funcs, entry_points, sinks, exports, imports


def _find_enclosing_shell_func(funcs: list[dict[str, Any]], line_no: int) -> str:
    for f in funcs:
        if f["line_start"] <= line_no <= f["line_end"]:
            return f["name"]
    return "<script>"


# --- Lua --------------------------------------------------------------------

_LUA_FUNC_RE = re.compile(
    r"^\s*(?:local\s+)?function\s+([A-Za-z_][\w.:]*)\s*\(([^)]*)\)"
)
_LUA_LOCAL_FUNC_ASSIGN_RE = re.compile(
    r"^\s*local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(([^)]*)\)"
)


def _extract_lua(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    # Find function starts
    starts: list[tuple[str, list[str], int]] = []
    for idx, line in enumerate(source_lines):
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        m = _LUA_FUNC_RE.match(line) or _LUA_LOCAL_FUNC_ASSIGN_RE.match(line)
        if m:
            name = m.group(1)
            params = [p.strip() for p in m.group(2).split(",") if p.strip()]
            starts.append((name, params, idx + 1))

    # Approximate function end by scanning for matching `end` at the same indent
    for k, (name, params, start_line) in enumerate(starts):
        next_start = starts[k + 1][2] - 1 if k + 1 < len(starts) else len(source_lines)
        end_line = next_start
        # Walk forward, counting block keywords vs `end`
        depth = 1
        for j in range(start_line, len(source_lines)):
            line = source_lines[j]
            # Strip line comments
            code = re.sub(r"--.*$", "", line)
            # Block-opening keywords that require an `end`
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
        exports.append({"name": name, "kind": "lua_function", "line": start_line})

    for idx, line in enumerate(source_lines):
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        line_no = idx + 1
        # require("...")
        req_m = re.search(r"""require\s*\(?\s*['"]([^'"]+)['"]""", line)
        if req_m:
            imports.append(req_m.group(1))
        if re.search(r"\bredis\.call\s*\(", line):
            sinks.append({
                "kind": "redis_call",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["redis-injection"],
            })
        if re.search(r"\bredis\.pcall\s*\(", line):
            sinks.append({
                "kind": "redis_pcall",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["redis-injection"],
            })
        if re.search(r"\bKEYS\s*\[", line):
            sinks.append({
                "kind": "redis_keys_input",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["redis-injection"],
            })
        if re.search(r"\bARGV\s*\[", line):
            sinks.append({
                "kind": "redis_argv_input",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["redis-injection"],
            })
        if re.search(r"\b(loadstring|load)\s*\(", line):
            sinks.append({
                "kind": "dynamic_code_load",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\bos\.execute\s*\(", line):
            sinks.append({
                "kind": "os_execute",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })
        if re.search(r"\bio\.popen\s*\(", line):
            sinks.append({
                "kind": "io_popen",
                "line": line_no,
                "function": _find_enclosing_lua_func(funcs, line_no),
                "snippet": _snippet(line),
                "vuln_classes": ["injection"],
            })

    return funcs, entry_points, sinks, exports, imports


def _find_enclosing_lua_func(funcs: list[dict[str, Any]], line_no: int) -> str:
    for f in funcs:
        if f["line_start"] <= line_no <= f["line_end"]:
            return f["name"]
    return "<script>"


# --- HTML / templates -------------------------------------------------------

_HTML_FORM_RE = re.compile(r"<form\b[^>]*\baction\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE)
_HTML_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE)
_HTML_IFRAME_SRC_RE = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE)
_HTML_INLINE_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE)
_HTML_JS_URL_RE = re.compile(r"""=\s*['"]\s*javascript:""", re.IGNORECASE)
_HTML_MUSTACHE_RE = re.compile(r"\{\{[^}]+\}\}")
_HTML_ASP_RE = re.compile(r"<%[^%]+%>")
_HTML_LINK_HREF_RE = re.compile(r"<link\b[^>]*\bhref\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE)


def _extract_html(
    source_lines: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    funcs: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    imports: list[str] = []

    for idx, line in enumerate(source_lines):
        line_no = idx + 1
        # Forms -> entry points
        for m in _HTML_FORM_RE.finditer(line):
            action = m.group(1)
            entry_points.append({
                "name": "form",
                "line": line_no,
                "kind": "html_form",
                "annotation": action,
            })
            funcs.append(_empty_func(f"form:{action}", line_no, line_no))
        # External scripts -> imports + supply-chain sink if remote
        for m in _HTML_SCRIPT_SRC_RE.finditer(line):
            src = m.group(1)
            imports.append(src)
            if src.startswith(("http://", "//")):
                sinks.append({
                    "kind": "external_script_load",
                    "line": line_no,
                    "function": "<html>",
                    "snippet": _snippet(line),
                    "vuln_classes": ["supply-chain", "xss"],
                })
            elif src.startswith("https://"):
                sinks.append({
                    "kind": "external_script_load",
                    "line": line_no,
                    "function": "<html>",
                    "snippet": _snippet(line),
                    "vuln_classes": ["supply-chain"],
                })
        # link hrefs (stylesheets / preload)
        for m in _HTML_LINK_HREF_RE.finditer(line):
            imports.append(m.group(1))
        # iframe srcs
        for m in _HTML_IFRAME_SRC_RE.finditer(line):
            imports.append(m.group(1))
            sinks.append({
                "kind": "iframe_embed",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(line),
                "vuln_classes": ["clickjacking", "xss"],
            })
        # Inline event handlers
        if _HTML_INLINE_HANDLER_RE.search(line):
            sinks.append({
                "kind": "inline_event_handler",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss"],
            })
        # javascript: URLs
        if _HTML_JS_URL_RE.search(line):
            sinks.append({
                "kind": "javascript_url",
                "line": line_no,
                "function": "<html>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss"],
            })
        # Template interpolation
        if _HTML_MUSTACHE_RE.search(line):
            sinks.append({
                "kind": "template_interpolation",
                "line": line_no,
                "function": "<template>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss", "ssti"],
            })
        if _HTML_ASP_RE.search(line):
            sinks.append({
                "kind": "asp_interpolation",
                "line": line_no,
                "function": "<template>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss", "ssti"],
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

    for idx, line in enumerate(source_lines):
        line_no = idx + 1
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            # Still scan for url() in comments? No -- skip pure comment lines.
            continue
        for m in _CSS_IMPORT_RE.finditer(line):
            url = m.group(1)
            imports.append(url)
            if url.startswith(("http://", "//")):
                sinks.append({
                    "kind": "external_css_import",
                    "line": line_no,
                    "function": "<stylesheet>",
                    "snippet": _snippet(line),
                    "vuln_classes": ["supply-chain"],
                })
        for m in _CSS_URL_RE.finditer(line):
            ref = m.group(1)
            if ref.startswith(("http://", "//", "https://", "data:")):
                imports.append(ref)
        if _CSS_EXPRESSION_RE.search(line):
            sinks.append({
                "kind": "css_expression",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss"],
            })
        if _CSS_BEHAVIOR_RE.search(line):
            sinks.append({
                "kind": "css_behavior",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss"],
            })
        if _CSS_BINDING_RE.search(line):
            sinks.append({
                "kind": "css_moz_binding",
                "line": line_no,
                "function": "<stylesheet>",
                "snippet": _snippet(line),
                "vuln_classes": ["xss"],
            })

    return funcs, entry_points, sinks, exports, imports


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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

_STREAM_SOURCE_PATTERNS: dict[str, list[tuple[str, str, list[str]]]] = {
    "python": [
        ("http_request_input", r"\brequest\.(?:args|form|json|values|files|headers)\b", ["tainted-input"]),
        ("process_input", r"\b(?:sys\.argv|os\.environ|getenv\s*\(|input\s*\()", ["tainted-input"]),
    ],
    "javascript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies)\b", ["tainted-input"]),
        ("process_input", r"\bprocess\.(?:argv|env)\b", ["tainted-input"]),
    ],
    "typescript": [
        ("http_request_input", r"\breq\.(?:params|query|body|headers|cookies)\b", ["tainted-input"]),
        ("process_input", r"\bprocess\.(?:argv|env)\b", ["tainted-input"]),
    ],
    "java": [
        ("http_request_input", r"\bget(?:Parameter|Header|InputStream)\s*\(", ["tainted-input"]),
        ("process_input", r"\bSystem\.getenv\s*\(", ["tainted-input"]),
    ],
    "go": [
        ("http_request_input", r"\br\.(?:URL\.Query|FormValue|Header\.Get)\s*\(", ["tainted-input"]),
        ("process_input", r"\bos\.(?:Args|Getenv)\b", ["tainted-input"]),
    ],
    "ruby": [
        ("http_request_input", r"\b(?:params\s*\[|request\.)", ["tainted-input"]),
        ("process_input", r"\b(?:ENV\s*\[|ARGV\b)", ["tainted-input"]),
    ],
    "php": [
        ("http_request_input", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", ["tainted-input"]),
        ("process_input", r"\bgetenv\s*\(", ["tainted-input"]),
    ],
    "c": [
        ("process_input", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()", ["tainted-input"]),
    ],
    "cpp": [
        ("process_input", r"\b(?:argv\s*\[|getenv\s*\(|read\s*\(|recv\s*\()", ["tainted-input"]),
    ],
    "shell": [
        ("positional_parameter", r"\$(?:[1-9]|@|\*)\b", ["tainted-input"]),
        ("environment_input", r"\$\{?[A-Z_][A-Z0-9_]*\}?", ["tainted-input"]),
    ],
    "dockerfile": [
        ("build_argument", r"^\s*(?:ARG|ENV)\s+[A-Za-z_][A-Za-z0-9_]*", ["tainted-input"]),
    ],
    "lua": [
        ("script_argument", r"\b(?:ARGV|KEYS)\s*\[", ["tainted-input"]),
    ],
    "html": [
        ("template_input", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>", ["tainted-input"]),
    ],
    "css": [
        ("template_input", r"\{\{[^}\r\n]+\}\}|<%[^%\r\n]+%>", ["tainted-input"]),
    ],
}

_STREAM_IMPORT_PATTERNS: dict[str, list[str]] = {
    "python": [r"\b(?:from\s+[\w.]+\s+import\b[^\r\n]*|import\s+[^\r\n]+)"],
    "javascript": [r"\bimport\b[^\r\n]*", r"\brequire\s*\([^\r\n]*"],
    "typescript": [r"\bimport\b[^\r\n]*", r"\brequire\s*\([^\r\n]*"],
    "java": [r"\bimport\s+[\w.*]+"],
    "go": [r"\bimport\s*(?:\([^\r\n]*|[\"`][^\"`]+[\"`])"],
    "ruby": [r"\b(?:require|require_relative|load)\s*\(?\s*['\"][^'\"]+"],
    "php": [r"\b(?:include|include_once|require|require_once|use)\b[^\r\n;]*"],
    "c": [r"#\s*include\s*[<\"][^>\"]+[>\"]"],
    "cpp": [r"#\s*include\s*[<\"][^>\"]+[>\"]"],
    "lua": [r"\brequire\s*\(?\s*['\"][^'\"]+"],
    "dockerfile": [r"^\s*(?:FROM|ADD)\s+[^\r\n]+"],
    "shell": [r"^\s*(?:\.|source)\s+[^\r\n]+"],
    "html": [r"<(?:script|link|iframe)\b[^>]*(?:src|href)\s*=\s*['\"]?[^'\"\s>]+"],
    "css": [r"@import\s+(?:url\()?\s*['\"]?[^'\"\s)]+"],
}

_STREAM_EXTRA_SINK_PATTERNS: dict[str, list[tuple[str, str, list[str]]]] = {
    "dockerfile": [
        ("remote_pipe_to_shell", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", ["supply-chain", "injection"]),
        ("permissive_chmod", r"\bchmod\s+(?:-R\s+)?[0-7]*777\b", ["privilege-escalation"]),
    ],
    "shell": [
        ("shell_eval", r"\beval\b", ["injection"]),
        ("remote_pipe_to_shell", r"\b(?:curl|wget)\b[^\r\n|;]*\|\s*(?:sh|bash|zsh)\b", ["supply-chain", "injection"]),
    ],
    "lua": [
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
}

_STREAM_EXTRA_ENTRY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "shell": [("shell_script", r"^#!")],
    "dockerfile": [
        ("container_cmd", r"^\s*CMD\b"),
        ("container_entrypoint", r"^\s*ENTRYPOINT\b"),
    ],
    "html": [("html_form", r"<form\b[^>]*\baction\s*=")],
}


def _byte_pattern(pattern: str) -> re.Pattern[bytes]:
    return re.compile(pattern.encode("ascii"), re.IGNORECASE)


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
            (kind, _byte_pattern(pattern), vuln_classes)
            for kind, pattern, vuln_classes in _STREAM_SOURCE_PATTERNS.get(language, [])
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

    def _append_line_bytes(self, data: bytes) -> None:
        if not data:
            return
        self._line_had_bytes = True
        if self._line_comment is None:
            stripped = data.lstrip(b" \t\v\f")
            if stripped:
                hash_comment = self.language not in {"c", "cpp"} and not (
                    self.language == "shell" and stripped.startswith(b"#!")
                )
                self._line_comment = stripped.startswith(b"//") or (
                    hash_comment and stripped.startswith(b"#")
                )
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
        for kind, pattern, vuln_classes in self._source_patterns:
            for match in pattern.finditer(window):
                if match.start() >= accept_before:
                    continue
                self._retain(
                    "security_sources",
                    {
                        "kind": kind,
                        "line": self._line_number,
                        "snippet": self._snippet(window, match.start(), match.end()),
                        "vuln_classes": vuln_classes,
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
    indexed.update(
        {
            "structural_index_available": True,
            "analysis_status": "degraded" if truncated else "complete",
            "analysis_mode": analysis_mode,
            "degradation_reason": "artifact_signal_limit" if truncated else None,
            "source_size": source_size,
            "bytes_scanned": source_size,
            "unavailable_dimensions": [],
            "artifact_truncated": bool(truncated),
            "truncated_dimensions": sorted(truncated),
            "signal_counts": signal_counts,
            "signal_limit_per_dimension": STRUCTURAL_SIGNAL_LIMIT,
        }
    )
    return indexed

def language_for_file(file_path: str) -> str | None:
    """Return the language key for a file, or None if unsupported.

    Recognises both tree-sitter-backed languages (by extension) and the
    lightweight regex-based extractors. Dockerfiles are matched by basename
    (``Dockerfile`` or ``Dockerfile.<variant>``).
    """
    return structural_language_for_file(file_path)


def index_file(
    file_path: str,
    language: str,
    source: bytes | None = None,
) -> dict[str, Any]:
    """Parse one bounded source value and return explicit coverage status."""
    if source is None:
        try:
            with open(file_path, "rb") as fh:
                source = fh.read()
        except OSError as exc:
            warnings.warn(f"Cannot read {file_path}: {exc}")
            return _empty_index(file_path, language)

    source_lines = source.decode("utf-8", errors="replace").splitlines()
    total_lines = len(source_lines)

    # Lightweight regex-based extractors run regardless of tree-sitter availability
    if language in LIGHTWEIGHT_LANGUAGES:
        try:
            return _complete_index_metadata(
                _attach_bounded_security_sources(
                    _index_lightweight(file_path, language, source_lines, total_lines),
                    file_path=file_path,
                    language=language,
                    source=source,
                ),
                source_size=len(source),
                analysis_mode="lightweight_regex",
            )
        except MemoryError:
            raise
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"lightweight extractor for '{language}' on {file_path} failed: {exc}; "
                "using bounded streaming security fallback.",
                stacklevel=2,
            )
            return _fallback_from_bytes(
                file_path,
                language,
                source,
                degradation_reason="lightweight_extractor_error",
            )

    if not _TS_AVAILABLE:
        warnings.warn(
            "tree-sitter is not installed; returning degraded index without "
            "structural analysis. Install tree-sitter and language grammars "
            "for full indexing.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_unavailable",
        )

    if language not in _TS_SUPPORTED_LANGUAGES:
        indexed = _empty_index(file_path, language, total_lines=total_lines)
        indexed.update(
            {
                "structural_index_available": False,
                "analysis_status": "unsupported",
                "analysis_mode": "none",
                "degradation_reason": "unsupported_language",
                "source_size": len(source),
                "bytes_scanned": len(source),
                "unavailable_dimensions": list(_UNSUPPORTED_UNAVAILABLE_DIMENSIONS),
                "artifact_truncated": False,
                "truncated_dimensions": [],
                "signal_counts": {dimension: 0 for dimension in _SIGNAL_DIMENSIONS},
            }
        )
        return indexed

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
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_grammar_unavailable",
        )

    try:
        tree = parser.parse(source)
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - retain bounded signal coverage
        warnings.warn(
            f"tree-sitter parse for '{language}' on {file_path} failed: {exc}; "
            "using bounded streaming security fallback.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_parse_error",
        )
    if tree is None:
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_parse_failed",
        )
    if bool(getattr(tree.root_node, "has_error", False)):
        warnings.warn(
            f"tree-sitter parse for '{language}' on {file_path} contains error nodes; "
            "using bounded streaming security fallback instead of claiming complete structure.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_syntax_error",
        )

    try:
        functions = _extract_functions_ts(tree, parse_lang, source)
        classes = _extract_classes_ts(tree, parse_lang, source)
        imports = _extract_imports_ts(tree, parse_lang, source)

        effective_lang = "typescript" if parse_lang == "tsx" else language
        _enrich_qualified_names(functions, classes, effective_lang)
        if effective_lang == "cpp":
            functions = _deduplicate_cpp_functions(functions)
        entry_points = _detect_entry_points(
            functions, classes, effective_lang, source_lines
        )
        entry_points.extend(
            _detect_top_level_entry_points(tree, effective_lang, source_lines)
        )
        sinks = _detect_sinks(functions, effective_lang, source_lines)
        call_sites = _detect_call_sites(functions, source_lines)
        exports = _detect_exports(functions, classes, effective_lang, source_lines)
        import_targets = _resolve_import_targets(imports, effective_lang)
        security_observations: dict[str, Any] = {}
        _attach_bounded_security_sources(
            security_observations,
            file_path=file_path,
            language=effective_lang,
            source=source,
        )
        _remove_internal_structural_fields(functions, classes)
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - retain bounded signal coverage
        warnings.warn(
            f"tree-sitter extraction for '{language}' on {file_path} failed: {exc}; "
            "using bounded streaming security fallback.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_analysis_error",
        )

    return _complete_index_metadata(
        {
            "file_path": file_path,
            "language": language,
            "total_functions": len(functions),
            "total_exports": len(exports),
            "total_lines": total_lines,
            "functions": functions,
            "entry_points": entry_points,
            "security_sinks": sinks,
            "security_sources": security_observations["security_sources"],
            "call_sites": call_sites,
            "imports": imports,
            "import_targets": import_targets,
            "exports": exports,
            "classes": classes,
            "signal_counts": security_observations["signal_counts"],
        },
        source_size=len(source),
        analysis_mode="tree_sitter",
    )


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
        "total_exports": 0,
        "total_lines": total_lines,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
    }
