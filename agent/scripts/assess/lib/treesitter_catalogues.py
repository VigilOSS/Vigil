"""Shared tree-sitter query, sink, and entry-point catalogues."""
from __future__ import annotations

from typing import Any

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
    "csharp": """
        (method_declaration) @func
        (constructor_declaration) @func
        (local_function_statement) @func
    """,
}

_CPP_DECLARATION_QUERY = """
    (declaration) @decl
    (field_declaration) @decl
"""

_C_DECLARATION_QUERY = """(declaration) @decl"""

_CLASS_QUERIES: dict[str, str] = {
    "java": """
        (class_declaration) @cls
        (interface_declaration) @cls
    """,
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
    "csharp": """
        (class_declaration) @cls
        (struct_declaration) @cls
        (interface_declaration) @cls
        (record_declaration) @cls
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
    "csharp": """(using_directive) @imp""",
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
            "cpp": [r"\bfopen\s*\(", r"\bopen\s*\(", r"\baccess\s*\(", r"\bstat\s*\(",
                    r"\b(?:std::)?(?:i|o|f)fstream\s+(?:[A-Za-z_]\w*)\s*[({]"],
            "python": [r"\bopen\s*\(", r"\bos\.path\.join\s*\(", r"\bPath\s*\("],
            "javascript": [r"\bfs\.readFile\w*\s*\(", r"\bfs\.writeFile\w*\s*\(", r"\bpath\.join\s*\("],
            "typescript": [r"\bfs\.readFile\w*\s*\(", r"\bfs\.writeFile\w*\s*\(", r"\bpath\.join\s*\("],
            "go": [r"\bos\.Open\w*\s*\(", r"\bos\.Create\s*\(", r"\bfilepath\.Join\s*\(",
                   r"\bioutil\.ReadFile\s*\(", r"\bos\.ReadFile\s*\("],
            "ruby": [r"\bFile\.open\s*\(", r"\bFile\.read\s*\(", r"\bIO\.read\s*\(",
                     r"\bFileUtils\.\w+\s*\("],
            "php": [r"\bfopen\s*\(", r"\bfile_get_contents\s*\(", r"\bfile_put_contents\s*\("],
            "csharp": [r"\bFile\.ReadAllText\s*\(", r"\bFile\.WriteAllText\s*\(",
                       r"\bFile\.Open\w*\s*\(", r"\bnew\s+StreamReader\s*\(",
                       r"\bPath\.Combine\s*\("],
        },
    },
    {
        # PHP's inclusion constructs load and EXECUTE the named file, so a
        # caller-controlled path is `lfi` (and `rfi` wherever `allow_url_include`
        # is on), not the `path-traversal` that reading one would be. They route
        # to different skills, so the coarser family was the wrong answer for the
        # commonest PHP RCE shape there is.
        "kind": "file_inclusion",
        "vuln_classes": ["lfi", "rfi"],
        "patterns": {
            "php": [r"\binclude\b", r"\brequire\b", r"\binclude_once\b",
                    r"\brequire_once\b"],
        },
    },
    {
        "kind": "sql_exec",
        "vuln_classes": ["sqli"],
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
            "csharp": [r"\bnew\s+SqlCommand\s*\(", r"\bnew\s+OleDbCommand\s*\(",
                       r"\.ExecuteReader\s*\(", r"\.ExecuteNonQuery\s*\(",
                       r"\.ExecuteScalar\s*\(", r"\bFromSqlRaw\s*\(",
                       r"\bExecuteSqlRaw\s*\("],
        },
    },
    {
        "kind": "process_exec",
        "vuln_classes": ["injection"],
        "patterns": {
            "java": [r"\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(",
                     r"\bProcessBuilder\s*\("],
            "c": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve\s*\("],
            "cpp": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve\s*\("],
            "python": [r"\bos\.system\s*\(", r"\bsubprocess\.run\s*\(",
                       r"\bsubprocess\.Popen\s*\(", r"\bsubprocess\.call\s*\(",
                       r"\bsubprocess\.check_output\s*\(",
                       r"\bsubprocess\.check_call\s*\(",
                       r"\bsubprocess\.getoutput\s*\(",
                       r"\bsubprocess\.getstatusoutput\s*\("],
            "javascript": [r"\bchild_process\.exec\s*\(", r"\bchild_process\.spawn\s*\("],
            "typescript": [r"\bchild_process\.exec\s*\(", r"\bchild_process\.spawn\s*\("],
            "go": [r"\bexec\.Command\s*\(", r"\bos\.StartProcess\s*\("],
            # No leading `\b`: it demands a word character to the LEFT of the
            # backtick, which idiomatic Ruby (`out = \`ssh ...\``) never writes,
            # so the anchored form could only ever match `a\`cmd\``.
            "ruby": [r"\bsystem\s*\(", r"\bexec\s*\(", r"`[^`]*`",
                     r"\bOpen3\.\w+\s*\(", r"\bIO\.popen\s*\("],
            "php": [r"\bexec\s*\(", r"\bsystem\s*\(", r"\bshell_exec\s*\(",
                    r"\bpassthru\s*\(", r"\bproc_open\s*\(", r"\bpopen\s*\("],
            "csharp": [r"\bProcess\.Start\s*\(", r"\bnew\s+ProcessStartInfo\s*\("],
        },
    },
    {
        "kind": "url_fetch",
        "vuln_classes": ["ssrf"],
        "patterns": {
            "java": [r"\.openStream\s*\(", r"\.getInputStream\s*\(",
                     r"\.getResponseCode\s*\(", r"\.send(?:Async)?\s*\("],
            "python": [r"\brequests\.get\s*\(", r"\brequests\.post\s*\(",
                       r"\brequests\.put\s*\(", r"\brequests\.patch\s*\(",
                       r"\brequests\.delete\s*\(", r"\brequests\.head\s*\(",
                       r"\brequests\.options\s*\(", r"\brequests\.request\s*\(",
                       r"\burllib\.request\.urlopen\s*\("],
            "javascript": [r"\bfetch\s*\(", r"\bhttp\.request\s*\(", r"\baxios\."],
            "typescript": [r"\bfetch\s*\(", r"\bhttp\.request\s*\(", r"\baxios\."],
            "go": [r"\bhttp\.Get\s*\(", r"\bhttp\.Post\s*\(",
                   r"\b\w*[Cc]lient\.Do\s*\("],
            "ruby": [r"\bNet::HTTP\.\w+\s*\(", r"\bHTTParty\.\w+\s*\(",
                     r"\bopen-uri\b", r"\bURI\.open\s*\("],
            "php": [r"\bcurl_exec\s*\(", r"\bfile_get_contents\s*\(.*http",
                    r"\bfopen\s*\(.*http"],
            "csharp": [
                r"\.(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync)\s*\(",
                r"\.(?:Download\w*|Upload\w*)\s*\(",
                r"\.GetResponse(?:Async)?\s*\(",
            ],
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
            "csharp": [r"\bBinaryFormatter\b", r"\bJavaScriptSerializer\b",
                       r"\bNetDataContractSerializer\b", r"\bLosFormatter\b",
                       r"\bTypeNameHandling\b", r"\bnew\s+XmlSerializer\s*\("],
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
            "csharp": [r"\bAssembly\.Load\w*\s*\(", r"\bActivator\.CreateInstance\s*\(",
                       r"\bType\.GetType\s*\(", r"\bCSharpCodeProvider\b"],
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
            "csharp": [r"\bMD5\b", r"\bSHA1\b", r"\bDESCryptoServiceProvider\b",
                       r"\bTripleDES\b", r"\bRijndaelManaged\b", r"\bnew\s+Random\s*\("],
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
            # No leading `\b`: it demands a word character to the LEFT of the
            # `$`, which valid PHP never writes before a variable sigil, so the
            # pattern could only ever match `a$_SESSION`.
            "php": [r"\$_SESSION\b", r"\bAuth::\w+\s*\(", r"\bpassword_verify\s*\(",
                    r"\bsession_start\s*\("],
            "csharp": [r"\bFormsAuthentication\b", r"\[Authorize\b",
                       r"\bHttpContext\.User\b", r"\bClaimsPrincipal\b"],
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
            "csharp": [r"\bHtml\.Raw\s*\(", r"@Html\.Raw\b"],
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
            "csharp": [r"\bResponse\.Redirect\s*\(", r"\bRedirect\s*\("],
        },
    },
    {
        "kind": "xml_parse",
        "vuln_classes": ["xxe"],
        "patterns": {
            "java": [r"\bDocumentBuilderFactory\b", r"\bSAXParserFactory\b",
                     r"\bXMLReader\b", r"\bXMLInputFactory\b"],
            "c": [r"\bxmlParseFile\s*\("],
            "cpp": [r"\bxmlParseFile\s*\("],
            "python": [r"\bxml\.etree\.ElementTree\.parse\s*\(", r"\blxml\.etree\.parse\s*\("],
            "go": [r"\bxml\.NewDecoder\s*\(", r"\bxml\.Unmarshal\s*\("],
            "ruby": [r"\bNokogiri::XML\s*\(", r"\bREXML::Document\.new\s*\("],
            "php": [r"\bsimplexml_load_string\s*\(", r"\bDOMDocument\b",
                    r"\bxml_parse\s*\("],
            "csharp": [r"\bnew\s+XmlDocument\s*\(", r"\bXmlTextReader\b",
                       r"\bXmlReader\.Create\s*\("],
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
        {"pattern": r"@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", "kind": "jaxrs_annotation"},
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
    "csharp": [
        {"pattern": r"\[Http(?:Get|Post|Put|Patch|Delete|Head|Options)\b", "kind": "aspnet_action"},
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
    # PHP's magic methods are where an attacker-controlled `unserialize()`
    # lands: the payload picks the class, and the runtime -- not the
    # application -- calls these. They are entry points for that reason, not
    # sinks. Matching is name equality per function and stays that way:
    # following a chain from one magic method into the next class is liveness
    # analysis, which this index does not do.
    "php": [
        {"name": "__construct", "kind": "constructor"},
        {"name": "__destruct", "kind": "destructor"},
        {"name": "__wakeup", "kind": "deserialization_hook"},
        {"name": "__unserialize", "kind": "deserialization_hook"},
        {"name": "__serialize", "kind": "serialization_hook"},
        {"name": "__sleep", "kind": "serialization_hook"},
        {"name": "__toString", "kind": "string_conversion_hook"},
        {"name": "__invoke", "kind": "invocation_hook"},
        {"name": "__call", "kind": "magic_call_hook"},
        {"name": "__get", "kind": "property_read_hook"},
        {"name": "__set", "kind": "property_write_hook"},
    ],
}

# String patterns scanned against source lines to detect framework registrations.
_ENTRY_LINE_PATTERNS: dict[str, list[dict[str, str]]] = {
    "java": [
        {"pattern": r"\bRouterFunctions\.route\s*\(", "kind": "spring_functional_route"},
    ],
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
        {"pattern": r"^\s*get\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*post\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*put\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*patch\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*delete\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*options\s+['\"/]", "kind": "sinatra_route"},
        {"pattern": r"^\s*head\s+['\"/]", "kind": "sinatra_route"},
    ],
    "php": [
        {"pattern": r"\bRoute::(?:get|post|put|patch|delete|options|any|match|resource|apiResource|resources|apiResources|redirect|view|fallback)\s*\(", "kind": "laravel_route"},
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
        {"pattern": r"^\s*Rails\.application\.routes\.draw\b", "kind": "rails_route"},
    ],
    # A Laravel/Slim route file is the reachability map of the application and
    # is written as top-level statements with no enclosing callable at all, so
    # the function-scoped table above never reaches one. Same registration
    # syntax read at file scope -- deliberately the same list object, not a
    # second copy for the two to drift apart.
    "php": _ENTRY_LINE_PATTERNS["php"],
}
